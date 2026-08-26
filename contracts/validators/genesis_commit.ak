// =============================================================================
// Aegis Insurance Protocol - Genesis Commitments Escrow (demand-gated pools)
// Location: contracts/validators/genesis_commit.ak
//
// *** NOT DEPLOYABLE UNTIL RED-TEAMED — new on-chain surface. ***
//
// Summary: A PER-PROPOSAL spend escrow for demand-gated pool building. Users
//          commit ADA into this escrow; if the proposal's liquidity threshold
//          is reached, the operator CONVERTS each commitment into a founding
//          LP position in the newly deployed pool (the commitment is the seed
//          capital). If the threshold is missed, owners RECLAIM
//          permissionlessly after the deadline — no operator can block it.
//
//          Parameterized PER PROPOSAL by {proposal_id, deadline,
//          pool_nft_policy, lp_token_policy} so every proposal gets a DISTINCT
//          script address, and the escrow is bound at the hash level to the
//          exact pool (NFT) + LP token it may convert into.
//
//          SAFETY FRAME: Convert COMPOSES with the deployed pool validator's
//          AddLiquidity arm — the pool's own growth / mint / locality checks
//          (datum_ok, value_ok, lp_minted, pool_out_no_lp, NN-A-3) still run
//          on the same tx. The escrow only ADDS constraints on top: right
//          pool (pinned NFT), right LP recipient (the committing owner), right
//          amount (the pool's own calculate_lp_mint applied to the committed
//          lovelace). The escrow can never relax pool security. Reclaim is the
//          fail-safe: the worst case of everything else is a full refund.
//
//          NO const ref to pool.ak hashes (avoids the deploy fixed-point
//          cycle); the pool is located by its one-shot NFT, never by hash.
// =============================================================================

use aegis/pool.{calculate_lp_mint}
use aegis/test_helpers/fixtures
use aegis/types.{PoolDatum, VerificationKeyHash}
use aegis/validation.{
  count_script_inputs, get_lower_bound, must_be_signed_by, output_has_nft,
}
use aiken/collection/list
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets
use cardano/transaction.{
  InlineDatum, NoDatum, Output, OutputReference, Transaction,
}

pub type GenesisCommitDatum {
  owner: VerificationKeyHash,
}

pub type GenesisCommitRedeemer {
  Reclaim
  Convert
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sum the aLP quantity across ALL outputs at the owner's ENTERPRISE key
/// address (payment = VerificationKey(pkh), stake = None). The aLP analogue of
/// `validation.sum_lovelace_to_enterprise_pkh`: Convert is operator-built (the
/// owner never signs), so the enterprise pin blocks the A-009 stake-graft on
/// the founding-LP UTxO, and summing via `foldl` — never first-match — is the
/// A-006 / A-013 lesson.
fn sum_lp_to_enterprise_pkh(
  outputs: List<Output>,
  pkh: VerificationKeyHash,
  lp_policy: ByteArray,
) -> Int {
  list.foldl(
    outputs,
    0,
    fn(out, acc) {
      if out.address.payment_credential == VerificationKey(pkh) && out.address.stake_credential == None {
        acc + assets.quantity_of(out.value, lp_policy, "aLP")
      } else {
        acc
      }
    },
  )
}

/// Count ALL inputs whose payment credential is a Script — any script, not a
/// specific hash. Convert pins this to exactly 2 (this escrow + the pool), so
/// a sibling proposal's escrow for the SAME bucket can never ride the same tx
/// and share the owner's LP output (cross-proposal double satisfaction — the
/// same-owner variant `count_script_inputs` alone cannot see).
fn count_all_script_inputs(inputs: List<transaction.Input>) -> Int {
  list.foldl(
    inputs,
    0,
    fn(input, acc) {
      when input.output.address.payment_credential is {
        Script(_) -> acc + 1
        _ -> acc
      }
    },
  )
}

// ---------------------------------------------------------------------------
// genesis_commit validator
// ---------------------------------------------------------------------------

/// `proposal_id` is a pure parameterization salt: it never gates logic, but it
/// gives every proposal a DISTINCT script hash so commitments to different
/// proposals can never be spent under each other's rules.
validator genesis_commit(
  proposal_id: ByteArray,
  deadline: Int,
  pool_nft_policy: ByteArray,
  lp_token_policy: ByteArray,
) {
  spend(
    datum_opt: Option<GenesisCommitDatum>,
    redeemer: GenesisCommitRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(GenesisCommitDatum { owner }) = datum_opt
    let Transaction { inputs, outputs, extra_signatories, validity_range, .. } = self

    when redeemer is {
      // ---------------------------------------------------------------------
      // RECLAIM: the fail-safe. After the deadline the owner takes their
      // commitment back, permissionlessly — no operator, oracle, or pool
      // state can block it. The worst case of everything else is this refund.
      // ---------------------------------------------------------------------
      Reclaim ->
        get_lower_bound(validity_range) > deadline && must_be_signed_by(
          extra_signatories,
          owner,
        )

      // ---------------------------------------------------------------------
      // CONVERT: operator-submitted (allowed before OR after the deadline;
      // post-deadline it races owner Reclaim and consumption resolves).
      // COMPOSES with the pool validator's AddLiquidity arm consumed in the
      // same tx — the pool's own growth / mint / locality checks still run;
      // this branch only ADDS: right pool, right LP recipient, right amount.
      // ---------------------------------------------------------------------
      Convert -> {
        expect Some(own_input) = list.find(
          inputs,
          fn(input) { input.output_reference == own_ref },
        )
        expect Script(own_hash) = own_input.output.address.payment_credential

        // (c) EXACTLY ONE input from this escrow (multi-escrow double
        // satisfaction, A-006 / A-013) AND exactly two script inputs in the
        // whole tx — this escrow + the pool — so no sibling escrow (of any
        // proposal) can share this tx's LP output.
        let single_commitment = count_script_inputs(inputs, own_hash) == 1 && count_all_script_inputs(
          inputs,
        ) == 2

        // (a) The tx spends the PINNED pool UTxO: an input carrying the
        // one-shot NFT under `pool_nft_policy`. Located by NFT, never by
        // script hash (no deploy fixed-point; a decoy at the pool address
        // fails closed here).
        expect Some(pool_in) = list.find(
          inputs,
          fn(input) { output_has_nft(input.output, pool_nft_policy) },
        )
        expect InlineDatum(raw_pool_datum) = pool_in.output.datum
        expect pool_datum: PoolDatum = raw_pool_datum

        // (RT-01) The committed UTxO must hold ONLY ADA. `committed` and the
        // pool's AddLiquidity value_ok both read lovelace only, and Convert
        // carries NO owner signature — so a riding native token would be
        // unconstrained and the operator could route it to their own output
        // while paying the owner just the lovelace-derived `lp_owed`. Forbidding
        // non-ADA in a converted commitment closes the skim structurally: a
        // token-bearing commitment cannot Convert, and its owner recovers the
        // FULL value (tokens included) via Reclaim after the deadline.
        // `without_lovelace` drops the ada entry; a pure-ADA commitment reduces
        // to `assets.zero`, any riding native token leaves a non-zero remainder.
        // (`assets.policies` is NOT usable here — it lists the ada policy id too.)
        let commit_ada_only =
          assets.without_lovelace(own_input.output.value) == assets.zero

        // (b) The owner's founding-LP position: >= the EXACT quantity the
        // pool's own deposit math prescribes for the committed lovelace,
        // evaluated against the SPENT pool input's datum (byte-for-byte the
        // deployed `calculate_lp_mint`, incl. the first-deposit 1:1 case).
        // `lp_owed > 0` fails a dust commitment closed: converting it would
        // sink the owner's ADA for zero LP — their path is Reclaim.
        let committed = assets.lovelace_of(own_input.output.value)
        let lp_owed = calculate_lp_mint(
          committed,
          pool_datum.total_liquidity,
          pool_datum.lp_supply,
        )
        let owner_paid = sum_lp_to_enterprise_pkh(
          outputs,
          owner,
          lp_token_policy,
        ) >= lp_owed

        single_commitment && commit_ada_only && lp_owed > 0 && owner_paid
      }
    }
  }

  else(_) {
    fail @"Unsupported purpose for genesis_commit"
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const gc_proposal_id: ByteArray = #"7573646d2d30333330"

const gc_deadline: Int = 1_700_000_000_000

const gc_escrow_hash: ByteArray =
  #"9e5e9e5e9e5e9e5e9e5e9e5e9e5e9e5e9e5e9e5e9e5e9e5e9e5e9e5e"

const gc_foreign_script_hash: ByteArray =
  #"1f2e1f2e1f2e1f2e1f2e1f2e1f2e1f2e1f2e1f2e1f2e1f2e1f2e1f2e"

const gc_owner: ByteArray = fixtures.insured_pkh

// Commit 100 ADA against the default pool (1:1 liquidity:supply) -> owed
// exactly 100_000_000 aLP.
const gc_committed: Int = 100_000_000

const gc_lp_owed: Int = 100_000_000

fn gc_datum() -> GenesisCommitDatum {
  GenesisCommitDatum { owner: gc_owner }
}

fn gc_own_ref() -> OutputReference {
  fixtures.out_ref(fixtures.tx_id_zero, 0)
}

fn gc_escrow_input(idx: Int, lovelace: Int) -> transaction.Input {
  fixtures.make_input(
    fixtures.tx_id_zero,
    idx,
    fixtures.script_addr(gc_escrow_hash),
    assets.from_lovelace(lovelace),
    InlineDatum(gc_datum()),
  )
}

// A decoy "pool" input at the pool script address WITHOUT the canonical NFT.
fn gc_decoy_pool_input() -> transaction.Input {
  fixtures.make_input(
    fixtures.tx_id_one,
    0,
    fixtures.script_addr(fixtures.pool_script_hash),
    assets.from_lovelace(500_000_000_000),
    InlineDatum(fixtures.default_pool_datum()),
  )
}

// The owner's founding-LP output: `lp_qty` aLP at `dest`.
fn gc_lp_output(dest: Address, lp_qty: Int) -> Output {
  Output {
    address: dest,
    value: assets.from_lovelace(2_000_000)
      |> assets.add(fixtures.lp_token_policy_id, "aLP", lp_qty),
    datum: NoDatum,
    reference_script: None,
  }
}

fn gc_spend(
  redeemer: GenesisCommitRedeemer,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  genesis_commit.spend(
    gc_proposal_id,
    gc_deadline,
    fixtures.pool_nft_policy,
    fixtures.lp_token_policy_id,
    Some(gc_datum()),
    redeemer,
    own_ref,
    tx,
  )
}

// ---------------------------------------------------------------------------
// Reclaim
// ---------------------------------------------------------------------------

fn gc_reclaim_tx(lower: Int, signer: ByteArray) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [gc_escrow_input(0, gc_committed)],
    outputs: [fixtures.pkh_output(gc_owner, gc_committed)],
    validity_range: fixtures.finite_range(lower, lower + 300_000),
    extra_signatories: [signer],
  }
}

// NEGATIVE: reclaim BEFORE the deadline — the escrow is still convertible.
test gc_reclaim_before_deadline_rejected() {
  gc_spend(Reclaim, gc_own_ref(), gc_reclaim_tx(gc_deadline - 1_000, gc_owner)) == False
}

// NEGATIVE: reclaim past the deadline but signed by a NON-owner.
test gc_reclaim_non_owner_rejected() {
  gc_spend(
    Reclaim,
    gc_own_ref(),
    gc_reclaim_tx(gc_deadline + 1_000, fixtures.attacker_pkh),
  ) == False
}

// GREEN: owner reclaims after the deadline. Permissionless-for-owner: no
// operator involvement anywhere in the tx.
test gc_reclaim_post_deadline_owner_accepted() {
  gc_spend(Reclaim, gc_own_ref(), gc_reclaim_tx(gc_deadline + 1_000, gc_owner))
}

// NEGATIVE: a validity lower bound EXACTLY AT the deadline is not yet past it.
test gc_reclaim_at_deadline_rejected() {
  gc_spend(Reclaim, gc_own_ref(), gc_reclaim_tx(gc_deadline, gc_owner)) == False
}

// ---------------------------------------------------------------------------
// Convert
// ---------------------------------------------------------------------------

fn gc_convert_tx(
  pool_in: transaction.Input,
  lp_qty: Int,
  lp_dest: Address,
  extra_input: Option<transaction.Input>,
) -> Transaction {
  let base_inputs = [gc_escrow_input(0, gc_committed), pool_in]
  let inputs = when extra_input is {
    Some(extra) -> list.concat(base_inputs, [extra])
    None -> base_inputs
  }
  Transaction {
    ..transaction.placeholder,
    inputs,
    outputs: [
      fixtures.pool_continuation(
        500_000_000_000 + gc_committed,
        True,
        PoolDatum {
          ..fixtures.default_pool_datum(),
          total_liquidity: fixtures.default_pool_datum().total_liquidity + gc_committed,
          lp_supply: fixtures.default_pool_datum().lp_supply + lp_qty,
        },
      ),
      gc_lp_output(lp_dest, lp_qty),
    ],
    validity_range: fixtures.finite_range(
      gc_deadline - 600_000,
      gc_deadline - 300_000,
    ),
  }
}

fn gc_live_pool_input() -> transaction.Input {
  fixtures.pool_input(
    fixtures.tx_id_one,
    0,
    500_000_000_000,
    fixtures.default_pool_datum(),
  )
}

// GREEN: compliant conversion — pinned pool NFT consumed, owed aLP lands at the
// owner's enterprise key address, single escrow input.
test gc_convert_compliant_accepted() {
  gc_spend(
    Convert,
    gc_own_ref(),
    gc_convert_tx(
      gc_live_pool_input(),
      gc_lp_owed,
      fixtures.pkh_addr(gc_owner),
      None,
    ),
  )
}

// GREEN: FIRST deposit into a freshly deployed pool (total_liquidity == 0,
// lp_supply == 0) mints 1:1 — the founding-LP seed-capital case.
test gc_convert_first_deposit_one_to_one_accepted() {
  let empty_pool_datum = PoolDatum {
    ..fixtures.default_pool_datum(),
    total_liquidity: 0,
    lp_supply: 0,
  }
  let pool_in = fixtures.pool_input(
    fixtures.tx_id_one,
    0,
    5_000_000,
    empty_pool_datum,
  )
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [gc_escrow_input(0, gc_committed), pool_in],
    outputs: [
      fixtures.pool_continuation(
        5_000_000 + gc_committed,
        True,
        PoolDatum {
          ..empty_pool_datum,
          total_liquidity: gc_committed,
          lp_supply: gc_committed,
        },
      ),
      gc_lp_output(fixtures.pkh_addr(gc_owner), gc_committed),
    ],
  }
  gc_spend(Convert, gc_own_ref(), tx)
}

// NEGATIVE: the consumed "pool" input does NOT carry the pinned pool NFT —
// the canonical-pool locate fails closed (decoy pool / wrong bucket).
test gc_convert_wrong_pool_nft_rejected() fail {
  gc_spend(
    Convert,
    gc_own_ref(),
    gc_convert_tx(
      gc_decoy_pool_input(),
      gc_lp_owed,
      fixtures.pkh_addr(gc_owner),
      None,
    ),
  )
}

// NEGATIVE: owner is paid one aLP LESS than calculate_lp_mint prescribes.
test gc_convert_underpaid_lp_rejected() {
  gc_spend(
    Convert,
    gc_own_ref(),
    gc_convert_tx(
      gc_live_pool_input(),
      gc_lp_owed - 1,
      fixtures.pkh_addr(gc_owner),
      None,
    ),
  ) == False
}

// NEGATIVE: the founding-LP output is routed to a non-owner address.
test gc_convert_lp_to_wrong_address_rejected() {
  gc_spend(
    Convert,
    gc_own_ref(),
    gc_convert_tx(
      gc_live_pool_input(),
      gc_lp_owed,
      fixtures.pkh_addr(fixtures.attacker_pkh),
      None,
    ),
  ) == False
}

// NEGATIVE: LP paid to the owner's payment key but with a GRAFTED stake
// credential (A-009) — the operator builds Convert, so without the enterprise
// pin it could farm staking rewards on the owner's founding-LP UTxO.
test gc_convert_lp_stake_grafted_rejected() {
  let grafted = Address {
    payment_credential: VerificationKey(gc_owner),
    stake_credential: Some(Inline(VerificationKey(fixtures.attacker_stake_pkh))),
  }
  gc_spend(
    Convert,
    gc_own_ref(),
    gc_convert_tx(gc_live_pool_input(), gc_lp_owed, grafted, None),
  ) == False
}

// NEGATIVE: TWO inputs from this escrow in one tx — the multi-escrow
// double-satisfaction vector (A-006 / A-013 lesson). Hard-pinned to one.
test gc_convert_two_escrow_inputs_rejected() {
  gc_spend(
    Convert,
    gc_own_ref(),
    gc_convert_tx(
      gc_live_pool_input(),
      gc_lp_owed,
      fixtures.pkh_addr(gc_owner),
      Some(gc_escrow_input(1, gc_committed)),
    ),
  ) == False
}

// NEGATIVE: a THIRD script input rides along (e.g. a sibling proposal's escrow
// for the same bucket). Convert allows exactly two script inputs — this escrow
// + the pool — so a same-owner sibling escrow can never share this tx's LP
// output (cross-proposal double satisfaction).
test gc_convert_foreign_script_input_rejected() {
  let foreign = fixtures.make_input(
    fixtures.tx_id_two,
    7,
    fixtures.script_addr(gc_foreign_script_hash),
    assets.from_lovelace(gc_committed),
    NoDatum,
  )
  gc_spend(
    Convert,
    gc_own_ref(),
    gc_convert_tx(
      gc_live_pool_input(),
      gc_lp_owed,
      fixtures.pkh_addr(gc_owner),
      Some(foreign),
    ),
  ) == False
}

// NEGATIVE: a commitment so small against so large a pool that
// calculate_lp_mint truncates to 0 — converting would sink the owner's ADA
// for zero LP. Rejected; the owner's path is Reclaim after the deadline.
test gc_convert_zero_lp_owed_rejected() {
  let whale_pool_datum = PoolDatum {
    ..fixtures.default_pool_datum(),
    total_liquidity: 1_000_000_000_000,
    lp_supply: 100,
  }
  let pool_in = fixtures.pool_input(
    fixtures.tx_id_one,
    0,
    1_000_000_000_000,
    whale_pool_datum,
  )
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [gc_escrow_input(0, 2_000_000), pool_in],
    outputs: [gc_lp_output(fixtures.pkh_addr(gc_owner), 1)],
  }
  gc_spend(Convert, gc_own_ref(), tx) == False
}

// ===========================================================================
// RED-TEAM FINDINGS  —  branch redteam/genesis-commit  —  DO NOT MERGE.
//
// These tests document behavior of the CURRENT (unpatched) validator. They
// assert the CURRENT outcome so they can live in-tree without changing the
// validator. A finding is "closed" only when the marked assertion FLIPS after
// a fix — see the per-test note. Do not treat their passing as a safety proof;
// treat it as a proof the malicious/undesirable shape is currently accepted.
// ===========================================================================

// A native token an owner (or the honest builder's change logic) leaves riding
// in a commitment UTxO. `committed = assets.lovelace_of(...)` ignores it.
const rt_riding_policy: ByteArray =
  #"cafebabecafebabecafebabecafebabecafebabecafebabecafebabe"

const rt_riding_name: ByteArray = #"52494445"

fn gc_escrow_input_with_token(
  idx: Int,
  lovelace: Int,
  tok_qty: Int,
) -> transaction.Input {
  fixtures.make_input(
    fixtures.tx_id_zero,
    idx,
    fixtures.script_addr(gc_escrow_hash),
    assets.from_lovelace(lovelace)
      |> assets.add(rt_riding_policy, rt_riding_name, tok_qty),
    InlineDatum(gc_datum()),
  )
}

// RT-01 [MEDIUM] — Convert does NOT conserve non-ADA value in the commitment
// UTxO. `committed` reads lovelace only; a riding native token is unconstrained
// by BOTH the escrow (this validator) and the pool's AddLiquidity arm (whose
// value_ok checks lovelace only). Convert requires NO owner signature, so the
// operator unilaterally routes the token to their own output while paying the
// owner just the lovelace-derived `lp_owed`. The honest `build_convert_tx`
// already does this: any escrow asset that is not carried into an explicit
// output falls to `change_address = operator_address`.
//
// FIXED: Convert now requires the committed UTxO to hold ONLY ADA
// (`commit_ada_only`), so a token-bearing commitment cannot Convert and the
// operator has nothing to skim — the owner recovers the full value via Reclaim.
// This is the regression gate: the skimming tx MUST be REJECTED (== False).
test rt01_convert_skims_riding_token_REJECTED() {
  let escrow_in = gc_escrow_input_with_token(0, gc_committed, 1)
  let attacker_skim_output =
    Output {
      address: fixtures.pkh_addr(fixtures.attacker_pkh),
      value: assets.from_lovelace(2_000_000)
        |> assets.add(rt_riding_policy, rt_riding_name, 1),
      datum: NoDatum,
      reference_script: None,
    }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [escrow_in, gc_live_pool_input()],
      outputs: [
        fixtures.pool_continuation(
          500_000_000_000 + gc_committed,
          True,
          PoolDatum {
            ..fixtures.default_pool_datum(),
            total_liquidity: fixtures.default_pool_datum().total_liquidity + gc_committed,
            lp_supply: fixtures.default_pool_datum().lp_supply + gc_lp_owed,
          },
        ),
        gc_lp_output(fixtures.pkh_addr(gc_owner), gc_lp_owed),
        attacker_skim_output,
      ],
      validity_range: fixtures.finite_range(
        gc_deadline - 600_000,
        gc_deadline - 300_000,
      ),
    }
  gc_spend(Convert, gc_own_ref(), tx) == False
}

// F-02 [LOW] — A commitment created WITHOUT a decodable GenesisCommitDatum
// (NoDatum here; a mis-typed inline datum is equivalent) is PERMANENTLY
// unspendable: `expect Some(GenesisCommitDatum { owner }) = datum_opt` aborts on
// BOTH redeemers, so neither Reclaim nor Convert can ever move the funds. This
// is the depositor's own loss (no third party profits) and the honest
// `build_commit_tx` always attaches the datum — but the lock is NOT documented
// in SPEC §6 and read_proposal_state silently drops such UTxOs, so a depositor
// who fat-fingers the datum gets no signal. `fail` = the spend aborts.
test f02_datumless_commitment_is_locked_reclaim() fail {
  genesis_commit.spend(
    gc_proposal_id,
    gc_deadline,
    fixtures.pool_nft_policy,
    fixtures.lp_token_policy_id,
    None,
    Reclaim,
    gc_own_ref(),
    gc_reclaim_tx(gc_deadline + 1_000, gc_owner),
  )
}
