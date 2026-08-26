use aegis/test_helpers/fixtures
use aegis/types.{PolicyDatum, policy_marker_asset_name}
use aegis/validation.{pool_is_consumed_via_nft}
use aiken/collection/list
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets
use cardano/transaction.{
  Input, NoDatum, Output, OutputReference, Transaction, placeholder,
}

// =============================================================================
// Aegis V8 stable-vault — thin POLICY validator (#362)
// Location: contracts/validators/policy_v8.ak
//
// The policy UTxOs created by the vault's Underwrite arm sit at THIS script
// address — the vault's CORE `policy_hash` compile param. Each holds exactly
// one marker + an inline PolicyDatum. When the vault SPENDS a policy UTxO
// (Claim / Expire / AcceptCancellation), the validator here also runs and must
// approve.
//
// V8 keeps EVERY lovelace-moving decision + its destination in the immutable
// pool_vault (M5: the vault recomputes the trigger, resolves the spot, pins the
// payout, burns the marker, validates all accounting). So this validator is
// DELIBERATELY THIN — it must add ZERO independent oracle / trigger / payout
// logic (that is exactly why V7 policy.ak must NOT be reused: its duplicate
// oracle read would contradict the vault's recompute and destroy version
// independence).
//
// Its ONLY job: a policy UTxO may be spent ONLY as part of an authorized marker
// BURN. This is airtight and non-duplicative:
//   * A marker burn requires policy_marker's BurnFor* redeemer, which itself
//     requires the one-shot pool NFT to be consumed (the vault is spent).
//   * The vault is only ever spent with a redeemer that validates the whole tx;
//     its Claim/Expire/AcceptCancellation arms are the ONLY ones that burn a
//     marker, and they own the accounting + single-marker-in/zero-out checks.
//   * The vault's LP arms (AddLiquidity/RemoveLiquidity/DepositRevenue) FORBID
//     any marker in the mint field (only_lp_minted), and Underwrite MINTS a
//     marker (never burns). So a policy UTxO can never be spent outside a
//     legitimate coverage burn — closing the "spend a policy in an AddLiquidity
//     and pocket its self-held coverage" drain that a naive
//     "pool-NFT-consumed only" gate would open.
//
// Parameterized by (pool_nft_policy, pool_nft_name, marker_policy). The DAG is
// pool_nft -> policy_marker -> policy_v8 -> pool_vault, and it is ACYCLIC, which
// is the whole of why there is no hash fixed-point: none of this validator's
// three parameters depends on pool_vault, so policy_v8's hash is fully
// determined before pool_vault compiles. Under Invariant S that hash IS a
// pool_vault compile parameter (`policy_hash`, position 4) — settlement
// authenticates a policy UTxO against a CORE root, with no registry read. The
// genesis RegistryDatum still copies the same hash into RuleSet.policy_hash;
// nothing reads that copy to authenticate a policy — the registry's own
// transitions only pin it unchanged (see lib/aegis/registry.ak).
// =============================================================================

validator policy_v8(
  pool_nft_policy: ByteArray,
  pool_nft_name: ByteArray,
  marker_policy: ByteArray,
) {
  spend(
    datum_opt: Option<PolicyDatum>,
    _redeemer: Data,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    // A well-formed policy UTxO always carries an inline PolicyDatum.
    expect Some(_pd) = datum_opt
    let Transaction { inputs, mint, .. } = self
    // Locate THIS input to learn our own script hash + our own marker.
    expect Some(own_input) =
      list.find(inputs, fn(i) { i.output_reference == own_ref })
    expect Script(own_hash) = own_input.output.address.payment_credential
    // Every policy UTxO of THIS script being spent in this tx. Explicit
    // credential match (never derived Eq on a sum type).
    let policy_ins =
      list.count(
        inputs,
        fn(i) {
          when i.output.address.payment_credential is {
            Script(h) -> h == own_hash
            _ -> False
          }
        },
      )
    let net_marker =
      assets.quantity_of(mint, marker_policy, policy_marker_asset_name)
    and {
      // the vault singleton is consumed (belt: a marker burn already implies it)
      pool_is_consumed_via_nft(inputs, pool_nft_policy, pool_nft_name),
      // [#363 red-team H2, defense-in-depth] bind the burn to THIS UTxO:
      // exactly one marker burned per policy UTxO spent at this script. The old
      // global `net < 0` let ONE burn authorize spending SEVERAL policy UTxOs
      // (the orphan-drain vector). This also still distinguishes
      // Claim/Expire/Cancel from every other vault arm, since only those burn.
      net_marker == -policy_ins,
      // and this UTxO must itself carry its marker, so a marker-less UTxO
      // parked at the policy address cannot ride along on someone else's burn.
      assets.quantity_of(
        own_input.output.value,
        marker_policy,
        policy_marker_asset_name,
      ) == 1,
    }
  }

  else(_) {
    fail @"Unsupported purpose for policy_v8 (spend-only)"
  }
}

// ---------------------------------------------------------------------------
// Tests (TDD)
// ---------------------------------------------------------------------------

const pv_pool_policy: ByteArray = #"a0a1"

const pv_pool_name: ByteArray = #"41454749535f504f4f4c5f5638"

const pv_marker_policy: ByteArray = #"b0b1"

/// this validator's own script hash, in the fixtures
const pv_policy_script: ByteArray = #"c0c1"

fn pv_own_ref() -> OutputReference {
  OutputReference { transaction_id: #"00", output_index: 9 }
}

/// The vault-ish input carrying (or not carrying) the one-shot pool NFT.
fn pv_input(with_pool_nft: Bool) -> Input {
  let val =
    if with_pool_nft {
      assets.from_lovelace(2_000_000)
        |> assets.add(pv_pool_policy, pv_pool_name, 1)
    } else {
      assets.from_lovelace(2_000_000)
    }
  Input {
    output_reference: OutputReference { transaction_id: #"00", output_index: 0 },
    output: Output {
      address: Address {
        payment_credential: VerificationKey(#"cc"),
        stake_credential: None,
      },
      value: val,
      datum: NoDatum,
      reference_script: None,
    },
  }
}

/// A policy UTxO at THIS script; `idx` distinguishes siblings, `with_marker`
/// controls whether it actually carries its own marker.
fn pv_policy_input(idx: Int, with_marker: Bool) -> Input {
  let val =
    if with_marker {
      assets.from_lovelace(30_000_000)
        |> assets.add(pv_marker_policy, policy_marker_asset_name, 1)
    } else {
      assets.from_lovelace(30_000_000)
    }
  Input {
    output_reference: OutputReference {
      transaction_id: #"00",
      output_index: idx,
    },
    output: Output {
      address: Address {
        payment_credential: Script(pv_policy_script),
        stake_credential: None,
      },
      value: val,
      datum: NoDatum,
      reference_script: None,
    },
  }
}

fn pv_mint(qty: Int) -> assets.Value {
  if qty == 0 {
    assets.zero
  } else {
    assets.from_asset(pv_marker_policy, policy_marker_asset_name, qty)
  }
}

/// ONE policy UTxO of this script (the own one, index 9) + the pool-NFT input.
fn pv_tx(with_pool_nft: Bool, marker_qty: Int) -> Transaction {
  Transaction {
    ..placeholder,
    inputs: [pv_input(with_pool_nft), pv_policy_input(9, True)],
    mint: pv_mint(marker_qty),
  }
}

/// TWO policy UTxOs of this script spent in the same tx.
fn pv_tx2(marker_qty: Int) -> Transaction {
  Transaction {
    ..placeholder,
    inputs: [pv_input(True), pv_policy_input(9, True), pv_policy_input(8, True)],
    mint: pv_mint(marker_qty),
  }
}

fn pv_run(datum: Option<PolicyDatum>, tx: Transaction) -> Bool {
  policy_v8.spend(
    pv_pool_policy,
    pv_pool_name,
    pv_marker_policy,
    datum,
    Void,
    pv_own_ref(),
    tx,
  )
}

test policy_v8_allows_spend_on_marker_burn() {
  // pool NFT consumed + this policy's marker burned (net -1, 1 policy in) -> approve
  pv_run(Some(fixtures.default_policy_datum()), pv_tx(True, -1))
}

test policy_v8_rejects_without_marker_burn() {
  // pool NFT consumed but NO marker burn (e.g. spent inside an AddLiquidity that
  // consumes the pool NFT) -> reject. Closes the coverage-pocketing drain.
  !pv_run(Some(fixtures.default_policy_datum()), pv_tx(True, 0))
}

test policy_v8_rejects_marker_mint_not_burn() {
  // a positive marker mint (not a burn) -> reject.
  !pv_run(Some(fixtures.default_policy_datum()), pv_tx(True, 1))
}

test policy_v8_rejects_without_pool_nft() {
  // marker "burned" but the canonical pool NFT is NOT consumed -> reject (belt).
  !pv_run(Some(fixtures.default_policy_datum()), pv_tx(False, -1))
}

// [#363 red-team H2, defense-in-depth] the burn must ACCOUNT for every policy
// UTxO spent at this script — one burn may not authorize draining several.
test policy_v8_rejects_one_burn_for_two_policies() {
  !pv_run(Some(fixtures.default_policy_datum()), pv_tx2(-1))
}

test policy_v8_allows_two_policies_with_two_burns() {
  // the binding generalizes: N policies spent <=> N markers burned
  pv_run(Some(fixtures.default_policy_datum()), pv_tx2(-2))
}

test policy_v8_rejects_markerless_utxo_riding_along() {
  // a marker-LESS UTxO parked at the policy address must not ride along on an
  // otherwise-legitimate burn (it carries no marker of its own to account for).
  let tx =
    Transaction {
      ..placeholder,
      inputs: [pv_input(True), pv_policy_input(9, False)],
      mint: pv_mint(-1),
    }
  !pv_run(Some(fixtures.default_policy_datum()), tx)
}
