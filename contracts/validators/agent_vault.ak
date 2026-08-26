// =============================================================================
// Aegis Insurance Protocol - Agent Vault (DeFAI Phase 3)
// Location: contracts/validators/agent_vault.ak
//
// *** NOT DEPLOYABLE UNTIL RED-TEAMED — new money-holding on-chain surface. ***
//
// Summary: A spend-bounded escrow that lets an AI agent (T) hold working
//          capital and buy Aegis cover FOR its owner, under caps the validator
//          — not the backend, not the model — enforces. It migrates the Phase-2
//          off-chain mandate signer's checks onto the chain: the agent key's
//          authority survives even a total backend/LLM compromise because the
//          bounds are phase-2 validation, not application code.
//
// Datum: { owner, agent, per_tx_cap, epoch_cap, epoch_len, epoch_start,
//          epoch_spent, policy_script, max_fee_leak }.
//
// Redeemers:
//   * Sweep — the owner takes their capital back, unilaterally, any time. The
//     escape hatch: the worst case of everything else reduces to this refund.
//   * Spend — the agent spends from the vault, but ONLY into a transaction that:
//       (a) the AGENT signed;
//       (b) leaves a SINGLE vault continuation (same script addr) whose datum
//           preserves every cap/identity field and updates only epoch state;
//       (c) spends `spent = vault_in − vault_cont` with 0 < spent ≤ per_tx_cap,
//           and epoch-accumulated spend ≤ epoch_cap (rolling window, reset when
//           now ≥ epoch_start + epoch_len);
//       (d) creates an Aegis policy output (at `policy_script`) whose coverage
//           beneficiary is the OWNER — the anti-laundering pin: a compromised
//           agent key cannot mint policies that pay an attacker;
//       (e) leaks ≤ `max_fee_leak` lovelace to non-owner KEY addresses (the
//           team/partner protocol-fee slices), so premium cannot be redirected
//           to an attacker key. Value to Aegis SCRIPT addresses (pool coverage)
//           is bounded by those validators + the owner pin.
//
// SAFETY FRAME: COMPOSES with the deployed pool/policy validators consumed in
//          the same Underwrite tx — their own solvency / floor / marker checks
//          still run. This vault only ADDS constraints; it can never relax core
//          security. The audited R17 core is untouched (satellite pattern,
//          mirrors genesis_commit.ak).
//
// KNOWN RESIDUAL (for the red-team): within `per_tx_cap`/`epoch_cap`, a
//          compromised agent could route the spend into the pool as an
//          owner-beneficiary policy with suboptimal terms — a bounded,
//          owner-recoverable loss (buys the owner possibly-unwanted cover),
//          never theft to a third party. The off-chain signer's premium-band
//          check narrows this; moving the band on-chain is a follow-up rev.
// =============================================================================

use aegis/ceiling_table.{meets_barrier_ceiling, meets_depeg_ceiling}
use aegis/oracle.{attested_price}
use aegis/test_helpers/fixtures
use aegis/types.{
  Barrier, Depeg, PolicyDatum, ScriptHash, VerificationKeyHash,
  policy_marker_asset_name,
}
use aegis/validation.{count_script_inputs, get_lower_bound, must_be_signed_by}
use aiken/collection/list
use cardano/address.{Script, VerificationKey}
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}

pub type AgentVaultDatum {
  owner: VerificationKeyHash,
  agent: VerificationKeyHash,
  per_tx_cap: Int,
  epoch_cap: Int,
  epoch_len: Int,
  epoch_start: Int,
  epoch_spent: Int,
  policy_script: ScriptHash,
  max_fee_leak: Int,
  // The oracle-observer script hash the on-chain premium ceiling reads the
  // attested spot from. A protocol constant the OWNER sets at fund time and
  // that is preserved across every Spend — a compromised agent cannot change
  // it, and a wrong value only weakens the ceiling that protects the owner.
  observer_script_hash: ByteArray,
  // The policy-marker minting policy id. The pool mints EXACTLY ONE marker onto
  // the policy output it settles the Underwrite on, so this pins the vault's
  // ceiling + spend bound to the policy the owner actually receives — never a
  // cheaper decoy the agent appends to shadow the ceiling. Owner-set at fund
  // time, preserved across every Spend; a wrong value only fails the vault
  // closed (no settled policy found -> Spend rejected).
  marker_policy: ByteArray,
}

pub type AgentVaultRedeemer {
  Spend
  Sweep
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Count outputs whose payment credential is exactly `Script(hash)`.
fn count_outputs_to_script(outputs: List<Output>, hash: ScriptHash) -> Int {
  list.foldl(
    outputs,
    0,
    fn(out, acc) {
      if out.address.payment_credential == Script(hash) {
        acc + 1
      } else {
        acc
      }
    },
  )
}

/// The Claim beneficiary of a policy datum:
///   * Some(payout_address) -> its payment credential
///   * None                 -> the insured enterprise key
/// True iff that beneficiary's payment key is `owner`.
fn beneficiary_is_owner(pd: PolicyDatum, owner: VerificationKeyHash) -> Bool {
  when pd.payout_address is {
    Some(addr) -> addr.payment_credential == VerificationKey(owner)
    None -> pd.insured == owner
  }
}

/// The SETTLED policy the Underwrite issues in this tx: the first output at
/// `policy_script` carrying EXACTLY ONE marker under `marker_policy`. This is
/// the output pool.ak binds the `(coverage, premium)` settlement to
/// (`policy_output_matches_underwrite`), so the vault's ceiling, owner pin and
/// spend bound read the policy the owner actually receives — never a cheaper
/// non-marker decoy the agent appends to shadow the ceiling. A malformed datum
/// at the marker output aborts (fail-closed).
fn find_marker_policy(
  outputs: List<Output>,
  policy_script: ScriptHash,
  marker_policy: ByteArray,
) -> Option<PolicyDatum> {
  list.reduce(
    outputs,
    None,
    fn(acc, out) {
      when acc is {
        Some(_) -> acc
        None ->
          when out.address.payment_credential is {
            Script(h) ->
              if h == policy_script && assets.quantity_of(
                out.value,
                marker_policy,
                policy_marker_asset_name,
              ) == 1 {
                when out.datum is {
                  InlineDatum(raw) -> {
                    expect pd: PolicyDatum = raw
                    Some(pd)
                  }
                  _ -> None
                }
              } else {
                None
              }
            _ -> None
          }
      }
    },
  )
}

/// The premium ceiling gate (the on-chain half of the Phase-2 signer band
/// check). Dispatches on risk class:
///   * Barrier — reads the SAME attested spot the pool validated in this tx
///     (freshness already enforced pool-side), derives the strike distance,
///     and bounds premium above by ceiling_table.
///   * Depeg — duration-only ceiling (no spot).
/// A compromised API/operator can no longer overcharge a vault-funded policy
/// within per_tx_cap; the overcharge is now a phase-2 rejection.
fn premium_within_ceiling(
  self: Transaction,
  observer_script_hash: ByteArray,
  pd: PolicyDatum,
) -> Bool {
  let t_days = ( pd.expiry_time - pd.start_time ) / 86_400_000
  when pd.risk_class is {
    Barrier -> {
      let price =
        attested_price(self, observer_script_hash, pd.oracle_provider, pd.oracle_nft)
      let spot = price.value
      if spot <= 0 {
        False
      } else {
        let d_bps = ( spot - pd.strike_price ) * 10_000 / spot
        meets_barrier_ceiling(pd.premium_paid, pd.coverage_amount, d_bps, t_days)
      }
    }
    Depeg -> meets_depeg_ceiling(pd.premium_paid, pd.coverage_amount, t_days)
  }
}

// ---------------------------------------------------------------------------
// agent_vault validator
// ---------------------------------------------------------------------------

validator agent_vault {
  spend(
    datum_opt: Option<AgentVaultDatum>,
    redeemer: AgentVaultRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(vault) = datum_opt
    let AgentVaultDatum {
      owner,
      agent,
      per_tx_cap,
      epoch_cap,
      epoch_len,
      epoch_start,
      epoch_spent,
      policy_script,
      max_fee_leak,
      observer_script_hash,
      marker_policy,
    } = vault
    let Transaction { inputs, outputs, extra_signatories, validity_range, .. } =
      self

    expect Some(own_input) =
      list.find(inputs, fn(input) { input.output_reference == own_ref })
    expect Script(own_hash) = own_input.output.address.payment_credential

    when redeemer is {
      // -----------------------------------------------------------------
      // SWEEP: the owner reclaims their capital, unconditionally. The escape
      // hatch that makes every other worst case recoverable.
      // -----------------------------------------------------------------
      Sweep -> must_be_signed_by(extra_signatories, owner)

      // -----------------------------------------------------------------
      // SPEND: the agent buys owner cover under validator-enforced caps.
      // -----------------------------------------------------------------
      Spend -> {
        // Exactly one vault input (no merging two vaults into one continuation
        // — the double-satisfaction lesson, A-006 / A-013).
        let single_vault = count_script_inputs(inputs, own_hash) == 1

        // The agent authorizes the spend.
        let agent_signed = must_be_signed_by(extra_signatories, agent)

        // Exactly one continuation at THIS vault's script address.
        expect Some(cont) =
          list.find(
            outputs,
            fn(out) { out.address.payment_credential == Script(own_hash) },
          )
        let one_cont = count_outputs_to_script(outputs, own_hash) == 1
        expect InlineDatum(raw_cont) = cont.datum
        expect cont_datum: AgentVaultDatum = raw_cont

        // Every cap/identity field is preserved; only epoch state may move.
        let preserved =
          cont_datum.owner == owner && cont_datum.agent == agent && cont_datum.per_tx_cap == per_tx_cap && cont_datum.epoch_cap == epoch_cap && cont_datum.epoch_len == epoch_len && cont_datum.policy_script == policy_script && cont_datum.max_fee_leak == max_fee_leak && cont_datum.observer_script_hash == observer_script_hash && cont_datum.marker_policy == marker_policy

        // The vault continuation holds ONLY ADA — a grafted token would be
        // unconstrained value the agent could later route out.
        let cont_ada_only =
          assets.without_lovelace(cont.value) == assets.zero

        // Spend magnitude.
        let vin = assets.lovelace_of(own_input.output.value)
        let vout = assets.lovelace_of(cont.value)
        let spent = vin - vout
        let spend_positive = spent > 0
        let per_tx_ok = spent <= per_tx_cap

        // Rolling epoch accounting. `now` is the tx's finite lower bound (the
        // ledger forbids claiming a future time), so the agent cannot reset the
        // window early.
        let now = get_lower_bound(validity_range)
        let new_epoch = now >= epoch_start + epoch_len
        let epoch_ok =
          if new_epoch {
            cont_datum.epoch_start == now && cont_datum.epoch_spent == spent && spent <= epoch_cap
          } else {
            cont_datum.epoch_start == epoch_start && cont_datum.epoch_spent == epoch_spent + spent && cont_datum.epoch_spent <= epoch_cap
          }

        // The SETTLED (marker-bearing) policy — the one the pool actually issues
        // this tx — must:
        //   (a) pay the OWNER (anti-laundering: a compromised agent cannot buy
        //       an attacker cover);
        //   (b) clear the premium ceiling (the overcharge bound), read on the
        //       SETTLED policy so a cheap non-marker decoy cannot shadow it;
        //   (c) bound the vault outflow: `spent` may exceed the settled premium
        //       by at most `max_fee_leak` (the treasury/fee slice). This is the
        //       DESTINATION-agnostic drain guard — the vault can never move more
        //       than premium + fee no matter where the outputs point (an
        //       attacker script, an agent-change key, anywhere), so a
        //       compromised agent key cannot siphon the caps to a third party.
        let settlement_ok =
          when find_marker_policy(outputs, policy_script, marker_policy) is {
            Some(pd) ->
              beneficiary_is_owner(pd, owner) && premium_within_ceiling(
                self,
                observer_script_hash,
                pd,
              ) && spent <= pd.premium_paid + max_fee_leak
            None -> False
          }

        single_vault && agent_signed && one_cont && preserved && cont_ada_only && spend_positive && per_tx_ok && epoch_ok && settlement_ok
      }
    }
  }

  else(_) {
    fail @"Unsupported purpose for agent_vault"
  }
}

// ===========================================================================
// Tests
// ===========================================================================

const av_vault_hash: ByteArray =
  #"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

const av_owner: ByteArray = fixtures.insured_pkh

const av_agent: ByteArray =
  #"a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6"

const av_team: ByteArray =
  #"7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"

const av_per_tx_cap: Int = 20_000_000

const av_epoch_cap: Int = 50_000_000

const av_epoch_len: Int = 604_800_000

const av_epoch_start: Int = 1_700_000_000_000

const av_vault_lovelace: Int = 100_000_000

const av_premium: Int = 5_000_000

fn av_datum(epoch_start: Int, epoch_spent: Int) -> AgentVaultDatum {
  AgentVaultDatum {
    owner: av_owner,
    agent: av_agent,
    per_tx_cap: av_per_tx_cap,
    epoch_cap: av_epoch_cap,
    epoch_len: av_epoch_len,
    epoch_start,
    epoch_spent,
    policy_script: fixtures.policy_script_hash,
    max_fee_leak: 2_000_000,
    observer_script_hash: av_observer_hash,
    marker_policy: av_marker_policy,
  }
}

const av_marker_policy: ByteArray =
  #"add4e550add4e550add4e550add4e550add4e550add4e550add4e550"

const av_attacker_script: ByteArray =
  #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

fn av_own_ref() -> OutputReference {
  fixtures.out_ref(fixtures.tx_id_zero, 0)
}

fn av_vault_input(lovelace: Int, datum: AgentVaultDatum) -> Input {
  fixtures.make_input(
    fixtures.tx_id_zero,
    0,
    fixtures.script_addr(av_vault_hash),
    assets.from_lovelace(lovelace),
    InlineDatum(datum),
  )
}

fn av_vault_cont(lovelace: Int, datum: AgentVaultDatum) -> Output {
  Output {
    address: fixtures.script_addr(av_vault_hash),
    value: assets.from_lovelace(lovelace),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

const av_observer_hash: ByteArray =
  #"0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e"

// The vault tests use a DEPEG policy so the premium ceiling is duration-only
// (`meets_depeg_ceiling`, no oracle read) — the vault-security assertions
// (marker binding, spend bound, drain guards, owner pin) then hold under BOTH
// the preprod AND the mainnet fixture builds, with no AegisSelf-allowlist
// coupling, so this module stays fully green in the harness MUST_PASS. The
// Barrier ceiling wiring is a thin `attested_price` + `meets_barrier_ceiling`
// branch already covered by the oracle + ceiling_table modules. 60-day term ->
// depeg ceiling 1435 bps: on 5000-ADA coverage a 200-ADA (400 bps) premium
// clears and a 2000-ADA (4000 bps) premium is rejected.
const av_policy_coverage: Int = 5_000_000_000

fn av_policy_datum_prem(beneficiary: ByteArray, premium: Int) -> PolicyDatum {
  PolicyDatum {
    ..fixtures.default_policy_datum_aegis_self(),
    risk_class: Depeg,
    coverage_amount: av_policy_coverage,
    start_time: av_epoch_start,
    expiry_time: av_epoch_start + 60 * 86_400_000,
    payout_address: Some(fixtures.pkh_addr(beneficiary)),
    premium_paid: premium,
  }
}

// The SETTLED policy output — carries the marker the pool mints onto the policy
// it issues, so the vault binds its ceiling + spend bound to THIS output.
fn av_policy_output_prem(beneficiary: ByteArray, premium: Int) -> Output {
  let base =
    fixtures.script_output_with_datum(
      fixtures.policy_script_hash,
      av_policy_datum_prem(beneficiary, premium),
      5_000_000_000,
    )
  Output {
    ..base,
    value: assets.merge(base.value, fixtures.marker_value(av_marker_policy, 1)),
  }
}

// A NON-marker owner policy — the pool never settles it. The vault must ignore
// it (proves the ceiling reads the marker-settled policy, not a cheap decoy).
fn av_decoy_policy_output(beneficiary: ByteArray, premium: Int) -> Output {
  fixtures.script_output_with_datum(
    fixtures.policy_script_hash,
    av_policy_datum_prem(beneficiary, premium),
    5_000_000_000,
  )
}

fn av_policy_output(beneficiary: ByteArray) -> Output {
  av_policy_output_prem(beneficiary, 200_000_000)
}

fn av_spend(datum: AgentVaultDatum, tx: Transaction) -> Bool {
  agent_vault.spend(Some(datum), Spend, av_own_ref(), tx)
}

fn av_sweep(datum: AgentVaultDatum, tx: Transaction) -> Bool {
  agent_vault.spend(Some(datum), Sweep, av_own_ref(), tx)
}

// A well-formed Spend tx: agent-signed, valid continuation, owner policy, one
// small team-fee output within the leak bound.
fn av_good_tx() -> Transaction {
  let cont_datum = av_datum(av_epoch_start, av_premium)
  Transaction {
    ..transaction.placeholder,
    inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
    outputs: [
      av_vault_cont(av_vault_lovelace - av_premium, cont_datum),
      av_policy_output(av_owner),
      fixtures.pkh_output(av_team, 1_000_000),
    ],
    validity_range: fixtures.finite_range(
      av_epoch_start + 1_000,
      av_epoch_start + 300_000,
    ),
    extra_signatories: [av_agent],
  }
}

// ---------------------------------------------------------------------------
// Sweep
// ---------------------------------------------------------------------------

test av_sweep_by_owner_accepted() {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [fixtures.pkh_output(av_owner, av_vault_lovelace)],
      extra_signatories: [av_owner],
    }
  av_sweep(av_datum(av_epoch_start, 0), tx)
}

test av_sweep_by_nonowner_rejected() {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [fixtures.pkh_output(fixtures.attacker_pkh, av_vault_lovelace)],
      extra_signatories: [fixtures.attacker_pkh],
    }
  av_sweep(av_datum(av_epoch_start, 0), tx) == False
}

// ---------------------------------------------------------------------------
// Spend — premium ceiling (the on-chain overcharge bound)
// ---------------------------------------------------------------------------

test av_spend_overcharged_premium_rejected() {
  // 60-day depeg policy (ceiling 1435 bps) with premium at 2000/5000 = 4000
  // bps, a gross overcharge above the ceiling. Everything else is valid.
  let cont_datum = av_datum(av_epoch_start, av_premium)
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [
        av_vault_cont(av_vault_lovelace - av_premium, cont_datum),
        av_policy_output_prem(av_owner, 2_000_000_000),
        fixtures.pkh_output(av_team, 1_000_000),
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}

// ---------------------------------------------------------------------------
// Spend — positive
// ---------------------------------------------------------------------------

test av_spend_valid_accepted() {
  av_spend(av_datum(av_epoch_start, 0), av_good_tx())
}

test av_spend_new_epoch_resets_accumulator() {
  // now is past epoch_start + epoch_len: epoch resets, epoch_spent == spent.
  let now = av_epoch_start + av_epoch_len + 1_000
  let cont_datum = av_datum(now, av_premium)
  let tx =
    Transaction {
      ..transaction.placeholder,
      // prior epoch was nearly exhausted; the reset must clear it
      inputs: [
        av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 49_000_000)),
      ],
      outputs: [
        av_vault_cont(av_vault_lovelace - av_premium, cont_datum),
        av_policy_output(av_owner),
        fixtures.pkh_output(av_team, 1_000_000),
      ],
      validity_range: fixtures.finite_range(now, now + 300_000),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 49_000_000), tx)
}

// ---------------------------------------------------------------------------
// Spend — negative
// ---------------------------------------------------------------------------

test av_spend_without_agent_signature_rejected() {
  let tx = Transaction { ..av_good_tx(), extra_signatories: [av_owner] }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}

test av_spend_over_per_tx_cap_rejected() {
  // spend 25 ADA > 20 ADA per-tx cap.
  let big = 25_000_000
  let cont_datum = av_datum(av_epoch_start, big)
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [
        av_vault_cont(av_vault_lovelace - big, cont_datum),
        av_policy_output(av_owner),
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}

test av_spend_over_epoch_cap_rejected() {
  // already spent 48 ADA this epoch; +5 ADA = 53 > 50 ADA epoch cap.
  let cont_datum = av_datum(av_epoch_start, 53_000_000)
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [
        av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 48_000_000)),
      ],
      outputs: [
        av_vault_cont(av_vault_lovelace - av_premium, cont_datum),
        av_policy_output(av_owner),
        fixtures.pkh_output(av_team, 1_000_000),
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 48_000_000), tx) == False
}

test av_spend_tampered_caps_rejected() {
  // continuation raises per_tx_cap — must be rejected (caps are immutable).
  let cont_datum =
    AgentVaultDatum {
      ..av_datum(av_epoch_start, av_premium),
      per_tx_cap: 1_000_000_000,
    }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [
        av_vault_cont(av_vault_lovelace - av_premium, cont_datum),
        av_policy_output(av_owner),
        fixtures.pkh_output(av_team, 1_000_000),
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}

test av_spend_no_owner_policy_rejected() {
  // No policy output at all — the anti-laundering pin fails.
  let cont_datum = av_datum(av_epoch_start, av_premium)
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [
        av_vault_cont(av_vault_lovelace - av_premium, cont_datum),
        fixtures.pkh_output(av_team, 1_000_000),
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}

test av_spend_policy_pays_attacker_rejected() {
  // A policy output exists, but its payout goes to the attacker — the exact
  // laundering the datum pin exists to stop.
  let cont_datum = av_datum(av_epoch_start, av_premium)
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [
        av_vault_cont(av_vault_lovelace - av_premium, cont_datum),
        av_policy_output(fixtures.attacker_pkh),
        fixtures.pkh_output(av_team, 1_000_000),
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}

test av_spend_grafted_token_in_continuation_rejected() {
  let cont_datum = av_datum(av_epoch_start, av_premium)
  let grafted =
    assets.from_lovelace(av_vault_lovelace - av_premium)
      |> assets.add(fixtures.lp_token_policy_id, "aLP", 1)
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [
        Output {
          address: fixtures.script_addr(av_vault_hash),
          value: grafted,
          datum: InlineDatum(cont_datum),
          reference_script: None,
        },
        av_policy_output(av_owner),
        fixtures.pkh_output(av_team, 1_000_000),
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}

test av_spend_two_vaults_double_satisfaction_rejected() {
  let cont_datum = av_datum(av_epoch_start, av_premium)
  let second_vault =
    fixtures.make_input(
      fixtures.tx_id_one,
      0,
      fixtures.script_addr(av_vault_hash),
      assets.from_lovelace(av_vault_lovelace),
      InlineDatum(av_datum(av_epoch_start, 0)),
    )
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [
        av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0)),
        second_vault,
      ],
      outputs: [
        av_vault_cont(av_vault_lovelace - av_premium, cont_datum),
        av_policy_output(av_owner),
        fixtures.pkh_output(av_team, 1_000_000),
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}

// ---------------------------------------------------------------------------
// Spend — red-team regressions (PR #129)
// ---------------------------------------------------------------------------

// CRITICAL (proven, pre-fix ACCEPTED): a compromised agent routes the full
// per_tx_cap to an arbitrary attacker SCRIPT address while attaching a cheap
// valid owner marker-policy to satisfy the owner pin. The destination-agnostic
// spend bound `spent <= settled_premium + max_fee_leak` rejects it: spent = 20,
// settled premium = 1, max_fee_leak = 2 -> 20 > 3.
test av_spend_drain_to_attacker_script_rejected() {
  let cont_datum = av_datum(av_epoch_start, 20_000_000)
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [
        av_vault_cont(av_vault_lovelace - 20_000_000, cont_datum),
        // a cheap but valid owner marker-policy — clears the ceiling + owner pin
        av_policy_output_prem(av_owner, 1_000_000),
        // the drained cap lands at an unrelated attacker script
        Output {
          address: fixtures.script_addr(av_attacker_script),
          value: assets.from_lovelace(19_000_000),
          datum: NoDatum,
          reference_script: None,
        },
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}

// Same drain but to an attacker KEY (agent-change-style skim) — the spend bound
// is destination-agnostic, so this is rejected identically.
test av_spend_drain_to_attacker_key_rejected() {
  let cont_datum = av_datum(av_epoch_start, 20_000_000)
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [
        av_vault_cont(av_vault_lovelace - 20_000_000, cont_datum),
        av_policy_output_prem(av_owner, 1_000_000),
        fixtures.pkh_output(fixtures.attacker_pkh, 19_000_000),
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}

// HIGH-1 (proven, pre-fix ACCEPTED): a cheap NON-marker owner decoy appears
// BEFORE the real overcharged marker owner-policy. Pre-fix the ceiling read the
// first (decoy) and passed; the fix reads the marker-settled policy and rejects
// the overcharge.
test av_spend_ceiling_decoy_first_rejected() {
  let cont_datum = av_datum(av_epoch_start, av_premium)
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [
        av_vault_cont(av_vault_lovelace - av_premium, cont_datum),
        // decoy: cheap, owner-beneficiary, NO marker -> not the settled policy
        av_decoy_policy_output(av_owner, 1_000_000),
        // the REAL settled (marker) policy — a gross overcharge
        av_policy_output_prem(av_owner, 2_000_000_000),
        fixtures.pkh_output(av_team, 1_000_000),
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}

// A marker-bearing policy that pays a NON-owner is rejected (anti-laundering on
// the SETTLED policy, not just "some owner policy exists").
test av_spend_settled_policy_pays_attacker_rejected() {
  let cont_datum = av_datum(av_epoch_start, av_premium)
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [
        av_vault_cont(av_vault_lovelace - av_premium, cont_datum),
        av_policy_output_prem(fixtures.attacker_pkh, 1_000_000),
        fixtures.pkh_output(av_team, 1_000_000),
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}

// A spend with NO marker policy at all (only a decoy) is rejected — the pool
// never settled it, so there is no owner cover to justify the outflow.
test av_spend_no_marker_policy_rejected() {
  let cont_datum = av_datum(av_epoch_start, av_premium)
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [av_vault_input(av_vault_lovelace, av_datum(av_epoch_start, 0))],
      outputs: [
        av_vault_cont(av_vault_lovelace - av_premium, cont_datum),
        av_decoy_policy_output(av_owner, 1_000_000),
        fixtures.pkh_output(av_team, 1_000_000),
      ],
      validity_range: fixtures.finite_range(
        av_epoch_start + 1_000,
        av_epoch_start + 300_000,
      ),
      extra_signatories: [av_agent],
    }
  av_spend(av_datum(av_epoch_start, 0), tx) == False
}
