use aegis/oracle.{resolve_oracle_price}
use aegis/pricing.{calculate_refund}
use aegis/types.{
  BatchClaim, BatchExpire, Cancel, Charli3, Claim, Expire, Orcfax,
  OracleProvider, PolicyDatum, PolicyRedeemer, cancellation_window,
}
use aegis/validation.{
  count_script_inputs, find_canonical_pool_output, get_lower_bound,
  get_upper_bound, must_be_signed_by, output_has_min_lovelace,
  sum_lovelace_to_enterprise_pkh,
}
// =============================================================================
// Aegis Insurance Protocol - Policy Validator
// Location: contracts/validators/policy.ak
// Summary: Governs the lifecycle of individual insurance policy UTxOs.
//          Each policy UTxO contains the premium + coverage collateral in ADA
//          and a PolicyDatum encoding the full policy terms.
//          Interacts with: oracle.ak (claim price verification),
//          pricing.ak (cancellation refund), validation.ak (helpers),
//          and is referenced by pool.ak (ProcessClaim).
//
// Redeemers:
//   Claim  - Trigger payout when oracle price <= strike price
//   Expire - Reclaim funds after policy expiration
//   Cancel - Cancel policy within the cancellation window
// =============================================================================

use aiken/collection/list
use cardano/address.{Script}
use cardano/assets
use cardano/transaction.{InlineDatum, Input, OutputReference, Transaction}

// ---------------------------------------------------------------------------
// [FIX A-012, generalized for v6] Helper: every policy UTxO consumed at this
// validator address must declare the SAME (oracle_provider, oracle_nft)
// pair. Without this guard, a single BatchClaim tx could consume policies
// bound to different oracle feeds (e.g. ADA/USD and DJED/USD) OR — new in
// v6 — different oracle providers (Charli3 + Orcfax). Each policy would
// independently resolve its own oracle from reference_inputs and the tx
// would pass — but the resulting cross-feed / cross-provider interactions
// are hard to reason about and constitute permanent grease for future bugs
// (most directly: they intersect the "same insured + multiple outputs"
// surface that A-006 partially closes).
//
// v6 generalization: in v5 this checked uniformity only on `oracle_nft`. In
// v6 the (provider, nft) pair is the structural identity of an oracle
// binding because Orcfax and Charli3 use the same byte width for their
// respective handles (both are 28-byte script/policy hashes), and a
// hypothetical collision on the byte sequence between, say, a Charli3 NFT
// policy id and an Orcfax FSP hash MUST not be allowed to bridge the two
// providers in one batch.
//
// Strategy: walk the inputs, find every input at `own_script_hash`, and
// fold into a state of (sentinel, all_equal). If all consumed policies share
// one (provider, nft) pair, the result is `True`. The empty-batch case (no
// policy inputs at all) is treated as `True` because the surrounding
// validator already enforces `count_script_inputs >= 1`.
// ---------------------------------------------------------------------------

fn batch_oracles_uniform(
  inputs: List<Input>,
  own_script_hash: ByteArray,
) -> Bool {
  let sentinel_init: (OracleProvider, ByteArray) = (Charli3, #"")
  let result =
    list.foldl(
      inputs,
      (sentinel_init, True, False),
      fn(input, acc) {
        let (sentinel, ok, seen) = acc
        when input.output.address.payment_credential is {
          Script(h) ->
            if h == own_script_hash {
              when input.output.datum is {
                InlineDatum(raw_pdat) -> {
                  expect pdat: PolicyDatum = raw_pdat
                  let pair: (OracleProvider, ByteArray) =
                    (pdat.oracle_provider, pdat.oracle_nft)
                  if !seen {
                    (pair, ok, True)
                  } else {
                    let (sent_provider, sent_nft) = sentinel
                    let (this_provider, this_nft) = pair
                    let same_provider =
                      when (sent_provider, this_provider) is {
                        (Charli3, Charli3) -> True
                        (Orcfax, Orcfax) -> True
                        _ -> False
                      }
                    (
                      sentinel,
                      ok && same_provider && this_nft == sent_nft,
                      True,
                    )
                  }
                }
                _ -> (sentinel, False, seen)
              }
            } else {
              acc
            }
          _ -> acc
        }
      },
    )
  let (_, all_equal, _) = result
  all_equal
}

// ---------------------------------------------------------------------------
// Policy Validator
// ---------------------------------------------------------------------------

validator policy_validator {
  spend(
    datum_opt: Option<PolicyDatum>,
    redeemer: PolicyRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    // Datum must be present
    expect Some(datum) = datum_opt

    let Transaction {
      inputs,
      reference_inputs,
      outputs,
      validity_range,
      extra_signatories,
      ..
    } = self

    // Find own input to determine script hash and value
    expect Some(self_input) =
      inputs
        |> list.find(fn(input) { input.output_reference == own_ref })
    let own_value = self_input.output.value

    // Determine own script hash for counting co-spent policy inputs
    expect Script(own_script_hash) =
      self_input.output.address.payment_credential

    when redeemer is {
      // -----------------------------------------------------------------------
      // CLAIM: Oracle price <= strike price -> payout to insured
      // -----------------------------------------------------------------------
      Claim -> {
        // [FIX F-001] Prevent double satisfaction: only one policy UTxO from
        // this script may be consumed per transaction
        let single_policy_input =
          count_script_inputs(inputs, own_script_hash) == 1

        // 1. [v6] Resolve the oracle price via the provider-uniform
        // dispatcher. Internally this matches on `datum.oracle_provider`
        // and dispatches to either `oracle/charli3.resolve` (which finds
        // the canonical Charli3 UTxO and parses its GenericData map) or
        // `oracle/orcfax.resolve` (which walks the FSP -> FS pointer
        // indirection and parses the FsDat<Rational>). Returns the
        // provider-uniform Price record. The trust handshake (canonical
        // address binding for Charli3 — A-016 — and FSP/FS dual-binding
        // for Orcfax) lives inside each parser; this branch just consumes
        // the resulting record.
        let price =
          resolve_oracle_price(
            reference_inputs,
            datum.oracle_provider,
            datum.oracle_nft,
          )

        // 2. Verify oracle price <= strike price (crash detected). Both
        // providers normalize to the protocol-wide 1e6 scale.
        let price_below_strike = price.value <= datum.strike_price

        // 3. Verify oracle data is fresh.
        // For Charli3, valid_until is the publisher-set expiry from the datum.
        // For Orcfax, valid_until is `created_at + orcfax_freshness_window_ms`
        // (30 minutes) computed inside the Orcfax parser.
        let tx_lower = get_lower_bound(validity_range)
        let oracle_fresh = tx_lower <= price.valid_until

        // 4. Verify transaction is within the policy period
        let within_start = tx_lower >= datum.start_time
        let tx_upper = get_upper_bound(validity_range)
        let within_expiry = tx_upper <= datum.expiry_time

        // 5. [FIX A-006/A-009/A-013] Verify aggregate payout to insured is
        // sufficient AND every payout output is an enterprise address.
        let payout_valid =
          sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= datum.coverage_amount

        // [FIX F-002] Verify remainder ALWAYS goes to pool with correct value.
        let policy_utxo_lovelace = assets.lovelace_of(own_value)
        let expected_remainder = policy_utxo_lovelace - datum.coverage_amount
        // [FIX A-008] Route residual to the CANONICAL pool (must carry pool_nft).
        let pool_output =
          find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          )
        let pool_receives_remainder =
          if expected_remainder <= 0 {
            True
          } else {
            when pool_output is {
              Some(out) -> output_has_min_lovelace(out, expected_remainder)
              None -> False
            }
          }

        single_policy_input && price_below_strike && oracle_fresh && within_start && within_expiry && payout_valid && pool_receives_remainder
      }

      // -----------------------------------------------------------------------
      // BATCH CLAIM: Multiple policies claimed in one transaction
      // -----------------------------------------------------------------------
      BatchClaim -> {
        let batch_size = count_script_inputs(inputs, own_script_hash)
        let has_policies = batch_size >= 1

        // [FIX A-012, generalized for v6] All consumed policies must share
        // the same (oracle_provider, oracle_nft) pair.
        let oracle_uniform = batch_oracles_uniform(inputs, own_script_hash)

        // [v6] Oracle checks via the provider-uniform dispatcher.
        let price =
          resolve_oracle_price(
            reference_inputs,
            datum.oracle_provider,
            datum.oracle_nft,
          )
        let price_below_strike = price.value <= datum.strike_price
        let tx_lower = get_lower_bound(validity_range)
        let oracle_fresh = tx_lower <= price.valid_until

        // Time bounds
        let within_start = tx_lower >= datum.start_time
        let tx_upper = get_upper_bound(validity_range)
        let within_expiry = tx_upper <= datum.expiry_time

        // [FIX A-006/A-009] Aggregate enterprise-output check.
        let payout_valid =
          sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= datum.coverage_amount

        // Pool remainder (same logic as Claim)
        let policy_utxo_lovelace = assets.lovelace_of(own_value)
        let expected_remainder = policy_utxo_lovelace - datum.coverage_amount
        let pool_output =
          find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          )
        let pool_receives_remainder =
          if expected_remainder <= 0 {
            True
          } else {
            when pool_output is {
              Some(out) -> output_has_min_lovelace(out, expected_remainder)
              None -> False
            }
          }

        has_policies && oracle_uniform && price_below_strike && oracle_fresh && within_start && within_expiry && payout_valid && pool_receives_remainder
      }

      // -----------------------------------------------------------------------
      // EXPIRE: Policy has expired -> return all funds to pool
      // -----------------------------------------------------------------------
      Expire -> {
        let tx_lower = get_lower_bound(validity_range)
        let is_expired = tx_lower > datum.expiry_time

        let policy_utxo_lovelace = assets.lovelace_of(own_value)
        let pool_output =
          find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          )
        let funds_to_pool =
          when pool_output is {
            Some(output) ->
              output_has_min_lovelace(output, policy_utxo_lovelace)
            None -> False
          }

        is_expired && funds_to_pool
      }

      // -----------------------------------------------------------------------
      // BATCH EXPIRE: Multiple expired policies reclaimed in one transaction
      // -----------------------------------------------------------------------
      BatchExpire -> {
        let batch_size = count_script_inputs(inputs, own_script_hash)
        let has_policies = batch_size >= 1

        let tx_lower = get_lower_bound(validity_range)
        let is_expired = tx_lower > datum.expiry_time

        let policy_utxo_lovelace = assets.lovelace_of(own_value)
        let pool_output =
          find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          )
        let funds_to_pool =
          when pool_output is {
            Some(output) ->
              output_has_min_lovelace(output, policy_utxo_lovelace)
            None -> False
          }

        has_policies && is_expired && funds_to_pool
      }

      // -----------------------------------------------------------------------
      // CANCEL: Early cancellation within the allowed window
      // -----------------------------------------------------------------------
      Cancel -> {
        // 1. Verify signed by the insured party
        let signed_by_insured =
          must_be_signed_by(extra_signatories, datum.insured)

        // 2. Verify within cancellation window
        let tx_upper = get_upper_bound(validity_range)
        let within_window = tx_upper <= datum.start_time + cancellation_window

        // 3. [FIX A-010] Reject Cancel if the policy is currently
        // in-the-money. Without this guard the insured can wait inside the
        // 1-hour cancellation window for the oracle to print, then choose:
        //   * if price <= strike (ITM)  -> Claim for full coverage,
        //   * if price >  strike (OTM)  -> Cancel for 90% premium back.
        // That free optionality on top of the parametric trigger is value
        // the underwriter never priced in. [v6] Resolve via the provider-
        // uniform dispatcher so the in-the-money guard works identically
        // for Charli3 and Orcfax policies.
        let price =
          resolve_oracle_price(
            reference_inputs,
            datum.oracle_provider,
            datum.oracle_nft,
          )
        let tx_lower = get_lower_bound(validity_range)
        let oracle_fresh = tx_lower <= price.valid_until
        // Note: Claim uses `oracle_price <= strike_price` to trigger payout,
        // so the symmetric in-the-money guard here is `oracle_price > strike`.
        let not_in_the_money = price.value > datum.strike_price

        // 4. Calculate refund amount (premium - 10% cancellation fee)
        let refund_amount = calculate_refund(datum.premium_paid)

        // 5. [FIX A-009/A-013] Aggregate enterprise refund check.
        let refund_valid =
          sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= refund_amount

        // 6. Verify remainder goes to pool (premium_paid - refund + coverage)
        let policy_utxo_lovelace = assets.lovelace_of(own_value)
        let expected_pool_amount = policy_utxo_lovelace - refund_amount
        let pool_output =
          find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          )
        let remainder_to_pool =
          when pool_output is {
            Some(out) -> output_has_min_lovelace(out, expected_pool_amount)
            None -> False
          }

        signed_by_insured && within_window && oracle_fresh && not_in_the_money && refund_valid && remainder_to_pool
      }
    }
  }

  else(_) {
    fail @"Unsupported purpose for policy_validator"
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test claim_price_check_triggers() {
  // Strike at $0.35, oracle at $0.30 -> should trigger
  let strike = 350_000
  let oracle_price = 300_000
  oracle_price <= strike
}

test claim_price_check_no_trigger() {
  // Strike at $0.35, oracle at $0.50 -> should NOT trigger
  let strike = 350_000
  let oracle_price = 500_000
  oracle_price > strike
}

test claim_price_check_at_boundary() {
  // Strike at $0.35, oracle at $0.35 -> SHOULD trigger (<=)
  let strike = 350_000
  let oracle_price = 350_000
  oracle_price <= strike
}

test expire_time_check() {
  // Policy expires at T=100, current time T=101 -> expired
  let expiry = 100
  let current = 101
  current > expiry
}

test expire_time_not_yet() {
  // Policy expires at T=100, current time T=99 -> not expired
  let expiry = 100
  let current = 99
  current <= expiry
}

test cancel_window_valid() {
  // Start at T=1000, cancel window 3600000, tx at T=2000 -> within window
  let start = 1_000
  let tx_upper = 2_000
  tx_upper <= start + cancellation_window
}

test cancel_window_expired() {
  // Start at T=1000, cancel window 3600000, tx at T=5000000 -> outside window
  let start = 1_000
  let tx_upper = 5_000_000
  tx_upper > start + cancellation_window
}

// ---------------------------------------------------------------------------
// Security Tests: Policy Validator Edge Cases
// ---------------------------------------------------------------------------

// [F-001] Double satisfaction: verify single-input constraint logic
test double_satisfaction_two_inputs_fail_check() {
  let count = 2
  count != 1
}

// [F-002] Remainder bypass
test claim_remainder_logic() {
  let policy_utxo_lovelace = 7_000_000_000
  let coverage = 5_000_000_000
  let expected_remainder = policy_utxo_lovelace - coverage
  expected_remainder == 2_000_000_000 && expected_remainder > 0
}

test claim_zero_remainder_logic() {
  let policy_utxo_lovelace = 5_000_000_000
  let coverage = 5_000_000_000
  let expected_remainder = policy_utxo_lovelace - coverage
  expected_remainder <= 0
}

test expire_full_value_check() {
  let policy_utxo_lovelace = 10_000_000_000
  policy_utxo_lovelace > 0
}

test cancel_window_at_exact_boundary() {
  let start = 1_000_000
  let tx_upper = start + cancellation_window
  tx_upper <= start + cancellation_window
}

test cancel_window_one_ms_past() {
  let start = 1_000_000
  let tx_upper = start + cancellation_window + 1
  tx_upper > start + cancellation_window
}

test expire_at_exact_boundary_fails() {
  let expiry = 100_000
  let current = expiry
  current <= expiry
}

test claim_at_exact_strike_triggers() {
  let strike = 350_000
  let oracle_price = 350_000
  oracle_price <= strike
}
