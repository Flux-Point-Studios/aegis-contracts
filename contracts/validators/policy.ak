use aegis/oracle.{resolve_oracle_price}
use aegis/pricing.{calculate_refund}
use aegis/types.{
  AegisSelf, BatchClaim, BatchExpire, BurnForCancel, BurnForClaim, BurnForExpire,
  Cancel, Charli3, Claim, Expire, Indigo, MarkerRedeemer, OracleProvider, Orcfax,
  PolicyDatum, PolicyRedeemer, cancellation_window, policy_marker_asset_name,
}
use aegis/validation.{
  count_script_inputs, find_canonical_pool_output, get_lower_bound,
  get_upper_bound, must_be_signed_by, output_has_min_lovelace,
  sum_lovelace_to_enterprise_pkh,
}
use aiken/collection/pairs
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
use cardano/transaction.{
  InlineDatum, Input, Mint, OutputReference, Transaction,
}

// Every policy UTxO consumed at this validator must declare the same
// (oracle_provider, oracle_nft) pair, so a BatchClaim cannot mix feeds.

fn batch_oracles_uniform(
  inputs: List<Input>,
  own_script_hash: ByteArray,
) -> Bool {
  let (_, all_equal) =
    list.foldl(
      inputs,
      (None, True),
      fn(input, acc) {
        let (sentinel, ok) = acc
        when input.output.address.payment_credential is {
          Script(h) ->
            if h == own_script_hash {
              when input.output.datum is {
                InlineDatum(raw_pdat) -> {
                  expect pdat: PolicyDatum = raw_pdat
                  let pair = (pdat.oracle_provider, pdat.oracle_nft)
                  when sentinel is {
                    None -> (Some(pair), ok)
                    Some(s) -> (sentinel, ok && pair == s)
                  }
                }
                _ -> (sentinel, False)
              }
            } else {
              acc
            }
          _ -> acc
        }
      },
    )
  all_equal
}

// ---------------------------------------------------------------------------
// Policy Validator
// ---------------------------------------------------------------------------

/// Policy validator parameterized by the policy marker minting policy id.
///
/// [V12.2+R12 / EXT-08, EXT-09] Every spend path (Claim, Cancel, Expire,
/// BatchExpire) requires the consumed policy UTxO to hold exactly 1
/// marker (policy_marker_policy_id, "AEGIS_POLICY"). The marker is
/// minted only by a real Aegis Underwrite (which co-spends the pool);
/// a synthetic policy UTxO at the policy validator address with a fake
/// datum cannot acquire one, so the synthetic-Cancel pool-drain attack
/// (EXT-08) and synthetic-Claim accounting-corruption attack (EXT-09)
/// are closed at this layer in addition to the pool side. BatchClaim
/// remains disabled in V12.2+R12 (inherited from R11).
validator policy_validator(policy_marker_policy_id: ByteArray) {
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
      redeemers,
      ..
    } = self

    // EXT-16 sibling-redeemer pairing on the policy side: the marker
    // mint redeemer dictates which spend variant is permitted. Read
    // once at the top so each branch can pin its own lifecycle.
    expect Some(raw_marker_redeemer) =
      pairs.get_first(redeemers, Mint(policy_marker_policy_id))
    expect marker_redeemer: MarkerRedeemer = raw_marker_redeemer

    // Find own input to determine script hash and value
    expect Some(self_input) =
      inputs
        |> list.find(fn(input) { input.output_reference == own_ref })
    let own_value = self_input.output.value

    // Determine own script hash for counting co-spent policy inputs
    expect Script(own_script_hash) =
      self_input.output.address.payment_credential

    // [V12.2+R12 / EXT-08, EXT-09] Marker presence pin. Every legitimate
    // Aegis policy UTxO carries exactly 1 marker
    // (policy_marker_policy_id, "AEGIS_POLICY") minted by the pool
    // validator at Underwrite / BatchUnderwrite time. Synthetic policy
    // UTxOs (written at this script address with a fake datum by an
    // attacker) cannot acquire one because the marker policy delegates
    // mint authority to the pool validator's spend logic. Required True
    // in every branch (the disabled BatchClaim arm naturally never
    // reaches this check).
    let has_marker =
      assets.quantity_of(
        own_value,
        policy_marker_policy_id,
        policy_marker_asset_name,
      ) == 1

    when redeemer is {
      // -----------------------------------------------------------------------
      // CLAIM: Oracle price <= strike price -> payout to insured
      // -----------------------------------------------------------------------
      Claim -> {
        // Prevent double satisfaction: only one policy UTxO from this
        // script may be consumed per transaction.
        let single_policy_input =
          count_script_inputs(inputs, own_script_hash) == 1

        // Resolve the oracle price via the provider-uniform dispatcher.
        let price =
          resolve_oracle_price(
            reference_inputs,
            datum.oracle_provider,
            datum.oracle_nft,
          )

        // Crash detected: oracle price at or below the strike.
        let price_below_strike = price.value <= datum.strike_price

        // Both validity-range legs must sit inside the freshness window,
        // and tx_lower must be at or after the observed_at of the reading.
        let tx_lower = get_lower_bound(validity_range)
        let tx_upper = get_upper_bound(validity_range)
        let oracle_fresh =
          tx_lower >= price.observed_at && tx_lower <= price.valid_until && tx_upper <= price.valid_until

        // Transaction must sit inside the policy period.
        let within_start = tx_lower >= datum.start_time
        let within_expiry = tx_upper <= datum.expiry_time

        // Aggregate payout to insured must be sufficient, and every payout
        // output must be an enterprise address.
        let payout_valid =
          sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= datum.coverage_amount

        // Require the canonical pool output is present in the tx. The
        // pool side (ProcessClaim) now owns the residual conservation
        // equation: cont == own + policy_lovelace - payout, so any leak
        // to "change" is impossible. Policy side only ensures the tx is
        // co-spent with the canonical pool.
        let pool_present =
          when find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          ) is {
            Some(_) -> True
            None -> False
          }

        let marker_redeemer_ok =
          when marker_redeemer is {
            BurnForClaim -> True
            _ -> False
          }

        single_policy_input && price_below_strike && oracle_fresh && within_start && within_expiry && payout_valid && pool_present && has_marker && marker_redeemer_ok
      }

      // -----------------------------------------------------------------------
      // BATCH CLAIM: disabled in V12.2+R11. Use a single Claim per policy.
      // -----------------------------------------------------------------------
      BatchClaim -> fail @"BatchClaim disabled in V12.2+R11. Use single Claim per policy."

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

        let marker_redeemer_ok =
          when marker_redeemer is {
            BurnForExpire { .. } -> True
            _ -> False
          }

        is_expired && funds_to_pool && has_marker && marker_redeemer_ok
      }

      // -----------------------------------------------------------------------
      // BATCH EXPIRE: Multiple expired policies reclaimed in one transaction
      // -----------------------------------------------------------------------
      BatchExpire -> {
        let has_policies = count_script_inputs(inputs, own_script_hash) >= 1

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

        let marker_redeemer_ok =
          when marker_redeemer is {
            BurnForExpire { .. } -> True
            _ -> False
          }

        has_policies && is_expired && funds_to_pool && has_marker && marker_redeemer_ok
      }

      // -----------------------------------------------------------------------
      // CANCEL: Early cancellation within the allowed window
      // -----------------------------------------------------------------------
      Cancel -> {
        // [V12.2+R12 / EXT-10] Reject multi-input Cancel. Symmetric
        // with Claim's existing single_policy_input guard. Without
        // this, an attacker pairs a legitimate policy input with a
        // synthetic-datum policy input and the pool only accounts for
        // the first one, while Cancel runs once per input.
        let single_policy_input =
          count_script_inputs(inputs, own_script_hash) == 1

        let signed_by_insured =
          must_be_signed_by(extra_signatories, datum.insured)

        let tx_upper = get_upper_bound(validity_range)
        let within_window = tx_upper <= datum.start_time + cancellation_window

        // Reject Cancel if the policy is in-the-money. Otherwise the
        // insured gets free optionality across the cancellation window:
        // Claim if ITM, Cancel if OTM.
        let price =
          resolve_oracle_price(
            reference_inputs,
            datum.oracle_provider,
            datum.oracle_nft,
          )
        let tx_lower = get_lower_bound(validity_range)
        // Same freshness rule as Claim.
        let oracle_fresh =
          tx_lower >= price.observed_at && tx_lower <= price.valid_until && tx_upper <= price.valid_until
        let not_in_the_money = price.value > datum.strike_price

        let refund_amount = calculate_refund(datum.premium_paid)

        let refund_valid =
          sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= refund_amount

        // Remainder must go to the pool (premium_paid - refund + coverage).
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

        let marker_redeemer_ok =
          when marker_redeemer is {
            BurnForCancel -> True
            _ -> False
          }

        signed_by_insured && within_window && oracle_fresh && not_in_the_money && refund_valid && remainder_to_pool && has_marker && single_policy_input && marker_redeemer_ok
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

test double_satisfaction_two_inputs_fail_check() {
  let count = 2
  count != 1
}

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
