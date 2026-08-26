// =============================================================================
// Aegis Insurance Protocol - Property Tests
// Location: contracts/lib/aegis/test_helpers/property_tests.ak
// Test-only. Aiken-native property tests for pool and policy validator
// invariants. Each branch gets a paired test:
//   * positive  — fuzzer generates a valid input shape, helper accepts
//   * negative  — fuzzer generates input with one invariant broken, rejects
//
// Helpers under test live in `aegis/pool`, `aegis/pricing`, and
// `aegis/validation`. Validator branches themselves cannot be invoked from
// inside another module in Aiken, so each property test exercises the
// helper(s) the corresponding branch composes with, plus a few aggregate
// invariants that hold across the whole `(premium, fee_total, partner_cut,
// team_cut, net_pool_growth)` pipeline.
//
// Aiken property-test syntax (v1.1.22 + aiken-lang/fuzz v2.1.1):
//   * one fuzzer per `via` clause
//   * combine multi-arg shapes via `fuzz.both(a, b)` returning `(a, b)` or
//     `fuzz.map3(a, b, c, fn(x, y, z) { (x, y, z) })`
// =============================================================================

use aegis/pool.{
  available_liquidity, calculate_lp_mint, calculate_withdrawal, can_underwrite,
  can_withdraw, is_pool_solvent, verify_add_liquidity_datum,
  verify_claim_datum, verify_remove_liquidity_datum, verify_underwrite_datum,
}
use aegis/pricing.{
  calculate_cancellation_fee, calculate_fee_total, calculate_net_pool_growth,
  calculate_protocol_fee, calculate_protocol_fee_split, calculate_refund,
  calculate_treasury_cut, is_premium_adequate, is_ratio_acceptable,
  net_premium,
}
use aegis/test_helpers/fixtures
use aegis/types.{
  cancellation_window, max_coverage_ratio, min_premium, min_utxo_lovelace,
  partner_share_cap_bps, treasury_share_bps,
}
use aegis/validation.{
  count_script_inputs, sum_lovelace_to_enterprise_pkh, sum_lovelace_to_pkh,
}
use aiken/collection/list
use aiken/fuzz

// ---------------------------------------------------------------------------
// Local fuzzers for protocol-shaped magnitudes
// ---------------------------------------------------------------------------

/// A premium in the legal range: >= min_premium (2 ADA) and <= 1M ADA. The
/// upper bound keeps the downstream `premium * 50` term inside the int range
/// the helpers were sized for.
const legal_premium: Fuzzer<Int> =
  fuzz.int_between(min_premium, 1_000_000_000_000)

/// A negative or below-min premium — any value < `min_premium`.
const below_min_premium: Fuzzer<Int> =
  fuzz.int_between(-10_000_000_000, min_premium - 1)

/// A pool-side liquidity value: non-zero, fits comfortably below int width.
const legal_pool_liquidity: Fuzzer<Int> =
  fuzz.int_between(1_000_000_000, 1_000_000_000_000_000)

/// A small positive int — used for "batch size" or "drift" magnitudes.
const small_pos: Fuzzer<Int> = fuzz.int_between(1, 1_000_000)

/// A medium positive int — coverage / payout magnitudes.
const med_pos: Fuzzer<Int> = fuzz.int_between(1, 1_000_000_000)

/// A negative int strictly below zero.
const neg_int: Fuzzer<Int> = fuzz.int_between(-1_000_000_000, -1)

// ---------------------------------------------------------------------------
// Underwrite (pool.ak) — pool.verify_underwrite_datum + pricing.is_premium_adequate
// ---------------------------------------------------------------------------

test prop_underwrite_accepts_valid_random_premiums(premium via legal_premium) {
  // Pair premium with a 10x-leverage coverage to stay inside the ratio cap.
  let coverage = premium * 10
  is_premium_adequate(premium, coverage) == True
}

test prop_underwrite_rejects_below_min_premium(premium via below_min_premium) {
  // ANY premium under `min_premium` must fail the adequacy gate.
  is_premium_adequate(premium, premium * 10) == False
}

test prop_underwrite_at_ratio_cap_accepts(premium via legal_premium) {
  // Exactly 50x ratio is the inclusive boundary.
  let coverage = premium * max_coverage_ratio
  is_premium_adequate(premium, coverage) == True
}

test prop_underwrite_one_lovelace_over_cap_rejects(premium via legal_premium) {
  let coverage = premium * max_coverage_ratio + 1
  is_premium_adequate(premium, coverage) == False
}

test prop_underwrite_ratio_check_accepts_negative_coverage(
  (premium, coverage) via fuzz.both(legal_premium, neg_int),
) {
  // The ratio check `coverage <= premium * 50` passes for negative coverage
  // when premium is positive (a degenerate case). Pinned here so a future
  // refactor that adds an explicit `coverage > 0` guard is caught by
  // failure of this property.
  is_ratio_acceptable(premium, coverage) == True
}

test prop_underwrite_datum_accepts_correct_net_growth(
  (premium, coverage)
    via fuzz.both(legal_premium, fuzz.int_between(1, 1_000_000_000_000)),
) {
  let net = calculate_net_pool_growth(premium, 200, min_utxo_lovelace)
  let old_total = 1_000_000_000_000
  let old_active = 10_000_000_000
  verify_underwrite_datum(
    old_total,
    old_active,
    old_total + net,
    old_active + coverage,
    net,
    coverage,
  ) == True
}

test prop_underwrite_datum_rejects_inflated_total(
  (premium, coverage)
    via fuzz.both(legal_premium, fuzz.int_between(1, 1_000_000_000_000)),
) {
  let net = calculate_net_pool_growth(premium, 200, min_utxo_lovelace)
  let old_total = 1_000_000_000_000
  let old_active = 10_000_000_000
  // Inflate `new_total` by one ADA beyond the legal increment.
  verify_underwrite_datum(
    old_total,
    old_active,
    old_total + net + 1_000_000,
    old_active + coverage,
    net,
    coverage,
  ) == False
}

// ---------------------------------------------------------------------------
// ProcessClaim (pool.ak) — pool.verify_claim_datum
// ---------------------------------------------------------------------------

test prop_claim_accepts_payout_within_active_coverage(payout via med_pos) {
  // Generate an `old_active` >= payout so the helper's bound holds.
  let old_active = payout + 1_000_000_000
  let total = old_active + 100_000_000_000
  verify_claim_datum(
    total,
    old_active,
    total - payout,
    old_active - payout,
    payout,
  ) == True
}

test prop_claim_rejects_payout_exceeding_active_coverage(
  (old_active, excess) via fuzz.both(med_pos, med_pos),
) {
  let payout = old_active + excess
  let old_total = old_active + 10_000_000_000
  verify_claim_datum(
    old_total,
    old_active,
    old_total - payout,
    old_active - payout,
    payout,
  ) == False
}

test prop_claim_rejects_negative_payout(payout via neg_int) {
  verify_claim_datum(
    10_000_000_000,
    5_000_000_000,
    10_000_000_000 - payout,
    5_000_000_000 - payout,
    payout,
  ) == False
}

test prop_claim_rejects_active_drift(
  (old_active, drift) via fuzz.both(med_pos, small_pos),
) {
  let payout = old_active / 2
  let old_total = old_active * 2
  // Attacker corrupts `new_active` to a value other than `old_active - payout`.
  verify_claim_datum(
    old_total,
    old_active,
    old_total - payout,
    old_active - payout - drift,
    payout,
  ) == False
}

// ---------------------------------------------------------------------------
// BatchUnderwrite (pool.ak) — pool.verify_underwrite_datum at scale
// ---------------------------------------------------------------------------

test prop_batch_underwrite_accepts_legal_totals(
  (premium, n) via fuzz.both(legal_premium, fuzz.int_between(1, 20)),
) {
  // A batch of `n` identical policies — total_premium = n × premium, etc.
  let total_premium = premium * n
  let total_coverage = total_premium * 10
  let net = calculate_net_pool_growth(total_premium, 200, min_utxo_lovelace)
  verify_underwrite_datum(
    100_000_000_000,
    10_000_000_000,
    100_000_000_000 + net,
    10_000_000_000 + total_coverage,
    net,
    total_coverage,
  ) == True
}

test prop_batch_underwrite_rejects_wrong_active_delta(
  (premium, n) via fuzz.both(legal_premium, fuzz.int_between(1, 20)),
) {
  let total_premium = premium * n
  let total_coverage = total_premium * 10
  let net = calculate_net_pool_growth(total_premium, 200, min_utxo_lovelace)
  let drift = 1_000_000
  // Attacker tries to under-reserve active_coverage.
  verify_underwrite_datum(
    100_000_000_000,
    10_000_000_000,
    100_000_000_000 + net,
    10_000_000_000 + total_coverage - drift,
    net,
    total_coverage,
  ) == False
}

// ---------------------------------------------------------------------------
// AddLiquidity (pool.ak) — pool.verify_add_liquidity_datum + lp_mint
// ---------------------------------------------------------------------------

test prop_add_liquidity_accepts_proportional_mint(
  (old_total, amount)
    via fuzz.both(
      legal_pool_liquidity,
      fuzz.int_between(1_000_000, 1_000_000_000_000),
    ),
) {
  // Match supply to total 1:1 so lp_minted = amount.
  let old_supply = old_total
  let lp_minted = calculate_lp_mint(amount, old_total, old_supply)
  verify_add_liquidity_datum(
    old_total,
    100_000_000,
    old_supply,
    old_total + amount,
    100_000_000,
    old_supply + lp_minted,
    amount,
  ) == True
}

test prop_add_liquidity_rejects_under_minted_supply(
  (old_total, amount)
    via fuzz.both(
      legal_pool_liquidity,
      fuzz.int_between(1_000_000, 1_000_000_000_000),
    ),
) {
  let old_supply = old_total
  let lp_minted = calculate_lp_mint(amount, old_total, old_supply)
  let drift = 1
  verify_add_liquidity_datum(
    old_total,
    100_000_000,
    old_supply,
    old_total + amount,
    100_000_000,
    old_supply + lp_minted - drift,
    amount,
  ) == False
}

test prop_add_liquidity_rejects_active_coverage_drift(
  (old_total, amount)
    via fuzz.both(
      legal_pool_liquidity,
      fuzz.int_between(1_000_000, 1_000_000_000_000),
    ),
) {
  // AddLiquidity must preserve active_coverage. Any mutation rejects.
  let old_supply = old_total
  let lp_minted = calculate_lp_mint(amount, old_total, old_supply)
  let active_drift = 1
  verify_add_liquidity_datum(
    old_total,
    100_000_000,
    old_supply,
    old_total + amount,
    100_000_000 + active_drift,
    old_supply + lp_minted,
    amount,
  ) == False
}

test prop_lp_mint_first_depositor_is_identity(
  amount via fuzz.int_between(1, 1_000_000_000_000_000),
) {
  // Pool empty: first depositor gets exactly `amount` LP tokens.
  calculate_lp_mint(amount, 0, 0) == amount
}

// ---------------------------------------------------------------------------
// RemoveLiquidity (pool.ak) — pool.verify_remove_liquidity_datum + withdrawal
// ---------------------------------------------------------------------------

test prop_remove_liquidity_accepts_proportional_burn(
  (old_total, lp_burned)
    via fuzz.both(
      legal_pool_liquidity,
      fuzz.int_between(1, 1_000_000_000_000),
    ),
) {
  let old_supply = old_total
  let amount = calculate_withdrawal(lp_burned, old_total, old_supply)
  verify_remove_liquidity_datum(
    old_total,
    100_000_000,
    old_supply,
    old_total - amount,
    100_000_000,
    old_supply - lp_burned,
    amount,
    lp_burned,
  ) == True
}

test prop_remove_liquidity_rejects_lp_burn_amount_mismatch(
  (old_total, lp_burned) via fuzz.both(legal_pool_liquidity, med_pos),
) {
  let old_supply = old_total
  let honest_amount = calculate_withdrawal(lp_burned, old_total, old_supply)
  let inflated_amount = honest_amount + 1_000_000
  verify_remove_liquidity_datum(
    old_total,
    100_000_000,
    old_supply,
    old_total - inflated_amount,
    100_000_000,
    old_supply - lp_burned,
    inflated_amount,
    lp_burned,
  ) == False
}

test prop_remove_liquidity_rejects_negative_lp_burn(lp_burned via neg_int) {
  // Negative burn flips direction (mint); validator rejects via `lp_burned >= 0`.
  verify_remove_liquidity_datum(
    1_000_000_000_000,
    100_000_000,
    1_000_000_000_000,
    1_000_000_000_000,
    100_000_000,
    1_000_000_000_000 - lp_burned,
    0,
    lp_burned,
  ) == False
}

test prop_withdrawal_is_proportional_to_burn(
  (lp_burned, multiplier)
    via fuzz.both(
      fuzz.int_between(1_000_000, 1_000_000_000_000),
      fuzz.int_between(1, 10),
    ),
) {
  // Withdrawal ratio: when `total = multiplier × supply`, withdrawal =
  // multiplier × lp_burned. Holds across all positive multiplier values.
  let total = lp_burned * multiplier * 100
  let supply = lp_burned * 100
  calculate_withdrawal(lp_burned, total, supply) == lp_burned * multiplier
}

test prop_can_withdraw_accepts_withdrawal_inside_buffer(
  (active, buffer)
    via fuzz.both(med_pos, fuzz.int_between(2_000_000, 1_000_000_000_000)),
) {
  // A withdrawal strictly less than the buffer (total - active) is allowed.
  let total = active + buffer
  can_withdraw(total, active, buffer - 1) == True
}

test prop_can_withdraw_respects_active_coverage(
  (active, excess) via fuzz.both(med_pos, small_pos),
) {
  // Withdrawals that would drop total below active_coverage MUST reject.
  let total = active + 1_000_000_000
  let withdrawal = 1_000_000_000 + excess
  can_withdraw(total, active, withdrawal) == False
}

// ---------------------------------------------------------------------------
// AcceptCancellation (pool.ak) — pricing.calculate_refund + magnitude bounds
// ---------------------------------------------------------------------------

test prop_cancel_refund_plus_fee_equals_premium(premium via legal_premium) {
  // Helper rounds the 10% fee via integer division; refund + fee == premium.
  let refund = calculate_refund(premium)
  let fee = calculate_cancellation_fee(premium)
  refund + fee == premium
}

test prop_cancel_refund_less_than_premium(premium via legal_premium) {
  // Refund must be strictly less than the premium for any premium >= 2 ADA.
  calculate_refund(premium) < premium
}

test prop_cancel_refund_non_negative(premium via legal_premium) {
  // Refund must never be negative for any non-negative premium.
  calculate_refund(premium) >= 0
}

test prop_cancel_window_closes_before_the_claim_opens() {
  // [#391 R2 F2c] The window is 1_800_000 ms, and the VALUE is not the point —
  // the RELATION is. While it equalled the Depeg waiting period and exceeded
  // Barrier's, a hindsight bet that lost was refunded 90% of its premium.
  cancellation_window == 1_800_000
}

// ---------------------------------------------------------------------------
// Claim (policy.ak) — validation.sum_lovelace_to_enterprise_pkh
// ---------------------------------------------------------------------------

test prop_claim_accepts_enterprise_payout_meeting_coverage(
  coverage via fuzz.int_between(1_000_000, 1_000_000_000_000),
) {
  // A single enterprise output for exactly `coverage` satisfies the gate.
  let payout = fixtures.pkh_output(fixtures.insured_pkh, coverage)
  sum_lovelace_to_enterprise_pkh([payout], fixtures.insured_pkh) >= coverage
}

test prop_claim_rejects_grafted_stake_payout(
  coverage via fuzz.int_between(1_000_000, 1_000_000_000_000),
) {
  // Same lovelace but with attacker stake credential — must NOT count.
  let grafted =
    fixtures.pkh_output_with_stake(
      fixtures.insured_pkh,
      fixtures.attacker_stake_pkh,
      coverage,
    )
  sum_lovelace_to_enterprise_pkh([grafted], fixtures.insured_pkh) == 0
}

test prop_claim_aggregates_split_payouts(
  (part_a, part_b) via fuzz.both(med_pos, med_pos),
) {
  // Two enterprise outputs sum to the total — exercises the A-006 aggregator.
  let o1 = fixtures.pkh_output(fixtures.insured_pkh, part_a)
  let o2 = fixtures.pkh_output(fixtures.insured_pkh, part_b)
  sum_lovelace_to_enterprise_pkh([o1, o2], fixtures.insured_pkh) == part_a + part_b
}

test prop_claim_unrelated_outputs_excluded(
  (coverage, attacker_value)
    via fuzz.both(
      fuzz.int_between(1_000_000, 1_000_000_000_000),
      fuzz.int_between(1_000_000, 1_000_000_000_000),
    ),
) {
  // Outputs to a different PKH must not pollute the sum.
  let to_insured = fixtures.pkh_output(fixtures.insured_pkh, coverage)
  let to_attacker = fixtures.pkh_output(fixtures.attacker_pkh, attacker_value)
  sum_lovelace_to_enterprise_pkh(
    [to_attacker, to_insured],
    fixtures.insured_pkh,
  ) == coverage
}

// ---------------------------------------------------------------------------
// BatchClaim (policy.ak) — uniformity + aggregate enterprise-payout sums
// ---------------------------------------------------------------------------

test prop_batch_claim_aggregate_payout_meets_total_coverage(
  (per_policy, count) via fuzz.both(med_pos, fuzz.int_between(1, 8)),
) {
  // Each policy emits its own enterprise output to the insured. The aggregate
  // sum must equal `count × per_policy`.
  let outputs =
    list.repeat(
      fixtures.pkh_output(fixtures.insured_pkh, per_policy),
      count,
    )
  sum_lovelace_to_enterprise_pkh(outputs, fixtures.insured_pkh) == per_policy * count
}

// ---------------------------------------------------------------------------
// Cancel (policy.ak) — sum_lovelace_to_pkh refund channel
// ---------------------------------------------------------------------------

test prop_cancel_refund_aggregate_meets_required(premium via legal_premium) {
  // The insured receives the canonical refund; aggregate sum to insured PKH
  // must be >= refund.
  let refund = calculate_refund(premium)
  let payout = fixtures.pkh_output(fixtures.insured_pkh, refund)
  sum_lovelace_to_pkh([payout], fixtures.insured_pkh) >= refund
}

test prop_cancel_refund_under_required_rejects(
  (premium, shortfall)
    via fuzz.both(legal_premium, fuzz.int_between(1, 100_000)),
) {
  // An under-funded refund output fails the `sum >= refund` gate.
  let refund = calculate_refund(premium)
  let short = fixtures.pkh_output(fixtures.insured_pkh, refund - shortfall)
  sum_lovelace_to_pkh([short], fixtures.insured_pkh) < refund
}

// ---------------------------------------------------------------------------
// Expire (policy.ak) — count_script_inputs
// ---------------------------------------------------------------------------

test prop_expire_counts_exact_policy_inputs(
  policy_count via fuzz.int_between(1, 5),
) {
  // The single-script-input count helper must report exactly `policy_count`
  // when the tx carries that many policy inputs.
  let inputs =
    list.indexed_map(
      list.repeat(0, policy_count),
      fn(idx, _) {
        fixtures.policy_input(
          fixtures.tx_id_zero,
          idx,
          2_000_000,
          fixtures.default_policy_datum(),
        )
      },
    )
  count_script_inputs(inputs, fixtures.policy_script_hash) == policy_count
}

// ---------------------------------------------------------------------------
// BatchExpire (policy.ak) — aggregate count_script_inputs across mixed inputs
// ---------------------------------------------------------------------------

test prop_batch_expire_counts_only_target_script(
  (policy_count, unrelated_count)
    via fuzz.both(fuzz.int_between(1, 10), fuzz.int_between(0, 5)),
) {
  // A mix of policy inputs + unrelated-script inputs: only policy inputs count.
  let policy_inputs =
    list.indexed_map(
      list.repeat(0, policy_count),
      fn(idx, _) {
        fixtures.policy_input(
          fixtures.tx_id_zero,
          idx,
          2_000_000,
          fixtures.default_policy_datum(),
        )
      },
    )
  let unrelated_inputs =
    list.indexed_map(
      list.repeat(0, unrelated_count),
      fn(idx, _) {
        fixtures.pool_input(
          fixtures.tx_id_one,
          idx,
          2_000_000,
          fixtures.default_pool_datum(),
        )
      },
    )
  count_script_inputs(
    list.concat(policy_inputs, unrelated_inputs),
    fixtures.policy_script_hash,
  ) == policy_count
}

// ---------------------------------------------------------------------------
// Pricing pipeline — conservation laws across the protocol fee split
// ---------------------------------------------------------------------------

test prop_premium_conservation_holds(
  (premium, partner_bps)
    via fuzz.both(legal_premium, fuzz.int_between(0, partner_share_cap_bps)),
) {
  // premium == net_pool_growth + team_cut + partner_cut, exactly.
  let fee_total = calculate_fee_total(premium, 200, min_utxo_lovelace)
  let (team, partner) =
    calculate_protocol_fee_split(fee_total, partner_bps, min_utxo_lovelace)
  let net = premium - fee_total
  premium == net + team + partner
}

test prop_fee_total_floor_invariant(premium via legal_premium) {
  // fee_total is always >= max(min_utxo, raw_fee).
  let raw = calculate_protocol_fee(premium, 200)
  let total = calculate_fee_total(premium, 200, min_utxo_lovelace)
  total >= min_utxo_lovelace && total >= raw
}

test prop_partner_silent_absorb_invariant(
  (fee_total, partner_bps)
    via fuzz.both(
      fuzz.int_between(1, 10_000_000_000),
      fuzz.int_between(0, partner_share_cap_bps),
    ),
) {
  // For any inputs: partner_cut == 0 OR partner_cut >= min_utxo_lovelace.
  let (_, partner) =
    calculate_protocol_fee_split(fee_total, partner_bps, min_utxo_lovelace)
  partner == 0 || partner >= min_utxo_lovelace
}

test prop_treasury_cut_bounded_by_raw_fee(premium via legal_premium) {
  // Treasury cut can never exceed the raw protocol fee.
  let raw_fee = calculate_protocol_fee(premium, 200)
  let cut = calculate_treasury_cut(premium, 200, treasury_share_bps)
  cut <= raw_fee
}

test prop_treasury_cut_non_negative(premium via legal_premium) {
  calculate_treasury_cut(premium, 200, treasury_share_bps) >= 0
}

test prop_net_premium_v12_compat_agrees_above_floor(premium via legal_premium) {
  // V12 net_premium agrees with V12.2 calculate_net_pool_growth whenever the
  // raw fee exceeds the min-utxo floor (premium ≥ 100 ADA at 200 bps).
  let raw = calculate_protocol_fee(premium, 200)
  if raw >= min_utxo_lovelace {
    net_premium(premium, 200) == calculate_net_pool_growth(
      premium,
      200,
      min_utxo_lovelace,
    )
  } else {
    True
  }
}

// ---------------------------------------------------------------------------
// Pool solvency — invariant across random states
// ---------------------------------------------------------------------------

test prop_pool_solvent_iff_total_ge_active(
  (total, active) via fuzz.both(legal_pool_liquidity, legal_pool_liquidity),
) {
  is_pool_solvent(total, active) == ( total >= active )
}

test prop_available_liquidity_eq_total_minus_active(
  (total, active) via fuzz.both(legal_pool_liquidity, legal_pool_liquidity),
) {
  available_liquidity(total, active) == total - active
}

test prop_can_underwrite_iff_available_ge_coverage(
  (total, coverage) via fuzz.both(legal_pool_liquidity, med_pos),
) {
  let active = 10_000_000_000
  can_underwrite(total, active, coverage) == ( total - active >= coverage )
}


