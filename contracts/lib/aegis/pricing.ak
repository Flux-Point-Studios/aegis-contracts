// =============================================================================
// Aegis Insurance Protocol - On-Chain Pricing Validation
// Location: contracts/lib/aegis/pricing.ak
// Summary: On-chain premium adequacy checks. The full pricing calculation
//          happens off-chain; these functions validate that the submitted
//          premium meets minimum requirements.
//          Used by validators/pool.ak (Underwrite) and validators/policy.ak
//          (Cancel refund calculation).
// =============================================================================

use aegis/types.{max_coverage_ratio, min_premium}
use aiken/math

// ---------------------------------------------------------------------------
// Premium Validation
// ---------------------------------------------------------------------------

/// Verify that a premium meets the minimum threshold.
/// Minimum premium is 2 ADA (2_000_000 lovelace).
pub fn is_above_minimum(premium: Int) -> Bool {
  premium >= min_premium
}

/// Verify that the coverage-to-premium ratio does not exceed the maximum.
/// Maximum ratio is 50x (coverage cannot be more than 50x the premium).
/// This prevents extremely leveraged policies that could drain the pool.
///
/// [FIX A-014] Use multiplication-style comparison instead of integer
/// division. The previous `coverage / premium <= 50` truncated, allowing
/// `coverage = premium * 50 + 1` to slip through (e.g., premium=2 ADA,
/// coverage=100.000001 ADA → `100_000_001 / 2_000_000 = 50` truncated,
/// passes). Multiplication-form is exact: `coverage <= premium * 50`.
pub fn is_ratio_acceptable(premium: Int, coverage: Int) -> Bool {
  premium > 0 && coverage <= premium * max_coverage_ratio
}

/// Combined premium adequacy check.
/// Returns True only if premium meets ALL requirements:
/// 1. Premium >= minimum (2 ADA)
/// 2. Coverage / Premium <= max ratio (50x)
pub fn is_premium_adequate(premium: Int, coverage: Int) -> Bool {
  is_above_minimum(premium) && is_ratio_acceptable(premium, coverage)
}

// ---------------------------------------------------------------------------
// Protocol Fee Calculation (V12.2: Hybrid Fee — floor inside carve)
// ---------------------------------------------------------------------------

/// Calculate the raw (un-floored) protocol fee from a premium.
/// Fee is denominated in basis points (1 bp = 0.01%).
/// Example: 200 bps on 10 ADA premium = 0.2 ADA raw_fee.
///
/// V12.2 callers usually want `calculate_fee_total` instead (which applies
/// the min-utxo floor). This helper is the un-floored value, used for:
///   * The treasury-cut math (treasury_share_bps of the RAW fee).
///   * Off-chain analytics that want the "intended" fee separate from the
///     floor-padded value.
pub fn calculate_protocol_fee(premium: Int, fee_bps: Int) -> Int {
  premium * fee_bps / 10_000
}

/// [v12.2] Compute the floored fee_total: `max(min_utxo_lovelace, raw_fee)`.
///
/// V12.2's "Hybrid Fee" rule moves the 2-ADA min-utxo floor INSIDE the
/// carve, so the pool's value reduction equals exactly `fee_total` (not
/// just the percentage fee with a separate exogenous pad as in V12). The
/// user's outflow equals `premium + treasury_cut + tx_fee` (linear in
/// premium).
///
/// Trade-off vs V12: small premiums (below `min_utxo × 10_000 / fee_bps`
/// = 100 ADA at the default 200 bps) yield slightly less net_pool_growth
/// — the LP absorbs the floor cost. Premiums at or above 100 ADA see
/// `fee_total == raw_fee` (math identical to V12). See V12.2 spec §10.1.
pub fn calculate_fee_total(
  premium: Int,
  fee_bps: Int,
  min_utxo_lovelace: Int,
) -> Int {
  math.max(min_utxo_lovelace, calculate_protocol_fee(premium, fee_bps))
}

/// [v12.2] Compute the net pool growth: `premium − calculate_fee_total(...)`.
///
/// This is the lovelace delta the pool's continuation UTxO grows by on an
/// Underwrite tx (and the negative of what it decreases by on the cancel-
/// path extraction). Validator's `value_ok`:
///   cont_pool.lovelace == own.lovelace + calculate_net_pool_growth(...)
pub fn calculate_net_pool_growth(
  premium: Int,
  fee_bps: Int,
  min_utxo_lovelace: Int,
) -> Int {
  premium - calculate_fee_total(premium, fee_bps, min_utxo_lovelace)
}

/// [v12.2] DEPRECATED — V12.2 validators use `calculate_net_pool_growth`
/// instead. V11/V12 callers continue to read this for legacy analytics;
/// the function stays compiled so cross-version code paths keep working.
/// V11/V12 semantics: `premium − raw_fee` (no floor).
pub fn net_premium(premium: Int, fee_bps: Int) -> Int {
  premium - calculate_protocol_fee(premium, fee_bps)
}

// ---------------------------------------------------------------------------
// Treasury Donation Calculation
// ---------------------------------------------------------------------------

/// Calculate the lovelace cut of a premium routed to the Cardano protocol
/// treasury via the Conway-era `treasury_donation` body field. The cut is
/// taken from the existing protocol fee — it does NOT increase the user's
/// premium nor the LPs' loss budget. At the default pin (200 bps fee, 2500
/// bps treasury share), 0.5% of the premium flows to the treasury.
///
/// Two-stage division (`/ 10_000` twice) is deliberate: it matches the
/// rounding convention of `calculate_protocol_fee` and floors the result so
/// the lovelace lands with the user, not the treasury, on any non-divisible
/// remainder. Single-stage division `(premium * protocol_fee_bps *
/// treasury_share_bps / 100_000_000)` would also work but invites a mental-
/// arithmetic divergence between this helper and the protocol fee path.
pub fn calculate_treasury_cut(
  premium: Int,
  protocol_fee_bps: Int,
  treasury_share_bps: Int,
) -> Int {
  premium * protocol_fee_bps / 10_000 * treasury_share_bps / 10_000
}

/// [v12.2] Split a `fee_total` into team and partner cuts with silent
/// partner_cut absorb.
///
/// Returns `(team_cut, partner_cut)` such that:
///   `team_cut + partner_cut == fee_total` (always, exactly)
/// and
///   `partner_cut == 0 OR partner_cut >= min_utxo_lovelace` (silent absorb).
///
/// Silent absorb rule: when
///   `partner_cut_raw = fee_total × partner_share_bps / 10_000 < min_utxo_lovelace`,
/// the partner output is NOT emitted on chain and `team_cut` absorbs the
/// full `fee_total`. PolicyDatum still records `partner_address` and
/// `partner_share_bps` for off-chain analytics — the partner registry can
/// reconstruct "would have received" amounts from the datum + premium.
///
/// **V12.2 signature breaking change.** V12's helper took
/// `(premium, protocol_fee_bps, partner_share_bps)`; V12.2's takes
/// `(fee_total, partner_share_bps, min_utxo_lovelace)`. V12.2 wants the
/// floored `fee_total` to be computed once at the call site (so the
/// validator and off-chain math share the same input to the split), and
/// the silent absorb rule needs `min_utxo_lovelace` as input. Wave 2.5/2.6
/// updates the three validator branches in `validators/pool.ak`.
///
/// See V12.2 spec §10.3 for the absorb-security analysis.
pub fn calculate_protocol_fee_split(
  fee_total: Int,
  partner_share_bps: Int,
  min_utxo_lovelace: Int,
) -> (Int, Int) {
  let partner_cut_raw = fee_total * partner_share_bps / 10_000
  let partner_cut =
    if partner_cut_raw >= min_utxo_lovelace {
      partner_cut_raw
    } else {
      0
    }
  let team_cut = fee_total - partner_cut
  (team_cut, partner_cut)
}

// ---------------------------------------------------------------------------
// Cancellation Fee Calculation
// ---------------------------------------------------------------------------

/// Calculate the cancellation fee (10% of premium).
/// cancellation_fee_bps = 1000 (10%)
pub fn calculate_cancellation_fee(premium: Int) -> Int {
  premium * 1_000 / 10_000
}

/// Calculate the refund amount when a policy is cancelled.
/// Refund = premium - cancellation_fee
pub fn calculate_refund(premium: Int) -> Int {
  premium - calculate_cancellation_fee(premium)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test minimum_premium_met() {
  is_above_minimum(2_000_000) == True
}

test minimum_premium_exceeded() {
  is_above_minimum(5_000_000) == True
}

test minimum_premium_not_met() {
  is_above_minimum(1_999_999) == False
}

test minimum_premium_zero() {
  is_above_minimum(0) == False
}

test ratio_acceptable_low_leverage() {
  // 10 ADA premium, 100 ADA coverage -> 10x ratio
  is_ratio_acceptable(10_000_000, 100_000_000) == True
}

test ratio_acceptable_at_max() {
  // 10 ADA premium, 500 ADA coverage -> 50x ratio (exactly at max)
  is_ratio_acceptable(10_000_000, 500_000_000) == True
}

test ratio_unacceptable_over_max() {
  // 10 ADA premium, 510 ADA coverage -> 51x ratio (over max)
  is_ratio_acceptable(10_000_000, 510_000_000) == False
}

test ratio_unacceptable_zero_premium() {
  is_ratio_acceptable(0, 100_000_000) == False
}

test premium_adequate_valid() {
  // 5 ADA premium, 100 ADA coverage -> above min, 20x ratio
  is_premium_adequate(5_000_000, 100_000_000) == True
}

test premium_adequate_fails_minimum() {
  // 1 ADA premium, 10 ADA coverage -> below minimum
  is_premium_adequate(1_000_000, 10_000_000) == False
}

test premium_adequate_fails_ratio() {
  // 2 ADA premium, 200 ADA coverage -> 100x ratio
  is_premium_adequate(2_000_000, 200_000_000) == False
}

test protocol_fee_calculation() {
  // 200 bps (2%) on 10 ADA = 0.2 ADA = 200_000 lovelace
  calculate_protocol_fee(10_000_000, 200) == 200_000
}

test protocol_fee_zero_bps() {
  calculate_protocol_fee(10_000_000, 0) == 0
}

test protocol_fee_full() {
  // 10000 bps (100%) on 10 ADA = 10 ADA
  calculate_protocol_fee(10_000_000, 10_000) == 10_000_000
}

test net_premium_after_fee() {
  // 10 ADA premium, 200 bps fee -> 9.8 ADA net
  net_premium(10_000_000, 200) == 9_800_000
}

test cancellation_fee_calculation() {
  // 10% of 10 ADA = 1 ADA
  calculate_cancellation_fee(10_000_000) == 1_000_000
}

test refund_calculation() {
  // 10 ADA - 1 ADA fee = 9 ADA refund
  calculate_refund(10_000_000) == 9_000_000
}

test refund_small_premium() {
  // 2 ADA - 0.2 ADA fee = 1.8 ADA refund
  calculate_refund(2_000_000) == 1_800_000
}

// ---------------------------------------------------------------------------
// Security Tests: Premium Edge Cases
// ---------------------------------------------------------------------------

// [F-008] Negative premium should fail ratio check
test ratio_rejects_negative_premium() {
  is_ratio_acceptable(-1_000_000, 100_000_000) == False
}

// Verify that coverage / premium integer division can be exploited
// at the boundary: 50 * premium exactly equals coverage passes
test ratio_boundary_exactly_at_max() {
  // premium = 2 ADA, coverage = 100 ADA -> ratio = 50x (exactly at max)
  is_premium_adequate(2_000_000, 100_000_000) == True
}

// [F-008] Integer division truncation: 100_000_001 / 2_000_000 = 50 (not 50.0000005)
// [FIX A-014] After multiplication-style comparison, the 1-lovelace-over
// case is now correctly REJECTED. Previously the truncation
// `100_000_001 / 2_000_000 = 50` slipped through; the new check
// `100_000_001 <= 2_000_000 * 50 = 100_000_000` evaluates False.
test ratio_truncation_one_lovelace_over_now_rejected_a014() {
  is_premium_adequate(2_000_000, 100_000_001) == False
}

// Boundary: exactly 50× still passes.
test ratio_at_exactly_50x_passes() {
  is_premium_adequate(2_000_000, 100_000_000) == True
}

// But coverage clearly above max ratio is rejected
test ratio_clearly_over_max() {
  // premium = 2 ADA, coverage = 102 ADA -> ratio = 51x (rejected)
  is_premium_adequate(2_000_000, 102_000_000) == False
}

// [FIX A-014] Confirm the multiplication form rejects ALL fractional
// over-coverage cases, not just the documented 1-lovelace edge.
test ratio_post_a014_rejects_fractional_overshoot() {
  // premium = 2_000_001, coverage = 100_000_100
  // Multiplication: 2_000_001 * 50 = 100_000_050.
  // 100_000_100 > 100_000_050 → rejected.
  is_ratio_acceptable(2_000_001, 100_000_100) == False
}

// Net premium with zero fee should equal gross premium
test net_premium_zero_fee() {
  net_premium(10_000_000, 0) == 10_000_000
}

// Cancellation fee on minimum premium
test cancellation_fee_on_minimum_premium() {
  // 10% of 2 ADA = 0.2 ADA
  calculate_cancellation_fee(2_000_000) == 200_000
}

// Refund should always be less than premium
test refund_always_less_than_premium() {
  let premium = 50_000_000
  calculate_refund(premium) < premium
}

// ---------------------------------------------------------------------------
// Treasury Cut Tests
// ---------------------------------------------------------------------------

// Zero premium should produce a zero cut at any rate. This anchors the
// boundary that the donation field can be `None` when nothing is owed.
test treasury_cut_zero_premium_yields_zero() {
  calculate_treasury_cut(0, 200, 2_500) == 0
}

// A zero protocol fee zeroes the cut even on a large premium. This guards
// the migration path where the operator wants to disable fees temporarily.
test treasury_cut_zero_fee_yields_zero() {
  calculate_treasury_cut(10_000_000_000, 0, 2_500) == 0
}

// Default 100 ADA premium at the deployed pin (200 bps fee, 2500 bps share)
// must produce exactly 0.5 ADA = 500_000 lovelace. This is the headline
// figure quoted in the Draper Dragon pitch.
test treasury_cut_default_100ada_premium() {
  // 100_000_000 * 200 / 10_000 * 2_500 / 10_000
  //   = 2_000_000 * 2_500 / 10_000
  //   = 500_000
  calculate_treasury_cut(100_000_000, 200, 2_500) == 500_000
}

// 10 million ADA premium — large but still well within the lovelace range —
// must round-trip through the two-stage division without overflow and yield
// exactly 50_000 ADA to the treasury.
test treasury_cut_large_premium_no_overflow() {
  // 10_000_000_000_000 * 200 / 10_000 * 2_500 / 10_000
  //   = 200_000_000_000 * 2_500 / 10_000
  //   = 50_000_000_000
  calculate_treasury_cut(10_000_000_000_000, 200, 2_500) == 50_000_000_000
}

// One-lovelace premium floors to zero under the two-stage division. This
// confirms the floor-rounding convention and prevents a 1-lovelace under-
// donation from rejecting an otherwise-valid tx.
test treasury_cut_tiny_premium_floors_to_zero() {
  // 1 * 200 / 10_000 * 2_500 / 10_000
  //   = 0 * 2_500 / 10_000
  //   = 0
  calculate_treasury_cut(1, 200, 2_500) == 0
}

// Cross-check against the analytic identity: cut == fee * share_bps / 10_000.
// Any drift between this helper and `calculate_protocol_fee` would surface
// here on a premium that is not exactly divisible by both stages.
test treasury_cut_matches_fee_times_share() {
  let premium = 250_000_000
  let fee = calculate_protocol_fee(premium, 200)
  let expected = fee * 2_500 / 10_000
  calculate_treasury_cut(premium, 200, 2_500) == expected
}

// ---------------------------------------------------------------------------
// [v12.2] Hybrid Fee Tests
// V12 used `(premium, fee_bps, partner_share_bps)`; V12.2 takes the floored
// `fee_total` directly + `min_utxo_lovelace` for the silent absorb rule.
// ---------------------------------------------------------------------------

test fee_total_floors_to_min_utxo_on_small_premium() {
  // 20 ADA premium, 2% fee = 0.4 ADA raw, floors to 2 ADA fee_total.
  calculate_fee_total(20_000_000, 200, 2_000_000) == 2_000_000
}

test fee_total_passes_through_on_threshold_premium() {
  // 100 ADA premium, 2% fee = 2 ADA raw, exactly at floor.
  calculate_fee_total(100_000_000, 200, 2_000_000) == 2_000_000
}

test fee_total_above_floor_on_500_ada() {
  // 500 ADA premium, 2% fee = 10 ADA raw, above floor.
  calculate_fee_total(500_000_000, 200, 2_000_000) == 10_000_000
}

test net_pool_growth_on_20_ada_premium_yields_18_ada() {
  // 20 ADA premium, 2 ADA floored fee → net = 18 ADA.
  calculate_net_pool_growth(20_000_000, 200, 2_000_000) == 18_000_000
}

test net_pool_growth_on_100_ada_premium_yields_98_ada() {
  // 100 ADA premium: raw_fee = floor = 2 ADA, net = 98 ADA.
  calculate_net_pool_growth(100_000_000, 200, 2_000_000) == 98_000_000
}

test net_pool_growth_on_500_ada_premium_yields_490_ada() {
  // 500 ADA premium: fee_total = 10 ADA, net = 490 ADA.
  calculate_net_pool_growth(500_000_000, 200, 2_000_000) == 490_000_000
}

test split_solo_policy_routes_full_fee_total_to_team() {
  // fee_total = 2 ADA, no partner → team = 2, partner = 0.
  let (team, partner) =
    calculate_protocol_fee_split(2_000_000, 0, 2_000_000)
  team == 2_000_000 && partner == 0
}

test split_partner_at_max_cap_500_ada_premium_absorbs() {
  // 500 ADA premium, fee_total = 10 ADA, partner @ 20% (2000 bps):
  //   partner_cut_raw = 10 × 2000 / 10_000 = 2 ADA (exactly at floor)
  // 2 >= min_utxo, so partner_cut = 2, team_cut = 8.
  let (team, partner) =
    calculate_protocol_fee_split(10_000_000, 2_000, 2_000_000)
  team == 8_000_000 && partner == 2_000_000
}

test split_silent_absorb_on_500_ada_premium_15pct_partner() {
  // 500 ADA premium, fee_total = 10 ADA, partner @ 15% (1500 bps):
  //   partner_cut_raw = 10 × 1500 / 10_000 = 1.5 ADA (below floor)
  // partner_cut absorbed → 0, team_cut = full 10 ADA.
  let (team, partner) =
    calculate_protocol_fee_split(10_000_000, 1_500, 2_000_000)
  team == 10_000_000 && partner == 0
}

test split_partner_above_floor_on_1000_ada_premium_15pct() {
  // 1000 ADA premium, fee_total = 20 ADA, partner @ 15%:
  //   partner_cut_raw = 20 × 1500 / 10_000 = 3 ADA (above floor)
  // partner_cut = 3, team_cut = 17.
  let (team, partner) =
    calculate_protocol_fee_split(20_000_000, 1_500, 2_000_000)
  team == 17_000_000 && partner == 3_000_000
}

test split_sum_equals_fee_total_silently_absorbed() {
  // Invariant: team + partner == fee_total ALWAYS, regardless of absorb.
  let fee_total = 12_345_678
  let (team, partner) =
    calculate_protocol_fee_split(fee_total, 1_337, 2_000_000)
  team + partner == fee_total
}

test split_zero_fee_yields_zero_both_sides() {
  // fee_total = 0 (degenerate; should never happen because fee_total has
  // a min_utxo floor). Defensive case for early-return safety.
  let (team, partner) = calculate_protocol_fee_split(0, 2_000, 2_000_000)
  team == 0 && partner == 0
}

test split_partner_share_zero_routes_full_fee_to_team() {
  // partner_address may be Some(_) in the calling datum, but share == 0.
  // Same numeric result as solo: team = fee_total, partner = 0.
  let (team, partner) =
    calculate_protocol_fee_split(2_000_000, 0, 2_000_000)
  team == 2_000_000 && partner == 0
}

test net_premium_v12_compat_unchanged_for_large_premium() {
  // The legacy V12 helper continues to compile + work; for large premium
  // its output equals calculate_net_pool_growth (since fee_total == raw_fee
  // when raw_fee >= min_utxo).
  net_premium(500_000_000, 200) == calculate_net_pool_growth(
    500_000_000,
    200,
    2_000_000,
  )
}

test net_premium_v12_diverges_from_v12_2_on_small_premium() {
  // Below the 100-ADA threshold, V12's net_premium gives raw arithmetic
  // (no floor) while V12.2's calculate_net_pool_growth applies the floor.
  // Concrete: 20 ADA premium → V12 net = 19.6, V12.2 net = 18.
  let v12_net = net_premium(20_000_000, 200)
  let v12_2_net = calculate_net_pool_growth(20_000_000, 200, 2_000_000)
  v12_net == 19_600_000 && v12_2_net == 18_000_000 && v12_net != v12_2_net
}

// ---------------------------------------------------------------------------
// [v12.2 §8] Property-style invariant tests
// ---------------------------------------------------------------------------

test invariant_1_premium_conservation_holds() {
  // premium == net_pool_growth + team_cut + partner_cut.
  let premium = 12_345_678
  let fee_total = calculate_fee_total(premium, 200, 2_000_000)
  let (team, partner) =
    calculate_protocol_fee_split(fee_total, 1_500, 2_000_000)
  let net = premium - fee_total
  premium == net + team + partner
}

test invariant_2_fee_floor_holds_on_small_premium() {
  let fee_total = calculate_fee_total(20_000_000, 200, 2_000_000)
  fee_total >= 2_000_000 && fee_total >= 400_000
}

test invariant_2_fee_floor_holds_on_large_premium() {
  let fee_total = calculate_fee_total(500_000_000, 200, 2_000_000)
  fee_total >= 2_000_000 && fee_total >= 10_000_000
}

test invariant_3_partner_consistency_silent_absorb_at_500() {
  let (_, partner) =
    calculate_protocol_fee_split(10_000_000, 1_500, 2_000_000)
  partner == 0 || partner >= 2_000_000
}

test invariant_3_partner_consistency_above_floor_at_1000() {
  let (_, partner) =
    calculate_protocol_fee_split(20_000_000, 1_500, 2_000_000)
  partner == 0 || partner >= 2_000_000
}

test invariant_4_team_safe_silent_absorb_path() {
  let fee_total = calculate_fee_total(100_000_000, 200, 2_000_000)
  let (team, _) =
    calculate_protocol_fee_split(fee_total, 2_000, 2_000_000)
  team >= 2_000_000
}

test invariant_4_team_safe_partner_pays_path() {
  let fee_total = calculate_fee_total(1_000_000_000, 200, 2_000_000)
  let (team, partner) =
    calculate_protocol_fee_split(fee_total, 2_000, 2_000_000)
  team >= 2_000_000 && team == 16_000_000 && partner == 4_000_000
}

test invariant_4_team_safe_solo_path() {
  let fee_total = calculate_fee_total(20_000_000, 200, 2_000_000)
  let (team, _) =
    calculate_protocol_fee_split(fee_total, 0, 2_000_000)
  team >= 2_000_000
}

test invariant_7_pool_delta_20_ada() {
  calculate_net_pool_growth(20_000_000, 200, 2_000_000) == 18_000_000
}

test invariant_7_pool_delta_500_ada() {
  calculate_net_pool_growth(500_000_000, 200, 2_000_000) == 490_000_000
}

test invariant_7_pool_delta_breakeven_at_100_ada() {
  calculate_net_pool_growth(100_000_000, 200, 2_000_000) == 98_000_000
}
