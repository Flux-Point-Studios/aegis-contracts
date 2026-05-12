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
// Protocol Fee Calculation
// ---------------------------------------------------------------------------

/// Calculate the protocol fee from a premium.
/// Fee is denominated in basis points (1 bp = 0.01%).
/// Example: 200 bps on 10 ADA premium = 0.2 ADA fee
pub fn calculate_protocol_fee(premium: Int, fee_bps: Int) -> Int {
  premium * fee_bps / 10_000
}

/// Calculate the net premium that goes to the pool after fee deduction.
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

/// [v12] Split a protocol fee into team and partner cuts.
///
/// Returns `(team_cut, partner_cut)` such that
///   `team_cut + partner_cut == calculate_protocol_fee(premium, protocol_fee_bps)`
/// exactly (no rounding drift between the two halves).
///
/// `partner_share_bps` is in bps OF THE FEE (not of the premium). At the
/// V12 defaults (`protocol_fee_bps = 200`, `partner_share_bps = 0..=2000`),
/// partner_cut is 0..=0.4% of premium and team_cut is 1.6..=2.0% of premium.
///
/// Floor-rounding convention: any fractional lovelace from the multi-stage
/// division accrues to `team_cut` (not partner). Rationale: the team is the
/// protocol's economic baseline; partners are a routing detail. Flooring
/// the partner share once and deriving team by subtraction guarantees the
/// invariant `team_cut + partner_cut == total_fee` holds exactly without a
/// double-rounding ambiguity. The `pool.ak` Underwrite / AcceptCancellation
/// / BatchUnderwrite branches all read this helper, so changing the
/// rounding convention here is a validator-hash-rotating event.
pub fn calculate_protocol_fee_split(
  premium: Int,
  protocol_fee_bps: Int,
  partner_share_bps: Int,
) -> (Int, Int) {
  let total_fee = calculate_protocol_fee(premium, protocol_fee_bps)
  let partner_cut = total_fee * partner_share_bps / 10_000
  let team_cut = total_fee - partner_cut
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
// [v12] Protocol Fee Split Tests
//
// TDD-first: these tests were written before `calculate_protocol_fee_split`
// (RED). The four spec-mandated cases plus two extra cross-checks below
// (sum-equals-total + Some(addr)/0-bps distinction).
// ---------------------------------------------------------------------------

test fee_split_solo_policy_routes_full_fee_to_team() {
  // 100 ADA premium, 2% fee = 2 ADA, no partner -> team gets full 2 ADA.
  let (team, partner) = calculate_protocol_fee_split(100_000_000, 200, 0)
  team == 2_000_000 && partner == 0
}

test fee_split_partner_at_max_cap() {
  // 100 ADA premium, 2% fee = 2 ADA, partner @ 20% -> partner 0.4, team 1.6.
  let (team, partner) = calculate_protocol_fee_split(100_000_000, 200, 2_000)
  team == 1_600_000 && partner == 400_000
}

test fee_split_zero_premium_yields_zero_both_sides() {
  let (team, partner) = calculate_protocol_fee_split(0, 200, 1_000)
  team == 0 && partner == 0
}

test fee_split_zero_fee_yields_zero_both_sides() {
  // protocol_fee_bps = 0 with partner_share_bps non-zero must yield (0, 0).
  // Guards against a degenerate path where partner_cut is computed against
  // a non-existent fee base.
  let (team, partner) = calculate_protocol_fee_split(100_000_000, 0, 2_000)
  team == 0 && partner == 0
}

test fee_split_sum_equals_total_fee_exact() {
  // Cross-check the invariant: split sums exactly to the total fee
  // regardless of partner_share_bps. Uses a mid-range bps (1337) to provoke
  // any rounding drift that would arise if both halves were independently
  // floored. The team-by-subtraction convention guarantees exact sum.
  let premium = 250_000_000
  let total_fee = calculate_protocol_fee(premium, 200)
  let (team, partner) = calculate_protocol_fee_split(premium, 200, 1_337)
  team + partner == total_fee
}

test fee_split_partner_share_zero_routes_full_fee_to_team() {
  // Distinct from solo: partner_address may be Some(_) in the calling
  // datum, but share == 0. The split function does not see the address;
  // it just respects the bps. Same numeric result as solo.
  let (team, partner) = calculate_protocol_fee_split(100_000_000, 200, 0)
  team == 2_000_000 && partner == 0
}
