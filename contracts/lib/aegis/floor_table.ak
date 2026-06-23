// =============================================================================
// Aegis Insurance Protocol - On-Chain Premium Floor Tables
// Location: contracts/lib/aegis/floor_table.ak
// Summary: Strike-distance-, duration- and risk-class-aware MINIMUM premium
//          (as bps of coverage) enforced by the pool validator's Underwrite
//          branch under the pool-funded coverage model.
//
//          Aiken cannot evaluate exp/log/erf on-chain, so the actuarial
//          premium curve is BAKED as a coarse lookup table. The off-chain
//          quote charges the exact model (docs/pricing/barrier_premium.py);
//          this table is a CONSERVATIVE-LOW backstop that bounds how far an
//          adversary hand-building a tx can under-price, WITHOUT ever
//          rejecting an honest quote.
//
//          Two engines, dispatched by PolicyDatum.risk_class:
//            * Barrier (ADA crash, Indigo CDP, Surf) — GBM one-touch premium,
//              keyed by strike distance d and duration T, conservative σ=0.95
//              / load +0.20 grade.
//            * Depeg (stablecoins) — Poisson hazard premium, duration-only,
//              established-coin tier λ=0.08/yr.
//
//          Table construction + the floor<=honest self-check (0 violations
//          over 61,000 samples) live in docs/pricing/gen_floor_tables.py.
//          Each band stores the premium at its MINIMUM-premium corner
//          (d = band upper edge, T = band lower edge); since touch premium
//          decreases in d and increases in T, that corner is <= every honest
//          quote inside the band. Equivalent to "ceil d to the next grid
//          line, floor T to the previous."
// =============================================================================

use aegis/types.{Barrier, Depeg, RiskClass, price_scale}

// ---------------------------------------------------------------------------
// Calibration anchors (mirror docs/pricing/CALIBRATION.md)
// ---------------------------------------------------------------------------

/// Barrier minimum strike distance: a barrier policy's strike must sit at
/// least 15% below the observed spot. Near-money cover is near-certain to
/// trigger (premium approaches 100% of coverage) — uninsurable cheaply — and
/// is also where GBM under-prices via jumps. Enforced by the validator BEFORE
/// the floor lookup; `barrier_floor_bps` also fails closed below it.
pub const min_strike_distance_bps: Int = 1500

/// Depeg trigger band, as a fraction of the $1 peg (= `price_scale`). A depeg
/// policy's strike must sit between 50% and 95% of peg: the upper bound forces
/// a GENUINE depeg trigger (>=5% below peg, where the λ touch-0.95 calibration
/// holds or over-prices), blocking the "strike just under peg = near-certain
/// cheap payout" drain; the lower bound rejects nonsensical sub-50% strikes.
pub const depeg_strike_lo_pct: Int = 50
pub const depeg_strike_hi_pct: Int = 95

// ---------------------------------------------------------------------------
// Band indexing
// ---------------------------------------------------------------------------

/// Map a duration in days to its T-band index 0..6, flooring to the band
/// lower edge {1, 7, 14, 30, 60, 90, 180}. Flooring (not rounding) is
/// required: premium increases in T, so the band's minimum honest premium is
/// at its lower edge.
fn t_band_index(t_days: Int) -> Int {
  if t_days < 7 {
    0
  } else if t_days < 14 {
    1
  } else if t_days < 30 {
    2
  } else if t_days < 60 {
    3
  } else if t_days < 90 {
    4
  } else if t_days < 180 {
    5
  } else {
    6
  }
}

/// Select the `i`-th of seven baked values (i in 0..6, clamped to the last).
fn pick7(i: Int, a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int) -> Int {
  when i is {
    0 -> a
    1 -> b
    2 -> c
    3 -> d
    4 -> e
    5 -> f
    _ -> g
  }
}

// ---------------------------------------------------------------------------
// Barrier floor (GBM one-touch, σ=0.95 / load +0.20)
// ---------------------------------------------------------------------------

/// Minimum premium (bps of coverage) for a Barrier policy at strike distance
/// `d_bps` (= 10000 × (spot − strike) / spot) and duration `t_days`.
///
/// Rows are keyed by the d-band UPPER edge (ceil d to the grid); columns by
/// the T-band LOWER edge (floor T to the grid). Below `min_strike_distance_bps`
/// it fails closed with an unreachable-high floor (the validator also hard-
/// rejects there). At/above 70% strike distance the floor is 0 — such a deep
/// barrier is so unlikely to touch that only the absolute `min_premium` /
/// ratio-cap floors apply.
pub fn barrier_floor_bps(d_bps: Int, t_days: Int) -> Int {
  if d_bps < min_strike_distance_bps {
    // Fail closed: 100× coverage is impossible to satisfy.
    1_000_000
  } else {
    let t = t_band_index(t_days)
    if d_bps < 2000 {
      // d-band [1500,2000), corner d_hi=2000
      pick7(t, 0, 1203, 3083, 5512, 7494, 8463, 9776)
    } else if d_bps < 2500 {
      // [2000,2500), corner 2500
      pick7(t, 0, 397, 1686, 4009, 6256, 7432, 9088)
    } else if d_bps < 3000 {
      // [2500,3000), corner 3000
      pick7(t, 0, 96, 789, 2714, 5036, 6370, 8346)
    } else if d_bps < 4000 {
      // [3000,4000), corner 4000
      pick7(t, 0, 1, 93, 934, 2829, 4254, 6710)
    } else if d_bps < 5000 {
      // [4000,5000), corner 5000
      pick7(t, 0, 0, 3, 184, 1204, 2362, 4921)
    } else if d_bps < 7000 {
      // [5000,7000), corner 7000
      pick7(t, 0, 0, 0, 0, 38, 229, 1497)
    } else {
      // [7000, ∞): corner 10000 — all zeros
      0
    }
  }
}

// ---------------------------------------------------------------------------
// Depeg floor (Poisson hazard, established-coin tier λ=0.08/yr)
// ---------------------------------------------------------------------------

/// Minimum premium (bps of coverage) for a Depeg policy of duration `t_days`.
/// Duration-only (the trigger strike is pinned to a band near the peg, so
/// there is no strike-distance dimension). Established-coin tier (USDC/USDT).
pub fn depeg_floor_bps(t_days: Int) -> Int {
  pick7(t_band_index(t_days), 2, 18, 36, 78, 156, 234, 464)
}

// ---------------------------------------------------------------------------
// Risk-class dispatch + predicates used by the validator
// ---------------------------------------------------------------------------

/// Does a Depeg policy's strike sit inside the insurable depeg band
/// [50%, 95%] of the $1 peg (`price_scale`)?
pub fn depeg_strike_in_band(strike_price: Int) -> Bool {
  strike_price >= price_scale * depeg_strike_lo_pct / 100 && strike_price <= price_scale * depeg_strike_hi_pct / 100
}

/// Premium-floor predicate for the Barrier class. `d_bps` is derived by the
/// validator from a fresh oracle spot reference input. Uses cross-multiplied
/// integer comparison (no division → no truncation games):
///   premium / coverage  >=  floor_bps / 10000
pub fn meets_barrier_floor(
  premium: Int,
  coverage: Int,
  d_bps: Int,
  t_days: Int,
) -> Bool {
  premium * 10_000 >= coverage * barrier_floor_bps(d_bps, t_days)
}

/// Premium-floor predicate for the Depeg class (duration-only).
pub fn meets_depeg_floor(premium: Int, coverage: Int, t_days: Int) -> Bool {
  premium * 10_000 >= coverage * depeg_floor_bps(t_days)
}

// ---------------------------------------------------------------------------
// Tests — cell regression locks
//
// Each cell value is pinned. Any edit to the table (intentional recalibration
// or accidental drift) must consciously update these pins. The generator
// docs/pricing/gen_floor_tables.py is the source of truth; these mirror it.
// ---------------------------------------------------------------------------

test t_band_index_floors_to_lower_edge() {
  t_band_index(1) == 0 && t_band_index(6) == 0 && t_band_index(7) == 1 && t_band_index(
    13,
  ) == 1 && t_band_index(14) == 2 && t_band_index(29) == 2 && t_band_index(30) == 3 && t_band_index(
    59,
  ) == 3 && t_band_index(60) == 4 && t_band_index(89) == 4 && t_band_index(90) == 5 && t_band_index(
    179,
  ) == 5 && t_band_index(180) == 6 && t_band_index(365) == 6
}

test barrier_row_d15_band() {
  // d in [1500,2000): corner d_hi=2000.
  barrier_floor_bps(1500, 1) == 0 && barrier_floor_bps(1500, 7) == 1203 && barrier_floor_bps(
    1750,
    14,
  ) == 3083 && barrier_floor_bps(1999, 30) == 5512 && barrier_floor_bps(1500, 60) == 7494 && barrier_floor_bps(
    1500,
    90,
  ) == 8463 && barrier_floor_bps(1500, 365) == 9776
}

test barrier_row_d20_band() {
  // d in [2000,2500): corner 2500.
  barrier_floor_bps(2000, 7) == 397 && barrier_floor_bps(2000, 14) == 1686 && barrier_floor_bps(
    2499,
    30,
  ) == 4009 && barrier_floor_bps(2000, 60) == 6256 && barrier_floor_bps(2000, 90) == 7432 && barrier_floor_bps(
    2000,
    180,
  ) == 9088
}

test barrier_row_d25_band() {
  // [2500,3000): corner 3000.
  barrier_floor_bps(2500, 14) == 789 && barrier_floor_bps(2700, 30) == 2714 && barrier_floor_bps(
    2999,
    60,
  ) == 5036 && barrier_floor_bps(2500, 90) == 6370 && barrier_floor_bps(2500, 180) == 8346
}

test barrier_row_d30_band() {
  // [3000,4000): corner 4000.
  barrier_floor_bps(3000, 30) == 934 && barrier_floor_bps(3500, 60) == 2829 && barrier_floor_bps(
    3999,
    90,
  ) == 4254 && barrier_floor_bps(3000, 180) == 6710
}

test barrier_row_d40_band() {
  // [4000,5000): corner 5000.
  barrier_floor_bps(4000, 30) == 184 && barrier_floor_bps(4500, 60) == 1204 && barrier_floor_bps(
    4999,
    90,
  ) == 2362 && barrier_floor_bps(4000, 180) == 4921
}

test barrier_row_d50_band() {
  // [5000,7000): corner 7000.
  barrier_floor_bps(5000, 60) == 38 && barrier_floor_bps(6000, 90) == 229 && barrier_floor_bps(
    6999,
    180,
  ) == 1497
}

test barrier_deep_band_is_zero() {
  // [7000, ∞): corner 10000 — all zeros (only min_premium/ratio cap apply).
  barrier_floor_bps(7000, 180) == 0 && barrier_floor_bps(9000, 365) == 0
}

test barrier_below_min_strike_fails_closed() {
  // d < 1500bps → unreachable-high floor so any premium check fails.
  barrier_floor_bps(1499, 30) == 1_000_000 && barrier_floor_bps(0, 30) == 1_000_000
}

test barrier_monotone_in_d_at_30d() {
  // Deeper strike (larger d) → strictly lower-or-equal floor at fixed T.
  let a = barrier_floor_bps(1500, 30)
  let b = barrier_floor_bps(2000, 30)
  let c = barrier_floor_bps(2500, 30)
  let e = barrier_floor_bps(3000, 30)
  let f = barrier_floor_bps(4000, 30)
  a >= b && b >= c && c >= e && e >= f
}

test barrier_monotone_in_t_at_d20() {
  // Longer duration → higher-or-equal floor at fixed d.
  let a = barrier_floor_bps(2000, 7)
  let b = barrier_floor_bps(2000, 30)
  let c = barrier_floor_bps(2000, 90)
  let e = barrier_floor_bps(2000, 180)
  a <= b && b <= c && c <= e
}

test depeg_row_pins() {
  depeg_floor_bps(1) == 2 && depeg_floor_bps(7) == 18 && depeg_floor_bps(14) == 36 && depeg_floor_bps(
    30,
  ) == 78 && depeg_floor_bps(60) == 156 && depeg_floor_bps(90) == 234 && depeg_floor_bps(
    365,
  ) == 464
}

// ---------------------------------------------------------------------------
// Tests — floor <= honest (never rejects an honest quote)
//
// Honest σ=0.95/load=0.20 premium rates (bps of coverage) computed by
// barrier_premium.py at representative interior points. The stored band floor
// must be <= the honest rate at every point inside that band.
// ---------------------------------------------------------------------------

test barrier_floor_under_honest_d20_30d() {
  // honest premium_rate(0.20, 30d; σ.95, +20%) = 0.5512 → 5512 bps.
  // Band [2000,2500)×[30,60) floor = 4009 ≤ 5512.
  barrier_floor_bps(2000, 30) <= 5512
}

test barrier_floor_under_honest_d27_30d() {
  // honest premium_rate(0.27, 30d; σ.95) ≈ 0.346 → ~3463 bps. Band corner floor 2714.
  barrier_floor_bps(2700, 30) <= 3463
}

test barrier_floor_under_honest_d15_90d() {
  // honest premium_rate(0.15, 90d; σ.95) = 0.9445 → 9445 bps. Band floor 8463.
  barrier_floor_bps(1500, 90) <= 9445
}

test depeg_floor_under_honest_30d() {
  // honest depeg_rate(30d; λ.08, +20%) = 0.00789 → 78 bps. Floor 78 (corner=30).
  // Equal at the corner is allowed (<=); deeper inside the band it is strictly under.
  depeg_floor_bps(30) <= 79
}

// ---------------------------------------------------------------------------
// Tests — predicates
// ---------------------------------------------------------------------------

test meets_barrier_floor_fair_premium_passes() {
  // 200 ADA cover, 30d, d=20%: floor 4009 bps = 80.18 ADA (honest price ~110).
  // A 96-ADA premium clears the floor; a 50-ADA premium (below 80.18) fails.
  meets_barrier_floor(96_000_000, 200_000_000, 2000, 30) == True && meets_barrier_floor(
    50_000_000,
    200_000_000,
    2000,
    30,
  ) == False
}

test meets_barrier_floor_at_exact_floor_passes() {
  // premium exactly at floor: 200 ADA × 4009/10000 = 80.18 ADA.
  meets_barrier_floor(80_180_000, 200_000_000, 2000, 30) == True && meets_barrier_floor(
    80_179_999,
    200_000_000,
    2000,
    30,
  ) == False
}

test meets_barrier_floor_below_min_strike_rejects() {
  // d=10% (<15% min): fail-closed floor 1_000_000 bps → no premium passes.
  meets_barrier_floor(10_000_000_000, 200_000_000, 1000, 30) == False
}

test meets_depeg_floor_fair_premium_passes() {
  // 1000 ADA cover, 30d depeg floor 78 bps = 7.8 ADA.
  meets_depeg_floor(8_000_000, 1_000_000_000, 30) == True && meets_depeg_floor(
    7_000_000,
    1_000_000_000,
    30,
  ) == False
}

test depeg_strike_band_accepts_5pct_below_peg() {
  // price_scale = 1_000_000. 0.95 peg = 950_000 (exactly the 95% upper edge).
  depeg_strike_in_band(950_000) == True && depeg_strike_in_band(900_000) == True && depeg_strike_in_band(
    500_000,
  ) == True
}

test depeg_strike_band_rejects_near_peg_and_absurd() {
  // 0.99 (too shallow — near-certain wobble) and 0.40 (sub-50%) both rejected.
  depeg_strike_in_band(990_000) == False && depeg_strike_in_band(400_000) == False
}

test dispatch_barrier_vs_depeg_select_different_tables() {
  // Same nominal duration, the two classes resolve to different floors —
  // confirms the risk_class split is load-bearing.
  let rc1: RiskClass = Barrier
  let rc2: RiskClass = Depeg
  let barrier =
    when rc1 is {
      Barrier -> barrier_floor_bps(2000, 30)
      Depeg -> depeg_floor_bps(30)
    }
  let depeg =
    when rc2 is {
      Barrier -> barrier_floor_bps(2000, 30)
      Depeg -> depeg_floor_bps(30)
    }
  barrier == 4009 && depeg == 78 && barrier != depeg
}
