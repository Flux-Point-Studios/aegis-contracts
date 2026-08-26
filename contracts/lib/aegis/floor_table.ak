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

use aegis/types.{Barrier, Depeg, RiskClass, min_policy_term_ms, price_scale}
use aiken/collection/list

// ---------------------------------------------------------------------------
// Calibration anchors (mirror docs/pricing/CALIBRATION.md)
// ---------------------------------------------------------------------------

/// Barrier minimum strike distance: a barrier policy's strike must sit at
/// least 15% below the observed spot. Near-money cover is near-certain to
/// trigger (premium approaches 100% of coverage) — uninsurable cheaply — and
/// is also where GBM under-prices via jumps. Enforced by the validator BEFORE
/// the floor lookup; `barrier_floor_bps` also fails closed below it.
pub const min_strike_distance_bps: Int = 1500

/// [#363 N2] Minimum distance between the VAULT-resolved spot and a DEPEG
/// strike. Barrier's 15% floor is unusable for a stablecoin (a 0.95 strike
/// would need spot >= 1.118), so Depeg gets its own modest margin: enough to
/// refuse cover on an asset whose peg is ALREADY broken at or below the strike,
/// while keeping the whole 50-95% insurable band buyable at a healthy peg.
pub const min_depeg_distance_bps: Int = 200

/// Depeg trigger band, as a fraction of the $1 peg (= `price_scale`). A depeg
/// policy's strike must sit between 50% and 95% of peg: the upper bound forces
/// a GENUINE depeg trigger (>=5% below peg, where the λ touch-0.95 calibration
/// holds or over-prices), blocking the "strike just under peg = near-certain
/// cheap payout" drain; the lower bound rejects nonsensical sub-50% strikes.
pub const depeg_strike_lo_pct: Int = 50
pub const depeg_strike_hi_pct: Int = 95

/// [#363 red-team F3] Minimum spot, as a percentage of the $1 peg, at which
/// Depeg cover may be SOLD. The peg must still be intact at underwrite.
///
/// `min_depeg_distance_bps` is measured against SPOT, so it only proves the
/// strike is out of the money — not that the peg holds. With a strike allowed
/// as deep as `depeg_strike_lo_pct` (50%), a coin already collapsed to ~$0.52
/// cleared that leg and bought cover at a $0.50 strike, priced off the
/// duration-only hazard curve calibrated for a HEALTHY peg (λ = 0.08/yr of
/// touching 0.95). The true hazard there is ~1. Anchoring to the peg closes it.
///
/// 99% leaves room for ordinary book noise (a healthy USDC/USDT sits inside
/// ~50 bps of peg) while refusing to price a live depeg on a healthy-peg curve.
/// MUST stay strictly above `depeg_strike_hi_pct`, so even the shallowest
/// permitted strike is genuinely out of the money when the policy is written —
/// pinned by `healthy_peg_is_above_every_permitted_strike`.
pub const min_depeg_spot_pct: Int = 99

// ---------------------------------------------------------------------------
// Band indexing
// ---------------------------------------------------------------------------

/// Map a duration in days to its T-band index 0..6, flooring to the band
/// lower edge {1, 7, 14, 30, 60, 90, 180}. Flooring (not rounding) is
/// required: premium increases in T, so the band's minimum honest premium is
/// at its lower edge.
pub fn t_band_index(t_days: Int) -> Int {
  if t_days < 7 {
    0
  } else if t_days < 9 {
    1
  } else if t_days < 11 {
    2
  } else if t_days < 13 {
    3
  } else if t_days < 16 {
    4
  } else if t_days < 20 {
    5
  } else if t_days < 25 {
    6
  } else if t_days < 30 {
    7
  } else if t_days < 38 {
    8
  } else if t_days < 46 {
    9
  } else if t_days < 55 {
    10
  } else if t_days < 65 {
    11
  } else if t_days < 75 {
    12
  } else if t_days < 90 {
    13
  } else if t_days < 105 {
    14
  } else if t_days < 120 {
    15
  } else if t_days < 140 {
    16
  } else if t_days < 160 {
    17
  } else if t_days < 180 {
    18
  } else {
    19
  }
}

fn pick_t(i: Int, v0: Int, v1: Int, v2: Int, v3: Int, v4: Int, v5: Int, v6: Int, v7: Int, v8: Int, v9: Int, v10: Int, v11: Int, v12: Int, v13: Int, v14: Int, v15: Int, v16: Int, v17: Int, v18: Int, v19: Int) -> Int {
  when i is {
    0 -> v0
    1 -> v1
    2 -> v2
    3 -> v3
    4 -> v4
    5 -> v5
    6 -> v6
    7 -> v7
    8 -> v8
    9 -> v9
    10 -> v10
    11 -> v11
    12 -> v12
    13 -> v13
    14 -> v14
    15 -> v15
    16 -> v16
    17 -> v17
    18 -> v18
    _ -> v19
  }
}

pub fn barrier_floor_bps(d_bps: Int, t_days: Int) -> Int {
  if d_bps < min_strike_distance_bps {
    1_000_000
  } else {
    let t = t_band_index(t_days)
    if d_bps < 1600 {
      pick_t(t, 5, 2420, 3169, 3795, 4322, 4972, 5653, 6305, 6810, 7425, 7886, 8288, 8639, 8920, 9253, 9514, 9725, 9952, 10136, 10287)
    } else if d_bps < 1700 {
      pick_t(t, 2, 2060, 2783, 3399, 3925, 4583, 5280, 5954, 6480, 7124, 7610, 8034, 8406, 8704, 9059, 9337, 9562, 9805, 10000, 10163)
    } else if d_bps < 1800 {
      pick_t(t, 0, 1739, 2426, 3026, 3548, 4208, 4917, 5609, 6153, 6824, 7333, 7779, 8171, 8487, 8862, 9157, 9396, 9655, 9863, 10036)
    } else if d_bps < 1900 {
      pick_t(t, 0, 1454, 2100, 2679, 3190, 3848, 4563, 5270, 5830, 6526, 7056, 7524, 7935, 8267, 8663, 8975, 9229, 9502, 9724, 9907)
    } else if d_bps < 2000 {
      pick_t(t, 0, 1203, 1803, 2356, 2854, 3504, 4221, 4937, 5512, 6229, 6779, 7267, 7697, 8046, 8463, 8791, 9059, 9348, 9582, 9776)
    } else if d_bps < 2150 {
      pick_t(t, 0, 889, 1414, 1921, 2390, 3019, 3730, 4454, 5044, 5789, 6366, 6882, 7339, 7711, 8158, 8511, 8799, 9111, 9365, 9575)
    } else if d_bps < 2300 {
      pick_t(t, 0, 641, 1088, 1541, 1976, 2574, 3268, 3992, 4589, 5356, 5956, 6497, 6979, 7374, 7849, 8226, 8535, 8870, 9143, 9370)
    } else if d_bps < 2500 {
      pick_t(t, 0, 397, 743, 1120, 1500, 2045, 2702, 3410, 4009, 4793, 5417, 5986, 6499, 6920, 7432, 7840, 8176, 8541, 8839, 9088)
    } else if d_bps < 2700 {
      pick_t(t, 0, 234, 488, 789, 1109, 1590, 2196, 2874, 3463, 4250, 4891, 5481, 6019, 6465, 7010, 7447, 7809, 8204, 8527, 8798)
    } else if d_bps < 2900 {
      pick_t(t, 0, 131, 308, 537, 796, 1207, 1752, 2385, 2953, 3732, 4379, 4985, 5542, 6009, 6584, 7049, 7435, 7859, 8207, 8498)
    } else if d_bps < 3100 {
      pick_t(t, 0, 69, 185, 352, 554, 893, 1369, 1948, 2485, 3243, 3887, 4500, 5072, 5556, 6156, 6646, 7055, 7506, 7878, 8191)
    } else if d_bps < 3400 {
      pick_t(t, 0, 23, 78, 173, 301, 540, 907, 1390, 1865, 2569, 3191, 3801, 4383, 4883, 5514, 6036, 6475, 6964, 7370, 7714)
    } else if d_bps < 3700 {
      pick_t(t, 0, 6, 29, 76, 150, 303, 567, 948, 1348, 1976, 2557, 3146, 3723, 4229, 4878, 5423, 5887, 6410, 6847, 7220)
    } else if d_bps < 4000 {
      pick_t(t, 0, 1, 9, 30, 67, 157, 333, 614, 934, 1469, 1992, 2544, 3100, 3600, 4254, 4814, 5296, 5846, 6311, 6710)
    } else if d_bps < 4400 {
      pick_t(t, 0, 0, 1, 7, 19, 56, 145, 313, 529, 930, 1358, 1837, 2344, 2816, 3454, 4016, 4512, 5086, 5579, 6008)
    } else if d_bps < 4800 {
      pick_t(t, 0, 0, 0, 1, 4, 16, 54, 141, 270, 542, 864, 1252, 1688, 2112, 2709, 3252, 3744, 4326, 4837, 5287)
    } else if d_bps < 5200 {
      pick_t(t, 0, 0, 0, 0, 0, 3, 16, 54, 121, 285, 505, 796, 1146, 1504, 2035, 2539, 3009, 3582, 4095, 4555)
    } else if d_bps < 5600 {
      pick_t(t, 0, 0, 0, 0, 0, 0, 4, 17, 46, 132, 266, 464, 722, 1006, 1451, 1895, 2326, 2867, 3366, 3824)
    } else if d_bps < 6000 {
      pick_t(t, 0, 0, 0, 0, 0, 0, 0, 4, 14, 52, 123, 242, 416, 621, 968, 1337, 1711, 2200, 2667, 3107)
    } else if d_bps < 6500 {
      pick_t(t, 0, 0, 0, 0, 0, 0, 0, 0, 2, 12, 37, 88, 176, 294, 517, 779, 1064, 1462, 1864, 2258)
    } else if d_bps < 7000 {
      pick_t(t, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 7, 23, 57, 111, 229, 387, 576, 863, 1174, 1497)
    } else if d_bps < 8000 {
      pick_t(t, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 4, 16, 41, 81, 161, 270, 406)
    } else if d_bps < 9000 {
      pick_t(t, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 9, 20)
    } else if d_bps < 10000 {
      pick_t(t, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    } else {
      0
    }
  }
}

pub fn depeg_floor_bps(t_days: Int) -> Int {
  pick_t(t_band_index(t_days), 2, 18, 23, 28, 34, 42, 52, 65, 78, 99, 120, 143, 169, 195, 234, 273, 311, 362, 413, 464)
}

// ---------------------------------------------------------------------------
// Risk-class dispatch + predicates used by the validator
// ---------------------------------------------------------------------------

/// Does a Depeg policy's strike sit inside the insurable depeg band
/// [50%, 95%] of the $1 peg (`price_scale`)?
pub fn depeg_strike_in_band(strike_price: Int) -> Bool {
  strike_price >= price_scale * depeg_strike_lo_pct / 100 && strike_price <= price_scale * depeg_strike_hi_pct / 100
}

/// [#363 red-team F3] Is the peg still intact enough to SELL depeg cover on the
/// healthy-peg hazard curve? Anchored to the peg (`price_scale`), independent of
/// how deep the strike sits.
pub fn depeg_peg_is_healthy(resolved_spot: Int) -> Bool {
  resolved_spot >= price_scale * min_depeg_spot_pct / 100
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

test t_band_index_edges() {
  and {
    t_band_index(1) == 0,
    t_band_index(6) == 0,
    t_band_index(7) == 1,
    t_band_index(8) == 1,
    t_band_index(9) == 2,
    t_band_index(10) == 2,
    t_band_index(11) == 3,
    t_band_index(12) == 3,
    t_band_index(13) == 4,
    t_band_index(15) == 4,
    t_band_index(16) == 5,
    t_band_index(19) == 5,
    t_band_index(20) == 6,
    t_band_index(24) == 6,
    t_band_index(25) == 7,
    t_band_index(29) == 7,
    t_band_index(30) == 8,
    t_band_index(37) == 8,
    t_band_index(38) == 9,
    t_band_index(45) == 9,
    t_band_index(46) == 10,
    t_band_index(54) == 10,
    t_band_index(55) == 11,
    t_band_index(64) == 11,
    t_band_index(65) == 12,
    t_band_index(74) == 12,
    t_band_index(75) == 13,
    t_band_index(89) == 13,
    t_band_index(90) == 14,
    t_band_index(104) == 14,
    t_band_index(105) == 15,
    t_band_index(119) == 15,
    t_band_index(120) == 16,
    t_band_index(139) == 16,
    t_band_index(140) == 17,
    t_band_index(159) == 17,
    t_band_index(160) == 18,
    t_band_index(179) == 18,
    t_band_index(180) == 19,
  }
}

test barrier_floor_representative_cells() {
  and {
    barrier_floor_bps(1599, 7) == 2420,
    barrier_floor_bps(1599, 30) == 6810,
    barrier_floor_bps(1599, 90) == 9253,
    barrier_floor_bps(1599, 179) == 10136,
    barrier_floor_bps(1699, 7) == 2060,
    barrier_floor_bps(1699, 30) == 6480,
    barrier_floor_bps(1699, 90) == 9059,
    barrier_floor_bps(1699, 179) == 10000,
    barrier_floor_bps(1799, 7) == 1739,
    barrier_floor_bps(1799, 30) == 6153,
    barrier_floor_bps(1799, 90) == 8862,
    barrier_floor_bps(1799, 179) == 9863,
    barrier_floor_bps(1899, 7) == 1454,
    barrier_floor_bps(1899, 30) == 5830,
    barrier_floor_bps(1899, 90) == 8663,
    barrier_floor_bps(1899, 179) == 9724,
    barrier_floor_bps(1999, 7) == 1203,
    barrier_floor_bps(1999, 30) == 5512,
    barrier_floor_bps(1999, 90) == 8463,
    barrier_floor_bps(1999, 179) == 9582,
    barrier_floor_bps(2149, 7) == 889,
    barrier_floor_bps(2149, 30) == 5044,
    barrier_floor_bps(2149, 90) == 8158,
    barrier_floor_bps(2149, 179) == 9365,
    barrier_floor_bps(2299, 7) == 641,
    barrier_floor_bps(2299, 30) == 4589,
    barrier_floor_bps(2299, 90) == 7849,
    barrier_floor_bps(2299, 179) == 9143,
    barrier_floor_bps(2499, 7) == 397,
    barrier_floor_bps(2499, 30) == 4009,
    barrier_floor_bps(2499, 90) == 7432,
    barrier_floor_bps(2499, 179) == 8839,
    barrier_floor_bps(2699, 7) == 234,
    barrier_floor_bps(2699, 30) == 3463,
    barrier_floor_bps(2699, 90) == 7010,
    barrier_floor_bps(2699, 179) == 8527,
    barrier_floor_bps(2899, 7) == 131,
    barrier_floor_bps(2899, 30) == 2953,
    barrier_floor_bps(2899, 90) == 6584,
    barrier_floor_bps(2899, 179) == 8207,
    barrier_floor_bps(3099, 7) == 69,
    barrier_floor_bps(3099, 30) == 2485,
    barrier_floor_bps(3099, 90) == 6156,
    barrier_floor_bps(3099, 179) == 7878,
    barrier_floor_bps(3399, 7) == 23,
    barrier_floor_bps(3399, 30) == 1865,
    barrier_floor_bps(3399, 90) == 5514,
    barrier_floor_bps(3399, 179) == 7370,
    barrier_floor_bps(3699, 7) == 6,
    barrier_floor_bps(3699, 30) == 1348,
    barrier_floor_bps(3699, 90) == 4878,
    barrier_floor_bps(3699, 179) == 6847,
    barrier_floor_bps(3999, 7) == 1,
    barrier_floor_bps(3999, 30) == 934,
    barrier_floor_bps(3999, 90) == 4254,
    barrier_floor_bps(3999, 179) == 6311,
    barrier_floor_bps(4399, 7) == 0,
    barrier_floor_bps(4399, 30) == 529,
    barrier_floor_bps(4399, 90) == 3454,
    barrier_floor_bps(4399, 179) == 5579,
    barrier_floor_bps(4799, 7) == 0,
    barrier_floor_bps(4799, 30) == 270,
    barrier_floor_bps(4799, 90) == 2709,
    barrier_floor_bps(4799, 179) == 4837,
    barrier_floor_bps(5199, 7) == 0,
    barrier_floor_bps(5199, 30) == 121,
    barrier_floor_bps(5199, 90) == 2035,
    barrier_floor_bps(5199, 179) == 4095,
    barrier_floor_bps(5599, 7) == 0,
    barrier_floor_bps(5599, 30) == 46,
    barrier_floor_bps(5599, 90) == 1451,
    barrier_floor_bps(5599, 179) == 3366,
    barrier_floor_bps(5999, 7) == 0,
    barrier_floor_bps(5999, 30) == 14,
    barrier_floor_bps(5999, 90) == 968,
    barrier_floor_bps(5999, 179) == 2667,
    barrier_floor_bps(6499, 7) == 0,
    barrier_floor_bps(6499, 30) == 2,
    barrier_floor_bps(6499, 90) == 517,
    barrier_floor_bps(6499, 179) == 1864,
    barrier_floor_bps(6999, 7) == 0,
    barrier_floor_bps(6999, 30) == 0,
    barrier_floor_bps(6999, 90) == 229,
    barrier_floor_bps(6999, 179) == 1174,
    barrier_floor_bps(7999, 7) == 0,
    barrier_floor_bps(7999, 30) == 0,
    barrier_floor_bps(7999, 90) == 16,
    barrier_floor_bps(7999, 179) == 270,
    barrier_floor_bps(8999, 7) == 0,
    barrier_floor_bps(8999, 30) == 0,
    barrier_floor_bps(8999, 90) == 0,
    barrier_floor_bps(8999, 179) == 9,
    barrier_floor_bps(9999, 7) == 0,
    barrier_floor_bps(9999, 30) == 0,
    barrier_floor_bps(9999, 90) == 0,
    barrier_floor_bps(9999, 179) == 0,
    barrier_floor_bps(1500, 7) == 2420,
    barrier_floor_bps(5000, 179) == 4095,
    barrier_floor_bps(6000, 90) == 517,
    barrier_floor_bps(9000, 179) == 0,
    barrier_floor_bps(1600, 13) == 3925,
  }
}

test barrier_deep_band_is_zero() {
  barrier_floor_bps(10000, 180) == 0 && barrier_floor_bps(12000, 365) == 0
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

test depeg_row_pins_finer_grid() {
  // [#363 F7] Values shift where the finer T-grid moves the band lower-edge:
  // 14d now floors to the 13d corner (34, was 36 @14d), 60d to the 55d corner
  // (143, was 156 @60d). The others sit on shared edges and are unchanged.
  depeg_floor_bps(1) == 2 && depeg_floor_bps(7) == 18 && depeg_floor_bps(14) == 34 && depeg_floor_bps(
    30,
  ) == 78 && depeg_floor_bps(60) == 143 && depeg_floor_bps(90) == 234 && depeg_floor_bps(
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
  // [#363 F7] 200 ADA cover, 30d, d=20%: finer grid floor is now 5044 bps =
  // 100.88 ADA (was 4009 on the 8x7 grid — the retune tightened it). A 110-ADA
  // premium clears the floor; a 50-ADA premium (below 100.88) fails.
  meets_barrier_floor(110_000_000, 200_000_000, 2000, 30) == True && meets_barrier_floor(
    50_000_000,
    200_000_000,
    2000,
    30,
  ) == False
}

test meets_barrier_floor_at_exact_floor_passes() {
  // premium exactly at floor: 200 ADA × 5044/10000 = 100.88 ADA.
  meets_barrier_floor(100_880_000, 200_000_000, 2000, 30) == True && meets_barrier_floor(
    100_879_999,
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

// [#363 red-team F3] The healthy-peg gate must sit strictly ABOVE every strike
// the band permits, so even the shallowest legal strike (0.95) is genuinely out
// of the money when the policy is written. If this ever inverts, cover could be
// sold already in the money — the exact hole F3 found.
// [#363 R4] THE property behind min_policy_term_ms: the vault must never admit
// a term the table prices at ZERO. Every reference to the constant elsewhere is
// RELATIVE (`min_policy_term_ms - 1`, `min_policy_term_ms`), so the tests are
// self-consistent with whatever value it holds — lowering it from 7 days to 1
// left the whole suite green, silently reverting the F6 control and putting
// every term back in t_band_index band 0, which is a literal 0 bps in every
// Barrier d-band.
//
// This asserts the property rather than the number, so it survives a deliberate
// re-tune of the constant and still catches an accidental one.
//
// Scoped to the NEAR-MONEY d-bands, where the table is the BINDING constraint.
// Deeper bands are deliberately 0 at short durations — per the header, a 40%+
// OTM barrier is so unlikely to touch that `is_premium_adequate`'s 50x ratio cap
// (an effective 200 bps) is the intended floor there. Asserting positivity
// across every band would encode a property the design does not have, and the
// first draft of this test did exactly that and failed at HEAD.
//
// The shallow end is where a zero floor is dangerous, and band 0 (t < 7d) is
// zero there TOO — which is the whole reason min_policy_term_ms exists.
test floor_is_priced_at_the_minimum_admissible_term() {
  let t_min_days = min_policy_term_ms / 86_400_000
  list.all(
    [min_strike_distance_bps, 2000, 2500, 3000],
    fn(d) { barrier_floor_bps(d, t_min_days) > 0 },
  )
}

test min_policy_term_is_seven_days() {
  // The absolute pin, alongside the property one above: the property survives a
  // deliberate re-tune, this catches an accidental edit.
  min_policy_term_ms == 7 * 86_400_000
}

test depeg_floor_is_priced_at_the_minimum_admissible_term() {
  depeg_floor_bps(min_policy_term_ms / 86_400_000) > 0
}

test healthy_peg_is_above_every_permitted_strike() {
  min_depeg_spot_pct > depeg_strike_hi_pct
}

test depeg_band_and_healthy_peg_imply_the_distance_margin() {
  // [#391 R2 F3] Why `underwrite_baseline_ok`'s Depeg arm no longer carries a
  // `d_bps >= min_depeg_distance_bps` conjunct: it CANNOT be the refusing leg.
  // The band caps the strike at `depeg_strike_hi_pct` of peg and the health
  // gate floors spot at `min_depeg_spot_pct` of peg, so the tightest admissible
  // pair is the WORST case for the margin — highest permitted strike against
  // the lowest permitted spot. Deleting the conjunct from the validator left
  // all 1096 tests green, which is what a redundant guard looks like; this pins
  // the implication so widening the band or softening the peg floor goes RED
  // here instead of silently removing a margin nobody notices is gone.
  let worst_spot = price_scale * min_depeg_spot_pct / 100
  let worst_strike = price_scale * depeg_strike_hi_pct / 100
  let d_bps = ( worst_spot - worst_strike ) * 10_000 / worst_spot
  and {
    depeg_peg_is_healthy(worst_spot),
    depeg_strike_in_band(worst_strike),
    d_bps >= min_depeg_distance_bps,
    // and it is not a coincidence of one decimal: the corner clears the margin
    // with room, so ordinary re-tuning of either percentage stays safe.
    d_bps >= 2 * min_depeg_distance_bps,
  }
}

test depeg_peg_health_gate_boundaries() {
  and {
    // exactly at $0.99 is the boundary — accepted
    depeg_peg_is_healthy(990_000),
    // an intact peg is accepted
    depeg_peg_is_healthy(price_scale),
    // one lovelace-unit below the gate is refused
    !depeg_peg_is_healthy(989_999),
    // a collapsed peg is refused however deep the buyer sets the strike
    !depeg_peg_is_healthy(520_000),
    // fail CLOSED on an unresolvable / zero spot
    !depeg_peg_is_healthy(0),
  }
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
  barrier == 5044 && depeg == 78 && barrier != depeg
}
