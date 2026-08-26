// =============================================================================
// Aegis - Premium CEILING table (the conservative-HIGH mirror of floor_table)
// Location: contracts/lib/aegis/ceiling_table.ak
//
// The floor table bounds UNDER-pricing (premium >= coverage x floor). This
// table bounds OVER-pricing: premium <= coverage x ceiling. It closes the
// "overcharge-within-budget" hole — a compromised API/operator pricing a
// vault-funded policy at up to per_tx_cap would otherwise be invisible on
// chain because the floor still passes. The Agent Vault's Spend arm enforces
// this ceiling against the SAME attested spot the pool reads.
//
// Construction (conservative-HIGH): each cell is K_MAX x the closed-form fair
// premium at the cell's MOST-EXPENSIVE corner — the SHALLOWEST strike distance
// (d-band LOWER edge) and the LONGEST term (T-band UPPER edge) — so any honest
// (d, T) inside the cell prices at or below it. K_MAX = 2.0 (matches the
// Phase-2 off-chain signer band). Values saturate at 10000 bps (= 100% of
// coverage), where the ceiling is a no-op because the engine already forbids
// premium >= coverage.
//
// Banding MIRRORS floor_table.ak exactly (same d-partition, same t_band_index)
// so d_bps/t_days map to the same cell — only the baked corner differs (d_lo/
// t_hi here vs d_hi/t_lo for the floor). Regenerate with docs/pricing (K_MAX,
// sigma=0.95, load=0.20); the Python mirror + golden test lock the values.
// =============================================================================

use aegis/floor_table.{barrier_floor_bps, depeg_floor_bps}
use aiken/collection/list

/// Map a duration in days to its T-band index 0..6. IDENTICAL to
/// floor_table.t_band_index (kept private there); duplicated so this module is
/// self-contained and diffs 1:1 against the floor.
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

/// Maximum premium (bps of coverage) for a Barrier policy at strike distance
/// `d_bps` and duration `t_days`. Columns are the T-band UPPER edges
/// {7,14,30,60,90,180,365}; rows are keyed by the d-band LOWER edge. Below the
/// 15% min strike distance the ceiling is a no-op (10000) — floor_table fails
/// that case closed, so the ceiling must not interfere with that rejection.
fn barrier_ceiling_raw(d_bps: Int, t_days: Int) -> Int {
  if d_bps < 1500 {
    10_000
  } else {
    let t = t_band_index(t_days)
    if d_bps < 2000 {
      // d-band [1500,2000), corner d_lo=1500
      pick7(t, 5635, 9934, 10000, 10000, 10000, 10000, 10000)
    } else if d_bps < 2500 {
      // [2000,2500), corner 2000
      pick7(t, 2408, 6167, 10000, 10000, 10000, 10000, 10000)
    } else if d_bps < 3000 {
      // [2500,3000), corner 2500
      pick7(t, 796, 3373, 8020, 10000, 10000, 10000, 10000)
    } else if d_bps < 4000 {
      // [3000,4000), corner 3000
      pick7(t, 300, 1580, 5429, 10000, 10000, 10000, 10000)
    } else if d_bps < 5000 {
      // [4000,5000), corner 4000
      pick7(t, 300, 300, 1869, 5660, 8510, 10000, 10000)
    } else if d_bps < 7000 {
      // [5000,7000), corner 5000
      pick7(t, 300, 300, 369, 2410, 4725, 9844, 10000)
    } else {
      // [7000, ∞): corner 7000
      pick7(t, 300, 300, 300, 300, 459, 2995, 8396)
    }
  }
}

/// [F7-retune reconcile] The barrier FLOOR was raised (docs/pricing F7 retune,
/// deployed in the V8 eligibility_logic). A max-premium CEILING below the min is
/// nonsensical and made those cells unwritable, so pin the ceiling at >= the
/// floor. Every cell where the #129 cap already exceeded the floor is unchanged;
/// only the cells the retune pushed the floor past the old cap move up to it.
pub fn barrier_ceiling_bps(d_bps: Int, t_days: Int) -> Int {
  let raw = barrier_ceiling_raw(d_bps, t_days)
  // Below the 15% min strike distance the FLOOR is a rejection sentinel (not a
  // real premium), so the ceiling stays its no-op 10000 there. Only pin to the
  // floor inside the writable band (d >= 1500), where a real floor lives.
  if d_bps < 1500 {
    raw
  } else {
    let f = barrier_floor_bps(d_bps, t_days)
    if raw > f {
      raw
    } else {
      f
    }
  }
}

/// Maximum premium (bps of coverage) for a Depeg policy of duration `t_days`.
/// Duration-only, conservative-HIGH: the native-coin hazard tier (λ=0.25) x
/// K_MAX at the T-band UPPER edge. The floor uses the established tier
/// (λ=0.08), so ceiling >> floor for every cell.
pub fn depeg_ceiling_bps(t_days: Int) -> Int {
  pick7(t_band_index(t_days), 300, 300, 489, 967, 1435, 2784, 5309)
}

/// Premium-ceiling predicate (Barrier). Cross-multiplied integer comparison,
/// mirroring meets_barrier_floor: premium/coverage <= ceiling_bps/10000.
pub fn meets_barrier_ceiling(
  premium: Int,
  coverage: Int,
  d_bps: Int,
  t_days: Int,
) -> Bool {
  premium * 10_000 <= coverage * barrier_ceiling_bps(d_bps, t_days)
}

/// Premium-ceiling predicate (Depeg, duration-only).
pub fn meets_depeg_ceiling(premium: Int, coverage: Int, t_days: Int) -> Bool {
  premium * 10_000 <= coverage * depeg_ceiling_bps(t_days)
}

// ---------------------------------------------------------------------------
// Tests — cell locks + floor<=ceiling invariant + honest-premium clearance
// ---------------------------------------------------------------------------

test ceiling_cell_locks() {
  // durations chosen to land in the intended T-band (floored): t=3->band0,
  // t=20->band2, t=365->band6, depeg t=20->band2.
  barrier_ceiling_bps(1500, 3) == 5635 && barrier_ceiling_bps(3200, 20) == 5429 && barrier_ceiling_bps(
    9000,
    365,
  ) == 8396 && depeg_ceiling_bps(20) == 489
}

// Every cell is floored at 300 bps (>= the max_coverage_ratio=50 minimum of
// 200 bps) so a ratio-minimum premium on a deep/short cell is never rejected.
test ceiling_floored_at_ratio_minimum() {
  barrier_ceiling_bps(9000, 3) == 300 && barrier_ceiling_bps(4200, 3) == 300 && depeg_ceiling_bps(
    3,
  ) == 300
}

test ceiling_below_min_distance_is_noop() {
  barrier_ceiling_bps(1000, 30) == 10_000
}

// The band's own floor corner must never exceed its ceiling corner — otherwise
// no valid premium could exist in the cell. Checks every d-band x T-band cell.
test floor_never_exceeds_ceiling() {
  let d_probe = [1500, 2000, 2500, 3000, 4000, 5000, 7000, 9000]
  let t_probe = [1, 7, 14, 30, 60, 90, 180, 365]
  list.all(
    d_probe,
    fn(d) {
      list.all(
        t_probe,
        fn(t) { barrier_floor_bps(d, t) <= barrier_ceiling_bps(d, t) },
      )
    },
  )
}

test depeg_floor_never_exceeds_ceiling() {
  let t_probe = [1, 7, 14, 30, 60, 90, 180, 365]
  list.all(t_probe, fn(t) { depeg_floor_bps(t) <= depeg_ceiling_bps(t) })
}

// An honest premium priced AT the floor clears the ceiling (the ceiling never
// rejects a legitimately-priced policy).
test honest_floor_premium_clears_ceiling() {
  let coverage = 100_000_000
  // d=30% (d_bps 3000), 30d: floor ~934 bps, ceiling 10000 -> clears.
  let floor_premium = coverage * barrier_floor_bps(3000, 30) / 10_000
  meets_barrier_ceiling(floor_premium, coverage, 3000, 30)
}

// A 5x-fair overcharge on a deep short policy is CAUGHT.
test gross_overcharge_is_rejected() {
  let coverage = 100_000_000
  // d=50% (d_bps 5000), 14d: ceiling 369 bps. A premium at 2000 bps (20% of
  // coverage) is a gross overcharge -> rejected.
  meets_barrier_ceiling(coverage * 2000 / 10_000, coverage, 5000, 14) == False
}
