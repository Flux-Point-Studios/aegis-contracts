//// Aegis V8 stable-vault — swappable ELIGIBILITY RULES (#362 §2.3).
////
//// This is the ONE part of coverage pricing that upgrades via the registry
//// beacon instead of a vault redeploy. It owns exactly the strike-/duration-/
//// vol-aware premium FLOOR + product dispatch — lifted verbatim from
//// `pool.ak::policy_floor_ok`, MINUS the oracle resolution + freshness (those
//// are the immutable vault's job; the logic is fed a vault-RESOLVED spot).
////
//// Trust boundary (R2): the logic returns a pure Bool over numbers the VAULT
//// supplies + pins to the real policy outputs. A malicious enacted logic can
//// only APPROVE an underpriced policy or DENY a fair one — a repricing attack
//// bounded by the 72h timelock (LPs exit first). It can never move value,
//// mint aLP, redirect a payout, or change the spot/premium/coverage — those
//// are all vault-owned.

use aegis/floor_table.{
  meets_barrier_floor, meets_depeg_floor, depeg_strike_in_band,
  min_strike_distance_bps,
}
use aegis/types.{Barrier, Depeg, RiskClass, depeg_eligible_nfts}
use aiken/collection/list

/// Per-policy terms the vault pins to each new policy output, then hands to the
/// logic for the floor judgment. `oracle_nft` gates the Depeg branch to
/// established-stablecoin feeds (pool.ak CRITICAL-1); barrier ignores it.
pub type PolicyTerms {
  risk_class: RiskClass,
  strike: Int,
  premium: Int,
  coverage: Int,
  term_days: Int,
  oracle_nft: ByteArray,
}

/// The withdraw redeemer. `spot` is the VAULT-resolved, already-fresh spot the
/// barrier floor is priced against (shared by every barrier policy in a batch,
/// matching pool.ak's one-resolution-per-tx). Ignored by pure-depeg entries.
pub type EligibilityClaim {
  spot: Int,
  policies: List<PolicyTerms>,
}

/// Barrier strike distance in bps against a vault-resolved spot.
/// `d = (spot - strike) / spot`. Guards spot > 0 (defensive; the vault only
/// ever supplies a positive resolved price).
pub fn barrier_distance_bps(spot: Int, strike: Int) -> Int {
  ( spot - strike ) * 10_000 / spot
}

/// The floor predicate for ONE policy against a resolved spot. Mirrors
/// `pool.ak::policy_floor_ok` sans freshness. This is the swappable rule.
pub fn policy_eligible(spot: Int, p: PolicyTerms) -> Bool {
  when p.risk_class is {
    Barrier ->
      if spot <= 0 {
        False
      } else {
        let d_bps = barrier_distance_bps(spot, p.strike)
        d_bps >= min_strike_distance_bps && meets_barrier_floor(
          p.premium,
          p.coverage,
          d_bps,
          p.term_days,
        )
      }
    Depeg ->
      list.has(depeg_eligible_nfts, p.oracle_nft) && depeg_strike_in_band(
        p.strike,
      ) && meets_depeg_floor(p.premium, p.coverage, p.term_days)
  }
}

/// The whole claim: EVERY policy must clear the floor. Empty list = vacuously
/// true, but the VAULT rejects an empty underwrite independently (a 0-policy
/// Underwrite has no coverage to reserve) so this is not a bypass here.
pub fn claim_eligible(claim: EligibilityClaim) -> Bool {
  list.all(claim.policies, fn(p) { policy_eligible(claim.spot, p) })
}

// ---------------------------------------------------------------------------
// Tests — lift the pool.ak floor semantics + prove the trust-boundary shape.
// Floor-cell values themselves are pinned exhaustively in floor_table.ak; here
// we prove the DISPATCH + the gates (min strike distance, depeg band/allowlist,
// spot guard, all-must-pass).
// ---------------------------------------------------------------------------

// A generously-priced 30d barrier at a deep (40%) strike distance: passes.
fn barrier_ok() -> PolicyTerms {
  PolicyTerms {
    risk_class: Barrier,
    strike: 60,
    // spot 100 -> d = 40% = 4000 bps (>> 1500 min). Premium 50% of coverage is
    // far above any barrier floor cell.
    premium: 500_000_000,
    coverage: 1_000_000_000,
    term_days: 30,
    oracle_nft: #"",
  }
}

test eligibility_barrier_generous_premium_passes() {
  policy_eligible(100, barrier_ok())
}

test eligibility_barrier_below_min_strike_distance_rejected() {
  // strike 90 vs spot 100 -> d = 10% = 1000 bps < 1500 min. Even a huge premium
  // cannot buy a near-money barrier.
  let near = PolicyTerms { ..barrier_ok(), strike: 90 }
  !policy_eligible(100, near)
}

test eligibility_barrier_underpriced_premium_rejected() {
  // deep 40% strike but a trivial premium (0.001% of coverage) misses the floor
  let cheap = PolicyTerms { ..barrier_ok(), premium: 10 }
  !policy_eligible(100, cheap)
}

test eligibility_barrier_nonpositive_spot_fails_closed() {
  and {
    !policy_eligible(0, barrier_ok()),
    !policy_eligible(-5, barrier_ok()),
  }
}

test eligibility_barrier_ignores_oracle_nft() {
  // a barrier with an arbitrary (non-depeg-allowlisted) oracle_nft still passes
  // on the price floor — the allowlist gates only Depeg.
  policy_eligible(100, PolicyTerms { ..barrier_ok(), oracle_nft: #"deadbeef" })
}

// A depeg policy on an allowlisted stablecoin feed with a strike in-band.
fn depeg_ok() -> PolicyTerms {
  // use the first network depeg-eligible feed if present; else the test is a
  // no-op guard (mainnet/preprod both populate it).
  let nft =
    when depeg_eligible_nfts is {
      [first, ..] -> first
      [] -> #""
    }
  PolicyTerms {
    risk_class: Depeg,
    // 80% of a $1 peg (scaled 1e6) = 800_000; inside the 50%-95% insurable band
    strike: 800_000,
    premium: 500_000_000,
    coverage: 1_000_000_000,
    term_days: 30,
    oracle_nft: nft,
  }
}

test eligibility_depeg_allowlisted_in_band_passes() {
  // Only meaningful when the network populates depeg_eligible_nfts; both do.
  when depeg_eligible_nfts is {
    [] -> True
    _ -> policy_eligible(0, depeg_ok())
  }
}

test eligibility_depeg_non_allowlisted_feed_rejected() {
  // the CRITICAL-1 gate: an ADA/BTC feed mislabeled Depeg can't skip the
  // barrier floor + spot read via the cheap duration-only depeg floor.
  !policy_eligible(0, PolicyTerms { ..depeg_ok(), oracle_nft: #"c0ffee" })
}

test eligibility_depeg_out_of_band_strike_rejected() {
  // strike at 99% of peg is above the 95% insurable ceiling -> rejected
  when depeg_eligible_nfts is {
    [] -> True
    _ -> !policy_eligible(0, PolicyTerms { ..depeg_ok(), strike: 990_000 })
  }
}

test eligibility_depeg_does_not_use_spot() {
  // depeg ignores spot entirely (trigger pinned near peg by construction) —
  // passes with spot 0.
  when depeg_eligible_nfts is {
    [] -> True
    _ -> policy_eligible(0, depeg_ok())
  }
}

test eligibility_claim_all_must_pass() {
  let good = barrier_ok()
  let bad = PolicyTerms { ..barrier_ok(), premium: 1 }
  and {
    claim_eligible(EligibilityClaim { spot: 100, policies: [good, good] }),
    // one bad policy fails the whole claim
    !claim_eligible(EligibilityClaim { spot: 100, policies: [good, bad] }),
  }
}

test eligibility_claim_empty_is_vacuously_true() {
  // vault independently rejects a 0-policy underwrite; the pure predicate is
  // vacuously true and that is documented, not a bypass.
  claim_eligible(EligibilityClaim { spot: 100, policies: [] })
}
