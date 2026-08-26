//// Aegis V8 stable-vault — LP share math with the virtual-shares inflation
//// defense (closes red-team H4/M7) + the vault arm-accounting predicates. The
//// immutable vault's never-rug arms call these pure fns; `backing` is the
//// vault's DERIVED spendable lovelace (utxo − min − reserve), so donations
//// (which land in `reserve`) can never skew the ratio.
////
//// Virtual-shares (OpenZeppelin ERC-4626 decimals-offset mitigation): a first
//// depositor mints `deposit * OFFSET` shares, and the `+ OFFSET` / `+ 1`
//// virtual terms make the classic "deposit 1, donate a lot, steal the next
//// depositor's funds" attack cost OFFSET× the victim's deposit — infeasible.

use aegis/eligibility.{PolicyTerms}
use aegis/floor_table.{
  depeg_peg_is_healthy, depeg_strike_in_band, min_strike_distance_bps,
}
use aegis/pricing.{is_ratio_acceptable}
use aegis/test_helpers/fixtures
use aegis/types.{
  Barrier, Depeg, PolicyDatum, RiskClass, claim_waiting_period_ms,
  max_policy_term_ms, max_reading_validity_ms, min_policy_term_ms, min_premium,
  price_scale, trailing_low_window_ms,
}
use cardano/address.{Address, Inline, Script, VerificationKey}

/// 10^6 virtual-share offset. Attack cost scales with this; 10^6 is ample and
/// keeps share magnitudes well inside Int.
pub const vshare_offset: Int = 1_000_000

// ---------------------------------------------------------------------------
// Underwrite SECURITY BASELINE (#362 coverage-arm-spec items 1,5,7 — the
// VAULT-BAKED floor a malicious enacted logic can never breach). The detailed
// actuarial curve (floor_table cells) is DELEGATED to the swappable
// eligibility_logic leaf; this baseline is what the immutable vault enforces
// ITSELF over its OWN resolved spot, so the worst a hostile logic can do is
// price BETWEEN this baseline and the correct curve (bounded under-pricing,
// handled by the 72h registry timelock) — never below it, never on a fake spot.
//
// `in_mandate` = list.has(allowed_oracle_nfts, oracle_nft) — the #327 gate, a
// vault compile-time param the validator evaluates. `in_depeg_allowlist` =
// list.has(depeg_eligible_nfts, oracle_nft) — the CRITICAL-1 mislabel gate.
// `resolved_spot` is the price the VAULT resolved via its pinned resolver
// (attested_price), never a logic- or redeemer-supplied number.
// ---------------------------------------------------------------------------
/// Explicit RiskClass equality — NEVER derive-Eq a sum type on Windows aiken
/// (a known silent-miscompile pitfall).
pub fn risk_class_eq(a: RiskClass, b: RiskClass) -> Bool {
  when a is {
    Barrier ->
      when b is {
        Barrier -> True
        Depeg -> False
      }
    Depeg ->
      when b is {
        Barrier -> False
        Depeg -> True
      }
  }
}

/// STRUCTURAL aLP-mint discipline: aLP may ONLY be minted/burned by AddLiquidity
/// / RemoveLiquidity; every other arm (Deposit / Underwrite / Claim + the
/// fail-closed Batch / Cancel / Expire) MUST have `alp_minted == 0`. The vault
/// calls this from `base_ok`, which is in every arm's conjunction — so no arm
/// can forget it (the red-team found a free-aLP-mint drain in BOTH the Underwrite
/// and Claim arms when the guard was per-arm; this makes it impossible to omit).
pub fn alp_mint_allowed(redeemer: VaultRedeemer, alp_minted: Int) -> Bool {
  when redeemer is {
    AddLiquidity { .. } -> True
    RemoveLiquidity { .. } -> True
    _ -> alp_minted == 0
  }
}

/// A policy's `payout_address` must never be aliased to the vault or the policy
/// script (the §2.6 pool-alias drain: a payout to the vault's own payment
/// credential lets the vault continuation satisfy the payment, so the insured is
/// cheated and the coverage stays in the pool). Compared by PAYMENT credential
/// so a matching cred with any stake credential is still rejected. `None` = pay
/// the insured directly (safe). Shared by Underwrite (pin at creation) and Claim
/// (re-check at payout) — one source of truth (DRY).
pub fn payout_not_aliased(
  payout: Option<Address>,
  vault_hash: ByteArray,
  policy_hash: ByteArray,
) -> Bool {
  when payout is {
    None -> True
    Some(a) -> and {
        a.payment_credential != Script(vault_hash),
        a.payment_credential != Script(policy_hash),
      }
  }
}

/// CRITICAL-2 binding: the eligibility-redeemer `PolicyTerms` the swappable logic
/// judged MUST equal, field-for-field, what the vault PINS into the policy-output
/// `PolicyDatum`. Combined with the vault asserting the redeemer.spot ==
/// vault-resolved spot, this closes the "logic passes on fake numbers while the
/// output carries real (cheap-premium, big-coverage) terms" gap. `term_days` is
/// floored from the pinned window, matching the floor-table T-band flooring.
pub fn terms_match_datum(t: PolicyTerms, pd: PolicyDatum) -> Bool {
  and {
    t.strike == pd.strike_price,
    t.premium == pd.premium_paid,
    t.coverage == pd.coverage_amount,
    t.oracle_nft == pd.oracle_nft,
    risk_class_eq(t.risk_class, pd.risk_class),
    t.term_days == ( pd.expiry_time - pd.start_time ) / 86_400_000,
  }
}

pub fn underwrite_baseline_ok(
  risk_class: RiskClass,
  resolved_spot: Int,
  resolved_min_12h: Int,
  strike: Int,
  premium: Int,
  coverage: Int,
  term_ms: Int,
  in_mandate: Bool,
  in_depeg_allowlist: Bool,
  // [V8.2 G3] the GOVERNED floors and bounds — Budgets.min_premium /
  // term_min_ms / term_max_ms, rail-bounded, threaded by the caller so the
  // compiled constants stay off the vault's hash surface.
  min_premium_b: Int,
  term_min_ms: Int,
  term_max_ms: Int,
) -> Bool {
  and {
    // #327 mandate: this pool may only underwrite feeds in its allowlist
    in_mandate,
    // [#391 R2 F2a] The strike must be clear of the reading's TRAILING LOW, not
    // merely of its spot. Spot is one instant and it can be up to
    // `max_spot_age_ms` stale, so a buyer who watches a DEX knows the barrier is
    // already through while the vault's print still says otherwise — that is the
    // free option: buy the already-broken cover, wait out the claim period, take
    // full coverage on a loss that pre-dates the term. The trailing low is a
    // twelve-hour low-water MARK, so it remembers the break the stale spot
    // forgot, and refusing the SALE costs an honest claimant nothing (a claim
    // rule that looked backwards would deny a genuine in-term break whose window
    // happens to also contain an older dip).
    //
    // Parsers default `min_price_12h` to spot when the publisher writes no key
    // 3, so on a 3-key feed this collapses to the spot gate below and changes
    // nothing — which is exactly the residual the publisher recommendation is
    // about.
    resolved_min_12h > strike,
    // min-premium + coverage/premium ratio baseline (prevents zero / negative /
    // absurd premium regardless of what the swappable logic says)
    premium >= min_premium_b && is_ratio_acceptable(premium, coverage),
    // [#363 red-team M1] vault-baked DURATION ceiling. The swappable logic owns
    // the duration-scaled actuarial curve, but the immutable vault bounds how
    // long LP capital can be locked, so the hostile-logic worst case stays
    // bounded UNDER-pricing rather than arbitrarily long-dated cheap options.
    term_ms > 0,
    term_ms <= term_max_ms,
    // [#363 red-team F6] ...and a vault-baked DURATION FLOOR, for the same
    // reason as the ceiling: the vault must never admit a term the premium
    // table cannot price. `floor_table.t_band_index` has no sub-7-day row —
    // every `t_days < 7` collapses to band 0, which returns a literal 0 bps in
    // EVERY strike-distance band. Without this, short-dated near-money cover
    // had no actuarial floor at all.
    term_ms >= term_min_ms,
    when risk_class is {
      Barrier ->
        // near-money guard over the VAULT-resolved spot (>= 15% strike distance)
        resolved_spot > 0 && {
          let d_bps = ( resolved_spot - strike ) * 10_000 / resolved_spot
          d_bps >= min_strike_distance_bps
        }
      Depeg ->
        and {
          // CRITICAL-1: only established-stablecoin feeds may take the cheap
          // duration-only depeg floor, and the strike must sit in the band
          in_depeg_allowlist,
          depeg_strike_in_band(strike),
          // [#391 R2 F3] The `resolved_spot > 0` and
          // `d_bps >= min_depeg_distance_bps` conjuncts that stood here are
          // GONE, as REDUNDANT rather than untested. Deleting either left all
          // 1096 tests green because neither can be the refusing leg: the two
          // survivors below already imply both. `depeg_peg_is_healthy` pins
          // spot at >= 99% of peg and `depeg_strike_in_band` caps the strike at
          // 95% of peg, so the tightest admissible pair is 950_000 against
          // 990_000 — 404 bps, twice the 200 bps margin — and a healthy peg is
          // positive by construction. `floor_table
          // ::depeg_band_and_healthy_peg_imply_the_distance_margin` pins that
          // implication at its corner, so widening the band or softening the
          // peg floor goes red instead of silently deleting a guard.
          //
          // [#363 red-team F3] The PEG itself must still be intact. A
          // spot-relative margin only proves the strike is out
          // of the money — a coin already collapsed to ~$0.52 cleared it at a
          // $0.50 strike and bought cover priced off the healthy-peg hazard
          // curve, whose λ does not remotely apply. Anchored to the peg, not
          // the strike, so deep "total collapse" cover stays buyable while the
          // peg holds and a LIVE depeg cannot be underwritten at any depth.
          depeg_peg_is_healthy(resolved_spot),
        }
    }
  }
}

// ---------------------------------------------------------------------------
// V8 vault datum + redeemer (#362 §2.1). A SINGLE canonical Vault UTxO carries
// the one-shot pool NFT + all LP value. Backing is DERIVED, never stored (C2).
//
// EXIT MODEL (post red-team v8-coverage-redteam CRITICAL-6): exits are ATOMIC
// `RemoveLiquidity` — the LP burns their OWN aLP in the same tx and is paid
// pro-rata of liquid backing. The ledger forbids burning tokens you do not
// hold, so there is no forgeable "exit intent" surface (the earlier two-step
// intent/settle let anyone forge an ExitIntent UTxO and drain via SettleExit).
// A queued two-step exit for heavy-coverage liquidity is a DEFERRED R3
// enhancement and MUST bind an intent to a real burn via a minted intent token,
// never a bare datum field.
// ---------------------------------------------------------------------------

pub type VaultState {
  Vault {
    lp_supply: Int,
    active_coverage: Int,
    reserve: Int,
    registry_nft: ByteArray,
  }
}

pub type VaultRedeemer {
  /// permissionless deposit; mints aLP pro-rata on the full pool total
  AddLiquidity { amount: Int }
  /// atomic exit; burn the caller's own aLP, pay pro-rata of liquid backing
  RemoveLiquidity { shares: Int }
  /// segregated first-loss/donation credit; no aLP minted
  DepositRevenue { amount: Int }
  // --- coverage arms (WIP #362): resolve spot in-vault, read eligibility
  // logic + registry, mint markers, create policy outputs. Not yet wired; the
  // pool_vault validator fails these closed. See the coverage-arm spec (the
  // v8-coverage-redteam must-fix list) before enabling.
  Underwrite { coverage: Int, premium: Int }
  Claim { payout: Int }
  AcceptCancellation
  Expire { total_returned: Int }
}

/// aLP minted for a deposit. `base`/`lp_supply` are pre-deposit.
///   mint = deposit * (lp_supply + OFFSET) / (base + 1)
/// First depositor (supply 0, base 0) -> deposit * OFFSET. The caller MUST
/// reject a result of 0 (a dust deposit into a huge pool rounds to nothing).
pub fn lp_mint(deposit: Int, base: Int, lp_supply: Int) -> Int {
  deposit * ( lp_supply + vshare_offset ) / ( base + 1 )
}

/// Lovelace returned for burning `lp_burned` aLP against the given base.
/// Inverse of `lp_mint`; the +1/+OFFSET virtual terms make it conserve.
///   withdrawal = lp_burned * (base + 1) / (lp_supply + OFFSET)
/// Note for exits we pass `base = backing` (liquid), so a burn of shares <=
/// lp_supply always yields <= backing (never withdraws parked coverage).
pub fn lp_withdraw(lp_burned: Int, base: Int, lp_supply: Int) -> Int {
  lp_burned * ( base + 1 ) / ( lp_supply + vshare_offset )
}

// ---------------------------------------------------------------------------
// Backing + pool total.
// ---------------------------------------------------------------------------

/// Spendable (liquid) backing behind aLP. Floors at 0 (a not-yet-funded vault
/// or a reserve larger than the balance yields 0, never negative). Coverage
/// that has been written has PHYSICALLY LEFT the pool into self-funded policy
/// UTxOs, so it is NOT part of this liquid figure.
pub fn derive_backing(own_lovelace: Int, min_utxo: Int, reserve: Int) -> Int {
  let b = own_lovelace - min_utxo - reserve
  if b > 0 {
    b
  } else {
    0
  }
}

/// Total LP-attributable capital = liquid backing + the coverage parked in live
/// policies (pool-funded, returns on expiry / is lost on claim). This is the
/// base LP shares MUST price against on DEPOSIT (the V7 `total_liquidity`
/// reconstructed from physical lovelace + the vault-controlled `active_coverage`
/// counter, so no free-floating total field exists for a malicious logic to
/// inflate — C2). At `active_coverage == 0` this equals `backing`, so the
/// LP-only phase is unaffected. Pricing a deposit against `backing` alone would
/// OVER-mint to a joining LP and dilute the incumbents — this closes that.
pub fn pool_total(backing: Int, active_coverage: Int) -> Int {
  backing + active_coverage
}

// ---------------------------------------------------------------------------
// Arm ACCOUNTING predicates (#362). The money math of each arm, extracted as
// pure fns so a fund-loss bug is caught by unit tests (the pool.ak pattern:
// security logic in pure fns, structural continuity — NFT, value-preservation,
// registry pin — in the validator). Each pins EVERY datum field the arm does
// not change (default-deny).
// ---------------------------------------------------------------------------

/// AddLiquidity: mint EXACTLY the pro-rata aLP against the FULL pool total
/// (liquid backing + parked coverage), grow the vault by the deposit, move only
/// lp_supply. `alp_minted` = the tx's net aLP mint (must be positive).
pub fn add_liquidity_ok(
  old: VaultState,
  new: VaultState,
  amount: Int,
  backing: Int,
  own_lovelace: Int,
  cont_lovelace: Int,
  alp_minted: Int,
) -> Bool {
  expect Vault { lp_supply, active_coverage, reserve, .. } = old
  expect Vault {
    lp_supply: ns,
    active_coverage: nc,
    reserve: nr,
    ..
  } = new
  // price against backing + active_coverage, NOT backing alone
  let minted = lp_mint(amount, pool_total(backing, active_coverage), lp_supply)
  and {
    amount > 0,
    alp_minted == minted,
    minted > 0,
    cont_lovelace == own_lovelace + amount,
    ns == lp_supply + minted,
    nc == active_coverage,
    nr == reserve,
  }
}

/// RemoveLiquidity: burn EXACTLY the caller's `shares` aLP and pay pro-rata of
/// LIQUID backing (never the parked coverage). `alp_minted` = net aLP mint
/// (must be exactly -shares); `paid` = lovelace sent to the exiter's non-aliased
/// address (the validator enforces the address). Under-pays vs the full-book
/// share while coverage is parked — conservative/safe, never a drain — and the
/// exiter forgoes pending coverage risk/reward (R3 refines heavy-coverage
/// liveness). shares <= lp_supply => payout <= backing, so it is always liquid.
pub fn remove_liquidity_ok(
  old: VaultState,
  new: VaultState,
  shares: Int,
  backing: Int,
  own_lovelace: Int,
  cont_lovelace: Int,
  alp_minted: Int,
  paid: Int,
) -> Bool {
  expect Vault { lp_supply, active_coverage, reserve, .. } = old
  expect Vault {
    lp_supply: ns,
    active_coverage: nc,
    reserve: nr,
    ..
  } = new
  let payout = lp_withdraw(shares, backing, lp_supply)
  and {
    shares > 0,
    shares <= lp_supply,
    // [door 6, 2026-08-10] NO EXIT-SIDE BOOK CAP HERE, and it is a ruling, not
    // an omission. The no-worsening form was ratified conditionally and its
    // required adversarial review BLOCKED it: the escape hatch is unreachable
    // (disjunct 1 guarantees post_total >= 3*nc, so the next pre_total >= 3*nc
    // and the strict-`>` hatch can never open; every other arm only grows the
    // slack, and genesis writes active_coverage 0). Reachably it IS the naive
    // mirror, whose whole-pool exit allowance is `backing - 2*active_coverage`
    // — exactly ZERO at the protocol's own 33% design point — so it delivers
    // the exit lock the door ruled against, and any buyer can front-run an exit
    // with a permissionless pool-funded Underwrite to freeze the pool for a
    // premium of ~2% of the coverage they park. The LP-vs-LP fairness gap this
    // would have closed stands as the operator's recorded accepted cost.
    // If an exit-side cap is ever wanted it must be LAXER than the sale-side
    // one, so the design point is not the lock point (e.g. `nc * 2`, leaving a
    // third of the pool withdrawable at full utilisation) — and it needs an
    // off-chain mirror in the same slice, which today's builder does not have.
    // [#391 F4] Supply may not reach zero while coverage is still parked. That
    // coverage returns to the vault on Expire, and with no shares outstanding
    // the virtual-share offset prices a later deposit of X at exactly X — the
    // returned book is then reachable by nobody. The last LP waits for the book
    // to settle, or leaves a share behind; every other exit is unaffected.
    ns > 0 || active_coverage == 0,
    alp_minted == -shares,
    paid >= payout,
    cont_lovelace == own_lovelace - payout,
    ns == lp_supply - shares,
    nc == active_coverage,
    nr == reserve,
  }
}

/// DepositRevenue: credit the segregated reserve, no aLP, only reserve moves.
pub fn deposit_revenue_ok(
  old: VaultState,
  new: VaultState,
  amount: Int,
  own_lovelace: Int,
  cont_lovelace: Int,
  alp_minted: Int,
) -> Bool {
  expect Vault { lp_supply, active_coverage, reserve, .. } = old
  expect Vault {
    lp_supply: ns,
    active_coverage: nc,
    reserve: nr,
    ..
  } = new
  and {
    amount > 0,
    alp_minted == 0,
    cont_lovelace == own_lovelace + amount,
    nr == reserve + amount,
    ns == lp_supply,
    nc == active_coverage,
  }
}

/// Underwrite: reserve `coverage` for a new policy, take `premium` (of which
/// `net_growth` stays in the pool, the fee routes to team/partner outputs the
/// validator checks). The coverage LEAVES the pool to fund the self-held policy
/// UTxO; `active_coverage` grows so the LP total is preserved. No aLP moves.
///
///   value:  cont_lovelace == own_lovelace + net_growth - coverage
///   datum:  active_coverage += coverage; supply/reserve unchanged
///   marker: exactly 1 minted; policy UTxO self-funded >= coverage
///   cap:    post active_coverage * 3 <= post pool_total (the 33% book cap)
pub fn underwrite_ok(
  old: VaultState,
  new: VaultState,
  coverage: Int,
  premium: Int,
  net_growth: Int,
  own_lovelace: Int,
  cont_lovelace: Int,
  marker_minted: Int,
  policy_lovelace: Int,
  min_utxo: Int,
) -> Bool {
  expect Vault { lp_supply, active_coverage, reserve, .. } = old
  expect Vault {
    lp_supply: ns,
    active_coverage: nc,
    reserve: nr,
    ..
  } = new
  let post_backing = derive_backing(cont_lovelace, min_utxo, reserve)
  let post_total = pool_total(post_backing, nc)
  and {
    coverage > 0,
    premium > 0,
    net_growth >= 0,
    // coverage must clear min-utxo so the exact-funded policy output is valid
    coverage >= min_utxo,
    cont_lovelace == own_lovelace + net_growth - coverage,
    nc == active_coverage + coverage,
    ns == lp_supply,
    nr == reserve,
    marker_minted == 1,
    policy_lovelace >= coverage,
    // 33% accumulation cap (lifts pool.ak): the live book <= 1/3 of the total
    nc * 3 <= post_total,
  }
}

/// Version-independent claim TRIGGER (M5 — the vault RECOMPUTES this from a
/// freshly-resolved price + the policy's PINNED strike/window; it never trusts a
/// stored verdict, so a v1 policy claims correctly after a v2 logic enacts).
/// Closes red-team #11 (stale-resolver replay, via the freshness legs) and #17
/// (claim-after-expiry, via within_expiry). Lifts pool.ak/policy.ak
/// `barrier_touched` + `oracle_fresh` (both barrier and depeg trigger when the
/// resolved price touches the strike; depeg's strike sits in the peg band).
///
///   touched   := spot <= strike OR (12h-low <= strike AND that low fell DURING
///                the policy, i.e. low_observed_at >= start_time — SEC F-1)
///   fresh     := tx_lower in [observed_at, valid_until] AND tx_upper <= valid_until
///                (claim wants a RECENT reading: tx_lower >= observed_at — the
///                OPPOSITE direction from the underwrite freshness leg)
///   in-window := tx_lower >= start_time AND tx_upper <= expiry_time
/// The barrier is "touched" (policy in-the-money) when the resolved spot is at/
/// under the strike, OR the trailing-12h low fell at/under the strike AND that
/// low fell DURING the policy (SEC F-1: a pre-start low must not trigger). Shared
/// by claim_trigger_ok (claim wants touched) and the Cancel gate (cancel wants
/// UN-touched) so both read the identical barrier definition — one source of truth.
/// [#391 R2 F1] Does this reading carry trailing-low PROVENANCE at all?
///
/// `low_observed_at` is `0` when the publisher wrote no key 4 — the shape every
/// live depeg feed uses today. Absence gates the CAPABILITY, never the reading:
/// a 3-key reading settles on spot alone, a 5-key reading may additionally use
/// its trailing low. Both the retro disjunct and the pre-start veto below
/// consult this, so neither can be reached by a reading that cannot answer it.
pub fn has_trailing_low(low_observed_at: Int) -> Bool {
  low_observed_at > 0
}

/// [#391 R2 F2a] The reading itself says the strike was already broken BEFORE
/// this policy started. That is not the insured's loss — the cover had not
/// attached — and paying it is the free option DEFECT 2 measured: buy on a
/// stale print while the peg is already through the strike, wait out the
/// period, collect full coverage on a breach the vault can SEE pre-dates the
/// term.
///
/// Only a reading with provenance can make this claim, so it is capability-
/// gated; a 3-key reading leaves the veto disarmed and settles on spot alone.
/// `underwrite_baseline_ok` refuses to SELL such a policy in the first place
/// (`resolved_min_12h > strike`), so the window this can fire on is the few
/// minutes between the print that set the strike and `start_time` — which is
/// why it can never deny an honest in-term break.
pub fn pre_start_breach(
  min_price_12h: Int,
  low_observed_at: Int,
  strike: Int,
  start_time: Int,
) -> Bool {
  and {
    has_trailing_low(low_observed_at),
    min_price_12h <= strike,
    low_observed_at < start_time,
  }
}

pub fn barrier_touched(
  spot: Int,
  min_price_12h: Int,
  low_observed_at: Int,
  strike: Int,
  start_time: Int,
) -> Bool {
  and {
    !pre_start_breach(min_price_12h, low_observed_at, strike, start_time),
    spot <= strike || min_price_12h <= strike && low_observed_at >= start_time,
  }
}

/// A resolved reading is fresh for settlement when the tx window sits inside the
/// oracle's [observed_at, valid_until] validity (claim/cancel want a RECENT
/// reading: tx_lower >= observed_at). Shared by claim_trigger_ok + the Cancel gate.
///
/// [#391 F2] It also bounds `low_observed_at` AGAINST THE READING IT TRAVELS
/// WITH. That field is the whole of `barrier_touched`'s retro gate — it decides
/// whether a touch fell during the policy — and it was publisher-authored and
/// unconstrained anywhere in lib or validators. Both directions cost money:
///
///   * a low stamped AFTER its own reading is physically impossible, and makes
///     any pre-policy touch look like it fell inside the term. Full coverage,
///     for a premium, on an event that already happened.
///   * a low stamped before the trailing window it summarises reads as UN-
///     touched, which denies a genuine claim AND lets the Cancel arm refund a
///     policy that is in the money — free optionality, chosen by the publisher.
///
/// Bounding it here rather than at each call site is what makes it total: every
/// arm that judges a reading routes through this predicate, so a future
/// settlement arm inherits the bound instead of having to remember it.
pub fn reading_fresh(
  low_observed_at: Int,
  observed_at: Int,
  valid_until: Int,
  tx_lower: Int,
  tx_upper: Int,
) -> Bool {
  and {
    // [#391 R2 F1] ...WHEN THE READING CARRIES ONE. A 3-key reading has no
    // key 4 to bound, and bounding its `0` sentinel would refuse the datum
    // shape every live depeg feed publishes. One conjunct per direction, so
    // each is deletable on its own against its own named test.
    !has_trailing_low(low_observed_at) || low_observed_at <= observed_at,
    !has_trailing_low(low_observed_at) || low_observed_at >= observed_at - trailing_low_window_ms,
    tx_lower >= observed_at,
    tx_lower <= valid_until,
    tx_upper <= valid_until,
    // [#363 K-1 residual] The publisher's validity window is BOUNDED by the
    // validator, not trusted unbounded. Without this a feed with
    // `valid_until = observed_at + 100y` is claim-fresh forever (dead-publisher
    // / frozen-price risk). See types.max_reading_validity_ms.
    valid_until <= observed_at + max_reading_validity_ms,
  }
}

test reading_fresh_rejects_unbounded_publisher_validity() {
  // A reading whose publisher-written validity outruns the ceiling is NOT fresh,
  // even with the tx sitting snugly inside [observed_at, valid_until]. This is
  // the K-1 residual: the claim trigger's only staleness bound WAS the
  // publisher envelope, and the publisher could make it infinite.
  let observed_at = 1_700_000_000_000
  let hundred_years = 100 * 365 * 86_400_000
  !reading_fresh(
    observed_at,
    observed_at,
    observed_at + hundred_years,
    observed_at + 1_000,
    observed_at + 2_000,
  )
}

test reading_fresh_accepts_validity_at_the_ceiling() {
  // Exactly at the ceiling is honest (a publisher publishing the max window),
  // and a tx inside it is fresh. Pins the boundary so the bound is not
  // accidentally exclusive.
  let observed_at = 1_700_000_000_000
  reading_fresh(
    observed_at,
    observed_at,
    observed_at + max_reading_validity_ms,
    observed_at + 1_000,
    observed_at + 2_000,
  )
}

test reading_fresh_rejects_validity_one_ms_over_ceiling() {
  let observed_at = 1_700_000_000_000
  !reading_fresh(
    observed_at,
    observed_at,
    observed_at + max_reading_validity_ms + 1,
    observed_at + 1_000,
    observed_at + 2_000,
  )
}

/// [#391 F1] `waiting_period_ms` is the policy's PINNED delay before it may be
/// claimed, and it is enforced HERE — on the shared `within_start` leg — rather
/// than inside `barrier_touched`. That placement is the whole point: the trigger
/// has TWO disjuncts, and `spot <= strike` carries no time gate whatsoever, so a
/// wait that gated only the `min_price_12h` disjunct would leave the buy-stale/
/// claim-next-block cycle completely intact through the other one. A conjunct
/// above the disjunction gates both, unconditionally.
///
/// It delays the claim; it does not erase the event. `min_price_12h` is a
/// twelve-hour low-water mark and `low_observed_at` remembers when that low
/// fell, so a genuine break inside the waiting period is still claimable once
/// the period expires — even if spot has fully recovered by then.
///
/// The Cancel gate deliberately does NOT take a waiting period: cancellation
/// asks only whether the policy is in the money, and delaying that answer would
/// hand the insured exactly the optionality the OTM check exists to remove.
pub fn claim_trigger_ok(
  spot: Int,
  min_price_12h: Int,
  low_observed_at: Int,
  observed_at: Int,
  valid_until: Int,
  strike: Int,
  start_time: Int,
  expiry_time: Int,
  tx_lower: Int,
  tx_upper: Int,
  waiting_period_ms: Int,
) -> Bool {
  let within_start = tx_lower >= start_time + waiting_period_ms
  let within_expiry = tx_upper <= expiry_time
  and {
    barrier_touched(spot, min_price_12h, low_observed_at, strike, start_time),
    reading_fresh(
      low_observed_at,
      observed_at,
      valid_until,
      tx_lower,
      tx_upper,
    ),
    within_start,
    within_expiry,
  }
}

/// [#391 F1] The waiting period THIS policy was sold under: the value pinned
/// into its datum at Underwrite, or the CORE floor for its class when the datum
/// predates the pin. Underwrite refuses a pin below that floor, so the pinned
/// value is only ever safer than CORE — which is what makes reading it here
/// safe even though the pin travels in the policy the claimant supplies.
pub fn policy_waiting_period_ms(pd: PolicyDatum) -> Int {
  when pd.settlement_pins is {
    None -> claim_waiting_period_ms(pd.risk_class)
    Some(p) -> p.claim_waiting_period_ms
  }
}

/// [V8.2 G5] The Pyth outage feed THIS policy was sold under. `#""` is "no
/// fallback": the value a mandate arming no second leg carries, and the value a
/// policy written before the pins tail existed decodes to. Underwrite binds the
/// pin EQUAL to the governed mandate's own fallback, so settlement can resolve
/// the leg from the policy alone and still be reading a feed governance named
/// for this policy's underlying — which is what lets the vault settle with no
/// registry input at all (Invariant S).
pub fn policy_fallback_feed_id(pd: PolicyDatum) -> ByteArray {
  when pd.settlement_pins is {
    None -> #""
    Some(p) -> p.fallback_feed_id
  }
}

/// [#391 F1] The Underwrite-side half: a policy may DISCLOSE a longer wait than
/// CORE, never a shorter one, and never one that outlives the cover it delays.
pub fn waiting_period_pin_ok(pd: PolicyDatum) -> Bool {
  when pd.settlement_pins is {
    None -> True
    Some(p) -> and {
        p.claim_waiting_period_ms >= claim_waiting_period_ms(pd.risk_class),
        p.claim_waiting_period_ms <= pd.expiry_time - pd.start_time,
      }
  }
}

/// Claim: pay `payout` (== the consumed policy's coverage) to the insured, pull
/// the policy's self-held lovelace back into the tx, burn its marker, and
/// release the coverage. Lifts pool.ak verify_claim_datum's non-negativity +
/// bound guards (F-007). `policy_lovelace` = the consumed policy UTxO's value.
///
///   value:  cont_lovelace == own_lovelace + policy_lovelace - payout
///   datum:  active_coverage -= payout; supply/reserve unchanged
///   marker: exactly 1 burned (net -1)
///
/// NOTE (red-team HIGH): the first-loss `reserve`-first draw
/// (verify_claim_datum_with_reserve) is NOT modelled here yet — that is folded
/// into the coverage-arm wiring so a claim draws the reserve tranche before LP
/// capital. Until then Claim stays fail-closed in the validator.
pub fn claim_ok(
  old: VaultState,
  new: VaultState,
  payout: Int,
  policy_coverage: Int,
  own_lovelace: Int,
  cont_lovelace: Int,
  policy_lovelace: Int,
  marker_minted: Int,
) -> Bool {
  expect Vault { lp_supply, active_coverage, reserve, .. } = old
  expect Vault {
    lp_supply: ns,
    active_coverage: nc,
    reserve: nr,
    ..
  } = new
  // First-loss draw: the claim loss hits the segregated `reserve` tranche
  // BEFORE LP-attributable backing (V7 verify_claim_datum_with_reserve). The
  // policy self-funds the payout, so value is net-neutral — decrementing the
  // reserve counter re-labels that lovelace from "set aside" to backing, so the
  // freed amount offsets the LP loss. `from_reserve = min(payout, reserve)`.
  let from_reserve =
    if payout <= reserve {
      payout
    } else {
      reserve
    }
  and {
    // payout is exactly the policy's coverage (no over/under-pay to the insured)
    payout == policy_coverage,
    payout >= 0,
    // cannot release more coverage than is outstanding (F-007 negative-active)
    payout <= active_coverage,
    cont_lovelace == own_lovelace + policy_lovelace - payout,
    nc == active_coverage - payout,
    nc >= 0,
    ns == lp_supply,
    nr == reserve - from_reserve,
    nr >= 0,
    marker_minted == -1,
  }
}

/// Expire: a policy PAST its expiry that was never claimed. Its self-held
/// lovelace returns WHOLLY to the pool and the coverage is released; nothing is
/// paid out. Mirror of `claim_ok` with no payout leg — releasing the coverage is
/// what keeps the pool from bleeding capacity as policies age out. The "past
/// expiry" gate (tx_lower > expiry_time) lives in the validator wiring (it needs
/// the validity range); this predicate is the pure accounting + conservation.
///
///   value:  cont_lovelace == own_lovelace + policy_lovelace   (all funds back)
///   datum:  active_coverage -= coverage; supply/reserve unchanged
///   marker: exactly 1 burned (net -1)
pub fn expire_ok(
  old: VaultState,
  new: VaultState,
  coverage: Int,
  own_lovelace: Int,
  cont_lovelace: Int,
  policy_lovelace: Int,
  marker_minted: Int,
) -> Bool {
  expect Vault { lp_supply, active_coverage, reserve, .. } = old
  expect Vault {
    lp_supply: ns,
    active_coverage: nc,
    reserve: nr,
    ..
  } = new
  and {
    coverage > 0,
    // cannot release more coverage than is outstanding (keeps nc >= 0)
    coverage <= active_coverage,
    // every lovelace the policy self-held returns to the pool; none leaves
    cont_lovelace == own_lovelace + policy_lovelace,
    nc == active_coverage - coverage,
    nc >= 0,
    ns == lp_supply,
    nr == reserve,
    marker_minted == -1,
  }
}

/// AcceptCancellation: the insured cancels early (within the cancellation window,
/// policy OUT of the money). They receive `refund` (= calculate_refund(premium),
/// ~90%); the retention (premium − refund) is already in the pool from underwrite
/// and stays as LP profit; the coverage returns to the pool. Only self-funded
/// policies cancel (the validator gates payout_address == None so a DAO-funded
/// buyer cannot pocket a refund on premium the DAO paid). Mirror of `expire_ok`
/// with a refund leg out to the insured.
///
///   value:  cont_lovelace == own_lovelace + policy_lovelace − refund
///   datum:  active_coverage −= coverage; supply/reserve unchanged
///   marker: exactly 1 burned (net −1)
pub fn cancel_ok(
  old: VaultState,
  new: VaultState,
  coverage: Int,
  refund: Int,
  own_lovelace: Int,
  cont_lovelace: Int,
  policy_lovelace: Int,
  marker_minted: Int,
) -> Bool {
  expect Vault { lp_supply, active_coverage, reserve, .. } = old
  expect Vault {
    lp_supply: ns,
    active_coverage: nc,
    reserve: nr,
    ..
  } = new
  and {
    coverage > 0,
    coverage <= active_coverage,
    refund >= 0,
    // the refund can never exceed what the policy returns — no pool drain even
    // if a premium were somehow pinned absurdly large (defense in depth; the
    // validator separately binds refund == calculate_refund(pinned premium))
    refund <= policy_lovelace,
    cont_lovelace == own_lovelace + policy_lovelace - refund,
    nc == active_coverage - coverage,
    nc >= 0,
    ns == lp_supply,
    nr == reserve,
    marker_minted == -1,
  }
}

// ---------------------------------------------------------------------------
// Tests (TDD) — the inflation attack + the arm fund-loss vectors are the
// load-bearing ones.
// ---------------------------------------------------------------------------

fn vs(supply: Int, cov: Int, reserve: Int) -> VaultState {
  Vault { lp_supply: supply, active_coverage: cov, reserve, registry_nft: #"aa" }
}

test lp_mint_first_depositor_gets_offset_scaled_shares() {
  lp_mint(100_000_000, 0, 0) == 100_000_000 * vshare_offset
}

test lp_mint_dust_into_huge_pool_stays_positive_here() {
  let backing = 1_000_000_000
  let supply = 1_000_000_000 * vshare_offset
  lp_mint(1, backing, supply) > 0
}

test inflation_attack_is_unprofitable() {
  // Attacker is first depositor with 1 lovelace, then DONATES 10^12 lovelace.
  // In V8 donations go to `reserve` (excluded from backing), so backing stays 1
  // and the attack is fully neutralized. This tests the WORST case: even if the
  // donation DID hit backing, virtual shares protect the victim.
  let attacker_deposit = 1
  let att_shares = lp_mint(attacker_deposit, 0, 0)
  let donation = 1_000_000_000_000
  let backing_after = attacker_deposit + donation
  let victim_deposit = 100_000_000
  let victim_shares = lp_mint(victim_deposit, backing_after, att_shares)
  let total_shares = att_shares + victim_shares
  let total_backing = backing_after + victim_deposit
  let attacker_redeem = lp_withdraw(att_shares, total_backing, total_shares)
  and {
    att_shares == vshare_offset,
    victim_shares > 0,
    attacker_redeem <= attacker_deposit + donation,
  }
}

test lp_roundtrip_returns_about_deposit() {
  let deposit = 500_000_000
  let shares = lp_mint(deposit, 0, 0)
  let out = lp_withdraw(shares, deposit, shares)
  and {
    out <= deposit,
    out >= deposit - 2,
  }
}

test lp_second_depositor_pro_rata_is_fair() {
  let d = 1_000_000_000
  let s1 = lp_mint(d, 0, 0)
  let s2 = lp_mint(d, d, s1)
  let total_backing = d + d
  let total_supply = s1 + s2
  let lp2_out = lp_withdraw(s2, total_backing, total_supply)
  and {
    lp2_out <= d,
    lp2_out >= d - d / 1_000_000,
  }
}

// --- backing derivation ---

test derive_backing_subtracts_min_and_reserve() {
  derive_backing(1_000_000_000, 2_000_000, 50_000_000) == 948_000_000
}

test derive_backing_floors_at_zero() {
  and {
    derive_backing(1_000_000, 2_000_000, 0) == 0,
    derive_backing(10_000_000, 2_000_000, 50_000_000) == 0,
  }
}

// --- AddLiquidity ---

test add_liquidity_first_deposit_ok() {
  let old = vs(0, 0, 0)
  let minted = lp_mint(500_000_000, 0, 0)
  let new = vs(minted, 0, 0)
  add_liquidity_ok(old, new, 500_000_000, 0, 2_000_000, 502_000_000, minted)
}

test add_liquidity_wrong_mint_rejected() {
  let old = vs(0, 0, 0)
  let minted = lp_mint(500_000_000, 0, 0)
  let new = vs(minted, 0, 0)
  and {
    !add_liquidity_ok(old, new, 500_000_000, 0, 2_000_000, 502_000_000, minted + 1),
    !add_liquidity_ok(old, vs(minted + 1, 0, 0), 500_000_000, 0, 2_000_000, 502_000_000, minted),
  }
}

test add_liquidity_value_skim_rejected() {
  let old = vs(0, 0, 0)
  let minted = lp_mint(500_000_000, 0, 0)
  let new = vs(minted, 0, 0)
  !add_liquidity_ok(old, new, 500_000_000, 0, 2_000_000, 501_999_999, minted)
}

test add_liquidity_cannot_touch_coverage_or_reserve() {
  let old = vs(0, 0, 0)
  let minted = lp_mint(500_000_000, 0, 0)
  and {
    !add_liquidity_ok(old, vs(minted, 1, 0), 500_000_000, 0, 2_000_000, 502_000_000, minted),
    !add_liquidity_ok(old, vs(minted, 0, 1), 500_000_000, 0, 2_000_000, 502_000_000, minted),
  }
}

test add_liquidity_prices_against_full_book_not_just_liquid() {
  // LP1 = 1000 ADA first. A 300-ADA policy is written: backing ~729, active 300,
  // pool_total ~1029. LP2 deposits 1000. Pricing against pool_total mints FEWER
  // shares than pricing against liquid backing would -> incumbents not diluted.
  let d = 1_000_000_000
  let s1 = lp_mint(d, 0, 0)
  let backing = 729_000_000
  let active = 300_000_000
  let minted_correct = lp_mint(d, pool_total(backing, active), s1)
  let minted_buggy = lp_mint(d, backing, s1)
  and {
    minted_correct < minted_buggy,
    add_liquidity_ok(vs(s1, active, 0), vs(s1 + minted_correct, active, 0), d, backing, backing + 2_000_000, backing + 2_000_000 + d, minted_correct),
    !add_liquidity_ok(vs(s1, active, 0), vs(s1 + minted_buggy, active, 0), d, backing, backing + 2_000_000, backing + 2_000_000 + d, minted_buggy),
  }
}

// --- RemoveLiquidity (atomic, forgery-free) ---

test remove_liquidity_solo_full_returns_deposit() {
  // solo LP deposits 500 ADA, then removes ALL shares -> ~500 ADA back.
  let d = 500_000_000
  let s = lp_mint(d, 0, 0)
  let payout = lp_withdraw(s, d, s)
  let old = vs(s, 0, 0)
  let new = vs(0, 0, 0)
  and {
    remove_liquidity_ok(old, new, s, d, d + 2_000_000, d + 2_000_000 - payout, -s, payout),
    payout <= d,
    payout >= d - 2,
  }
}

test remove_liquidity_must_burn_exactly_shares() {
  let d = 500_000_000
  let s = lp_mint(d, 0, 0)
  let payout = lp_withdraw(s, d, s)
  let old = vs(s, 0, 0)
  let new = vs(0, 0, 0)
  and {
    // under-burn (attacker keeps aLP) -> reject
    !remove_liquidity_ok(old, new, s, d, d + 2_000_000, d + 2_000_000 - payout, -( s - 1 ), payout),
    // no burn at all -> reject
    !remove_liquidity_ok(old, new, s, d, d + 2_000_000, d + 2_000_000 - payout, 0, payout),
  }
}

test remove_liquidity_over_drain_rejected() {
  // draining MORE lovelace than the pro-rata payout -> reject
  let d = 500_000_000
  let s = lp_mint(d, 0, 0)
  let payout = lp_withdraw(s, d, s)
  let old = vs(s, 0, 0)
  let new = vs(0, 0, 0)
  !remove_liquidity_ok(old, new, s, d, d + 2_000_000, d + 2_000_000 - payout - 1, -s, payout)
}

test remove_liquidity_underpay_the_exiter_rejected() {
  // paying the exiter LESS than pro-rata (paid < payout) -> reject
  let d = 500_000_000
  let s = lp_mint(d, 0, 0)
  let payout = lp_withdraw(s, d, s)
  let old = vs(s, 0, 0)
  let new = vs(0, 0, 0)
  !remove_liquidity_ok(old, new, s, d, d + 2_000_000, d + 2_000_000 - payout, -s, payout - 1)
}

test remove_liquidity_partial_pro_rata_is_fair() {
  // two equal LPs; LP1 removes all their shares, gets ~half the backing.
  let d = 500_000_000
  let s1 = lp_mint(d, 0, 0)
  let s2 = lp_mint(d, d, s1)
  let backing = d + d
  let supply = s1 + s2
  let payout = lp_withdraw(s1, backing, supply)
  let old = vs(supply, 0, 0)
  let new = vs(supply - s1, 0, 0)
  and {
    remove_liquidity_ok(old, new, s1, backing, backing + 2_000_000, backing + 2_000_000 - payout, -s1, payout),
    payout <= d + 1,
    payout >= d - 2,
  }
}

test remove_liquidity_payout_never_exceeds_backing() {
  // even removing ALL supply, the payout is <= backing (never touches parked
  // coverage): pool with active coverage, remove everything.
  let backing = 400_000_000
  let supply = 1_000_000 * vshare_offset
  let payout = lp_withdraw(supply, backing, supply)
  payout <= backing
}

// --- DepositRevenue ---

test deposit_revenue_ok_and_rejects_alp_mint() {
  let old = vs(1000, 500, 10)
  let new = vs(1000, 500, 10 + 40_000_000)
  and {
    deposit_revenue_ok(old, new, 40_000_000, 100_000_000, 140_000_000, 0),
    !deposit_revenue_ok(old, new, 40_000_000, 100_000_000, 140_000_000, 1),
    !deposit_revenue_ok(old, vs(1000, 500, 10), 40_000_000, 100_000_000, 140_000_000, 0),
  }
}

// --- Underwrite accounting ---

fn uw_old() -> VaultState {
  vs(1_000_000_000, 0, 0)
}

test underwrite_happy_path() {
  let old = uw_old()
  let new = vs(1_000_000_000, 300_000_000, 0)
  underwrite_ok(old, new, 300_000_000, 30_000_000, 29_000_000, 1_002_000_000, 731_000_000, 1, 300_000_000, 2_000_000)
}

test underwrite_rejects_coverage_inflation() {
  let old = uw_old()
  let bad = vs(1_000_000_000, 300_000_001, 0)
  !underwrite_ok(old, bad, 300_000_000, 30_000_000, 29_000_000, 1_002_000_000, 731_000_000, 1, 300_000_000, 2_000_000)
}

test underwrite_rejects_value_skim() {
  let old = uw_old()
  let new = vs(1_000_000_000, 300_000_000, 0)
  and {
    !underwrite_ok(old, new, 300_000_000, 30_000_000, 29_000_000, 1_002_000_000, 731_000_001, 1, 300_000_000, 2_000_000),
    !underwrite_ok(old, new, 300_000_000, 30_000_000, 29_000_000, 1_002_000_000, 731_000_000, 1, 299_999_999, 2_000_000),
  }
}

test underwrite_requires_exactly_one_marker() {
  let old = uw_old()
  let new = vs(1_000_000_000, 300_000_000, 0)
  and {
    !underwrite_ok(old, new, 300_000_000, 30_000_000, 29_000_000, 1_002_000_000, 731_000_000, 0, 300_000_000, 2_000_000),
    !underwrite_ok(old, new, 300_000_000, 30_000_000, 29_000_000, 1_002_000_000, 731_000_000, 2, 300_000_000, 2_000_000),
  }
}

test underwrite_cannot_mint_alp_or_touch_supply() {
  let old = uw_old()
  let bad = vs(1_000_000_001, 300_000_000, 0)
  !underwrite_ok(old, bad, 300_000_000, 30_000_000, 29_000_000, 1_002_000_000, 731_000_000, 1, 300_000_000, 2_000_000)
}

test underwrite_enforces_33pct_accumulation_cap() {
  let old = vs(100_000_000, 0, 0)
  let new = vs(100_000_000, 90_000_000, 0)
  !underwrite_ok(old, new, 90_000_000, 10_000_000, 9_000_000, 102_000_000, 21_000_000, 1, 90_000_000, 2_000_000)
}

// --- Claim accounting ---

test claim_happy_path() {
  let old = vs(1_000_000_000, 300_000_000, 0)
  let new = vs(1_000_000_000, 0, 0)
  claim_ok(old, new, 300_000_000, 300_000_000, 731_000_000, 731_000_000, 300_000_000, -1)
}

test claim_rejects_payout_not_equal_coverage() {
  let old = vs(1_000_000_000, 300_000_000, 0)
  and {
    // over-pay drain -> reject (active would go to -1)
    !claim_ok(old, vs(1_000_000_000, -1, 0), 300_000_001, 300_000_000, 731_000_000, 730_999_999, 300_000_000, -1),
    // under-pay cheats the insured -> reject
    !claim_ok(old, vs(1_000_000_000, 1, 0), 299_999_999, 300_000_000, 731_000_000, 731_000_001, 300_000_000, -1),
  }
}

test claim_rejects_active_coverage_underflow() {
  let old = vs(1_000_000_000, 100_000_000, 0)
  let new = vs(1_000_000_000, -200_000_000, 0)
  !claim_ok(old, new, 300_000_000, 300_000_000, 731_000_000, 731_000_000, 300_000_000, -1)
}

test claim_requires_marker_burn() {
  let old = vs(1_000_000_000, 300_000_000, 0)
  let new = vs(1_000_000_000, 0, 0)
  and {
    !claim_ok(old, new, 300_000_000, 300_000_000, 731_000_000, 731_000_000, 300_000_000, 0),
    !claim_ok(old, new, 300_000_000, 300_000_000, 731_000_000, 731_000_000, 300_000_000, 1),
  }
}

test claim_rejects_pool_value_skim() {
  let old = vs(1_000_000_000, 300_000_000, 0)
  let new = vs(1_000_000_000, 0, 0)
  !claim_ok(old, new, 300_000_000, 300_000_000, 731_000_000, 731_000_001, 300_000_000, -1)
}

test claim_draws_reserve_first() {
  // First-loss tranche: a 300-ADA claim against a pool with a 100-ADA reserve
  // must absorb min(300,100)=100 from the reserve (leaving it 0), so the freed
  // lovelace re-enters backing and the LP loss is 200 not 300. Value is
  // net-neutral (self-funded policy pays out); only the reserve counter moves.
  let old = vs(1_000_000_000, 300_000_000, 100_000_000)
  let new = vs(1_000_000_000, 0, 0)
  claim_ok(old, new, 300_000_000, 300_000_000, 831_000_000, 831_000_000, 300_000_000, -1)
}

test claim_reserve_draw_is_capped_at_reserve() {
  // reserve LARGER than the payout absorbs only `payout`, not the whole reserve.
  // reserve 500, payout 300 -> new reserve 200; active 300 -> 0.
  let old = vs(1_000_000_000, 300_000_000, 500_000_000)
  let new = vs(1_000_000_000, 0, 200_000_000)
  and {
    claim_ok(old, new, 300_000_000, 300_000_000, 831_000_000, 831_000_000, 300_000_000, -1),
    // draining MORE than min(payout,reserve) from the reserve is rejected
    !claim_ok(old, vs(1_000_000_000, 0, 199_000_000), 300_000_000, 300_000_000, 831_000_000, 831_000_000, 300_000_000, -1),
  }
}

// --- claim TRIGGER (version-independent, M5) ---
// Fixture: strike 100, policy window [1000, 5000], a fresh reading observed at
// 1500 valid_until 4000, 12h-low 120 first seen at 1500. Claim tx range [2000,2100].

test claim_trigger_barrier_touch_now_passes() {
  // spot 90 <= strike 100 -> touched; fresh + in window
  claim_trigger_ok(90, 120, 1500, 1500, 4000, 100, 1000, 5000, 2000, 2100, 0)
}

test claim_trigger_no_touch_rejected() {
  // spot 150 > 100 and the 12h-low 120 > 100 -> never touched
  !claim_trigger_ok(150, 120, 1500, 1500, 4000, 100, 1000, 5000, 2000, 2100, 0)
}

test claim_trigger_12h_low_during_window_passes() {
  // spot 150 now, but the 12h low 90 <= strike AND its low fell at 1500 >= start
  claim_trigger_ok(150, 90, 1500, 1500, 4000, 100, 1000, 5000, 2000, 2100, 0)
}

test claim_trigger_12h_low_before_start_rejected() {
  // SEC F-1: the 12h low 90 touched, but it fell at 500 < start 1000 -> not counted
  !claim_trigger_ok(150, 90, 500, 1500, 4000, 100, 1000, 5000, 2000, 2100, 0)
}

test claim_trigger_stale_reading_rejected() {
  // tx_lower 2000 < observed_at 2500 -> reading is in the FUTURE / not yet seen
  !claim_trigger_ok(90, 120, 2500, 2500, 4000, 100, 1000, 5000, 2000, 2100, 0)
}

test claim_trigger_reading_past_validity_rejected() {
  // tx_upper 4500 > valid_until 4000 -> the reading has expired
  !claim_trigger_ok(90, 120, 1500, 1500, 4000, 100, 1000, 5000, 3900, 4500, 0)
}

test claim_trigger_after_expiry_rejected() {
  // tx_upper 6000 > expiry 5000 -> policy already ended (#17)
  !claim_trigger_ok(90, 120, 5500, 5500, 7000, 100, 1000, 5000, 5500, 6000, 0)
}

test claim_trigger_before_start_rejected() {
  // tx_lower 500 < start 1000 -> policy not yet active
  !claim_trigger_ok(90, 120, 400, 400, 4000, 100, 1000, 5000, 500, 600, 0)
}

// --- claim TRIGGER: the waiting period + the bounded low-water mark [#391] ---
// The eight fixtures above pass a ZERO waiting period on purpose: each was
// written to isolate one leg (touch, freshness, expiry, before-start) and a
// real period would move every one of them for reasons unrelated to the leg
// under test. These five pin the period itself, on the same toy window.

test claim_trigger_inside_the_waiting_period_rejected() {
  // spot 90 <= strike 100 and the reading is fresh, so the ONLY thing that can
  // reject this is the wait: tx_lower 1200 < start 1000 + 500.
  !claim_trigger_ok(90, 120, 1100, 1100, 4000, 100, 1000, 5000, 1200, 1300, 500)
}

test claim_trigger_at_the_waiting_period_boundary_passes() {
  // tx_lower EXACTLY at start + wait. The bound is inclusive, so the first
  // block after the period is claimable and the period is not off by one.
  claim_trigger_ok(90, 120, 1400, 1400, 4000, 100, 1000, 5000, 1500, 1600, 500)
}

test claim_trigger_break_that_recovered_inside_the_wait_still_pays() {
  // The honest buyer the waiting period must not rob. Spot is back ABOVE the
  // strike (150 > 100) by the time the period expires, but the twelve-hour low
  // 90 remembers the break and `low_observed_at` 1100 places it inside the
  // policy. Paid at 1600. The wait delays the claim; it never erases the event.
  claim_trigger_ok(150, 90, 1100, 1600, 5000, 100, 1000, 5000, 1600, 1700, 500)
}

test reading_fresh_rejects_a_low_stamped_after_its_own_reading() {
  // [#391 F2] The publisher-authored field, in the direction that costs the
  // pool: a low reported to have happened 500 ms AFTER the reading carrying it.
  !reading_fresh(2001, 2000, 4000, 2000, 2100)
}

test reading_fresh_rejects_a_low_older_than_the_trailing_window() {
  // [#391 F2] The other direction, which costs the buyer: a low stamped outside
  // the twelve hours `min_price_12h` is defined over reads as un-touched, which
  // denies a real claim and lets Cancel refund an in-the-money policy.
  let observed_at = 1_700_000_000_000
  and {
    !reading_fresh(
      observed_at - trailing_low_window_ms - 1,
      observed_at,
      observed_at + 4_200_000,
      observed_at,
      observed_at + 100,
    ),
    // exactly at the edge of the window is honest
    reading_fresh(
      observed_at - trailing_low_window_ms,
      observed_at,
      observed_at + 4_200_000,
      observed_at,
      observed_at + 100,
    ),
  }
}

// --- Underwrite security baseline (vault-baked floor vs a malicious logic) ---

test baseline_barrier_deep_strike_adequate_premium_passes() {
  // spot 100, strike 60 -> 40% distance (>>15%); premium 500 ADA on 1000 ADA
  // coverage (ratio 2x <= 50x, premium >> 20 ADA min); 7-day term. The reading's
  // trailing low is at spot: an ordinary market that has not been near 60.
  underwrite_baseline_ok(
    Barrier, 100, 100, 60, 500_000_000, 1_000_000_000, 7 * 86_400_000, True,
    False,
    min_premium,
    min_policy_term_ms,
    max_policy_term_ms,
  )
}

test baseline_barrier_near_money_rejected() {
  // strike 90 vs spot 100 -> 10% distance < 15% min
  !underwrite_baseline_ok(
    Barrier, 100, 100, 90, 500_000_000, 1_000_000_000, 7 * 86_400_000, True,
    False,
    min_premium,
    min_policy_term_ms,
    max_policy_term_ms,
  )
}

test baseline_rejects_out_of_mandate() {
  // in_mandate False -> reject regardless of everything else
  !underwrite_baseline_ok(
    Barrier, 100, 100, 60, 500_000_000, 1_000_000_000, 7 * 86_400_000, False,
    False,
    min_premium,
    min_policy_term_ms,
    max_policy_term_ms,
  )
}

test baseline_rejects_below_min_premium() {
  // premium 10 ADA < 20 ADA mainnet min
  !underwrite_baseline_ok(
    Barrier, 100, 100, 60, 10_000_000, 1_000_000_000, 7 * 86_400_000, True,
    False,
    min_premium,
    min_policy_term_ms,
    max_policy_term_ms,
  )
}

test baseline_rejects_over_leveraged_ratio() {
  // coverage 2000 ADA > 50x a 20-ADA premium (1000 ADA cap) -> reject
  !underwrite_baseline_ok(
    Barrier, 100, 100, 60, 20_000_000, 2_000_000_000, 7 * 86_400_000, True,
    False,
    min_premium,
    min_policy_term_ms,
    max_policy_term_ms,
  )
}

test baseline_rejects_nonpositive_spot() {
  and {
    !underwrite_baseline_ok(
      Barrier, 0, 0, 60, 500_000_000, 1_000_000_000, 7 * 86_400_000, True, False,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    !underwrite_baseline_ok(
      Barrier, -5, -5, 60, 500_000_000, 1_000_000_000, 7 * 86_400_000, True,
      False,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
  }
}

// [#391 R2 F2a] THE SALE-SIDE HALF OF THE FREE OPTION, on both classes.
//
// A spot print may be up to `max_spot_age_ms` old, so a buyer watching a DEX
// knows the barrier is already through while the vault's print still says it is
// not. The trailing low is a twelve-hour low-water MARK, so it remembers what
// the stale spot forgot. Every OTHER leg here passes: the strike clears the 15%
// distance against spot, the peg reads healthy, the term and premium are fine.
// Only `resolved_min_12h > strike` can refuse.
test baseline_refuses_a_strike_the_trailing_low_has_already_touched() {
  and {
    // Barrier: spot 100 (40% clear of a 60 strike) but the reading remembers a
    // print AT 60 inside the trailing twelve hours.
    !underwrite_baseline_ok(
      Barrier, 100, 60, 60, 500_000_000, 1_000_000_000, 7 * 86_400_000, True,
      False,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    // Depeg: peg reads a healthy 1.00 and the strike sits in band 20% below —
    // but the coin printed 0.80 within the trailing window.
    !underwrite_baseline_ok(
      Depeg, 1_000_000, 800_000, 800_000, 500_000_000, 1_000_000_000,
      7 * 86_400_000, True, True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
  }
}

test baseline_accepts_a_trailing_low_one_unit_above_the_strike() {
  // The boundary, and the honest anchor for the gate above: a market that came
  // within one unit of the strike and did not touch it is still insurable. The
  // gate is `>`, not `>=` — a low EQUAL to the strike is a touch.
  and {
    underwrite_baseline_ok(
      Barrier, 100, 61, 60, 500_000_000, 1_000_000_000, 7 * 86_400_000, True,
      False,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    underwrite_baseline_ok(
      Depeg, 1_000_000, 800_001, 800_000, 500_000_000, 1_000_000_000,
      7 * 86_400_000, True, True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
  }
}

test baseline_depeg_allowlisted_in_band_passes() {
  // strike 800_000 = 80% of a HEALTHY 1e6 peg: in the 50-95% band, and the
  // trailing low sits at peg so nothing has been near the strike.
  underwrite_baseline_ok(
    Depeg,
    1_000_000,
    1_000_000,
    800_000,
    500_000_000,
    1_000_000_000,
    7 * 86_400_000,
    True,
    True,
    min_premium,
    min_policy_term_ms,
    max_policy_term_ms,
  )
}

// [#391 R2 F3] NON-VACUOUS. This test used to pass `resolved_spot = 0`, which
// failed the arm's own `resolved_spot > 0` leg BEFORE the allowlist was
// consulted — so deleting `in_depeg_allowlist,` left all 1096 tests green. The
// spot is now a healthy peg and every other leg passes; the allowlist flag is
// the ONLY thing that can refuse.
test baseline_depeg_not_allowlisted_rejected() {
  !underwrite_baseline_ok(
    Depeg,
    1_000_000,
    1_000_000,
    800_000,
    500_000_000,
    1_000_000_000,
    7 * 86_400_000,
    True,
    False,
    min_premium,
    min_policy_term_ms,
    max_policy_term_ms,
  )
}

// [#391 R2 F3] NON-VACUOUS, same story: `resolved_spot = 0` refused this before
// the band was read, so deleting `depeg_strike_in_band(strike),` survived. Both
// ends of the band are exercised against a healthy peg, and the strike is the
// only out-of-range quantity.
test baseline_depeg_out_of_band_rejected() {
  and {
    // 99% of peg — above the 95% insurable ceiling
    !underwrite_baseline_ok(
      Depeg,
      1_000_000,
      1_000_000,
      990_000,
      500_000_000,
      1_000_000_000,
      7 * 86_400_000,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    // 40% of peg — below the 50% floor
    !underwrite_baseline_ok(
      Depeg,
      1_000_000,
      1_000_000,
      400_000,
      500_000_000,
      1_000_000_000,
      7 * 86_400_000,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
  }
}

// [#363 red-team N2 CRITICAL] Depeg no longer IGNORES spot — ignoring it WAS
// the vulnerability (cover bought mid-depeg, claimed next block).
test baseline_depeg_rejects_already_broken_peg() {
  and {
    // peg already BELOW the strike -> the policy is born in the money
    !underwrite_baseline_ok(
      Depeg,
      790_000,
      790_000,
      800_000,
      500_000_000,
      1_000_000_000,
      7 * 86_400_000,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    // [#391 R2 F3] The arm that USED to sit here read "peg only 12 bps clear of
    // the strike -> inside the 200 bps margin" and was a lie about which leg
    // refused it: at spot 801_000 the peg is 20% gone, so `depeg_peg_is_healthy`
    // rejected it and `min_depeg_distance_bps` was never reached. The margin is
    // in fact UNREACHABLE as a refusal (see the arm's comment and
    // `depeg_band_and_healthy_peg_imply_the_distance_margin`), so the conjunct
    // was deleted as redundant and this arm now says what it really tests: a peg
    // one unit under the 99% floor is refused however far the strike sits.
    !underwrite_baseline_ok(
      Depeg,
      989_999,
      989_999,
      800_000,
      500_000_000,
      1_000_000_000,
      7 * 86_400_000,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    // an unresolvable / zero spot must fail CLOSED, never open
    !underwrite_baseline_ok(
      Depeg,
      0,
      0,
      800_000,
      500_000_000,
      1_000_000_000,
      7 * 86_400_000,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
  }
}

// [#363 red-team F3] A spot-relative margin only ever proves the strike is 2%
// out of the money — it says nothing about whether the PEG is intact. With
// `depeg_strike_lo_pct = 50` a strike may sit at $0.50, so a coin that has
// ALREADY collapsed to ~$0.52 would sell "depeg cover" priced off the
// duration-only hazard curve, which is calibrated for a HEALTHY peg
// (λ = 0.08/yr of touching 0.95). The real probability of a coin at $0.52
// touching $0.50 within days is near 1 — mispricing by orders of magnitude,
// needing no governance compromise. The margin must be anchored to the PEG.
test baseline_depeg_rejects_collapsed_peg_at_deep_strike() {
  and {
    // USDC has already broken to $0.52; strike at the band floor of $0.50.
    !underwrite_baseline_ok(
      Depeg,
      520_000,
      520_000,
      500_000,
      500_000_000,
      1_000_000_000,
      7 * 86_400_000,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    // Softer but still broken: $0.90 against the shallowest allowed strike.
    !underwrite_baseline_ok(
      Depeg,
      900_000,
      900_000,
      850_000,
      500_000_000,
      1_000_000_000,
      7 * 86_400_000,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
  }
}

test baseline_depeg_accepts_healthy_peg_at_deep_strike() {
  // The same deep $0.50 strike is fine while the peg IS intact — this is the
  // honest "insure me against a total collapse" purchase, and it must stay
  // buyable. Pins that the F3 guard bounds the PEG, not the strike depth.
  underwrite_baseline_ok(
    Depeg,
    price_scale,
    price_scale,
    500_000,
    500_000_000,
    1_000_000_000,
    7 * 86_400_000,
    True,
    True,
    min_premium,
    min_policy_term_ms,
    max_policy_term_ms,
  )
}

// [#363 red-team M1] The floor must bound DURATION, not just price. Without
// these a hostile ENACTED logic mints arbitrarily long-dated, arbitrarily cheap
// coverage that locks LP capital far beyond the 72h-timelock worst case.
test baseline_rejects_over_max_term() {
  and {
    // one ms over the ceiling -> rejected though the price legs are fine.
    // Expressed against the constant so it tracks N4's 400d -> 180d change.
    !underwrite_baseline_ok(
      Barrier,
      100,
      100,
      60,
      500_000_000,
      1_000_000_000,
      max_policy_term_ms + 1,
      True,
      False,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    // the Depeg path must be bounded on duration too (healthy peg, in band)
    !underwrite_baseline_ok(
      Depeg,
      1_000_000,
      1_000_000,
      800_000,
      500_000_000,
      1_000_000_000,
      max_policy_term_ms + 1,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
  }
}

test baseline_accepts_exactly_max_term() {
  // boundary: exactly at the cap, not over it
  underwrite_baseline_ok(
    Barrier, 100, 100, 60, 500_000_000, 1_000_000_000, max_policy_term_ms, True,
    False,
    min_premium,
    min_policy_term_ms,
    max_policy_term_ms,
  )
}

// [#363 red-team F6] Symmetric to the ceiling, and for the same reason: the
// vault must never admit a term the floor table cannot price.
// `floor_table.t_band_index` maps every `t_days < 7` to band 0, and for BARRIER
// that band is a literal 0 bps in every strike-distance row — so a 6-day
// Barrier the actuarial curve contributes NOTHING below a week. The binding
// constraint there is `is_premium_adequate`'s 50x ratio cap, an effective
// 200 bps — so sub-7-day cover was priced at a flat 2% against an honest
// 7-day 15%-OTM rate of 1203 bps, ~6x under, on exactly the short-dated
// near-money barriers a crash pays out on. Depeg's band 0 is 2 bps, which the
// same 200 bps ratio floor dominates outright; the sharp hole is Barrier's.
test baseline_rejects_under_min_term() {
  and {
    !underwrite_baseline_ok(
      Barrier,
      100,
      100,
      60,
      500_000_000,
      1_000_000_000,
      min_policy_term_ms - 1,
      True,
      False,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    // the Depeg path is bounded at the bottom too (healthy peg, in band)
    !underwrite_baseline_ok(
      Depeg,
      1_000_000,
      1_000_000,
      800_000,
      500_000_000,
      1_000_000_000,
      min_policy_term_ms - 1,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
  }
}

test baseline_accepts_exactly_min_term() {
  // boundary: exactly 7 days is AT the floor — the shortest duration the buy
  // UI offers, and the first term the table prices non-zero.
  underwrite_baseline_ok(
    Barrier, 100, 100, 60, 500_000_000, 1_000_000_000, min_policy_term_ms, True,
    False,
    min_premium,
    min_policy_term_ms,
    max_policy_term_ms,
  )
}

test baseline_rejects_nonpositive_term() {
  and {
    !underwrite_baseline_ok(
      Barrier, 100, 100, 60, 500_000_000, 1_000_000_000, 0, True, False,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    !underwrite_baseline_ok(
      Barrier, 100, 100, 60, 500_000_000, 1_000_000_000, -1, True, False,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
  }
}

// --- CRITICAL-2 term binding: redeemer PolicyTerms == pinned PolicyDatum ---

// --- payout aliasing (shared Underwrite/Claim guard) ---

test payout_none_is_safe() {
  payout_not_aliased(None, #"aa", #"bb")
}

test payout_to_unrelated_wallet_passes() {
  let insured =
    Address {
      payment_credential: VerificationKey(#"cc"),
      stake_credential: None,
    }
  payout_not_aliased(Some(insured), #"aa", #"bb")
}

test payout_aliased_to_vault_rejected() {
  // payment cred == the vault script hash -> the §2.6 drain -> reject, even with
  // a different stake credential grafted on.
  let to_vault =
    Address { payment_credential: Script(#"aa"), stake_credential: None }
  and {
    !payout_not_aliased(Some(to_vault), #"aa", #"bb"),
    !payout_not_aliased(
      Some(
        Address {
          payment_credential: Script(#"aa"),
          stake_credential: Some(Inline(VerificationKey(#"dd"))),
        },
      ),
      #"aa",
      #"bb",
    ),
  }
}

test payout_aliased_to_policy_script_rejected() {
  let to_policy =
    Address { payment_credential: Script(#"bb"), stake_credential: None }
  !payout_not_aliased(Some(to_policy), #"aa", #"bb")
}

test risk_class_eq_reflexive_and_distinct() {
  and {
    risk_class_eq(Barrier, Barrier),
    risk_class_eq(Depeg, Depeg),
    !risk_class_eq(Barrier, Depeg),
    !risk_class_eq(Depeg, Barrier),
  }
}

// --- structural aLP-mint discipline (closes the twice-found free-aLP drain) ---

test alp_mint_allowed_liquidity_arms_may_mint_or_burn() {
  // AddLiquidity mints; RemoveLiquidity burns (negative). Both are the ONLY
  // arms that may move aLP, at any quantity.
  and {
    alp_mint_allowed(AddLiquidity { amount: 100 }, 5),
    alp_mint_allowed(RemoveLiquidity { shares: 5 }, -5),
    alp_mint_allowed(AddLiquidity { amount: 100 }, 0),
  }
}

test alp_mint_allowed_coverage_arms_forbid_any_mint() {
  // The exact drain the red-team found TWICE: a free aLP co-mint inside a
  // legitimate Underwrite / Claim, drained later via RemoveLiquidity. Every
  // non-liquidity arm must reject a non-zero mint.
  and {
    !alp_mint_allowed(Underwrite { coverage: 1, premium: 1 }, 5),
    !alp_mint_allowed(Claim { payout: 1 }, 5),
    !alp_mint_allowed(Claim { payout: 1 }, -5),
    !alp_mint_allowed(DepositRevenue { amount: 1 }, 5),
    !alp_mint_allowed(Expire { total_returned: 1 }, 5),
    !alp_mint_allowed(AcceptCancellation, 5),
  }
}

test alp_mint_allowed_coverage_arms_pass_with_zero_mint() {
  // The honest path: a Claim / Underwrite that mints no aLP is fine.
  and {
    alp_mint_allowed(Underwrite { coverage: 1, premium: 1 }, 0),
    alp_mint_allowed(Claim { payout: 1 }, 0),
    alp_mint_allowed(DepositRevenue { amount: 1 }, 0),
    alp_mint_allowed(AcceptCancellation, 0),
    alp_mint_allowed(Expire { total_returned: 1 }, 0),
  }
}

// --- Expire arm accounting (coverage returns to pool, no payout) ---

test expire_returns_coverage_and_burns_marker() {
  // A 50-ADA-coverage policy self-held 50 ADA; on expiry all 50 return to the
  // pool, active_coverage drops 200->150, one marker burned, nothing paid out.
  let old = vs(1000, 200_000_000, 10_000_000)
  let new = vs(1000, 150_000_000, 10_000_000)
  expire_ok(old, new, 50_000_000, 100_000_000, 150_000_000, 50_000_000, -1)
}

test expire_rejects_skimmed_return() {
  // Attacker routes part of the returning policy lovelace to themselves:
  // cont < own + policy_lovelace. Must reject (LP capital leaks on expiry).
  let old = vs(1000, 200_000_000, 10_000_000)
  let new = vs(1000, 150_000_000, 10_000_000)
  !expire_ok(old, new, 50_000_000, 100_000_000, 149_000_000, 50_000_000, -1)
}

test expire_rejects_coverage_not_released() {
  // active_coverage left unchanged (nc == old) — the released coverage would
  // ghost the book, inflating apparent free capacity forever. Reject.
  let old = vs(1000, 200_000_000, 10_000_000)
  let new = vs(1000, 200_000_000, 10_000_000)
  !expire_ok(old, new, 50_000_000, 100_000_000, 150_000_000, 50_000_000, -1)
}

test expire_rejects_no_marker_burn() {
  // Marker not burned (net 0): the policy could be re-expired / re-used. Reject.
  let old = vs(1000, 200_000_000, 10_000_000)
  let new = vs(1000, 150_000_000, 10_000_000)
  !expire_ok(old, new, 50_000_000, 100_000_000, 150_000_000, 50_000_000, 0)
}

test expire_rejects_reserve_touched() {
  // Expire must not move the first-loss reserve. Reject any reserve delta.
  let old = vs(1000, 200_000_000, 10_000_000)
  let new = vs(1000, 150_000_000, 9_000_000)
  !expire_ok(old, new, 50_000_000, 100_000_000, 150_000_000, 50_000_000, -1)
}

test expire_rejects_over_release() {
  // Release more coverage than outstanding -> nc would go negative. Reject.
  let old = vs(1000, 40_000_000, 10_000_000)
  let new = vs(1000, -10_000_000, 10_000_000)
  !expire_ok(old, new, 50_000_000, 100_000_000, 150_000_000, 50_000_000, -1)
}

// --- barrier_touched shared definition (claim wants touched, cancel wants NOT) ---

test barrier_touched_spot_low_and_sec_f1_boundary() {
  and {
    // spot at/under strike -> touched
    barrier_touched(90, 200, 5, 100, 1),
    // trailing-12h low at/under strike AND the low fell DURING the policy -> touched
    barrier_touched(200, 90, 5, 100, 1),
    // fully out of the money -> NOT touched (cancellable)
    !barrier_touched(200, 200, 5, 100, 1),
    // SEC F-1: a 12h low at/under strike but observed BEFORE start -> NOT touched
    !barrier_touched(200, 90, 0, 100, 1),
  }
}

// --- AcceptCancellation accounting (refund to insured, coverage to pool) ---

test cancel_refunds_insured_and_burns_marker() {
  // 50-ADA-coverage policy self-held 50 ADA; premium was 5 ADA -> refund 4.5.
  // cont = 100 + 50 - 4.5 = 145.5; active_coverage 200->150; marker burned.
  let old = vs(1000, 200_000_000, 10_000_000)
  let new = vs(1000, 150_000_000, 10_000_000)
  cancel_ok(old, new, 50_000_000, 4_500_000, 100_000_000, 145_500_000, 50_000_000, -1)
}

test cancel_rejects_refund_exceeding_return() {
  // Refund larger than the policy's returning lovelace -> would drain the pool.
  let old = vs(1000, 200_000_000, 10_000_000)
  let new = vs(1000, 150_000_000, 10_000_000)
  !cancel_ok(old, new, 50_000_000, 60_000_000, 100_000_000, 90_000_000, 50_000_000, -1)
}

test cancel_rejects_skimmed_continuation() {
  // cont short of own + policy_lovelace - refund: LP capital skimmed. Reject.
  let old = vs(1000, 200_000_000, 10_000_000)
  let new = vs(1000, 150_000_000, 10_000_000)
  !cancel_ok(old, new, 50_000_000, 4_500_000, 100_000_000, 144_500_000, 50_000_000, -1)
}

test cancel_rejects_coverage_not_released() {
  let old = vs(1000, 200_000_000, 10_000_000)
  let new = vs(1000, 200_000_000, 10_000_000)
  !cancel_ok(old, new, 50_000_000, 4_500_000, 100_000_000, 145_500_000, 50_000_000, -1)
}

test cancel_rejects_no_marker_burn() {
  let old = vs(1000, 200_000_000, 10_000_000)
  let new = vs(1000, 150_000_000, 10_000_000)
  !cancel_ok(old, new, 50_000_000, 4_500_000, 100_000_000, 145_500_000, 50_000_000, 0)
}

test cancel_rejects_reserve_touched() {
  let old = vs(1000, 200_000_000, 10_000_000)
  let new = vs(1000, 150_000_000, 9_000_000)
  !cancel_ok(old, new, 50_000_000, 4_500_000, 100_000_000, 145_500_000, 50_000_000, -1)
}

test terms_match_datum_exact_match_passes() {
  let pd = fixtures.default_policy_datum()
  // term = (expiry - start)/86_400_000 = 604_800_000/86_400_000 = 7 days
  let t =
    PolicyTerms {
      risk_class: Barrier,
      strike: 350_000,
      premium: 200_000_000,
      coverage: 5_000_000_000,
      term_days: 7,
      oracle_nft: pd.oracle_nft,
    }
  terms_match_datum(t, pd)
}

test terms_match_datum_any_field_divergence_rejected() {
  let pd = fixtures.default_policy_datum()
  let base =
    PolicyTerms {
      risk_class: Barrier,
      strike: 350_000,
      premium: 200_000_000,
      coverage: 5_000_000_000,
      term_days: 7,
      oracle_nft: pd.oracle_nft,
    }
  and {
    // the attack: logic judged a cheap premium / big coverage while the pinned
    // datum carries different (real) numbers -> reject each divergence
    !terms_match_datum(PolicyTerms { ..base, premium: 199_999_999 }, pd),
    !terms_match_datum(PolicyTerms { ..base, coverage: 5_000_000_001 }, pd),
    !terms_match_datum(PolicyTerms { ..base, strike: 350_001 }, pd),
    !terms_match_datum(PolicyTerms { ..base, term_days: 6 }, pd),
    !terms_match_datum(PolicyTerms { ..base, oracle_nft: #"deadbeef" }, pd),
    !terms_match_datum(PolicyTerms { ..base, risk_class: Depeg }, pd),
  }
}

// ===========================================================================
// [#391 F4] The orphaned book. Nothing stops `lp_supply` reaching 0 while
// coverage is still parked in live policies, and the parked lovelace returns
// to a pool with no shares against it. Written in POSITIVE form: the predicate
// ACCEPTS the exit that orphans it.
// ===========================================================================

test ec_last_lp_may_not_exit_while_the_book_is_still_live() {
  // One LP, 500 ADA in, one 150 ADA policy live. The LP burns EVERY share and
  // is paid out of liquid backing alone, so supply hits 0 while 150 ADA of
  // coverage is still parked. That coverage returns on Expire to a pool that
  // has no shares against it.
  let d = 500_000_000
  let s = lp_mint(d, 0, 0)
  let coverage = 150_000_000
  let backing = d - coverage
  let payout = lp_withdraw(s, backing, s)
  let old = vs(s, coverage, 0)
  let new = vs(0, coverage, 0)
  !remove_liquidity_ok(
    old,
    new,
    s,
    backing,
    backing + 2_000_000,
    backing + 2_000_000 - payout,
    -s,
    payout,
  )
}

test ec_a_deposit_into_the_orphaned_pool_redeems_at_par() {
  // Why the orphaned book is not merely idle: the virtual-share offset prices
  // a deposit into a ZERO-supply pool at par with itself. 100 ADA into a pool
  // already holding 150 ADA mints shares worth 100 ADA, not 250 — so the 150
  // is reachable by nobody, ever.
  let stranded = 150_000_000
  let deposit = 100_000_000
  let minted = lp_mint(deposit, stranded, 0)
  let back = lp_withdraw(minted, stranded + deposit, minted)
  and {
    minted > 0,
    back <= deposit,
    back >= deposit - 100,
  }
}

// HONEST ANCHOR for F4: exits that do NOT orphan a book must keep working —
// the last LP leaving an empty pool, and any LP leaving a pool whose book is
// live as long as somebody stays.
test ec_honest_anchor_exits_that_orphan_nothing_still_work() {
  let d = 500_000_000
  let s1 = lp_mint(d, 0, 0)
  let s2 = lp_mint(d, d, s1)
  let coverage = 150_000_000
  let backing = d + d - coverage
  let supply = s1 + s2
  let partial = lp_withdraw(s1, backing, supply)
  let solo = lp_withdraw(s1, d, s1)
  and {
    // a live book, but s2 stays: the exit orphans nothing
    remove_liquidity_ok(
      vs(supply, coverage, 0),
      vs(supply - s1, coverage, 0),
      s1,
      backing,
      backing + 2_000_000,
      backing + 2_000_000 - partial,
      -s1,
      partial,
    ),
    // the last LP of an EMPTY book may still leave entirely
    remove_liquidity_ok(
      vs(s1, 0, 0),
      vs(0, 0, 0),
      s1,
      d,
      d + 2_000_000,
      d + 2_000_000 - solo,
      -s1,
      solo,
    ),
  }
}
