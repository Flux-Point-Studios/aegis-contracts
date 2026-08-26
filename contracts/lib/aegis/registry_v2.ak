//// Aegis V8.2 stable-vault — second-generation registry state machine
//// (docs/v8-stable-vault/V82-IMMUTABLE-CORE.md §4). `RuleSet` slims to a bare
//// `logic_hash`, and every operational identity the V8.1 vault baked into its
//// compiled hash — mandates, publisher VKH, observer hash, feed allowlists,
//// budgets, fee split, settlement pins — moves here as GOVERNED data, read by
//// Underwrite alone (Invariant S: settlement takes no registry input).
//// Timelocks are self-governed in-datum; the V8.2 registry validator bakes
//// per-network floors and passes them to these checks as facts.
////
//// `aegis/registry` (v1) stays beside this module: it is the source of the
//// DEPLOYED registry validator's pinned hash, and the Admin model is shared
//// from there. Pure functions over plain values, unit-tested without
//// ScriptContext mocks.

use aegis/registry.{Admin, admin_eq, admin_signed, admin_valid}
use aegis/types.{
  AegisSelf, Charli3, Indigo, NoSecondLeg, OracleMandate, OracleProvider,
  Orcfax, Pyth, PythPullLeg, SecondLeg, TrailingLowLeg, min_policy_term_ms,
  min_utxo_lovelace, pyth_max_confidence_bps as core_pyth_max_confidence_bps,
}
use aiken/collection/list
use aiken/math
use aiken/primitive/bytearray
use cardano/address.{Address, Script, VerificationKey}

/// Everything Underwrite needs and settlement must never re-read. Values under
/// `settlement_pins` are GOVERNED *sources*: Underwrite copies them into each
/// new PolicyDatum, after which the policy is self-contained.
pub type UnderwriteConfig {
  /// primary AegisSelf NFT ↔ optional Pyth Lazer fallback (#"" = none). READ by
  /// Underwrite.
  mandates: List<OracleMandate>,
  /// AegisSelf feed-host VKH new policies pin. CARRIED, not yet read by any
  /// validator — width-bounded here and inert until one does.
  publisher_vkh: ByteArray,
  /// MIRROR of pool_vault's CORE `observer_script_hash`, not a governed value.
  /// `attested_price` reads the Price out of the redeemer of `Script(h)`, so the
  /// identity of this hash IS the reading's genuineness; governing it made the
  /// Underwrite spot buyer-authored (G10 red-team CRITICAL). Underwrite binds it
  /// EQUAL to its compile parameter, and only a SHAPE bound lives here, because
  /// the equality needs a hash this module must never learn.
  observer_hash: ByteArray,
  depeg_eligible: List<ByteArray>,
  pyth_feed_allowlist: List<ByteArray>,
  pyth_state_nft: ByteArray,
  floors: Floors,
  /// providers Underwrite may sell against. A SET rail bounds it to the
  /// push-oracle predicate, so governance may ADD a provider but never one
  /// whose spot the buyer authors. Empty halts new business, like `mandates`.
  admissible_providers: List<OracleProvider>,
  budgets: Budgets,
  fee: Fee,
  settlement_pins: SettlementPins,
}

/// The five baseline floors under the actuarial curve. Every value is basis
/// points on the shared 10_000 scale, so the depeg band and the peg-health gate
/// cannot drift onto two different divisors the way the percent forms in
/// `floor_table` can.
///
/// CARRIED AND RAIL-CHECKED, READ BY NO VALIDATOR. The floors Underwrite
/// actually enforces are the compiled constants in `floor_table.ak`, reached
/// through `vault.underwrite_baseline_ok`. Enacting a value here changes
/// nothing today. That is a hazard rather than a nicety: the slice that
/// de-constantises `underwrite_baseline_ok` makes every value silently enacted
/// in the interim go live at once, with no further governance action — so the
/// enactment that MOVES these must be the one that reads them.
pub type Floors {
  min_strike_distance_bps: Int,
  min_depeg_distance_bps: Int,
  depeg_strike_lo_bps: Int,
  depeg_strike_hi_bps: Int,
  min_depeg_spot_bps: Int,
}

pub type Budgets {
  spot_age_barrier_ms: Int,
  spot_age_depeg_ms: Int,
  underwrite_span_ms: Int,
  term_min_ms: Int,
  term_max_ms: Int,
  min_premium: Int,
  /// share of the post-trade pool that may sit as live coverage, in bps. NAMED
  /// and rail-checked, but READ BY NO VALIDATOR: the book cap Underwrite
  /// enforces is the literal `nc * 3` in `vault.underwrite_ok`. Same hazard as
  /// `Floors` — the enactment that moves this must be the one that reads it.
  utilisation_bps: Int,
  /// premium adequacy: coverage <= premium * this. CARRIED, not yet read —
  /// `is_premium_adequate` uses the compiled ratio.
  max_coverage_ratio: Int,
}

pub type Fee {
  /// the protocol's take of each premium, in bps — the RATE, bounded by
  /// `max_fee_take_rail_bps`. `treasury_bps` is treasury's share OF this take,
  /// not of the premium.
  take_bps: Int,
  treasury_bps: Int,
  team_address: Address,
}

pub type SettlementPins {
  reading_validity_ms: Int,
  pyth_freshness_ms: Int,
  pyth_max_confidence_bps: Int,
  pyth_reject_absent_confidence: Bool,
  grace_barrier_ms: Int,
  grace_depeg_ms: Int,
  cancellation_window_ms: Int,
  cancellation_fee_bps: Int,
}

pub type PendingUpdate {
  logic_hash: ByteArray,
  config: UnderwriteConfig,
  /// Some = governance handover (the team-multisig -> cMATRA rail)
  new_admin: Option<Admin>,
  timelock_ms: Int,
  cancel_cooldown_ms: Int,
  /// POSIX ms; EnactUpdate requires tx.lower >= this
  effective_after: Int,
}

pub type RegistryDatum {
  /// strictly increments on every EnactUpdate
  epoch: Int,
  /// the ONLY swappable code pointer (RuleSet v2)
  logic_hash: ByteArray,
  config: UnderwriteConfig,
  pending: Option<PendingUpdate>,
  admin: Admin,
  /// ProposeUpdate requires tx.lower >= this (set by CancelUpdate)
  cooldown_until: Int,
  /// self-governed; a proposal changing it waits the OLD value
  timelock_ms: Int,
  cancel_cooldown_ms: Int,
}

// ---------------------------------------------------------------------------
// Field equality — explicit, not derived (sum-type Eq is a known Windows-aiken
// silent-miscompile pitfall; ByteArray/Int comparisons are safe primitives).
// ---------------------------------------------------------------------------

/// [#403 FIX 1] Constructor tag for a mandate's second leg. Explicit, like
/// `provider_tag` and for the same reason: a derived sum-type `==` is a known
/// Windows-aiken silent-miscompile pitfall, and this value decides whether a
/// buyer must supply an independent price at all.
pub fn second_leg_tag(l: SecondLeg) -> Int {
  when l is {
    NoSecondLeg -> 0
    TrailingLowLeg -> 1
    PythPullLeg { .. } -> 2
  }
}

pub fn second_leg_eq(a: SecondLeg, b: SecondLeg) -> Bool {
  when (a, b) is {
    (PythPullLeg { feed_id: fa, require_confidence: ca },
     PythPullLeg { feed_id: fb, require_confidence: cb }) ->
      fa == fb && ca == cb
    _ -> second_leg_tag(a) == second_leg_tag(b)
  }
}

pub fn mandate_eq(a: OracleMandate, b: OracleMandate) -> Bool {
  and {
    a.primary_nft == b.primary_nft,
    a.fallback_feed_id == b.fallback_feed_id,
    // [#403 FIX 1] ...and the second leg. Without this an EnactUpdate could
    // swap a pair's mandatory pull leg out from under the proposal the admins
    // signed, which is the whole sale-side gate turned off by a field nobody
    // compared.
    second_leg_eq(a.second_leg, b.second_leg),
  }
}

pub fn mandates_eq(a: List<OracleMandate>, b: List<OracleMandate>) -> Bool {
  when a is {
    [] -> list.is_empty(b)
    [x, ..xs] ->
      when b is {
        [] -> False
        [y, ..ys] -> and {
            mandate_eq(x, y),
            mandates_eq(xs, ys),
          }
      }
  }
}

/// The provider's CBOR constructor index. Named EXHAUSTIVELY, with no `_`
/// arm, so appending a sixth provider is a compile error here and in
/// `provider_is_push` rather than a silent default.
pub fn provider_tag(p: OracleProvider) -> Int {
  when p is {
    Charli3 -> 0
    Orcfax -> 1
    AegisSelf -> 2
    Indigo -> 3
    Pyth -> 4
  }
}

/// CORE, and the reason a governed provider list is safe: a PUSH oracle's
/// price is written by someone other than the transaction builder. Pyth Lazer
/// is PULL — `pyth.get_updates` reads its signed payload out of a withdrawal
/// redeemer the builder supplies, and at Underwrite the BUYER is the builder,
/// so admitting it hands him the spot that strike distance is measured
/// against. Charli3 and Orcfax are dead providers, kept decodable only.
pub fn provider_is_push(p: OracleProvider) -> Bool {
  when p is {
    Charli3 -> False
    Orcfax -> False
    AegisSelf -> True
    // [#316] RETIRED. Not push any more — Indigo stopped publishing a standing
    // datum, so nothing writes its price for the builder. False is what keeps
    // it out of `admissible_providers` under `config_within_rails` forever.
    Indigo -> False
    Pyth -> False
  }
}

pub fn providers_eq(a: List<OracleProvider>, b: List<OracleProvider>) -> Bool {
  list.map(a, provider_tag) == list.map(b, provider_tag)
}

pub fn floors_eq(a: Floors, b: Floors) -> Bool {
  and {
    a.min_strike_distance_bps == b.min_strike_distance_bps,
    a.min_depeg_distance_bps == b.min_depeg_distance_bps,
    a.depeg_strike_lo_bps == b.depeg_strike_lo_bps,
    a.depeg_strike_hi_bps == b.depeg_strike_hi_bps,
    a.min_depeg_spot_bps == b.min_depeg_spot_bps,
  }
}

pub fn budgets_eq(a: Budgets, b: Budgets) -> Bool {
  and {
    a.spot_age_barrier_ms == b.spot_age_barrier_ms,
    a.spot_age_depeg_ms == b.spot_age_depeg_ms,
    a.underwrite_span_ms == b.underwrite_span_ms,
    a.term_min_ms == b.term_min_ms,
    a.term_max_ms == b.term_max_ms,
    a.min_premium == b.min_premium,
    a.utilisation_bps == b.utilisation_bps,
    a.max_coverage_ratio == b.max_coverage_ratio,
  }
}

pub fn fee_eq(a: Fee, b: Fee) -> Bool {
  and {
    a.take_bps == b.take_bps,
    a.treasury_bps == b.treasury_bps,
    a.team_address == b.team_address,
  }
}

pub fn pins_eq(a: SettlementPins, b: SettlementPins) -> Bool {
  and {
    a.reading_validity_ms == b.reading_validity_ms,
    a.pyth_freshness_ms == b.pyth_freshness_ms,
    a.pyth_max_confidence_bps == b.pyth_max_confidence_bps,
    a.pyth_reject_absent_confidence == b.pyth_reject_absent_confidence,
    a.grace_barrier_ms == b.grace_barrier_ms,
    a.grace_depeg_ms == b.grace_depeg_ms,
    a.cancellation_window_ms == b.cancellation_window_ms,
    a.cancellation_fee_bps == b.cancellation_fee_bps,
  }
}

// [#403 FIX 1] `config_eq` is what pins an ENACTED config to the PROPOSED one.
// A field it does not compare is a field an enactment may change freely, so a
// second leg outside `mandate_eq` would let the timelocked proposal say
// "USDC carries a mandatory Pyth pull leg" and the enactment write
// `NoSecondLeg` — the sale-side gate switched off by a field nobody compared.
test registry2_config_eq_sees_a_swapped_second_leg() {
  let with_pull =
    [
      OracleMandate {
        primary_nft: #"01",
        fallback_feed_id: #"",
        second_leg: PythPullLeg { feed_id: #"02", require_confidence: True },
      },
    ]
  let dropped =
    [
      OracleMandate {
        primary_nft: #"01",
        fallback_feed_id: #"",
        second_leg: NoSecondLeg,
      },
    ]
  let confidence_relaxed =
    [
      OracleMandate {
        primary_nft: #"01",
        fallback_feed_id: #"",
        second_leg: PythPullLeg { feed_id: #"02", require_confidence: False },
      },
    ]
  and {
    mandates_eq(with_pull, with_pull),
    !mandates_eq(with_pull, dropped),
    !mandates_eq(with_pull, confidence_relaxed),
    !mandates_eq(dropped, [
      OracleMandate {
        primary_nft: #"01",
        fallback_feed_id: #"",
        second_leg: TrailingLowLeg,
      },
    ]),
  }
}

pub fn config_eq(a: UnderwriteConfig, b: UnderwriteConfig) -> Bool {
  and {
    mandates_eq(a.mandates, b.mandates),
    a.publisher_vkh == b.publisher_vkh,
    a.observer_hash == b.observer_hash,
    a.depeg_eligible == b.depeg_eligible,
    a.pyth_feed_allowlist == b.pyth_feed_allowlist,
    a.pyth_state_nft == b.pyth_state_nft,
    floors_eq(a.floors, b.floors),
    providers_eq(a.admissible_providers, b.admissible_providers),
    budgets_eq(a.budgets, b.budgets),
    fee_eq(a.fee, b.fee),
    pins_eq(a.settlement_pins, b.settlement_pins),
  }
}

fn distinct(xs: List<a>) -> Bool {
  list.length(list.unique(xs)) == list.length(xs)
}

/// An admin `admin_signed` can actually satisfy. `admin_valid` (shared with
/// v1) bounds the threshold against the DISTINCT keys; V8.2 adds the key
/// WIDTH, because `admin_signed` matches keys against `extra_signatories` and
/// those are 28-byte verification-key hashes — a key of any other width can
/// never match a signatory, so it is dead weight that inflates the key count
/// `admin_valid` measures the threshold against without adding a reachable
/// signer.
///
/// One mis-width key does NOT by itself brick the M-of-N. The quorum stays
/// satisfiable exactly while at least `threshold` distinct 28-byte keys remain:
/// one typo in a 2-of-3 is survivable, the same typo in a 3-of-3 is not. This
/// predicate refuses the whole admin either way, because it also runs at
/// genesis (`check_genesis`), where a silently thinned margin can never be
/// repaired — see there for why recovery costs a vault generation.
pub fn admin_well_formed(a: Admin) -> Bool {
  and {
    admin_valid(a),
    list.all(a.keys, fn(k) { bytearray.length(k) == 28 }),
  }
}

// ---------------------------------------------------------------------------
// Well-formedness — shape and the §5 outer rails, not calibration. Checked
// fail-fast at propose and re-checked at enact. An EMPTY mandate list is
// deliberately legal — it is the halt-new-business fail-safe posture.
// ---------------------------------------------------------------------------

/// Ceiling on both self-governed clocks. Floors alone are one-sided: an
/// enacted `timelock_ms` of 1e21 puts every later `effective_after` beyond
/// any reachable `tx_lower`, freezing propose/enact — and with them mandate
/// rotation and the halt-new-business fail-safe — forever, surviving an
/// admin handover. Five days leaves a DAO room to lengthen public notice
/// above the 72h mainnet floor while capping the worst-case governance
/// freeze a hostile enactment can impose.
pub const max_registry_clock_ms: Int = 432_000_000

/// Validity-range width cap on the admin arms (propose, cancel), the
/// pool_vault `max_underwrite_span_ms` rail applied to the registry. Cancel
/// arms `cooldown_until` from tx_upper, so an uncapped range inflates the
/// cooldown by up to the ~7.5-day forecast horizon; six hours bounds that
/// inflation while leaving a real signature-collection window for the admin
/// multisig (underwrite's 20-min cap assumes one interactive signer).
pub const max_registry_span_ms: Int = 21_600_000

// --- §5 rails: wide-once outer bounds on the governed budgets and pins.
// A governed value without a rail is an unbounded delegation to the admin
// quorum; each bound is wide enough that honest recalibration never touches
// it, tight enough that a hostile config is bounded. min_premium carries NO
// upper rail deliberately: its danger direction is down (dust policies,
// already floored at min-UTxO); raising it only deters new business, the
// fail-safe posture an empty mandate list already expresses.

/// Spot-age ceiling, both risk classes. The spot-age budget pins the
/// publisher's minimum cadence (and burn); a "spot" print more than a day
/// old prices nothing a new policy should bind against.
pub const max_spot_age_rail_ms: Int = 86_400_000

/// Underwrite validity-width ceiling: the span bounds bind-time clock drift,
/// so an unbounded span lets a buyer bind tonight against this morning's
/// price. One hour is 3x the genesis 20-min single-signer window.
pub const max_underwrite_span_rail_ms: Int = 3_600_000

/// Term floor: 7 days. TWO independent hazards set it, and the tighter one is
/// not the obvious one.
///
/// (a) GOVERNANCE CANNOT REACT. A sub-day policy outruns governance entirely —
/// the mainnet registry timelock alone is 72 h, so no mandate rotation or halt
/// can act within the policy's own life. This alone argues for 3 days, which is
/// what the operator ratified on 2026-08-09.
///
/// (b) THE PREMIUM TABLE CANNOT PRICE IT, and this is why the ratified 3 days
/// was raised to 7 on 2026-08-10. `floor_table.t_band_index` returns band 0 for
/// EVERY term under 7 days, and band 0 is a literal 0 bps once the strike is far
/// enough out — floor_table's own comment names the shallow end as where a zero
/// floor is dangerous. A rail at 1 or 3 days lets a rail-legal enactment set
/// `budgets.term_min_ms` into that band, and the vault would then admit cover
/// the premium table values at nothing. G3 made this rail load-bearing: since
/// 2026-08-10 Underwrite reads `budgets.term_min_ms` and the compiled
/// `min_policy_term_ms` no longer binds, so this rail is the ONLY term floor.
///
/// The rule the deleted CORE floor stated and this one keeps: the vault must
/// never admit a term the premium table cannot price. Costs nothing today — the
/// genesis value is already 7 days — and forecloses only a sub-7-day product,
/// which is unpriceable until the table is extended. Widening is a generation;
/// tightening stays free.
pub const min_term_rail_ms: Int = 604_800_000

/// Term ceiling: 366 days. Past a leap year the terms Underwrite pinned
/// (premium, distances, freshness pins) are stale by construction, with no
/// way to reprice the open position.
pub const max_term_rail_ms: Int = 31_622_400_000

/// Ceiling on BOTH settlement freshness pins (`reading_validity_ms` and
/// `pyth_freshness_ms`): unbounded, a hostile config makes day-old prints
/// claimable forever — the newest-wins squeeze only works while the window
/// is short enough that fresher prints exist inside it.
pub const max_reading_validity_rail_ms: Int = 86_400_000

/// Grace ceiling, both classes. Grace is how long the primary must be
/// ledger-provably silent before the Pyth leg opens at settlement, so an
/// unbounded grace silently disables the fallback and strands every claim
/// on a dead publisher. A day bounds the strand; genesis is 30 min.
pub const max_grace_rail_ms: Int = 86_400_000

/// Cancellation-window ceiling: the window is a cooling-off period, not an
/// exit option. Unbounded, it converts every policy into a free option the
/// buyer abandons the moment the market moves his way; a day caps that
/// option's value. Genesis is 1 h.
pub const max_cancellation_window_rail_ms: Int = 86_400_000

// --- §5 rails, second set: the four DIRECTIONS.
//
// The first set above is all ceilings. A governed FLOOR needs a floor rail, a
// governed list needs a set rail, and a governed pair of numbers that must
// stay ordered needs a relational one — otherwise the bound is the value it is
// supposed to bound. Each is picked WIDE on purpose: a rail exists to survive
// a hostile quorum, not to express today's risk appetite, and a rail set at
// today's calibration means the first honest recalibration needs a migration.
//
// HELD FOR HUMAN RATIFICATION BEFORE GENESIS. Every VALUE below, and the
// decision to govern the five baseline floors at all (which revises
// V82-IMMUTABLE-CORE §7's "a governed rail bounds nothing"), encodes "the
// worst setting we would survive" — an actuarial and capital question, not an
// engineering one. A rail picked by an agent to make a test pass is the
// failure mode. The SHAPE below is the deliverable; the numbers are proposals.

/// Book-utilisation ceiling. Above 80% the pool cannot absorb one full claim
/// plus the min-UTxO continuation, so the cap stops bounding anything. Genesis
/// is 3_333 (the unnamed `nc * 3` cap, now named).
pub const max_utilisation_rail_bps: Int = 8_000

/// Premium-adequacy ceiling: coverage <= premium * ratio. Genesis is 50, which
/// `types.min_policy_term_ms`'s own commentary already records as binding and
/// roughly 6x wrong for short-dated cover — so the rail has to sit well above
/// it or the recalibration that fixes it is a migration.
pub const max_coverage_ratio_rail: Int = 200

/// Strike-distance FLOOR rail. Genesis is 1_500. Below 1% out-of-the-money a
/// barrier is a certainty inside tick noise, so any premium under-prices it.
pub const min_strike_distance_rail_bps: Int = 100

/// Depeg-distance FLOOR rail. Genesis is 200. A healthy stable trades inside
/// ~50 bps of peg, so 25 is already under ordinary book noise.
pub const min_depeg_distance_rail_bps: Int = 25

/// Depeg strike-band FLOOR rail. Genesis is 5_000. A strike under 1% of peg
/// describes cover that can never pay.
pub const min_depeg_strike_lo_rail_bps: Int = 100

/// Depeg strike-band CEILING rail. Genesis is 9_500, justified only by where
/// the touch-0.95 calibration holds, while 96-99% is the most commercially
/// demanded stablecoin cover. Strictly below peg either way.
pub const max_depeg_strike_hi_rail_bps: Int = 9_900

/// Peg-health FLOOR rail. Genesis is 9_900. Below 90% the peg is broken by any
/// definition, so a gate under this rail sells cover on an asset that has
/// already failed.
pub const min_depeg_spot_rail_bps: Int = 9_000

/// Protocol fee-take ceiling: 10% of each premium. The rail bounds the RATE,
/// not `treasury_bps`, which is treasury's share OF the take.
pub const max_fee_take_rail_bps: Int = 1_000

/// [#418] Pyth confidence ceiling: 20% of price. The bound here USED to be the
/// bps scale itself, which admits a print whose stated error bar is the whole
/// price — not a price at all — so the rail bounded nothing.
///
/// 2_000 rather than a tighter number, because the error is ASYMMETRIC: this
/// constant compiles into the vault through `config_within_rails`, so
/// tightening it later is a constant swap and loosening it later costs a whole
/// generation. Three independent reviews landed on 200 / 1_000 / 2_000 against
/// the same evidence — Pyth publishes no numeric threshold of its own — and
/// where sourced analyses disagree under an asymmetric error, the loosest
/// candidate is the one that cannot strand governance mid-crisis. It is still
/// 20x the value the observer gates on and 5x tighter than the old scale cap.
pub const max_pyth_confidence_rail_bps: Int = 2_000

/// The one clock rail BOTH transition arms route through: floors are
/// per-network facts baked by the registry validator and passed in; the
/// ceiling is compiled here.
pub fn clocks_well_formed(
  timelock_ms: Int,
  cancel_cooldown_ms: Int,
  timelock_floor_ms: Int,
  cooldown_floor_ms: Int,
) -> Bool {
  and {
    timelock_ms >= timelock_floor_ms,
    timelock_ms <= max_registry_clock_ms,
    cancel_cooldown_ms >= cooldown_floor_ms,
    cancel_cooldown_ms <= max_registry_clock_ms,
  }
}

/// Every rail a config must sit inside — and NOT the fee sink, which is the
/// one conjunct that needs the vault's hash. The registry validator takes the
/// registry NFT policy and name and nothing else, so teaching it the vault's
/// hash would add a registry -> vault back-edge for a check the vault does
/// better with its own. See `fee_sink_not_vault`.
pub fn config_within_rails(c: UnderwriteConfig) -> Bool {
  let b = c.budgets
  let f = c.floors
  let s = c.settlement_pins
  and {
    // [#381 S5 coupling] a mandate's fallback is allowlisted or absent (#"")
    list.all(
      c.mandates,
      fn(m) {
        or {
          m.fallback_feed_id == #"",
          list.has(c.pyth_feed_allowlist, m.fallback_feed_id),
        }
      },
    ),
    // [#403 FIX 1] ...and a mandatory PULL leg names an ALLOWLISTED Pyth feed.
    // The same S5 coupling the fallback carries, for the same reason: without
    // it a config in rails could point the sale-side leg at any 1-byte feed id
    // and the observer would attest whatever that resolved to.
    // [#403 FIX 1] ...and a mandatory PULL leg names an ALLOWLISTED Pyth feed.
    // The same S5 coupling the fallback carries, for the same reason: without
    // it a config in rails could point the sale-side leg at any 1-byte feed id
    // and the observer would attest whatever that resolved to.
    list.all(
      c.mandates,
      fn(m) {
        when m.second_leg is {
          PythPullLeg { feed_id, .. } ->
            list.has(c.pyth_feed_allowlist, feed_id)
          _ -> True
        }
      },
    ),
    distinct(list.map(c.mandates, fn(m) { m.primary_nft })),
    distinct(c.depeg_eligible),
    distinct(c.pyth_feed_allowlist),
    bytearray.length(c.publisher_vkh) == 28,
    bytearray.length(c.observer_hash) == 28,
    bytearray.length(c.pyth_state_nft) == 28,
    b.spot_age_barrier_ms > 0,
    b.spot_age_barrier_ms <= max_spot_age_rail_ms,
    b.spot_age_depeg_ms > 0,
    b.spot_age_depeg_ms <= max_spot_age_rail_ms,
    b.underwrite_span_ms > 0,
    b.underwrite_span_ms <= max_underwrite_span_rail_ms,
    b.term_min_ms >= min_term_rail_ms,
    b.term_min_ms <= b.term_max_ms,
    b.term_max_ms <= max_term_rail_ms,
    // [#363 F5] a premium below min-UTxO cannot even be paid on chain
    b.min_premium >= min_utxo_lovelace,
    // CEILING: the book cap, and the premium-adequacy ratio under it
    b.utilisation_bps > 0,
    b.utilisation_bps <= max_utilisation_rail_bps,
    b.max_coverage_ratio > 0,
    b.max_coverage_ratio <= max_coverage_ratio_rail,
    // FLOOR: the five baseline floors, each above its own rail
    f.min_strike_distance_bps >= min_strike_distance_rail_bps,
    f.min_strike_distance_bps <= 10_000,
    f.min_depeg_distance_bps >= min_depeg_distance_rail_bps,
    f.min_depeg_distance_bps <= 10_000,
    f.depeg_strike_lo_bps >= min_depeg_strike_lo_rail_bps,
    f.depeg_strike_hi_bps <= max_depeg_strike_hi_rail_bps,
    f.min_depeg_spot_bps >= min_depeg_spot_rail_bps,
    f.min_depeg_spot_bps <= 10_000,
    // RELATIONAL (R4). Each of these three used to be a compile-time
    // comparison of two constants — floor_table's
    // `healthy_peg_is_above_every_permitted_strike`, types'
    // `depeg_feeds_are_canonical`, and the band's own ordering. The instant
    // their operands became registry data those tests kept passing while
    // binding nothing, so the couplings live here as conjuncts, not tests.
    f.min_depeg_spot_bps > f.depeg_strike_hi_bps,
    f.depeg_strike_lo_bps < f.depeg_strike_hi_bps,
    // ...and the ABORT-shaped one: Depeg Underwrite resolves the same pinned
    // feed the Claim will judge on, which only resolves for a mandate primary.
    list.all(
      c.depeg_eligible,
      fn(n) { list.any(c.mandates, fn(m) { m.primary_nft == n }) },
    ),
    // SET: governance may add a provider, never one whose spot the buyer
    // authors at Underwrite
    list.all(c.admissible_providers, provider_is_push),
    distinct(list.map(c.admissible_providers, fn(p) { provider_tag(p) })),
    c.fee.take_bps >= 0,
    c.fee.take_bps <= max_fee_take_rail_bps,
    c.fee.treasury_bps >= 0,
    c.fee.treasury_bps <= 10_000,
    s.reading_validity_ms > 0,
    s.reading_validity_ms <= max_reading_validity_rail_ms,
    s.pyth_freshness_ms > 0,
    s.pyth_freshness_ms <= max_reading_validity_rail_ms,
    s.pyth_max_confidence_bps >= 0,
    s.pyth_max_confidence_bps <= max_pyth_confidence_rail_bps,
    s.grace_barrier_ms >= 0,
    s.grace_barrier_ms <= max_grace_rail_ms,
    s.grace_depeg_ms >= 0,
    s.grace_depeg_ms <= max_grace_rail_ms,
    s.cancellation_window_ms >= 0,
    s.cancellation_window_ms <= max_cancellation_window_rail_ms,
    s.cancellation_fee_bps >= 0,
    s.cancellation_fee_bps <= 10_000,
  }
}

/// The vault can never be its own fee sink. Split out of the rails because it
/// is the only conjunct that needs a hash the registry validator must not
/// learn: `registry_v2` takes the NFT policy and name, so a `vault_hash`
/// parameter would make the two scripts' hashes mutually dependent — the const
/// cycle that has already deadlocked a deploy here. Underwrite enforces it,
/// where the vault's own hash is a fact rather than a parameter.
pub fn fee_sink_not_vault(f: Fee, vault_payment_hash: ByteArray) -> Bool {
  when f.team_address.payment_credential is {
    Script(h) -> h != vault_payment_hash
    VerificationKey(_) -> True
  }
}

// ---------------------------------------------------------------------------
// Transitions. Each takes (old, new) datums + the tx facts and validator-baked
// floors, returns the full conjunction. Default-deny: every field the arm does
// not change is pinned equal.
// ---------------------------------------------------------------------------

/// Genesis: the one datum no transition wrote. The spend validator does not
/// run at creation, so anything the arms assume "held since the last
/// transition" is established here or nowhere.
///
/// The admin is the reason this gate exists. `admin_signed` counts DISTINCT
/// admin keys present in `extra_signatories`, and only 28-byte hashes can ever
/// appear there, so the quorum is reachable exactly while the number of
/// distinct 28-byte keys is at least `threshold`. A genesis `Admin` that fails
/// that — threshold above the distinct key count, or threshold below 1 — makes
/// `admin_signed` False forever; mis-width keys thin the reachable set one key
/// at a time and cross the same line once too few well-formed ones are left.
/// `admin_signed` gates Propose AND Cancel, so a genesis admin over that line is
/// dead from birth and no pending can ever be created for the permissionless
/// Enact to apply. Nothing on chain would catch it, and the registry NFT policy
/// is a `pool_vault` compile parameter, so recovery means a whole new vault
/// generation. `admin_well_formed` therefore refuses ANY mis-width key here, not
/// only the ones that already brick the quorum: at genesis no later transaction
/// can restore the margin.
///
/// `pending` must be empty: a planted one never passed `check_propose`, and
/// `check_enact` cannot reconstruct the propose-time wait, so its own
/// `effective_after` is the only clock it answers to. `cooldown_until` must be
/// unarmed for the v1 N5 reason, applied at birth: no arm ever lowers it.
pub fn check_genesis(
  d: RegistryDatum,
  timelock_floor_ms: Int,
  cooldown_floor_ms: Int,
) -> Bool {
  and {
    admin_well_formed(d.admin),
    d.pending == None,
    d.cooldown_until == 0,
    bytearray.length(d.logic_hash) == 28,
    clocks_well_formed(
      d.timelock_ms,
      d.cancel_cooldown_ms,
      timelock_floor_ms,
      cooldown_floor_ms,
    ),
    config_within_rails(d.config),
  }
}

/// ProposeUpdate: admin-signed; no pending; past any cancel cooldown; the
/// validity range is width-capped; the new pending waits >= the OLD in-datum
/// timelock from tx upper, floored (a proposal shrinking `timelock_ms` cannot
/// shorten its own wait, and an unvalidated genesis cannot rush the first
/// transition); proposed clocks sit between the validator-baked floors and
/// the compiled ceiling; the proposed config is well-formed; nothing outside
/// `pending` moves.
pub fn check_propose(
  old: RegistryDatum,
  new: RegistryDatum,
  tx_lower_ms: Int,
  tx_upper_ms: Int,
  signed: Bool,
  timelock_floor_ms: Int,
  cooldown_floor_ms: Int,
) -> Bool {
  expect Some(p) = new.pending
  let handover_ok =
    when p.new_admin is {
      Some(a) -> admin_well_formed(a)
      None -> True
    }
  and {
    signed,
    old.pending == None,
    tx_lower_ms >= old.cooldown_until,
    tx_upper_ms - tx_lower_ms <= max_registry_span_ms,
    // the wait runs on the OLD clock — a proposal shrinking timelock_ms
    // cannot shorten its own timelock. FLOORED: genesis is validated by
    // nothing on chain, so a datum born with a zero or negative timelock
    // must not grant a rushed first transition.
    p.effective_after >= tx_upper_ms + math.max(
      old.timelock_ms,
      timelock_floor_ms,
    ),
    clocks_well_formed(
      p.timelock_ms,
      p.cancel_cooldown_ms,
      timelock_floor_ms,
      cooldown_floor_ms,
    ),
    bytearray.length(p.logic_hash) == 28,
    handover_ok,
    config_within_rails(p.config),
    // everything outside `pending` is pinned
    new.epoch == old.epoch,
    new.logic_hash == old.logic_hash,
    config_eq(new.config, old.config),
    admin_eq(new.admin, old.admin),
    new.cooldown_until == old.cooldown_until,
    new.timelock_ms == old.timelock_ms,
    new.cancel_cooldown_ms == old.cancel_cooldown_ms,
  }
}

/// EnactUpdate: PERMISSIONLESS after the timelock elapses. logic_hash, config
/// and both clocks are applied from the pending; admin := handover admin if
/// present; epoch strictly increments; pending cleared. Floors and
/// well-formedness are RE-CHECKED so even a pending that never passed propose
/// cannot enact sub-floor clocks, a malformed config, or an admin no quorum
/// can sign.
pub fn check_enact(
  old: RegistryDatum,
  new: RegistryDatum,
  tx_lower_ms: Int,
  timelock_floor_ms: Int,
  cooldown_floor_ms: Int,
) -> Bool {
  expect Some(p) = old.pending
  let want_admin =
    when p.new_admin is {
      Some(a) -> a
      None -> old.admin
    }
  and {
    tx_lower_ms >= p.effective_after,
    new.epoch == old.epoch + 1,
    new.logic_hash == p.logic_hash,
    bytearray.length(new.logic_hash) == 28,
    config_eq(new.config, p.config),
    // re-check: even a pending that never passed propose cannot enact a
    // malformed config or sub-floor clocks
    config_within_rails(new.config),
    new.timelock_ms == p.timelock_ms,
    new.cancel_cooldown_ms == p.cancel_cooldown_ms,
    clocks_well_formed(
      new.timelock_ms,
      new.cancel_cooldown_ms,
      timelock_floor_ms,
      cooldown_floor_ms,
    ),
    admin_eq(new.admin, want_admin),
    // enact is the arm that WRITES the admin, and it is PERMISSIONLESS, so
    // propose's check on `new_admin` is fail-fast and this one is the
    // load-bearing guard — the split the config and the clocks above already
    // use. It is also wider: on the no-handover path the admin written is
    // `old.admin`, which propose never inspects. A pending carrying an
    // unsignable admin can only come from a genesis datum, and no validator
    // runs at genesis.
    admin_well_formed(want_admin),
    new.pending == None,
    new.cooldown_until == old.cooldown_until,
  }
}

/// CancelUpdate: admin-signed; width-capped validity range; clears the
/// pending and arms the re-propose cooldown from the tx upper bound using
/// the IN-DATUM clock, floored; exact window, not an open ray (v1 N5: `>=`
/// let one Cancel brick governance forever); nothing else moves.
pub fn check_cancel(
  old: RegistryDatum,
  new: RegistryDatum,
  tx_lower_ms: Int,
  tx_upper_ms: Int,
  signed: Bool,
  cooldown_floor_ms: Int,
) -> Bool {
  expect Some(_) = old.pending
  and {
    signed,
    new.pending == None,
    tx_upper_ms - tx_lower_ms <= max_registry_span_ms,
    // [v1 N5] EXACT window from the IN-DATUM clock, not an open ray.
    // FLOORED against an unvalidated genesis born with a zero cooldown.
    new.cooldown_until == tx_upper_ms + math.max(
      old.cancel_cooldown_ms,
      cooldown_floor_ms,
    ),
    new.epoch == old.epoch,
    new.logic_hash == old.logic_hash,
    config_eq(new.config, old.config),
    admin_eq(new.admin, old.admin),
    new.timelock_ms == old.timelock_ms,
    new.cancel_cooldown_ms == old.cancel_cooldown_ms,
  }
}

// ---------------------------------------------------------------------------
// Tests — the self-governed timelock, the floors, the config well-formedness
// and the default-deny pins are the load-bearing ones.
// ---------------------------------------------------------------------------

const tl_floor = 300_000

const cd_floor = 60_000

const t_logic_a =
  #"01010101010101010101010101010101010101010101010101010101"

const t_logic_b =
  #"02020202020202020202020202020202020202020202020202020202"

const t_publisher =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const t_observer =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

const t_state_nft =
  #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

const t_vault =
  #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

const t_team_key =
  #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

const t_other_script =
  #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

/// Admin keys are matched against `extra_signatories`, which are 28-byte
/// verification-key hashes — so the fixtures have to be that wide too.
fn t_key(tag: ByteArray) -> ByteArray {
  bytearray.concat(tag, #"000000000000000000000000000000000000000000000000000000")
}

fn t_admin() -> Admin {
  Admin { keys: [t_key(#"aa"), t_key(#"bb"), t_key(#"cc")], threshold: 2 }
}

/// The genesis datum is the one no transition wrote: `t_datum()` carrying
/// whichever admin the ceremony typed.
fn t_genesis(a: Admin) -> RegistryDatum {
  RegistryDatum { ..t_datum(), admin: a }
}

/// EnactUpdate applying `a` as the handover admin, with the successor datum
/// the arm itself prescribes — so only the admin is under test.
fn t_enact_handover(a: Admin) -> Bool {
  let eff = 5_000_000
  let p = PendingUpdate { ..t_pending(eff), new_admin: Some(a) }
  let old = RegistryDatum { ..t_datum(), pending: Some(p) }
  check_enact(
    old,
    RegistryDatum { ..t_enacted(old, p), admin: a },
    eff,
    tl_floor,
    cd_floor,
  )
}

fn t_team_address() -> Address {
  Address {
    payment_credential: VerificationKey(t_team_key),
    stake_credential: None,
  }
}

fn t_config() -> UnderwriteConfig {
  UnderwriteConfig {
    mandates: [
      OracleMandate {
        primary_nft: #"01",
        fallback_feed_id: #"0006",
        second_leg: TrailingLowLeg,
      },
      OracleMandate {
        primary_nft: #"02",
        fallback_feed_id: #"",
        second_leg: TrailingLowLeg,
      },
    ],
    publisher_vkh: t_publisher,
    observer_hash: t_observer,
    depeg_eligible: [#"02"],
    pyth_feed_allowlist: [#"0006", #"0010"],
    pyth_state_nft: t_state_nft,
    floors: Floors {
      min_strike_distance_bps: 1_500,
      min_depeg_distance_bps: 200,
      depeg_strike_lo_bps: 5_000,
      depeg_strike_hi_bps: 9_500,
      min_depeg_spot_bps: 9_900,
    },
    admissible_providers: [AegisSelf],
    budgets: Budgets {
      spot_age_barrier_ms: 600_000,
      spot_age_depeg_ms: 300_000,
      underwrite_span_ms: 1_200_000,
      term_min_ms: 604_800_000,
      term_max_ms: 15_552_000_000,
      min_premium: 2_000_000,
      utilisation_bps: 3_333,
      max_coverage_ratio: 50,
    },
    fee: Fee {
      take_bps: 200,
      treasury_bps: 2_500,
      team_address: t_team_address(),
    },
    settlement_pins: SettlementPins {
      reading_validity_ms: 7_200_000,
      pyth_freshness_ms: 4_200_000,
      pyth_max_confidence_bps: 100,
      pyth_reject_absent_confidence: False,
      grace_barrier_ms: 1_800_000,
      grace_depeg_ms: 1_800_000,
      cancellation_window_ms: 3_600_000,
      cancellation_fee_bps: 1_000,
    },
  }
}

/// A changed-but-well-formed config for pendings (one budget recalibrated).
fn t_config_b() -> UnderwriteConfig {
  let c = t_config()
  let b = c.budgets
  UnderwriteConfig { ..c, budgets: Budgets { ..b, spot_age_barrier_ms: 900_000 } }
}

fn t_datum() -> RegistryDatum {
  RegistryDatum {
    epoch: 7,
    logic_hash: t_logic_a,
    config: t_config(),
    pending: None,
    admin: t_admin(),
    cooldown_until: 0,
    timelock_ms: 1_000_000,
    cancel_cooldown_ms: 500_000,
  }
}

fn t_pending(eff: Int) -> PendingUpdate {
  PendingUpdate {
    logic_hash: t_logic_b,
    config: t_config_b(),
    new_admin: None,
    timelock_ms: 1_000_000,
    cancel_cooldown_ms: 500_000,
    effective_after: eff,
  }
}

/// The exact successor a correct EnactUpdate writes.
fn t_enacted(old: RegistryDatum, p: PendingUpdate) -> RegistryDatum {
  RegistryDatum {
    epoch: old.epoch + 1,
    logic_hash: p.logic_hash,
    config: p.config,
    pending: None,
    admin: old.admin,
    cooldown_until: old.cooldown_until,
    timelock_ms: p.timelock_ms,
    cancel_cooldown_ms: p.cancel_cooldown_ms,
  }
}

// --- ProposeUpdate ---------------------------------------------------------

test registry2_propose_happy_path() {
  let old = t_datum()
  let up = 1_000_000
  let new =
    RegistryDatum { ..old, pending: Some(t_pending(up + old.timelock_ms)) }
  check_propose(old, new, 500_000, up, True, tl_floor, cd_floor)
}

test registry2_propose_unsigned_rejected() {
  let old = t_datum()
  let up = 1_000_000
  let new =
    RegistryDatum { ..old, pending: Some(t_pending(up + old.timelock_ms)) }
  !check_propose(old, new, 500_000, up, False, tl_floor, cd_floor)
}

test registry2_propose_short_timelock_rejected() {
  let old = t_datum()
  let up = 1_000_000
  let new =
    RegistryDatum { ..old, pending: Some(t_pending(up + old.timelock_ms - 1)) }
  !check_propose(old, new, 500_000, up, True, tl_floor, cd_floor)
}

test registry2_propose_waits_old_timelock_when_shrinking() {
  // the proposal SHRINKS timelock_ms to the floor; its own wait must still be
  // the OLD in-datum timelock, not the proposed one
  let old = t_datum()
  let up = 1_000_000
  let shrink = PendingUpdate { ..t_pending(0), timelock_ms: tl_floor }
  let early = PendingUpdate { ..shrink, effective_after: up + tl_floor }
  let patient = PendingUpdate { ..shrink, effective_after: up + old.timelock_ms }
  and {
    !check_propose(
      old,
      RegistryDatum { ..old, pending: Some(early) },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    check_propose(
      old,
      RegistryDatum { ..old, pending: Some(patient) },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
  }
}

test registry2_propose_timelock_below_floor_rejected() {
  let old = t_datum()
  let up = 1_000_000
  let p =
    PendingUpdate { ..t_pending(up + old.timelock_ms), timelock_ms: tl_floor - 1 }
  !check_propose(
    old,
    RegistryDatum { ..old, pending: Some(p) },
    500_000,
    up,
    True,
    tl_floor,
    cd_floor,
  )
}

test registry2_propose_cooldown_below_floor_rejected() {
  let old = t_datum()
  let up = 1_000_000
  let p =
    PendingUpdate {
      ..t_pending(up + old.timelock_ms),
      cancel_cooldown_ms: cd_floor - 1,
    }
  !check_propose(
    old,
    RegistryDatum { ..old, pending: Some(p) },
    500_000,
    up,
    True,
    tl_floor,
    cd_floor,
  )
}

test registry2_propose_second_pending_rejected() {
  let up = 1_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9)) }
  let new =
    RegistryDatum { ..old, pending: Some(t_pending(up + old.timelock_ms)) }
  !check_propose(old, new, 500_000, up, True, tl_floor, cd_floor)
}

test registry2_propose_during_cooldown_rejected() {
  let up = 1_000_000
  let old = RegistryDatum { ..t_datum(), cooldown_until: 600_000 }
  let new =
    RegistryDatum { ..old, pending: Some(t_pending(up + old.timelock_ms)) }
  // tx.lower 500k < cooldown 600k
  !check_propose(old, new, 500_000, up, True, tl_floor, cd_floor)
}

test registry2_propose_invalid_handover_admin_rejected() {
  let old = t_datum()
  let up = 1_000_000
  let bricked = Admin { keys: [t_key(#"aa")], threshold: 2 }
  let p =
    PendingUpdate {
      ..t_pending(up + old.timelock_ms),
      new_admin: Some(bricked),
    }
  !check_propose(
    old,
    RegistryDatum { ..old, pending: Some(p) },
    500_000,
    up,
    True,
    tl_floor,
    cd_floor,
  )
}

test registry2_propose_cannot_mutate_outside_pending() {
  let old = t_datum()
  let up = 1_000_000
  let base =
    RegistryDatum { ..old, pending: Some(t_pending(up + old.timelock_ms)) }
  and {
    !check_propose(
      old,
      RegistryDatum { ..base, epoch: 8 },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    !check_propose(
      old,
      RegistryDatum { ..base, logic_hash: t_logic_b },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    !check_propose(
      old,
      RegistryDatum { ..base, config: t_config_b() },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    !check_propose(
      old,
      RegistryDatum {
        ..base,
        admin: Admin { keys: [t_key(#"ee")], threshold: 1 },
      },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    !check_propose(
      old,
      RegistryDatum { ..base, cooldown_until: 1 },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    !check_propose(
      old,
      RegistryDatum { ..base, timelock_ms: 2_000_000 },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    !check_propose(
      old,
      RegistryDatum { ..base, cancel_cooldown_ms: cd_floor },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
  }
}

test registry2_propose_malformed_config_rejected() {
  let old = t_datum()
  let up = 1_000_000
  let cfg = t_config_b()
  let bad =
    UnderwriteConfig {
      ..cfg,
      mandates: [OracleMandate {
        primary_nft: #"01",
        fallback_feed_id: #"9999",
        second_leg: TrailingLowLeg,
      }],
    }
  let p = PendingUpdate { ..t_pending(up + old.timelock_ms), config: bad }
  !check_propose(
    old,
    RegistryDatum { ..old, pending: Some(p) },
    500_000,
    up,
    True,
    tl_floor,
    cd_floor,
  )
}

test registry2_propose_short_logic_hash_rejected() {
  let old = t_datum()
  let up = 1_000_000
  let p = PendingUpdate { ..t_pending(up + old.timelock_ms), logic_hash: #"02" }
  !check_propose(
    old,
    RegistryDatum { ..old, pending: Some(p) },
    500_000,
    up,
    True,
    tl_floor,
    cd_floor,
  )
}

// --- EnactUpdate -----------------------------------------------------------

test registry2_enact_happy_path_permissionless() {
  let eff = 5_000_000
  let p = t_pending(eff)
  let old = RegistryDatum { ..t_datum(), pending: Some(p) }
  // no `signed` parameter exists: enactment needs no signature at all
  check_enact(old, t_enacted(old, p), eff, tl_floor, cd_floor)
}

test registry2_enact_before_timelock_rejected() {
  let eff = 5_000_000
  let p = t_pending(eff)
  let old = RegistryDatum { ..t_datum(), pending: Some(p) }
  !check_enact(old, t_enacted(old, p), eff - 1, tl_floor, cd_floor)
}

test registry2_enact_wrong_logic_rejected() {
  let eff = 5_000_000
  let p = t_pending(eff)
  let old = RegistryDatum { ..t_datum(), pending: Some(p) }
  let stale = RegistryDatum { ..t_enacted(old, p), logic_hash: t_logic_a }
  !check_enact(old, stale, eff, tl_floor, cd_floor)
}

test registry2_enact_wrong_config_rejected() {
  let eff = 5_000_000
  let p = t_pending(eff)
  let old = RegistryDatum { ..t_datum(), pending: Some(p) }
  let stale = RegistryDatum { ..t_enacted(old, p), config: t_config() }
  !check_enact(old, stale, eff, tl_floor, cd_floor)
}

test registry2_enact_epoch_must_strictly_increment() {
  let eff = 5_000_000
  let p = t_pending(eff)
  let old = RegistryDatum { ..t_datum(), pending: Some(p) }
  let good = t_enacted(old, p)
  and {
    !check_enact(
      old,
      RegistryDatum { ..good, epoch: old.epoch },
      eff,
      tl_floor,
      cd_floor,
    ),
    !check_enact(
      old,
      RegistryDatum { ..good, epoch: old.epoch + 2 },
      eff,
      tl_floor,
      cd_floor,
    ),
  }
}

test registry2_enact_applies_admin_handover() {
  let eff = 5_000_000
  let cmatra =
    Admin {
      keys: [
        t_key(#"11"), t_key(#"22"), t_key(#"33"), t_key(#"44"), t_key(#"55"),
      ],
      threshold: 3,
    }
  let p = PendingUpdate { ..t_pending(eff), new_admin: Some(cmatra) }
  let old = RegistryDatum { ..t_datum(), pending: Some(p) }
  let good = RegistryDatum { ..t_enacted(old, p), admin: cmatra }
  let keep_old_admin = t_enacted(old, p)
  and {
    check_enact(old, good, eff, tl_floor, cd_floor),
    // refusing the handover (keeping the old admin) must be rejected
    !check_enact(old, keep_old_admin, eff, tl_floor, cd_floor),
  }
}

test registry2_enact_applies_proposed_clocks() {
  let eff = 5_000_000
  let p =
    PendingUpdate {
      ..t_pending(eff),
      timelock_ms: 2_000_000,
      cancel_cooldown_ms: 700_000,
    }
  let old = RegistryDatum { ..t_datum(), pending: Some(p) }
  let good = t_enacted(old, p)
  let stale =
    RegistryDatum {
      ..good,
      timelock_ms: old.timelock_ms,
      cancel_cooldown_ms: old.cancel_cooldown_ms,
    }
  and {
    check_enact(old, good, eff, tl_floor, cd_floor),
    !check_enact(old, stale, eff, tl_floor, cd_floor),
  }
}

test registry2_enact_subfloor_pending_rejected() {
  // belt-and-braces: even a pending that never passed propose cannot enact a
  // sub-floor clock
  let eff = 5_000_000
  let p = PendingUpdate { ..t_pending(eff), timelock_ms: tl_floor - 1 }
  let old = RegistryDatum { ..t_datum(), pending: Some(p) }
  !check_enact(old, t_enacted(old, p), eff, tl_floor, cd_floor)
}

test registry2_enact_malformed_pending_config_rejected() {
  let eff = 5_000_000
  let cfg = t_config_b()
  let bad = UnderwriteConfig { ..cfg, pyth_feed_allowlist: [#"0006", #"0006"] }
  let p = PendingUpdate { ..t_pending(eff), config: bad }
  let old = RegistryDatum { ..t_datum(), pending: Some(p) }
  !check_enact(old, t_enacted(old, p), eff, tl_floor, cd_floor)
}

test registry2_enact_must_clear_pending_and_pin_cooldown() {
  let eff = 5_000_000
  let p = t_pending(eff)
  let old = RegistryDatum { ..t_datum(), pending: Some(p) }
  let good = t_enacted(old, p)
  and {
    !check_enact(
      old,
      RegistryDatum { ..good, pending: Some(p) },
      eff,
      tl_floor,
      cd_floor,
    ),
    !check_enact(
      old,
      RegistryDatum { ..good, cooldown_until: 123 },
      eff,
      tl_floor,
      cd_floor,
    ),
  }
}

// --- the admin every arm writes --------------------------------------------

test registry2_propose_narrow_handover_key_rejected() {
  // `admin_signed` matches admin keys against `extra_signatories`, which are
  // 28-byte VKHs. A key of any other width matches no signatory, so the
  // reachable quorum sits below the threshold — unsatisfiable forever, the
  // same brick as `threshold > |keys|` and the same ceremony typo.
  let old = t_datum()
  let up = 1_000_000
  let narrow =
    Admin {
      keys: [bytearray.take(t_key(#"11"), 27), t_key(#"22")],
      threshold: 2,
    }
  let p =
    PendingUpdate { ..t_pending(up + old.timelock_ms), new_admin: Some(narrow) }
  !check_propose(
    old,
    RegistryDatum { ..old, pending: Some(p) },
    500_000,
    up,
    True,
    tl_floor,
    cd_floor,
  )
}

test registry2_enact_refuses_unsatisfiable_handover_admin() {
  // EnactUpdate is PERMISSIONLESS and is the arm that WRITES the admin, so
  // propose's check on the same value is fail-fast and this one is the
  // load-bearing guard — the split the config and the clocks already use. A
  // pending that never passed propose can only come from genesis, and no
  // validator runs at genesis.
  and {
    !t_enact_handover(Admin { keys: [t_key(#"11"), t_key(#"22")], threshold: 3 }),
    !t_enact_handover(Admin { keys: [t_key(#"11"), t_key(#"22")], threshold: 0 }),
    !t_enact_handover(Admin { keys: [], threshold: 1 }),
    !t_enact_handover(Admin { keys: [t_key(#"11"), t_key(#"11")], threshold: 2 }),
    !t_enact_handover(
      Admin { keys: [bytearray.take(t_key(#"11"), 27)], threshold: 1 },
    ),
    // the control: a well-formed handover still enacts
    t_enact_handover(Admin { keys: [t_key(#"11"), t_key(#"22")], threshold: 2 }),
  }
}

test registry2_enact_refuses_unsatisfiable_carried_admin() {
  // no handover: the admin the arm writes is `old.admin`, and writing an
  // unsignable one forward is the same brick by a quieter route
  let eff = 5_000_000
  let p = t_pending(eff)
  let bricked = Admin { keys: [t_key(#"11"), t_key(#"22")], threshold: 3 }
  let old = RegistryDatum { ..t_genesis(bricked), pending: Some(p) }
  !check_enact(old, t_enacted(old, p), eff, tl_floor, cd_floor)
}

// --- genesis: the one datum no transition wrote ----------------------------

test registry2_genesis_unsatisfiable_admin_rejected() {
  // threshold > |keys| — a plausible ceremony fat-finger. `signed` is
  // COMPUTED by the validator from `admin_signed`, never asserted, so with
  // every admin key signing the quorum still falls short: Propose is locked
  // from birth, and with no pending there is nothing for Cancel or Enact to
  // run on either. The registry NFT policy is a `pool_vault` compile
  // parameter, so replacing the UTxO means a whole new vault generation —
  // which is why this has to be impossible to create, not merely unlikely.
  let bricked = Admin { keys: [t_key(#"aa"), t_key(#"bb")], threshold: 3 }
  let g = t_genesis(bricked)
  let up = 1_000_000
  and {
    !admin_signed(bricked, bricked.keys),
    !check_propose(
      g,
      RegistryDatum { ..g, pending: Some(t_pending(up + g.timelock_ms)) },
      500_000,
      up,
      admin_signed(bricked, bricked.keys),
      tl_floor,
      cd_floor,
    ),
    !check_genesis(g, tl_floor, cd_floor),
  }
}

test registry2_genesis_malformed_admin_rejected() {
  and {
    check_genesis(t_genesis(t_admin()), tl_floor, cd_floor),
    // threshold 0 is not "anyone signs": `admin_signed` demands >= 1
    !check_genesis(
      t_genesis(Admin { keys: [t_key(#"aa"), t_key(#"bb")], threshold: 0 }),
      tl_floor,
      cd_floor,
    ),
    !check_genesis(
      t_genesis(Admin { keys: [], threshold: 1 }),
      tl_floor,
      cd_floor,
    ),
    // duplicates do not double-count, so the reachable quorum is 1, not 2
    !check_genesis(
      t_genesis(Admin { keys: [t_key(#"aa"), t_key(#"aa")], threshold: 2 }),
      tl_floor,
      cd_floor,
    ),
    !check_genesis(
      t_genesis(
        Admin { keys: [bytearray.take(t_key(#"aa"), 27)], threshold: 1 },
      ),
      tl_floor,
      cd_floor,
    ),
  }
}

test registry2_genesis_planted_pending_rejected() {
  // a genesis pending never passed check_propose, and check_enact cannot
  // reconstruct the propose-time wait — so a planted `effective_after` of 0
  // enacts on sight, setting aside the timelock this design calls its core
  // security parameter
  let planted = RegistryDatum { ..t_datum(), pending: Some(t_pending(0)) }
  !check_genesis(planted, tl_floor, cd_floor)
}

test registry2_genesis_armed_cooldown_rejected() {
  // [v1 N5] from birth: a `cooldown_until` past any reachable tx_lower makes
  // Propose's `tx_lower >= old.cooldown_until` unsatisfiable forever, and no
  // arm ever lowers it
  let armed =
    RegistryDatum { ..t_datum(), cooldown_until: 9_223_372_036_854_775_807 }
  !check_genesis(armed, tl_floor, cd_floor)
}

test registry2_genesis_rechecks_shape_and_rails() {
  // every transition re-checks these; genesis is the one write with no arm
  // behind it to re-check it
  let dup_allowlist =
    UnderwriteConfig { ..t_config(), pyth_feed_allowlist: [#"0006", #"0006"] }
  and {
    !check_genesis(
      RegistryDatum { ..t_datum(), logic_hash: #"02" },
      tl_floor,
      cd_floor,
    ),
    !check_genesis(
      RegistryDatum { ..t_datum(), timelock_ms: tl_floor - 1 },
      tl_floor,
      cd_floor,
    ),
    !check_genesis(
      RegistryDatum { ..t_datum(), cancel_cooldown_ms: cd_floor - 1 },
      tl_floor,
      cd_floor,
    ),
    !check_genesis(
      RegistryDatum { ..t_datum(), config: dup_allowlist },
      tl_floor,
      cd_floor,
    ),
  }
}

// --- CancelUpdate ----------------------------------------------------------

test registry2_cancel_happy_arms_cooldown() {
  let up = 2_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9_000_000)) }
  let new =
    RegistryDatum {
      ..old,
      pending: None,
      cooldown_until: up + old.cancel_cooldown_ms,
    }
  check_cancel(old, new, 1_400_000, up, True, cd_floor)
}

test registry2_cancel_unsigned_rejected() {
  let up = 2_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9_000_000)) }
  let new =
    RegistryDatum {
      ..old,
      pending: None,
      cooldown_until: up + old.cancel_cooldown_ms,
    }
  !check_cancel(old, new, 1_400_000, up, False, cd_floor)
}

test registry2_cancel_draws_cooldown_from_datum_not_module() {
  // the armed window comes from the IN-DATUM clock, not a compiled constant
  let up = 2_000_000
  let old =
    RegistryDatum {
      ..t_datum(),
      cancel_cooldown_ms: 987_654,
      pending: Some(t_pending(9_000_000)),
    }
  let new =
    RegistryDatum { ..old, pending: None, cooldown_until: up + 987_654 }
  check_cancel(old, new, 1_400_000, up, True, cd_floor)
}

test registry2_cancel_oversized_cooldown_rejected() {
  // [v1 N5] EXACT window, not an open ray — `>=` let one Cancel set
  // cooldown_until to 2^63-1 and permanently brick governance
  let up = 2_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9_000_000)) }
  let bricked =
    RegistryDatum {
      ..old,
      pending: None,
      cooldown_until: 9_223_372_036_854_775_807,
    }
  !check_cancel(old, bricked, 1_400_000, up, True, cd_floor)
}

test registry2_cancel_without_cooldown_rejected() {
  let up = 2_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9_000_000)) }
  let new = RegistryDatum { ..old, pending: None }
  // cooldown_until left at 0 -> rejected
  !check_cancel(old, new, 1_400_000, up, True, cd_floor)
}

test registry2_cancel_cannot_mutate_rest() {
  let up = 2_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9_000_000)) }
  let base =
    RegistryDatum {
      ..old,
      pending: None,
      cooldown_until: up + old.cancel_cooldown_ms,
    }
  and {
    !check_cancel(
      old,
      RegistryDatum { ..base, epoch: 8 },
      1_400_000,
      up,
      True,
      cd_floor,
    ),
    !check_cancel(
      old,
      RegistryDatum { ..base, logic_hash: t_logic_b },
      1_400_000,
      up,
      True,
      cd_floor,
    ),
    !check_cancel(
      old,
      RegistryDatum { ..base, config: t_config_b() },
      1_400_000,
      up,
      True,
      cd_floor,
    ),
    !check_cancel(
      old,
      RegistryDatum { ..base, timelock_ms: 1 },
      1_400_000,
      up,
      True,
      cd_floor,
    ),
    !check_cancel(
      old,
      RegistryDatum { ..base, cancel_cooldown_ms: 1 },
      1_400_000,
      up,
      True,
      cd_floor,
    ),
  }
}

// --- config_within_rails ----------------------------------------------------

test registry2_config_genesis_shape_well_formed() {
  config_within_rails(t_config())
}

test registry2_config_empty_mandates_allowed() {
  // the halt-new-business fail-safe posture must remain expressible. It
  // empties `depeg_eligible` too: under the R4 subset rail a depeg feed with
  // no mandate is the violation, and an emptied mandate list orphans it.
  let cfg = t_config()
  config_within_rails(
    UnderwriteConfig { ..cfg, mandates: [], depeg_eligible: [] },
  )
}

test registry2_config_fallback_not_allowlisted_rejected() {
  let cfg = t_config()
  let bad =
    UnderwriteConfig {
      ..cfg,
      mandates: [OracleMandate {
        primary_nft: #"01",
        fallback_feed_id: #"9999",
        second_leg: TrailingLowLeg,
      }],
    }
  !config_within_rails(bad)
}

test registry2_config_duplicate_lists_rejected() {
  let cfg = t_config()
  let dup_primary =
    [
      OracleMandate {
        primary_nft: #"01",
        fallback_feed_id: #"0006",
        second_leg: TrailingLowLeg,
      },
      OracleMandate {
        primary_nft: #"01",
        fallback_feed_id: #"",
        second_leg: TrailingLowLeg,
      },
    ]
  and {
    !config_within_rails(
      UnderwriteConfig { ..cfg, mandates: dup_primary },
    ),
    !config_within_rails(
      UnderwriteConfig { ..cfg, depeg_eligible: [#"02", #"02"] },
    ),
    !config_within_rails(
      UnderwriteConfig { ..cfg, pyth_feed_allowlist: [#"0006", #"0006"] },
    ),
  }
}

test registry2_config_bad_hash_lengths_rejected() {
  let cfg = t_config()
  and {
    !config_within_rails(
      UnderwriteConfig { ..cfg, publisher_vkh: bytearray.take(t_publisher, 27) },
    ),
    !config_within_rails(UnderwriteConfig { ..cfg, observer_hash: #"01" }),
    !config_within_rails(UnderwriteConfig { ..cfg, pyth_state_nft: #"" }),
  }
}

test registry2_config_bad_budgets_rejected() {
  let cfg = t_config()
  let b = cfg.budgets
  and {
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets { ..b, term_min_ms: b.term_max_ms + 1 },
      },
    ),
    !config_within_rails(
      UnderwriteConfig { ..cfg, budgets: Budgets { ..b, spot_age_barrier_ms: 0 } },
    ),
    !config_within_rails(
      UnderwriteConfig { ..cfg, budgets: Budgets { ..b, spot_age_depeg_ms: 0 } },
    ),
    !config_within_rails(
      UnderwriteConfig { ..cfg, budgets: Budgets { ..b, underwrite_span_ms: 0 } },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets { ..b, min_premium: min_utxo_lovelace - 1 },
      },
    ),
  }
}

test registry2_config_fee_bounds_rejected() {
  let cfg = t_config()
  and {
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        fee: Fee { ..cfg.fee, treasury_bps: 10_001 },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        fee: Fee { ..cfg.fee, treasury_bps: -1 },
      },
    ),
  }
}

// --- S3 rails: clock ceilings, genesis floors, validity width --------------

test registry2_propose_clock_above_ceiling_rejected() {
  let old = t_datum()
  let up = 1_000_000
  let base = t_pending(up + old.timelock_ms)
  let big_tl = PendingUpdate { ..base, timelock_ms: max_registry_clock_ms + 1 }
  let big_cd =
    PendingUpdate { ..base, cancel_cooldown_ms: max_registry_clock_ms + 1 }
  let at_ceiling =
    PendingUpdate {
      ..base,
      timelock_ms: max_registry_clock_ms,
      cancel_cooldown_ms: max_registry_clock_ms,
    }
  and {
    !check_propose(
      old,
      RegistryDatum { ..old, pending: Some(big_tl) },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    !check_propose(
      old,
      RegistryDatum { ..old, pending: Some(big_cd) },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    check_propose(
      old,
      RegistryDatum { ..old, pending: Some(at_ceiling) },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
  }
}

test registry2_enact_above_ceiling_pending_rejected() {
  // belt-and-braces: even a pending that never passed propose cannot enact
  // an above-ceiling clock
  let eff = 5_000_000
  let big_tl =
    PendingUpdate { ..t_pending(eff), timelock_ms: max_registry_clock_ms + 1 }
  let big_cd =
    PendingUpdate {
      ..t_pending(eff),
      cancel_cooldown_ms: max_registry_clock_ms + 1,
    }
  let at_ceiling =
    PendingUpdate {
      ..t_pending(eff),
      timelock_ms: max_registry_clock_ms,
      cancel_cooldown_ms: max_registry_clock_ms,
    }
  let old_tl = RegistryDatum { ..t_datum(), pending: Some(big_tl) }
  let old_cd = RegistryDatum { ..t_datum(), pending: Some(big_cd) }
  let old_at = RegistryDatum { ..t_datum(), pending: Some(at_ceiling) }
  and {
    !check_enact(
      old_tl,
      t_enacted(old_tl, big_tl),
      eff,
      tl_floor,
      cd_floor,
    ),
    !check_enact(
      old_cd,
      t_enacted(old_cd, big_cd),
      eff,
      tl_floor,
      cd_floor,
    ),
    check_enact(
      old_at,
      t_enacted(old_at, at_ceiling),
      eff,
      tl_floor,
      cd_floor,
    ),
  }
}

test registry2_propose_unfloored_genesis_waits_floor() {
  // genesis is validated by nothing on chain (the spend validator does not
  // run at creation), so a datum born with a zero or negative timelock must
  // not grant a rushed first transition — the wait clamps to the floor
  let up = 1_000_000
  let zero = RegistryDatum { ..t_datum(), timelock_ms: 0 }
  let neg = RegistryDatum { ..t_datum(), timelock_ms: -1_000_000 }
  and {
    !check_propose(
      zero,
      RegistryDatum { ..zero, pending: Some(t_pending(up)) },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    !check_propose(
      zero,
      RegistryDatum { ..zero, pending: Some(t_pending(up + tl_floor - 1)) },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    !check_propose(
      neg,
      RegistryDatum { ..neg, pending: Some(t_pending(up)) },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    check_propose(
      zero,
      RegistryDatum { ..zero, pending: Some(t_pending(up + tl_floor)) },
      500_000,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
  }
}

test registry2_cancel_unfloored_genesis_arms_floor_cooldown() {
  // same genesis hole on the cancel clock: a datum born with
  // cancel_cooldown_ms = 0 must still arm at least the floor
  let up = 2_000_000
  let zero =
    RegistryDatum {
      ..t_datum(),
      cancel_cooldown_ms: 0,
      pending: Some(t_pending(9_000_000)),
    }
  let unarmed = RegistryDatum { ..zero, pending: None, cooldown_until: up }
  let floored =
    RegistryDatum { ..zero, pending: None, cooldown_until: up + cd_floor }
  and {
    !check_cancel(zero, unarmed, 1_400_000, up, True, cd_floor),
    check_cancel(zero, floored, 1_400_000, up, True, cd_floor),
  }
}

test registry2_propose_wide_validity_rejected() {
  let old = t_datum()
  let up = 100_000_000
  let new =
    RegistryDatum { ..old, pending: Some(t_pending(up + old.timelock_ms)) }
  and {
    !check_propose(
      old,
      new,
      up - max_registry_span_ms - 1,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
    check_propose(
      old,
      new,
      up - max_registry_span_ms,
      up,
      True,
      tl_floor,
      cd_floor,
    ),
  }
}

test registry2_cancel_wide_validity_rejected() {
  let up = 100_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9_000_000)) }
  let new =
    RegistryDatum {
      ..old,
      pending: None,
      cooldown_until: up + old.cancel_cooldown_ms,
    }
  and {
    !check_cancel(old, new, up - max_registry_span_ms - 1, up, True, cd_floor),
    check_cancel(old, new, up - max_registry_span_ms, up, True, cd_floor),
  }
}

test registry2_config_bad_pins_rejected() {
  let cfg = t_config()
  let s = cfg.settlement_pins
  and {
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins { ..s, reading_validity_ms: 0 },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins { ..s, pyth_freshness_ms: 0 },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins { ..s, pyth_max_confidence_bps: -1 },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins { ..s, grace_barrier_ms: -1 },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins { ..s, cancellation_window_ms: -1 },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins { ..s, cancellation_fee_bps: 10_001 },
      },
    ),
  }
}

// --- S4 rails: §5 upper bounds on the governed budgets and pins ------------

test registry2_config_spot_age_above_rail_rejected() {
  let cfg = t_config()
  let b = cfg.budgets
  and {
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets { ..b, spot_age_barrier_ms: max_spot_age_rail_ms + 1 },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets { ..b, spot_age_depeg_ms: max_spot_age_rail_ms + 1 },
      },
    ),
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets {
          ..b,
          spot_age_barrier_ms: max_spot_age_rail_ms,
          spot_age_depeg_ms: max_spot_age_rail_ms,
        },
      },
    ),
  }
}

test registry2_config_span_above_rail_rejected() {
  let cfg = t_config()
  let b = cfg.budgets
  and {
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets {
          ..b,
          underwrite_span_ms: max_underwrite_span_rail_ms + 1,
        },
      },
    ),
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets { ..b, underwrite_span_ms: max_underwrite_span_rail_ms },
      },
    ),
  }
}

/// G3 made this rail the ONLY term floor: the vault stopped reading
/// `min_policy_term_ms` outside its own tests, so nothing tied the rail to the
/// term the premium table can actually price. Lowering it to 1 day left all
/// 1132 tests green — the identical silent revert `floor_table` already records
/// happening once to this same constant. Only the hash-surface literal pin
/// reddened, and that gate asks whether a value was re-pinned deliberately, not
/// whether it is sound.
///
/// The rail may exceed the priced floor; it may never fall below it, because a
/// rail-legal enactment under the priced floor sells cover at `t_band_index`
/// band 0, which is a literal 0 bps once the strike is far enough out.
test registry2_term_rail_never_admits_a_term_the_table_cannot_price() {
  min_term_rail_ms >= min_policy_term_ms
}

test registry2_config_term_outside_rail_rejected() {
  let cfg = t_config()
  let b = cfg.budgets
  and {
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets { ..b, term_max_ms: max_term_rail_ms + 1 },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets { ..b, term_min_ms: min_term_rail_ms - 1 },
      },
    ),
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets {
          ..b,
          term_min_ms: min_term_rail_ms,
          term_max_ms: max_term_rail_ms,
        },
      },
    ),
  }
}

test registry2_config_stale_freshness_pins_rejected() {
  let cfg = t_config()
  let s = cfg.settlement_pins
  and {
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins {
          ..s,
          reading_validity_ms: max_reading_validity_rail_ms + 1,
        },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins {
          ..s,
          pyth_freshness_ms: max_reading_validity_rail_ms + 1,
        },
      },
    ),
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins {
          ..s,
          reading_validity_ms: max_reading_validity_rail_ms,
          pyth_freshness_ms: max_reading_validity_rail_ms,
        },
      },
    ),
  }
}

test registry2_config_grace_above_rail_rejected() {
  let cfg = t_config()
  let s = cfg.settlement_pins
  and {
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins {
          ..s,
          grace_barrier_ms: max_grace_rail_ms + 1,
        },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins {
          ..s,
          grace_depeg_ms: max_grace_rail_ms + 1,
        },
      },
    ),
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins {
          ..s,
          grace_barrier_ms: max_grace_rail_ms,
          grace_depeg_ms: max_grace_rail_ms,
        },
      },
    ),
  }
}

test registry2_config_cancellation_window_above_rail_rejected() {
  let cfg = t_config()
  let s = cfg.settlement_pins
  and {
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins {
          ..s,
          cancellation_window_ms: max_cancellation_window_rail_ms + 1,
        },
      },
    ),
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins {
          ..s,
          cancellation_window_ms: max_cancellation_window_rail_ms,
        },
      },
    ),
  }
}

test registry2_config_confidence_above_its_rail_rejected() {
  // [#418] The old bound was the bps SCALE, which admits a print whose stated
  // error bar is the whole price — a type bound wearing a rail's clothes. The
  // rail is now its own constant, and the boundary is EXACT so the refusal is
  // attributable to the rail rather than to a blanket ban.
  let cfg = t_config()
  let s = cfg.settlement_pins
  and {
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins {
          ..s,
          pyth_max_confidence_bps: max_pyth_confidence_rail_bps + 1,
        },
      },
    ),
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins {
          ..s,
          pyth_max_confidence_bps: max_pyth_confidence_rail_bps,
        },
      },
    ),
    // ...and the LIVE value must still be proposable, or the enacted config
    // becomes unproposable the moment this rail ships.
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        settlement_pins: SettlementPins {
          ..s,
          pyth_max_confidence_bps: core_pyth_max_confidence_bps,
        },
      },
    ),
    // The rail must sit strictly ABOVE the value the observer actually gates
    // on, or governance could never widen tolerance during the dislocation the
    // cover exists for — and the ceiling is compiled into the vault, so
    // loosening it later costs a whole generation.
    max_pyth_confidence_rail_bps > core_pyth_max_confidence_bps,
    max_pyth_confidence_rail_bps < 10_000,
  }
}

// --- §5 rails: the four directions, and the three relations ----------------
// A governed value without a rail is an unbounded delegation to the admin
// quorum. `config_within_rails` is where the four directions land — ceiling,
// FLOOR, set-membership, relational — and the relational ones are the reason
// this block exists rather than three compile-time tests: the moment their
// operands become registry data, a constant-vs-constant test keeps passing
// while binding nothing.

test registry2_rails_admit_the_genesis_config() {
  config_within_rails(t_config())
}

test registry2_rejects_utilisation_above_rail() {
  // CEILING. The book cap is the only knob bounding how much of the pool sits
  // as live coverage, and its dangerous direction is UP: a restriction can be
  // clamped off chain for free, a relaxation cannot.
  let cfg = t_config()
  let b = cfg.budgets
  and {
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets { ..b, utilisation_bps: max_utilisation_rail_bps },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets { ..b, utilisation_bps: max_utilisation_rail_bps + 1 },
      },
    ),
    // a zero cap is not a fail-safe, it is a book that can never be written,
    // and `mandates: []` already expresses halt-new-business
    !config_within_rails(
      UnderwriteConfig { ..cfg, budgets: Budgets { ..b, utilisation_bps: 0 } },
    ),
  }
}

test registry2_rejects_coverage_ratio_above_rail() {
  // CEILING. Premium adequacy is the last-resort LP protection: coverage may
  // not exceed premium * ratio, so a ratio above the rail sells unbounded
  // cover for a dust premium.
  let cfg = t_config()
  let b = cfg.budgets
  and {
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets { ..b, max_coverage_ratio: max_coverage_ratio_rail },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        budgets: Budgets { ..b, max_coverage_ratio: max_coverage_ratio_rail + 1 },
      },
    ),
    !config_within_rails(
      UnderwriteConfig { ..cfg, budgets: Budgets { ..b, max_coverage_ratio: 0 } },
    ),
  }
}

test registry2_rejects_strike_floor_below_rail() {
  // FLOOR — the direction the landed rails do not have. Below the rail the
  // barrier is a certainty inside tick noise, so the premium prices nothing.
  let cfg = t_config()
  let f = cfg.floors
  and {
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        floors: Floors {
          ..f,
          min_strike_distance_bps: min_strike_distance_rail_bps,
        },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        floors: Floors {
          ..f,
          min_strike_distance_bps: min_strike_distance_rail_bps - 1,
        },
      },
    ),
  }
}

test registry2_rejects_depeg_distance_floor_below_rail() {
  // FLOOR. A healthy stable sits inside ~50 bps of peg, so a distance floor
  // under the rail sells cover that is already in the money on book noise.
  let cfg = t_config()
  let f = cfg.floors
  and {
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        floors: Floors {
          ..f,
          min_depeg_distance_bps: min_depeg_distance_rail_bps,
        },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        floors: Floors {
          ..f,
          min_depeg_distance_bps: min_depeg_distance_rail_bps - 1,
        },
      },
    ),
  }
}

test registry2_rejects_depeg_band_outside_rails() {
  // FLOOR + CEILING on the depeg strike band.
  let cfg = t_config()
  let f = cfg.floors
  and {
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        floors: Floors {
          ..f,
          depeg_strike_lo_bps: min_depeg_strike_lo_rail_bps - 1,
        },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        floors: Floors {
          ..f,
          depeg_strike_hi_bps: max_depeg_strike_hi_rail_bps + 1,
          min_depeg_spot_bps: 10_000,
        },
      },
    ),
  }
}

test registry2_rejects_peg_health_below_rail() {
  // FLOOR. Below the rail the peg is broken by any definition, so the gate
  // would admit cover on an asset that has already failed.
  let cfg = t_config()
  let f = cfg.floors
  and {
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        floors: Floors {
          ..f,
          min_depeg_spot_bps: min_depeg_spot_rail_bps,
          depeg_strike_hi_bps: min_depeg_spot_rail_bps - 1,
        },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        floors: Floors {
          ..f,
          min_depeg_spot_bps: min_depeg_spot_rail_bps - 1,
          depeg_strike_hi_bps: min_depeg_spot_rail_bps - 2,
        },
      },
    ),
  }
}

test registry2_rejects_fee_take_above_rail() {
  // CEILING on the protocol take of each premium — the RATE, not treasury's
  // share of it.
  let cfg = t_config()
  let fee = cfg.fee
  and {
    config_within_rails(
      UnderwriteConfig {
        ..cfg,
        fee: Fee { ..fee, take_bps: max_fee_take_rail_bps },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        fee: Fee { ..fee, take_bps: max_fee_take_rail_bps + 1 },
      },
    ),
    !config_within_rails(
      UnderwriteConfig { ..cfg, fee: Fee { ..fee, take_bps: -1 } },
    ),
  }
}

test registry2_rejects_non_push_provider() {
  // SET. Governance may add a provider; it may never add one whose spot the
  // BUYER authors. Pyth Lazer's price arrives in a withdrawal redeemer the
  // transaction builder supplies, and at Underwrite the buyer is the builder.
  let cfg = t_config()
  and {
    config_within_rails(
      UnderwriteConfig { ..cfg, admissible_providers: [AegisSelf] },
    ),
    !config_within_rails(
      UnderwriteConfig { ..cfg, admissible_providers: [AegisSelf, Pyth] },
    ),
    !config_within_rails(
      UnderwriteConfig { ..cfg, admissible_providers: [Charli3] },
    ),
    !config_within_rails(
      UnderwriteConfig { ..cfg, admissible_providers: [Orcfax] },
    ),
    // a duplicate is a ceremony typo the same way a duplicate admin key is
    !config_within_rails(
      UnderwriteConfig { ..cfg, admissible_providers: [AegisSelf, AegisSelf] },
    ),
  }
}

// [#316] The governance half of retiring Indigo. `config_within_rails` bounds
// `admissible_providers` by `provider_is_push`, so a provider that is no longer
// push cannot be voted back into the sellable set by any EnactUpdate — the arm
// is dead in the resolver AND unreachable through governance.
test registry2_indigo_is_retired_and_ungovernable() {
  let cfg = t_config()
  and {
    !provider_is_push(Indigo),
    !config_within_rails(
      UnderwriteConfig { ..cfg, admissible_providers: [Indigo] },
    ),
    !config_within_rails(
      UnderwriteConfig { ..cfg, admissible_providers: [AegisSelf, Indigo] },
    ),
  }
}

test registry2_push_providers_are_named_exhaustively() {
  and {
    provider_is_push(AegisSelf),
    !provider_is_push(Indigo),
    !provider_is_push(Pyth),
    !provider_is_push(Charli3),
    !provider_is_push(Orcfax),
  }
}

test registry2_rejects_peg_health_at_or_below_band_hi() {
  // RELATIONAL (R4/1). Replaces floor_table's compile-time
  // `healthy_peg_is_above_every_permitted_strike`, which compares two
  // constants: once its operands are registry data it stays GREEN while
  // binding nothing. A peg gate at or below the band ceiling means the
  // highest permitted strike is already "healthy", so Depeg cover can be
  // bought on an asset the same config calls broken.
  let cfg = t_config()
  let f = cfg.floors
  and {
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        floors: Floors {
          ..f,
          depeg_strike_hi_bps: 9_500,
          min_depeg_spot_bps: 9_500,
        },
      },
    ),
    !config_within_rails(
      UnderwriteConfig {
        ..cfg,
        floors: Floors {
          ..f,
          depeg_strike_hi_bps: 9_500,
          min_depeg_spot_bps: 9_400,
        },
      },
    ),
  }
}

test registry2_rejects_depeg_eligible_outside_mandate_primaries() {
  // RELATIONAL (R4/2), and the ABORT-shaped one. Depeg Underwrite resolves
  // the SAME pinned feed the Claim will judge on, which only resolves when the
  // depeg feed is a mandate primary. A config that violates the subset makes
  // the arm ABORT fail-closed rather than reject cleanly, and the compile-time
  // `depeg_feeds_are_canonical` test cannot see it once both lists are data.
  let cfg = t_config()
  and {
    !config_within_rails(
      UnderwriteConfig { ..cfg, depeg_eligible: [#"02", #"99"] },
    ),
    // halting new business empties BOTH: a depeg feed with no mandate is the
    // violation, not the empty list
    config_within_rails(
      UnderwriteConfig { ..cfg, mandates: [], depeg_eligible: [] },
    ),
    !config_within_rails(UnderwriteConfig { ..cfg, mandates: [] }),
  }
}

test registry2_rejects_inverted_depeg_band() {
  // RELATIONAL (R4/3). An inverted band admits no strike at all, so every
  // Depeg underwrite reverts with no diagnostic.
  let cfg = t_config()
  let f = cfg.floors
  !config_within_rails(
    UnderwriteConfig {
      ..cfg,
      floors: Floors {
        ..f,
        depeg_strike_lo_bps: 9_500,
        depeg_strike_hi_bps: 5_000,
      },
    },
  )
}

test registry2_fee_sink_is_never_the_vault() {
  // The one conjunct that CANNOT live in `config_within_rails`: the registry
  // validator takes the NFT policy and name and nothing else, so it does not
  // know the vault's hash and must not learn it — that back-edge is the const
  // cycle this repo has already deadlocked a deploy on. The vault checks this
  // at Underwrite, where the hash is its own.
  let vault_team =
    Address { payment_credential: Script(t_vault), stake_credential: None }
  let other_team =
    Address {
      payment_credential: Script(t_other_script),
      stake_credential: None,
    }
  let fee = t_config().fee
  and {
    !fee_sink_not_vault(Fee { ..fee, team_address: vault_team }, t_vault),
    fee_sink_not_vault(Fee { ..fee, team_address: other_team }, t_vault),
    fee_sink_not_vault(fee, t_vault),
  }
}
