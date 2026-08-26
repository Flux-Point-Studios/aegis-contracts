// =============================================================================
// Aegis - Pyth fallback STALE GATE (#381 V8.1 S2)
//
// The security heart of the dual-oracle design: the Pyth leg is admissible
// ONLY when the AegisSelf primary is LEDGER-PROVABLY stale. The claim tx must
// present the primary feed UTxO itself as a reference input and prove its
// published expiry (+ grace) lies strictly before the tx's certified lower
// bound. While the primary is healthy this predicate is False and no oracle
// choice exists (R2); when the feed UTxO cannot be presented at all the
// predicate ABORTS — absence is deliberately unprovable (an absence proof
// would be forgeable by simply omitting the reference input).
//
// STRICT SINGLETON (the two-feed substitution killer): EXACTLY ONE reference
// input may qualify as the primary feed, and it must carry EXACTLY ONE token
// under the primary policy. The one-shot mint makes a second token
// impossible today; the assertion is defense-in-depth against any future
// rotation window in which two feed generations could coexist under one
// canonical entry — in that world a claimant must never get to CHOOSE which
// generation's staleness to prove.
//
// Identity mirrors aegis_self.find_feed_output byte-for-byte: canonical-list
// membership for the handle AND the publisher payment credential on the UTxO
// — a decoy under an attacker policy or at a foreign address never qualifies,
// so it can neither prove staleness nor mask the real feed.
// =============================================================================

use aegis/oracle
use aegis/oracle/charli3.{
  OracleDatum, create_oracle_datum_with_min, get_oracle_expiry,
}
use aegis/oracle/types as oracle_types
use aegis/test_helpers/fixtures
use aegis/test_helpers/pyth_fixtures
use aegis/types as aegis_types
use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Address, VerificationKey}
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}

/// True iff the primary AegisSelf feed named by `primary_nft` is ledger-
/// provably stale: its published `valid_until` (datum key 2) plus `grace_ms`
/// lies STRICTLY before `tx_lower` (the one bound the ledger certifies is at
/// or before inclusion). Aborts fail-closed when the feed UTxO is absent,
/// duplicated, over-carried, non-canonical, or malformed.
pub fn primary_stale_proven(
  reference_inputs: List<Input>,
  primary_nft: ByteArray,
  grace_ms: Int,
  tx_lower: Int,
) -> Bool {
  expect aegis_types.is_canonical_aegis_self_nft(primary_nft)
  let publisher_credential =
    VerificationKey(aegis_types.aegis_self_publisher_vkh)
  // STRICT SINGLETON leg 1: exactly one qualifying reference input.
  expect [feed_input] = list.filter(
    reference_inputs,
    fn(input) {
      list.has(assets.policies(input.output.value), primary_nft) && input.output.address.payment_credential == publisher_credential
    },
  )
  // STRICT SINGLETON leg 2: that UTxO carries exactly one token (qty 1)
  // under the primary policy.
  expect [Pair(_, 1)] = dict.to_pairs(
    assets.tokens(feed_input.output.value, primary_nft),
  )
  expect InlineDatum(raw) = feed_input.output.datum
  expect datum: OracleDatum = raw
  get_oracle_expiry(datum) + grace_ms < tx_lower
}

// ===========================================================================
// Tests — fixtures derive the feed identity from the ACTIVE network module
// (#363 N6: never a hardcoded literal). tx_lower/grace in POSIX ms.
// ===========================================================================

const s2_grace_ms: Int = 1_800_000

fn s2_primary_nft() -> ByteArray {
  expect [nft, ..] = aegis_types.aegis_self_canonical_nfts
  nft
}

fn s2_publisher_addr() -> Address {
  Address(VerificationKey(aegis_types.aegis_self_publisher_vkh), None)
}

fn s2_feed_input(tag: ByteArray, qty: Int, at: Address, expiry: Int) -> Input {
  Input(
    OutputReference(tag, 0),
    Output {
      address: at,
      value: assets.from_asset(s2_primary_nft(), "F", qty),
      datum: InlineDatum(
        create_oracle_datum_with_min(
          600_000,
          expiry - 4_200_000,
          expiry,
          600_000,
          expiry - 4_200_000,
        ),
      ),
      reference_script: None,
    },
  )
}

test s2_stale_primary_proven() {
  // valid_until 1_000, grace 1_800_000 -> stale from 1_801_001 onward
  let refs = [s2_feed_input(#"01", 1, s2_publisher_addr(), 1_000)]
  primary_stale_proven(refs, s2_primary_nft(), s2_grace_ms, 1_801_001)
}

test s2_fresh_primary_not_stale() {
  // expiry far beyond tx_lower -> healthy -> the Pyth leg stays closed
  let refs = [s2_feed_input(#"01", 1, s2_publisher_addr(), 9_000_000)]
  !primary_stale_proven(refs, s2_primary_nft(), s2_grace_ms, 1_801_001)
}

test s2_boundary_exact_not_stale() {
  // valid_until + grace == tx_lower is NOT stale (strict <)
  let refs = [s2_feed_input(#"01", 1, s2_publisher_addr(), 1_000)]
  !primary_stale_proven(refs, s2_primary_nft(), s2_grace_ms, 1_801_000)
}

test s2_boundary_one_ms_past_is_stale() {
  let refs = [s2_feed_input(#"01", 1, s2_publisher_addr(), 1_000)]
  primary_stale_proven(refs, s2_primary_nft(), s2_grace_ms, 1_801_001)
}

test s2_two_feed_substitution_aborts() fail {
  // The killer case: a stale-looking UTxO presented ALONGSIDE the real feed.
  // Two qualifying reference inputs must abort, never pick-first.
  let refs = [
    s2_feed_input(#"01", 1, s2_publisher_addr(), 1_000),
    s2_feed_input(#"02", 1, s2_publisher_addr(), 9_000_000),
  ]
  primary_stale_proven(refs, s2_primary_nft(), s2_grace_ms, 1_801_001) || True
}

test s2_qty_two_aborts() fail {
  let refs = [s2_feed_input(#"01", 2, s2_publisher_addr(), 1_000)]
  primary_stale_proven(refs, s2_primary_nft(), s2_grace_ms, 1_801_001) || True
}

test s2_absent_feed_aborts() fail {
  // absence is unprovable staleness — fail-closed, both legs die together
  primary_stale_proven([], s2_primary_nft(), s2_grace_ms, 1_801_001) || True
}

test s2_decoy_at_foreign_address_aborts() fail {
  // the real feed missing; a decoy at a non-publisher address never qualifies
  let decoy_addr = Address(
    VerificationKey(#"00000000000000000000000000000000000000000000000000000000"),
    None,
  )
  let refs = [s2_feed_input(#"01", 1, decoy_addr, 1_000)]
  primary_stale_proven(refs, s2_primary_nft(), s2_grace_ms, 1_801_001) || True
}

test s2_noncanonical_handle_aborts() fail {
  let refs = [s2_feed_input(#"01", 1, s2_publisher_addr(), 1_000)]
  primary_stale_proven(refs, #"deadbeef", s2_grace_ms, 1_801_001) || True
}

// ===========================================================================
// [#381 V8.1 S4] settle_price — the ONE shared Claim/Cancel resolution.
//
// Primary first, always: when the observer attests the policy's own AegisSelf
// feed, that price settles and the fallback is never consulted — no oracle
// choice exists while the primary is present (R2). The Pyth leg opens ONLY
// when ALL of: the POLICY pins a non-empty fallback feed-id, the
// fallback id is canonical (defense-in-depth; the S5 invariant pins the
// allowlist to the mandate image), the primary is LEDGER-PROVABLY stale
// (primary_stale_proven — strict singleton over the presented feed UTxO), and
// the Pyth reading is BOTH inside the per-class spot-age budget of tx_UPPER
// (kills the update cherry-pick: tx_upper is the bound the ledger forces
// forward, so it is the one that caps the reading's age at inclusion — see the
// leg itself for why the tx_lower form this replaced was vacuous) and at/after
// the policy's start_time (kills SEC-F1 pre-start retroactive coverage; with
// the spot-only Price collapse, observed_at IS low_observed_at, so this also
// bounds the barrier disjunct). The vault's existing claim_trigger_ok /
// reading_fresh / otm_ok conjuncts then apply to the returned Price unchanged.
// ===========================================================================

/// [V8.2 G5] `fallback_feed_id` arrives as the POLICY'S OWN PIN, not out of a
/// vault compile parameter it used to be looked up in. Underwrite binds that
/// pin equal to the governed mandate's fallback for the policy's `oracle_nft`
/// (`pool_vault` `fallback_pin_ok`), so the authority behind the id is
/// unchanged while settlement's dependency on the vault's parameter list is
/// gone — the eleven mainnet mandate slots were 450 B of compiled parameter
/// standing between the vault and the publishable-script ceiling, and the pin
/// was already in the datum carrying exactly this value.
pub fn settle_price(
  self: Transaction,
  observer_script_hash: ByteArray,
  fallback_feed_id: ByteArray,
  primary_nft: ByteArray,
  risk_class: aegis_types.RiskClass,
  start_time: Int,
  tx_lower: Int,
  tx_upper: Int,
) -> oracle_types.Price {
  when
    oracle.attested_price_opt(
      self,
      observer_script_hash,
      aegis_types.AegisSelf,
      primary_nft,
    )
  is {
    Some(p) -> p
    None -> {
      expect fallback_feed_id != #""
      expect oracle.is_canonical_oracle_nft(aegis_types.Pyth, fallback_feed_id)
      expect
        primary_stale_proven(
          self.reference_inputs,
          primary_nft,
          aegis_types.pyth_fallback_grace_ms(risk_class),
          tx_lower,
        )
      let p = oracle.attested_price(
        self,
        observer_script_hash,
        aegis_types.Pyth,
        fallback_feed_id,
      )
      // [V8.2 H2] Bounded against tx_UPPER, the only bound the ledger forces
      // FORWARD. `currentSlot < invalidHereafter` puts tx_upper at or after
      // inclusion, so this caps the reading's real age at settlement. The old
      // leg read `tx_lower <= observed_at + budget`, and the ledger certifies
      // tx_lower only as `invalidBefore <= currentSlot` — an upper bound, which
      // bounds nothing below. tx_lower was therefore free to sink to the floor
      // `reading_fresh` imposes (`tx_lower >= observed_at`), where the leg holds
      // for a reading of any age; the sole remaining cap on inclusion was
      // `tx_upper <= valid_until`, i.e. Pyth's own 70-minute window. The
      // enforced window was 70 minutes, not the 10/5 that max_spot_age_ms
      // advertises.
      //
      // Direction matters: reading_fresh wants `tx_lower >= observed_at` and
      // this wants `tx_upper <= observed_at + budget`, so the two clamp the tx
      // validity range inside the reading's budget from both sides rather than
      // fighting. Underwrite's sibling leg judges `start_time`, not a tx bound,
      // because there the quantity at risk is the age of the reading that SET
      // the strike; here it is the age of the reading that SETTLES the money.
      expect tx_upper <= p.observed_at + aegis_types.max_spot_age_ms(risk_class)
      expect p.observed_at >= start_time
      p
    }
  }
}

// ===========================================================================
// settle_price tests. The Pyth side rides the REAL signed Lazer payload
// (pyth_fixtures, feed 2 @ timestamp 1772613309000 ms); the AegisSelf side
// rides the s2 feed fixtures. Attestations are packed GENUINELY via
// fixtures.with_observer_attestation (it resolves, never fabricates).
// ===========================================================================

const s4_obs: ByteArray = #"92c3"

const s4_pyth_ts: Int = 1_772_613_309_000

/// [V8.2 G5] The fallback the POLICY pins — the value Underwrite copied out of
/// the governed mandate for this pair. Feed 2 is the vendored Lazer payload.
const s4_pinned_feed: ByteArray = #"02"

/// A settle tx on the FALLBACK leg: pyth machinery + a primary feed UTxO with
/// the given expiry + a genuine (Pyth, #"02") observer attestation.
fn s4_fallback_tx(primary_expiry: Int) -> Transaction {
  let base = pyth_fixtures.pyth_tx()
  let with_primary = Transaction {
    ..base,
    reference_inputs: [
      s2_feed_input(#"aa", 1, s2_publisher_addr(), primary_expiry),
      ..base.reference_inputs
    ],
  }
  fixtures.with_observer_attestation(
    with_primary,
    s4_obs,
    [(aegis_types.Pyth, #"02")],
  )
}

test s4_primary_present_settles_primary() {
  // fresh primary attested -> its price returns; fallback machinery absent.
  let base = Transaction {
    ..fixtures.base_tx(),
    reference_inputs: [
      s2_feed_input(#"aa", 1, s2_publisher_addr(), 9_000_000_000),
    ],
  }
  let tx = fixtures.with_observer_attestation(
    base,
    s4_obs,
    [(aegis_types.AegisSelf, s2_primary_nft())],
  )
  let p = settle_price(
    tx,
    s4_obs,
    s4_pinned_feed,
    s2_primary_nft(),
    aegis_types.Barrier,
    0,
    1_000,
    2_000,
  )
  p.value == 600_000
}

test s4_fallback_settles_on_stale_primary() {
  // stale primary (expiry 1000, grace 30min) + pyth attestation ->
  // the pyth price returns. tx_lower inside the 10-min barrier budget of the
  // payload timestamp and after staleness.
  let tx = s4_fallback_tx(1_000)
  let p = settle_price(
    tx,
    s4_obs,
    s4_pinned_feed,
    s2_primary_nft(),
    aegis_types.Barrier,
    s4_pyth_ts - 86_400_000,
    s4_pyth_ts + 60_000,
    s4_pyth_ts + 120_000,
  )
  p.value == pyth_fixtures.feed2_value_1e6 && p.min_price_12h == p.value
}

test s4_fresh_primary_blocks_fallback() fail {
  // R2: primary healthy (expiry far future) -> the Pyth leg must NOT open.
  let tx = s4_fallback_tx(9_000_000_000_000)
  settle_price(
    tx,
    s4_obs,
    s4_pinned_feed,
    s2_primary_nft(),
    aegis_types.Barrier,
    s4_pyth_ts - 86_400_000,
    s4_pyth_ts + 60_000,
    s4_pyth_ts + 120_000,
  ).value > 0
}

test s4_empty_fallback_id_aborts() fail {
  // A policy sold under a mandate arming no fallback pins #"" — no Pyth leg
  // exists for it, and a stale primary strands the claim rather than opening
  // one. This is also the shape of every policy written before the pins tail.
  let tx = s4_fallback_tx(1_000)
  settle_price(
    tx,
    s4_obs,
    #"",
    s2_primary_nft(),
    aegis_types.Barrier,
    s4_pyth_ts - 86_400_000,
    s4_pyth_ts + 60_000,
    s4_pyth_ts + 120_000,
  ).value > 0
}

test s4_noncanonical_pinned_feed_aborts() fail {
  // [V8.2 G5] The pin travels in the BUYER-authored datum, so the canonical
  // check is the leg that stands between it and `attested_price`. Underwrite
  // binds the pin to the governed mandate, which is what ties the feed to this
  // policy's underlying; this is the defense-in-depth behind that binding.
  let tx = s4_fallback_tx(1_000)
  settle_price(
    tx,
    s4_obs,
    #"deadbeef",
    s2_primary_nft(),
    aegis_types.Barrier,
    s4_pyth_ts - 86_400_000,
    s4_pyth_ts + 60_000,
    s4_pyth_ts + 120_000,
  ).value > 0
}

test s4_spot_age_budget_kills_cherry_pick() fail {
  // THE 70-minute cherry-pick, at the ceiling it actually reached.
  //
  // The budget used to be judged against tx_lower, which the ledger certifies
  // only as `invalidBefore <= currentSlot` — an upper bound, so tx_lower is
  // freely back-datable down to the floor `reading_fresh` imposes
  // (`tx_lower >= observed_at`). Parked at that floor it satisfied
  // `tx_lower <= observed_at + budget` for a reading of ANY age, and the only
  // thing still bounding inclusion was `tx_upper <= valid_until` — Pyth's own
  // 70-minute window. That is a 7x overrun of the 10-minute Barrier budget
  // `max_spot_age_ms` advertises, and it is what this shape asserts is dead:
  // tx_lower AT observed_at, tx_upper at the old operative ceiling.
  let tx = s4_fallback_tx(1_000)
  settle_price(
    tx,
    s4_obs,
    s4_pinned_feed,
    s2_primary_nft(),
    aegis_types.Barrier,
    s4_pyth_ts - 86_400_000,
    s4_pyth_ts,
    s4_pyth_ts + aegis_types.pyth_ordinary_window_ms,
  ).value > 0
}

test s4_spot_age_budget_accepts_tx_upper_at_the_edge() {
  // The exact accepted instant: tx_upper == observed_at + the class budget.
  // Inclusive, so an honest claim built right on the boundary is not a
  // false-reject. tx_lower stays at observed_at — reading_fresh's floor runs
  // the OPPOSITE direction from this leg, so the two together pin the whole
  // tx window inside [observed_at, observed_at + budget].
  let tx = s4_fallback_tx(1_000)
  let p = settle_price(
    tx,
    s4_obs,
    s4_pinned_feed,
    s2_primary_nft(),
    aegis_types.Barrier,
    s4_pyth_ts - 86_400_000,
    s4_pyth_ts,
    s4_pyth_ts + aegis_types.max_spot_age_ms(aegis_types.Barrier),
  )
  p.value == pyth_fixtures.feed2_value_1e6
}

test s4_spot_age_budget_rejects_one_ms_past_the_edge() fail {
  // One millisecond past that instant, everything else identical.
  let tx = s4_fallback_tx(1_000)
  settle_price(
    tx,
    s4_obs,
    s4_pinned_feed,
    s2_primary_nft(),
    aegis_types.Barrier,
    s4_pyth_ts - 86_400_000,
    s4_pyth_ts,
    s4_pyth_ts + aegis_types.max_spot_age_ms(aegis_types.Barrier) + 1,
  ).value > 0
}

test s4_spot_age_budget_is_per_class_depeg() {
  // Depeg's budget is half Barrier's (300s), so a tx_upper that Barrier accepts
  // must be judged against the tighter number — the class argument is not
  // decorative. Accepted exactly at the Depeg edge...
  let tx = s4_fallback_tx(1_000)
  let p = settle_price(
    tx,
    s4_obs,
    s4_pinned_feed,
    s2_primary_nft(),
    aegis_types.Depeg,
    s4_pyth_ts - 86_400_000,
    s4_pyth_ts,
    s4_pyth_ts + aegis_types.max_spot_age_ms(aegis_types.Depeg),
  )
  p.value == pyth_fixtures.feed2_value_1e6
}

test s4_spot_age_budget_depeg_rejects_barrier_edge() fail {
  // ...and rejected at the Barrier edge, which is 300s beyond it.
  let tx = s4_fallback_tx(1_000)
  settle_price(
    tx,
    s4_obs,
    s4_pinned_feed,
    s2_primary_nft(),
    aegis_types.Depeg,
    s4_pyth_ts - 86_400_000,
    s4_pyth_ts,
    s4_pyth_ts + aegis_types.max_spot_age_ms(aegis_types.Barrier),
  ).value > 0
}

test s4_start_gate_kills_pre_start_reading() fail {
  // policy starts AFTER the pyth reading -> pre-start coverage forbidden.
  let tx = s4_fallback_tx(1_000)
  settle_price(
    tx,
    s4_obs,
    s4_pinned_feed,
    s2_primary_nft(),
    aegis_types.Barrier,
    s4_pyth_ts + 1,
    s4_pyth_ts + 60_000,
    s4_pyth_ts + 120_000,
  ).value > 0
}
