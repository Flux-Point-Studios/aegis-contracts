// =============================================================================
// Aegis Insurance Protocol - Pyth Lazer Oracle Parser (Wave 1, fifth provider)
// Location: contracts/lib/aegis/oracle/pyth.ak
// Summary: Pyth Lazer on-chain oracle resolver. Pyth Lazer on Cardano uses a
//          trusted-signer Ed25519 model (NOT Wormhole VAAs). A consuming tx:
//            (a) references the shared "Pyth State" UTxO (NFT under
//                `pyth_state_nft_policy`, at the Pyth script address) as a
//                reference input, and
//            (b) performs a 0-ADA withdrawal from the Pyth withdraw script
//                whose REDEEMER carries the signed price-update payload(s).
//          The Pyth withdraw script verifies the Ed25519 signature(s); the
//          official `pyth-network/pyth-lazer-cardano` Aiken lib exposes
//          `pyth.get_updates(pyth_id, self)` which reads the verified updates.
//
//          ─────────────────────────────────────────────────────────────────
//          CRITICAL FOOTGUN (the whole point of Wave 1):
//          The Pyth withdraw script does NOT enforce freshness and does NOT
//          prevent replay. Per the official docs: "It does not enforce
//          freshness of the update, nor does it disallow verifying the same
//          update multiple times." A still-validly-signed OLD update can be
//          re-presented (replay). AEGIS MUST enforce both, which we do here:
//
//            * Freshness + replay binding: `update.timestamp_us` (microseconds)
//              is converted to POSIX ms and surfaced as `Price.observed_at`;
//              `Price.valid_until = observed_at + pyth_ordinary_window_ms`.
//              The downstream policy.ak gate is, for every oracle-reading
//              branch (Claim, Cancel-as-Claim):
//
//                tx_lower >= price.observed_at &&
//                tx_lower <= price.valid_until &&
//                tx_upper <= price.valid_until
//
//              This rejects a stale update (tx_lower > valid_until) AND a
//              future-dated one (tx_lower < observed_at), and BINDS the price
//              to THIS tx's validity range. A replayed old update fails
//              `tx_upper <= valid_until` because the node-enforced validity
//              range of any real tx advances past the old update's window.
//
//          ─────────────────────────────────────────────────────────────────
//          Trust handshake (mirrors the 3-layer style of indigo.ak):
//            1. `pyth_state_nft_policy` is pinned per-network (mainnet
//               c935c937…, preprod placeholder). `get_updates` only accepts a
//               state UTxO carrying a "Pyth State" token under THIS policy
//               (`assets.has_nft_strict`), at a Script address. A forged state
//               UTxO under an attacker policy is rejected inside the lib.
//            2. The signed updates come from the Pyth withdraw script
//               redeemer; the lib resolves the current withdraw script hash
//               from the state datum and reads its redeemer. The Ed25519
//               signature is verified by the Pyth withdraw script itself
//               (which must be a withdrawal in the same tx).
//            3. We pin the target `feed_id` (the Pyth Lazer feed identifier,
//               carried in `PolicyDatum.oracle_nft` as a big-endian byte
//               array) and require an exact match — a wrong-feed update (e.g.
//               SOL/USD when the policy insures iBTC) is rejected.
//
// References:
//   * Lib: github.com/pyth-network/pyth-lazer-cardano (lib/pyth.ak)
//   * Docs: docs.pyth.network/price-feeds/pro/integrate-as-consumer/cardano
//   * Pyth State NFT policy (mainnet): types/mainnet.ak::pyth_state_nft_policy
// =============================================================================

use aegis/oracle/types.{Price}
use aegis/test_helpers/pyth_fixtures
use aegis/types as aegis_types
use aiken/collection/list
use aiken/primitive/bytearray
use cardano/address.{Script}
use cardano/transaction.{Transaction, Withdraw}
use pyth
use types/u32
use types/u64

// ---------------------------------------------------------------------------
// Feed-id handle decoding
// ---------------------------------------------------------------------------

/// Decode the Pyth Lazer `feed_id` from the per-provider handle carried in
/// `PolicyDatum.oracle_nft`. For Pyth the handle is NOT an NFT policy — it is
/// the feed-id encoded big-endian (e.g. ADA/USD = feed 16 -> #"10"). We
/// reuse the existing `oracle_nft: ByteArray` schema field so the PolicyDatum
/// shape does not change (no extra CBOR field), mirroring how Orcfax overloads
/// the same field to mean "FSP script hash".
pub fn decode_feed_id(handle: ByteArray) -> Int {
  bytearray.to_int_big_endian(handle)
}

// ---------------------------------------------------------------------------
// Decimal renormalisation (Pyth native exponent -> Aegis 1e6 fixed point)
// ---------------------------------------------------------------------------

/// 10^n for n >= 0. Aiken has no built-in integer pow over Int here, so we
/// fold. n is tiny (|exponent| <= ~18 for any real Pyth feed), so this is
/// cheap and total.
pub fn pow10(n: Int) -> Int {
  if n <= 0 {
    1
  } else {
    10 * pow10(n - 1)
  }
}

/// Renormalise a Pyth price quoted at `exponent` (Pyth's convention is
/// `real_value = price * 10^exponent`, exponent typically NEGATIVE, e.g. -8)
/// into Aegis's fixed 1e6 scale (price_scale = 1e6 = 10^6).
///
///   value_1e6 = price * 10^(exponent + 6)
///
/// Let net = exponent + pyth_price_scale_exp.
///   * net >= 0 : multiply by 10^net (exact).
///   * net <  0 : divide by 10^(-net), FLOOR-rounded (matches the Orcfax
///                num/denom floor convention in oracle/orcfax.ak; floor is
///                conservative — it never inflates a price upward, so it can
///                never push an OTM position falsely into-the-money on the
///                attacker's behalf).
pub fn rescale_to_1e6(price: Int, exponent: Int) -> Int {
  let net = exponent + aegis_types.pyth_price_scale_exp
  if net >= 0 {
    price * pow10(net)
  } else {
    price / pow10(-net)
  }
}

// ---------------------------------------------------------------------------
// [#381 V8.1 S1] Confidence gate
// ---------------------------------------------------------------------------

/// Reject a reading whose reported confidence interval is too wide to settle
/// money against: confidence/price > pyth_max_confidence_bps. Cross-multiplied
/// integer form; a negative confidence is nonsense and rejects. An ABSENT
/// confidence follows pyth_reject_absent_confidence (OQ3 — False until the
/// verified Lazer subscription is confirmed to always deliver it).
pub fn confidence_ok(price: Int, confidence: Option<Option<Int>>) -> Bool {
  when confidence is {
    Some(Some(c)) -> c >= 0 && c * 10_000 <= price * aegis_types.pyth_max_confidence_bps
    _ -> !aegis_types.pyth_reject_absent_confidence
  }
}

// ---------------------------------------------------------------------------
// Feed extraction
// ---------------------------------------------------------------------------

/// Pull the verified, unwrapped (value, exponent, timestamp_us) for the
/// target `feed_id` out of the set of Pyth updates in this tx.
///
/// Aborts (fail-closed) if:
///   * no Pyth update is present (get_updates yields []),
///   * the target feed-id is absent from every update,
///   * the feed carries no price (`price: Option<Option<Int>>` is None/Some(None)),
///   * the feed carries no exponent.
///
/// We scan ALL updates (Pyth may batch several PriceUpdate messages) and take
/// the NEWEST reading of the target feed (max parent `update.timestamp_us`,
/// the freshness anchor). The claimant orders the redeemer list, so a
/// first-match rule would let them pick any signed reading in the batch by
/// position alone — low to trip a Barrier at Claim, high to prove OTM at
/// Cancel. Newest-wins removes that ORDERING choice and nothing else: it is
/// not an age bound, and it does not stop a claimant submitting an all-old
/// batch. Bounding the reading's age is the CALLER's job and lives outside
/// this module — `fallback.settle_price` does it with
/// `tx_upper <= observed_at + max_spot_age_ms(risk_class)`. Any new consumer
/// of this function must carry an equivalent bound; the returned timestamp is
/// exact but unjudged.
pub fn find_feed_reading(
  self: Transaction,
  feed_id: Int,
) -> (Int, Int, Int, Bool) {
  let updates = pyth.get_updates(aegis_types.pyth_state_nft_policy, self)
  let readings =
    list.filter_map(
      updates,
      fn(update) {
        when
          list.find(
            update.feeds,
            fn(feed) { u32.as_int(feed.feed_id) == feed_id },
          )
        is {
          Some(feed) ->
            when (feed.price, feed.exponent) is {
              // price is Option<Option<Int>>: Some(Some(p)) is a real quote.
              // Some(None)/None means "no value this round" — skip.
              (Some(Some(p)), Some(exp)) -> {
                // [#381 V8.1 S1] A matched feed whose confidence is too wide
                // aborts LOUDLY — including when a laxer reading rides along
                // with a tighter one; nothing wide may enter the batch.
                expect confidence_ok(p, feed.confidence)
                // [#403 FIX 4] PRESENCE travels with the reading. The
                // magnitude was just judged above; whether the payload
                // carried one at all is a fact only the sale-side pull leg
                // may demand, per mandate.
                let has_conf =
                  when feed.confidence is {
                    Some(Some(_)) -> True
                    _ -> False
                  }
                Some(
                  (
                    rescale_to_1e6(p, exp),
                    u64.as_int(update.timestamp_us),
                    has_conf,
                  ),
                )
              }
              _ -> None
            }
          None -> None
        }
      },
    )
  when newest_reading(readings) is {
    Some((value_1e6, observed_at_us, has_conf)) ->
      (value_1e6, observed_at_us, feed_id, has_conf)
    None -> fail @"Pyth: target feed-id not found with a populated price"
  }
}

/// Max-by-timestamp over (value, observed_at_us) readings; ties keep the
/// earlier list entry (genuine same-instant readings are identical anyway).
pub fn newest_reading(readings: List<(Int, Int, Bool)>) -> Option<(Int, Int, Bool)> {
  list.reduce(
    readings,
    None,
    fn(acc, r) {
      when acc is {
        None -> Some(r)
        Some((_, best_ts, _)) ->
          if r.2nd > best_ts {
            Some(r)
          } else {
            acc
          }
      }
    },
  )
}

test s4h_newest_reading_picks_max_timestamp() {
  and {
    newest_reading([(100, 5, False), (90, 9, True), (95, 7, False)]) == Some(
      (90, 9, True),
    ),
    newest_reading([(90, 9, True), (100, 5, False)]) == Some((90, 9, True)),
    newest_reading([(42, 1, False)]) == Some((42, 1, False)),
    newest_reading([]) == None,
    // tie keeps the first entry
    newest_reading([(1, 5, False), (2, 5, True)]) == Some((1, 5, False)),
  }
}

test s4h_duplicated_update_batch_resolves_identically() {
  // The real signed payload presented TWICE in one redeemer — the multi-
  // update fold path over genuinely signed data must resolve to the same
  // reading as the single-update tx.
  let raw_updates: Data =
    [pyth_fixtures.pyth_test_update, pyth_fixtures.pyth_test_update]
  let base = pyth_fixtures.pyth_tx()
  let tx =
    Transaction {
      ..base,
      redeemers: [
        Pair(
          Withdraw(Script(pyth_fixtures.pyth_test_withdraw_hash)),
          raw_updates,
        ),
      ],
    }
  let p = resolve(tx, #"02")
  p.value == pyth_fixtures.feed2_value_1e6 && p.observed_at == pyth_fixtures.feed_observed_at_ms
}

// ---------------------------------------------------------------------------
// Provider-uniform Resolver (Wave 1 entrypoint)
// ---------------------------------------------------------------------------

/// Resolve a Pyth Lazer oracle reading for the feed-id encoded in `handle`
/// and emit the provider-uniform `Price` record.
///
/// **Trust handshake.** `get_updates` pins the Pyth State NFT policy
/// (`pyth_state_nft_policy`, per-network) and requires the state UTxO at a
/// Script address; the Ed25519 signature is verified by the Pyth withdraw
/// script (a withdrawal that must be present in this same tx). We additionally
/// pin the exact `feed_id`.
///
/// **Scaling.** Pyth feeds carry their own `exponent`; we renormalise to the
/// protocol-wide 1e6 scale via `rescale_to_1e6` (floor on the divide leg).
///
/// **Freshness + replay (THE Wave-1 deliverable).** Pyth's withdraw script
/// enforces NEITHER. We derive:
///   observed_at = timestamp_us / 1000          (microseconds -> POSIX ms)
///   valid_until = observed_at + pyth_ordinary_window_ms
/// and rely on policy.ak's existing 3-leg gate
/// (`tx_lower >= observed_at && tx_lower <= valid_until && tx_upper <=
/// valid_until`) to reject stale/future/replayed updates and bind the price
/// to this tx. observed_at is EXACT (read from the signed payload), so unlike
/// Indigo there is no approximation in the freshness anchor.
pub fn resolve(self: Transaction, handle: ByteArray) -> Price {
  let feed_id = decode_feed_id(handle)
  let (value_1e6, observed_at_us, _matched_feed, confidence_present) =
    find_feed_reading(self, feed_id)
  // Pyth timestamps are MICROSECONDS; the Aegis/Cardano validity range and
  // every other provider's Price are POSIX MILLISECONDS. Convert once here.
  let observed_at_ms = observed_at_us / 1_000
  Price {
    value: value_1e6,
    observed_at: observed_at_ms,
    valid_until: observed_at_ms + aegis_types.pyth_ordinary_window_ms,
    // Pyth Lazer is a spot-at-claim provider with no trailing-12h-low feed.
    // SECURITY: default `min_price_12h` to `value` (NEVER 0 — a 0 default makes
    // the Claim `min_price_12h <= strike` leg pass for every policy and drains
    // the pool). With this spot-only fallback the 12h-grace leg collapses to
    // pure spot-at-claim, matching the Indigo/Orcfax non-AegisSelf parsers.
    // [#391 R2 F1] `0` is the NO-PROVENANCE sentinel, not a price. This
    // provider publishes no trailing low at all, so it cannot say WHEN one
    // fell — and `low_observed_at = observed_at` was a claim it could not
    // support. With `min_price_12h == value` the retro disjunct was already
    // subsumed by `spot <= strike`, so nothing about what PAYS changes; what
    // changes is that `vault.pre_start_breach` no longer reads a collapsed
    // spot pair as a trailing low that pre-dates the policy, which would
    // have vetoed an honest spot-at-claim settlement whenever the reading
    // was published before coverage began.
    min_price_12h: value_1e6,
    low_observed_at: 0,
    confidence_present,
  }
}

// ===========================================================================
// Tests
//
// Fixtures mirror the lib's data shapes (PriceUpdate / Feed with U32/U64
// opaque wrappers). We build them directly and exercise the pure helpers
// (decode_feed_id, pow10, rescale_to_1e6) plus the Price-derivation math.
// The full `find_feed_reading` path that calls `pyth.get_updates` requires a
// constructed Transaction with a Pyth State reference input + withdraw
// redeemer; those whole-tx fixtures are exercised via the validator-level
// security_tests harness (Wave 1 covers the provider math + freshness/replay
// logic here). See report for the Transaction-level test note.
// ===========================================================================

// --- feed-id handle decode -------------------------------------------------

test pyth_decode_feed_id_ada_usd_is_16() {
  // ADA/USD = Pyth Lazer feed 16 -> big-endian #"10".
  decode_feed_id(#"10") == 16
}

test pyth_decode_feed_id_multibyte() {
  // A 2-byte feed-id round-trips big-endian: 0x0120 = 288.
  decode_feed_id(#"0120") == 288
}

test pyth_decode_feed_id_zero_for_empty() {
  decode_feed_id(#"") == 0
}

// --- pow10 -----------------------------------------------------------------

test pyth_pow10_base_cases() {
  pow10(0) == 1 && pow10(1) == 10 && pow10(6) == 1_000_000
}

test pyth_pow10_negative_clamps_to_one() {
  pow10(-3) == 1
}

// --- rescale_to_1e6 --------------------------------------------------------

test pyth_rescale_exp_minus_8_divides_by_100() {
  // Pyth ADA/USD at exponent -8: price 38_500_000 (=0.385 real). net =
  // -8 + 6 = -2 -> divide by 100 -> 385_000 in 1e6 scale (0.385 * 1e6). ✓
  rescale_to_1e6(38_500_000, -8) == 385_000
}

test pyth_rescale_exp_minus_6_is_identity() {
  // exponent -6 => net 0 => value unchanged (already 1e6 scale).
  rescale_to_1e6(385_000, -6) == 385_000
}

test pyth_rescale_exp_minus_4_multiplies_by_100() {
  // exponent -4 => net +2 => multiply by 100. 3_850 * 100 = 385_000.
  rescale_to_1e6(3_850, -4) == 385_000
}

test pyth_rescale_floor_rounds_down() {
  // Floor on the divide leg: 38_500_001 at exp -8 -> /100 -> 385_000 (floor,
  // not 385_000.01). Confirms we never round UP (conservative; can't push
  // an OTM position falsely ITM).
  rescale_to_1e6(38_500_001, -8) == 385_000
}

test pyth_rescale_btc_like_large_value() {
  // iBTC-style: 65_000.123456 at exp -8 = price 6_500_012_345_600. net -2 ->
  // /100 -> 65_000_123_456 in 1e6 scale. ✓ (65000.123456 * 1e6).
  rescale_to_1e6(6_500_012_345_600, -8) == 65_000_123_456
}

// --- freshness derivation (the Wave-1 deliverable) -------------------------
//
// These assert the Price record we hand the validator carries an observed_at
// in POSIX ms (converted from microseconds) and a valid_until exactly one
// freshness window later — the values policy.ak's 3-leg gate consumes.

test pyth_freshness_observed_at_converts_us_to_ms() {
  // timestamp_us = 1_700_000_000_000_000 µs == 1_700_000_000_000 ms.
  let observed_at_us = 1_700_000_000_000_000
  let observed_at_ms = observed_at_us / 1_000
  observed_at_ms == 1_700_000_000_000
}

test pyth_freshness_valid_until_is_window_after_observed() {
  let observed_at_ms = 1_700_000_000_000
  let valid_until = observed_at_ms + aegis_types.pyth_ordinary_window_ms
  valid_until == 1_700_000_000_000 + 15 * 60 * 1_000 && aegis_types.pyth_ordinary_window_ms == 900_000
}

// POSITIVE: a fresh update yields a Price whose window admits a same-slot tx.
test pyth_positive_fresh_update_passes_3leg_gate() {
  // Simulate the Price the resolver would emit for a fresh ADA/USD reading,
  // then run policy.ak's exact freshness predicate against a tx whose lower
  // bound equals observed_at (same instant) and upper bound 30s later.
  let observed_at_ms = 1_700_000_000_000
  let valid_until = observed_at_ms + aegis_types.pyth_ordinary_window_ms
  let price =
    Price {
      value: 385_000,
      observed_at: observed_at_ms,
      valid_until,
      min_price_12h: 385_000,
      low_observed_at: observed_at_ms,
      confidence_present: False,
    }
  let tx_lower = observed_at_ms
  let tx_upper = observed_at_ms + 30_000
  let oracle_fresh =
    tx_lower >= price.observed_at && tx_lower <= price.valid_until && tx_upper <= price.valid_until
  oracle_fresh
}

// NEGATIVE: a STALE update (published > window ago) is rejected. This is the
// anti-replay leg — an attacker re-presenting an old, still-validly-signed
// update produces a Price whose valid_until is in the past relative to the
// tx's validity range.
test pyth_negative_stale_update_rejected_by_gate() {
  let observed_at_ms = 1_700_000_000_000
  let valid_until = observed_at_ms + aegis_types.pyth_ordinary_window_ms
  let price =
    Price {
      value: 385_000,
      observed_at: observed_at_ms,
      valid_until,
      min_price_12h: 385_000,
      low_observed_at: observed_at_ms,
      confidence_present: False,
    }
  // tx happens 71 minutes after the update was observed -> past valid_until.
  let tx_lower = observed_at_ms + 71 * 60 * 1_000
  let tx_upper = tx_lower + 30_000
  let oracle_fresh =
    tx_lower >= price.observed_at && tx_lower <= price.valid_until && tx_upper <= price.valid_until
  oracle_fresh == False
}

// NEGATIVE: a REPLAYED update at the exact window boundary + 1ms is rejected
// (boundary tightness — no off-by-one slack lets a just-expired update slip).
test pyth_negative_replay_at_window_boundary_rejected() {
  let observed_at_ms = 1_700_000_000_000
  let valid_until = observed_at_ms + aegis_types.pyth_ordinary_window_ms
  let price =
    Price {
      value: 385_000,
      observed_at: observed_at_ms,
      valid_until,
      min_price_12h: 385_000,
      low_observed_at: observed_at_ms,
      confidence_present: False,
    }
  // tx_upper exactly 1ms past valid_until -> upper-bound leg fails.
  let tx_lower = observed_at_ms + 10_000
  let tx_upper = valid_until + 1
  let oracle_fresh =
    tx_lower >= price.observed_at && tx_lower <= price.valid_until && tx_upper <= price.valid_until
  oracle_fresh == False
}

// NEGATIVE: a FUTURE-DATED update (tx_lower before observed_at) is rejected.
// Defends against a tx that tries to use an update timestamped after its own
// validity window (e.g. to dodge the upper-bound staleness check by claiming
// an artificially-future observation).
test pyth_negative_future_dated_update_rejected() {
  let observed_at_ms = 1_700_000_000_000
  let valid_until = observed_at_ms + aegis_types.pyth_ordinary_window_ms
  let price =
    Price {
      value: 385_000,
      observed_at: observed_at_ms,
      valid_until,
      min_price_12h: 385_000,
      low_observed_at: observed_at_ms,
      confidence_present: False,
    }
  // tx_lower 5 minutes BEFORE the update's observed_at.
  let tx_lower = observed_at_ms - 5 * 60 * 1_000
  let tx_upper = observed_at_ms + 30_000
  let oracle_fresh =
    tx_lower >= price.observed_at && tx_lower <= price.valid_until && tx_upper <= price.valid_until
  oracle_fresh == False
}

// --- feed-id mismatch (fixture-level, exercising find logic in isolation) ---
//
// We can exercise the feed-matching predicate (`u32.as_int(feed.feed_id) ==
// feed_id`) against constructed Feed fixtures without a whole Transaction.

test pyth_feed_id_match_predicate_positive() {
  let feed =
    pyth.Feed {
      feed_id: u32.from_int(16),
      price: Some(Some(38_500_000)),
      best_bid_price: None,
      best_ask_price: None,
      publisher_count: None,
      exponent: Some(-8),
      confidence: None,
      funding_rate: None,
      funding_timestamp: None,
      funding_rate_interval: None,
      market_session: None,
      ema_price: None,
      ema_confidence: None,
      feed_update_timestamp: None,
    }
  u32.as_int(feed.feed_id) == 16
}

// NEGATIVE: a wrong feed-id does not match the target. The resolver's
// list.find over feeds returns None for this feed, and (if it were the only
// feed) find_feed_reading would fail-closed.
test pyth_negative_wrong_feed_id_does_not_match() {
  let feed =
    pyth.Feed {
      feed_id: u32.from_int(2),
      // SOL/USD-style reading present, but target is feed 16 (ADA/USD).
      price: Some(Some(150_000_000_000)),
      best_bid_price: None,
      best_ask_price: None,
      publisher_count: None,
      exponent: Some(-8),
      confidence: None,
      funding_rate: None,
      funding_timestamp: None,
      funding_rate_interval: None,
      market_session: None,
      ema_price: None,
      ema_confidence: None,
      feed_update_timestamp: None,
    }
  let target_feed_id = 16
  ( u32.as_int(feed.feed_id) == target_feed_id ) == False
}

// NEGATIVE: a feed present for the target id but with NO price (Some(None))
// must not be treated as a quote. Mirrors the `(Some(Some(p)), _)` guard in
// find_feed_reading.
test pyth_negative_feed_with_no_price_is_skipped() {
  let feed =
    pyth.Feed {
      feed_id: u32.from_int(16),
      price: Some(None),
      best_bid_price: None,
      best_ask_price: None,
      publisher_count: None,
      exponent: Some(-8),
      confidence: None,
      funding_rate: None,
      funding_timestamp: None,
      funding_rate_interval: None,
      market_session: None,
      ema_price: None,
      ema_confidence: None,
      feed_update_timestamp: None,
    }
  let has_real_price =
    when feed.price is {
      Some(Some(_)) -> True
      _ -> False
    }
  has_real_price == False
}

// POSITIVE end-to-end math: a populated feed at exp -8 rescales correctly and
// the unwrap path yields the expected 1e6 value.
test pyth_positive_populated_feed_yields_correct_1e6_value() {
  let feed =
    pyth.Feed {
      feed_id: u32.from_int(16),
      price: Some(Some(38_500_000)),
      best_bid_price: None,
      best_ask_price: None,
      publisher_count: None,
      exponent: Some(-8),
      confidence: None,
      funding_rate: None,
      funding_timestamp: None,
      funding_rate_interval: None,
      market_session: None,
      ema_price: None,
      ema_confidence: None,
      feed_update_timestamp: None,
    }
  expect Some(Some(p)) = feed.price
  expect Some(exp) = feed.exponent
  rescale_to_1e6(p, exp) == 385_000
}

// ---------------------------------------------------------------------------
// [#381 V8.1 S0] Whole-Transaction substrate proof. The resolve path above was
// previously exercised only at the unit level; these drive the REAL chain:
// resolve -> find_feed_reading -> pyth.get_updates over a constructed tx with
// the State NFT reference input + a genuine signed Lazer message (fixtures in
// aegis/test_helpers/pyth_fixtures). One green per documented feed + the
// fail-closed negatives a claim tx could plausibly present.
// ---------------------------------------------------------------------------

test s0_resolve_extracts_feed2_end_to_end() {
  let price = resolve(pyth_fixtures.pyth_tx(), #"02")
  and {
    price.value == pyth_fixtures.feed2_value_1e6,
    price.observed_at == pyth_fixtures.feed_observed_at_ms,
    price.valid_until == pyth_fixtures.feed_observed_at_ms + aegis_types.pyth_ordinary_window_ms,
    // spot-only provider: the 12h-low leg collapses to spot-at-claim, and
    // [#391 R2 F1] the observation timestamp is the NO-PROVENANCE sentinel —
    // Pyth has no trailing low, so it cannot say when one fell, and the old
    // `low_observed_at == observed_at` collapse read as a trailing low that
    // pre-dated any policy whose start_time was after the reading.
    price.min_price_12h == price.value,
    price.low_observed_at == 0,
  }
}

test s0_resolve_extracts_feed112_end_to_end() {
  let price = resolve(pyth_fixtures.pyth_tx(), #"70")
  price.value == pyth_fixtures.feed112_value_1e6 && price.observed_at == pyth_fixtures.feed_observed_at_ms
}

test s0_resolve_unknown_feed_fails() fail {
  // feed 99 is absent from the update -> find_feed_reading aborts
  // the result must be load-bearing or the compiler elides the call
  resolve(pyth_fixtures.pyth_tx(), #"63").value > 0
}

test s0_resolve_without_state_ref_input_fails() fail {
  // the result must be load-bearing or the compiler elides the call
  resolve(pyth_fixtures.pyth_tx_no_state(), #"02").value > 0
}

test s0_resolve_wrong_withdraw_script_fails() fail {
  // redeemer parked under a script the State datum does not name
  // the result must be load-bearing or the compiler elides the call
  resolve(pyth_fixtures.pyth_tx_wrong_withdraw(), #"02").value > 0
}

test s1_confidence_rejects_wide_interval() {
  // 2% confidence on a 1e6 price vs the 1% ceiling
  !confidence_ok(1_000_000, Some(Some(20_000)))
}

test s1_confidence_accepts_tight_interval() {
  confidence_ok(1_000_000, Some(Some(9_999)))
}

test s1_confidence_rejects_negative() {
  !confidence_ok(1_000_000, Some(Some(-1)))
}

test s1_confidence_absent_follows_oq3_flag() {
  confidence_ok(1_000_000, None) == !aegis_types.pyth_reject_absent_confidence && confidence_ok(
    1_000_000,
    Some(None),
  ) == !aegis_types.pyth_reject_absent_confidence
}
