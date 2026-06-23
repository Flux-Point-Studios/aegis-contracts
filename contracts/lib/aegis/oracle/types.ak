// =============================================================================
// Aegis Insurance Protocol - Oracle Internal Types (v6 multi-provider)
// Location: contracts/lib/aegis/oracle/types.ak
// Summary: Provider-uniform price record produced by every oracle parser.
//          Each provider's parser (`aegis/oracle/charli3`,
//          `aegis/oracle/orcfax`, ...) consumes provider-specific reference
//          inputs and emits this single shape. Validator branches consume
//          ONLY this shape — they never see provider-specific datum quirks.
//
//          This decoupling is the core of the v6 multi-oracle design: it
//          contains parser bugs to a single module, and means adding a new
//          provider only requires (a) a new parser module, (b) a new
//          `OracleProvider` variant in `aegis/types`, and (c) one new branch
//          in the dispatcher in `aegis/oracle`. Validator code does NOT
//          change shape.
// =============================================================================

// ---------------------------------------------------------------------------
// Provider-uniform Price Record
// ---------------------------------------------------------------------------

/// Internal price record. Every provider's parser produces this shape.
///
/// **Scaling.** `value` is scaled by 1e6 (matches Aegis's protocol-wide
/// `price_scale = 1_000_000`). Charli3's datum already encodes price at this
/// scale; Orcfax's datum encodes price as a `Rational { num, denom }` and the
/// Orcfax parser converts via `num * 1_000_000 / denom` (floor-rounded —
/// see comment in `aegis/oracle/orcfax`).
///
/// **Freshness.** `valid_until` is the POSIX millisecond beyond which the
/// reading is stale. For Charli3 this is the publisher-set `expiry` field of
/// the oracle datum. For Orcfax (which has no on-chain expiry) the parser
/// computes `valid_until = created_at + orcfax_freshness_window_ms` (70 min
/// in v7, widened from 30 min in v6 based on empirical mainnet observation).
/// The validator's freshness check pins BOTH legs of the validity range:
/// `tx_lower <= valid_until && tx_upper <= valid_until` (added in v6.0.1
/// after independent review flagged the upper-bound bypass).
///
/// **Why a struct and not a tuple.** Field names self-document the parser's
/// contract; tuples would force every consumer to remember the position
/// convention.
pub type Price {
  /// Price scaled by 1e6. The validator compares this directly against
  /// `policy_datum.strike_price`, which uses the same 1e6 scale.
  value: Int,
  /// POSIX milliseconds when this reading was published / committed by the
  /// upstream provider. Aegis does not currently use this for any branch
  /// logic — it is exposed for diagnostic purposes and so future audit
  /// findings (e.g., a "no time travel" check that requires `created_at <=
  /// tx_upper`) can be added without changing the parser surface.
  observed_at: Int,
  /// POSIX milliseconds beyond which the reading is stale. Validator's
  /// freshness check: `tx_lower <= valid_until`.
  valid_until: Int,
  /// Trailing-12h LOW price, scaled by 1e6. Lets a barrier policy stay
  /// claimable for ~12h after spot touches the strike, even if spot
  /// recovers. Only AegisSelf populates a real value (publisher datum key
  /// 3); every other provider's parser sets this EQUAL TO `value` (a
  /// spot-only fallback), so the Claim branch's `min_price_12h <= strike`
  /// leg can never spuriously pass for them.
  ///
  /// SECURITY: parsers MUST default this to `value` (or a high sentinel)
  /// whenever no real 12h-low is available — NEVER 0. A 0 default would
  /// make `min_price_12h <= strike` true for every policy and drain the
  /// pool. The AegisSelf accessor defaults a missing key 3 to key 0
  /// (the spot price) for exactly this reason.
  min_price_12h: Int,
  /// POSIX milliseconds when the `min_price_12h` low was observed (publisher
  /// datum key 4). The Claim branch requires `low_observed_at >= start_time`
  /// so the 12h-grace leg only honours a barrier touch that happened DURING
  /// the policy's life (closes SEC F-1: a policy bought after a dip claiming
  /// on that pre-purchase dip). Parsers default this to the reading's
  /// `observed_at` (key 1) when key 4 is absent; with the
  /// `min_price_12h == value` spot fallback that collapses the 12h leg to
  /// spot-at-claim for non-AegisSelf providers and legacy datums.
  low_observed_at: Int,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test price_record_construction() {
  let p =
    Price {
      value: 350_000,
      observed_at: 1_700_000_000_000,
      valid_until: 1_700_001_800_000,
      min_price_12h: 350_000,
      low_observed_at: 1_700_000_000_000,
    }
  p.value == 350_000 && p.valid_until == 1_700_001_800_000
}

test price_freshness_window_within_bounds() {
  // Sanity: a Price with `valid_until = observed_at + 30 min` matches the
  // Orcfax-derived freshness pattern. The validator's tx_lower must satisfy
  // `tx_lower <= valid_until` — if tx_lower equals observed_at + 15 min, the
  // reading is fresh.
  let observed_at = 1_700_000_000_000
  let valid_until = observed_at + 30 * 60 * 1_000
  let tx_lower = observed_at + 15 * 60 * 1_000
  tx_lower <= valid_until
}

test price_stale_reading_fails_freshness() {
  let observed_at = 1_700_000_000_000
  let valid_until = observed_at + 30 * 60 * 1_000
  // tx_lower 31 minutes after observed_at → past valid_until.
  let tx_lower = observed_at + 31 * 60 * 1_000
  tx_lower <= valid_until == False
}
