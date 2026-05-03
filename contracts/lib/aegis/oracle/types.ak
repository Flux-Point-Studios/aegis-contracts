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
/// computes `valid_until = created_at + orcfax_freshness_window_ms`. The
/// validator's freshness check is the provider-uniform `tx_lower <= valid_until`.
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
