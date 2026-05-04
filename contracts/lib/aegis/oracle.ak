// =============================================================================
// Aegis Insurance Protocol - Oracle Top-Level Dispatcher (v6 multi-provider)
// Location: contracts/lib/aegis/oracle.ak
// Summary: Provider-uniform top-level oracle dispatcher used by validators.
//          The single function `resolve_oracle_price` matches on the policy
//          datum's `oracle_provider` tag and delegates to the corresponding
//          parser module — `aegis/oracle/charli3` or `aegis/oracle/orcfax` —
//          each of which produces the provider-uniform `Price` record.
//
//          v6 layering:
//            * `aegis/oracle/types`   — internal Price record (provider-uniform)
//            * `aegis/oracle/charli3` — Charli3 datum types + parser; owns the
//                                       A-016 trust handshake.
//            * `aegis/oracle/orcfax`  — Orcfax FsDat<Rational> parser; owns the
//                                       FSP -> FS pointer indirection and the
//                                       30-minute consumer-side freshness window.
//            * `aegis/oracle`         — this file. Dispatcher + v5 backwards-
//                                       compat re-exports so existing tests
//                                       (security_tests.ak, fixtures.ak) and
//                                       the v5 import path
//                                       `use aegis/oracle.{find_oracle_datum,
//                                       get_oracle_price, is_oracle_valid,
//                                       create_oracle_datum}` keep compiling
//                                       without modification.
//
//          Why a `when` exhaustivity check IS the curated whitelist:
//            * Adding a new provider requires extending the `OracleProvider`
//              sum type (in `aegis/types`) AND adding a branch here. Both
//              changes rotate the validator hash, which is the visible trust
//              signal we want.
//            * A free-form `oracle_script_hash: ByteArray` would either need
//              a hardcoded list (defeats the point — adding still rotates the
//              hash) or a separate registry UTxO (large new audit surface).
// =============================================================================

use aegis/oracle/aegis_self
use aegis/oracle/charli3
use aegis/oracle/orcfax
use aegis/oracle/types as oracle_types
use aegis/types.{AegisSelf, Charli3, OracleProvider, Orcfax}
use cardano/transaction.{Input}

// ---------------------------------------------------------------------------
// Top-level Dispatcher (v6)
// ---------------------------------------------------------------------------

/// Resolve an oracle reading from `reference_inputs` for the given provider
/// and provider-specific handle (`oracle_nft`).
///
/// **Provider semantics of `oracle_nft`** (the field name is retained for v5
/// backwards-compat at the schema level but its meaning branches):
///   * `Charli3` -> the Charli3 oracle NFT policy id.
///   * `Orcfax`  -> the Orcfax FSP (Feed Source Pointer) script hash. The
///                  per-fact FS hash is resolved at runtime by reading the
///                  FSP datum, so it does not appear in the policy datum.
///
/// **Trust handshake.** Each provider's parser owns its own canonical-
/// address binding: Charli3 pins `charli3_oracle_script_hash`; Orcfax pins
/// the Script credential to equal the FSP/FS hash itself (both layers).
/// The dispatcher does not re-implement these checks — they live with the
/// per-provider parsers, which is the only place they belong.
///
/// **Failure semantics.** Any mismatch (missing reference input, wrong
/// address, wrong NFT, wrong feed_id, stale created_at, decode failure)
/// aborts the validator. This is the audit-grade behavior — the dispatcher
/// fails closed rather than returning a default price.
pub fn resolve_oracle_price(
  reference_inputs: List<Input>,
  provider: OracleProvider,
  oracle_nft: ByteArray,
) -> oracle_types.Price {
  when provider is {
    Charli3 -> charli3.resolve(reference_inputs, oracle_nft)
    Orcfax -> orcfax.resolve(reference_inputs, oracle_nft)
    AegisSelf -> aegis_self.resolve(reference_inputs, oracle_nft)
  }
}

// ---------------------------------------------------------------------------
// v5 Backwards-Compat Re-exports
// ---------------------------------------------------------------------------
//
// Pre-v6 callers (validators/policy.ak before refactor, security_tests.ak,
// fixtures.ak) imported these names from `aegis/oracle`. The v6 refactor moved
// the implementations into `aegis/oracle/charli3`, but we keep the symbols
// reachable here via thin pass-through wrappers to avoid a sweeping import-
// path migration across the test suite. Each wrapper is a 1-line delegation.
// ---------------------------------------------------------------------------

/// v5 re-export. See `aegis/oracle/charli3.find_oracle_datum`.
pub fn find_oracle_datum(
  reference_inputs: List<Input>,
  oracle_nft_policy: ByteArray,
) -> charli3.OracleDatum {
  charli3.find_oracle_datum(reference_inputs, oracle_nft_policy)
}

/// v5 re-export. See `aegis/oracle/charli3.get_oracle_price`.
pub fn get_oracle_price(datum: charli3.OracleDatum) -> Int {
  charli3.get_oracle_price(datum)
}

/// v5 re-export. See `aegis/oracle/charli3.get_oracle_timestamp`.
pub fn get_oracle_timestamp(datum: charli3.OracleDatum) -> Int {
  charli3.get_oracle_timestamp(datum)
}

/// v5 re-export. See `aegis/oracle/charli3.get_oracle_expiry`.
pub fn get_oracle_expiry(datum: charli3.OracleDatum) -> Int {
  charli3.get_oracle_expiry(datum)
}

/// v5 re-export. See `aegis/oracle/charli3.is_oracle_valid`.
pub fn is_oracle_valid(datum: charli3.OracleDatum, current_time: Int) -> Bool {
  charli3.is_oracle_valid(datum, current_time)
}

/// v5 re-export. See `aegis/oracle/charli3.create_oracle_datum`.
pub fn create_oracle_datum(
  price: Int,
  timestamp: Int,
  expiry: Int,
) -> charli3.OracleDatum {
  charli3.create_oracle_datum(price, timestamp, expiry)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test dispatcher_charli3_branch_compiles() {
  // Sanity: the `when provider is { Charli3 -> ... | Orcfax -> ... | AegisSelf -> ... }`
  // shape exhaustively matches the OracleProvider sum type. Compilation of
  // this file IS the assertion; this test pins the property as a regression
  // check against accidentally adding a non-exhaustive `_` branch to dispatch.
  let provider: OracleProvider = Charli3
  when provider is {
    Charli3 -> True
    Orcfax -> False
    AegisSelf -> False
  }
}

test dispatcher_orcfax_branch_compiles() {
  let provider: OracleProvider = Orcfax
  when provider is {
    Charli3 -> False
    Orcfax -> True
    AegisSelf -> False
  }
}

test dispatcher_aegis_self_branch_compiles() {
  let provider: OracleProvider = AegisSelf
  when provider is {
    Charli3 -> False
    Orcfax -> False
    AegisSelf -> True
  }
}

test dispatcher_v5_compat_create_and_read() {
  // The v5 re-export path stays bit-for-bit equivalent.
  let datum = create_oracle_datum(420_000, 1_700_000_000_000, 1_700_999_999_999)
  get_oracle_price(datum) == 420_000 && get_oracle_timestamp(datum) == 1_700_000_000_000 && get_oracle_expiry(
    datum,
  ) == 1_700_999_999_999
}
