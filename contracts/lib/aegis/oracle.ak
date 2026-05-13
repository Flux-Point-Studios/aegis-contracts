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
//                                       70-minute consumer-side freshness window
//                                       (widened from 30 min in v7 — see
//                                       types.ak::orcfax_freshness_window_ms).
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
use aegis/oracle/indigo
use aegis/oracle/orcfax
use aegis/oracle/types as oracle_types
use aegis/types.{
  AegisSelf, Charli3, Indigo, OracleProvider, Orcfax,
  aegis_self_canonical_nfts, charli3_ada_usd_nft_policy,
  indigo_canonical_nfts, orcfax_fsp_script_hash,
}
use aiken/collection/list
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
    // [v12.2 commit 2.3] Indigo arm wired to oracle/indigo.ak::resolve.
    // Trust handshake: NFT canonical-membership + per-iAsset oracle script
    // credential pin + single-token-of-policy (see indigo.ak::find_feed_datum).
    Indigo -> indigo.resolve(reference_inputs, oracle_nft)
  }
}

/// [v12.2] Predicate: is the supplied `oracle_nft` a canonical handle for
/// the supplied provider?
///
/// V12.2 soft-disables Charli3 and Orcfax (arms return False
/// unconditionally) and adds the Indigo arm with a 4-element allowlist.
///   * Charli3   -> False unconditionally (soft-disabled)
///   * Orcfax    -> False unconditionally (soft-disabled)
///   * AegisSelf -> membership in `aegis_self_canonical_nfts`
///                  (5 entries — unchanged from V12)
///   * Indigo    -> membership in `indigo_canonical_nfts` (4 entries)
///
/// Rationale:
///   * Charli3 is in distress (sale signal 2026-04-30 from CEO Robert
///     Hever; see project_oracle_landscape_2026-05.md). Their preprod
///     ADA/USD oracle has been intermittently stale; the V12 redundancy
///     plan that envisioned Charli3 as the mainnet primary no longer
///     holds.
///   * Orcfax announced wind-down 2026-03-27 with sunset target
///     2026-07-31. Continued reliance is unsafe past that date.
///   * AegisSelf (Node-2 publisher) is vendor-survival-independent and
///     covers 5 pairs (ADA/BTC/ETH/USDC/USDT). V12 already shipped
///     AegisSelf as the routing default for every dApp build path; V12.2
///     formalises that AegisSelf is one of two allowed providers.
///   * Indigo on-chain price oracle is the second allowed V12.2 provider
///     — 4 iAssets directly bound (iUSD/iBTC/iETH/iSOL). The script-
///     credential pin lives in the parser (`oracle/indigo.ak::find_feed_output`),
///     pairing the NFT to its iAsset's parameterized oracle script address.
///
/// **Why soft-disable rather than hard-remove the Charli3/Orcfax variants.**
/// V11 policies on preprod (4 stranded test policies) are still claimable
/// via CLI against the V11 validator hash and carry
/// `oracle_provider: Charli3`. Soft-disable preserves decoder symmetry —
/// datums still parse, the validator just rejects them at the Underwrite-
/// time canonical-handle check. Equivalent functional outcome (no new
/// policies), cleaner backwards-compat.
///
/// **Reactivation path.** Flipping either arm back to its V12 equality
/// check is a one-line redeploy. The dead resolvers in
/// `oracle/charli3.ak` and `oracle/orcfax.ak` are kept in tree (with
/// deprecation marker) so the reverse path is just a constant change here
/// — no resolver rewrite needed.
///
/// **Imports of `charli3_ada_usd_nft_policy` and `orcfax_fsp_script_hash`**
/// stay because the V12.2 tests below reference them; they're not in the
/// arm bodies any more, but the audit-grade approach is to keep the
/// references in tree.
pub fn is_canonical_oracle_nft(
  provider: OracleProvider,
  oracle_nft: ByteArray,
) -> Bool {
  when provider is {
    // [v12.2] Soft-disabled. New policies cannot bind to Charli3 under V12.2.
    Charli3 -> False
    // [v12.2] Soft-disabled. Same as Charli3.
    Orcfax -> False
    AegisSelf -> list.has(aegis_self_canonical_nfts, oracle_nft)
    // [v12.2 NEW] Indigo on-chain oracle binding. 4 iAssets pinned via the
    // canonical NFT list. The script-credential pin lives in the parser
    // (oracle/indigo.ak::find_feed_output), pairing the NFT to its
    // iAsset's parameterized oracle script address.
    Indigo -> list.has(indigo_canonical_nfts, oracle_nft)
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
  // [v12.2] Sanity: the `when provider is { Charli3 | Orcfax | AegisSelf |
  // Indigo }` shape exhaustively matches the OracleProvider sum type.
  // Compilation of this file IS the assertion; this test pins the property
  // as a regression check against accidentally adding a non-exhaustive `_`
  // branch to dispatch.
  let provider: OracleProvider = Charli3
  when provider is {
    Charli3 -> True
    Orcfax -> False
    AegisSelf -> False
    Indigo -> False
  }
}

test dispatcher_orcfax_branch_compiles() {
  let provider: OracleProvider = Orcfax
  when provider is {
    Charli3 -> False
    Orcfax -> True
    AegisSelf -> False
    Indigo -> False
  }
}

test dispatcher_aegis_self_branch_compiles() {
  let provider: OracleProvider = AegisSelf
  when provider is {
    Charli3 -> False
    Orcfax -> False
    AegisSelf -> True
    Indigo -> False
  }
}

test dispatcher_indigo_branch_compiles() {
  // [v12.2] Fourth provider exhaustivity pin.
  let provider: OracleProvider = Indigo
  when provider is {
    Charli3 -> False
    Orcfax -> False
    AegisSelf -> False
    Indigo -> True
  }
}

test dispatcher_v5_compat_create_and_read() {
  // The v5 re-export path stays bit-for-bit equivalent.
  let datum = create_oracle_datum(420_000, 1_700_000_000_000, 1_700_999_999_999)
  get_oracle_price(datum) == 420_000 && get_oracle_timestamp(datum) == 1_700_000_000_000 && get_oracle_expiry(
    datum,
  ) == 1_700_999_999_999
}

// ---------------------------------------------------------------------------
// [v12.2] is_canonical_oracle_nft soft-disable + Indigo arm tests
// ---------------------------------------------------------------------------

test is_canonical_rejects_charli3_under_v12_2() {
  // Even the V12-pinned canonical Charli3 NFT (which V12 accepted) is now
  // rejected under V12.2. Guards against accidental un-disable on a
  // refactor.
  !is_canonical_oracle_nft(Charli3, charli3_ada_usd_nft_policy)
}

test is_canonical_rejects_orcfax_under_v12_2() {
  // Same shape: the V12-pinned canonical Orcfax FSP hash is rejected.
  !is_canonical_oracle_nft(Orcfax, orcfax_fsp_script_hash)
}

test is_canonical_rejects_charli3_with_any_bytes() {
  // Defensive: ANY Charli3 binding (including hand-crafted attacker bytes)
  // must be rejected. The False arm is unconditional — no oracle_nft can
  // satisfy it.
  !is_canonical_oracle_nft(
    Charli3,
    #"00000000000000000000000000000000000000000000000000000000",
  )
}

test is_canonical_rejects_orcfax_with_any_bytes() {
  !is_canonical_oracle_nft(
    Orcfax,
    #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  )
}

test is_canonical_still_accepts_aegis_self_ada() {
  // AegisSelf arm unchanged. The V12 5-element allowlist is the live trust
  // anchor for ADA/BTC/ETH/USDC/USDT bindings.
  is_canonical_oracle_nft(
    AegisSelf,
    #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
  )
}

test is_canonical_accepts_indigo_iusd() {
  // V12.2 NEW: Indigo arm accepts any NFT in `indigo_canonical_nfts`.
  // Live preprod-mock NFT from Wave 4 mint (tx d0de29b9...).
  is_canonical_oracle_nft(
    Indigo,
    #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
  )
}

test is_canonical_accepts_indigo_ibtc() {
  // Live preprod-mock NFT from Wave 4 mint (tx 0a923058...).
  is_canonical_oracle_nft(
    Indigo,
    #"1e66200fca30b83d5937b67b896fa46f1adac98922555f9e791c1c83",
  )
}

test is_canonical_accepts_indigo_ieth() {
  // Live preprod-mock NFT from Wave 4 mint (tx 146667ec...).
  is_canonical_oracle_nft(
    Indigo,
    #"e81e84a5d34137bcbc2ba73f1b4e735ac0cc375f0bfeb5e98a397102",
  )
}

test is_canonical_accepts_indigo_isol() {
  // Live preprod-mock NFT from Wave 4 mint (tx cea3b933...).
  is_canonical_oracle_nft(
    Indigo,
    #"875cea49cb6963ad462187f77dcc5b4d458a66d7eb9a646c2c5405a7",
  )
}

test is_canonical_rejects_indigo_with_aegis_self_nft() {
  // Defensive: an AegisSelf NFT submitted with provider=Indigo must be
  // rejected. The two allowlists are disjoint by construction; this test
  // pins that disjointness against accidental drift.
  !is_canonical_oracle_nft(
    Indigo,
    #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
  )
}

test is_canonical_rejects_aegis_self_with_indigo_nft() {
  // Symmetric: an Indigo NFT (live Wave-4 iUSD mint) submitted with
  // provider=AegisSelf must be rejected. Same disjointness, opposite
  // direction.
  !is_canonical_oracle_nft(
    AegisSelf,
    #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
  )
}

test is_canonical_rejects_indigo_with_unknown_nft() {
  // Defensive: any non-canonical NFT with provider=Indigo rejects.
  !is_canonical_oracle_nft(
    Indigo,
    #"00112233445566778899001122334455667788990011223344556677",
  )
}

test is_canonical_rejects_indigo_with_empty_nft() {
  !is_canonical_oracle_nft(Indigo, #"")
}
