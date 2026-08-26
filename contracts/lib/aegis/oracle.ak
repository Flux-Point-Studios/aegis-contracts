// =============================================================================
// Aegis Insurance Protocol - Oracle Top-Level Dispatcher
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
use aegis/oracle/orcfax
use aegis/oracle/pyth
use aegis/oracle/types as oracle_types
use aegis/test_helpers/pyth_fixtures
use aegis/types.{
  AegisSelf, Charli3, Indigo, OracleProvider, Orcfax, Pyth,
  aegis_self_canonical_nfts, charli3_ada_usd_nft_policy,
  is_canonical_aegis_self_nft,
  orcfax_fsp_script_hash, pyth_canonical_feed_ids,
}
use aiken/collection/list
use aiken/collection/pairs
use aiken/primitive/bytearray
use cardano/address.{Credential, Script}
use cardano/transaction.{Input, Transaction, Withdraw}

// ---------------------------------------------------------------------------
// [V5 size] Oracle-observer forwarding (#315)
//
// resolve_oracle_price (incl. the ~7.5 KB Pyth Ed25519/Solana branch) is too
// large to inline into BOTH the pool and policy validators — the pool then
// exceeds the 16 KB max-tx-size. So a leaf `oracle_observer` withdraw validator
// runs resolve_oracle_price ONCE and ATTESTS the resolved Price(s) in its
// withdrawal redeemer; the pool/policy READ the attested Price via
// `attested_price` below instead of resolving inline. Same resolver, relocated:
// the cryptographic/economic trust boundary is byte-identical.
// ---------------------------------------------------------------------------

/// One genuine oracle reading the observer attests for a (provider, oracle_nft).
/// The observer's withdraw handler proves `resolve_oracle_price(self, …) ==
/// price` for every Attestation; consumers then trust `price` because the
/// observer ran (Conway only admits a Withdraw redeemer whose script ran True).
pub type Attestation {
  provider: OracleProvider,
  oracle_nft: ByteArray,
  price: oracle_types.Price,
}

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
///
/// **Pyth note.** The `Pyth` provider needs the WHOLE `Transaction` (the
/// official `pyth.get_updates` reads BOTH the Pyth State reference input AND
/// the Pyth withdraw-script redeemer that carries the signed update). The
/// other four providers only need `reference_inputs`. We therefore thread
/// `self: Transaction` through the dispatcher; `reference_inputs` is retained
/// for the legacy providers (it equals `self.reference_inputs`, passed by the
/// caller so the four existing arms are byte-for-byte unchanged).
pub fn resolve_oracle_price(
  self: Transaction,
  reference_inputs: List<Input>,
  provider: OracleProvider,
  oracle_nft: ByteArray,
) -> oracle_types.Price {
  when provider is {
    Charli3 -> charli3.resolve(reference_inputs, oracle_nft)
    Orcfax -> orcfax.resolve(reference_inputs, oracle_nft)
    AegisSelf -> aegis_self.resolve(reference_inputs, oracle_nft)
    // [#316] RETIRED. Indigo stopped publishing a standing price datum on
    // 2026-05-28 — the price now rides the consuming transaction as a signed
    // Pyth message in a zero-stake withdrawal redeemer, so there is no UTxO
    // left to read. The arm fails closed rather than resolving a stale datum.
    Indigo -> fail @"Indigo oracle retired: datum publishing ended 2026-05-28"
    // [Pyth Wave 1] Pyth Lazer. `oracle_nft` here carries the Pyth feed-id
    // big-endian (NOT an NFT policy). The resolver pins the Pyth State NFT
    // policy + exact feed-id and enforces freshness/replay via observed_at /
    // valid_until — see oracle/pyth.ak.
    Pyth -> pyth.resolve(self, oracle_nft)
  }
}

/// [V5 size] Read the oracle-observer's ATTESTED Price for `(provider,
/// oracle_nft)` instead of resolving inline. The pool/policy validators are
/// parameterized by `observer_script_hash`; this helper:
///   (A) requires the observer ACTUALLY withdrew (a `self.withdrawals` entry for
///       its credential — load-bearing + audit-legible: Conway only admits a
///       Withdraw redeemer whose script ran to True, but (A) makes the
///       dependency explicit at the read site — DO NOT remove);
///   (B) reads the observer's VALIDATED redeemer (the attestation list);
///   (C) binds to THIS policy's declared feed — a wrong/absent feed aborts.
/// The returned Price is genuine because the observer proved
/// `resolve_oracle_price(self, …) == price` for it. FRESHNESS is NOT certified
/// here — every freshness gate stays consumer-side (see policy/pool), so the
/// observer attests genuineness only and replay defense never moves.
pub fn attested_price(
  self: Transaction,
  observer_script_hash: ByteArray,
  provider: OracleProvider,
  oracle_nft: ByteArray,
) -> oracle_types.Price {
  let obs_cred: Credential = Script(observer_script_hash)
  expect True =
    list.any(self.withdrawals, fn(w) { w.1st == obs_cred })
  expect Some(raw) = pairs.get_first(self.redeemers, Withdraw(obs_cred))
  expect attestations: List<Attestation> = raw
  expect Some(a) =
    list.find(
      attestations,
      fn(a) { a.provider == provider && a.oracle_nft == oracle_nft },
    )
  a.price
}

/// Predicate: is the supplied `oracle_nft` a canonical handle for the
/// supplied provider?
///   * AegisSelf -> membership in `aegis_self_canonical_nfts`
///   * Indigo    -> RETIRED (#316): no handle is canonical, so Underwrite
///     cannot mint a policy bound to it
///   * Charli3 / Orcfax -> not supported (resolvers retained in tree so
///     V11 datums remain CBOR-decodable for off-chain analytics).
pub fn is_canonical_oracle_nft(
  provider: OracleProvider,
  oracle_nft: ByteArray,
) -> Bool {
  when provider is {
    Charli3 -> False
    Orcfax -> False
    AegisSelf -> is_canonical_aegis_self_nft(oracle_nft)
    Indigo -> False
    // [#381 V8.1 S1] The handle is a feed-id (big-endian bytes), not an NFT
    // policy, and must be an EXPLICIT member of the per-network allowlist.
    // The State-NFT trust anchor still lives inside pyth.resolve; this gate
    // pins WHICH markets may settle money (genesis: ADA/USD only).
    Pyth -> list.has(pyth_canonical_feed_ids, oracle_nft)
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
  // Sanity: the `when provider is { Charli3 | Orcfax | AegisSelf |
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
    Pyth -> False
  }
}

test dispatcher_orcfax_branch_compiles() {
  let provider: OracleProvider = Orcfax
  when provider is {
    Charli3 -> False
    Orcfax -> True
    AegisSelf -> False
    Indigo -> False
    Pyth -> False
  }
}

test dispatcher_aegis_self_branch_compiles() {
  let provider: OracleProvider = AegisSelf
  when provider is {
    Charli3 -> False
    Orcfax -> False
    AegisSelf -> True
    Indigo -> False
    Pyth -> False
  }
}

test dispatcher_indigo_branch_compiles() {
  // Fourth provider exhaustivity pin.
  let provider: OracleProvider = Indigo
  when provider is {
    Charli3 -> False
    Orcfax -> False
    AegisSelf -> False
    Indigo -> True
    Pyth -> False
  }
}

test dispatcher_pyth_branch_compiles() {
  // [Pyth Wave 1] Fifth provider exhaustivity pin.
  let provider: OracleProvider = Pyth
  when provider is {
    Charli3 -> False
    Orcfax -> False
    AegisSelf -> False
    Indigo -> False
    Pyth -> True
  }
}

test is_canonical_accepts_pyth_nonempty_feed_id() {
  // [Pyth Wave 1] Pyth handle = feed-id big-endian. ADA/USD = 16 = #"10".
  is_canonical_oracle_nft(Pyth, #"10")
}

test is_canonical_rejects_pyth_empty_feed_id() {
  // [Pyth Wave 1] Empty handle (feed-id 0) rejected.
  !is_canonical_oracle_nft(Pyth, #"")
}

test dispatcher_v5_compat_create_and_read() {
  // The v5 re-export path stays bit-for-bit equivalent.
  let datum = create_oracle_datum(420_000, 1_700_000_000_000, 1_700_999_999_999)
  get_oracle_price(datum) == 420_000 && get_oracle_timestamp(datum) == 1_700_000_000_000 && get_oracle_expiry(
    datum,
  ) == 1_700_999_999_999
}

// ---------------------------------------------------------------------------
// is_canonical_oracle_nft soft-disable + Indigo arm tests
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

test is_canonical_accepts_every_aegis_self_feed() {
  // [#363 F5] Was pinned to the retired preprod ADA feed (d2f08410…), canonical
  // on NEITHER profile after the V8B re-parameterization. Derived AND broadened:
  // every canonical entry must pass the AegisSelf arm. That is the real
  // behaviour under test (provider dispatch + the V12 `list.has` rewrite),
  // it is non-vacuous, and it is correct under both network modules.
  list.all(
    aegis_self_canonical_nfts,
    fn(n) { is_canonical_oracle_nft(AegisSelf, n) },
  )
}

// [#424] THE FALSE DIRECTION, which nothing tested. The suite drove the
// AegisSelf arm only over members expecting True, so `fn(_) { True }` passed
// all 1123 tests — and the commit that collapsed three inlined copies of the
// allowlist into one `is_canonical_aegis_self_nft` is exactly the edit that
// could have bound the wrong list or dropped the membership test outright.
// A predicate proven only where it must accept is not proven at all.
//
// The decisive witness is DERIVED, not chosen: the first canonical entry with
// one byte pushed onto the front. It is guaranteed absent from whichever list
// is compiled in, on either profile, without this test having to know a literal
// — a hand-picked constant is one allowlist edit away from becoming a member
// and silently inverting its own meaning. Both entry points are driven, because
// `is_canonical_oracle_nft` dispatches on the provider before it ever reaches
// the predicate and could refuse for the dispatch instead.
test aegis_self_refuses_an_nft_outside_the_allowlist() {
  expect [first, ..] = aegis_self_canonical_nfts
  let absent = bytearray.push(first, 0xff)
  and {
    !list.has(aegis_self_canonical_nfts, absent),
    !is_canonical_aegis_self_nft(absent),
    !is_canonical_aegis_self_nft(#""),
    !is_canonical_oracle_nft(AegisSelf, absent),
    !is_canonical_oracle_nft(AegisSelf, #""),
  }
}

// [#316] Indigo RETIRED datum publishing on 2026-05-28 — all four oracle NFTs
// stopped within 104 seconds of each other and now pass the price alongside the
// consuming transaction as a signed Pyth message in a zero-stake withdrawal
// redeemer. The `Indigo` arm parses the INLINE DATUM of a UTxO nobody updates,
// so it is unreachable. Retiring it means no handle is canonical under Indigo:
// Underwrite's canonical gate is what admits a policy, so this is the property
// that makes an Indigo policy unmintable. Both networks' former canonical NFTs
// are named so the assertion is non-vacuous under either compiled profile.
test indigo_is_retired_so_no_nft_is_canonical() {
  and {
    !is_canonical_oracle_nft(
      Indigo,
      #"e3455f2715338b454fb853442f72dc03b98396854f97510027fe22ff",
    ),
    !is_canonical_oracle_nft(
      Indigo,
      #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
    ),
    !is_canonical_oracle_nft(Indigo, #""),
    list.all(
      aegis_self_canonical_nfts,
      fn(n) { !is_canonical_oracle_nft(Indigo, n) },
    ),
  }
}

// ---------------------------------------------------------------------------
// [#381 V8.1 S1] Pyth canonical feed-id allowlist — RED-first pin
// ---------------------------------------------------------------------------

test s1_pyth_canonical_rejects_unknown_feed() {
  // Wave-1 accepted ANY non-empty handle; V8.1 requires explicit membership.
  !is_canonical_oracle_nft(Pyth, #"63")
}

test s1_pyth_canonical_accepts_listed_feed() {
  // derived from the active network's allowlist, never a literal (#363 N6)
  expect [first, ..] = pyth_canonical_feed_ids
  is_canonical_oracle_nft(Pyth, first)
}

test s1_pyth_canonical_rejects_empty_handle() {
  !is_canonical_oracle_nft(Pyth, #"")
}

/// [#381 V8.1 S1] As `attested_price`, but a MISSING observer withdrawal or a
/// missing (provider, oracle_nft) attestation yields None instead of aborting
/// — the seam S4's fallback helper needs to TRY the primary leg and fall
/// through. A present-but-malformed redeemer still aborts (fail-closed): only
/// genuine absence is survivable.
pub fn attested_price_opt(
  self: Transaction,
  observer_script_hash: ByteArray,
  provider: OracleProvider,
  oracle_nft: ByteArray,
) -> Option<oracle_types.Price> {
  let obs_cred: Credential = Script(observer_script_hash)
  if !list.any(self.withdrawals, fn(w) { w.1st == obs_cred }) {
    None
  } else {
    expect Some(raw) = pairs.get_first(self.redeemers, Withdraw(obs_cred))
    expect attestations: List<Attestation> = raw
    when
      list.find(
        attestations,
        fn(a) { a.provider == provider && a.oracle_nft == oracle_nft },
      )
    is {
      Some(a) -> Some(a.price)
      None -> None
    }
  }
}

fn s1_observer_tx(observer_hash: ByteArray, att_nft: ByteArray) -> Transaction {
  let base = pyth_fixtures.pyth_tx()
  let obs_cred: Credential = Script(observer_hash)
  let genuine = resolve_oracle_price(base, base.reference_inputs, Pyth, att_nft)
  let att: Data =
    [Attestation { provider: Pyth, oracle_nft: att_nft, price: genuine }]
  Transaction {
    ..base,
    withdrawals: [
      Pair(Script(pyth_fixtures.pyth_test_withdraw_hash), 0),
      Pair(obs_cred, 0),
    ],
    redeemers: list.concat(base.redeemers, [Pair(Withdraw(obs_cred), att)]),
  }
}

test s1_attested_price_opt_present() {
  let tx = s1_observer_tx(#"92c3", #"02")
  when attested_price_opt(tx, #"92c3", Pyth, #"02") is {
    Some(p) -> p.value == pyth_fixtures.feed2_value_1e6
    None -> False
  }
}

test s1_attested_price_opt_none_without_observer_withdrawal() {
  // the raw pyth tx carries NO observer withdrawal -> None, not an abort
  attested_price_opt(pyth_fixtures.pyth_tx(), #"92c3", Pyth, #"02") == None
}

test s1_attested_price_opt_none_for_unattested_feed() {
  let tx = s1_observer_tx(#"92c3", #"02")
  attested_price_opt(tx, #"92c3", Pyth, #"70") == None
}
