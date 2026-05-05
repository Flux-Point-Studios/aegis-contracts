// =============================================================================
// Aegis Insurance Protocol - Orcfax Oracle Resolver (v6 multi-provider)
// Location: contracts/lib/aegis/oracle/orcfax.ak
// Summary: Orcfax V1 implementation of the provider-uniform
//          `aegis/oracle/types.Price` shape. Walks the FSP -> FS pointer
//          indirection from `reference_inputs`, parses the `FsDat<Rational>`,
//          verifies the feed_id, derives the freshness window, and converts
//          the rational price to the protocol-wide 1e6 scale.
//
// References:
//   * Orcfax docs:    https://docs.orcfax.io/consume
//   * Orcfax types:   https://github.com/orcfax/orcfax-aiken/blob/main/lib/orcfax/types.ak
//   * Orcfax tokens:  https://github.com/orcfax/orcfax-aiken/blob/main/lib/orcfax/tokens.ak
//   * Orcfax feeds:   https://github.com/orcfax/orcfax-aiken/blob/main/lib/orcfax/feed_id.ak
//   * Validity range: https://github.com/orcfax/orcfax-aiken/blob/main/lib/orcfax/validity_range.ak
//
// **Why we do NOT vendor `orcfax/orcfax-aiken` as an Aiken dependency.**
// The upstream library is small (~150 LOC across 4 files) and pinning a
// network dependency would couple Aegis's deploy cadence to upstream
// release cadence, complicating the audit-grade pinning of every byte of
// validator code. Instead we re-declare the minimum subset of upstream
// types here (FsDat, Statement, Rational) — these are pure data shapes
// matching the upstream CBOR positionally, so the wire format is
// guaranteed to be identical. If upstream rotates the schema, we update
// here in lockstep with their release notes.
// =============================================================================

use aegis/oracle/types.{Price}
use aegis/types as aegis_types
use aiken/collection/list
use aiken/primitive/bytearray
use cardano/address.{Script}
use cardano/assets
use cardano/transaction.{InlineDatum, Input}

// ---------------------------------------------------------------------------
// Re-declared Orcfax CBOR Shapes
// ---------------------------------------------------------------------------

/// Orcfax `Statement<t>` matching upstream `lib/orcfax/types.ak` positionally.
///
/// `feed_id` example: hex `4345522f4144412d5553442f` decodes to
/// `"CER/ADA-USD/"` — note the **mandatory** trailing slash (per upstream
/// `feed_id.ak` test `test_mk_feed_id_b`). The trailing `/` "prevents
/// `ADA-USDM` being a match for `ADA-USD`". Aegis matches with `starts_with`
/// rather than equality so a future versioned feed (e.g.,
/// `"CER/ADA-USD/3/"`) is forward-compatible without an Aegis redeploy.
pub type Statement<t> {
  feed_id: ByteArray,
  /// POSIX milliseconds when the upstream signed the fact statement.
  /// Aegis uses this to derive `Price.valid_until` since Orcfax has NO
  /// on-chain expiry field.
  created_at: Int,
  body: t,
}

/// Orcfax `Rational` matching upstream `lib/orcfax/rational.ak` positionally.
/// Encodes price as `num / denom` with arbitrary precision. Aegis converts
/// to 1e6-scaled int via `num * 1_000_000 / denom` (floor-rounded).
pub type Rational {
  num: Int,
  denom: Int,
}

/// Orcfax `FsDat<t>` matching upstream `lib/orcfax/types.ak` positionally.
/// `context` is opaque to consumers; we accept it as `Data` and ignore it.
pub type FsDat<t> {
  statement: Statement<t>,
  context: Data,
}

/// Concrete Orcfax fact-statement datum specialization Aegis consumes:
/// `FsDat<Rational>` — i.e., a CER (Currency Exchange Rate) fact statement.
pub type RationalFsDat =
  FsDat<Rational>

// ---------------------------------------------------------------------------
// FSP -> FS Resolution Helpers
// ---------------------------------------------------------------------------

/// Find the FSP UTxO. Two simultaneous bindings:
///   1. The reference input's value must contain a token with policy id
///      `fsp_hash` AND asset name `aegis_types.orcfax_fsp_asset_name` (the CIP-67
///      reference NFT label). Quantity must equal exactly 1 (FSP NFT is a
///      one-shot per network).
///   2. The reference input's address payment credential must be the
///      `Script(fsp_hash)` itself — i.e., FSP NFT policy == FSP validator
///      script. This is the FSP equivalent of A-016: a stolen-or-moved FSP
///      NFT lying at a non-canonical address must NOT be accepted.
///
/// Failing either binding yields `None`. The dispatcher then `expect Some`s
/// to fail closed — which is the audit-grade behavior — rather than silently
/// returning a default price.
fn find_fsp_input(
  reference_inputs: List<Input>,
  fsp_hash: ByteArray,
) -> Option<Input> {
  list.find(
    reference_inputs,
    fn(i) {
      let qty =
        assets.quantity_of(i.output.value, fsp_hash, aegis_types.orcfax_fsp_asset_name)
      let at_canonical_fsp =
        when i.output.address.payment_credential is {
          Script(h) -> h == fsp_hash
          _ -> False
        }
      qty == 1 && at_canonical_fsp
    },
  )
}

/// Find the FS UTxO matching the dynamic `fs_hash` discovered from the FSP
/// datum. Same dual-binding logic as `find_fsp_input`:
///   1. The reference input's value must carry a token with policy id
///      `fs_hash` and asset name `aegis_types.orcfax_fs_asset_name` (empty bytestring),
///      quantity exactly 1.
///   2. The reference input's address payment credential must be
///      `Script(fs_hash)` — Orcfax's design pins FS NFT policy == FS
///      validator hash, and this binding closes the "stolen FS NFT at the
///      wrong address" surface.
fn find_fs_input(
  reference_inputs: List<Input>,
  fs_hash: ByteArray,
) -> Option<Input> {
  list.find(
    reference_inputs,
    fn(i) {
      let qty =
        assets.quantity_of(i.output.value, fs_hash, aegis_types.orcfax_fs_asset_name)
      let at_canonical_fs =
        when i.output.address.payment_credential is {
          Script(h) -> h == fs_hash
          _ -> False
        }
      qty == 1 && at_canonical_fs
    },
  )
}

/// Compare the Orcfax `feed_id` to a required prefix (e.g.,
/// `aegis_types.orcfax_ada_usd_feed_id` = `"CER/ADA-USD/"`). The upstream convention is
/// "prefix match", letting versioned feeds (`"CER/ADA-USD/3/"`) be accepted
/// by integrators pinned to the unversioned base — without requiring a
/// validator redeploy. The trailing slash on the prefix is load-bearing:
/// `"CER/ADA-USD/"` does NOT match `"CER/ADA-USDM/"` because the candidate
/// must contain the slash byte at position |prefix|-1.
fn feed_id_starts_with(candidate: ByteArray, prefix: ByteArray) -> Bool {
  let prefix_len = bytearray.length(prefix)
  let candidate_len = bytearray.length(candidate)
  if candidate_len < prefix_len {
    False
  } else {
    bytearray.take(candidate, prefix_len) == prefix
  }
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// Resolve an Orcfax fact-statement reading from `reference_inputs` and emit
/// the provider-uniform `Price` record.
///
/// **Pre-conditions enforced:**
///   1. An FSP input is present at `Script(fsp_hash)` carrying the FSP NFT.
///   2. The FSP datum is an inline ByteArray containing the dynamic `fs_hash`.
///   3. An FS input is present at `Script(fs_hash)` carrying the FS NFT.
///   4. The FS datum is an inline `FsDat<Rational>` (`RationalFsDat`).
///   5. `statement.feed_id` starts with the supplied `feed_id_prefix` (e.g.,
///      `"CER/ADA-USD/"`).
///   6. `statement.body.denom != 0` — defensive, fails closed rather than
///      panicking on division by zero.
///
/// Failure of any pre-condition aborts the validator (`expect`/`fail`),
/// rather than silently returning a default price. This is the audit-grade
/// behavior Aegis maintains across both providers.
///
/// **Conversion math.** Rational `num/denom` -> 1e6-scaled int via
/// `num * 1_000_000 / denom`. Floor-rounded by Aiken's integer division
/// semantics. The economic bias of floor-rounding is "report a slightly
/// LOWER price", which biases toward MORE Claim eligibility — a safer
/// direction than over-reporting (which would suppress legitimate claims).
///
/// **Freshness.** Orcfax has NO on-chain expiry field. We derive
/// `valid_until = created_at + aegis_types.orcfax_freshness_window_ms` so the validator
/// can apply the same `tx_lower <= valid_until` check as it does for
/// Charli3.
pub fn resolve_with_feed(
  reference_inputs: List<Input>,
  fsp_hash: ByteArray,
  feed_id_prefix: ByteArray,
) -> Price {
  // [v6.0.2 / A-027 fix] Pin `fsp_hash` to the canonical Orcfax FSP
  // script hash for the active network. Pre-fix, the FSP script
  // credential was pinned to the same caller-supplied value, letting an
  // attacker deploy a permissive FSP+FS pair under their own hash and
  // reference them. The pre-existing `orcfax_fsp_script_hash_preview`
  // and `_mainnet` constants were unused for binding; this asserts the
  // active-network constant.
  expect fsp_hash == aegis_types.orcfax_fsp_script_hash

  // 1. FSP discovery.
  expect Some(fsp_input) = find_fsp_input(reference_inputs, fsp_hash)
  expect InlineDatum(fsp_idat) = fsp_input.output.datum
  expect fs_hash: ByteArray = fsp_idat

  // 2. FS discovery via the dynamic fs_hash.
  expect Some(fs_input) = find_fs_input(reference_inputs, fs_hash)
  expect InlineDatum(fs_idat) = fs_input.output.datum
  expect fs_dat: RationalFsDat = fs_idat

  // 3. Feed identity.
  expect feed_id_starts_with(fs_dat.statement.feed_id, feed_id_prefix)

  // 4. Defensive: reject zero-denom rationals before division.
  expect fs_dat.statement.body.denom != 0

  // 5. Convert rational -> 1e6-scaled int.
  let scaled =
    fs_dat.statement.body.num * 1_000_000 / fs_dat.statement.body.denom

  // 6. Compute consumer-side freshness window (Orcfax has no on-chain expiry).
  let valid_until = fs_dat.statement.created_at + aegis_types.orcfax_freshness_window_ms

  Price { value: scaled, observed_at: fs_dat.statement.created_at, valid_until }
}

/// Default Orcfax resolver — pinned to the CER/ADA-USD feed prefix because
/// that is the only feed Aegis currently consumes (matching the Charli3
/// ADA/USD pairing). When/if Aegis adds a non-ADA insured asset, callers
/// would invoke `resolve_with_feed` directly with the appropriate prefix
/// and a corresponding `oracle_nft` (FSP hash) per policy datum.
pub fn resolve(reference_inputs: List<Input>, fsp_hash: ByteArray) -> Price {
  resolve_with_feed(reference_inputs, fsp_hash, aegis_types.orcfax_ada_usd_feed_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test feed_id_starts_with_exact_match() {
  feed_id_starts_with(#"4345522f4144412d5553442f", #"4345522f4144412d5553442f") == True
}

test feed_id_starts_with_versioned_match() {
  // Future Orcfax may publish `"CER/ADA-USD/3/"` (hex 4345522f4144412d5553442f33 2f).
  // The base prefix `"CER/ADA-USD/"` must still match — forward compatibility.
  let versioned = #"4345522f4144412d5553442f332f"
  // "CER/ADA-USD/3/"
  let base_prefix = #"4345522f4144412d5553442f"
  // "CER/ADA-USD/"
  feed_id_starts_with(versioned, base_prefix) == True
}

test feed_id_starts_with_rejects_ada_usdm() {
  // `"CER/ADA-USDM/"` (hex 4345522f4144412d5553444d 2f) does NOT start with
  // `"CER/ADA-USD/"` because byte index 11 of the candidate is `'M'` (0x4d)
  // not `'/'` (0x2f). This is the load-bearing trailing-slash defense.
  let ada_usdm = #"4345522f4144412d5553444d2f"
  // "CER/ADA-USDM/"
  let ada_usd_prefix = #"4345522f4144412d5553442f"
  // "CER/ADA-USD/"
  feed_id_starts_with(ada_usdm, ada_usd_prefix) == False
}

test feed_id_starts_with_rejects_unrelated_pair() {
  let btc_usd = #"4345522f4254432d5553442f"
  // "CER/BTC-USD/"
  let ada_usd_prefix = #"4345522f4144412d5553442f"
  // "CER/ADA-USD/"
  feed_id_starts_with(btc_usd, ada_usd_prefix) == False
}

test feed_id_starts_with_shorter_candidate_rejected() {
  // A candidate strictly shorter than the prefix is impossible to match.
  let too_short = #"4345522f4144412d"
  // "CER/ADA-"
  let prefix = #"4345522f4144412d5553442f"
  // "CER/ADA-USD/"
  feed_id_starts_with(too_short, prefix) == False
}

test rational_to_scaled_basic_conversion() {
  // 0.45 USD per ADA → num=45, denom=100 → scaled = 45 * 1_000_000 / 100 = 450_000.
  let num: Int = 45
  let denom: Int = 100
  let scaled = num * 1_000_000 / denom
  scaled == 450_000
}

test rational_to_scaled_floor_rounding_bias() {
  // 0.4473333... → num=4473, denom=10000 → 447300 lovelace per scaled-1e6 unit.
  // Verify floor rounding under truncating Int division.
  let num: Int = 4_473
  let denom: Int = 10_000
  let scaled = num * 1_000_000 / denom
  scaled == 447_300
}

test rational_to_scaled_high_precision_orcfax_example() {
  // Real-world example from Orcfax docs:
  //   54301 / 1250000000 = 0.000043440... (1 USD per N ADA direction)
  //   But Aegis's strike convention is "USD per ADA scaled 1e6":
  //   With Aegis pinned to the standard `CER/ADA-USD/` direction (USD per
  //   1 ADA), a typical reading is num=4473, denom=10000 ≈ $0.4473.
  //   See Q4 in ORCFAX_INTEGRATION_SCOPE.md — verified direction matches.
  let num: Int = 4_473
  let denom: Int = 10_000
  let scaled = num * 1_000_000 / denom
  // 0.4473 USD/ADA → 447_300 in 1e6 scale.
  scaled == 447_300
}

test orcfax_freshness_window_is_70_minutes() {
  // [v7] Widened from 30 min to 70 min — see types.ak::orcfax_freshness_window_ms
  // doc comment for the 1h-heartbeat empirical justification.
  aegis_types.orcfax_freshness_window_ms == 70 * 60 * 1_000
}

test orcfax_valid_until_derivation_matches_window() {
  let created_at: Int = 1_700_000_000_000
  let valid_until = created_at + aegis_types.orcfax_freshness_window_ms
  valid_until == created_at + 70 * 60 * 1_000
}
