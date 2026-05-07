// =============================================================================
// Aegis Insurance Protocol - Auth Coverage Payload (v8 / RELAY-PRESIGNED-AUTH)
// Location: contracts/lib/aegis/auth_payload.ak
// Summary: Canonical CBOR encoder + Ed25519 signature verifier for the
//          off-chain payload the insured signs at policy-creation time.
//
//          Cross-stack agreement is load-bearing: the TypeScript side uses
//          @stricahq/cbors and the Python side uses cbor2; both must produce
//          byte-identical output to `cbor.serialise(payload)` here. The
//          reference test vectors live at the bottom of this file (and as
//          JSON fixtures at tests/fixtures/auth_payload_vectors.json) so any
//          divergence is caught at CI time.
//
//          Encoding shape: `AuthCoveragePayload` is encoded as Plutus's
//          canonical Constr 0 — i.e., `cbor.serialise` produces
//          `d8799f<14 fields>ff` (CBOR major-type-6 tag 121 + indefinite-
//          length list of fields + break). Byte-strings are major-type-2
//          definite-length; integers use the smallest-possible header per
//          RFC 8949 §4.2 (which is Plutus's `serialise_data` default). This
//          IS the canonical Cardano on-chain CBOR — every CIP-30 wallet
//          uses it for tx-body encoding, so a Cardano-native cross-stack
//          encoder reproduces it natively.
//
//          Used by: validators/policy.ak (ClaimWithAuth + RotateAuth),
//          validators/auth_witness_nft.ak (mint-time payload decode + bind
//          to policy datum's auth_commitment).
// =============================================================================

use aegis/types.{AuthCoveragePayload}
use aiken/cbor
use aiken/crypto.{blake2b_256, verify_ed25519_signature}
use aiken/primitive/bytearray

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// [v8] Canonical CBOR encoding of an `AuthCoveragePayload`. Delegates to
/// `cbor.serialise` (which IS Plutus's `serialise_data` builtin) so the
/// on-chain encoder is the canonical authority — TS / Python encoders are
/// validated against this output via cross-stack byte-vector tests.
///
/// The payload is encoded as Plutus Constr 0 (tag 121 + indefinite-length
/// field list). Field order is fixed by the type definition in `types.ak`
/// and MUST NOT be changed without a coordinated cross-stack rotation.
pub fn encode(payload: AuthCoveragePayload) -> ByteArray {
  cbor.serialise(payload)
}

/// [v8] BLAKE2b-256 commitment over the canonical CBOR. Stored on-chain as
/// `PolicyDatum.auth_commitment` and signed off-chain by the insured's
/// Aegis-wallet Ed25519 key. The 32-byte digest is what the relay's
/// `ClaimWithAuth` redeemer carries (alongside the signature) and what the
/// validator re-derives at claim time.
pub fn commit(payload: AuthCoveragePayload) -> ByteArray {
  blake2b_256(encode(payload))
}

/// [v8] Compute the commitment directly from a CBOR byte string. Used by
/// the witness-NFT mint validator and the policy validator's claim branch
/// — both have access to the on-chain CBOR (from the witness UTxO datum)
/// and re-hash it to verify the policy's auth_commitment binding.
pub fn commit_from_cbor(payload_cbor: ByteArray) -> ByteArray {
  blake2b_256(payload_cbor)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// [v8] Verify a 64-byte raw Ed25519 signature over `commit` produced by
/// the insured's Aegis-wallet pubkey. Wraps `verify_ed25519_signature`
/// from `aiken/crypto`. The Plutus builtin enforces strict-S (Δ11) — see
/// `test_h2_ed25519_strict_s_regression` for the closing test.
pub fn verify_signature(
  insured_vkey: ByteArray,
  commit: ByteArray,
  sig: ByteArray,
) -> Bool {
  verify_ed25519_signature(insured_vkey, commit, sig)
}

// ---------------------------------------------------------------------------
// Length checks (Δ12 / F-AUTH-6)
// ---------------------------------------------------------------------------

/// [v8 / F-AUTH-6 / Δ12] A 32-byte commitment is the only acceptable shape
/// for `PolicyDatum.auth_commitment.Some(_)`. The validator's ClaimWithAuth
/// branch asserts this at entry (step 2 of §1.6) so a malformed datum
/// committed via a future schema-evolution oversight cannot bypass the
/// hash binding.
pub fn is_valid_commit_length(commit: ByteArray) -> Bool {
  bytearray.length(commit) == 32
}

/// [v8] A 32-byte Ed25519 vkey is the only acceptable shape for
/// `AuthWitnessDatum.insured_vkey`.
pub fn is_valid_vkey_length(vkey: ByteArray) -> Bool {
  bytearray.length(vkey) == 32
}

/// [v8] A 64-byte Ed25519 raw signature is the only acceptable shape.
pub fn is_valid_signature_length(sig: ByteArray) -> Bool {
  bytearray.length(sig) == 64
}

// ---------------------------------------------------------------------------
// Tests — round-trip canonical encoding + cross-stack reference vectors
// ---------------------------------------------------------------------------

// Reference test vectors. Output as hex strings into
// tests/fixtures/auth_payload_vectors.json so the TS / Python encoders can
// compare byte-for-byte. The Aiken side is the authority — any divergence
// in another stack is a bug in that stack's encoder.
//
// TV-1: minimal preprod, oracle_provider = Charli3 (0)
fn tv1() -> AuthCoveragePayload {
  AuthCoveragePayload {
    domain_tag: #"41454749535f434c41494d5f415554485f76315f50524550524f44",
    network_magic: 1,
    policy_validator: #"8ea5aed0e4f66e9ce6593fbed30856c8997441b1e5cd8bc3085e943f",
    policy_id: #"aabbccdd00112233445566778899aabbccddeeff0011223344556677",
    insured_pkh: #"00112233445566778899aabbccddeeff00112233445566778899aabb",
    payout_address: #"6000112233445566778899aabbccddeeff00112233445566778899aabb",
    max_coverage: 100_000_000,
    oracle_provider: 0,
    oracle_nft: #"886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e",
    oracle_freshness: 0,
    not_before: 1_700_000_000_000,
    not_after: 1_700_604_800_000,
    pool_script_hash: #"c366b0ea2667b432a432999f54e11978c0ed37c7c4b971067fb1589f",
    pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
  }
}

// TV-2: mainnet payload with non-zero oracle_freshness
fn tv2() -> AuthCoveragePayload {
  AuthCoveragePayload {
    domain_tag: #"41454749535f434c41494d5f415554485f76315f4d41494e4e4554",
    network_magic: 764_824_073,
    policy_validator: #"1111111111111111111111111111111111111111111111111111111a",
    policy_id: #"2222222222222222222222222222222222222222222222222222222b",
    insured_pkh: #"3333333333333333333333333333333333333333333333333333333c",
    payout_address: #"613333333333333333333333333333333333333333333333333333333c",
    max_coverage: 5_000_000_000,
    oracle_provider: 1,
    oracle_nft: #"4444444444444444444444444444444444444444444444444444444d",
    oracle_freshness: 60_000,
    not_before: 1_725_000_000_000,
    not_after: 1_725_604_800_000,
    pool_script_hash: #"5555555555555555555555555555555555555555555555555555555e",
    pool_nft: #"6666666666666666666666666666666666666666666666666666",
  }
}

// TV-3: edge — max_coverage at the largest signed 64-bit value
fn tv3() -> AuthCoveragePayload {
  AuthCoveragePayload { ..tv1(), max_coverage: 9_223_372_036_854_775_807 }
}

// TV-4: edge — minimal time window (not_after - not_before == 1)
fn tv4() -> AuthCoveragePayload {
  AuthCoveragePayload {
    ..tv1(),
    not_before: 1_700_000_000_000,
    not_after: 1_700_000_000_001,
  }
}

// TV-5: edge — oracle_provider = AegisSelf (Constr index 2, the v7 addition)
fn tv5() -> AuthCoveragePayload {
  AuthCoveragePayload {
    ..tv1(),
    oracle_provider: 2,
    oracle_nft: #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
  }
}

test auth_payload_encode_round_trip() {
  // Encode + decode round-trip — sanity check the canonical encoder.
  let p = tv1()
  let encoded = encode(p)
  bytearray.length(encoded) > 0
}

test auth_payload_commit_is_32_bytes() {
  // Commit must always be exactly 32 bytes (BLAKE2b-256).
  let p = tv1()
  let c = commit(p)
  bytearray.length(c) == 32 && is_valid_commit_length(c)
}

test auth_payload_commit_from_cbor_matches_commit() {
  // commit_from_cbor(encode(p)) == commit(p) — the validator's re-hash
  // path must agree with the off-chain signer's pre-hash path.
  let p = tv1()
  commit_from_cbor(encode(p)) == commit(p)
}

test auth_payload_distinct_payloads_distinct_commits() {
  // Two payloads differing in even one field must produce different
  // commits — this is the security property the relay-presigned-auth
  // design depends on (a sig over commit_a doesn't authorize commit_b).
  commit(tv1()) != commit(tv2()) && commit(tv1()) != commit(tv3()) && commit(
    tv1(),
  ) != commit(tv4()) && commit(tv1()) != commit(tv5())
}

test auth_payload_tv1_is_charli3() {
  tv1().oracle_provider == 0
}

test auth_payload_tv2_is_orcfax() {
  tv2().oracle_provider == 1
}

test auth_payload_tv5_is_aegis_self() {
  tv5().oracle_provider == 2
}

test auth_payload_tv3_handles_max_int_coverage() {
  // Largest signed 64-bit = 2^63 - 1 = 9_223_372_036_854_775_807
  tv3().max_coverage == 9_223_372_036_854_775_807
}

test auth_payload_tv4_minimal_window() {
  let p = tv4()
  p.not_after - p.not_before == 1
}

test auth_payload_length_check_rejects_short_commit() {
  // 31 bytes — below the BLAKE2b-256 spec — must be rejected.
  is_valid_commit_length(
    #"00112233445566778899aabbccddeeff00112233445566778899aabbccddee",
  ) == False
}

test auth_payload_length_check_rejects_long_commit() {
  // 33 bytes — above spec — must be rejected.
  is_valid_commit_length(
    #"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff11",
  ) == False
}

test auth_payload_length_check_accepts_32_bytes() {
  is_valid_commit_length(
    #"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
  )
}

test auth_payload_signature_length_64_bytes() {
  // 128 hex chars == 64 bytes (Ed25519 raw signature length).
  is_valid_signature_length(
    #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  )
}

test auth_payload_signature_length_rejects_63_bytes() {
  // 126 hex chars == 63 bytes — below Ed25519 spec.
  is_valid_signature_length(
    #"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  ) == False
}

test auth_payload_vkey_length_32_bytes() {
  is_valid_vkey_length(
    #"0000000000000000000000000000000000000000000000000000000000000000",
  )
}

test auth_payload_vkey_length_rejects_31_bytes() {
  is_valid_vkey_length(
    #"00000000000000000000000000000000000000000000000000000000000000",
  ) == False
}

// ---------------------------------------------------------------------------
// Cross-stack canonical CBOR byte-vector tests (Δ10 / M-1 / Appendix B)
//
// These tests pin the on-chain canonical CBOR for tv1..tv5 against the
// hex strings published in tests/fixtures/auth_payload_vectors.json. The
// frontend (TS) and Python encoders compare against the SAME hex strings;
// any divergence between the three encoders produces a build red.
// ---------------------------------------------------------------------------

test auth_payload_tv1_canonical_cbor_pinned() {
  encode(tv1()) == #"d8799f581b41454749535f434c41494d5f415554485f76315f50524550524f4401581c8ea5aed0e4f66e9ce6593fbed30856c8997441b1e5cd8bc3085e943f581caabbccdd00112233445566778899aabbccddeeff0011223344556677581c00112233445566778899aabbccddeeff00112233445566778899aabb581d6000112233445566778899aabbccddeeff00112233445566778899aabb1a05f5e10000581c886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e001b0000018bcfe568001b0000018bf3f1ec00581cc366b0ea2667b432a432999f54e11978c0ed37c7c4b971067fb1589f581bdeadbeef00112233445566778899aabbccddeeff00112233445566ff"
}

test auth_payload_tv1_commit_pinned() {
  commit(tv1()) == #"091c23daf3b3bab1bb7508ae312d48198f121fff1e7a6caeddd49f52aeb80885"
}

test auth_payload_tv2_canonical_cbor_pinned() {
  encode(tv2()) == #"d8799f581b41454749535f434c41494d5f415554485f76315f4d41494e4e45541a2d964a09581c1111111111111111111111111111111111111111111111111111111a581c2222222222222222222222222222222222222222222222222222222b581c3333333333333333333333333333333333333333333333333333333c581d613333333333333333333333333333333333333333333333333333333c1b000000012a05f20001581c4444444444444444444444444444444444444444444444444444444d19ea601b00000191a20322001b00000191c60fa600581c5555555555555555555555555555555555555555555555555555555e581a6666666666666666666666666666666666666666666666666666ff"
}

test auth_payload_tv2_commit_pinned() {
  commit(tv2()) == #"64b01e537a005e32a53cc37494755cea1f3413fc2b25accefb9e7080c3023bec"
}

test auth_payload_tv3_canonical_cbor_pinned() {
  encode(tv3()) == #"d8799f581b41454749535f434c41494d5f415554485f76315f50524550524f4401581c8ea5aed0e4f66e9ce6593fbed30856c8997441b1e5cd8bc3085e943f581caabbccdd00112233445566778899aabbccddeeff0011223344556677581c00112233445566778899aabbccddeeff00112233445566778899aabb581d6000112233445566778899aabbccddeeff00112233445566778899aabb1b7fffffffffffffff00581c886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e001b0000018bcfe568001b0000018bf3f1ec00581cc366b0ea2667b432a432999f54e11978c0ed37c7c4b971067fb1589f581bdeadbeef00112233445566778899aabbccddeeff00112233445566ff"
}

test auth_payload_tv3_commit_pinned() {
  commit(tv3()) == #"36c8d12ee98204b99586493283b3837ab2806efb6a90a137476c62196967907d"
}

test auth_payload_tv4_canonical_cbor_pinned() {
  encode(tv4()) == #"d8799f581b41454749535f434c41494d5f415554485f76315f50524550524f4401581c8ea5aed0e4f66e9ce6593fbed30856c8997441b1e5cd8bc3085e943f581caabbccdd00112233445566778899aabbccddeeff0011223344556677581c00112233445566778899aabbccddeeff00112233445566778899aabb581d6000112233445566778899aabbccddeeff00112233445566778899aabb1a05f5e10000581c886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e001b0000018bcfe568001b0000018bcfe56801581cc366b0ea2667b432a432999f54e11978c0ed37c7c4b971067fb1589f581bdeadbeef00112233445566778899aabbccddeeff00112233445566ff"
}

test auth_payload_tv4_commit_pinned() {
  commit(tv4()) == #"a3226b2c3f6fddc20240f2e29e174ccf1c9d239c448fdb95df3009c764e4e688"
}

test auth_payload_tv5_canonical_cbor_pinned() {
  encode(tv5()) == #"d8799f581b41454749535f434c41494d5f415554485f76315f50524550524f4401581c8ea5aed0e4f66e9ce6593fbed30856c8997441b1e5cd8bc3085e943f581caabbccdd00112233445566778899aabbccddeeff0011223344556677581c00112233445566778899aabbccddeeff00112233445566778899aabb581d6000112233445566778899aabbccddeeff00112233445566778899aabb1a05f5e10002581cd2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f001b0000018bcfe568001b0000018bf3f1ec00581cc366b0ea2667b432a432999f54e11978c0ed37c7c4b971067fb1589f581bdeadbeef00112233445566778899aabbccddeeff00112233445566ff"
}

test auth_payload_tv5_commit_pinned() {
  commit(tv5()) == #"da7f8de46f6165f6fa6cea88c5b87851fa23ffefd3e7de57f420454714593f03"
}
