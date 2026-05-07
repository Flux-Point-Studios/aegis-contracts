// =============================================================================
// Aegis Insurance Protocol - Type Definitions
// Location: contracts/lib/aegis/types.ak
// Summary: All on-chain datum and redeemer types used across the protocol.
//          Imported by validators (policy.ak, pool.ak, lp_token.ak) and
//          helper modules (oracle.ak, pricing.ak, validation.ak, pool.ak).
// =============================================================================

use aiken/crypto.{Blake2b_224, Hash, Script, VerificationKey, blake2b_224}
use aiken/primitive/bytearray
use cardano/transaction.{OutputReference}

// ---------------------------------------------------------------------------
// Type Aliases
// ---------------------------------------------------------------------------

/// Payment key hash for identifying users
pub type VerificationKeyHash =
  Hash<Blake2b_224, VerificationKey>

/// Script hash for identifying validators
pub type ScriptHash =
  Hash<Blake2b_224, Script>

// ---------------------------------------------------------------------------
// Oracle Provider Tag (Aegis v6)
// ---------------------------------------------------------------------------

/// [v7] Oracle provider tag. Aegis v7 supports three providers — Charli3
/// (mainnet primary), Orcfax (redundant secondary; provider winding down
/// 2026-07-31), and AegisSelf (Aegis-published feed; vendor-survival-
/// independent fallback). Sum-type semantics give us compile-time
/// exhaustivity — adding a new provider in the future requires a redeploy
/// that visibly rotates the validator hash, which IS the curated whitelist.
///
/// CBOR encoding: `Charli3 = constr_0([])`, `Orcfax = constr_1([])`,
/// `AegisSelf = constr_2([])`. Minimal on-chain bytes (1 byte for the
/// constr index + empty list of fields).
///
/// Why a sum type and not a free-form `oracle_script_hash: ByteArray`:
///   * A free-form ByteArray would require a second runtime check ("is this
///     hash whitelisted?"), either as a hardcoded list (which defeats the
///     point — adding a provider would still need a redeploy) or as a separate
///     registry UTxO (large new audit surface). A sum-type variant *is* the
///     whitelist, enforced by Aiken's exhaustivity check on `when` branches.
///   * Type-safe parser dispatch. The validator's
///     `when datum.oracle_provider is { Charli3 -> ... | Orcfax -> ... |
///     AegisSelf -> ... }` branches each call a provider-specific resolver-
///     and-parser without casting Data through unsafe holes.
///
/// Trade-off: adding a fourth provider in v8 (e.g., Pyth Lazer once GA on
/// Cardano) requires another datum-schema rotation. Frequency of new
/// providers we'd actually trust enough to onboard is bounded; each onboarding
/// deserves its own audit pass anyway. A datum rotation per onboarding is
/// the right cadence.
pub type OracleProvider {
  /// Charli3 ODV (Oracle Data Verification). Single canonical UTxO at a
  /// Charli3-controlled validator address, identified by an oracle NFT
  /// (`oracle_nft` field below carries the NFT policy id). Datum is
  /// `OracleDatum { price_data: GenericData { Map<Int,Int> } }` with
  /// keys 0=price (1e6-scaled), 1=created_at, 2=expiry — see
  /// `aegis/oracle/charli3` for the parser.
  Charli3
  /// Orcfax V1. Two-layer pointer indirection (FSP -> FS): the consumer
  /// references both an FSP UTxO (whose datum carries the dynamic FS hash)
  /// and the FS UTxO whose datum is `FsDat<Rational>`. For Orcfax-bound
  /// policies, the `oracle_nft` field below carries the FSP script hash
  /// (NOT the NFT policy id) — see `aegis/oracle/orcfax` for the parser.
  Orcfax
  /// [v7 NEW] Aegis-self. We publish ADA/USD ourselves at a UTxO under a
  /// one-shot-minted NFT (AEGIS_PRICE_FEED_V1) at the publisher wallet's
  /// payment credential. Same Charli3-compatible CBOR datum format as
  /// `Charli3` so we reuse the parser; the trust handshake pins both NFT
  /// policy id (`oracle_nft` field) AND publisher VKH (compile-time
  /// constant `aegis_self_publisher_vkh`). Vendor-survival-independent —
  /// keeps Aegis claimable even if Charli3 dissolves and Orcfax sunsets.
  AegisSelf
}

// ---------------------------------------------------------------------------
// Policy Datum
// ---------------------------------------------------------------------------

/// The datum stored in each insurance policy UTxO.
/// Contains all terms of the insurance contract.
///
/// [v6 schema] PolicyDatum has 11 positional fields. The new
/// `oracle_provider` tag is APPENDED to the end of the schema so existing
/// v5 (10-field) policies remain forensically decodable; their datums simply
/// fail the v6 `expect pdat: PolicyDatum = raw_pdat` check, which is the
/// intended migration semantics — v5 policies are stranded after the v6
/// redeploy and must be cleaned up via Expire/Cancel paths against the v5
/// validator (still on chain at the v5 hash).
pub type PolicyDatum {
  /// Unique identifier for this policy (hash of concatenated terms)
  policy_id: ByteArray,
  /// Payment key hash of the insured party (beneficiary)
  insured: VerificationKeyHash,
  /// ADA/USD price threshold for payout trigger (scaled by 1e6)
  /// Example: $0.35 = 350_000
  strike_price: Int,
  /// Maximum payout in lovelace
  /// Example: 5000 ADA = 5_000_000_000
  coverage_amount: Int,
  /// Premium paid by the insured in lovelace
  premium_paid: Int,
  /// Policy effective start time (POSIX milliseconds)
  start_time: Int,
  /// Policy expiration time (POSIX milliseconds)
  expiry_time: Int,
  /// Provider-dependent oracle handle. Field name retained for v5
  /// backwards-compat at the schema level, but semantics now branch on
  /// `oracle_provider`:
  ///   * `Charli3` -> Charli3 oracle NFT policy id (matches a token in the
  ///     value of the canonical oracle UTxO at `charli3_oracle_script_hash`).
  ///   * `Orcfax`  -> Orcfax FSP (Feed Source Pointer) script hash. The FS
  ///     hash itself is resolved at runtime by reading the FSP datum, so it
  ///     does NOT live in the policy datum.
  oracle_nft: ByteArray,
  /// Payment script hash of the pool validator for returning funds
  pool_script_hash: ScriptHash,
  /// [FIX A-008] NFT identifying the canonical pool. Used by Claim/Expire/Cancel
  /// to verify that the residual is sent to the REAL pool UTxO (one carrying
  /// `pool_nft`), not just any UTxO at `pool_script_hash`. Without this binding
  /// an attacker could route policy residuals to a stuck UTxO at the pool address
  /// that the pool validator can't subsequently spend.
  pool_nft: ByteArray,
  /// [v6 NEW] Oracle provider tag. Selects the parser (and trust handshake)
  /// used at Claim/BatchClaim/Cancel time. Aegis v6 ships `Charli3` (default
  /// primary) and `Orcfax` (redundant secondary) so a single oracle outage,
  /// deprecation, or governance breakdown cannot brick the protocol. Pinned
  /// at policy-creation time and immutable for the policy's lifetime —
  /// ensures the trust handshake the insured agreed to at premium-payment
  /// time is the same one enforced at claim time.
  oracle_provider: OracleProvider,
  /// [v8 NEW / RELAY-PRESIGNED-AUTH] 32-byte BLAKE2b-256 of the canonical
  /// CBOR encoding of the `AuthCoveragePayload` the insured signed off-chain
  /// to authorize a relay to file a claim on their behalf. `None` means the
  /// insured opted out of relay coverage at policy-creation time and only
  /// the in-browser auto-claim or a manually-built tx can spend the policy
  /// via `Claim`/`BatchClaim`. `Some(commit)` permits the additional
  /// `ClaimWithAuth` and `RotateAuth` redeemers gated on a witness UTxO
  /// reference whose payload hashes to `commit`.
  ///
  /// This 12-field schema is INCOMPATIBLE with the v6.0.2 11-field
  /// `PolicyDatum` — the existing preprod policy `23889dec…` is stranded
  /// against the v8 validator hash. Pre-redeploy the operator must Cancel
  /// or Expire that policy against the v6.0.2 validator (still on-chain).
  auth_commitment: Option<ByteArray>,
}

// ---------------------------------------------------------------------------
// Pool Datum
// ---------------------------------------------------------------------------

/// The datum stored in the liquidity pool UTxO.
/// Tracks aggregate pool state.
pub type PoolDatum {
  /// Total ADA deposited by liquidity providers (lovelace)
  total_liquidity: Int,
  /// ADA currently reserved as coverage for active policies (lovelace)
  active_coverage: Int,
  /// Minting policy ID for LP tokens
  lp_token_policy: ByteArray,
  /// Protocol fee in basis points (e.g., 200 = 2%)
  protocol_fee_bps: Int,
  /// NFT identifying this unique pool UTxO
  pool_nft: ByteArray,
  /// [FIX A-003] Outstanding aLP token supply.
  /// Tracked on-chain so the pool validator can verify the exact mint or
  /// burn quantity matches `calculate_lp_mint` / `calculate_withdrawal`,
  /// preventing direction-flip attacks (mint during Remove, burn during Add).
  lp_supply: Int,
}

// ---------------------------------------------------------------------------
// Policy Redeemer
// ---------------------------------------------------------------------------

/// Actions that can be performed on a policy UTxO
pub type PolicyRedeemer {
  /// Trigger an insurance payout (single policy per tx).
  Claim
  /// Batch-claim multiple policies in a single transaction.
  BatchClaim
  /// Reclaim funds after policy has expired (single).
  Expire
  /// Batch-expire multiple policies in a single transaction.
  BatchExpire
  /// Cancel a policy within the cancellation window.
  Cancel
  /// [v8 NEW] Relay-driven claim path. The relay supplies a 64-byte raw
  /// Ed25519 signature `sig` over `datum.auth_commitment` (the 32-byte
  /// BLAKE2b-256 of the insured's canonical-CBOR `AuthCoveragePayload`).
  /// The validator iterates `reference_inputs`, locates the unique witness
  /// UTxO carrying the canonical `auth_witness_nft_policy_id` token whose
  /// asset name equals `blake2b_224(datum.policy_id)`, decodes its
  /// `AuthWitnessDatum`, and asserts: payload hashes to commit, vkey hashes
  /// to insured PKH, signature verifies, oracle provider matches policy,
  /// payout address equals enterprise address of insured. The same Claim
  /// invariants (oracle freshness, time bounds, A-009 enterprise payout
  /// aggregate, A-008 residual to canonical pool, F-001 single-script-input
  /// global guard) all apply.
  ClaimWithAuth { sig: ByteArray }
  /// [v8 NEW] Rotate the auth commitment without paying out — used when the
  /// insured wants to invalidate an old auth (suspected Aegis-seed share
  /// leak, payout-address rotation, oracle-provider rotation by re-mint).
  /// Gated by a CIP-30 main-wallet `extra_signatories` check on
  /// `datum.insured`. Re-uses the policy UTxO (consumed and recreated) and
  /// requires a fresh witness UTxO at `auth_witness_validator_hash` carrying
  /// the new commitment in its datum.
  RotateAuth { new_commit: ByteArray, new_witness_ref: OutputReference }
}

// ---------------------------------------------------------------------------
// [v8 NEW] Auth Coverage Payload + Witness Datum
// ---------------------------------------------------------------------------

/// [v8] The off-chain payload the insured signs (with their Aegis-wallet
/// Ed25519 key) at policy-creation time to authorize a relay to file a
/// claim on their behalf. Encoded as canonical CBOR (constructor-zero
/// indefinite-length, matching `cbor.serialise`); the BLAKE2b-256 of that
/// CBOR is the `auth_commitment` stored in the policy datum.
///
/// FIELD ORDER IS LOAD-BEARING. Cross-stack tools (TypeScript via
/// `@stricahq/cbors`, Python via `cbor2`, on-chain via `cbor.serialise`)
/// must produce byte-identical CBOR; the field order here defines the
/// canonical ordering for all three encoders. See Appendix B of
/// RELAY_PRESIGNED_AUTH_SCOPE_v2.md for the reference test vectors.
pub type AuthCoveragePayload {
  /// Network-specific bytes — `"AEGIS_CLAIM_AUTH_v1_PREPROD"` or
  /// `"AEGIS_CLAIM_AUTH_v1_MAINNET"` (or `_PREVIEW`). Combined with
  /// `network_magic` no signature can replay across networks even if the
  /// user shares an Ed25519 keypair across them (BIP-44 derivation does).
  domain_tag: ByteArray,
  /// Cardano network magic — 1 for preprod, 2 for preview, 764824073 for
  /// mainnet. Numeric guard alongside the textual `domain_tag`.
  network_magic: Int,
  /// 28-byte v8 policy_validator script hash. Pinned at sig time so a
  /// future redeploy of the policy validator (which rotates the hash)
  /// invalidates all outstanding auths — visible trust signal.
  policy_validator: ByteArray,
  /// `PolicyDatum.policy_id` — derived per `derive_policy_id` (§1.8).
  policy_id: ByteArray,
  /// `PolicyDatum.insured` — VKH of the insured.
  insured_pkh: ByteArray,
  /// 29-byte enterprise CIP-19 address bytes (header byte 0x60/0x61 +
  /// 28-byte payment_credential VKH). For preprod/preview the header is
  /// 0x60; for mainnet it is 0x61. The validator computes this canonically
  /// from `datum.insured` via `enterprise_addr_of` and asserts equality.
  payout_address: ByteArray,
  /// `PolicyDatum.coverage_amount` (lovelace).
  max_coverage: Int,
  /// `PolicyDatum.oracle_provider` encoded as a Constr index — 0=Charli3,
  /// 1=Orcfax, 2=AegisSelf. Stored as `Int` here (rather than the sum
  /// type) so the canonical CBOR is shape-stable across stacks; the
  /// validator and mint policy assert it matches the policy datum's tag.
  oracle_provider: Int,
  /// `PolicyDatum.oracle_nft` — provider-specific handle. For Charli3 +
  /// AegisSelf this is the NFT policy id; for Orcfax this is the FSP
  /// script hash.
  oracle_nft: ByteArray,
  /// Advisory milliseconds — informational (not enforced on-chain).
  /// Encoded explicitly as `Int` (NOT `Option<Int>`) so the field is
  /// always present with a numeric value; off-chain UIs may display it
  /// to the user as part of the human-readable signing prompt (Δ16). A
  /// value of `0` denotes "no specific freshness commitment".
  oracle_freshness: Int,
  /// `PolicyDatum.start_time` (POSIX milliseconds).
  not_before: Int,
  /// `PolicyDatum.expiry_time` (POSIX milliseconds).
  not_after: Int,
  /// `PolicyDatum.pool_script_hash`.
  pool_script_hash: ByteArray,
  /// `PolicyDatum.pool_nft`.
  pool_nft: ByteArray,
}

/// [v8] Datum stored at the `auth_witness_validator` address, carrying the
/// insured's pre-signed coverage payload for the relay to use later. The
/// witness UTxO is created atomically with the policy at Underwrite (Δ1)
/// and CANNOT be spent except via the auth-NFT-burn-only path (§1.6) —
/// i.e., it is reference-only for `ClaimWithAuth` and `RotateAuth`.
pub type AuthWitnessDatum {
  /// Must equal `PolicyDatum.policy_id` of the bound policy. The validator
  /// re-asserts this; a witness whose `policy_id` mismatches the policy is
  /// rejected.
  policy_id: ByteArray,
  /// 32-byte Ed25519 verification key of the AEGIS WALLET (NOT the CIP-30
  /// main wallet). The validator asserts `blake2b_224(insured_vkey) ==
  /// datum.insured` so a substituted vkey under a controlled signature
  /// fails the binding (closes C-2).
  insured_vkey: ByteArray,
  /// Canonical-CBOR-encoded `AuthCoveragePayload`. Stored on-chain so any
  /// relay can verify locally without an off-chain registry. The validator
  /// re-decodes this at claim time (cheap — one CBOR decode + one
  /// BLAKE2b-256) so the payload semantics are NOT trusted from the
  /// commitment alone.
  payload_cbor: ByteArray,
  /// 64-byte raw Ed25519 signature over `blake2b_256(payload_cbor)`. Equal
  /// to the `sig` carried in the `ClaimWithAuth` redeemer (the validator
  /// asserts redundancy: both must match — defense in depth so a relay
  /// cannot present a stale witness with a fresh redeemer-supplied sig
  /// for a different commitment).
  signature: ByteArray,
}

// ---------------------------------------------------------------------------
// Pool Redeemer
// ---------------------------------------------------------------------------

/// Actions that can be performed on the pool UTxO
pub type PoolRedeemer {
  /// Reserve coverage for a new insurance policy (single)
  Underwrite {
    /// Coverage amount in lovelace to reserve
    coverage: Int,
    /// Premium collected in lovelace
    premium: Int,
  }
  /// Process a claim payout from the pool. [v6.0.2 / L-006 fix] The
  /// `policy_script` redeemer field has been removed — the validator now
  /// resolves the policy script credential via the pool_validator's
  /// compile-time `policy_script_hash` parameter, closing the surface
  /// where an attacker-deployed permissive script could be supplied via
  /// the redeemer to drain the pool through fake `PolicyDatum` UTxOs.
  ProcessClaim {
    /// Amount to pay out in lovelace
    payout: Int,
  }
  /// Deposit ADA into the liquidity pool
  AddLiquidity {
    /// Amount being deposited in lovelace
    amount: Int,
  }
  /// Withdraw ADA from the liquidity pool
  RemoveLiquidity {
    /// Amount being withdrawn in lovelace
    amount: Int,
  }
  /// Batch-underwrite: create N policies in a single transaction
  BatchUnderwrite {
    /// Total coverage across all policies
    total_coverage: Int,
    /// Total premium collected across all policies
    total_premium: Int,
  }
  /// Process batch-expire: return expired policy funds to pool. [v6.0.2 /
  /// L-006 fix] `policy_script` removed; validator uses the parameterized
  /// `policy_script_hash`.
  BatchExpireProcess {
    /// Total lovelace being returned from expired policies
    total_returned: Int,
  }
  /// [FIX A-020] Process a cancellation. Consumes a Cancel-redeemed policy,
  /// sends the canonical refund (90% of premium) to the insured, decrements
  /// `active_coverage` by the consumed policy's coverage, and retains the
  /// 10% cancellation fee in the pool. The refund magnitude is derived
  /// on-chain from the consumed policy's `premium_paid` (NOT a caller-
  /// controlled amount), so an over-refund cannot drain the pool.
  ///
  /// [v6.0.2 / L-006 fix] `policy_script` removed; validator uses the
  /// parameterized `policy_script_hash`.
  AcceptCancellation
}

// ---------------------------------------------------------------------------
// LP Token Redeemer
// ---------------------------------------------------------------------------

/// Actions for the LP token minting policy
pub type LPTokenRedeemer {
  /// Mint new LP tokens (when adding liquidity)
  MintLP
  /// Burn LP tokens (when removing liquidity)
  BurnLP
}

// ---------------------------------------------------------------------------
// Protocol Constants
// ---------------------------------------------------------------------------

/// Minimum premium in lovelace (2 ADA)
pub const min_premium: Int = 2_000_000

/// Maximum coverage-to-premium ratio (50x leverage)
pub const max_coverage_ratio: Int = 50

/// Cancellation window in milliseconds (1 hour)
pub const cancellation_window: Int = 3_600_000

/// Cancellation fee in basis points (1000 = 10%)
pub const cancellation_fee_bps: Int = 1_000

/// Price scaling factor (Charli3 uses 1e6)
pub const price_scale: Int = 1_000_000

/// Minimum ADA in a UTxO (lovelace)
pub const min_utxo_lovelace: Int = 2_000_000

/// Share of the protocol fee (NOT premium) routed to the Cardano treasury via
/// the Conway-era `treasury_donation` body field. Expressed in basis points of
/// the protocol fee, NOT of the premium itself: `treasury_cut = floor(premium *
/// protocol_fee_bps / 10_000 * treasury_share_bps / 10_000)`. At the current
/// pin (`protocol_fee_bps = 200`, `treasury_share_bps = 2500`) this means 25%
/// of the 2% protocol fee = 0.5% of the premium routes to the treasury.
///
/// This is a compile-time constant rather than a `PoolDatum` field so the
/// economic terms are pinned by validator hash. Any change requires a
/// redeploy, which prevents an operator from silently turning the donation
/// into an extraction vector via datum mutation.
pub const treasury_share_bps: Int = 2_500

/// [FIX A-016] Canonical Charli3 oracle script hash on Cardano preprod.
/// `find_oracle_datum` validates that the reference input carrying the
/// Charli3 NFT is at THIS specific script address — preventing forged
/// oracle data via attacker-deployed UTxOs that hold a stolen or moved
/// Charli3 NFT. Hardcoded as a compile-time constant so the binding is
/// pinned by validator hash; any rotation in Charli3's oracle script
/// requires an Aegis redeploy, which is the correct trust handshake.
///
/// Address: addr_test1wq3pacs7jcrlwehpuy3ryj8kwvsqzjp9z6dpmx8txnr0vkq6vqeuu
pub const charli3_oracle_script_hash: ByteArray =
  #"221ee21e9607f766e1e1223248f67320014825169a1d98eb34c6f658"

/// [v6.0.2 / A-026-class fix] Charli3 ADA/USD oracle NFT policy id.
///
/// Pinned at compile time alongside `charli3_oracle_script_hash` so the
/// trust handshake is BOTH legs of the address+NFT pair, not just the
/// address. Pre-fix, the `oracle_nft` field of `PolicyDatum` was caller-
/// controlled — an attacker could output a fake-NFT UTxO at the canonical
/// Charli3 address (anyone can output to any address, only spending is
/// gated) and have the parser read attacker-controlled price data.
///
/// Preprod value (live ODV oracle for ADA/USD); rotate on mainnet build.
/// On-chain validators are rebuilt per-network so this constant is
/// network-specific in practice; the visible validator-hash rotation is
/// the governance signal that the binding has changed.
pub const charli3_ada_usd_nft_policy: ByteArray =
  #"886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e"

// ---------------------------------------------------------------------------
// Orcfax Feed Source Pointer (FSP) Hashes (Aegis v6)
// ---------------------------------------------------------------------------

/// [v6] Orcfax Feed Source Pointer (FSP) script hash on Cardano preview.
///
/// Orcfax uses a two-layer indirection unlike Charli3's single canonical UTxO:
///   * **FSP** ("FactStatementPointer") is a STABLE UTxO whose inline datum is
///     a ByteArray holding the *current* FS (Fact Statement) script hash. The
///     FSP script hash is the immutable handle Orcfax publishes for an
///     integrator. If Orcfax rotates the FS validator (protocol upgrade), the
///     FSP datum is updated to point at the new hash; integrators NEVER have
///     to redeploy.
///   * **FS** ("FactStatement") is the per-fact UTxO containing the actual
///     price datum (`FsDat<Rational>`). The FS NFT lives under a policy that
///     EQUALS the FS validator script hash — i.e., the policy is the validator
///     (a parameterless minting+spending validator with the same script).
///
/// We pin the FSP hash here; the FS hash is resolved at runtime from the FSP
/// datum. This is Orcfax's answer to Charli3's "if we rotate the script,
/// every integrator must redeploy" problem — and the same problem Aegis hit
/// explicitly in A-016. For Aegis it is a feature: routine Orcfax upgrades
/// do not strand existing Aegis policies.
///
/// Source: <https://docs.orcfax.io/consume>.
pub const orcfax_fsp_script_hash_preview: ByteArray =
  #"0690081bc113f74e04640ea78a87d88abbd2f18831c44c4064524230"

/// [v6] Orcfax FSP script hash on Cardano mainnet (for future mainnet deploy).
///
/// Source: <https://docs.orcfax.io/consume>.
pub const orcfax_fsp_script_hash_mainnet: ByteArray =
  #"8793893b5dda6a513ba63c80e9d7b2d4f108060c11979bfc7d863ff0"

/// [v6] Orcfax CER/ADA-USD feed identifier as raw UTF-8 bytes.
///
/// Hex `4345522f4144412d5553442f` decodes to the ASCII string
/// `"CER/ADA-USD/"`. The trailing `/` is **mandatory** per Orcfax's
/// `feed_id.ak` (test `test_mk_feed_id_b`) — the docstring explains it
/// "prevents `ADA-USDM` being a match for `ADA-USD`". Aegis matches with
/// `starts_with` rather than equality so a future Orcfax-versioned feed
/// (e.g., `CER/ADA-USD/3/`) is forward-compatible without an Aegis redeploy.
pub const orcfax_ada_usd_feed_id: ByteArray = #"4345522f4144412d5553442f"

/// [v6] Orcfax FS NFT asset name. Per Orcfax's `lib/orcfax/tokens.ak` the FS
/// asset name is the empty bytestring (`""`) — the FS NFT is uniquely
/// identified by its policy id (= the FS validator hash) alone. This is
/// distinct from Charli3 which uses a labeled `#"4f5241434c45"` ("ORACLE")
/// asset name on its NFT.
pub const orcfax_fs_asset_name: ByteArray = #""

/// [v6] Orcfax FSP NFT asset name (CIP-67 reference NFT label `000de140`
/// concatenated with the empty `fsp_label`). Per Orcfax's
/// `lib/orcfax/tokens.ak`: `fsp_vali = #"000de140" <> fsp_label = ""`.
pub const orcfax_fsp_asset_name: ByteArray = #"000de140"

/// [v7] Orcfax freshness window in POSIX milliseconds (70 min).
///
/// Orcfax's `FsDat<Rational>` carries NO `expiry` field — the only timestamp
/// is `created_at`. Freshness is the consumer's responsibility, enforced via
/// `lb - created_at < max_freshness_ms` AND `ub - lb < max_freshness_ms` to
/// pin both sides of the validity window.
///
/// **v6 used 30 min; v7 widened to 70 min** based on empirical mainnet
/// observation (2026-05-04 via Kupo, 53 ADA-USD publishes over 39h):
/// mean gap 45 min, p95 51 min, max 55 min. Configured Orcfax cadence is a
/// 1h heartbeat (`cer-feeds/feeds/mainnet/cer-feeds.json`: `interval: 3600,
/// deviation: 1`). v6's 30-min window would false-reject ~95% of legitimate
/// fresh-but-late readings; 70 min gives a 15-min buffer beyond worst-case
/// observed and absorbs ledger lower-bound padding.
pub const orcfax_freshness_window_ms: Int = 70 * 60 * 1_000

/// [v6.0.2 / A-027 fix] Active-network Orcfax FSP script hash.
///
/// Set per build target. Pre-fix, the Orcfax parser took the FSP hash as a
/// caller-supplied argument (sourced from `PolicyDatum.oracle_nft`) and
/// pinned the FSP UTxO's script credential to the SAME caller-supplied
/// value — letting an attacker deploy a permissive FSP+FS pair under their
/// own hash and reference them. The post-fix parser asserts the supplied
/// `fsp_hash` equals THIS pinned constant before any UTxO lookup runs.
///
/// Currently set to the preview value (Aegis-on-preview is the only
/// deployment that consumes Orcfax — preprod has no Orcfax, mainnet not
/// yet shipped). Promoting to mainnet flips this to
/// `orcfax_fsp_script_hash_mainnet` and rotates the validator hash, which
/// IS the visible trust signal.
pub const orcfax_fsp_script_hash: ByteArray =
  #"0690081bc113f74e04640ea78a87d88abbd2f18831c44c4064524230"

// ---------------------------------------------------------------------------
// Aegis-self Publisher Constants (Aegis v7)
// ---------------------------------------------------------------------------

/// [v7] Aegis-self publisher payment-key-hash (= the VKH that signs all
/// publish txs). Derived from the publisher mnemonic at
/// `D:/wallet/publisher_mnemonic.txt` via path `m/1852'/1815'/0'/0/0`.
///
/// The `aegis/oracle/aegis_self.ak` parser pins this VKH so a forged UTxO
/// at a different credential — even one carrying an AEGIS_PRICE_FEED_V1
/// NFT moved by a key compromise — is rejected by the validator. Combined
/// with the per-network NFT policy id (passed via `PolicyDatum.oracle_nft`
/// at policy-creation time), this is a two-layer trust handshake.
///
/// **Network coverage**: BIP-44 derivation uses the same VKH on testnet
/// (preprod, preview) AND mainnet — only the network header byte in the
/// bech32 address differs. So this single constant is correct across all
/// three networks. If we later separate the mainnet wallet for production
/// hygiene (different mnemonic), this constant becomes per-network.
///
/// Typed as `ByteArray` rather than the `VerificationKeyHash` alias because
/// `Hash<Blake2b_224, VerificationKey>` is an opaque type from `aiken/crypto`
/// and can't be initialized from a literal — same reason
/// `charli3_oracle_script_hash` above is `ByteArray`, not `ScriptHash`.
pub const aegis_self_publisher_vkh: ByteArray =
  #"6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152"

// ---------------------------------------------------------------------------
// [v8 NEW] Auth Witness Constants
// ---------------------------------------------------------------------------

/// [v8] Network-specific Ed25519 signing-domain tag for `AuthCoveragePayload`.
/// Combined with `network_magic` no signature can replay across networks
/// even if the user shares an Ed25519 keypair across them. The tag is the
/// FIRST field of the canonical CBOR payload (§2.1) so any cross-network
/// replay attempt fails the in-validator decode-and-recompare check.
///
/// Pinned to the preprod tag for the current build target. Per-network
/// rotation is via a redeploy that swaps this constant — the visible
/// validator-hash rotation IS the trust signal that the network binding
/// changed. Mainnet build will set this to `auth_domain_tag_mainnet`.
pub const auth_domain_tag: ByteArray =
  #"41454749535f434c41494d5f415554485f76315f50524550524f44"

/// [v8] UTF-8 of `"AEGIS_CLAIM_AUTH_v1_PREPROD"` — re-exposed as a named
/// constant so tests can compare by alias rather than re-typing hex.
pub const auth_domain_tag_preprod: ByteArray =
  #"41454749535f434c41494d5f415554485f76315f50524550524f44"

/// [v8] UTF-8 of `"AEGIS_CLAIM_AUTH_v1_PREVIEW"`.
pub const auth_domain_tag_preview: ByteArray =
  #"41454749535f434c41494d5f415554485f76315f50524556494557"

/// [v8] UTF-8 of `"AEGIS_CLAIM_AUTH_v1_MAINNET"`.
pub const auth_domain_tag_mainnet: ByteArray =
  #"41454749535f434c41494d5f415554485f76315f4d41494e4e4554"

/// [v8] Cardano network magic — 1 for preprod (current), 2 for preview,
/// 764824073 for mainnet. Pinned at compile time alongside the domain tag.
pub const network_magic_preprod: Int = 1

pub const network_magic_preview: Int = 2

pub const network_magic_mainnet: Int = 764_824_073

/// [v8] Active-build network magic. Set per build target — flipping this
/// value rotates the validator hash, which is the visible trust signal
/// that the network binding has changed.
pub const network_magic: Int = 1

/// [v8] One-shot-minted `auth_witness_nft` policy id. Pinned at compile
/// time so the `auth_witness_validator` self-check rejects any witness
/// UTxO whose token does NOT match this canonical policy id (closes the
/// redeemer-controlled-identifier anti-pattern flagged in round 6 /
/// Δ17). The mint policy is parameterized over `(init_utxo_ref,
/// network_tag, operator_pkh)`; a fresh mint per network produces a
/// different policy id. Update this constant per build target.
///
/// Placeholder until first preprod deploy of the auth_witness_nft minting
/// policy (post-Phase-1). The compile-time pin enforces "this validator
/// only trusts witness NFTs from THIS minting policy"; a wrong constant
/// would silently never match any witness UTxO at validation time
/// (fail-closed), making length-checked tests below load-bearing as a
/// regression guard against typos.
///
/// [v8 / Δ41 — v3.2 + Δ42 — v3.3 deploy-cycle break] Used by
/// `auth_witness_validator` (self-check on the witness UTxO's
/// `own_value`). The `policy_validator` does NOT reference this
/// constant directly; instead it asserts the witness UTxO sits at
/// `auth_witness_validator_hash` (script-credential equality). The
/// two checks compose transitively: only legit-minted NFTs can ever
/// reach the auth_witness_validator script address (via the spend-
/// path's burn-or-respend self-check on `own_value`), and only UTxOs
/// at that script address are accepted as witnesses by
/// policy_validator — same security as the pre-v3.2 token-policy-id
/// binding.
///
/// [Δ42 — v3.3] The `auth_witness_nft.ak` mint validator no longer
/// references `auth_witness_validator_hash` either: the Underwrite-
/// path destination check is dropped and replaced by a per-tx
/// "EXACTLY ONE output carries this asset + matching AuthWitnessDatum"
/// pin. This makes the mint policy's compiled hash INDEPENDENT of the
/// `auth_witness_validator_hash` constant value, closing the v3.2
/// second-order deploy cycle and enabling a truly linear deploy
/// ordering (see `auth_witness_validator_hash` doc below).
///
/// Updated post-deploy via the deploy ordering documented in §12.4 of
/// `RELAY_PRESIGNED_AUTH_SCOPE_v2.md`. The `check_deploy_constants.py`
/// gate enforces both auth-related constants are non-placeholder
/// before mainnet tag.
pub const auth_witness_nft_policy_id: ByteArray =
  #"6a468ac08682ac2ae89cde1cdbec4f4761504cea10290eb610eb23f4"

/// [v8 / Δ41 — v3.2 + Δ42 — v3.3 deploy-cycle break] Compile-time-pinned
/// 28-byte script hash of the deployed `auth_witness_validator`. The
/// `policy_validator` references THIS constant when locating witness
/// UTxOs (`ClaimWithAuth` and `RotateAuth` branches), via a
/// `Script(auth_witness_validator_hash)` payment-credential equality
/// check on the candidate UTxO's address. Pre-v3.2 the policy
/// validator referenced `auth_witness_nft_policy_id` (the NFT policy
/// id) at the same call sites, which created a circular deploy dep:
/// `auth_witness_nft` was parameterized over `policy_validator_hash`,
/// while `policy_validator` referenced `auth_witness_nft_policy_id` —
/// neither hash converges at deploy time. v3.2 broke the first-order
/// cycle by having `policy_validator` bind to the
/// auth_witness_validator script hash instead; v3.3 closes the
/// second-order cycle (Δ42) by also dropping all references to this
/// constant from `auth_witness_nft.ak`, so this constant's value
/// affects ONLY the `policy_validator` compiled hash.
///
/// The auth_witness_validator's own self-check on `own_value` (using
/// `auth_witness_nft_policy_id`) is the security backbone — only
/// legit-minted witnesses can ever exist at that script address.
///
/// **Deploy ordering** (post-Δ42 / v3.3 — linear, acyclic, 5 rebuilds):
///
///   1. Build with both `auth_witness_nft_policy_id` and
///      `auth_witness_validator_hash` at the all-zeros placeholder.
///      `auth_witness_nft.mint` base hash is STABLE (no const
///      dependency post-Δ42).
///   2. Apply `auth_witness_nft(init_utxo_ref, network_tag,
///      operator_pkh)` — 3 params, NO `policy_validator_hash` and NO
///      reference to `auth_witness_validator_hash` → stable
///      `auth_witness_nft_policy_id`.
///   3. Bake `auth_witness_nft_policy_id` const → rebuild →
///      `auth_witness_validator.spend` hash freezes (depends only on
///      this const).
///   4. Bake `auth_witness_validator_hash` const → rebuild →
///      `policy_validator.spend` hash freezes (depends only on this
///      const). `auth_witness_nft.mint` base hash does NOT change at
///      this step (Δ42 invariant).
///   5. Mint pool NFT, deploy reference scripts, init pool (existing
///      v6.0.2 → v8 procedure). The pool validator's compile-time
///      `policy_script_hash` parameter consumes the
///      policy_validator hash from step 4.
///
/// Placeholder until first preprod deploy of the auth_witness_validator
/// (post-Phase-1, step 4 above). The compile-time pin enforces "this
/// validator only trusts witness UTxOs sitting at THIS validator
/// script"; a wrong constant would silently never match any witness
/// UTxO (fail-closed). The `check_deploy_constants.py` gate enforces
/// it is non-placeholder AND 28 bytes before mainnet tag.
pub const auth_witness_validator_hash: ByteArray =
  #"5c404889f2d25ab7af9fc52f54c088bd427934742cea9ca53cdfcf4b"

/// [v8 / Δ19 / V-002 / V-008] Operator-only sweeper PKH. The mint policy's
/// `SweepBurn` redeemer requires this PKH to be in the tx's
/// `extra_signatories` and the policy's `payload.not_after` to have already
/// elapsed before allowing an orphan witness UTxO to be burned without
/// co-spending the policy. Compile-time-pinned so a fresh sweeper key
/// rotation requires a redeploy + visible validator-hash change.
///
/// Currently set to `aegis_self_publisher_vkh` — the operator wallet that
/// signs publisher txs is the same wallet authorized to sweep orphan
/// witnesses. If we later separate the sweeper key from the publisher key,
/// this constant becomes its own pin.
pub const aegis_operator_pkh: ByteArray =
  #"6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152"

/// [v8 / Δ24 / V-009] UTF-8 of `"PREPROD"` — accepted `network_tag`
/// parameter value for the auth_witness_nft mint policy.
pub const network_tag_preprod: ByteArray = #"50524550524f44"

/// [v8 / Δ24 / V-009] UTF-8 of `"PREVIEW"`.
pub const network_tag_preview: ByteArray = #"50524556494557"

/// [v8 / Δ24 / V-009] UTF-8 of `"MAINNET"`.
pub const network_tag_mainnet: ByteArray = #"4d41494e4e4554"

/// [v8] Address bytes prefix for a CIP-19 type-6 (key-payment, no stake)
/// enterprise address on a TESTNET network (preprod, preview). The header
/// byte is `0x60` per CIP-19. Combined with the 28-byte VKH this yields
/// a 29-byte enterprise address — the canonical form `payout_address`
/// must take in `AuthCoveragePayload` (Δ9).
pub const enterprise_addr_header_testnet: ByteArray = #"60"

/// [v8] Address bytes prefix for a CIP-19 type-6 enterprise address on
/// MAINNET. The header byte is `0x61` per CIP-19.
pub const enterprise_addr_header_mainnet: ByteArray = #"61"

/// [v8] Active-build enterprise address header. Pinned to testnet for
/// preprod build; mainnet build flips to `enterprise_addr_header_mainnet`.
pub const enterprise_addr_header: ByteArray = #"60"

/// [v6.0.2 / A-026 fix] AegisSelf canonical publisher NFT policy id.
///
/// One-shot-minted per network (current preprod value below). The parser
/// now rejects any `oracle_nft` that does not equal this constant, closing
/// the surface where an attacker mints a fake NFT under their own permissive
/// policy and outputs it at the publisher VKH address (which anyone can do
/// — Cardano addresses accept inbound outputs from any sender; only spending
/// is gated by the payment credential).
///
/// **Why the original two-layer handshake was insufficient.** The header
/// of `aegis/oracle/aegis_self.ak` claimed the trust handshake "requires
/// the attacker to BOTH steal the publisher key AND mint under our
/// parameterized one-shot policy." That argument was wrong: the parser
/// only checked that the UTxO contained a token under the *caller-supplied*
/// `oracle_nft` policy id, not that the policy id was canonical. An
/// attacker minting under a fresh permissive policy and referencing the
/// resulting UTxO bypassed both legs.
///
/// **Per-network rotation.** The publisher NFT is a one-shot minted via
/// the `pool_nft.ak` validator parameterized over an init UTxO consumed
/// at mint time; a fresh mint per network produces a different policy id.
/// Update this constant per build target. Current value: preprod
/// `AEGIS_PRICE_FEED_V1`.
pub const aegis_self_nft_policy: ByteArray =
  #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f"

// ---------------------------------------------------------------------------
// [v8 NEW] Helpers — policy_id derivation, enterprise address, provider tag
// ---------------------------------------------------------------------------

/// [v8 / Δ3 / H-3] Compute the canonical `policy_id` for a freshly-created
/// policy. INCLUDES the consumed underwrite input ref so two same-terms
/// policies cannot collide on `policy_id` even when assembled from
/// different LP capital. The pool validator's Underwrite branch verifies
/// `pdat.policy_id == derive_policy_id(...)` (cheap — one BLAKE2b hash).
///
/// Encoding is byte concatenation in a fixed order; widths are pinned so
/// the off-chain builder produces byte-identical input. Integers are
/// big-endian to match the CBOR convention used elsewhere in the protocol.
/// `output_index` is encoded as 2 bytes — the ledger limits an output
/// index to 2^15-1 in practice, so 16-bit big-endian is comfortably wide.
///
/// **Single-Underwrite path** (one input, one policy output): callers use
/// `derive_policy_id` and supply `own_ref` (the consumed pool UTxO's
/// reference) as the anchor. The OutputReference.output_index in this case
/// is the consumed UTxO's tx-output index — already unique per pool
/// continuation since each Underwrite consumes a fresh pool UTxO.
pub fn derive_policy_id(
  insured_pkh: ByteArray,
  strike_price: Int,
  coverage_amount: Int,
  start_time: Int,
  expiry_time: Int,
  pool_nft: ByteArray,
  underwrite_tx_input: OutputReference,
) -> ByteArray {
  let preimage =
    insured_pkh
      |> bytearray.concat(bytearray.from_int_big_endian(strike_price, 8))
      |> bytearray.concat(bytearray.from_int_big_endian(coverage_amount, 8))
      |> bytearray.concat(bytearray.from_int_big_endian(start_time, 8))
      |> bytearray.concat(bytearray.from_int_big_endian(expiry_time, 8))
      |> bytearray.concat(pool_nft)
      |> bytearray.concat(underwrite_tx_input.transaction_id)
      |> bytearray.concat(
          bytearray.from_int_big_endian(underwrite_tx_input.output_index, 2),
        )
  blake2b_224(preimage)
}

/// [v8 / Δ21 / V-003] Compute the canonical `policy_id` for a single
/// policy output produced by a `BatchUnderwrite`. The batch path consumes
/// ONE pool input but produces N policy outputs, so the per-output anchor
/// must distinguish each batch entry. The salt `batch_index` is the
/// 0-based index of the policy output within the batch — combined with
/// the consumed pool UTxO's `OutputReference`, every batch output has a
/// unique anchor and thus a unique `policy_id`.
///
/// Encoding mirrors `derive_policy_id` exactly with one extra trailing
/// 2-byte big-endian `batch_index` so the hash preimage cannot collide
/// across the single-Underwrite and batch-Underwrite paths (single uses
/// the 80-byte preimage, batch uses 82). Off-chain builders MUST mirror
/// this construction byte-for-byte.
pub fn derive_policy_id_batch(
  insured_pkh: ByteArray,
  strike_price: Int,
  coverage_amount: Int,
  start_time: Int,
  expiry_time: Int,
  pool_nft: ByteArray,
  underwrite_tx_input: OutputReference,
  batch_index: Int,
) -> ByteArray {
  let preimage =
    insured_pkh
      |> bytearray.concat(bytearray.from_int_big_endian(strike_price, 8))
      |> bytearray.concat(bytearray.from_int_big_endian(coverage_amount, 8))
      |> bytearray.concat(bytearray.from_int_big_endian(start_time, 8))
      |> bytearray.concat(bytearray.from_int_big_endian(expiry_time, 8))
      |> bytearray.concat(pool_nft)
      |> bytearray.concat(underwrite_tx_input.transaction_id)
      |> bytearray.concat(
          bytearray.from_int_big_endian(underwrite_tx_input.output_index, 2),
        )
      |> bytearray.concat(bytearray.from_int_big_endian(batch_index, 2))
  blake2b_224(preimage)
}

/// [v8 / Δ9 / F-AUTH-4] Compute the canonical 29-byte CIP-19 enterprise
/// address bytes for a given payment-credential VKH on the active network.
/// Header byte is `0x60` for testnet (preprod, preview) and `0x61` for
/// mainnet. The validator computes this canonically from `datum.insured`
/// and asserts equality against `payload.payout_address` so a relay
/// cannot redirect the payout to its own address.
pub fn enterprise_addr_of(insured: ByteArray) -> ByteArray {
  bytearray.concat(enterprise_addr_header, insured)
}

/// [v8] Encode an `OracleProvider` as the integer Constr index used in
/// the canonical `AuthCoveragePayload` CBOR — 0=Charli3, 1=Orcfax,
/// 2=AegisSelf. The validator and mint policy assert
/// `payload.oracle_provider == oracle_provider_to_int(datum.oracle_provider)`
/// so a sig over a payload with a different provider is rejected (Δ5).
pub fn oracle_provider_to_int(provider: OracleProvider) -> Int {
  when provider is {
    Charli3 -> 0
    Orcfax -> 1
    AegisSelf -> 2
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test policy_datum_construction() {
  let datum =
    PolicyDatum {
      policy_id: #"aabb",
      insured: #"0011223344556677889900112233445566778899001122334455667788",
      strike_price: 350_000,
      coverage_amount: 5_000_000_000,
      premium_paid: 100_000_000,
      start_time: 1_700_000_000_000,
      expiry_time: 1_700_604_800_000,
      oracle_nft: #"886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e",
      pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
      pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
      oracle_provider: Charli3,
      auth_commitment: None,
    }
  datum.strike_price == 350_000 && datum.coverage_amount == 5_000_000_000
}

test pool_datum_construction() {
  let datum =
    PoolDatum {
      total_liquidity: 100_000_000_000,
      active_coverage: 20_000_000_000,
      lp_token_policy: #"aabb",
      protocol_fee_bps: 200,
      pool_nft: #"ccdd",
      lp_supply: 100_000_000_000,
    }
  datum.total_liquidity == 100_000_000_000 && datum.protocol_fee_bps == 200
}

test constants_are_reasonable() {
  min_premium == 2_000_000 && max_coverage_ratio == 50 && cancellation_window == 3_600_000 && cancellation_fee_bps == 1_000
}

test orcfax_freshness_window_widened_for_v7() {
  // v7 widened from v6's 30 min to 70 min — must be ≥ Orcfax's empirical
  // worst-case gap (max 55 min observed on mainnet) plus ledger lb padding.
  orcfax_freshness_window_ms == 4_200_000 && orcfax_freshness_window_ms > 65 * 60 * 1_000
}

test aegis_self_publisher_vkh_is_28_bytes() {
  // VKH must be exactly 28 bytes (Blake2b-224). The length assertion is
  // load-bearing: a wrong-length constant would silently never match any
  // payment_credential at validation time (fail-closed), so this guards
  // against a typo that would brick all AegisSelf claims. The equality
  // pin doubles as a regression check on the canonical value.
  let len_ok = bytearray.length(aegis_self_publisher_vkh) == 28
  let value_ok =
    aegis_self_publisher_vkh == #"6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152"
  len_ok && value_ok
}

test policy_datum_aegis_self_variant_constructs() {
  let datum =
    PolicyDatum {
      policy_id: #"aabb",
      insured: #"0011223344556677889900112233445566778899001122334455667788",
      strike_price: 1_000_000,
      coverage_amount: 10_000_000_000,
      premium_paid: 100_000_000,
      start_time: 1_700_000_000_000,
      expiry_time: 1_700_604_800_000,
      // For AegisSelf, oracle_nft carries the publisher NFT policy id.
      oracle_nft: #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
      pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
      pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
      oracle_provider: AegisSelf,
      auth_commitment: None,
    }
  let is_aegis_self =
    when datum.oracle_provider is {
      AegisSelf -> True
      _ -> False
    }
  datum.strike_price == 1_000_000 && is_aegis_self
}
