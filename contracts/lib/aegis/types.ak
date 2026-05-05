// =============================================================================
// Aegis Insurance Protocol - Type Definitions
// Location: contracts/lib/aegis/types.ak
// Summary: All on-chain datum and redeemer types used across the protocol.
//          Imported by validators (policy.ak, pool.ak, lp_token.ak) and
//          helper modules (oracle.ak, pricing.ak, validation.ak, pool.ak).
// =============================================================================

use aiken/crypto.{Blake2b_224, Hash, Script, VerificationKey}
use aiken/primitive/bytearray

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
    aegis_self_publisher_vkh ==
      #"6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152"
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
    }
  let is_aegis_self =
    when datum.oracle_provider is {
      AegisSelf -> True
      _ -> False
    }
  datum.strike_price == 1_000_000 && is_aegis_self
}
