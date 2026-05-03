// =============================================================================
// Aegis Insurance Protocol - Type Definitions
// Location: contracts/lib/aegis/types.ak
// Summary: All on-chain datum and redeemer types used across the protocol.
//          Imported by validators (policy.ak, pool.ak, lp_token.ak) and
//          helper modules (oracle.ak, pricing.ak, validation.ak, pool.ak).
// =============================================================================

use aiken/crypto.{Blake2b_224, Hash, Script, VerificationKey}

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

/// [v6] Oracle provider tag. Aegis v6 supports both Charli3 (legacy primary)
/// and Orcfax (redundant secondary). Sum-type semantics give us compile-time
/// exhaustivity — adding a new provider in the future requires a redeploy
/// that visibly rotates the validator hash, which IS the curated whitelist.
///
/// CBOR encoding: `Charli3 = constr_0([])`, `Orcfax = constr_1([])`. Minimal
/// on-chain bytes (1 byte for the constr index + empty list of fields).
///
/// Why a sum type and not a free-form `oracle_script_hash: ByteArray`:
///   * A free-form ByteArray would require a second runtime check ("is this
///     hash whitelisted?"), either as a hardcoded list (which defeats the
///     point — adding a provider would still need a redeploy) or as a separate
///     registry UTxO (large new audit surface). A sum-type variant *is* the
///     whitelist, enforced by Aiken's exhaustivity check on `when` branches.
///   * Type-safe parser dispatch. The validator's
///     `when datum.oracle_provider is { Charli3 -> ... | Orcfax -> ... }`
///     branches each call a provider-specific resolver-and-parser without
///     casting Data through unsafe holes.
///
/// Trade-off: adding a third provider in v7 (e.g., Wingriders Time-Weighted
/// Pool oracle, a CIP-0073 standard feed, or an in-house FEAR index) requires
/// another datum-schema rotation. Frequency of new providers we'd actually
/// trust enough to onboard is bounded; each onboarding deserves its own audit
/// pass anyway. A datum rotation per onboarding is the right cadence.
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
  /// Process a claim payout from the pool
  ProcessClaim {
    /// Amount to pay out in lovelace
    payout: Int,
    /// Script hash of the policy validator (to verify policy consumption)
    policy_script: ScriptHash,
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
  /// Process batch-expire: return expired policy funds to pool
  BatchExpireProcess {
    /// Total lovelace being returned from expired policies
    total_returned: Int,
    /// Script hash of the policy validator
    policy_script: ScriptHash,
  }
  /// [FIX A-020] Process a cancellation. Consumes a Cancel-redeemed policy
  /// at `policy_script`, sends the canonical refund (90% of premium) to the
  /// insured, decrements `active_coverage` by the consumed policy's coverage,
  /// and retains the 10% cancellation fee in the pool. The refund magnitude
  /// is derived on-chain from the consumed policy's `premium_paid` (NOT a
  /// caller-controlled amount), so an over-refund cannot drain the pool.
  AcceptCancellation {
    /// Script hash of the policy validator (to locate the consumed policy)
    policy_script: ScriptHash,
  }
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

/// [v6] Orcfax recommended freshness window in POSIX milliseconds (30 min).
///
/// Orcfax's `FsDat<Rational>` carries NO `expiry` field — the only timestamp
/// is `created_at`. Freshness is the consumer's responsibility, enforced via
/// `lb - created_at < max_freshness_ms` AND `ub - lb < max_freshness_ms` to
/// pin both sides of the validity window. This matches Orcfax's recommended
/// pattern in `lib/orcfax/validity_range.ak` and `synthetics/aik/lib/
/// synthetics/constants.ak` (`max_ttl = 30 * 60 * 1000`).
pub const orcfax_freshness_window_ms: Int = 30 * 60 * 1_000

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
