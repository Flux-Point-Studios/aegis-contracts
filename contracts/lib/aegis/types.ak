// =============================================================================
// Aegis Insurance Protocol - Type Definitions
// Location: contracts/lib/aegis/types.ak
// Summary: All on-chain datum and redeemer types used across the protocol.
//          Imported by validators (policy.ak, pool.ak, lp_token.ak) and
//          helper modules (oracle.ak, pricing.ak, validation.ak, pool.ak).
// =============================================================================

use aiken/collection/list
use aiken/crypto.{Blake2b_224, Hash, Script, VerificationKey}
use aiken/primitive/bytearray
use cardano/address.{
  Address, VerificationKey as PaymentVKCred, from_verification_key,
  with_delegation_key,
}

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
  /// [v12.2 NEW] Indigo on-chain price oracle. Constructor index 3. 4
  /// iAssets directly bound (iUSD, iBTC, iETH, iSOL) via
  /// `indigo_canonical_nfts` + `indigo_oracle_script_hashes` (paired by
  /// index). Resolver: `oracle/indigo.ak`. Trust handshake: NFT pin +
  /// per-iAsset oracle script credential pin + single-token-of-policy.
  /// See V12.2 spec §2.6 for the on-chain architecture.
  Indigo
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
  /// [v12 NEW] Optional partner address that receives a share of the 2%
  /// protocol fee. Set at policy-creation time and immutable. None means
  /// the entire protocol fee flows to `team_address` (solo policy); Some(addr)
  /// requires `partner_share_bps > 0` and routes `partner_cut` to that
  /// address.
  ///
  /// Trust model: caller-supplied. Anyone can set any address. A caller
  /// setting an attacker-controlled `partner_address` is self-pwning
  /// (diverting their own fees away from the team to a wallet they don't
  /// control); the protocol incurs no risk. Partner registry / lookup is
  /// a frontend UX concern (post-V12 follow-up).
  partner_address: Option<Address>,
  /// [v12 NEW] Partner share of the protocol fee in basis points of the
  /// fee (NOT of the premium). 0..=2000 (capped by validator at
  /// `partner_share_cap_bps`). Set at policy-creation time and immutable.
  ///
  /// Validator invariants:
  ///   * `partner_share_bps >= 0` (defensive; rejects signed-int weirdness)
  ///   * `partner_share_bps <= partner_share_cap_bps` (= 2000 bps = 20% of fee)
  ///   * `partner_address == None` => `partner_share_bps == 0`
  ///   * `partner_address == Some(_)` => no lower-bound on partner_share_bps;
  ///     a 0-share partner is legal (treated as a "credit" — partner is
  ///     recorded in the datum for analytics but receives no lovelace)
  partner_share_bps: Int,
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

/// Minimum premium in lovelace.
///
/// [v12.2 Round-7 R7-A] Per-network value to neutralise the cancel-cycle
/// LP drain attack at the floor threshold.
///
///   PREPROD: 2_000_000 (= 2 ADA, current). Dev-convenient — exercises the
///            full fee_total floor path so red-team tests stay reproducible.
///            R7-A is bounded by tiny TVL on preprod so the asymmetric
///            drain ratio doesn't matter for testing.
///
///   MAINNET: 100_000_000 (= 100 ADA). Threshold where `raw_fee = premium ×
///            200 / 10_000 ≥ min_utxo`, so the Hybrid fee_total floor
///            stops kicking in and the cancel-cycle asymmetry vanishes.
///            See V12.2 spec §10.X / red-team report R7-A. The mainnet
///            deploy must substitute this constant by commenting out the
///            preprod line and uncommenting the mainnet line below.
pub const min_premium: Int = 2_000_000
// MAINNET: pub const min_premium: Int = 100_000_000

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

/// [v12 / A-026 generalised] AegisSelf canonical publisher NFT allowlist.
///
/// Five one-shot mints under the SAME canonical publisher VKH, one per
/// supported pair (ADA/USD, BTC/USD, ETH/USD, USDC/USD, USDT/USD). Each
/// NFT has `quantity: 1` permanent and its mint authority is the consumed
/// init UTxO of `pool_nft.ak`, already spent — so re-minting is impossible
/// even with a publisher-key compromise. The parser at
/// `aegis/oracle/aegis_self.ak` rejects any `oracle_nft` that is not a
/// member of this list, preserving the round-6 A-026 trust anchor — the
/// only set-theoretic change is that the canonical set now has five
/// elements instead of one.
///
/// **Per-policy binding.** `PolicyDatum.oracle_nft` is frozen at
/// Underwrite time, so a BTC-bound policy reads BTC prices only and an
/// ADA-bound policy reads ADA prices only. No cross-pair contamination.
///
/// **Order.** Alphabetical by symbol (ADA, BTC, ETH, USDC, USDT) for diff
/// stability. `list.has` is order-agnostic so the on-chain semantics do
/// not depend on the order; this is a maintenance convention only.
///
/// **Per-network rotation.** Values below are preprod. Mainnet flips to
/// fresh one-shot mints during the mainnet deploy and rotates the
/// validator hash as the visible trust signal.
pub const aegis_self_canonical_nfts: List<ByteArray> =
  [
    // ADA/USD — asset name "AEGIS_PRICE_FEED_V1"
    #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
    // BTC/USD — asset name "AEGIS_PRICE_FEED_BTC_USD_V1"
    #"ae304e27806536dbbc222115c2b543e845f99bd8c7a3a01669f2d7bd",
    // ETH/USD — asset name "AEGIS_PRICE_FEED_ETH_USD_V1"
    #"d80aa1a72a46813b5045e163751076d54551fac4a6f8d720e15807ad",
    // USDC/USD — asset name "AEGIS_PRICE_FEED_USDC_USD_V1"
    #"860faa663d8a3ae3071d61f95464340c0e49c1f47f56db76441df7a0",
    // USDT/USD — asset name "AEGIS_PRICE_FEED_USDT_USD_V1"
    #"a4093bfc7758b86ca1b96df842367bce96cb954650a392020246c0cb",
  ]

// ---------------------------------------------------------------------------
// Indigo On-chain Oracle Bindings (Aegis v12.2)
// ---------------------------------------------------------------------------

/// [v12.2 NEW] Indigo canonical oracle NFT policy ids — 4 entries, one per
/// supported iAsset (iUSD, iBTC, iETH, iSOL).
///
/// **Per-iAsset binding.** `PolicyDatum.oracle_nft` is frozen at Underwrite
/// time, so an iUSD-bound depeg policy reads iUSD prices only and an iBTC-
/// bound crash policy reads iBTC prices only. No cross-iAsset contamination.
///
/// **Ordering.** Indexed: 0=iUSD, 1=iBTC, 2=iETH, 3=iSOL. The order is
/// load-bearing — the corresponding entry of `indigo_oracle_script_hashes`
/// at the same index pairs the NFT with the per-iAsset oracle script
/// credential. A reorder of one list without the other is an audit incident.
///
/// **Per-network rotation.** Values below are **PREPROD** mock-mints
/// minted live on 2026-05-11 via `scripts/init_indigo_mock.py`
/// (one-shot policies, one per iAsset). The mainnet block (commented
/// out below) carries the live Indigo NFT policy ids validated
/// 2026-05-12 via Koios.
///
/// **Wave 4 mint provenance.** Each preprod entry is the policy id of
/// the per-iAsset one-shot mint, bound to a distinct operator-wallet
/// init UTxO + asset name (`MOCK_IUSD_ORACLE`, `MOCK_IBTC_ORACLE`,
/// `MOCK_IETH_ORACLE`, `MOCK_ISOL_ORACLE`). Provenance recorded in
/// `configs/indigo-mock-mint.preprod.json`. Trust anchor for the
/// preprod path is the operator-controlled mock script
/// (`d27ccc13...`) holding all 4 UTxOs.
pub const indigo_canonical_nfts: List<ByteArray> =
  [
    // **PREPROD BLOCK (active for V12.2 preprod deploy — Wave 4 mints):**
    // 0 = iUSD preprod mock NFT policy id (mint tx d0de29b9...)
    #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
    // 1 = iBTC preprod mock NFT policy id (mint tx 0a923058...)
    #"1e66200fca30b83d5937b67b896fa46f1adac98922555f9e791c1c83",
    // 2 = iETH preprod mock NFT policy id (mint tx 146667ec...)
    #"e81e84a5d34137bcbc2ba73f1b4e735ac0cc375f0bfeb5e98a397102",
    // 3 = iSOL preprod mock NFT policy id (mint tx cea3b933...)
    #"875cea49cb6963ad462187f77dcc5b4d458a66d7eb9a646c2c5405a7",
    //
    // **MAINNET BLOCK (commented out until mainnet promotion):**
    // #"e3455f2715338b454fb853442f72dc03b98396854f97510027fe22ff",  // iUSD
    // #"408f13b240f57c3473b5727a68a88c50c1b6bb15c0c10912008dc59e",  // iBTC
    // #"6c9497ffd7e8baf86c3c0d6fcd43c524daa49ad5fceba26d715468e9",  // iETH
    // #"107992fe118ef6ae341ae0996f355124e03a8fccdcade60692175df2",  // iSOL
  ]

/// [v12.2 NEW] Indigo per-iAsset oracle script credentials — 4 entries,
/// paired by index with `indigo_canonical_nfts`.
///
/// **Mainnet values** (commented out below; validated Wave 1.5 via Koios):
///   0 = `1042576d1de963437bd4bb50dcd91459756e6812b7c06dd543a332c8` (iUSD)
///   1 = `d27ad3ed7b073018d429e57c2f8d1f52445aa241e280e6da149a91b4` (iBTC)
///   2 = `f350350cd40d0d8e8744f2c6cad54a0abc9d51f107f57fb95c181a3f` (iETH)
///   3 = `e3c50817e0fbaab03e4411249cfcb22aa004844e9ad86ca4d76524bc` (iSOL)
///
/// **Preprod values** are a single shared mock-script hash deployed
/// Wave 4 (compiled out-of-tree as a 3-line always-succeeds Aiken
/// validator; bech32 form
/// `addr_test1wrf8enqnl26m0q5cfg73lxf4xxtu5x5phcrfjs0lcqp7uagh2hm3k`).
/// On preprod we use ONE shared mock script for all 4 iAssets (vs
/// Indigo's 4 distinct hashes on mainnet — see V12.2 spec §5b). That
/// preprod simplification reduces dev-loop cost without weakening the
/// parser's invariants — the script-credential pin still enforces
/// "UTxO must be at the canonical script address," it just happens
/// that the 4 canonical preprod addresses are the same address. The 4
/// list entries thus all carry the same hash.
pub const indigo_oracle_script_hashes: List<ByteArray> =
  [
    // **PREPROD BLOCK (active for V12.2 preprod deploy — Wave 4 mock):**
    // All 4 entries point at the operator mock script (one shared address).
    #"d27ccc13fab5b782984a3d1f99353197ca1a81be069941ffc003ee75",
    #"d27ccc13fab5b782984a3d1f99353197ca1a81be069941ffc003ee75",
    #"d27ccc13fab5b782984a3d1f99353197ca1a81be069941ffc003ee75",
    #"d27ccc13fab5b782984a3d1f99353197ca1a81be069941ffc003ee75",
    //
    // **MAINNET BLOCK (commented out until mainnet promotion):**
    // #"1042576d1de963437bd4bb50dcd91459756e6812b7c06dd543a332c8",  // iUSD
    // #"d27ad3ed7b073018d429e57c2f8d1f52445aa241e280e6da149a91b4",  // iBTC
    // #"f350350cd40d0d8e8744f2c6cad54a0abc9d51f107f57fb95c181a3f",  // iETH
    // #"e3c50817e0fbaab03e4411249cfcb22aa004844e9ad86ca4d76524bc",  // iSOL
  ]

// ---------------------------------------------------------------------------
// Protocol Fee Routing (Aegis v12)
// ---------------------------------------------------------------------------

/// [v12] Team wallet address (preprod) that receives the team's share of the
/// 2% protocol fee on every Underwrite / BatchUnderwrite / AcceptCancellation
/// tx. Compile-time pinned per network — rotation = new validator hash =
/// new deploy.
///
/// The fee path: each fee-bearing branch checks that the tx outputs contain
/// at least one entry with `address == team_address` carrying lovelace
/// >= max(min_utxo_lovelace, team_cut). The validator compares the FULL
/// `Address` value (payment + stake), not just payment_credential — so an
/// operator who delegates the team wallet to a different stake pool
/// (rotating the stake VKH) must rebuild and redeploy.
///
/// **Per D9 operator confirmation.** Smart-constructor form (Path B): the
/// preprod team address bech32
/// `addr_test1qrph8epfa8dg6wjwmls873g0xllyjnlt3hh08nv9kcrw9ln40ur83k9c87dpxuar3jucqrg0sc54zvzmf53pu6due2eqa5m8d2`
/// decodes to payment VKH `c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe`
/// and stake VKH `757f0678d8b83f9a1373a38cb9800d0f862951305b4d221e69bccab2`.
/// Bytes pinned verbatim from `docs/architecture/_decode_addresses.py`.
pub const team_address_preprod: Address =
  from_verification_key(
    #"c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe",
  )
    |> with_delegation_key(
        #"757f0678d8b83f9a1373a38cb9800d0f862951305b4d221e69bccab2",
      )

/// [v12] Team wallet address (mainnet).
///
/// Bech32: `addr1q9s6m9d8yedfcf53yhq5j5zsg0s58wpzamwexrxpfelgz2wgk0s9l9fqc93tyc8zu4z7hp9dlska2kew9trdg8nscjcq3sk5s3`
/// (Flux Point Studios team wallet). Decodes to payment VKH
/// `61ad95a7265a9c269125c149505043e143b822eedd930cc14e7e8129` and stake VKH
/// `c8b3e05f9520c162b260e2e545eb84adfc2dd55b2e2ac6d41e70c4b0`.
pub const team_address_mainnet: Address =
  from_verification_key(
    #"61ad95a7265a9c269125c149505043e143b822eedd930cc14e7e8129",
  )
    |> with_delegation_key(
        #"c8b3e05f9520c162b260e2e545eb84adfc2dd55b2e2ac6d41e70c4b0",
      )

/// [v12] Active-network team address. Set per build target.
///
/// Currently pinned to preprod; promoting to mainnet flips this to
/// `team_address_mainnet` and rotates the validator hash. Same selection
/// shape as `orcfax_fsp_script_hash` — a single active-network constant
/// whose value is edited per build.
pub const team_address: Address = team_address_preprod

/// [v12] Maximum partner share of the protocol fee, in basis points of the
/// protocol fee (not of the premium). 2000 bps = 20% of the 2% protocol
/// fee = 0.4% of the premium maximum to any partner. The validator rejects
/// any `PolicyDatum.partner_share_bps > partner_share_cap_bps` at
/// Underwrite / BatchUnderwrite / AcceptCancellation time.
///
/// The cap is a defense-in-depth measure: caller-supplied `partner_address`
/// is a self-pwn surface (a caller diverting their own fees away from the
/// team into a wallet they don't control), but a careless integrator could
/// set `partner_share_bps = 10_000` and route 100% of the protocol fee to
/// the partner, leaving the team with nothing. The cap pins the floor on
/// team revenue at 80% of the protocol fee (1.6% of premium).
pub const partner_share_cap_bps: Int = 2_000

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
      partner_address: None,
      partner_share_bps: 0,
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
      partner_address: None,
      partner_share_bps: 0,
    }
  let is_aegis_self =
    when datum.oracle_provider is {
      AegisSelf -> True
      _ -> False
    }
  datum.strike_price == 1_000_000 && is_aegis_self
}

// ---------------------------------------------------------------------------
// [v12] NFT allowlist tests
// ---------------------------------------------------------------------------

test allowlist_accepts_ada_usd() {
  list.has(
    aegis_self_canonical_nfts,
    #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
  )
}

test allowlist_accepts_btc_usd() {
  list.has(
    aegis_self_canonical_nfts,
    #"ae304e27806536dbbc222115c2b543e845f99bd8c7a3a01669f2d7bd",
  )
}

test allowlist_accepts_eth_usd() {
  list.has(
    aegis_self_canonical_nfts,
    #"d80aa1a72a46813b5045e163751076d54551fac4a6f8d720e15807ad",
  )
}

test allowlist_accepts_usdc_usd() {
  list.has(
    aegis_self_canonical_nfts,
    #"860faa663d8a3ae3071d61f95464340c0e49c1f47f56db76441df7a0",
  )
}

test allowlist_accepts_usdt_usd() {
  list.has(
    aegis_self_canonical_nfts,
    #"a4093bfc7758b86ca1b96df842367bce96cb954650a392020246c0cb",
  )
}

test allowlist_rejects_non_canonical_nft() {
  // Random 28-byte hex string not in the canonical list.
  !list.has(
    aegis_self_canonical_nfts,
    #"00112233445566778899001122334455667788990011223344556677",
  )
}

test allowlist_rejects_empty_nft() {
  // Defensive: empty bytestring must not match any canonical entry.
  !list.has(aegis_self_canonical_nfts, #"")
}

test allowlist_size_is_exactly_five() {
  // Guards against accidental drift — adding a sixth NFT without rotating
  // the validator hash would be an audit incident.
  list.length(aegis_self_canonical_nfts) == 5
}

// ---------------------------------------------------------------------------
// [v12] Protocol-fee constant tests
// ---------------------------------------------------------------------------

test team_address_preprod_payment_credential_28_bytes() {
  // Defensive length pin. A typo in the hex literal would silently bypass
  // the equality check at Underwrite time and route fees to an attacker.
  when team_address_preprod.payment_credential is {
    PaymentVKCred(h) -> bytearray.length(h) == 28
    _ -> False
  }
}

test team_address_mainnet_payment_credential_28_bytes() {
  when team_address_mainnet.payment_credential is {
    PaymentVKCred(h) -> bytearray.length(h) == 28
    _ -> False
  }
}

test team_address_preprod_has_stake_credential() {
  // The team address is a BASE address (payment + stake), not enterprise.
  team_address_preprod.stake_credential != None
}

test team_address_mainnet_has_stake_credential() {
  team_address_mainnet.stake_credential != None
}

test partner_share_cap_bps_is_2000() {
  partner_share_cap_bps == 2_000
}

test policy_datum_v12_no_partner() {
  let datum =
    PolicyDatum {
      policy_id: #"aabb",
      insured: #"0011223344556677889900112233445566778899001122334455667788",
      strike_price: 350_000,
      coverage_amount: 5_000_000_000,
      premium_paid: 100_000_000,
      start_time: 1_700_000_000_000,
      expiry_time: 1_700_604_800_000,
      oracle_nft: #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
      pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
      pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
      oracle_provider: AegisSelf,
      partner_address: None,
      partner_share_bps: 0,
    }
  datum.partner_share_bps == 0 && datum.partner_address == None
}

test policy_datum_v12_with_partner() {
  let datum =
    PolicyDatum {
      policy_id: #"aabb",
      insured: #"0011223344556677889900112233445566778899001122334455667788",
      strike_price: 350_000,
      coverage_amount: 5_000_000_000,
      premium_paid: 100_000_000,
      start_time: 1_700_000_000_000,
      expiry_time: 1_700_604_800_000,
      oracle_nft: #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
      pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
      pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
      oracle_provider: AegisSelf,
      partner_address: Some(team_address_preprod),
      partner_share_bps: 2_000,
    }
  datum.partner_share_bps == 2_000
}

// ---------------------------------------------------------------------------
// [v12.2] Indigo provider + NFT/script allowlist tests
// ---------------------------------------------------------------------------

test policy_datum_indigo_variant_constructs() {
  // V12.2 adds Indigo as the 4th OracleProvider variant. A PolicyDatum
  // bound to Indigo must construct cleanly with an Indigo canonical NFT.
  let datum =
    PolicyDatum {
      policy_id: #"aabb",
      insured: #"0011223344556677889900112233445566778899001122334455667788",
      strike_price: 1_000_000,
      coverage_amount: 10_000_000_000,
      premium_paid: 100_000_000,
      start_time: 1_700_000_000_000,
      expiry_time: 1_700_604_800_000,
      // iUSD preprod mock NFT (live Wave-4 mint).
      oracle_nft: #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
      pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
      pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
      oracle_provider: Indigo,
      partner_address: None,
      partner_share_bps: 0,
    }
  let is_indigo =
    when datum.oracle_provider is {
      Indigo -> True
      _ -> False
    }
  datum.strike_price == 1_000_000 && is_indigo
}

test indigo_canonical_nfts_size_is_exactly_four() {
  // V12.2 binds exactly 4 iAssets (iUSD, iBTC, iETH, iSOL). A 5th NFT
  // entry without a validator redeploy would be an audit incident.
  list.length(indigo_canonical_nfts) == 4
}

test indigo_oracle_script_hashes_size_matches_nft_count() {
  // The two lists are paired by index — a length mismatch is structurally
  // wrong (the parser's lookup would either crash or pair the wrong
  // (NFT, script) entries). Static-size pin.
  list.length(indigo_oracle_script_hashes) == list.length(indigo_canonical_nfts)
}

test indigo_accepts_iusd_preprod_nft() {
  // iUSD preprod mock NFT (live Wave-4 mint tx d0de29b9...).
  list.has(
    indigo_canonical_nfts,
    #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
  )
}

test indigo_accepts_ibtc_preprod_nft() {
  // iBTC preprod mock NFT (live Wave-4 mint tx 0a923058...).
  list.has(
    indigo_canonical_nfts,
    #"1e66200fca30b83d5937b67b896fa46f1adac98922555f9e791c1c83",
  )
}

test indigo_accepts_ieth_preprod_nft() {
  // iETH preprod mock NFT (live Wave-4 mint tx 146667ec...).
  list.has(
    indigo_canonical_nfts,
    #"e81e84a5d34137bcbc2ba73f1b4e735ac0cc375f0bfeb5e98a397102",
  )
}

test indigo_accepts_isol_preprod_nft() {
  // iSOL preprod mock NFT (live Wave-4 mint tx cea3b933...).
  list.has(
    indigo_canonical_nfts,
    #"875cea49cb6963ad462187f77dcc5b4d458a66d7eb9a646c2c5405a7",
  )
}

test indigo_rejects_unknown_nft() {
  // A non-canonical NFT must not appear in the allowlist.
  !list.has(
    indigo_canonical_nfts,
    #"00112233445566778899001122334455667788990011223344556677",
  )
}

test indigo_rejects_empty_nft() {
  !list.has(indigo_canonical_nfts, #"")
}

test indigo_disjoint_from_aegis_self() {
  // The Indigo and AegisSelf allowlists must be disjoint. An NFT in one
  // MUST NOT be in the other. Defensive pin against accidental drift.
  !list.has(
    indigo_canonical_nfts,
    #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
  ) && !list.has(
    aegis_self_canonical_nfts,
    #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
  )
}

test indigo_oracle_script_hash_first_entry_is_28_bytes() {
  // All 4 entries must be 28-byte ByteArrays (Blake2b-224 script hashes).
  when indigo_oracle_script_hashes is {
    [first, ..] -> bytearray.length(first) == 28
    [] -> False
  }
}

test indigo_canonical_nft_first_entry_is_28_bytes() {
  // Same defensive length pin for the NFT policy ids.
  when indigo_canonical_nfts is {
    [first, ..] -> bytearray.length(first) == 28
    [] -> False
  }
}

test aegis_self_canonical_nfts_unchanged_at_five_in_v12_2() {
  // V12.2 explicitly keeps AegisSelf at 5 entries (the original Wave-1 plan
  // to add iUSD was cancelled in Wave 1.5 when we pivoted to Indigo
  // direct-bind). Pinning this length protects against accidental drift.
  list.length(aegis_self_canonical_nfts) == 5
}
