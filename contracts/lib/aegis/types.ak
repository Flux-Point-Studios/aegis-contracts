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
// Policy Datum
// ---------------------------------------------------------------------------

/// The datum stored in each insurance policy UTxO.
/// Contains all terms of the insurance contract.
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
  /// Charli3 oracle NFT policy ID used to identify the price feed UTxO
  oracle_nft: ByteArray,
  /// Payment script hash of the pool validator for returning funds
  pool_script_hash: ScriptHash,
  /// [FIX A-008] NFT identifying the canonical pool. Used by Claim/Expire/Cancel
  /// to verify that the residual is sent to the REAL pool UTxO (one carrying
  /// `pool_nft`), not just any UTxO at `pool_script_hash`. Without this binding
  /// an attacker could route policy residuals to a stuck UTxO at the pool address
  /// that the pool validator can't subsequently spend.
  pool_nft: ByteArray,
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
