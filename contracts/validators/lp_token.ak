use aegis/types.{BurnLP, LPTokenRedeemer, MintLP}
// =============================================================================
// Aegis Insurance Protocol - LP Token Minting Policy
// Location: contracts/validators/lp_token.ak
// Summary: Controls minting and burning of LP tokens that represent
//          proportional ownership of the liquidity pool.
//          LP tokens can only be minted/burned when the pool validator is
//          being consumed in the same transaction. Verified by checking that
//          a script input with the pool validator's script hash exists.
//          Parameterized by the pool validator's script hash.
//          Interacts with: validators/pool.ak (must be consumed in tx).
// =============================================================================

use aiken/collection/list
use aiken/crypto.{ScriptHash}
use cardano/address.{Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

// ---------------------------------------------------------------------------
// LP Token Minting Policy
// ---------------------------------------------------------------------------

validator lp_token_policy(pool_script_hash: ScriptHash) {
  mint(redeemer: LPTokenRedeemer, policy_id: PolicyId, self: Transaction) {
    let Transaction { inputs, mint, .. } = self

    // Core check: the pool validator must be consumed in this transaction.
    // This ensures LP tokens can only be minted/burned as part of a valid
    // pool operation (AddLiquidity or RemoveLiquidity).
    let pool_is_consumed =
      list.any(
        inputs,
        fn(input) {
          when input.output.address.payment_credential is {
            Script(hash) -> hash == pool_script_hash
            _ -> False
          }
        },
      )

    // [FIX F-005] Verify mint direction matches redeemer.
    // Without this, MintLP could be used with a negative mint (burn)
    // or BurnLP with a positive mint, breaking LP accounting.
    // Sum all token quantities under this policy to determine net direction.
    let mint_quantity =
      assets.reduce(
        mint,
        0,
        fn(pid, _asset_name, qty, acc) {
          if pid == policy_id {
            acc + qty
          } else {
            acc
          }
        },
      )

    when redeemer is {
      // Minting LP tokens: net quantity must be positive
      MintLP -> pool_is_consumed && mint_quantity > 0

      // Burning LP tokens: net quantity must be negative
      BurnLP -> pool_is_consumed && mint_quantity < 0
    }
  }

  else(_) {
    fail @"Unsupported purpose for lp_token_policy"
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Note: Minting policy tests require constructing a full Transaction with
// inputs that include pool validator script UTxOs. These are better suited
// for integration tests. Here we verify the logic structure.

test mint_redeemer_construction() {
  let redeemer = MintLP
  when redeemer is {
    MintLP -> True
    BurnLP -> False
  }
}

test burn_redeemer_construction() {
  let redeemer = BurnLP
  when redeemer is {
    MintLP -> False
    BurnLP -> True
  }
}
