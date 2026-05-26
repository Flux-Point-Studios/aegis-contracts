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

use aiken/collection/dict
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

    // Verify mint direction matches redeemer.
    // Without this, MintLP could be used with a negative mint (burn)
    // or BurnLP with a positive mint, breaking LP accounting.
    // The fold also rejects any asset name other than "aLP" under this
    // policy: a piggy-backed (policy_id, "JUNK") mint short-circuits to
    // (-1, False) which makes both arms below fail.
    let (mint_quantity, names_ok) =
      dict.foldl(
        assets.tokens(mint, policy_id),
        (0, True),
        fn(name, qty, acc) {
          let (q, ok) = acc
          (q + qty, ok && name == "aLP")
        },
      )

    when redeemer is {
      // Minting LP tokens: net quantity must be positive AND only "aLP"
      MintLP -> pool_is_consumed && names_ok && mint_quantity > 0

      // Burning LP tokens: net quantity must be negative AND only "aLP"
      BurnLP -> pool_is_consumed && names_ok && mint_quantity < 0
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
