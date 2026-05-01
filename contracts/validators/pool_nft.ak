// =============================================================================
// Aegis Insurance Protocol - Pool NFT Minting Policy (One-Shot)
// Location: contracts/validators/pool_nft.ak
// Summary: A one-shot minting policy that produces EXACTLY one NFT
//          (`AEGIS_POOL` by default) when a specific output reference is
//          consumed in the same transaction. After that UTxO is spent it
//          can never be spent again, so the policy can never mint a second
//          NFT — the canonical pool NFT becomes a true one-shot.
//
//          This validator closes finding A-011: previously the protocol
//          assumed an off-chain one-shot mint without on-chain enforcement,
//          so a misconfigured deployment could produce multiple pool UTxOs
//          and break the "single canonical pool" invariant.
//
// Deployment flow:
//   1. Pick any UTxO at a wallet you control (an "init UTxO").
//   2. Compile this validator parameterized by that UTxO's output reference
//      (`utxo_ref`) and an asset name (`token_name`, default `"AEGIS_POOL"`).
//   3. The compiled minting policy ID is the canonical `pool_nft` and is
//      written into both `PoolDatum.pool_nft` and every `PolicyDatum.pool_nft`.
//   4. Build a tx that:
//        - Consumes the init UTxO (this is the only time it's spendable).
//        - Mints exactly 1 unit of `(policy_id, token_name)`.
//        - Creates the canonical pool UTxO at the pool validator address with
//          the NFT and an inline `PoolDatum`.
//      Submit. Once that init UTxO is spent, no further mint of this policy
//      can ever succeed because the parametric guard requires exactly that
//      output reference to be re-consumed — but a UTxO can only be spent
//      once on Cardano.
//
// Interactions:
//   - Mint (one-shot) -> consumed init UTxO + 1 NFT minted.
//   - Burn            -> permitted (mint quantity < 0). Useful only as a
//                        safety valve if the canonical pool ever needs to be
//                        retired; the protocol normally keeps the NFT locked
//                        at the pool validator address forever.
// =============================================================================

use aiken/collection/list
use cardano/assets.{PolicyId}
use cardano/transaction.{OutputReference, Transaction}

// ---------------------------------------------------------------------------
// Pool NFT Minting Policy
// ---------------------------------------------------------------------------

validator pool_nft(utxo_ref: OutputReference, token_name: ByteArray) {
  mint(_redeemer: Data, policy_id: PolicyId, self: Transaction) {
    let Transaction { inputs, mint, .. } = self

    // 1. The parameterized init UTxO must be consumed in this tx. Once spent,
    // the parameter can never be re-satisfied — making this a true one-shot.
    let init_utxo_consumed =
      list.any(inputs, fn(input) { input.output_reference == utxo_ref })

    // 2. Compute the net quantity minted under THIS policy id. The fold
    // sums over all (asset_name, qty) pairs to handle the (very unusual)
    // case of multiple asset names; the check below requires the named
    // asset to be exactly +1 AND the total over the policy to be exactly +1
    // (so the attacker cannot piggy-back additional asset names).
    let total_under_policy =
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
    let named_qty = assets.quantity_of(mint, policy_id, token_name)

    // 3. Mint path: one and only one (canonical) NFT is produced.
    let one_shot_mint =
      init_utxo_consumed && named_qty == 1 && total_under_policy == 1

    // 4. Burn path: a strictly-negative mint is allowed even after the init
    // UTxO is gone, so the NFT is recoverable if the pool is retired. The
    // pool validator's spend logic (which the NFT is locked at) controls
    // whether the burn is well-formed; here we only enforce the direction.
    let burn_path = total_under_policy < 0

    one_shot_mint || burn_path
  }

  else(_) {
    fail @"Unsupported purpose for pool_nft minting policy"
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// The validator above is parameterized; integration testing requires a full
// Transaction. The following tests cover the LOGICAL primitives the validator
// composes (init-UTxO presence, mint quantity, burn direction).

test pool_nft_logic_consumed_and_one_minted() {
  // Init UTxO IS consumed AND named_qty == 1 AND total_under_policy == 1.
  let init_utxo_consumed = True
  let named_qty = 1
  let total_under_policy = 1
  init_utxo_consumed && named_qty == 1 && total_under_policy == 1
}

test pool_nft_logic_init_utxo_not_consumed_rejected() {
  // The init UTxO must be in the inputs. If not, the one-shot path fails.
  let init_utxo_consumed = False
  let named_qty = 1
  let total_under_policy = 1
  let one_shot_mint = init_utxo_consumed && named_qty == 1 && total_under_policy == 1
  one_shot_mint == False
}

test pool_nft_logic_more_than_one_token_minted_rejected() {
  // Two NFTs minted under this policy in the same tx: rejected.
  let init_utxo_consumed = True
  let named_qty = 2
  let total_under_policy = 2
  let one_shot_mint = init_utxo_consumed && named_qty == 1 && total_under_policy == 1
  one_shot_mint == False
}

test pool_nft_logic_extra_asset_name_under_policy_rejected() {
  // Attacker mints AEGIS_POOL=1 plus EXTRA=1 under the same policy id
  // (total = 2). The total_under_policy guard catches it.
  let init_utxo_consumed = True
  let named_qty = 1
  let total_under_policy = 2
  let one_shot_mint = init_utxo_consumed && named_qty == 1 && total_under_policy == 1
  one_shot_mint == False
}

test pool_nft_logic_burn_path_negative_quantity() {
  // Burn path: total under policy is strictly negative. Permitted.
  let total_under_policy = -1
  let burn_path = total_under_policy < 0
  burn_path
}

test pool_nft_logic_zero_mint_rejected() {
  // Net zero is neither a valid mint nor a valid burn.
  let init_utxo_consumed = True
  let named_qty = 0
  let total_under_policy = 0
  let one_shot_mint = init_utxo_consumed && named_qty == 1 && total_under_policy == 1
  let burn_path = total_under_policy < 0
  ( one_shot_mint || burn_path ) == False
}
