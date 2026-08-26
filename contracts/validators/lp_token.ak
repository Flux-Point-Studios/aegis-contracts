use aegis/types.{BurnLP, LPTokenRedeemer, MintLP}
use aegis/validation.{pool_is_consumed_via_nft}
// =============================================================================
// Aegis Insurance Protocol - LP Token Minting Policy
// Location: contracts/validators/lp_token.ak
// Summary: Controls minting and burning of LP tokens that represent
//          proportional ownership of the liquidity pool. aLP can only be
//          minted/burned when the vault's ONE-SHOT pool NFT is consumed in the
//          same tx (i.e. the pool_vault UTxO is being spent) — binding to the
//          unforgeable NFT, NOT a raw pool-script-hash scan.
//
//          Why the NFT, not the script hash (red-team C3 / COVERAGE-ARM-SPEC
//          item 17): a script-hash scan authorises ANY UTxO at the pool address,
//          and — critically — parameterising this policy by the pool_vault hash
//          while pool_vault is parameterised by THIS policy id forms a
//          bidirectional const cycle that never converges at ceremony time
//          (a deploy deadlock). Binding to `pool_nft_policy` (minted first, from
//          a seed UTxO, standalone) makes this policy depend only on the NFT, so
//          the parameter chain is acyclic: pool_nft -> lp_token -> pool_vault.
//          The pool NFT is a one-shot that lives ONLY in the vault, so
//          "NFT consumed" == "vault spent" — identical authority, unforgeable.
// =============================================================================

use aiken/collection/dict
use cardano/address.{Address, VerificationKey}
use cardano/assets.{PolicyId}
use cardano/transaction.{
  Input, NoDatum, Output, OutputReference, Transaction, placeholder,
}

// ---------------------------------------------------------------------------
// LP Token Minting Policy
// ---------------------------------------------------------------------------

validator lp_token_policy(pool_nft_policy: PolicyId, pool_nft_name: ByteArray) {
  mint(redeemer: LPTokenRedeemer, policy_id: PolicyId, self: Transaction) {
    let Transaction { inputs, mint, .. } = self

    // Core check: the vault's one-shot pool NFT must be consumed in this tx,
    // which the ledger only allows when the pool_vault UTxO is spent — and the
    // vault only permits an aLP mint/burn inside AddLiquidity / RemoveLiquidity.
    let pool_is_consumed =
      pool_is_consumed_via_nft(inputs, pool_nft_policy, pool_nft_name)

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

const lt_nft_policy: ByteArray = #"a0a1"

const lt_nft_name: ByteArray = #"41454749535f504f4f4c"

const lt_lp_policy: ByteArray = #"b0b1"

fn lt_input(value: assets.Value) -> Input {
  Input {
    output_reference: OutputReference {
      transaction_id: #"00",
      output_index: 0,
    },
    output: Output {
      address: Address {
        payment_credential: VerificationKey(#"cc"),
        stake_credential: None,
      },
      value: value,
      datum: NoDatum,
      reference_script: None,
    },
  }
}

fn lt_tx(with_nft: Bool, mint: assets.Value) -> Transaction {
  let val =
    if with_nft {
      assets.from_lovelace(2_000_000)
        |> assets.add(lt_nft_policy, lt_nft_name, 1)
    } else {
      assets.from_lovelace(2_000_000)
    }
  Transaction { ..placeholder, inputs: [lt_input(val)], mint: mint }
}

test lp_mint_allowed_when_pool_nft_consumed() {
  lp_token_policy.mint(
    lt_nft_policy,
    lt_nft_name,
    MintLP,
    lt_lp_policy,
    lt_tx(True, assets.from_asset(lt_lp_policy, "aLP", 100)),
  )
}

test lp_mint_rejected_when_pool_nft_absent() {
  // No pool NFT consumed -> pool_is_consumed False. This is the C3 / cycle fix:
  // an aLP mint is authorised ONLY by the vault singleton, never a bare tx.
  !lp_token_policy.mint(
    lt_nft_policy,
    lt_nft_name,
    MintLP,
    lt_lp_policy,
    lt_tx(False, assets.from_asset(lt_lp_policy, "aLP", 100)),
  )
}

test lp_burn_allowed_when_pool_nft_consumed() {
  lp_token_policy.mint(
    lt_nft_policy,
    lt_nft_name,
    BurnLP,
    lt_lp_policy,
    lt_tx(True, assets.from_asset(lt_lp_policy, "aLP", -100)),
  )
}

test lp_mint_rejected_wrong_direction() {
  // MintLP with a negative net -> rejected (direction bind).
  !lp_token_policy.mint(
    lt_nft_policy,
    lt_nft_name,
    MintLP,
    lt_lp_policy,
    lt_tx(True, assets.from_asset(lt_lp_policy, "aLP", -100)),
  )
}

test lp_mint_rejected_non_alp_name() {
  // A piggy-backed non-"aLP" token under this policy -> names_ok False.
  !lp_token_policy.mint(
    lt_nft_policy,
    lt_nft_name,
    MintLP,
    lt_lp_policy,
    lt_tx(True, assets.from_asset(lt_lp_policy, "JUNK", 100)),
  )
}
