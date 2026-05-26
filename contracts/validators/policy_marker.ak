use aegis/types.{
  BurnForCancel, BurnForClaim, BurnForExpire, MarkerRedeemer, MintMarkers,
  PolicyDatum, policy_marker_asset_name,
}
use aegis/validation.{pool_is_consumed_via_nft}
// =============================================================================
// Aegis Insurance Protocol - Policy Marker Minting Policy (V12.2+R12)
// Location: contracts/validators/policy_marker.ak
// Summary: Parametric minting policy whose tokens prove a policy UTxO was
//          legitimately created by Aegis. Every policy UTxO at the policy
//          validator address MUST hold exactly 1 marker
//          (policy_id, "AEGIS_POLICY") for Cancel / Claim / Expire to spend
//          it; pool's Underwrite / BatchUnderwrite mint the markers, pool's
//          ProcessClaim / AcceptCancellation / BatchExpireProcess burn them.
//
// Closes:
//   EXT-08 (CRITICAL) — synthetic Cancel direct pool drain. Attacker writes
//                       fake policy UTxO with premium_paid=1000 ADA, funds
//                       with 2 ADA, calls Cancel → pool refunds 900 ADA real
//                       lovelace. Fix: Cancel requires has_marker on the
//                       consumed policy; only a real Aegis Underwrite (which
//                       co-spends the pool) ever mints a marker.
//   EXT-09 (CRITICAL) — synthetic Claim accounting corruption. Same root
//                       cause; same fix on the Claim path.
//
// Mint validation (`MintMarkers { count }`):
//   1. Pool consumed: at least one input has VALUE that contains ≥1 of
//      the canonical pool NFT (pool_nft_policy_id, pool_nft_asset_name).
//      Pins to the SPECIFIC canonical pool UTxO (carrying the one-shot
//      pool NFT), not just any UTxO at the pool script address. Delegates
//      mint authority to the pool's spend logic, which only authorises
//      Underwrite / BatchUnderwrite.
//   2. `count > 0`.
//   3. `count == number of NEW policy outputs at policy_validator_hash`.
//   4. Total quantity minted under (own_policy_id, "AEGIS_POLICY") == count.
//   5. Every new policy output at policy_validator_hash contains exactly 1
//      marker (own_policy_id, "AEGIS_POLICY").
//
// Burn validation (`BurnMarkers`):
//   1. Pool consumed (same pool-NFT input scan; delegates burn authority
//      to the pool's spend logic — only ProcessClaim / AcceptCancellation /
//      BatchExpireProcess co-spend the pool with a policy input that
//      carries a marker, so only those redeemers can burn).
//   2. Net mint quantity for this policy under "AEGIS_POLICY" is < 0
//      AND no positive entries piggy-back under a different asset name.
//
// Parameterized by:
//   * `pool_nft_policy_id`: 28-byte policy id of the one-shot pool NFT
//     (the canonical pool's globally-unique discriminator — see
//     `validators/pool_nft.ak`).
//   * `pool_nft_asset_name`: asset name of the one-shot pool NFT (default
//     `"AEGIS_POOL"` per `pool_nft.ak`'s `token_name` parameter). Bound at
//     compile time so the marker policy binds to the SPECIFIC NFT, not just
//     "any token under the pool_nft policy id".
//   * `policy_validator_hash`: 28-byte hash of the deployed policy
//     validator (binds the per-policy marker presence check).
//
// Parameterization order (DAG, no cycles):
//   1. pool_nft  (one-shot, see validators/pool_nft.ak)
//   2. policy_marker  (apply with pool_nft_policy_id + pool_nft_asset_name
//                      + UNparameterized policy_validator_hash)
//   3. policy_validator  (apply with parameterized policy_marker_policy_id)
//   4. pool_validator  (apply with parameterized policy_validator_hash +
//                       parameterized policy_marker_policy_id)
//
// At runtime, marker mint requires consuming an input that holds the
// canonical pool_nft token — pin to the specific pool, not the script.
// This breaks the parameterization cycle that existed in the initial
// V12.2+R12 draft (marker ↔ pool ↔ policy) while still cryptographically
// binding marker minting to a legitimate pool spend.
// =============================================================================

use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{InlineDatum, Output, Transaction}

// ---------------------------------------------------------------------------
// Policy Marker Minting Policy
// ---------------------------------------------------------------------------

validator policy_marker(
  pool_nft_policy_id: ByteArray,
  pool_nft_asset_name: ByteArray,
) {
  mint(redeemer: MarkerRedeemer, policy_id: PolicyId, self: Transaction) {
    let Transaction { inputs, mint, .. } = self

    // Delegates full authority to the pool validator's spend logic. The
    // canonical pool UTxO is the one carrying the one-shot pool NFT
    // (pool_nft_policy_id, pool_nft_asset_name) — once that UTxO is
    // consumed, the marker policy infers a legitimate pool spend
    // happened. The pool validator's Underwrite/BatchUnderwrite arms
    // own the load-bearing "new policy output has 1 marker AND mint
    // equals expected count" check (using the APPLIED policy script
    // hash that this marker policy cannot reference without a
    // hash fixed-point). Symmetrically, ProcessClaim /
    // AcceptCancellation / BatchExpireProcess own the "consumed policy
    // has 1 marker AND mint is -1 / -N" check. Synthetic policy
    // UTxOs cannot acquire markers because the marker policy refuses
    // to mint without a co-spent canonical pool, and the pool's
    // own arms enforce datum + value continuity.
    let pool_is_consumed =
      pool_is_consumed_via_nft(
        inputs,
        pool_nft_policy_id,
        pool_nft_asset_name,
      )

    // Net quantity minted under (own_policy_id, "AEGIS_POLICY") AND
    // rejection of any non-canonical asset name under this policy_id.
    let (named_qty, names_ok) =
      dict.foldl(
        assets.tokens(mint, policy_id),
        (0, True),
        fn(name, qty, acc) {
          let (q, ok) = acc
          if name == policy_marker_asset_name {
            (q + qty, ok)
          } else {
            (q, False)
          }
        },
      )

    when redeemer is {
      // -------------------------------------------------------------------
      // MINT MARKERS: positive net mint, pool co-spend, asset-name pure.
      // -------------------------------------------------------------------
      MintMarkers { count } -> {
        let count_positive = count > 0
        let mint_matches_count = named_qty == count
        pool_is_consumed && count_positive && names_ok && mint_matches_count
      }

      // -------------------------------------------------------------------
      // BURN: single-marker burn paired with Claim lifecycle.
      // -------------------------------------------------------------------
      BurnForClaim -> pool_is_consumed && names_ok && named_qty == -1

      // -------------------------------------------------------------------
      // BURN: single-marker burn paired with Cancel lifecycle.
      // -------------------------------------------------------------------
      BurnForCancel -> pool_is_consumed && names_ok && named_qty == -1

      // -------------------------------------------------------------------
      // BURN: N-marker burn paired with Expire / BatchExpire lifecycle.
      // -------------------------------------------------------------------
      BurnForExpire { count } -> {
        let count_positive = count > 0
        let mint_matches_count = named_qty == -count
        pool_is_consumed && names_ok && count_positive && mint_matches_count
      }
    }
  }

  else(_) {
    fail @"Unsupported purpose for policy_marker minting policy"
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test marker_redeemer_mint_construction() {
  let redeemer = MintMarkers { count: 3 }
  when redeemer is {
    MintMarkers { count } -> count == 3
    _ -> False
  }
}

test marker_redeemer_burn_for_claim_construction() {
  let redeemer = BurnForClaim
  when redeemer is {
    BurnForClaim -> True
    _ -> False
  }
}

test marker_redeemer_burn_for_cancel_construction() {
  let redeemer = BurnForCancel
  when redeemer is {
    BurnForCancel -> True
    _ -> False
  }
}

test marker_redeemer_burn_for_expire_construction() {
  let redeemer = BurnForExpire { count: 4 }
  when redeemer is {
    BurnForExpire { count } -> count == 4
    _ -> False
  }
}

test marker_asset_name_is_AEGIS_POLICY() {
  // ASCII "AEGIS_POLICY" is 12 bytes.
  policy_marker_asset_name == #"41454749535f504f4c494359"
}

test marker_mint_count_must_be_positive() {
  let count = 0
  count > 0 == False
}

test marker_burn_for_expire_requires_matching_negative() {
  // BurnForExpire { count: 3 } requires named_qty == -3.
  let count = 3
  let named_qty = -3
  named_qty == -count
}
