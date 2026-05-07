// =============================================================================
// Aegis Insurance Protocol - Auth Witness Validator (v8 / RELAY-PRESIGNED-AUTH)
// Location: contracts/validators/auth_witness.ak
// Summary: Locks the auth witness UTxO at a script address. Witness UTxOs
//          are reference-only for `ClaimWithAuth`; they can be normal-spent
//          ONLY along two narrowly-scoped paths:
//
//            (1) Burn-only: a tx that burns the auth witness NFT in the same
//                Mint redeemer (BurnViaConsume / SweepBurn) as it consumes
//                the witness UTxO. The continuation-output check rejects
//                any tx that "burns" the NFT but recreates it at this
//                validator via a separate mint+output.
//
//            (2) [Δ32 / VR-002] Rotation respend: a tx that consumes the
//                old witness UTxO and produces a new witness UTxO at this
//                validator with the SAME NFT asset name. The NFT moves
//                with the UTxO (no mint, no burn — net mint quantity for
//                the asset is 0). The policy validator's `RotateAuth`
//                branch is the cryptographic gate (user CIP-30 sig + new-
//                payload binding chain); this validator's only job on the
//                rotation path is to refuse a substitution that would
//                produce TWO outputs carrying the same NFT (which would
//                later break ClaimWithAuth's `count == 1` gate).
//
//          Pre-Δ32 (v3 spec) RotateAuth was implemented by minting a
//          second witness alongside the unburned old one — leaving two
//          UTxOs sharing the same asset_name on chain. ClaimWithAuth's
//          `length(witnesses) == 1` gate then rejected every claim until
//          the policy expired AND the operator could SweepBurn the
//          orphan. Verification red-team finding VR-002 (HIGH). Option A
//          of the v3.1 remediation moves the NFT through the witness
//          UTxO without invoking the mint policy at all — there is never
//          more than one witness UTxO under a given asset_name post-
//          rotation, so ClaimWithAuth's count gate stays satisfied.
// =============================================================================

use aegis/types.{auth_witness_nft_policy_id}
use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Script}
use cardano/assets
use cardano/transaction.{OutputReference, Transaction}

// ---------------------------------------------------------------------------
// Auth Witness Validator
// ---------------------------------------------------------------------------

validator auth_witness_validator {
  spend(
    _datum: Option<Data>,
    _redeemer: Data,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    let Transaction { inputs, outputs, mint, .. } = self

    // Locate the witness UTxO being spent (this validator).
    expect Some(self_input) =
      list.find(inputs, fn(i) { i.output_reference == own_ref })

    // Determine the asset name carried on the witness UTxO. By
    // construction this is `blake2b_224(policy_id)` — but we don't need
    // to recompute the policy_id here; we simply iterate the value and
    // find the unique asset under `auth_witness_nft_policy_id`.
    let own_value = self_input.output.value
    let assets_for_policy =
      assets.tokens(own_value, auth_witness_nft_policy_id)
        |> dict.to_pairs

    // The witness must carry exactly one auth_witness NFT.
    expect [Pair(asset_name, qty)] = assets_for_policy
    let witness_qty_ok = qty == 1

    // Determine the script hash of the validator the spent UTxO sat at —
    // i.e., this validator's own hash. Used for both the burn-path
    // continuation check and the rotation-path continuation lookup.
    expect Script(own_script_hash) =
      self_input.output.address.payment_credential

    // Net mint quantity for the (auth_witness_nft_policy_id, asset_name)
    // pair in this tx. -1 indicates a burn (path 1); 0 indicates a pure
    // re-spend without mint activity (path 2 — rotation).
    let mint_qty =
      assets.quantity_of(mint, auth_witness_nft_policy_id, asset_name)

    // Count witness continuations at this validator carrying the same
    // (auth_witness_nft_policy_id, asset_name) pair. The continuation
    // count is the load-bearing primitive for both paths:
    //   * Burn path: must be 0 (asset disappears entirely from chain).
    //   * Rotation path: must be exactly 1 (asset moves with the new
    //     witness UTxO; never 2 — that would re-create the
    //     count==1-gate-fails scenario VR-002 originally exposed).
    let continuation_count =
      list.foldl(
        outputs,
        0,
        fn(out, acc) {
          when out.address.payment_credential is {
            Script(h) ->
              if h == own_script_hash {
                let q =
                  assets.quantity_of(
                    out.value,
                    auth_witness_nft_policy_id,
                    asset_name,
                  )
                if q == 1 {
                  acc + 1
                } else {
                  acc
                }
              } else {
                acc
              }
            _ -> acc
          }
        },
      )

    // Path 1 — Burn-only: the matching NFT is being burned in this tx
    // (mint == -1) AND no continuation output at this validator carries
    // it. Closes the surface where an attacker "burns" the asset and
    // re-mints it at the same address in the same tx (impossible by
    // mint-policy construction, but a layered check makes the audit
    // story tighter).
    let burn_path_valid = mint_qty == -1 && continuation_count == 0

    // Path 2 — Rotation respend (Δ32 / VR-002): the NFT is neither
    // minted nor burned (mint_qty == 0) AND exactly one continuation
    // output exists at this validator with the same asset_name. The
    // policy validator's RotateAuth branch independently enforces:
    //   (a) user CIP-30 signature on the rotation,
    //   (b) the policy UTxO is consumed and recreated with the new
    //       commitment,
    //   (c) the new witness UTxO's datum carries a canonically-encoded
    //       payload whose 14 fields all bind to the policy datum and
    //       active-network constants, and whose Ed25519 signature
    //       verifies (Δ33).
    // This validator's job on the rotation path is purely structural:
    // refuse a TWO-witness configuration that would later break
    // ClaimWithAuth's `length(witnesses) == 1` gate.
    let rotate_path_valid = mint_qty == 0 && continuation_count == 1

    witness_qty_ok && ( burn_path_valid || rotate_path_valid )
  }

  else(_) {
    fail @"auth_witness_validator only supports the spend purpose"
  }
}
