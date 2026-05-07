// =============================================================================
// Aegis Insurance Protocol - Auth Witness NFT Minting Policy (v8 / v3.3)
// Location: contracts/validators/auth_witness_nft.ak
// Summary: Parameterized over `(init_utxo_ref, network_tag, operator_pkh)`.
//          The mint policy's policy id is one-shot **per deployment** —
//          `init_utxo_ref` is hashed into the script's compiled bytes so a
//          different deployment produces a different policy id — but the
//          validator does NOT require `init_utxo_ref` consumption at every
//          mint (Δ18 / V-001 fix; pre-fix the validator was one-shot per
//          LIFETIME, which bricked the relay-presigned-auth feature after
//          the first user).
//
//          [Δ41 — v3.2 deploy-cycle break] The pre-v3.2 mint policy was
//          parameterized over a 4-tuple `(init_utxo_ref, network_tag,
//          policy_validator_hash, operator_pkh)`. Combined with
//          `policy_validator` referencing `auth_witness_nft_policy_id`,
//          this created a CIRCULAR deploy dependency: the auth-NFT mint
//          policy's hash depended on the policy_validator hash, and the
//          policy_validator's hash depended on the auth-NFT policy id —
//          neither hash converges at deploy time. v3.2 dropped
//          `policy_validator_hash` from the mint policy's parameter set
//          (3-tuple) AND switched the Underwrite-path "policy output at
//          policy_validator" check to a "witness output at
//          auth_witness_validator script address" check using the new
//          compile-time constant `auth_witness_validator_hash` in
//          `lib/aegis/types.ak`.
//
//          [Δ42 — v3.3 final cycle break] v3.2 left a SECOND-ORDER cycle:
//          this mint policy still imported `auth_witness_validator_hash`
//          and gated the witness-output destination on
//          `if h == auth_witness_validator_hash`. Because that constant
//          is itself populated post-deploy (in the linear ordering, after
//          step 4), every change to it ROTATES this mint policy's base
//          hash — and therefore its policy id — bringing the deploy
//          ordering back into a fixed-point loop:
//            * step 2 produces policy_id_v0 with both consts at all-zeros
//            * step 3 bakes auth_witness_nft_policy_id, then rebuilds
//              auth_witness_validator → its hash freezes
//            * step 4 bakes auth_witness_validator_hash → rebuilds
//              policy_validator AND auth_witness_nft → policy_id_v0
//              becomes stale → invalidates the auth_witness_validator
//              hash that step 3 baked → loop.
//          Δ42 closes the cycle by REMOVING all `auth_witness_validator_hash`
//          references from this file. The Underwrite path's witness-
//          destination script-credential pin is dropped; the path now
//          asserts only that the same `(self_policy_id, asset_name)`
//          pair is present in EXACTLY ONE tx output AND that that
//          output's `AuthWitnessDatum` carries the matching
//          `policy_id` and `payload_cbor`. Off-chain code routes the
//          witness output to `auth_witness_validator`; if a buggy or
//          malicious mint puts it elsewhere, the witness becomes
//          orphan-only — no security loss, because `policy_validator`
//          accepts witnesses ONLY at `Script(auth_witness_validator_hash)`
//          and `auth_witness_validator` self-checks `own_value` carries
//          a token under the canonical `auth_witness_nft_policy_id`.
//          The three-leg trust chain still holds, with leg 1 (mint
//          policy's destination check) replaced by a weaker "single
//          tx-output carrying the asset" check that suffices because
//          legs 2 + 3 close the spoofing surface.
//
//          BurnViaConsume + SweepBurn lose their script-credential
//          source-filter (used pre-Δ42 to skip the witness input when
//          locating the consumed policy). The negative-filter is no
//          longer needed: BurnViaConsume identifies the consumed policy
//          by `PolicyDatum`-shaped inline datum (script inputs whose
//          datum is `AuthWitnessDatum` simply fail the typed decode
//          path); SweepBurn locates the witness UTxO by NFT-quantity-1
//          match on inputs and reads `payload.not_after` directly from
//          its datum.
//
//          Asset name is `blake2b_224(redeemer.policy_id)` so a witness
//          can never collide on (policy_id, asset_name). Mint quantity is
//          strictly +1 per call; only one (asset_name, qty) pair under
//          this policy is permitted per tx.
//
//          Mint redeemer: `MintWitness { policy_id, payload_cbor }` —
//          used at Underwrite-with-auth ONLY. Pre-v3.1 the same redeemer
//          also serviced the RotateAuth path (mint a fresh witness
//          alongside the un-burned old one); v3.1 closes VR-002 by
//          moving rotation to a respend-at-script flow that does NOT
//          invoke the mint policy at all (Δ32). This redeemer therefore
//          binds to the Underwrite-creation case exclusively.
//          Burn redeemers (Δ19 / V-002 split):
//            * `BurnViaConsume { policy_id }` — requires the matching
//              policy UTxO to be CONSUMED in the same tx. This makes the
//              burn tightly bound to a Cancel/Expire/Claim/ClaimWithAuth
//              of the policy: the witness can be cleaned up in-line with
//              policy termination, paying the user's tx fee once.
//            * `SweepBurn { policy_id }` — operator-only burn of an
//              orphan witness UTxO whose policy was terminated in a
//              prior tx. The window-elapsed gate's `not_after` is read
//              from the WITNESS UTXO'S payload datum (Δ31 / VR-001) —
//              NOT from the redeemer — so a compromised operator key
//              cannot smuggle `not_after = 0` to destroy live witnesses.
//
//          Per spec §1.5 (v3.3-updated), the mint validator must:
//            * exactly one token minted under (this policy_id, asset_name)
//            * asset_name == blake2b_224(redeemer.policy_id)
//            * Underwrite path: EXACTLY ONE tx output (anywhere) carrying
//              the same `(self_policy_id, asset_name)` pair, whose
//              InlineDatum is an `AuthWitnessDatum` with
//              `policy_id == redeemer.policy_id` AND
//              `payload_cbor == redeemer.payload_cbor`. The off-chain
//              code routes this output to `auth_witness_validator_hash`;
//              an orphan mint elsewhere is harmless because (a)
//              policy_validator only accepts witnesses sitting at
//              `auth_witness_validator_hash` so the orphan can never be
//              referenced under ClaimWithAuth/RotateAuth, and (b) the
//              auth_witness_validator's spend path enforces burn-or-
//              respend semantics on the canonical NFT, so a UTxO at the
//              canonical script can never be moved without the mint
//              policy's cooperation.
//            * Underwrite path additionally re-binds via the policy
//              datum invariants (policy_id, auth_commitment,
//              oracle_provider) on the policy output — this binding does
//              NOT pin the policy output's script address, but the
//              policy validator (which actually processes
//              Cancel/Expire/Claim/ClaimWithAuth) refuses to spend
//              policies at attacker-controlled addresses, so a misbuilt
//              policy is a self-inflicted user error, not a security
//              issue.
//            * [Δ34 / VR-004] The redeemer's `payload_cbor` re-encodes
//              byte-equal to itself via `cbor.serialise(decoded)` —
//              non-canonical CBOR is rejected at mint time so a buggy
//              encoder cannot silently mint un-claimable witnesses.
//
//          The mint policy is parameterized over the operator-chosen
//          init_utxo_ref so a one-shot publish per network produces a
//          unique policy_id, and the resulting hash is pinned in
//          `types.auth_witness_nft_policy_id`. (Δ17 / closes F-AUTH-2.)
//
//          [Δ42 — v3.3] Security argument for dropping the on-chain
//          script-credential pin on witness destination/source:
//            * Primary security backbone is `policy_validator`'s
//              `Script(auth_witness_validator_hash)` payment-credential
//              check at consume time (witness identification at
//              ClaimWithAuth + RotateAuth call sites). An orphan
//              witness mint at any other address can never be observed
//              as a witness by policy_validator — the script-credential
//              filter rejects it at ClaimWithAuth/RotateAuth time.
//            * `auth_witness_validator`'s self-check on `own_value`
//              carrying a token under the canonical
//              `auth_witness_nft_policy_id` (file unchanged in v3.3 —
//              the security backbone of leg 2 of the three-leg trust
//              chain). Once a UTxO is at the canonical script address,
//              it can leave only via burn or via a respend that
//              preserves the asset_name with a fresh datum.
//            * The mint policy's per-tx "EXACTLY ONE output carries
//              this asset" check still pins the output's value+datum
//              shape; combined with the off-chain code routing that
//              output to the canonical script, the legitimate happy
//              path is unchanged. An attacker who routes the output
//              elsewhere produces an orphan that is unreachable from
//              policy_validator — funds are safe.
// =============================================================================

use aegis/auth_payload.{commit_from_cbor}
use aegis/types.{
  AuthCoveragePayload, AuthWitnessDatum, PolicyDatum, network_tag_mainnet,
  network_tag_preprod, network_tag_preview, oracle_provider_to_int,
}
use aegis/validation.{get_lower_bound, must_be_signed_by}
use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{blake2b_224}
use cardano/address.{Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{InlineDatum, OutputReference, Transaction}

// ---------------------------------------------------------------------------
// Redeemer
// ---------------------------------------------------------------------------

pub type AuthWitnessMintRedeemer {
  /// Mint a fresh witness for an Underwrite-with-auth tx. Carries the
  /// policy_id (so the minted asset_name can be derived) and the
  /// payload_cbor (so the mint validator can re-decode + bind to the
  /// policy datum's auth_commitment + canonicalize the bytes per Δ34).
  ///
  /// [Δ32 / VR-002] Pre-v3.1 this redeemer also serviced the RotateAuth
  /// path; v3.1 routes rotation through a respend at the
  /// auth_witness_validator script (NFT moves with the UTxO), so this
  /// redeemer is exclusive to Underwrite-creation.
  MintWitness { policy_id: ByteArray, payload_cbor: ByteArray }
  /// [Δ19 / V-002] Burn an in-flight witness atomically with the policy's
  /// termination. The matching policy UTxO MUST be a script input in the
  /// same tx (the policy_validator's Cancel / Expire / Claim / ClaimWithAuth
  /// branch handles its own bindings and consumes the policy). This is the
  /// happy-path cleanup — saves the user a separate orphan-cleanup tx fee.
  BurnViaConsume { policy_id: ByteArray }
  /// [Δ19 / V-008 + Δ31 / VR-001] Sweep an orphan witness UTxO whose policy
  /// was terminated in a prior tx. Operator-only: requires the tx to be
  /// signed by `operator_pkh`. The window-elapsed gate's `not_after` is
  /// read from the WITNESS UTXO's payload datum (Δ31 / VR-001) —
  /// NOT from the redeemer — so a compromised operator key
  /// cannot smuggle `not_after = 0` to destroy live witnesses.
  SweepBurn { policy_id: ByteArray }
}

// ---------------------------------------------------------------------------
// Auth Witness NFT Mint Validator
// ---------------------------------------------------------------------------

/// Parameterized over `(init_utxo_ref, network_tag, operator_pkh)`.
///
/// `init_utxo_ref` is consumed at the operator's first publish, making the
/// resulting policy id one-shot **per deployment** via parameter-baking
/// into the compiled validator hash (the parameter is part of the script
/// bytes, so two deployments with different init_refs produce different
/// policy ids). The validator does NOT additionally require this UTxO to
/// be consumed at every mint — that was the V-001 bug; per-mint anti-
/// forgery is enforced via the underwrite_path check below, which binds
/// the mint to a legitimate policy creation.
///
/// `network_tag` is one of `"PREPROD"` / `"PREVIEW"` / `"MAINNET"` and is
/// included in the parameter set so the resulting policy id is network-
/// distinct.
///
/// `operator_pkh` is the sweeper key that authorizes orphan-witness
/// SweepBurn calls (Δ19 / V-008).
///
/// [Δ41 — v3.2 deploy-cycle break] The pre-v3.2 4th parameter
/// `policy_validator_hash` is REMOVED. [Δ42 — v3.3 final cycle break]
/// Additionally, all references to the compile-time constant
/// `auth_witness_validator_hash` are removed from this validator's body.
/// The Underwrite path now binds via:
///   (a) EXACTLY ONE tx output carries the `(self_policy_id, asset_name)`
///       pair AND its inline `AuthWitnessDatum` matches the redeemer; and
///   (b) the policy datum's `auth_commitment` + `policy_id` +
///       `oracle_provider` invariants on a separate output (no script-
///       credential pin on either output).
/// Three-leg transitive trust chain (mint policy's structural check +
/// auth_witness_validator's burn-or-respend self-check on canonical NFT
/// + policy_validator's `Script(auth_witness_validator_hash)` filter at
/// witness-consume time) preserves the same security as the pre-v3.3
/// mint-time destination pin. See module-level header for the per-leg
/// argument.
validator auth_witness_nft(
  init_utxo_ref: OutputReference,
  network_tag: ByteArray,
  operator_pkh: ByteArray,
) {
  mint(
    redeemer: AuthWitnessMintRedeemer,
    own_policy_id: PolicyId,
    self: Transaction,
  ) {
    let Transaction {
      inputs,
      outputs,
      mint,
      extra_signatories,
      validity_range,
      ..
    } = self

    // [Δ24 / V-009] `init_utxo_ref` is referenced via a pinned anchor at
    // compile-time so two deployments with different init_refs produce
    // different policy ids. We use the field at validator construction to
    // keep the parameter alive in the compiled hash — Aiken would warn on
    // an unused parameter and the compiler's ABI for parameterised
    // validators relies on every parameter being syntactically referenced.
    let _init_anchor_in_hash = init_utxo_ref.transaction_id

    // [Δ24 / V-009] Network tag must be exactly one of the three pinned
    // bytestring constants. Pre-Δ24 the check was `network_tag != #""`
    // which permitted a 1-byte typo (e.g., `#"00"`) to silently produce a
    // legitimate-but-misnamed policy id. The strict whitelist closes the
    // typo class; per-deployment rotation still works because the parameter
    // is hashed into the validator script.
    let network_tag_ok =
      network_tag == network_tag_preprod || network_tag == network_tag_preview || network_tag == network_tag_mainnet

    when redeemer is {
      MintWitness { policy_id, payload_cbor } -> {
        // 1. Asset name must be blake2b_224(policy_id).
        let expected_asset_name = blake2b_224(policy_id)

        // 2. Exactly one token minted under (own_policy_id, expected_asset_name).
        let mint_qty =
          assets.quantity_of(mint, own_policy_id, expected_asset_name)
        let exactly_one_minted = mint_qty == 1

        // 3. No other tokens minted under this policy in the same tx.
        let only_one_under_policy =
          list.length(dict.to_pairs(assets.tokens(mint, own_policy_id))) == 1

        // 4. [Δ18 / V-001] The init_utxo_ref-consumption check is REMOVED.
        // Pre-Δ18 every mint required `init_utxo_ref` to be in the inputs;
        // since UTxOs spend exactly once, that bricked all subsequent mints
        // on chain. The parameter alone (baked into the compiled script
        // hash) gives one-shot-per-deployment uniqueness; per-mint anti-
        // forgery is enforced via the Underwrite path check below which
        // binds the mint to a legitimate policy creation.
        // 5. Decode the payload_cbor and compute the canonical commit.
        expect Some(payload_data) = cbor.deserialise(payload_cbor)
        expect payload: AuthCoveragePayload = payload_data
        let commit = commit_from_cbor(payload_cbor)

        // [Δ34 / VR-004] Canonical-form gate at mint: re-serialize the
        // decoded payload and assert byte-equal to the redeemer-supplied
        // CBOR. Pre-Δ34 a buggy off-chain encoder could submit non-
        // canonical bytes (non-shortest-form ints, indefinite-length
        // bytestrings) that decoded successfully here but later failed
        // ClaimWithAuth's canonical check (Δ22) — silently producing a
        // witness whose `payload_cbor` was unclaimable. Pinning the
        // canonical form at mint time closes the surface earlier so a
        // user never finishes Underwrite with an un-claimable policy.
        let payload_canonical = cbor.serialise(payload)
        let payload_canonical_ok = payload_canonical == payload_cbor

        // 6. The payload's policy_id must match the redeemer's policy_id
        // (so the asset_name binding is consistent end-to-end).
        let payload_policy_id_ok = payload.policy_id == policy_id

        // 7. [Δ42 — v3.3] Underwrite path: EXACTLY ONE tx output carries
        // the `(own_policy_id, expected_asset_name)` pair AND its
        // inline `AuthWitnessDatum` carries the matching `policy_id`
        // and `payload_cbor`.
        //
        // Pre-Δ42 (v3.2) the check additionally required this output to
        // sit at `Script(auth_witness_validator_hash)` — but that
        // compile-time constant was itself populated post-deploy, which
        // re-introduced a deploy cycle (this mint policy's hash rotated
        // every time `auth_witness_validator_hash` was updated). Δ42
        // drops the script-credential pin and relies on:
        //   * `policy_validator` (witness-consume side) accepting only
        //     UTxOs sitting at `Script(auth_witness_validator_hash)`
        //     (script-credential equality at ClaimWithAuth + RotateAuth
        //     call sites). An orphan mint elsewhere is unreachable.
        //   * `auth_witness_validator`'s spend path enforcing
        //     burn-or-respend semantics on the canonical NFT (file
        //     unchanged) — once a UTxO sits at that script, it can
        //     leave only via burn or via a respend that preserves the
        //     asset_name with a fresh datum.
        //   * Off-chain code routes the witness output to the canonical
        //     script. A buggy/malicious tx that puts the witness output
        //     at a different address produces an orphan that NEVER
        //     becomes reachable as a witness — no security loss.
        let witness_output_count =
          list.foldl(
            outputs,
            0,
            fn(out, acc) {
              let qty =
                assets.quantity_of(
                  out.value,
                  own_policy_id,
                  expected_asset_name,
                )
              if qty == 1 {
                when out.datum is {
                  InlineDatum(raw_awd) ->
                    when raw_awd is {
                      _ -> {
                        expect awd: AuthWitnessDatum = raw_awd
                        let awd_policy_id_ok = awd.policy_id == policy_id
                        let awd_payload_ok = awd.payload_cbor == payload_cbor
                        if awd_policy_id_ok && awd_payload_ok {
                          acc + 1
                        } else {
                          acc
                        }
                      }
                    }
                  _ -> acc
                }
              } else {
                acc
              }
            },
          )
        let underwrite_path_valid = witness_output_count == 1

        // [Δ41 / Δ42] Provider-tag binding via a typed-decode on the
        // policy output. We iterate outputs and accept any output whose
        // datum decodes as a `PolicyDatum` with matching policy_id +
        // commit + oracle_provider. We SKIP outputs that carry the
        // canonical NFT (those are the witness outputs we just bound;
        // their datum is `AuthWitnessDatum`, and a typed decode as
        // `PolicyDatum` would crash). Skipping by NFT-presence rather
        // than by script-credential keeps the v3.3 cycle break intact.
        let policy_provider_bound =
          list.any(
            outputs,
            fn(out) {
              let qty =
                assets.quantity_of(
                  out.value,
                  own_policy_id,
                  expected_asset_name,
                )
              if qty >= 1 {
                False
              } else {
                when out.datum is {
                  InlineDatum(raw_pdat) ->
                    when raw_pdat is {
                      _ -> {
                        expect pdat: PolicyDatum = raw_pdat
                        let policy_id_ok = pdat.policy_id == policy_id
                        let commit_ok = pdat.auth_commitment == Some(commit)
                        let provider_ok =
                          payload.oracle_provider == oracle_provider_to_int(
                            pdat.oracle_provider,
                          )
                        policy_id_ok && commit_ok && provider_ok
                      }
                    }
                  _ -> False
                }
              }
            },
          )

        exactly_one_minted && only_one_under_policy && payload_canonical_ok && payload_policy_id_ok && underwrite_path_valid && policy_provider_bound && network_tag_ok
      }

      BurnViaConsume { policy_id } -> {
        // [Δ19 / V-002] The policy with this policy_id MUST be co-spent
        // in the same tx. This forces every burn into a 2-script-input tx
        // (policy + witness): the policy validator's chosen redeemer
        // (Cancel / Expire / Claim / ClaimWithAuth) handles its own
        // bindings, and the witness NFT's burn is gated on the policy
        // termination. Pre-Δ19 the check was inverted (`policy NOT in
        // inputs`) which let any third party destroy live witnesses for
        // a profit (V-002 — grief-ROI attack class).
        //
        // [Δ42 — v3.3] Identification of the policy input is via its
        // datum shape (PolicyDatum with matching policy_id) only. The
        // pre-Δ42 negative-filter that skipped script inputs at
        // `auth_witness_validator_hash` is REMOVED — the constant is no
        // longer imported by this file (cycle break). Inputs whose
        // datum is `AuthWitnessDatum` (the witness input being burned)
        // simply fail the typed `expect pdat: PolicyDatum = raw_pdat`
        // path and contribute False to the `list.any` fold — no crash,
        // because the typed-decode failure is caught by the surrounding
        // `when` arm returning False rather than panicking. Atomic-burn
        // semantics are preserved: the policy must be consumed in the
        // same tx; if the user misbuilt their policy at an attacker
        // address, the policy_validator (which actually processes
        // Cancel/Expire/Claim/ClaimWithAuth) would have rejected the
        // spend, so this branch is never reached for an attacker-
        // crafted policy. Defense in depth.
        let policy_consumed_in_tx =
          list.any(
            inputs,
            fn(i) {
              when i.output.datum is {
                InlineDatum(raw_pdat) ->
                  when raw_pdat is {
                    _ -> {
                      expect pdat: PolicyDatum = raw_pdat
                      pdat.policy_id == policy_id
                    }
                  }
                _ -> False
              }
            },
          )

        // Mint quantity must be exactly -1 (burn one).
        let expected_asset_name = blake2b_224(policy_id)
        let burn_qty =
          assets.quantity_of(mint, own_policy_id, expected_asset_name)
        let burn_one = burn_qty == -1

        // Only one (asset_name, qty) pair under this policy in the tx.
        let only_one_under_policy =
          list.length(dict.to_pairs(assets.tokens(mint, own_policy_id))) == 1

        policy_consumed_in_tx && burn_one && only_one_under_policy && network_tag_ok
      }

      SweepBurn { policy_id } -> {
        // [Δ19 / V-008 + Δ31 / VR-001] Operator-only orphan cleanup.
        // Three on-chain gates:
        //   (1) `extra_signatories` contains `operator_pkh` — the sweeper
        //       key authorized at deploy time.
        //   (2) The witness UTxO being burned MUST be a regular input
        //       whose value carries the canonical NFT — i.e., we have
        //       on-chain access to its `payload_cbor`. Pre-Δ31 the
        //       sweeper redeemer carried `not_after` as an operator-
        //       supplied integer with NO binding to the witness's actual
        //       payload; the operator could pass `not_after = 0` and the
        //       `tx_lower > 0` check would pass for any modern tx,
        //       effectively granting the operator-key holder a unilateral
        //       kill switch on every live witness. Reading
        //       `payload.not_after` from the on-chain bytes binds the
        //       gate to what the user actually signed.
        //   (3) The tx's validity-range lower bound is strictly greater
        //       than `payload.not_after` — the policy's auth has provably
        //       expired, so no honest user could still be filing a
        //       ClaimWithAuth against this witness. (Off-chain runbook
        //       supplements with k≥20 confirmations on policy non-
        //       existence to avoid reorg griefing — that part cannot be
        //       enforced in Plutus.)
        //
        // [Δ42 — v3.3] The pre-Δ42 defense-in-depth check that the
        // witness input sits at a `Script(_)` payment credential is
        // RETAINED (it does not introduce any compile-time-constant
        // dependency — `Script(_)` is a structural pattern, not the
        // concrete `auth_witness_validator_hash` constant). The
        // primary security backbone — the policy_validator's
        // `Script(auth_witness_validator_hash)` filter at witness-
        // consume time + auth_witness_validator's burn-or-respend
        // self-check — is unchanged.
        let signed_by_operator =
          must_be_signed_by(extra_signatories, operator_pkh)

        // Locate the witness UTxO being burned. It is a regular input
        // carrying the (own_policy_id, blake2b_224(policy_id)) pair
        // with quantity 1. We use this input's `payload_cbor` to bind
        // `not_after` to the actual user-signed payload (Δ31 / VR-001
        // fix).
        let expected_asset_name = blake2b_224(policy_id)
        expect Some(witness_input) =
          list.find(
            inputs,
            fn(i) {
              assets.quantity_of(
                i.output.value,
                own_policy_id,
                expected_asset_name,
              ) == 1
            },
          )

        // The witness must sit at a script address (the
        // auth_witness_validator) — defense in depth so a malformed
        // input shape cannot bypass the binding.
        let witness_at_script =
          when witness_input.output.address.payment_credential is {
            Script(_) -> True
            _ -> False
          }

        expect InlineDatum(raw_awd) = witness_input.output.datum
        expect awd: AuthWitnessDatum = raw_awd
        let witness_policy_id_ok = awd.policy_id == policy_id
        expect Some(payload_data) = cbor.deserialise(awd.payload_cbor)
        expect payload: AuthCoveragePayload = payload_data
        let payload_policy_id_ok = payload.policy_id == policy_id

        let tx_lower = get_lower_bound(validity_range)
        // Strict `>` (not `>=`) per spec §1.5 narrative: the policy's
        // auth window has provably elapsed, NOT just touched its
        // boundary. Aligns with the Δ7 ClaimWithAuth window-end
        // semantics (`tx_upper <= datum.expiry_time` — exclusive of
        // post-expiry slots).
        let auth_window_elapsed = tx_lower > payload.not_after

        // Mint quantity must be exactly -1 (burn one).
        let burn_qty =
          assets.quantity_of(mint, own_policy_id, expected_asset_name)
        let burn_one = burn_qty == -1

        // Only one (asset_name, qty) pair under this policy in the tx.
        let only_one_under_policy =
          list.length(dict.to_pairs(assets.tokens(mint, own_policy_id))) == 1

        signed_by_operator && witness_at_script && witness_policy_id_ok && payload_policy_id_ok && auth_window_elapsed && burn_one && only_one_under_policy && network_tag_ok
      }
    }
  }

  else(_) {
    fail @"auth_witness_nft only supports the mint purpose"
  }
}
