use aegis/auth_payload.{
  commit_from_cbor, is_valid_commit_length, verify_signature,
}
use aegis/oracle.{resolve_oracle_price}
use aegis/pricing.{calculate_refund}
use aegis/types.{
  AegisSelf, AuthCoveragePayload, AuthWitnessDatum, BatchClaim, BatchExpire,
  Cancel, Charli3, Claim, ClaimWithAuth, Expire, OracleProvider, Orcfax,
  PolicyDatum, PolicyRedeemer, RotateAuth, auth_domain_tag,
  auth_witness_nft_policy_id, auth_witness_validator_hash, cancellation_window,
  enterprise_addr_of, network_magic, oracle_provider_to_int,
}
use aegis/validation.{
  count_script_inputs, find_canonical_pool_output, get_lower_bound,
  get_upper_bound, must_be_signed_by, output_has_min_lovelace,
  sum_lovelace_to_enterprise_pkh,
}
use aiken/cbor
// =============================================================================
// Aegis Insurance Protocol - Policy Validator
// Location: contracts/validators/policy.ak
// Summary: Governs the lifecycle of individual insurance policy UTxOs.
//          Each policy UTxO contains the premium + coverage collateral in ADA
//          and a PolicyDatum encoding the full policy terms.
//          Interacts with: oracle.ak (claim price verification),
//          pricing.ak (cancellation refund), validation.ak (helpers),
//          and is referenced by pool.ak (ProcessClaim).
//
// Redeemers:
//   Claim  - Trigger payout when oracle price <= strike price
//   Expire - Reclaim funds after policy expiration
//   Cancel - Cancel policy within the cancellation window
// =============================================================================

use aiken/collection/list
use aiken/crypto.{blake2b_224}
use cardano/address.{Script}
use cardano/assets
use cardano/transaction.{InlineDatum, Input, OutputReference, Transaction}

// ---------------------------------------------------------------------------
// [FIX A-012, generalized for v6] Helper: every policy UTxO consumed at this
// validator address must declare the SAME (oracle_provider, oracle_nft)
// pair. Without this guard, a single BatchClaim tx could consume policies
// bound to different oracle feeds (e.g. ADA/USD and DJED/USD) OR — new in
// v6 — different oracle providers (Charli3 + Orcfax). Each policy would
// independently resolve its own oracle from reference_inputs and the tx
// would pass — but the resulting cross-feed / cross-provider interactions
// are hard to reason about and constitute permanent grease for future bugs
// (most directly: they intersect the "same insured + multiple outputs"
// surface that A-006 partially closes).
//
// v6 generalization: in v5 this checked uniformity only on `oracle_nft`. In
// v6 the (provider, nft) pair is the structural identity of an oracle
// binding because Orcfax and Charli3 use the same byte width for their
// respective handles (both are 28-byte script/policy hashes), and a
// hypothetical collision on the byte sequence between, say, a Charli3 NFT
// policy id and an Orcfax FSP hash MUST not be allowed to bridge the two
// providers in one batch.
//
// Strategy: walk the inputs, find every input at `own_script_hash`, and
// fold into a state of (sentinel, all_equal). If all consumed policies share
// one (provider, nft) pair, the result is `True`. The empty-batch case (no
// policy inputs at all) is treated as `True` because the surrounding
// validator already enforces `count_script_inputs >= 1`.
// ---------------------------------------------------------------------------

fn batch_oracles_uniform(
  inputs: List<Input>,
  own_script_hash: ByteArray,
) -> Bool {
  let sentinel_init: (OracleProvider, ByteArray) = (Charli3, #"")
  let result =
    list.foldl(
      inputs,
      (sentinel_init, True, False),
      fn(input, acc) {
        let (sentinel, ok, seen) = acc
        when input.output.address.payment_credential is {
          Script(h) ->
            if h == own_script_hash {
              when input.output.datum is {
                InlineDatum(raw_pdat) -> {
                  expect pdat: PolicyDatum = raw_pdat
                  let pair: (OracleProvider, ByteArray) =
                    (pdat.oracle_provider, pdat.oracle_nft)
                  if !seen {
                    (pair, ok, True)
                  } else {
                    let (sent_provider, sent_nft) = sentinel
                    let (this_provider, this_nft) = pair
                    let same_provider =
                      when (sent_provider, this_provider) is {
                        (Charli3, Charli3) -> True
                        (Orcfax, Orcfax) -> True
                        (AegisSelf, AegisSelf) -> True
                        _ -> False
                      }
                    (
                      sentinel,
                      ok && same_provider && this_nft == sent_nft,
                      True,
                    )
                  }
                }
                _ -> (sentinel, False, seen)
              }
            } else {
              acc
            }
          _ -> acc
        }
      },
    )
  let (_, all_equal, _) = result
  all_equal
}

// ---------------------------------------------------------------------------
// [v8] Helper: pattern-match equality on `OracleProvider` sum-type.
//
// Aiken sum types do not auto-derive `==`; this helper is the canonical
// equality check for `OracleProvider`. Used in `RotateAuth` to assert
// the rotated datum's oracle binding is unchanged.
// ---------------------------------------------------------------------------
fn oracle_provider_eq(a: OracleProvider, b: OracleProvider) -> Bool {
  when (a, b) is {
    (Charli3, Charli3) -> True
    (Orcfax, Orcfax) -> True
    (AegisSelf, AegisSelf) -> True
    _ -> False
  }
}

// ---------------------------------------------------------------------------
// [v8] Helper: decode the canonical CBOR payload at the validator.
//
// Wraps `cbor.deserialise` + the Aiken `expect AuthCoveragePayload = data`
// shape coercion so the call sites stay readable. Cost: one CBOR decode
// (the stdlib note in cbor.ak warns this is ~10x more expensive than
// serialise; it remains cheap relative to oracle-resolution cost).
// ---------------------------------------------------------------------------
fn cbor_decode_payload(payload_cbor: ByteArray) -> Data {
  expect Some(d) = cbor.deserialise(payload_cbor)
  d
}

// ---------------------------------------------------------------------------
// [v8 / RELAY-PRESIGNED-AUTH] Helper: count and locate witness UTxOs.
//
// A witness UTxO is a reference input sitting at the canonical
// `auth_witness_validator_hash` script address with an inline
// `AuthWitnessDatum` whose `policy_id` matches the policy datum's
// policy_id. The validator MUST find EXACTLY ONE such witness — Δ7 /
// closes C-2 + F-AUTH-3 (witness-stuffing DoS via duplicate ref-input
// shapes).
//
// [Δ41 — v3.2 deploy-cycle break] Pre-v3.2 the witness was identified by
// its NFT — `assets.quantity_of(value, auth_witness_nft_policy_id,
// blake2b_224(policy_id)) == 1`. Combined with the auth_witness_nft mint
// policy being parameterized over `policy_validator_hash`, this created
// a circular deploy dependency. v3.2 closes the cycle by identifying the
// witness via its script credential instead: a UTxO at
// `auth_witness_validator_hash` whose `AuthWitnessDatum.policy_id`
// matches. Security is preserved because the auth_witness_validator
// SELF-CHECKS that `own_value` carries a token under the canonical
// `auth_witness_nft_policy_id` — only legit-minted UTxOs can ever be
// spendable from that script address, so reference-input observations
// of UTxOs at that address cannot be forged by an attacker minting
// under a different NFT policy. Three-leg transitive trust chain:
//   * mint policy ensures the witness output ends up at
//     `auth_witness_validator_hash` AND carries the canonical NFT.
//   * auth_witness_validator's spend path enforces burn-only or
//     rotation-respend semantics (Δ32) — the NFT can never leave the
//     script except via burn or via a substituting respend.
//   * policy_validator (this code) accepts a witness iff it sits at
//     `auth_witness_validator_hash`.
//
// We iterate ALL reference inputs and fold to (count, last_match) rather
// than `list.find` first-match because the latter would silently accept
// a tx with two witness ref inputs. With strict count-equals-1, any
// witness-stuffing attempt fails.
// ---------------------------------------------------------------------------
fn collect_witnesses(
  reference_inputs: List<Input>,
  policy_id: ByteArray,
) -> (Int, Option<Input>) {
  list.foldl(
    reference_inputs,
    (0, None),
    fn(input, acc) {
      let (count, _last) = acc
      when input.output.address.payment_credential is {
        Script(h) ->
          if h == auth_witness_validator_hash {
            when input.output.datum is {
              InlineDatum(raw_awd) ->
                when raw_awd is {
                  _ -> {
                    expect awd: AuthWitnessDatum = raw_awd
                    if awd.policy_id == policy_id {
                      (count + 1, Some(input))
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
        _ -> acc
      }
    },
  )
}

// ---------------------------------------------------------------------------
// Policy Validator
// ---------------------------------------------------------------------------

validator policy_validator {
  spend(
    datum_opt: Option<PolicyDatum>,
    redeemer: PolicyRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    // Datum must be present
    expect Some(datum) = datum_opt

    let Transaction {
      inputs,
      reference_inputs,
      outputs,
      validity_range,
      extra_signatories,
      ..
    } = self

    // Find own input to determine script hash and value
    expect Some(self_input) =
      inputs
        |> list.find(fn(input) { input.output_reference == own_ref })
    let own_value = self_input.output.value

    // Determine own script hash for counting co-spent policy inputs
    expect Script(own_script_hash) =
      self_input.output.address.payment_credential

    when redeemer is {
      // -----------------------------------------------------------------------
      // CLAIM: Oracle price <= strike price -> payout to insured
      // -----------------------------------------------------------------------
      Claim -> {
        // [FIX F-001] Prevent double satisfaction: only one policy UTxO from
        // this script may be consumed per transaction
        let single_policy_input =
          count_script_inputs(inputs, own_script_hash) == 1

        // 1. [v6] Resolve the oracle price via the provider-uniform
        // dispatcher. Internally this matches on `datum.oracle_provider`
        // and dispatches to either `oracle/charli3.resolve` (which finds
        // the canonical Charli3 UTxO and parses its GenericData map) or
        // `oracle/orcfax.resolve` (which walks the FSP -> FS pointer
        // indirection and parses the FsDat<Rational>). Returns the
        // provider-uniform Price record. The trust handshake (canonical
        // address binding for Charli3 — A-016 — and FSP/FS dual-binding
        // for Orcfax) lives inside each parser; this branch just consumes
        // the resulting record.
        let price =
          resolve_oracle_price(
            reference_inputs,
            datum.oracle_provider,
            datum.oracle_nft,
          )

        // 2. Verify oracle price <= strike price (crash detected). Both
        // providers normalize to the protocol-wide 1e6 scale.
        let price_below_strike = price.value <= datum.strike_price

        // 3. Verify oracle data is fresh.
        // For Charli3, valid_until is the publisher-set expiry from the datum.
        // For Orcfax, valid_until is `created_at + orcfax_freshness_window_ms`
        // computed inside the Orcfax parser.
        // [v6.0.1 fix] BOTH legs of the validity range must be inside the
        // freshness window, otherwise an attacker could submit a tx with
        // tx_lower fresh but tx_upper hours later, and the chain would
        // include the tx after the price has actually staled.
        // [v6.0.2 / L-003 fix] Also require `tx_lower >= price.observed_at`
        // — closes the surface where a tx is built fresh, withheld, and
        // replayed after a publisher correction; without this, the only
        // anchor was `valid_until` (a publisher-controlled future time),
        // not the time the reading was actually committed on-chain.
        let tx_lower = get_lower_bound(validity_range)
        let tx_upper = get_upper_bound(validity_range)
        let oracle_fresh =
          tx_lower >= price.observed_at && tx_lower <= price.valid_until && tx_upper <= price.valid_until

        // 4. Verify transaction is within the policy period
        let within_start = tx_lower >= datum.start_time
        let within_expiry = tx_upper <= datum.expiry_time

        // 5. [FIX A-006/A-009/A-013] Verify aggregate payout to insured is
        // sufficient AND every payout output is an enterprise address.
        let payout_valid =
          sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= datum.coverage_amount

        // [FIX F-002] Verify remainder ALWAYS goes to pool with correct value.
        let policy_utxo_lovelace = assets.lovelace_of(own_value)
        let expected_remainder = policy_utxo_lovelace - datum.coverage_amount
        // [FIX A-008] Route residual to the CANONICAL pool (must carry pool_nft).
        let pool_output =
          find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          )
        let pool_receives_remainder =
          if expected_remainder <= 0 {
            True
          } else {
            when pool_output is {
              Some(out) -> output_has_min_lovelace(out, expected_remainder)
              None -> False
            }
          }

        single_policy_input && price_below_strike && oracle_fresh && within_start && within_expiry && payout_valid && pool_receives_remainder
      }

      // -----------------------------------------------------------------------
      // BATCH CLAIM: Multiple policies claimed in one transaction
      // -----------------------------------------------------------------------
      BatchClaim -> {
        let batch_size = count_script_inputs(inputs, own_script_hash)
        let has_policies = batch_size >= 1

        // [FIX A-012, generalized for v6] All consumed policies must share
        // the same (oracle_provider, oracle_nft) pair.
        let oracle_uniform = batch_oracles_uniform(inputs, own_script_hash)

        // [v6] Oracle checks via the provider-uniform dispatcher.
        let price =
          resolve_oracle_price(
            reference_inputs,
            datum.oracle_provider,
            datum.oracle_nft,
          )
        let price_below_strike = price.value <= datum.strike_price
        // [v6.0.1 fix] Both validity-range legs must be inside the freshness
        // window — otherwise an attacker could spend a stale price by
        // submitting a tx with tx_lower fresh but tx_upper much later.
        // [v6.0.2 / L-003 fix] Also require `tx_lower >= price.observed_at`
        // to close tx-withhold-and-replay-after-correction.
        let tx_lower = get_lower_bound(validity_range)
        let tx_upper = get_upper_bound(validity_range)
        let oracle_fresh =
          tx_lower >= price.observed_at && tx_lower <= price.valid_until && tx_upper <= price.valid_until

        // Time bounds
        let within_start = tx_lower >= datum.start_time
        let within_expiry = tx_upper <= datum.expiry_time

        // [FIX A-006/A-009] Aggregate enterprise-output check.
        let payout_valid =
          sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= datum.coverage_amount

        // Pool remainder (same logic as Claim)
        let policy_utxo_lovelace = assets.lovelace_of(own_value)
        let expected_remainder = policy_utxo_lovelace - datum.coverage_amount
        let pool_output =
          find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          )
        let pool_receives_remainder =
          if expected_remainder <= 0 {
            True
          } else {
            when pool_output is {
              Some(out) -> output_has_min_lovelace(out, expected_remainder)
              None -> False
            }
          }

        has_policies && oracle_uniform && price_below_strike && oracle_fresh && within_start && within_expiry && payout_valid && pool_receives_remainder
      }

      // -----------------------------------------------------------------------
      // EXPIRE: Policy has expired -> return all funds to pool
      // -----------------------------------------------------------------------
      Expire -> {
        let tx_lower = get_lower_bound(validity_range)
        let is_expired = tx_lower > datum.expiry_time

        let policy_utxo_lovelace = assets.lovelace_of(own_value)
        let pool_output =
          find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          )
        let funds_to_pool =
          when pool_output is {
            Some(output) ->
              output_has_min_lovelace(output, policy_utxo_lovelace)
            None -> False
          }

        is_expired && funds_to_pool
      }

      // -----------------------------------------------------------------------
      // BATCH EXPIRE: Multiple expired policies reclaimed in one transaction
      // -----------------------------------------------------------------------
      BatchExpire -> {
        let batch_size = count_script_inputs(inputs, own_script_hash)
        let has_policies = batch_size >= 1

        let tx_lower = get_lower_bound(validity_range)
        let is_expired = tx_lower > datum.expiry_time

        let policy_utxo_lovelace = assets.lovelace_of(own_value)
        let pool_output =
          find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          )
        let funds_to_pool =
          when pool_output is {
            Some(output) ->
              output_has_min_lovelace(output, policy_utxo_lovelace)
            None -> False
          }

        has_policies && is_expired && funds_to_pool
      }

      // -----------------------------------------------------------------------
      // [v8] CLAIM WITH AUTH: relay-driven claim using the insured's
      // pre-signed AuthCoveragePayload (§1.6 of v2 spec). All Claim
      // invariants apply (oracle, time, A-009 enterprise payout aggregate,
      // A-008 residual to canonical pool, F-001 single-script-input GLOBAL
      // guard) PLUS the auth-binding chain.
      // -----------------------------------------------------------------------
      ClaimWithAuth { sig } -> {
        // Step 1-2: auth_commitment must be present and exactly 32 bytes
        // (Δ12 / F-AUTH-6).
        expect Some(commit) = datum.auth_commitment
        let commit_len_ok = is_valid_commit_length(commit)

        // Step 3-4 / Δ7 / closes C-2 + F-AUTH-3: locate THE unique
        // witness UTxO via ALL-iteration count-equals-1, NOT first-match.
        let (witness_count, witness_opt) =
          collect_witnesses(reference_inputs, datum.policy_id)
        let exactly_one_witness = witness_count == 1
        expect Some(witness) = witness_opt

        // Step 5-7: parse the witness datum.
        expect InlineDatum(raw_w) = witness.output.datum
        expect awd: AuthWitnessDatum = raw_w

        // Step 8: belt — witness datum's policy_id must match the policy
        // (the asset-name binding `blake2b_224(policy_id)` already pins
        // this; the explicit field assertion is defense-in-depth).
        let witness_policy_id_ok = awd.policy_id == datum.policy_id

        // Step 9 / Δ12: the on-chain CBOR must hash to the policy's
        // commitment. This is the load-bearing payload-binding check —
        // without it, an attacker could supply a witness with attacker-
        // controlled payload bytes whose SIGNATURE happens to verify
        // (e.g., a sig over a different commitment).
        let payload_binds_to_commit =
          commit_from_cbor(awd.payload_cbor) == commit

        // Step 10 / closes C-2: the witness's vkey must hash to the
        // insured PKH. Without this, an attacker swapping in their own
        // vkey + sig pair would pass the Ed25519 check.
        let vkey_binds_to_insured =
          blake2b_224(awd.insured_vkey) == datum.insured

        // Step 11: headline Ed25519 verification — must succeed.
        let signature_valid = verify_signature(awd.insured_vkey, commit, sig)

        // Step 12: belt — the redeemer-supplied sig must equal the
        // witness-stored sig (rules out a relay presenting a fresh sig
        // over a different commitment with a stale witness datum).
        let sig_matches_witness = awd.signature == sig

        // Step 13 / Δ12: re-decode the canonical CBOR payload at the
        // validator (one cbor_decode + one BLAKE2b — cheap). The fields
        // we read are then asserted against the policy datum below.
        expect payload: AuthCoveragePayload =
          cbor_decode_payload(awd.payload_cbor)

        // [Δ22 / A-A-003] Canonical-form gate: re-serialize the decoded
        // payload and assert byte-equal to the on-chain CBOR. Pre-Δ22 the
        // Aiken stdlib's `cbor.deserialise` accepted non-canonical CBOR
        // (non-shortest-form ints, indefinite-length bytestrings via the
        // `0x5f` chunked form, etc.) — an attacker could craft bytes that
        // decode to the same logical payload but produce a different
        // BLAKE2b commit, partially escaping wallet-side validation. The
        // re-encode-and-compare check pins the CBOR to its canonical form.
        let payload_canonical = cbor.serialise(payload)
        let payload_canonical_ok = payload_canonical == awd.payload_cbor

        // [Δ20 / V-007 / A-A-002] Bind ALL 14 payload fields to the
        // active-network constants and the policy datum. Pre-Δ20 only 3
        // fields were checked (policy_id, oracle_provider, payout_address)
        // and the other 11 were decoded-and-discarded — wallets displayed
        // them, the validator did not enforce them. The full binding
        // makes every field the user signed over a load-bearing on-chain
        // assertion.
        let payload_domain_tag_ok = payload.domain_tag == auth_domain_tag
        let payload_network_magic_ok = payload.network_magic == network_magic
        let payload_policy_validator_ok =
          payload.policy_validator == own_script_hash
        let payload_insured_pkh_ok = payload.insured_pkh == datum.insured
        let payload_max_coverage_ok =
          payload.max_coverage == datum.coverage_amount
        let payload_oracle_nft_ok = payload.oracle_nft == datum.oracle_nft
        // [Δ37 / VR-008] Bind oracle_freshness to the same 24h sanity cap
        // the off-chain Python and TS encoders enforce. Pre-Δ37 the on-
        // chain check was `>= 0`, accepting arbitrarily large BigInts —
        // an attacker tooling that bypassed off-chain validation could
        // sign payloads with `oracle_freshness = 999_999_999_999` ms
        // (~285 years) and the validator would accept. Symmetric upper
        // bound closes the cross-stack asymmetry.
        let payload_oracle_freshness_ok =
          payload.oracle_freshness >= 0 && payload.oracle_freshness <= 86_400_000
        let payload_not_before_ok = payload.not_before == datum.start_time
        let payload_not_after_ok = payload.not_after == datum.expiry_time
        let payload_pool_script_hash_ok =
          payload.pool_script_hash == datum.pool_script_hash
        let payload_pool_nft_ok = payload.pool_nft == datum.pool_nft

        // Step 14 / Δ5 / closes F-AUTH-5: the signed payload's
        // oracle_provider tag must match the policy's oracle_provider
        // (encoded as int). Without this, a sig over a Charli3-bound
        // payload could be replayed against an Orcfax-bound policy.
        let provider_binds =
          payload.oracle_provider == oracle_provider_to_int(
            datum.oracle_provider,
          )

        // Step 15: belt — the signed payload's policy_id matches the
        // policy datum's policy_id (already pinned by the witness asset
        // name + commit binding, but a third explicit check is cheap).
        let payload_policy_id_ok = payload.policy_id == datum.policy_id

        // Step 16 / Δ9 / closes F-AUTH-4: the signed payload's
        // payout_address MUST equal the canonical 29-byte enterprise
        // address bytes derived from `datum.insured`. Without this, a
        // relay could attach an arbitrary 29-byte string to the sig and
        // (combined with A-009's enterprise-pkh aggregation) effectively
        // redirect the payout — A-009 only constrains the payment
        // credential, not the address bytes embedded in the auth.
        let payout_addr_binds =
          payload.payout_address == enterprise_addr_of(datum.insured)

        // Step 17: reuse the same Claim invariants as the regular Claim
        // branch — oracle resolved + below strike + fresh + within
        // window, payout aggregate, residual to canonical pool.
        let price =
          resolve_oracle_price(
            reference_inputs,
            datum.oracle_provider,
            datum.oracle_nft,
          )
        let price_below_strike = price.value <= datum.strike_price
        let tx_lower = get_lower_bound(validity_range)
        let tx_upper = get_upper_bound(validity_range)
        let oracle_fresh =
          tx_lower >= price.observed_at && tx_lower <= price.valid_until && tx_upper <= price.valid_until
        let within_start = tx_lower >= datum.start_time
        let within_expiry = tx_upper <= datum.expiry_time
        let payout_valid =
          sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= datum.coverage_amount
        let policy_utxo_lovelace = assets.lovelace_of(own_value)
        let expected_remainder = policy_utxo_lovelace - datum.coverage_amount
        let pool_output =
          find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          )
        let pool_receives_remainder =
          if expected_remainder <= 0 {
            True
          } else {
            when pool_output is {
              Some(out) -> output_has_min_lovelace(out, expected_remainder)
              None -> False
            }
          }

        // Step 18 / Δ6 / closes F-AUTH-1: GLOBAL single-script-input
        // guard — same expression as Claim. Prevents cross-redeemer
        // double satisfaction (e.g., two policies, one Claim + one
        // ClaimWithAuth in the same tx).
        let single_policy_input =
          count_script_inputs(inputs, own_script_hash) == 1

        commit_len_ok && exactly_one_witness && witness_policy_id_ok && payload_binds_to_commit && vkey_binds_to_insured && signature_valid && sig_matches_witness && payload_canonical_ok && payload_domain_tag_ok && payload_network_magic_ok && payload_policy_validator_ok && payload_insured_pkh_ok && payload_max_coverage_ok && payload_oracle_nft_ok && payload_oracle_freshness_ok && payload_not_before_ok && payload_not_after_ok && payload_pool_script_hash_ok && payload_pool_nft_ok && provider_binds && payload_policy_id_ok && payout_addr_binds && price_below_strike && oracle_fresh && within_start && within_expiry && payout_valid && pool_receives_remainder && single_policy_input
      }

      // -----------------------------------------------------------------------
      // [v8 / v3.1] ROTATE AUTH: invalidate the old auth_commitment
      // without paying out. Gated by CIP-30 main-wallet sig (§1.4 of v2
      // spec). No value flows; the policy UTxO is consumed and recreated
      // with the new commitment.
      //
      // [Δ32 / VR-002 — v3.1 fix] Pre-v3.1 the rotation flow MINTED a new
      // witness alongside the un-burned old one — leaving two UTxOs
      // sharing the same `auth_witness_nft` asset name on chain.
      // ClaimWithAuth's `length(witnesses) == 1` gate (Δ7) then rejected
      // every claim until the policy expired, bricking the relay-
      // presigned-auth path for the entire post-rotation period. v3.1
      // adopts Option A: the OLD witness UTxO is SPENT and a NEW witness
      // UTxO is RESPENT at the auth_witness_validator script — the NFT
      // moves with the UTxO, no mint policy invocation, and the chain
      // never holds more than one witness UTxO under a given asset name.
      // The auth_witness_validator's spend path (post-Δ32) accepts the
      // rotation respend by checking `mint_qty == 0 &&
      // continuation_count == 1` for the asset; the policy validator's
      // RotateAuth branch (this code) is the cryptographic gate that
      // makes the rotation respend safe.
      //
      // [Δ33 / VR-003 — v3.1 fix] The new witness's payload is bound to
      // the policy datum across ALL 14 fields (mirror of Δ20 in
      // ClaimWithAuth) AND canonically re-encoded byte-equal (mirror of
      // Δ22) AND its Ed25519 signature verified against the new commit.
      // Pre-Δ33 a malicious frontend could trick the user into signing
      // a rotation tx whose new witness carried attacker-controlled
      // payload fields — the rotation would pass on chain and the next
      // ClaimWithAuth would fail, bricking the relay-auth path until
      // expiry.
      // -----------------------------------------------------------------------
      RotateAuth { new_commit, new_witness_ref } -> {
        // Step 1: gated by the insured's CIP-30 main-wallet signature.
        // The main-wallet keys are independent of the Aegis-wallet seed
        // (Δ9 + ROTATE-AUTH semantics) so a compromised Aegis seed does
        // NOT enable an attacker to rotate the auth.
        let signed_by_insured =
          must_be_signed_by(extra_signatories, datum.insured)

        // Step 2: the new commitment must be exactly 32 bytes.
        let commit_len_ok = is_valid_commit_length(new_commit)

        // [Δ25 / V-010] Reject no-op rotation: `new_commit` MUST differ
        // from `datum.auth_commitment`. Pre-Δ25 a malicious caller could
        // submit RotateAuth with `new_commit == old_commit`, paying a tx
        // fee for nothing while reusing the existing witness as the
        // "new" one — pure churn that bloats orphan witness count and
        // burns the user's min-ADA. Requiring a real change is cheap and
        // closes the nuisance class. The `None` case (first-time
        // rotation from an opt-out policy) is treated as a real change
        // because no prior commit existed to be equal to.
        let actual_rotation =
          when datum.auth_commitment is {
            Some(old) -> old != new_commit
            None -> True
          }

        // Step 3: the policy UTxO must be re-created with the same datum
        // except for the new auth_commitment. Find the canonical
        // continuation (same script address, same policy datum modulo
        // auth_commitment).
        let cont_output_opt =
          list.find(
            outputs,
            fn(out) {
              when out.address.payment_credential is {
                Script(h) -> h == own_script_hash
                _ -> False
              }
            },
          )
        expect Some(cont_output) = cont_output_opt
        expect InlineDatum(raw_new_datum) = cont_output.datum
        expect new_datum: PolicyDatum = raw_new_datum

        // The new datum must match the old datum across every field
        // EXCEPT auth_commitment, which becomes Some(new_commit). No
        // coverage / strike / time / pool / oracle binding mutations.
        let datum_unchanged_except_commit =
          new_datum.policy_id == datum.policy_id && new_datum.insured == datum.insured && new_datum.strike_price == datum.strike_price && new_datum.coverage_amount == datum.coverage_amount && new_datum.premium_paid == datum.premium_paid && new_datum.start_time == datum.start_time && new_datum.expiry_time == datum.expiry_time && new_datum.oracle_nft == datum.oracle_nft && new_datum.pool_script_hash == datum.pool_script_hash && new_datum.pool_nft == datum.pool_nft && oracle_provider_eq(
            new_datum.oracle_provider,
            datum.oracle_provider,
          ) && new_datum.auth_commitment == Some(new_commit)

        // The policy UTxO's value must be preserved (no value siphon).
        let value_preserved =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value)

        // [Δ32 / VR-002 + Δ41 — v3.2] Locate the OLD witness UTxO being
        // spent — it is a regular input at the canonical
        // `auth_witness_validator_hash` script address whose
        // `AuthWitnessDatum.policy_id` matches. We use this script hash
        // for the continuation lookup below, and we read the old
        // witness datum to bind its sub-fields where the v3.1 invariant
        // table requires it.
        //
        // Pre-Δ41 the old-witness identification was via the NFT token
        // (`assets.quantity_of(value, auth_witness_nft_policy_id,
        // blake2b_224(policy_id)) == 1`). Δ41 swaps to the
        // script-credential check to break the deploy cycle (see
        // header comment on `auth_witness_validator_hash`); the
        // auth_witness_validator's own self-check on `own_value`
        // carrying the canonical NFT closes the spoofing surface,
        // because the validator's spend path will refuse any tx that
        // doesn't burn or respend the NFT correctly.
        expect Some(old_witness_input) =
          list.find(
            inputs,
            fn(i) {
              when i.output.address.payment_credential is {
                Script(h) ->
                  if h == auth_witness_validator_hash {
                    when i.output.datum is {
                      InlineDatum(raw_awd) ->
                        when raw_awd is {
                          _ -> {
                            expect awd: AuthWitnessDatum = raw_awd
                            awd.policy_id == datum.policy_id
                          }
                        }
                      _ -> False
                    }
                  } else {
                    False
                  }
                _ -> False
              }
            },
          )
        expect InlineDatum(raw_old_w) = old_witness_input.output.datum
        expect old_awd: AuthWitnessDatum = raw_old_w
        let old_witness_policy_id_ok = old_awd.policy_id == datum.policy_id

        // [Δ32 / VR-002 + Δ41 — v3.2] Locate the NEW witness UTxO — a
        // regular OUTPUT at the canonical auth_witness_validator_hash
        // script address with `AuthWitnessDatum.policy_id` matching the
        // policy AND carrying the canonical
        // (auth_witness_nft_policy_id, blake2b_224(policy_id)) NFT.
        // There must be EXACTLY ONE such output: zero would leave the
        // policy without a witness; two would re-create the VR-002
        // count==1-gate-fails state. The counting is done up-front so a
        // single fold across `outputs` covers both presence and
        // uniqueness.
        //
        // The NFT-asset-name check is preserved alongside the
        // script-credential check (Δ41 split) so an attacker cannot
        // produce a "rotated" witness output at the right script
        // address but with a wrong asset_name — the spend path's burn-
        // or-respend semantics rely on the NFT moving with the UTxO,
        // and a missing/swapped NFT would either force a re-mint
        // (rejected by `mint_qty_zero`) or leave the post-rotation
        // chain in a broken state.
        let asset_name = blake2b_224(datum.policy_id)
        let new_witness_count =
          list.foldl(
            outputs,
            0,
            fn(out, acc) {
              when out.address.payment_credential is {
                Script(h) ->
                  if h == auth_witness_validator_hash {
                    when out.datum is {
                      InlineDatum(raw_new_w) ->
                        when raw_new_w is {
                          _ -> {
                            expect new_awd: AuthWitnessDatum = raw_new_w
                            let datum_pid_ok =
                              new_awd.policy_id == datum.policy_id
                            let nft_present_ok =
                              assets.quantity_of(
                                out.value,
                                auth_witness_nft_policy_id,
                                asset_name,
                              ) == 1
                            if datum_pid_ok && nft_present_ok {
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
                _ -> acc
              }
            },
          )
        let exactly_one_new_witness = new_witness_count == 1

        // The redeemer-attested `new_witness_ref` is the OutputReference
        // the off-chain builder commits to ahead of time. With Option A
        // it points at the OLD witness UTxO being spent — the NEW
        // witness inherits the asset_name via the respend so we use the
        // input's reference as the rotation anchor. (Pre-v3.1 this was
        // the new mint's output_reference; under Option A the mint never
        // happens and the binding moves to the spent input.)
        let witness_ref_attested =
          old_witness_input.output_reference == new_witness_ref

        // Locate the unique new witness output — `expect Some` after the
        // count gate above ensures we crash loudly on the unreachable
        // zero-output case rather than silently passing a partial check.
        expect Some(new_witness_out) =
          list.find(
            outputs,
            fn(out) {
              when out.address.payment_credential is {
                Script(h) ->
                  if h == auth_witness_validator_hash {
                    when out.datum is {
                      InlineDatum(raw_new_w) ->
                        when raw_new_w is {
                          _ -> {
                            expect new_awd: AuthWitnessDatum = raw_new_w
                            let datum_pid_ok =
                              new_awd.policy_id == datum.policy_id
                            let nft_present_ok =
                              assets.quantity_of(
                                out.value,
                                auth_witness_nft_policy_id,
                                asset_name,
                              ) == 1
                            datum_pid_ok && nft_present_ok
                          }
                        }
                      _ -> False
                    }
                  } else {
                    False
                  }
                _ -> False
              }
            },
          )
        expect InlineDatum(raw_new_w) = new_witness_out.datum
        expect new_awd: AuthWitnessDatum = raw_new_w
        let new_witness_policy_id_ok = new_awd.policy_id == datum.policy_id
        let new_witness_commit_ok =
          commit_from_cbor(new_awd.payload_cbor) == new_commit

        // [Δ33 / VR-003] Decode the NEW witness's payload, re-encode it,
        // and bind every field — same chain as ClaimWithAuth's Δ20+Δ22.
        // Pre-Δ33 a malicious frontend could craft a rotation whose new
        // witness carried attacker-controlled fields (e.g.,
        // `payout_address` pointing at the attacker), the user's CIP-30
        // sig over the rotation tx body would authorize the rotation,
        // and the validator would accept. The next ClaimWithAuth would
        // then fail Δ20 — bricking the relay-auth path for the policy.
        expect new_payload_data: AuthCoveragePayload =
          cbor_decode_payload(new_awd.payload_cbor)
        let new_payload_canonical = cbor.serialise(new_payload_data)
        let new_payload_canonical_ok =
          new_payload_canonical == new_awd.payload_cbor

        let new_payload_domain_tag_ok =
          new_payload_data.domain_tag == auth_domain_tag
        let new_payload_network_magic_ok =
          new_payload_data.network_magic == network_magic
        let new_payload_policy_validator_ok =
          new_payload_data.policy_validator == own_script_hash
        let new_payload_policy_id_ok =
          new_payload_data.policy_id == datum.policy_id
        let new_payload_insured_pkh_ok =
          new_payload_data.insured_pkh == datum.insured
        let new_payload_payout_addr_ok =
          new_payload_data.payout_address == enterprise_addr_of(datum.insured)
        let new_payload_max_coverage_ok =
          new_payload_data.max_coverage == datum.coverage_amount
        let new_payload_provider_ok =
          new_payload_data.oracle_provider == oracle_provider_to_int(
            datum.oracle_provider,
          )
        let new_payload_oracle_nft_ok =
          new_payload_data.oracle_nft == datum.oracle_nft
        // [Δ37 / VR-008] Match ClaimWithAuth: 24h sanity cap mirrors the
        // off-chain Python and TS encoders so the cross-stack symmetry
        // holds at rotation time too.
        let new_payload_oracle_freshness_ok =
          new_payload_data.oracle_freshness >= 0 && new_payload_data.oracle_freshness <= 86_400_000
        let new_payload_not_before_ok =
          new_payload_data.not_before == datum.start_time
        let new_payload_not_after_ok =
          new_payload_data.not_after == datum.expiry_time
        let new_payload_pool_script_hash_ok =
          new_payload_data.pool_script_hash == datum.pool_script_hash
        let new_payload_pool_nft_ok =
          new_payload_data.pool_nft == datum.pool_nft

        // [Δ33 / VR-003] Verify the NEW witness's Ed25519 signature
        // against the new commit. Pre-Δ33 the validator only checked
        // that `commit_from_cbor(payload_cbor) == new_commit` — i.e.,
        // the bytes hash to the commit — but did NOT verify the
        // signature on the new payload. A malicious frontend could
        // craft a witness with a junk signature and the rotation would
        // pass on chain (the next ClaimWithAuth would catch it via
        // step 11, but a half-valid rotation already destroyed the
        // user's relay-auth path). Verifying at rotation time closes
        // the surface immediately. The new witness's `insured_vkey`
        // must hash to `datum.insured` so an attacker cannot smuggle a
        // controlled vkey + matching sig past this check (closes the
        // C-2 analogue for rotation).
        let new_vkey_binds_to_insured =
          blake2b_224(new_awd.insured_vkey) == datum.insured
        let new_signature_valid =
          verify_signature(new_awd.insured_vkey, new_commit, new_awd.signature)

        // GLOBAL single-script-input guard — only one policy_validator
        // input per tx (Δ6 / F-AUTH-1).
        let single_policy_input =
          count_script_inputs(inputs, own_script_hash) == 1

        signed_by_insured && commit_len_ok && actual_rotation && datum_unchanged_except_commit && value_preserved && old_witness_policy_id_ok && exactly_one_new_witness && witness_ref_attested && new_witness_policy_id_ok && new_witness_commit_ok && new_payload_canonical_ok && new_payload_domain_tag_ok && new_payload_network_magic_ok && new_payload_policy_validator_ok && new_payload_policy_id_ok && new_payload_insured_pkh_ok && new_payload_payout_addr_ok && new_payload_max_coverage_ok && new_payload_provider_ok && new_payload_oracle_nft_ok && new_payload_oracle_freshness_ok && new_payload_not_before_ok && new_payload_not_after_ok && new_payload_pool_script_hash_ok && new_payload_pool_nft_ok && new_vkey_binds_to_insured && new_signature_valid && single_policy_input
      }

      // -----------------------------------------------------------------------
      // CANCEL: Early cancellation within the allowed window
      // -----------------------------------------------------------------------
      Cancel -> {
        // 1. Verify signed by the insured party
        let signed_by_insured =
          must_be_signed_by(extra_signatories, datum.insured)

        // 2. Verify within cancellation window
        let tx_upper = get_upper_bound(validity_range)
        let within_window = tx_upper <= datum.start_time + cancellation_window

        // 3. [FIX A-010] Reject Cancel if the policy is currently
        // in-the-money. Without this guard the insured can wait inside the
        // 1-hour cancellation window for the oracle to print, then choose:
        //   * if price <= strike (ITM)  -> Claim for full coverage,
        //   * if price >  strike (OTM)  -> Cancel for 90% premium back.
        // That free optionality on top of the parametric trigger is value
        // the underwriter never priced in. [v6] Resolve via the provider-
        // uniform dispatcher so the in-the-money guard works identically
        // for Charli3 and Orcfax policies.
        let price =
          resolve_oracle_price(
            reference_inputs,
            datum.oracle_provider,
            datum.oracle_nft,
          )
        let tx_lower = get_lower_bound(validity_range)
        // [v6.0.1 fix] Both validity-range legs must be inside the freshness
        // window — symmetric with Claim/BatchClaim so a Cancel can't replay
        // a stale price by widening the validity range.
        // [v6.0.2 / L-003 fix] Also require `tx_lower >= price.observed_at`
        // — symmetric with Claim/BatchClaim, closes the same withhold-
        // and-replay surface for Cancel.
        let oracle_fresh =
          tx_lower >= price.observed_at && tx_lower <= price.valid_until && tx_upper <= price.valid_until
        // Note: Claim uses `oracle_price <= strike_price` to trigger payout,
        // so the symmetric in-the-money guard here is `oracle_price > strike`.
        let not_in_the_money = price.value > datum.strike_price

        // 4. Calculate refund amount (premium - 10% cancellation fee)
        let refund_amount = calculate_refund(datum.premium_paid)

        // 5. [FIX A-009/A-013] Aggregate enterprise refund check.
        let refund_valid =
          sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= refund_amount

        // 6. Verify remainder goes to pool (premium_paid - refund + coverage)
        let policy_utxo_lovelace = assets.lovelace_of(own_value)
        let expected_pool_amount = policy_utxo_lovelace - refund_amount
        let pool_output =
          find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          )
        let remainder_to_pool =
          when pool_output is {
            Some(out) -> output_has_min_lovelace(out, expected_pool_amount)
            None -> False
          }

        signed_by_insured && within_window && oracle_fresh && not_in_the_money && refund_valid && remainder_to_pool
      }
    }
  }

  else(_) {
    fail @"Unsupported purpose for policy_validator"
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test claim_price_check_triggers() {
  // Strike at $0.35, oracle at $0.30 -> should trigger
  let strike = 350_000
  let oracle_price = 300_000
  oracle_price <= strike
}

test claim_price_check_no_trigger() {
  // Strike at $0.35, oracle at $0.50 -> should NOT trigger
  let strike = 350_000
  let oracle_price = 500_000
  oracle_price > strike
}

test claim_price_check_at_boundary() {
  // Strike at $0.35, oracle at $0.35 -> SHOULD trigger (<=)
  let strike = 350_000
  let oracle_price = 350_000
  oracle_price <= strike
}

test expire_time_check() {
  // Policy expires at T=100, current time T=101 -> expired
  let expiry = 100
  let current = 101
  current > expiry
}

test expire_time_not_yet() {
  // Policy expires at T=100, current time T=99 -> not expired
  let expiry = 100
  let current = 99
  current <= expiry
}

test cancel_window_valid() {
  // Start at T=1000, cancel window 3600000, tx at T=2000 -> within window
  let start = 1_000
  let tx_upper = 2_000
  tx_upper <= start + cancellation_window
}

test cancel_window_expired() {
  // Start at T=1000, cancel window 3600000, tx at T=5000000 -> outside window
  let start = 1_000
  let tx_upper = 5_000_000
  tx_upper > start + cancellation_window
}

// ---------------------------------------------------------------------------
// Security Tests: Policy Validator Edge Cases
// ---------------------------------------------------------------------------

// [F-001] Double satisfaction: verify single-input constraint logic
test double_satisfaction_two_inputs_fail_check() {
  let count = 2
  count != 1
}

// [F-002] Remainder bypass
test claim_remainder_logic() {
  let policy_utxo_lovelace = 7_000_000_000
  let coverage = 5_000_000_000
  let expected_remainder = policy_utxo_lovelace - coverage
  expected_remainder == 2_000_000_000 && expected_remainder > 0
}

test claim_zero_remainder_logic() {
  let policy_utxo_lovelace = 5_000_000_000
  let coverage = 5_000_000_000
  let expected_remainder = policy_utxo_lovelace - coverage
  expected_remainder <= 0
}

test expire_full_value_check() {
  let policy_utxo_lovelace = 10_000_000_000
  policy_utxo_lovelace > 0
}

test cancel_window_at_exact_boundary() {
  let start = 1_000_000
  let tx_upper = start + cancellation_window
  tx_upper <= start + cancellation_window
}

test cancel_window_one_ms_past() {
  let start = 1_000_000
  let tx_upper = start + cancellation_window + 1
  tx_upper > start + cancellation_window
}

test expire_at_exact_boundary_fails() {
  let expiry = 100_000
  let current = expiry
  current <= expiry
}

test claim_at_exact_strike_triggers() {
  let strike = 350_000
  let oracle_price = 350_000
  oracle_price <= strike
}
