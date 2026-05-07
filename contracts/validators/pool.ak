use aegis/oracle.{canonical_oracle_nft}
use aegis/pool.{
  can_underwrite, can_withdraw, verify_add_liquidity_datum, verify_claim_datum,
  verify_remove_liquidity_datum, verify_underwrite_datum,
}
use aegis/pricing.{
  calculate_refund, calculate_treasury_cut, is_premium_adequate, net_premium,
}
use aegis/types.{
  AcceptCancellation, AddLiquidity, BatchExpireProcess, BatchUnderwrite,
  PolicyDatum, PoolDatum, PoolRedeemer, ProcessClaim, RemoveLiquidity,
  Underwrite, derive_policy_id, derive_policy_id_batch, treasury_share_bps,
}
use aegis/validation.{
  count_script_inputs, get_lower_bound, get_upper_bound, output_has_nft,
}
// =============================================================================
// Aegis Insurance Protocol - Pool Validator
// Location: contracts/validators/pool.ak
// Summary: Manages the shared liquidity pool that underwrites all insurance
//          policies. The pool is a single UTxO (identified by pool_nft)
//          containing all deposited liquidity from LPs plus a PoolDatum
//          tracking aggregate pool state.
//          Interacts with: pool.ak (lib - math helpers),
//          pricing.ak (premium validation), types.ak (datum/redeemer types),
//          validation.ak (output helpers).
//          Referenced by: validators/lp_token.ak (minting authorization).
//
// Redeemers:
//   Underwrite      - Reserve coverage for a new policy
//   ProcessClaim    - Process a claim payout
//   AddLiquidity    - LP deposits ADA into the pool
//   RemoveLiquidity - LP withdraws ADA from the pool
// =============================================================================

use aiken/collection/list
use cardano/address.{Script}
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction, ValidityRange,
}

// ---------------------------------------------------------------------------
// [FIX A-004] Helper: locate a freshly created policy output whose datum
// matches the Underwrite redeemer parameters and points back to THIS pool.
// ---------------------------------------------------------------------------

fn consumed_policies_total_to(
  inputs: List<Input>,
  policy_script: ByteArray,
  own_pool_hash: ByteArray,
  own_pool_nft: ByteArray,
  expected_total: Int,
) -> Bool {
  let total =
    list.foldl(
      inputs,
      0,
      fn(input, acc) {
        when input.output.address.payment_credential is {
          Script(h) ->
            if h == policy_script {
              when input.output.datum is {
                InlineDatum(raw_pdat) -> {
                  expect pdat: PolicyDatum = raw_pdat
                  if pdat.pool_script_hash == own_pool_hash && pdat.pool_nft == own_pool_nft {
                    acc + assets.lovelace_of(input.output.value)
                  } else {
                    acc
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
  total == expected_total
}

fn batch_policies_match_totals(
  outputs: List<Output>,
  own_pool_hash: ByteArray,
  own_pool_nft: ByteArray,
  policy_script_hash: ByteArray,
  validity_range: ValidityRange,
  total_coverage: Int,
  total_premium: Int,
  underwrite_anchor: OutputReference,
) -> Bool {
  // [Δ21 / V-003] Per-output anchor: each policy output in the batch must
  // have its `policy_id` derived via `derive_policy_id_batch(...,
  // underwrite_anchor, batch_index)` where `batch_index` is the 0-based
  // index of the policy output within the batch. The fold tracks the
  // running batch_index and increments it ONLY for outputs that match the
  // policy_validator address (so non-policy outputs — e.g., the pool
  // continuation — do not consume an anchor index). Off-chain builders
  // mirror the same construction so each batch entry has a unique,
  // collision-resistant policy_id.
  let quad =
    list.foldl(
      outputs,
      (0, 0, True, 0),
      fn(out, acc) {
        let (cov_acc, prem_acc, ok_acc, batch_idx) = acc
        when out.address.payment_credential is {
          // [FIX A-021] Script credential MUST match the parameterized
          // policy_validator hash. The previous wildcard `Script(_)` allowed
          // an attacker to route the new policy output to any script address
          // (e.g., a mint-only policy's hash, an always-fail script, etc.),
          // inflating active_coverage on the pool while making the policy
          // permanently unspendable. Cost-to-damage ratio ~1:1 — the attacker
          // paid `coverage + premium` for `coverage` worth of locked pool
          // capacity.
          Script(h) ->
            if h == policy_script_hash {
              when out.datum is {
                InlineDatum(raw_pdat) -> {
                  expect pdat: PolicyDatum = raw_pdat
                  let time_ok =
                    start_time_in_tx_range(
                      pdat.start_time,
                      pdat.expiry_time,
                      validity_range,
                    )
                  // [v6.0.2 / A-026, A-027] `pdat.oracle_nft` must equal
                  // the network's canonical handle for the declared
                  // provider, so a non-canonical handle can never enter
                  // a `PolicyDatum`. Defense-in-depth alongside the
                  // per-parser `expect oracle_nft == canonical` checks.
                  let oracle_pinned =
                    pdat.oracle_nft == canonical_oracle_nft(
                      pdat.oracle_provider,
                    )
                  // [Δ21 / V-003 / H-3] Per-output policy_id binding: the
                  // datum's policy_id must equal the canonical batch
                  // derivation, anchored on the consumed pool UTxO's
                  // OutputReference plus the per-output batch_index.
                  let policy_id_ok =
                    pdat.policy_id == derive_policy_id_batch(
                      pdat.insured,
                      pdat.strike_price,
                      pdat.coverage_amount,
                      pdat.start_time,
                      pdat.expiry_time,
                      pdat.pool_nft,
                      underwrite_anchor,
                      batch_idx,
                    )
                  if pdat.pool_script_hash == own_pool_hash && pdat.pool_nft == own_pool_nft && time_ok && oracle_pinned && policy_id_ok {
                    let funded =
                      assets.lovelace_of(out.value) >= pdat.coverage_amount
                    (
                      cov_acc + pdat.coverage_amount,
                      prem_acc + pdat.premium_paid,
                      ok_acc && funded,
                      batch_idx + 1,
                    )
                  } else {
                    // Output is at the policy address but does not bind
                    // to this pool / fails another check — strictly
                    // reject by setting ok_acc to False so the totals
                    // cannot match. The batch_idx still advances so a
                    // subsequent legitimate output gets a fresh anchor.
                    (cov_acc, prem_acc, False, batch_idx + 1)
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
  let (cov_sum, prem_sum, funded_ok, _) = quad
  cov_sum == total_coverage && prem_sum == total_premium && funded_ok
}

/// [FIX A-015] Verify the policy datum's start_time falls within the
/// transaction's validity range and expiry_time strictly follows.
///
/// Without this, an attacker (or a careless builder) could create a
/// policy whose start_time is in the deep past or far future. Past-
/// dated policies have their cancellation window already closed at
/// creation, leaving the holder unable to cancel; future-dated policies
/// drift the active_coverage view of the pool with no way to claim
/// against them. The check is cheap (Int comparisons) and the
/// requirement that builders set a finite validity range is honored by
/// every honest off-chain path.
fn start_time_in_tx_range(
  start_time: Int,
  expiry_time: Int,
  validity_range: ValidityRange,
) -> Bool {
  let tx_lower = get_lower_bound(validity_range)
  let tx_upper = get_upper_bound(validity_range)
  start_time >= tx_lower && start_time <= tx_upper && expiry_time > start_time
}

fn policy_output_matches_underwrite(
  outputs: List<Output>,
  own_pool_hash: ByteArray,
  own_pool_nft: ByteArray,
  policy_script_hash: ByteArray,
  validity_range: ValidityRange,
  coverage: Int,
  premium: Int,
  underwrite_anchor: OutputReference,
) -> Bool {
  // [FIX A-025] Count matching policy outputs and require EXACTLY 1.
  // The previous `list.any` short-circuited at the first match — an
  // attacker could attach N legitimate policy outputs to a single
  // Underwrite, the pool's `active_coverage` only grew by ONE redeemer-
  // coverage, and the N-1 extras were stranded liability the pool
  // never accounted for. Live-on-chain demonstration:
  // tx b1400c6474dbecf2ad65a3ccdabac94c6a967e026d31ea128846ece02cd6f0a1
  // accepted 3 policy outputs against a single 5 ADA active_coverage
  // increment. With the count check, redeploys of that attack fail
  // because the second matching output causes the count to exceed 1.
  let matching_count =
    list.foldl(
      outputs,
      0,
      fn(out, acc) {
        when out.address.payment_credential is {
          Script(h) ->
            if h == policy_script_hash {
              when out.datum is {
                InlineDatum(raw_pdat) -> {
                  expect pdat: PolicyDatum = raw_pdat
                  // [v6.0.2 / A-026, A-027] Bind `oracle_nft` to the
                  // network-canonical handle for the declared provider.
                  // See `policy_output_matches_underwrite` doc above.
                  let oracle_pinned =
                    pdat.oracle_nft == canonical_oracle_nft(
                      pdat.oracle_provider,
                    )
                  // [v8 / Δ3 / H-3] policy_id must equal the canonical
                  // derivation that includes the consumed pool UTxO's
                  // OutputReference. Off-chain builders compute the same
                  // value via `aegis/types.derive_policy_id`. Without this
                  // binding, two policies with identical (insured, terms,
                  // pool_nft) collide on policy_id — a precondition for
                  // the witness-asset-name forgery attack class.
                  let policy_id_ok =
                    pdat.policy_id == derive_policy_id(
                      pdat.insured,
                      pdat.strike_price,
                      pdat.coverage_amount,
                      pdat.start_time,
                      pdat.expiry_time,
                      pdat.pool_nft,
                      underwrite_anchor,
                    )
                  let predicate =
                    pdat.pool_script_hash == own_pool_hash && pdat.pool_nft == own_pool_nft && pdat.coverage_amount == coverage && pdat.premium_paid == premium && oracle_pinned && policy_id_ok && assets.lovelace_of(
                      out.value,
                    ) >= coverage && start_time_in_tx_range(
                      pdat.start_time,
                      pdat.expiry_time,
                      validity_range,
                    )
                  if predicate {
                    acc + 1
                  } else {
                    acc
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
  matching_count == 1
}

// ---------------------------------------------------------------------------
// Pool Validator
// ---------------------------------------------------------------------------

/// Pool validator parameterized by the policy_validator's script hash.
///
/// [FIX A-022] The parameter is consumed by `policy_output_matches_underwrite`
/// and `batch_policies_match_totals` to require that newly-created policy
/// outputs land at the canonical policy_validator address. Without this
/// binding, an attacker could route the policy output to any script
/// credential (e.g., a mint-only policy hash), permanently locking the
/// pool's active_coverage at near-1:1 cost. Off-chain deployers MUST apply
/// this parameter (`aiken blueprint apply`) using the deployed
/// policy_validator hash before publishing the pool reference script.
validator pool_validator(policy_script_hash: ByteArray) {
  spend(
    datum_opt: Option<PoolDatum>,
    redeemer: PoolRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    // Datum must be present
    expect Some(datum) = datum_opt

    // [FIX A-021] Bind `treasury_donation` so the three fee-bearing branches
    // (Underwrite, BatchUnderwrite, AcceptCancellation) can enforce that the
    // Conway-era body field is at least the protocol-fee-derived cut. The
    // pool is a singleton (A-011), so this validator is the single point of
    // donation enforcement — there is no double-satisfaction risk because
    // there is only ever one consumed pool input per tx.
    let Transaction {
      inputs,
      outputs,
      mint,
      treasury_donation,
      validity_range,
      ..
    } = self

    // Find our own input to determine the script address
    let own_input =
      list.find(inputs, fn(input) { input.output_reference == own_ref })
    expect Some(self_input) = own_input
    let own_address = self_input.output.address
    let own_value = self_input.output.value

    // Find the continuing output (pool UTxO must be recreated)
    let pool_output =
      list.find(
        outputs,
        fn(output) {
          output.address == own_address && output_has_nft(
            output,
            datum.pool_nft,
          )
        },
      )

    when redeemer is {
      // -----------------------------------------------------------------------
      // UNDERWRITE: Reserve coverage for a new policy, collect premium
      // -----------------------------------------------------------------------
      Underwrite { coverage, premium } -> {
        expect Some(cont_output) = pool_output

        // 1. Parse the new pool datum
        expect InlineDatum(raw_new_datum) = cont_output.datum
        expect new_datum: PoolDatum = raw_new_datum

        // [FIX A-024] Reject non-positive coverage. Aiken's integer
        // division floors toward negative infinity, so the prior
        // `is_ratio_acceptable` check (`coverage / premium <= 50`)
        // accepted negative coverage (e.g. `-5 / 2_000_000 = -1 <= 50`).
        // `verify_underwrite_datum` then reduced `active_coverage` by
        // |coverage|, inflating apparent pool capacity and corrupting
        // accounting. Live exploit:
        // 01a1067cd496a31f069e0355717fe2ab1c4ebd5b2e0eb8ba1632a179cf04459a
        let coverage_positive = coverage > 0
        let premium_positive = premium > 0

        // 2. Verify premium adequacy
        let premium_ok = is_premium_adequate(premium, coverage)

        // 3. Verify pool can underwrite this coverage
        let can_cover =
          can_underwrite(datum.total_liquidity, datum.active_coverage, coverage)

        // 4. Calculate net premium (after protocol fee)
        let net = net_premium(premium, datum.protocol_fee_bps)

        // 5. Verify datum update is correct
        let datum_ok =
          verify_underwrite_datum(
            datum.total_liquidity,
            datum.active_coverage,
            new_datum.total_liquidity,
            new_datum.active_coverage,
            net,
            coverage,
          )

        // 6. Verify immutable fields are preserved (incl. lp_supply, which
        // does NOT change on Underwrite — only on Add/Remove Liquidity).
        let immutable_ok =
          new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft && new_datum.lp_supply == datum.lp_supply

        // 7. [FIX A-007] Pool value must EQUAL old value + premium exactly.
        // Previously used `>=`, which allowed extra value to enter the pool
        // without being counted in `total_liquidity`, silently diluting LPs.
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + premium

        // 8. [FIX A-004] An Underwrite tx MUST create a policy output whose
        // datum is bound to THIS pool with matching coverage and premium.
        // Previously, an attacker could call Underwrite without creating any
        // policy, locking pool capacity for ~2% cost.
        let own_pool_hash =
          when self_input.output.address.payment_credential is {
            Script(h) -> h
            _ -> #""
          }
        let policy_funded =
          policy_output_matches_underwrite(
            outputs,
            own_pool_hash,
            datum.pool_nft,
            policy_script_hash,
            validity_range,
            coverage,
            premium,
            own_ref,
          )

        // 9. [FIX A-021] The Conway-era treasury_donation must be at least the
        // protocol-fee-derived cut. Sourced from the submitter's wallet
        // inputs (NOT from the premium that flows to the pool), so the
        // strict A-007 value check on the pool continuation is unaffected.
        // `>=` (not `==`) is used per scope §3.3 — overshoots are tips to
        // the treasury, not an attack surface.
        let required_donation =
          calculate_treasury_cut(
            premium,
            datum.protocol_fee_bps,
            treasury_share_bps,
          )
        let donation_ok =
          when treasury_donation is {
            Some(amt) -> amt >= required_donation
            None -> required_donation == 0
          }

        coverage_positive && premium_positive && premium_ok && can_cover && datum_ok && immutable_ok && value_ok && policy_funded && donation_ok
      }

      // -----------------------------------------------------------------------
      // PROCESS CLAIM: Deduct payout from pool
      // -----------------------------------------------------------------------
      ProcessClaim { payout } -> {
        expect Some(cont_output) = pool_output

        // 1. Parse the new pool datum
        expect InlineDatum(raw_new_datum) = cont_output.datum
        expect new_datum: PoolDatum = raw_new_datum

        // 2. Verify payout is positive
        let payout_positive = payout > 0

        // [FIX A-001] Find the consumed policy UTxO and read its datum.
        // Verify (a) the policy targets THIS pool, (b) its coverage matches
        // the requested payout. Without these checks, anyone can submit ANY
        // policy UTxO (including a self-constructed synthetic policy) and
        // request an arbitrarily large payout.
        //
        // [v6.0.2 / L-006 fix] Resolve the policy script credential via
        // the validator's parameterized `policy_script_hash` rather than a
        // redeemer-supplied field. Pre-fix, an attacker could submit
        // `ProcessClaim { policy_script: <attacker_hash> }` referencing a
        // policy UTxO at their own permissive script and drain the pool
        // up to `active_coverage` in a single tx for ~3 ADA cost.
        let own_pool_hash =
          when self_input.output.address.payment_credential is {
            Script(h) -> h
            _ -> #""
          }
        expect Some(policy_input) =
          list.find(
            inputs,
            fn(i) {
              when i.output.address.payment_credential is {
                Script(h) -> h == policy_script_hash
                _ -> False
              }
            },
          )
        expect InlineDatum(raw_policy_datum) = policy_input.output.datum
        expect policy_datum: PolicyDatum = raw_policy_datum
        // [FIX F-004 + A-001] Policy must point at THIS pool AND payout must
        // equal the policy's declared coverage. Both bindings prevent the
        // single-tx pool drain attack described in A-001.
        let policy_targets_this_pool =
          policy_datum.pool_script_hash == own_pool_hash && policy_datum.pool_nft == datum.pool_nft
        let payout_matches_coverage = payout == policy_datum.coverage_amount
        let policy_consumed =
          policy_targets_this_pool && payout_matches_coverage

        // 3. Verify datum update is correct
        let datum_ok =
          verify_claim_datum(
            datum.total_liquidity,
            datum.active_coverage,
            new_datum.total_liquidity,
            new_datum.active_coverage,
            payout,
          )

        // 4. Verify immutable fields preserved
        let immutable_ok =
          new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft && new_datum.lp_supply == datum.lp_supply

        // 5. [FIX A-007] Pool value must DECREASE by exactly `payout`.
        // Previously used `>=`, which permitted the pool to retain extra value
        // (the difference being unaccounted-for in the datum, rendering pool
        // accounting drift-prone).
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) - payout

        // [FIX F-007 / A-005] Solvency is now enforced inside verify_claim_datum
        // (which requires payout ≤ old_active and new_active ≥ 0). The previous
        // `new_total >= new_active` check was tautological because both fields
        // decrement by the same payout.
        let remains_non_negative =
          new_datum.total_liquidity >= 0 && new_datum.active_coverage >= 0

        payout_positive && policy_consumed && datum_ok && immutable_ok && value_ok && remains_non_negative
      }

      // -----------------------------------------------------------------------
      // ADD LIQUIDITY: LP deposits ADA, receives LP tokens
      // -----------------------------------------------------------------------
      AddLiquidity { amount } -> {
        expect Some(cont_output) = pool_output

        // 1. Parse the new pool datum
        expect InlineDatum(raw_new_datum) = cont_output.datum
        expect new_datum: PoolDatum = raw_new_datum

        // 2. Verify amount is positive
        let amount_positive = amount > 0

        // 3. [FIX A-003] Verify datum update including lp_supply.
        let datum_ok =
          verify_add_liquidity_datum(
            datum.total_liquidity,
            datum.active_coverage,
            datum.lp_supply,
            new_datum.total_liquidity,
            new_datum.active_coverage,
            new_datum.lp_supply,
            amount,
          )

        // 4. Verify immutable fields preserved (lp_supply moves with the
        // deposit; verify_add_liquidity_datum enforces its delta).
        let immutable_ok =
          new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft

        // 5. [FIX A-007] Pool value must EQUAL old + amount exactly.
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + amount

        // 6. [FIX A-003] LP mint quantity must EXACTLY MATCH the lp_supply
        // delta in the new datum. This binds direction + magnitude in one
        // check: an attacker cannot mint with a Burn redeemer (covered by
        // verify_add_liquidity_datum requiring positive delta), nor mint
        // a different magnitude than the calculation prescribes.
        let mint_qty = assets.quantity_of(mint, datum.lp_token_policy, "aLP")
        let lp_supply_delta = new_datum.lp_supply - datum.lp_supply
        let lp_minted = mint_qty == lp_supply_delta && mint_qty > 0

        amount_positive && datum_ok && immutable_ok && value_ok && lp_minted
      }

      // -----------------------------------------------------------------------
      // REMOVE LIQUIDITY: LP burns tokens, withdraws ADA
      // -----------------------------------------------------------------------
      RemoveLiquidity { amount } -> {
        expect Some(cont_output) = pool_output

        // 1. Parse the new pool datum
        expect InlineDatum(raw_new_datum) = cont_output.datum
        expect new_datum: PoolDatum = raw_new_datum

        // 2. Verify amount is positive
        let amount_positive = amount > 0

        // 3. Verify withdrawal does not impair active coverage
        let withdrawal_safe =
          can_withdraw(datum.total_liquidity, datum.active_coverage, amount)

        // 4. [FIX A-003] LP burn quantity is taken from the mint and must
        // be the canonical match for the requested withdrawal amount.
        let mint_qty = assets.quantity_of(mint, datum.lp_token_policy, "aLP")
        let lp_burned_qty = -mint_qty

        // positive number = burn count
        // 5. Verify datum update — including lp_supply decrement and the
        // exact relationship between lp_burned and amount.
        let datum_ok =
          verify_remove_liquidity_datum(
            datum.total_liquidity,
            datum.active_coverage,
            datum.lp_supply,
            new_datum.total_liquidity,
            new_datum.active_coverage,
            new_datum.lp_supply,
            amount,
            lp_burned_qty,
          )

        // 6. Verify immutable fields preserved (lp_supply changes per
        // verify_remove_liquidity_datum).
        let immutable_ok =
          new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft

        // 7. [FIX A-002] Pool value must DECREASE by exactly `amount`.
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) - amount

        // 8. [FIX A-003] Sanity: mint must be strictly negative (burn).
        let direction_ok = mint_qty < 0

        amount_positive && withdrawal_safe && datum_ok && immutable_ok && value_ok && direction_ok
      }

      // -----------------------------------------------------------------------
      // BATCH UNDERWRITE: Create N policies in a single transaction
      // Same logic as Underwrite but with aggregate totals.
      // -----------------------------------------------------------------------
      BatchUnderwrite { total_coverage, total_premium } -> {
        expect Some(cont_output) = pool_output

        // 1. Parse the new pool datum
        expect InlineDatum(raw_new_datum) = cont_output.datum
        expect new_datum: PoolDatum = raw_new_datum

        // [FIX A-024] Same positivity guard as Underwrite. Without this,
        // a BatchUnderwrite with `total_coverage < 0` would shrink the
        // pool's active_coverage and corrupt accounting.
        let coverage_positive = total_coverage > 0
        let premium_positive = total_premium > 0

        // 2. Verify premium is adequate (use aggregate amounts)
        let premium_ok = is_premium_adequate(total_premium, total_coverage)

        // 3. Verify pool can cover the total coverage
        let can_cover =
          can_underwrite(
            datum.total_liquidity,
            datum.active_coverage,
            total_coverage,
          )

        // 4. Net premium after protocol fee
        let net = net_premium(total_premium, datum.protocol_fee_bps)

        // 5. Verify datum update (same math, aggregate amounts)
        let datum_ok =
          verify_underwrite_datum(
            datum.total_liquidity,
            datum.active_coverage,
            new_datum.total_liquidity,
            new_datum.active_coverage,
            net,
            total_coverage,
          )

        // 6. Verify immutable fields preserved
        // (lp_supply is immutable for Underwrite/ProcessClaim/BatchUnderwrite/BatchExpireProcess
        //  — only AddLiquidity / RemoveLiquidity move it.)
        let immutable_ok =
          new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft && new_datum.lp_supply == datum.lp_supply

        // 7. [FIX A-007] Pool value must EQUAL old + total_premium exactly.
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + total_premium

        // 8. [FIX A-004] BatchUnderwrite must create policy outputs that
        // collectively match the redeemer's totals. We verify the SUM of
        // coverages across all policy outputs at any script address that
        // bind to this pool equals total_coverage, and likewise for premium.
        let own_pool_hash =
          when self_input.output.address.payment_credential is {
            Script(h) -> h
            _ -> #""
          }
        let batch_policies_funded =
          batch_policies_match_totals(
            outputs,
            own_pool_hash,
            datum.pool_nft,
            policy_script_hash,
            validity_range,
            total_coverage,
            total_premium,
            own_ref,
          )

        // 9. [FIX A-021] Aggregate treasury cut = floor(total_premium *
        // protocol_fee_bps * treasury_share_bps / 1e8). Aggregating in one
        // shot (rather than summing per-policy cuts) matches the off-chain
        // builder's single-donation field; per-policy cuts would re-introduce
        // a multi-claim double-satisfaction shape and waste min-fee bytes.
        let required_donation =
          calculate_treasury_cut(
            total_premium,
            datum.protocol_fee_bps,
            treasury_share_bps,
          )
        let donation_ok =
          when treasury_donation is {
            Some(amt) -> amt >= required_donation
            None -> required_donation == 0
          }

        coverage_positive && premium_positive && premium_ok && can_cover && datum_ok && immutable_ok && value_ok && batch_policies_funded && donation_ok
      }

      // -----------------------------------------------------------------------
      // BATCH EXPIRE PROCESS: Return expired policy funds to pool
      // -----------------------------------------------------------------------
      BatchExpireProcess { total_returned } -> {
        expect Some(cont_output) = pool_output

        // 1. Parse the new pool datum
        expect InlineDatum(raw_new_datum) = cont_output.datum
        expect new_datum: PoolDatum = raw_new_datum

        // 2. Verify total_returned is positive
        let returned_positive = total_returned > 0

        // 3. [FIX A-001] Verify the consumed policies (a) come from the
        // canonical policy_validator (parameterized hash), (b) bind to
        // THIS pool, and (c) their lovelace sum equals total_returned.
        //
        // [v6.0.2 / L-006 fix] The policy script credential is now sourced
        // from the validator's `policy_script_hash` parameter, not a
        // redeemer-supplied field. Pre-fix, an attacker could substitute
        // their own permissive script.
        let own_pool_hash =
          when self_input.output.address.payment_credential is {
            Script(h) -> h
            _ -> #""
          }
        let policies_consumed =
          count_script_inputs(inputs, policy_script_hash) >= 1
        let consumed_policies_match =
          consumed_policies_total_to(
            inputs,
            policy_script_hash,
            own_pool_hash,
            datum.pool_nft,
            total_returned,
          )

        // 4. Verify datum: active_coverage decremented by total_returned,
        //    total_liquidity stays the same (expired policy funds were
        //    already counted in total_liquidity when underwritten)
        let datum_ok =
          new_datum.total_liquidity == datum.total_liquidity && new_datum.active_coverage == datum.active_coverage - total_returned

        // 5. Verify immutable fields preserved
        let immutable_ok =
          new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft && new_datum.lp_supply == datum.lp_supply

        // 6. [FIX A-007] Pool value must EQUAL old + total_returned exactly.
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + total_returned

        // 7. [FIX A-005] Non-negativity (the old new_total >= new_active check
        // was tautological because both fields decrement equally).
        let remains_non_negative =
          new_datum.total_liquidity >= 0 && new_datum.active_coverage >= 0 && total_returned <= datum.active_coverage

        returned_positive && policies_consumed && consumed_policies_match && datum_ok && immutable_ok && value_ok && remains_non_negative
      }

      // -----------------------------------------------------------------------
      // [FIX A-020] ACCEPT CANCELLATION: Settle a Cancel-redeemed policy.
      //
      // Background: the A-008 fix forced `policy.Cancel` to route its residual
      // via `find_canonical_pool_output` (must carry pool_nft). The only UTxO
      // with that NFT is the live pool, so the pool MUST be co-spent on cancel.
      // But there was no pool redeemer that fit the cancellation pattern,
      // making Cancel structurally unbuildable until this redeemer was added.
      //
      // Semantics:
      //   - Insured receives the canonical refund = `calculate_refund(premium_paid)`
      //     (currently 90% of the policy's premium). The refund amount is
      //     DERIVED from the consumed policy's datum, not caller-controlled,
      //     so a hostile builder cannot inflate it.
      //   - Pool's lovelace decreases by exactly `refund_amount` (the refund
      //     comes out of the pool's reserves; the policy's pre-funded coverage
      //     flows back to the insured directly via `policy.Cancel`'s output
      //     check, not via the pool).
      //   - Pool's `total_liquidity` decrements by `refund_amount`.
      //   - Pool's `active_coverage` decrements by the consumed policy's
      //     `coverage_amount` (de-reservation).
      //   - lp_supply is unchanged (LP economics untouched).
      //   - Anti-A-001: the consumed policy must declare it points at THIS
      //     pool (matching pool_script_hash + pool_nft).
      //   - The 10% cancellation fee remains in the pool's actual lovelace
      //     surplus (it was originally counted into total_liquidity at
      //     Underwrite time as part of net_premium; on cancel we only return
      //     the 90% refund, so the 10% retention is implicit).
      // -----------------------------------------------------------------------
      AcceptCancellation -> {
        expect Some(cont_output) = pool_output

        // 1. Parse the new pool datum
        expect InlineDatum(raw_new_datum) = cont_output.datum
        expect new_datum: PoolDatum = raw_new_datum

        // 2. Locate the consumed Cancel-redeemed policy and parse its datum.
        //
        // [v6.0.2 / L-006 fix] Resolve the policy script credential via
        // the validator's `policy_script_hash` parameter rather than a
        // redeemer field. Same root cause as the ProcessClaim and
        // BatchExpireProcess fixes.
        let own_pool_hash =
          when self_input.output.address.payment_credential is {
            Script(h) -> h
            _ -> #""
          }
        expect Some(policy_input) =
          list.find(
            inputs,
            fn(i) {
              when i.output.address.payment_credential is {
                Script(h) -> h == policy_script_hash
                _ -> False
              }
            },
          )
        expect InlineDatum(raw_policy_datum) = policy_input.output.datum
        expect policy_datum: PolicyDatum = raw_policy_datum

        // 3. [Anti-A-001] Policy must point at THIS pool.
        let policy_targets_this_pool =
          policy_datum.pool_script_hash == own_pool_hash && policy_datum.pool_nft == datum.pool_nft

        // 4. Compute the canonical refund (derived; not caller-controlled).
        let refund_amount = calculate_refund(policy_datum.premium_paid)

        // 5. Sanity bounds (defensive — guarantees no underflow).
        let bounds_ok =
          refund_amount >= 0 && refund_amount <= datum.total_liquidity && policy_datum.coverage_amount <= datum.active_coverage

        // 6. Pool's value must DECREASE by exactly refund_amount
        // (the policy's pre-funded value is routed by policy.Cancel directly
        // to the insured; it does NOT flow into the pool's continuation).
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) - refund_amount

        // 7. Datum: total_liquidity drops by refund, active_coverage drops by
        // the consumed policy's coverage. lp_supply unchanged.
        let datum_ok =
          new_datum.total_liquidity == datum.total_liquidity - refund_amount && new_datum.active_coverage == datum.active_coverage - policy_datum.coverage_amount

        // 8. Immutable fields preserved (incl. lp_supply — LP supply does NOT
        // change on cancel; only Add/Remove Liquidity move it).
        let immutable_ok =
          new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft && new_datum.lp_supply == datum.lp_supply

        // 9. Solvency post-cancel.
        let remains_non_negative =
          new_datum.total_liquidity >= 0 && new_datum.active_coverage >= 0

        // 10. [FIX A-021] Treasury cut on the cancellation fee. The
        // cancellation fee is the 10% of premium retained on cancel
        // (cancellation_fee_bps = 1_000); the treasury takes its share of
        // THAT fee, not of the 90% refund. So the cut is `floor(premium_paid
        // * 1_000 * treasury_share_bps / 1e8)`. Derived from the consumed
        // policy datum (NOT caller-controlled), so a hostile builder cannot
        // dodge the donation by lying about premium.
        let required_donation =
          policy_datum.premium_paid * 1_000 / 10_000 * treasury_share_bps / 10_000
        let donation_ok =
          when treasury_donation is {
            Some(amt) -> amt >= required_donation
            None -> required_donation == 0
          }

        policy_targets_this_pool && bounds_ok && value_ok && datum_ok && immutable_ok && remains_non_negative && donation_ok
      }
    }
  }

  else(_) {
    fail @"Unsupported purpose for pool_validator"
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test underwrite_coverage_check() {
  // Pool: 100 ADA total, 30 ADA active -> 70 ADA available
  // New policy wants 50 ADA coverage -> should pass
  can_underwrite(100_000_000, 30_000_000, 50_000_000)
}

test underwrite_coverage_insufficient() {
  // Pool: 100 ADA total, 80 ADA active -> 20 ADA available
  // New policy wants 50 ADA coverage -> should fail
  can_underwrite(100_000_000, 80_000_000, 50_000_000) == False
}

test withdrawal_safe_check() {
  // Pool: 100 ADA total, 30 ADA active, withdraw 50 ADA
  // After: 50 ADA total, 30 ADA active -> still solvent
  can_withdraw(100_000_000, 30_000_000, 50_000_000)
}

test withdrawal_unsafe_check() {
  // Pool: 100 ADA total, 80 ADA active, withdraw 30 ADA
  // After: 70 ADA total, 80 ADA active -> insolvent!
  can_withdraw(100_000_000, 80_000_000, 30_000_000) == False
}
