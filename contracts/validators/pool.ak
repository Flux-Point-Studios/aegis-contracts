use aegis/oracle.{is_canonical_oracle_nft}
use aegis/pool.{
  can_underwrite, can_withdraw, verify_add_liquidity_datum, verify_claim_datum,
  verify_remove_liquidity_datum, verify_underwrite_datum,
}
use aegis/pricing.{
  calculate_protocol_fee_split, calculate_refund, calculate_treasury_cut,
  is_premium_adequate, net_premium,
}
use aegis/types.{
  AcceptCancellation, AddLiquidity, BatchExpireProcess, BatchUnderwrite,
  PolicyDatum, PoolDatum, PoolRedeemer, ProcessClaim, RemoveLiquidity,
  Underwrite, min_utxo_lovelace, partner_share_cap_bps, team_address,
  treasury_share_bps,
}
use aegis/validation.{
  count_script_inputs, get_lower_bound, get_upper_bound, output_has_nft,
}
use cardano/address.{Address}
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

// ---------------------------------------------------------------------------
// [v12 §3.10] BatchFeeTotals — aggregated walker output for BatchUnderwrite.
//
// The walker `batch_policies_match_totals_v12` (below) folds across the tx
// outputs and produces this record. Two separate sums are tracked for team
// and partner cuts:
//   * `team_total_floored` / `partner_totals_floored` — used by the team/
//     partner output check (`output_to_address_at_least`). Each per-policy
//     cut is floored to min_utxo BEFORE summing — submitter pads each
//     floor gap, NOT the pool.
//   * `team_total_unfloored` / `partner_totals_unfloored_sum` — used by the
//     pool's value_ok invariant. Pool grows by `total_premium - team_total
//     _unfloored - partner_totals_unfloored_sum` (percentage-calculated cuts
//     only, NOT floored). The floor pads come from the submitter wallet,
//     exogenous to pool accounting.
//
// `partner_totals_floored` is keyed by Address — the off-chain builder
// emits ONE consolidated output per unique partner address. The aggregator
// in `accumulate_partner` (below) merges per-policy contributions per
// address.
//
// `shares_ok` = all policies pass partner_share_bps ∈ [0, cap] AND the
// `Some(_) | share == 0 when None` consistency check.
// ---------------------------------------------------------------------------
type BatchFeeTotals {
  cov_sum: Int,
  prem_sum: Int,
  funded_ok: Bool,
  team_total_floored: Int,
  team_total_unfloored: Int,
  partner_totals_floored: List<(Address, Int)>,
  partner_totals_unfloored_sum: Int,
  shares_ok: Bool,
}

/// [v12 §3.10] Merge a per-policy partner cut into the running floored
/// totals list. If `addr` already has an entry, bump it; otherwise push a
/// new entry. Aiken stdlib lacks a `Map<Address, Int>` constructor, so the
/// aggregation uses a `List<(Address, Int)>` accumulator — address equality
/// is structural (Aiken records).
fn accumulate_partner(
  acc: List<(Address, Int)>,
  addr: Address,
  amt: Int,
) -> List<(Address, Int)> {
  when list.find(acc, fn(pair) { pair.1st == addr }) is {
    Some(_) ->
      list.map(
        acc,
        fn(pair) {
          if pair.1st == addr {
            (addr, pair.2nd + amt)
          } else {
            pair
          }
        },
      )
    None -> list.push(acc, (addr, amt))
  }
}

/// [v12 §3.10] Sum the lovelace across all aggregated partner cuts. Used
/// to derive `total_net = total_premium - team_total_unfloored -
/// sum_partner_cuts(partner_totals_unfloored)`.
fn sum_partner_cuts(entries: List<(Address, Int)>) -> Int {
  list.foldl(entries, 0, fn(entry, acc) { acc + entry.2nd })
}

fn batch_policies_match_totals(
  outputs: List<Output>,
  own_pool_hash: ByteArray,
  own_pool_nft: ByteArray,
  policy_script_hash: ByteArray,
  validity_range: ValidityRange,
  total_coverage: Int,
  total_premium: Int,
) -> Bool {
  let triple =
    list.foldl(
      outputs,
      (0, 0, True),
      fn(out, acc) {
        let (cov_acc, prem_acc, ok_acc) = acc
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
                  // [v12 / A-026, A-027 generalised] `pdat.oracle_nft` must
                  // be a canonical handle for the declared provider. For
                  // AegisSelf this is membership in the V12 five-NFT
                  // allowlist; for Charli3/Orcfax it's the single pinned
                  // value (semantics unchanged). Defense-in-depth alongside
                  // the per-parser `expect ... canonical` checks.
                  let oracle_pinned =
                    is_canonical_oracle_nft(pdat.oracle_provider, pdat.oracle_nft)
                  if pdat.pool_script_hash == own_pool_hash && pdat.pool_nft == own_pool_nft && time_ok && oracle_pinned {
                    let funded =
                      assets.lovelace_of(out.value) >= pdat.coverage_amount
                    (
                      cov_acc + pdat.coverage_amount,
                      prem_acc + pdat.premium_paid,
                      ok_acc && funded,
                    )
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
  let (cov_sum, prem_sum, funded_ok) = triple
  cov_sum == total_coverage && prem_sum == total_premium && funded_ok
}

/// [v12 §3.10] BatchUnderwrite walker. Iterates the tx outputs once and
/// returns a `BatchFeeTotals` carrying:
///   * `cov_sum` / `prem_sum` — aggregate coverage and premium from policy
///     outputs (must equal redeemer's total_coverage / total_premium).
///   * `funded_ok` — every policy output carries >= its coverage in lovelace.
///   * `team_total_floored` / `team_total_unfloored` — per-policy team_cut_i
///     sums, floored and unfloored respectively. The validator uses the
///     floored sum for the team-output gate; the unfloored sum for the
///     pool-value invariant (floor pads come from submitter, not pool).
///   * `partner_totals_floored` — `List<(Address, Int)>` of per-unique-
///     partner aggregated floored cuts. The off-chain builder emits ONE
///     output per unique partner address; the validator checks each
///     entry's sum is matched by an output `>=` the entry's amount.
///   * `partner_totals_unfloored_sum` — `Σ partner_cut_i` for the pool
///     value invariant.
///   * `shares_ok` — `True` iff every policy passes (cap + consistency +
///     non-negativity) on its `partner_share_bps`.
///
/// The walker enforces ALL the per-policy invariants in a single pass
/// (canonical pool binding, canonical oracle NFT, time-range, policy
/// script credential, coverage-funded, cap-bound bps, consistency).
/// Any per-policy violation degrades `shares_ok` or `funded_ok` to False
/// — the validator's top-level conjunction catches it.
fn batch_policies_match_totals_v12(
  outputs: List<Output>,
  own_pool_hash: ByteArray,
  own_pool_nft: ByteArray,
  policy_script_hash: ByteArray,
  validity_range: ValidityRange,
  total_coverage: Int,
  total_premium: Int,
  protocol_fee_bps: Int,
) -> BatchFeeTotals {
  let init =
    BatchFeeTotals {
      cov_sum: 0,
      prem_sum: 0,
      funded_ok: True,
      team_total_floored: 0,
      team_total_unfloored: 0,
      partner_totals_floored: [],
      partner_totals_unfloored_sum: 0,
      shares_ok: True,
    }
  let totals =
    list.foldl(
      outputs,
      init,
      fn(out, acc) {
        when out.address.payment_credential is {
          // [FIX A-021] Script credential MUST match the parameterized
          // policy_validator hash. See `batch_policies_match_totals` doc.
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
                  // [v12 / A-026, A-027 generalised] Canonical NFT pin.
                  let oracle_pinned =
                    is_canonical_oracle_nft(pdat.oracle_provider, pdat.oracle_nft)
                  if pdat.pool_script_hash == own_pool_hash && pdat.pool_nft == own_pool_nft && time_ok && oracle_pinned {
                    let funded =
                      assets.lovelace_of(out.value) >= pdat.coverage_amount
                    // [v12 §3.10] Per-policy partner_share_bps invariants.
                    // Bounds + consistency are folded into shares_ok; the
                    // validator's top-level conjunction rejects the whole
                    // batch if ANY policy fails.
                    let bps_in_bounds =
                      pdat.partner_share_bps >= 0 && pdat.partner_share_bps <= partner_share_cap_bps
                    let bps_consistency =
                      when pdat.partner_address is {
                        Some(_) -> True
                        None -> pdat.partner_share_bps == 0
                      }
                    let this_shares_ok = bps_in_bounds && bps_consistency
                    // [v12 §3.10] Per-policy fee split. Both halves
                    // (floored AND unfloored) accumulate — the floored
                    // sum drives the per-address output checks; the
                    // unfloored sum drives the pool's value_ok invariant.
                    let (team_cut_i, partner_cut_i) =
                      calculate_protocol_fee_split(
                        pdat.premium_paid,
                        protocol_fee_bps,
                        pdat.partner_share_bps,
                      )
                    let team_cut_floored_i = floor_to_min_utxo(team_cut_i)
                    // [v12 §3.10 / D7] Per-policy floor on partner_cut: each
                    // policy's partner_cut floors independently BEFORE
                    // summing into the per-address aggregate. The
                    // attacker-bypass attempt
                    // (aggregate-then-floor) was specifically called out
                    // in §3.10.2(1) — per-policy floor is what's enforced.
                    let partner_cut_floored_i = floor_to_min_utxo(partner_cut_i)
                    let new_partner_totals_floored =
                      when pdat.partner_address is {
                        Some(addr) ->
                          accumulate_partner(
                            acc.partner_totals_floored,
                            addr,
                            partner_cut_floored_i,
                          )
                        None -> acc.partner_totals_floored
                      }
                    let partner_unfloored_delta =
                      when pdat.partner_address is {
                        Some(_) -> partner_cut_i
                        None -> 0
                      }
                    BatchFeeTotals {
                      cov_sum: acc.cov_sum + pdat.coverage_amount,
                      prem_sum: acc.prem_sum + pdat.premium_paid,
                      funded_ok: acc.funded_ok && funded,
                      team_total_floored: acc.team_total_floored + team_cut_floored_i,
                      team_total_unfloored: acc.team_total_unfloored + team_cut_i,
                      partner_totals_floored: new_partner_totals_floored,
                      partner_totals_unfloored_sum: acc.partner_totals_unfloored_sum + partner_unfloored_delta,
                      shares_ok: acc.shares_ok && this_shares_ok,
                    }
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
  // Aggregate totals must match the redeemer's claimed totals AND every
  // policy output's lovelace must be >= its coverage.
  BatchFeeTotals {
    ..totals,
    funded_ok: totals.funded_ok && totals.cov_sum == total_coverage && totals.prem_sum == total_premium,
  }
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

/// [v12 §3.8] Locate the freshly-created policy output that matches the
/// Underwrite redeemer and surface its `(partner_address, partner_share_bps)`
/// for the caller's team/partner output enforcement.
///
/// Returns:
///   * `Some((partner_addr, partner_bps))` when EXACTLY ONE policy output
///     in `outputs` satisfies every binding (pool_nft, pool_script_hash,
///     coverage_amount, premium_paid, oracle pin, lovelace >= coverage,
///     start_time inside the tx validity range), and the new policy
///     datum's partner fields are returned for the validator to enforce
///     the team/partner output checks.
///   * `None` otherwise — caught by the caller's `expect Some(...)` which
///     fails the branch immediately. The count-exactly-one A-025 fix is
///     preserved: 0 OR >1 matching outputs both surface as None.
fn policy_output_matches_underwrite(
  outputs: List<Output>,
  own_pool_hash: ByteArray,
  own_pool_nft: ByteArray,
  policy_script_hash: ByteArray,
  validity_range: ValidityRange,
  coverage: Int,
  premium: Int,
) -> Option<(Option<Address>, Int)> {
  // [FIX A-025] Walk the outputs counting matches and capturing the partner
  // fields of the (unique) matching one. The fold accumulator carries the
  // count plus the most-recent matching policy's partner fields. We only
  // return `Some(...)` when count == 1, so >1 matches degrade to None and
  // fail the branch the same way 0 matches do. [v12] The previous Bool
  // return type is widened to `Option<(Option<Address>, Int)>` so the
  // caller can apply the per-policy team/partner output checks without a
  // second walk over `outputs`.
  let walk =
    list.foldl(
      outputs,
      (0, None, 0),
      fn(out, acc) {
        let (count_acc, partner_addr_acc, partner_bps_acc) = acc
        when out.address.payment_credential is {
          Script(h) ->
            if h == policy_script_hash {
              when out.datum is {
                InlineDatum(raw_pdat) -> {
                  expect pdat: PolicyDatum = raw_pdat
                  // [v12 / A-026, A-027 generalised] Bind `oracle_nft` to
                  // a canonical handle for the declared provider. AegisSelf
                  // accepts the five-NFT allowlist; Charli3/Orcfax pin a
                  // single value. See `is_canonical_oracle_nft` in oracle.ak.
                  let oracle_pinned =
                    is_canonical_oracle_nft(pdat.oracle_provider, pdat.oracle_nft)
                  let predicate =
                    pdat.pool_script_hash == own_pool_hash && pdat.pool_nft == own_pool_nft && pdat.coverage_amount == coverage && pdat.premium_paid == premium && oracle_pinned && assets.lovelace_of(
                      out.value,
                    ) >= coverage && start_time_in_tx_range(
                      pdat.start_time,
                      pdat.expiry_time,
                      validity_range,
                    )
                  if predicate {
                    (count_acc + 1, pdat.partner_address, pdat.partner_share_bps)
                  } else {
                    (count_acc, partner_addr_acc, partner_bps_acc)
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
  let (matching_count, partner_addr, partner_bps) = walk
  if matching_count == 1 {
    Some((partner_addr, partner_bps))
  } else {
    None
  }
}

// ---------------------------------------------------------------------------
// [v12 §3.8 / D7] Floor-pad helper. The per-output min-utxo floor is
// `max(min_utxo_lovelace, percentage_cut)` — when the percentage-calculated
// fee cut is below the 2-ADA min-utxo floor (small premiums, < 100 ADA at
// the default 200 bps), the submitter's wallet pays the floor-pad subsidy.
// The pool's `total_liquidity` and physical lovelace still grow by exactly
// `net_premium = premium - team_cut - partner_cut` (NOT minus the floored
// amounts) — the floor pad is exogenous to pool accounting, sourced from
// submitter inputs the same way the Conway `treasury_donation` is.
// ---------------------------------------------------------------------------
fn floor_to_min_utxo(amount: Int) -> Int {
  if amount > min_utxo_lovelace {
    amount
  } else {
    min_utxo_lovelace
  }
}

/// [v12 §3.8 / D7] Predicate: does `outputs` contain at least one entry at
/// `addr` carrying at least `required_lovelace`?
///
/// The team/partner output check is a `list.any` with `>=` — the off-chain
/// builder always emits ONE consolidated output per address, but the
/// validator accepts split-across-N too (only one of them needs to satisfy
/// the threshold, since `>=` covers overshoots). Address equality is on the
/// FULL `Address` (payment + stake), not just payment_credential, so an
/// operator who delegates the team wallet to a different stake pool must
/// rebuild and redeploy.
fn output_to_address_at_least(
  outputs: List<Output>,
  addr: Address,
  required_lovelace: Int,
) -> Bool {
  list.any(
    outputs,
    fn(o) {
      o.address == addr && assets.lovelace_of(o.value) >= required_lovelace
    },
  )
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
      // [v12 §3.8] UNDERWRITE: Reserve coverage for a new policy, collect
      // premium, and route the 2% protocol fee to team_address (+ optional
      // partner_address per the new policy's PolicyDatum).
      //
      // V12 breaking changes vs V11:
      //   * Pool continuation grows by `net_premium`, NOT by the full premium.
      //     The 2% leaves the pool at Underwrite time and routes to the
      //     team/partner outputs (was phantom liquidity in V11).
      //   * NEW: an output at `team_address` with lovelace >= max(min_utxo,
      //     team_cut) is required.
      //   * NEW: if the new policy's `partner_address` is Some(addr), an
      //     output at addr with lovelace >= max(min_utxo, partner_cut) is
      //     required.
      //   * NEW: cap + consistency on the new policy's `partner_share_bps`.
      //
      // Floor-pad invariant (D7): when the percentage-calculated cuts are
      // below the 2-ADA min-utxo floor, the submitter's wallet supplies the
      // pad — the POOL's value reduction is by the percentage cuts only.
      // The floor pad is exogenous to pool accounting, same submitter-source
      // pattern as the Conway `treasury_donation`.
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

        // 7. [v12 §3.8] Pool value grows by `net`, NOT by the full premium.
        // Pre-V12 this was `+ premium` and the 2% sat as phantom lovelace in
        // the pool — unreachable by team OR LPs (since `total_liquidity`
        // only counted `net`). V12 routes the 2% explicitly to the
        // team/partner outputs below, making pool accounting honest.
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + net

        // 8. [FIX A-004 / v12] An Underwrite tx MUST create exactly one
        // policy output bound to THIS pool with matching coverage/premium.
        // V12 widens the helper's return type from Bool to
        // `Option<(Option<Address>, Int)>` so the partner fields of the new
        // policy's datum can be threaded back here for the team/partner
        // output checks without a second walk over outputs.
        let own_pool_hash =
          when self_input.output.address.payment_credential is {
            Script(h) -> h
            _ -> #""
          }
        expect Some((new_partner_address, new_partner_share_bps)) =
          policy_output_matches_underwrite(
            outputs,
            own_pool_hash,
            datum.pool_nft,
            policy_script_hash,
            validity_range,
            coverage,
            premium,
          )

        // 9. [v12 §3.8] Cap check on partner_share_bps. Defense-in-depth
        // alongside the canonical-datum pin in
        // `policy_output_matches_underwrite`.
        let partner_share_in_bounds =
          new_partner_share_bps >= 0 && new_partner_share_bps <= partner_share_cap_bps

        // 10. [v12 §3.8] Partner-address consistency: nonzero share REQUIRES
        // Some(addr). A None address with positive share is rejected; a
        // None address with zero share is the solo path (no partner output
        // required).
        let partner_consistency =
          when new_partner_address is {
            Some(_) -> True
            None -> new_partner_share_bps == 0
          }

        // 11. [v12 §3.8] Compute the (team_cut, partner_cut) split.
        let (team_cut, partner_cut) =
          calculate_protocol_fee_split(
            premium,
            datum.protocol_fee_bps,
            new_partner_share_bps,
          )

        // 12. [v12 / D7] Team output check. Required lovelace is
        // max(min_utxo, team_cut). When team_cut < min_utxo (premium < 100
        // ADA at the default fee), the submitter's wallet supplies the
        // floor pad — see the dedicated block-comment on
        // `floor_to_min_utxo` above.
        let team_required_lovelace = floor_to_min_utxo(team_cut)
        let team_output_funded =
          output_to_address_at_least(outputs, team_address, team_required_lovelace)

        // 13. [v12 §3.8 / D7] Partner output check. If partner_address is
        // Some(addr), an output at addr with lovelace >=
        // max(min_utxo, partner_cut) is required. If None,
        // `partner_consistency` above already enforces share == 0, so
        // partner_cut == 0 and there is nothing to route.
        let partner_required_lovelace = floor_to_min_utxo(partner_cut)
        let partner_output_funded =
          when new_partner_address is {
            Some(addr) ->
              output_to_address_at_least(
                outputs,
                addr,
                partner_required_lovelace,
              )
            None -> True
          }

        // 14. [FIX A-021] The Conway-era treasury_donation must be at least
        // the protocol-fee-derived cut. Sourced from the submitter's wallet
        // inputs (NOT from the premium that flows to the pool), so the
        // strict V12 value check on the pool continuation is unaffected.
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

        coverage_positive && premium_positive && premium_ok && can_cover && datum_ok && immutable_ok && value_ok && donation_ok && partner_share_in_bounds && partner_consistency && team_output_funded && partner_output_funded
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
      // [v12 §3.10] BATCH UNDERWRITE: Create N policies in a single tx.
      //
      // Per D10: in-scope for V12 (validator + backend; UI deferred). Each
      // policy in the batch carries its own (partner_address,
      // partner_share_bps) in its PolicyDatum. The validator aggregates the
      // per-policy floored team and partner cuts into per-address required
      // sums, then checks the tx outputs contain at least one output to
      // each required address with value >= that address's required sum.
      //
      // Per-policy floor invariant (D10/§3.10.2(1)): each policy's team and
      // partner cuts are floored to min_utxo INDIVIDUALLY before summing.
      // An aggregate-then-floor builder shape would skip ~2 ADA of pad on
      // batches of small premiums, which is a fee-bypass attack the
      // validator rejects (the per-policy floor is the canonical sum).
      //
      // Pool continuation invariant: pool grows by `total_net = total_premium
      // - team_total_unfloored - partner_totals_unfloored_sum` (UNFLOORED
      // percentage cuts only). The floor pads come from submitter wallet
      // inputs and are exogenous to pool accounting — same submitter-source
      // pattern as the Conway `treasury_donation` and the single Underwrite
      // floor pads.
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

        // 4. Verify immutable fields preserved
        // (lp_supply is immutable for Underwrite/ProcessClaim/BatchUnderwrite/BatchExpireProcess
        //  — only AddLiquidity / RemoveLiquidity move it.)
        let immutable_ok =
          new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft && new_datum.lp_supply == datum.lp_supply

        // 5. [v12 §3.10] Walk policy outputs ONCE, aggregating per-policy
        // team_cut and partner_cut totals (floored AND unfloored), the
        // canonical-pool/pool_nft binding, oracle pin, time range, and
        // partner_share_bps invariants.
        let own_pool_hash =
          when self_input.output.address.payment_credential is {
            Script(h) -> h
            _ -> #""
          }
        let batch_totals =
          batch_policies_match_totals_v12(
            outputs,
            own_pool_hash,
            datum.pool_nft,
            policy_script_hash,
            validity_range,
            total_coverage,
            total_premium,
            datum.protocol_fee_bps,
          )

        // 6. [v12 §3.10] Derive `total_net` from UNFLOORED per-policy sums.
        // The floored sums are used by the team/partner output gates only;
        // the pool's value invariant is the percentage-calculated cuts only
        // (floor pads come from submitter, not pool).
        let total_net =
          total_premium - batch_totals.team_total_unfloored - batch_totals.partner_totals_unfloored_sum

        // 7. Verify datum update with the per-policy net premium sum.
        let datum_ok =
          verify_underwrite_datum(
            datum.total_liquidity,
            datum.active_coverage,
            new_datum.total_liquidity,
            new_datum.active_coverage,
            total_net,
            total_coverage,
          )

        // 8. [v12 §3.10] Pool value equality — grow by `total_net`, NOT by
        // `total_premium`. The 2% premium-fee delta exits the pool to
        // team/partner outputs; floor pads come from the submitter and
        // never touch the pool value invariant.
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + total_net

        // 9. [v12 §3.10] Funded check from `batch_totals`: coverage and
        // premium sums match the redeemer; every policy output is at the
        // canonical policy script and carries >= its coverage in lovelace.
        let batch_policies_funded = batch_totals.funded_ok

        // 10. [v12 §3.10] Per-policy partner_share_bps invariants
        // (cap, consistency, non-negativity) folded into shares_ok by the
        // walker.
        let shares_ok = batch_totals.shares_ok

        // 11. [v12 §3.10] Team output check on the aggregated floored sum.
        // A single consolidated team output is the natural off-chain shape
        // (the off-chain builder always emits ONE team output per batch).
        // `list.any` with `>=` accepts the single-output shape; an N-split
        // team shape would not satisfy `list.any` here, but is structurally
        // unusual (waste of CBOR bytes).
        let team_output_funded =
          output_to_address_at_least(
            outputs,
            team_address,
            batch_totals.team_total_floored,
          )

        // 12. [v12 §3.10] Partner output check on each unique partner
        // address in the aggregator. For each entry `(addr, cut_sum)` in
        // `partner_totals_floored`, an output at addr with value >=
        // cut_sum must exist. Aggregated form (one output per unique
        // partner) is the natural builder shape.
        let partner_outputs_funded =
          list.all(
            batch_totals.partner_totals_floored,
            fn(entry) {
              output_to_address_at_least(outputs, entry.1st, entry.2nd)
            },
          )

        // 13. [FIX A-021 / v12] Aggregate treasury cut against total_premium
        // (unchanged numerically from V11; the cut already represents the
        // protocol fee * the treasury share, both in bps, multiplied
        // against the FULL premium).
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

        coverage_positive && premium_positive && premium_ok && can_cover && datum_ok && immutable_ok && value_ok && batch_policies_funded && shares_ok && team_output_funded && partner_outputs_funded && donation_ok
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

        // 5. [v12 §3.9] Compute the cancellation_fee retention and split it
        // by the SAME 2%/partner split as Underwrite — but applied to the
        // 10% retention, NOT the original premium (Choice B2). Rationale:
        // the 2% protocol fee on the original premium was already extracted
        // at Underwrite (and routed to team + partner there). Charging the
        // same 2%-of-PREMIUM cut again on cancel would double the team's
        // take from cancelled policies. B2 keeps the LP's exposure to
        // cancel matched against V11's expectation (10% retention minus
        // the per-event protocol fee) instead of changing the LP yield
        // curve on cancels.
        let cancellation_fee = policy_datum.premium_paid - refund_amount

        // 6. [v12 §3.9] Cap check on partner_share_bps from the policy
        // datum (set at Underwrite time, immutable for the policy's
        // lifetime). Cancel applies the SAME cap to the cancel-path split.
        let partner_share_in_bounds =
          policy_datum.partner_share_bps >= 0 && policy_datum.partner_share_bps <= partner_share_cap_bps

        // 7. [v12 §3.9] Partner-address consistency: nonzero share REQUIRES
        // Some(addr). Mirror of the Underwrite-branch invariant.
        let partner_consistency =
          when policy_datum.partner_address is {
            Some(_) -> True
            None -> policy_datum.partner_share_bps == 0
          }

        // 8. [v12 §3.9] Split the cancellation_fee using the canonical
        // helper. Uses the PoolDatum's protocol_fee_bps (same as Underwrite
        // — the cancel cut tracks the pool's current fee rate).
        let (team_cut, partner_cut) =
          calculate_protocol_fee_split(
            cancellation_fee,
            datum.protocol_fee_bps,
            policy_datum.partner_share_bps,
          )

        // 9. Sanity bounds (defensive — guarantees no underflow).
        let bounds_ok =
          refund_amount >= 0 && refund_amount <= datum.total_liquidity && policy_datum.coverage_amount <= datum.active_coverage

        // 10. [v12 §3.9] Pool's value decreases by refund_amount AND the
        // team/partner cuts extracted from the cancellation fee retention.
        // The refund goes to the insured (routed by `policy.Cancel`);
        // team_cut/partner_cut go to their respective outputs (below).
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) - refund_amount - team_cut - partner_cut

        // 11. [v12 §3.9] Datum: total_liquidity drops by refund + team_cut +
        // partner_cut (all three flow out of the pool). active_coverage
        // drops by the consumed policy's coverage_amount (de-reservation).
        // lp_supply unchanged.
        let datum_ok =
          new_datum.total_liquidity == datum.total_liquidity - refund_amount - team_cut - partner_cut && new_datum.active_coverage == datum.active_coverage - policy_datum.coverage_amount

        // 12. Immutable fields preserved (incl. lp_supply — LP supply does
        // NOT change on cancel; only Add/Remove Liquidity move it).
        let immutable_ok =
          new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft && new_datum.lp_supply == datum.lp_supply

        // 13. Solvency post-cancel.
        let remains_non_negative =
          new_datum.total_liquidity >= 0 && new_datum.active_coverage >= 0

        // 14. [v12 / D7] Team output check on the cancel-path cut. Required
        // lovelace is max(min_utxo, team_cut). For the typical 100-ADA
        // premium case team_cut is 0.2 ADA so required is the 2-ADA floor;
        // the canceller's wallet supplies the 1.8-ADA pad.
        let team_required_lovelace = floor_to_min_utxo(team_cut)
        let team_output_funded =
          output_to_address_at_least(outputs, team_address, team_required_lovelace)

        // 15. [v12 / D7] Partner output check on the cancel-path cut. Same
        // shape as Underwrite — conditional on the policy datum's
        // partner_address.
        let partner_required_lovelace = floor_to_min_utxo(partner_cut)
        let partner_output_funded =
          when policy_datum.partner_address is {
            Some(addr) ->
              output_to_address_at_least(
                outputs,
                addr,
                partner_required_lovelace,
              )
            None -> True
          }

        // 16. [FIX A-021 / v12 §3.9] Treasury cut on the cancellation fee.
        // Numerically equivalent to V11's `floor(premium_paid * 1_000 *
        // treasury_share_bps / 1e8)`, re-expressed against `cancellation_fee`
        // for clarity (since cancellation_fee == premium_paid * 1_000 /
        // 10_000). Derived from the consumed policy datum (NOT caller-
        // controlled), so a hostile builder cannot dodge the donation by
        // lying about premium.
        let required_donation =
          cancellation_fee * datum.protocol_fee_bps / 10_000 * treasury_share_bps / 10_000
        let donation_ok =
          when treasury_donation is {
            Some(amt) -> amt >= required_donation
            None -> required_donation == 0
          }

        policy_targets_this_pool && bounds_ok && value_ok && datum_ok && immutable_ok && remains_non_negative && donation_ok && partner_share_in_bounds && partner_consistency && team_output_funded && partner_output_funded
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
