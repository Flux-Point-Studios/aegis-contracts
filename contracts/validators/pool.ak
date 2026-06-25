use aegis/oracle.{is_canonical_oracle_nft}
use aegis/pool.{
  can_underwrite, can_withdraw, verify_add_liquidity_datum, verify_claim_datum,
  verify_remove_liquidity_datum, verify_underwrite_datum,
}
use aegis/pricing.{
  calculate_fee_total, calculate_protocol_fee, calculate_protocol_fee_split,
  calculate_refund, calculate_treasury_cut, is_premium_adequate, net_premium,
}
use aegis/types.{
  AcceptCancellation, AddLiquidity, AegisSelf, Barrier, BatchExpireProcess,
  BatchUnderwrite, BurnForCancel, BurnForClaim, BurnForExpire, MarkerRedeemer,
  MintMarkers, PolicyDatum, PoolDatum, PoolRedeemer, ProcessClaim,
  RemoveLiquidity, Underwrite, min_utxo_lovelace, partner_share_cap_bps,
  policy_marker_asset_name, team_address, treasury_share_bps,
}
use aegis/validation.{
  count_script_inputs, get_lower_bound, get_upper_bound, output_has_nft,
}
use cardano/address.{Address, VerificationKey}
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
use aiken/collection/pairs
use aiken/interval.{Finite, Interval, IntervalBound}
use cardano/address.{Script}
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, Mint, NoDatum, Output, OutputReference, Redeemer,
  ScriptPurpose, Transaction, ValidityRange,
}

// ---------------------------------------------------------------------------
// Helper: locate a freshly created policy output whose datum
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
// §3.7 BatchFeeTotals — aggregated walker output for BatchUnderwrite.
//
// The walker `batch_policies_match_totals_v12_2` (below) folds across the
// tx outputs and produces this record. V12.2 collapses V12's two-tier
// floored/unfloored tracking into a single canonical "actual lovelace
// routed" set of sums because the silent partner_cut absorb rule already
// encodes the contract — there's no separate "intended" tracking needed.
//
//   * `cov_sum` / `prem_sum`  — aggregate coverage and premium from policy
//                                outputs (must match redeemer totals).
//   * `funded_ok`             — every policy output's lovelace >= its
//                                coverage.
//   * `fee_total_sum`         — Σ fee_total_i (per-policy floored fee_totals).
//                                Drives the pool's value invariant:
//                                  cont == own + (total_premium - fee_total_sum).
//   * `team_total`            — Σ team_cut_i. By construction, equals
//                                fee_total_sum - partner_totals_sum.
//   * `partner_totals`        — `List<(Address, Int)>` of per-unique-
//                                partner aggregated cuts. Only entries
//                                with partner_cut_i > 0 contribute
//                                (silently-absorbed policies don't add to
//                                this list, even when partner_address is
//                                Some(_)).
//   * `partner_totals_sum`    — Σ over all entries in partner_totals
//                                (cached for the value-invariant check).
//   * `shares_ok`             — all policies pass partner_share_bps ∈
//                                [0, cap] AND the `Some(_) | share == 0
//                                when None` consistency check.
//
// V12 had 8 fields (added `team_total_unfloored` /
// `partner_totals_unfloored_sum` for the pool-value invariant separately
// from the floored sums for the output checks); V12.2 has 7 because the
// floor is inside fee_total and no separate unfloored tracking is needed.
// ---------------------------------------------------------------------------
type BatchFeeTotals {
  cov_sum: Int,
  prem_sum: Int,
  funded_ok: Bool,
  fee_total_sum: Int,
  team_total: Int,
  partner_totals: List<(Address, Int)>,
  partner_totals_sum: Int,
  shares_ok: Bool,
  aliases_ok: Bool,
  /// [V12.2+R12 / EXT-11] Per-policy validity check. Closes the
  /// aggregate-only walker gap where a negative-coverage "ballast"
  /// policy could let the aggregate ratio pass while individual
  /// policies are 100× under-reserved. For each policy walked, the
  /// walker AND-folds `coverage_amount > 0 && premium_paid > 0 &&
  /// is_premium_adequate(premium_paid, coverage_amount)` into this
  /// field. Required True by the final BatchUnderwrite conjunction.
  per_policy_terms_ok: Bool,
  /// [V12.2+R12 / EXT-09] Per-policy marker presence. Every new
  /// policy output at the policy validator address must hold exactly
  /// 1 marker (policy_marker_policy_id, "AEGIS_POLICY"). Required
  /// True by the final BatchUnderwrite conjunction. Pairs with the
  /// total mint of +N markers check.
  per_policy_marker_ok: Bool,
  /// [V12.2+R13 / EXT-13] Number of walker-ACCEPTED policies. A
  /// policy output is "accepted" iff it passes EVERY check the
  /// walker applies (pool binding, oracle pin, time-range, coverage
  /// positive, premium positive, premium adequacy, AND 1 marker on
  /// the output). Only accepted policies contribute to cov_sum /
  /// prem_sum / fee accumulators AND only accepted policies count
  /// toward the marker-mint pin (`marker_mint_ok == matched_policy_count`).
  /// Replaces the R12 BROAD scan `count_policy_outputs` which let
  /// walker-rejected policies still receive a real marker.
  matched_policy_count: Int,
  /// [V12.2+R13 / EXT-13] All-or-nothing flag on policy outputs at
  /// the policy validator address. True iff EVERY output at
  /// policy_script_hash decoded as PolicyDatum passes the walker's
  /// per-policy `valid_policy` check. ANY walker-rejected policy
  /// output collapses this to False — closes the laundering attack
  /// where the attacker mixes one accepted + one rejected policy
  /// into a batch and the rejected one gets a marker without
  /// contributing premium. Required True by the final BatchUnderwrite
  /// conjunction.
  all_policy_outputs_valid: Bool,
}

/// §3.10 Merge a per-policy partner cut into the running floored
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

/// §3.10 BatchUnderwrite walker. Iterates the tx outputs once and
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
  policy_marker_policy_id: ByteArray,
  validity_range: ValidityRange,
  total_coverage: Int,
  total_premium: Int,
  protocol_fee_bps: Int,
  team_address: Address,
  own_address: Address,
) -> BatchFeeTotals {
  let init =
    BatchFeeTotals {
      cov_sum: 0,
      prem_sum: 0,
      funded_ok: True,
      fee_total_sum: 0,
      team_total: 0,
      partner_totals: [],
      partner_totals_sum: 0,
      shares_ok: True,
      aliases_ok: True,
      per_policy_terms_ok: True,
      per_policy_marker_ok: True,
      matched_policy_count: 0,
      all_policy_outputs_valid: True,
    }
  let totals =
    list.foldl(
      outputs,
      init,
      fn(out, acc) {
        when out.address.payment_credential is {
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
                  // [V12.2+R13 / EXT-13] valid_policy is the conjunction
                  // of EVERY per-policy gate the walker can evaluate
                  // locally on this output. Walker-rejected policies
                  // (any gate False) MUST NOT contribute to
                  // cov_sum/prem_sum/fees AND MUST NOT count toward
                  // marker mint. The two new fields:
                  //   * matched_policy_count - tallies accepted only.
                  //   * all_policy_outputs_valid - collapses to False
                  //     on ANY rejected policy output (closes the
                  //     mixed-batch marker-laundering attack).
                  let funded =
                    assets.lovelace_of(out.value) == pdat.coverage_amount
                  let bps_in_bounds =
                    pdat.partner_share_bps >= 0 && pdat.partner_share_bps <= partner_share_cap_bps
                  let bps_consistency =
                    pdat.partner_address != None || pdat.partner_share_bps == 0
                  let this_shares_ok = bps_in_bounds && bps_consistency
                  let this_per_policy_terms_ok =
                    pdat.coverage_amount >= min_utxo_lovelace && pdat.premium_paid > 0 && is_premium_adequate(
                      pdat.premium_paid,
                      pdat.coverage_amount,
                    )
                  let marker_qty_on_output =
                    assets.quantity_of(
                      out.value,
                      policy_marker_policy_id,
                      policy_marker_asset_name,
                    )
                  let this_per_policy_marker_ok = marker_qty_on_output == 1
                  let this_alias_ok =
                    partner_address_not_aliased(
                      pdat.partner_address,
                      team_address,
                      own_address,
                      policy_script_hash,
                    )
                  // [V12.2+R13 / EXT-13] valid_policy: walker-accepted iff
                  // EVERY gate is True. Per auditor pseudo-code: pool
                  // binding + time + oracle + coverage > 0 + premium > 0 +
                  // premium-adequate + marker present + funded + shares_ok
                  // + alias_ok. (We add funded/shares/alias here even
                  // though earlier walker shape kept them as separate AND
                  // fields — folding them into valid_policy keeps the
                  // accepted set semantically clean and prevents a partial-
                  // accept from contributing to fee accumulators while
                  // flunking elsewhere.)
                  let valid_policy =
                    pdat.pool_script_hash == own_pool_hash && pdat.pool_nft == own_pool_nft && time_ok && oracle_pinned && pdat.coverage_amount > 0 && pdat.premium_paid > 0 && is_premium_adequate(
                      pdat.premium_paid,
                      pdat.coverage_amount,
                    ) && marker_qty_on_output == 1 && funded && this_shares_ok && this_alias_ok
                  if valid_policy {
                    // §3.7 Per-policy Hybrid fee math (only accumulated
                    // for walker-accepted policies).
                    let fee_total_i =
                      calculate_fee_total(
                        pdat.premium_paid,
                        protocol_fee_bps,
                        min_utxo_lovelace,
                      )
                    let (team_cut_i, partner_cut_i) =
                      calculate_protocol_fee_split(
                        fee_total_i,
                        pdat.partner_share_bps,
                        min_utxo_lovelace,
                      )
                    let new_partner_totals =
                      when pdat.partner_address is {
                        Some(addr) ->
                          if partner_cut_i > 0 {
                            accumulate_partner(
                              acc.partner_totals,
                              addr,
                              partner_cut_i,
                            )
                          } else {
                            acc.partner_totals
                          }
                        None -> acc.partner_totals
                      }
                    let new_partner_totals_sum =
                      acc.partner_totals_sum + partner_cut_i
                    BatchFeeTotals {
                      cov_sum: acc.cov_sum + pdat.coverage_amount,
                      prem_sum: acc.prem_sum + pdat.premium_paid,
                      funded_ok: acc.funded_ok && funded,
                      fee_total_sum: acc.fee_total_sum + fee_total_i,
                      team_total: acc.team_total + team_cut_i,
                      partner_totals: new_partner_totals,
                      partner_totals_sum: new_partner_totals_sum,
                      shares_ok: acc.shares_ok && this_shares_ok,
                      aliases_ok: acc.aliases_ok && this_alias_ok,
                      per_policy_terms_ok: acc.per_policy_terms_ok && this_per_policy_terms_ok,
                      per_policy_marker_ok: acc.per_policy_marker_ok && this_per_policy_marker_ok,
                      matched_policy_count: acc.matched_policy_count + 1,
                      all_policy_outputs_valid: acc.all_policy_outputs_valid,
                    }
                  } else {
                    // [V12.2+R13 / EXT-13] Walker-REJECTED policy output:
                    // do NOT bump cov_sum/prem_sum/fees/match_count, but
                    // collapse all_policy_outputs_valid to False. This is
                    // the load-bearing change: in R12 a rejected policy
                    // output was simply skipped, leaving the broad scan
                    // free to give it a marker. Here it's still skipped
                    // from accounting, but its existence is recorded so
                    // the BatchUnderwrite final conjunction can fail-
                    // close.
                    BatchFeeTotals {
                      ..acc,
                      all_policy_outputs_valid: False,
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
  // Aggregate totals must match the redeemer's claimed totals AND every
  // accepted policy output's lovelace must be >= its coverage (already
  // checked per-policy via `funded` inside `valid_policy`; redundancy
  // is intentional).
  BatchFeeTotals {
    ..totals,
    funded_ok: totals.funded_ok && totals.cov_sum == total_coverage && totals.prem_sum == total_premium,
  }
}

/// Verify the policy datum's start_time falls within the
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

/// §3.8 Locate the freshly-created policy output that matches the
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
  policy_marker_policy_id: ByteArray,
  validity_range: ValidityRange,
  coverage: Int,
  premium: Int,
) -> Option<(Option<Address>, Int)> {
  // Returns Some when exactly one output matches; partner fields are
  // captured from the matching policy datum for downstream output checks.
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
                  let marker_on_this_output =
                    assets.quantity_of(
                      out.value,
                      policy_marker_policy_id,
                      policy_marker_asset_name,
                    ) == 1
                  let predicate =
                    pdat.pool_script_hash == own_pool_hash && pdat.pool_nft == own_pool_nft && pdat.coverage_amount == coverage && pdat.premium_paid == premium && oracle_pinned && assets.lovelace_of(
                      out.value,
                    ) == coverage && start_time_in_tx_range(
                      pdat.start_time,
                      pdat.expiry_time,
                      validity_range,
                    ) && marker_on_this_output
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

/// §3.8 / D7] Predicate: does `outputs` contain at least one entry at
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

/// [FIX R8-DRAIN-1] Reject `partner_address` aliasing with privileged
/// addresses (team_address, pool address, policy_validator script
/// credential). Without this guard, a hostile builder can set
/// `partner_address = Some(team_address)` (or the pool's own address,
/// or any script credential the user controls indirectly) and the team
/// + partner output checks — two independent `list.any` calls over the
/// same outputs list — become satisfiable by a SINGLE on-chain output.
/// The team is short-changed by `partner_cut` per cycle, linear in
/// premium, hitting Underwrite, BatchUnderwrite, and AcceptCancellation
/// symmetrically.
fn partner_address_not_aliased(
  partner_address: Option<Address>,
  team_address: Address,
  pool_address: Address,
  policy_script_hash: ByteArray,
) -> Bool {
  when partner_address is {
    None -> True
    Some(addr) ->
      addr != team_address && addr != pool_address && addr.payment_credential != Script(
        policy_script_hash,
      )
  }
}

// Read the marker mint redeemer for `policy_marker_policy_id` from
// the tx's `redeemers` pair-list. Returns the parsed `MarkerRedeemer`
// or fails if absent / malformed.
fn marker_mint_redeemer(
  redeemers: Pairs<ScriptPurpose, Redeemer>,
  policy_marker_policy_id: ByteArray,
) -> MarkerRedeemer {
  expect Some(raw) = pairs.get_first(redeemers, Mint(policy_marker_policy_id))
  expect parsed: MarkerRedeemer = raw
  parsed
}

// Count tokens `(policy_marker_policy_id, "AEGIS_POLICY")` carried by
// `inputs`. Sum is over the consumed UTxO values, ignoring datum /
// address — every marker the validator must see on the input side
// MUST live at the policy validator address (other code paths
// enforce that), so this is the locality counter for the input side.
fn count_marker_tokens_in_inputs(
  inputs: List<Input>,
  policy_marker_policy_id: ByteArray,
) -> Int {
  list.foldl(
    inputs,
    0,
    fn(i, acc) {
      acc + assets.quantity_of(
        i.output.value,
        policy_marker_policy_id,
        policy_marker_asset_name,
      )
    },
  )
}

// Count tokens `(policy_marker_policy_id, "AEGIS_POLICY")` carried by
// `outputs`. Aggregate across every output regardless of address —
// EXT-18's locality invariant is that the count on each branch
// matches the table (no stray marker outputs anywhere).
fn count_marker_tokens_in_outputs(
  outputs: List<Output>,
  policy_marker_policy_id: ByteArray,
) -> Int {
  list.foldl(
    outputs,
    0,
    fn(o, acc) {
      acc + assets.quantity_of(
        o.value,
        policy_marker_policy_id,
        policy_marker_asset_name,
      )
    },
  )
}

// ---------------------------------------------------------------------------
// Pool Validator
// ---------------------------------------------------------------------------

/// Pool validator parameterized by the policy_validator's script hash
/// and the policy marker minting policy id.
///
/// `policy_script_hash` is consumed by `policy_output_matches_underwrite`
/// and `batch_policies_match_totals_v12` to require that newly-created
/// policy outputs land at the canonical policy_validator address.
///
/// `policy_marker_policy_id` (V12.2+R12 / EXT-08, EXT-09): every new
/// policy output must hold exactly 1 marker
/// (policy_marker_policy_id, "AEGIS_POLICY") at Underwrite /
/// BatchUnderwrite, and every consumed policy input must hold exactly 1
/// marker at ProcessClaim / AcceptCancellation / BatchExpireProcess.
/// The corresponding mint or burn quantity is also pinned per-branch
/// (+1 single, +N batch; -1 single, -N batch). Synthetic-policy attacks
/// (write a UTxO at the policy address with a fake datum) cannot mint a
/// marker because mint authority is delegated to the pool validator
/// itself via the marker policy's pool-consumed gate.
///
/// Off-chain deployers MUST apply this parameter (`aiken blueprint
/// apply`) using the deployed policy_validator hash AND the deployed
/// policy_marker minting policy id before publishing the pool reference
/// script.
validator pool_validator(
  policy_script_hash: ByteArray,
  policy_marker_policy_id: ByteArray,
) {
  spend(
    datum_opt: Option<PoolDatum>,
    redeemer: PoolRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    // Datum must be present
    expect Some(datum) = datum_opt

    // Bind `treasury_donation` so the three fee-bearing branches
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
      redeemers,
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
      // §3.8 UNDERWRITE: Reserve coverage for a new policy, collect
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

        // Reject non-positive coverage. Aiken's integer
        // division floors toward negative infinity, so the prior
        // `is_ratio_acceptable` check (`coverage / premium <= 50`)
        // accepted negative coverage (e.g. `-5 / 2_000_000 = -1 <= 50`).
        // `verify_underwrite_datum` then reduced `active_coverage` by
        // |coverage|, inflating apparent pool capacity and corrupting
        // accounting. Live exploit:
        // 01a1067cd496a31f069e0355717fe2ab1c4ebd5b2e0eb8ba1632a179cf04459a
        let coverage_positive = coverage > 0
        let premium_positive = premium > 0

        // Reject coverage below min_utxo so exact-funding (== coverage)
        // outputs still satisfy the min-utxo ledger rule.
        let coverage_min_utxo = coverage >= min_utxo_lovelace

        // 2. Verify premium adequacy
        let premium_ok = is_premium_adequate(premium, coverage)

        // 3. Verify pool can underwrite this coverage
        let can_cover =
          can_underwrite(datum.total_liquidity, datum.active_coverage, coverage)

        // 4. §3.5 Compute fee_total with floor INSIDE the carve.
        // Pool grows by `net_pool_growth = premium - fee_total`; the
        // fee_total leaves the pool to team/partner outputs.
        let fee_total =
          calculate_fee_total(premium, datum.protocol_fee_bps, min_utxo_lovelace)
        let net_pool_growth = premium - fee_total

        // 5. Verify datum update is correct. The new datum's total_liquidity
        // grows by net_pool_growth (NOT premium, NOT V12's net_premium).
        let datum_ok =
          verify_underwrite_datum(
            datum.total_liquidity,
            datum.active_coverage,
            new_datum.total_liquidity,
            new_datum.active_coverage,
            net_pool_growth,
            coverage,
          )

        // 6. Verify immutable fields are preserved (incl. lp_supply, which
        // does NOT change on Underwrite — only on Add/Remove Liquidity).
        let immutable_ok =
          new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft && new_datum.lp_supply == datum.lp_supply

        // 7. §3.5 Pool value grows by `net_pool_growth`, NOT by
        // the full premium and NOT by V12's `net_premium`. The fee_total
        // leaves the pool to team/partner outputs; the floor is inside
        // fee_total so the pool gives back a slight discount on small
        // premiums (LP absorbs the floor cost in exchange for a clean
        // user-facing fee curve — V12.2 spec §10.1).
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + net_pool_growth

        // 8. An Underwrite tx MUST create exactly one
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
            policy_marker_policy_id,
            validity_range,
            coverage,
            premium,
          )

        let marker_mint_ok =
          assets.quantity_of(
            mint,
            policy_marker_policy_id,
            policy_marker_asset_name,
          ) == 1

        // EXT-16 sibling-redeemer pairing: the marker mint redeemer
        // MUST be `MintMarkers { count: 1 }` on Underwrite.
        let marker_redeemer_ok =
          when marker_mint_redeemer(redeemers, policy_marker_policy_id) is {
            MintMarkers { count } -> count == 1
            _ -> False
          }

        // EXT-18 marker locality: 0 marker inputs, exactly 1 marker
        // output anywhere in the tx (the matched policy output).
        let marker_inputs =
          count_marker_tokens_in_inputs(inputs, policy_marker_policy_id)
        let marker_outputs =
          count_marker_tokens_in_outputs(outputs, policy_marker_policy_id)
        let marker_locality_ok = marker_inputs == 0 && marker_outputs == 1

        // 9. §3.8 Cap check on partner_share_bps. Defense-in-depth
        // alongside the canonical-datum pin in
        // `policy_output_matches_underwrite`.
        let partner_share_in_bounds =
          new_partner_share_bps >= 0 && new_partner_share_bps <= partner_share_cap_bps

        // 10. §3.8 Partner-address consistency: nonzero share REQUIRES
        // Some(addr). A None address with positive share is rejected; a
        // None address with zero share is the solo path (no partner output
        // required).
        let partner_consistency =
          new_partner_address != None || new_partner_share_bps == 0

        // 11. §3.5 Compute the (team_cut, partner_cut) split with
        // silent partner_cut absorb. team_cut absorbs sub-floor partner_cut.
        let (team_cut, partner_cut) =
          calculate_protocol_fee_split(
            fee_total,
            new_partner_share_bps,
            min_utxo_lovelace,
          )

        // 12. §3.5 Team output check. Threshold IS `team_cut`
        // (no floor_to_min_utxo wrapper). team_cut >= min_utxo_lovelace
        // is guaranteed by the silent-absorb invariant (V12.2 spec
        // §8.1.4): either partner_cut == 0 → team == fee_total >=
        // min_utxo, or partner_cut > 0 → fee_total >= 5 × min_utxo (cap
        // forces) → team >= 4 × min_utxo. Either way team >= min_utxo.
        let team_output_funded =
          output_to_address_at_least(outputs, team_address, team_cut)

        // 13. §3.5 Partner output check with silent absorb. When
        // partner_cut == 0 (sub-floor → absorbed by team), the partner
        // output is OMITTED entirely — even if partner_address is
        // Some(_), no on-chain output to partner_address is required.
        // PolicyDatum still records the partner attribution for off-chain
        // analytics (V12.2 spec §10.3 silent-absorb security analysis).
        let partner_output_funded =
          when new_partner_address is {
            Some(addr) ->
              if partner_cut > 0 {
                output_to_address_at_least(outputs, addr, partner_cut)
              } else {
                // Silent absorb path: no partner output required.
                True
              }
            None -> True
          }

        // 14. The Conway-era treasury_donation must be at least
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

        // [FIX R8-DRAIN-1] Underwrite arm: reject partner_address aliasing
        // with team_address / pool address / policy script. See the
        // helper `partner_address_not_aliased` doc for severity rationale.
        let partner_not_aliased =
          partner_address_not_aliased(
            new_partner_address,
            team_address,
            own_address,
            policy_script_hash,
          )

        let no_policy_inputs =
          count_script_inputs(inputs, policy_script_hash) == 0

        // [NN-A-3] aLP-mint authorization. lp_token_policy authorizes minting
        // "aLP" on ANY pool spend (it only checks `pool_is_consumed`), so an
        // Underwrite tx could co-mint aLP to a wallet with no ADA deposit and
        // no lp_supply increment — later burned via RemoveLiquidity to drain
        // the pool. Underwrite must NEITHER mint nor burn aLP; aLP can only
        // net-change via Add/Remove, which carry the full LP accounting.
        // Symmetric with the marker_qty_zero pin above.
        let lp_mint_qty = assets.quantity_of(mint, datum.lp_token_policy, "aLP")
        let no_lp_mint = lp_mint_qty == 0

        coverage_positive && premium_positive && coverage_min_utxo && premium_ok && can_cover && datum_ok && immutable_ok && value_ok && donation_ok && partner_share_in_bounds && partner_consistency && partner_not_aliased && team_output_funded && partner_output_funded && marker_mint_ok && marker_redeemer_ok && marker_locality_ok && no_lp_mint && no_policy_inputs
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

        // Find the consumed policy UTxO and read its datum.
        // Verify (a) the policy targets THIS pool, (b) its coverage matches
        // the requested payout. Without these checks, anyone can submit ANY
        // policy UTxO (including a self-constructed synthetic policy) and
        // request an arbitrarily large payout.
        //
        // Resolve the policy script credential via
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
        // Policy must point at THIS pool AND payout must
        // equal the policy's declared coverage. Both bindings prevent the
        // single-tx pool drain attack described in A-001.
        let policy_targets_this_pool =
          policy_datum.pool_script_hash == own_pool_hash && policy_datum.pool_nft == datum.pool_nft
        let payout_matches_coverage = payout == policy_datum.coverage_amount
        let policy_consumed =
          policy_targets_this_pool && payout_matches_coverage

        // [V12.2+R12 / EXT-09] The consumed policy input must hold
        // exactly 1 marker (policy_marker_policy_id, "AEGIS_POLICY")
        // AND the tx mint must burn exactly -1 marker. Closes the
        // synthetic-Claim accounting-corruption attack: a fake policy
        // UTxO with attacker-crafted PolicyDatum cannot acquire a
        // marker (marker mint is gated on a pool spend authorising
        // Underwrite), so any Claim that consumes a non-marker UTxO is
        // rejected at this gate.
        let policy_has_marker =
          assets.quantity_of(
            policy_input.output.value,
            policy_marker_policy_id,
            policy_marker_asset_name,
          ) == 1
        let marker_burn_ok =
          assets.quantity_of(
            mint,
            policy_marker_policy_id,
            policy_marker_asset_name,
          ) == -1

        // EXT-16 sibling-redeemer pairing: marker mint redeemer must
        // be BurnForClaim on ProcessClaim.
        let marker_redeemer_ok =
          when marker_mint_redeemer(redeemers, policy_marker_policy_id) is {
            BurnForClaim -> True
            _ -> False
          }

        // EXT-18 marker locality: exactly 1 marker on the input side
        // (the consumed policy) and 0 markers on the output side.
        let marker_inputs =
          count_marker_tokens_in_inputs(inputs, policy_marker_policy_id)
        let marker_outputs =
          count_marker_tokens_in_outputs(outputs, policy_marker_policy_id)
        let marker_locality_ok = marker_inputs == 1 && marker_outputs == 0

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

        // 5. Pool value conservation. The consumed policy UTxO's full
        // lovelace must land in the continuation, minus the payout to the
        // insured. Equation:
        //   cont == own + policy_lovelace - payout
        // Total in: own + policy_lovelace. Total out: cont + payout.
        // Change (= total_in - total_out) must be 0 — no leak path to
        // collateral residual.
        let policy_lovelace = assets.lovelace_of(policy_input.output.value)
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + policy_lovelace - payout

        // Solvency is now enforced inside verify_claim_datum
        // (which requires payout ≤ old_active and new_active ≥ 0). The previous
        // `new_total >= new_active` check was tautological because both fields
        // decrement by the same payout.
        let remains_non_negative =
          new_datum.total_liquidity >= 0 && new_datum.active_coverage >= 0

        let exactly_one_policy_input =
          count_script_inputs(inputs, policy_script_hash) == 1

        // [NN-A-3] aLP-mint authorization. ProcessClaim must NEITHER mint nor
        // burn aLP — lp_token_policy would otherwise authorize a co-minted
        // aLP on this pool spend with no lp_supply change. See the Underwrite
        // arm for the full rationale.
        let lp_mint_qty = assets.quantity_of(mint, datum.lp_token_policy, "aLP")
        let no_lp_mint = lp_mint_qty == 0

        payout_positive && policy_consumed && datum_ok && immutable_ok && value_ok && remains_non_negative && policy_has_marker && marker_burn_ok && marker_redeemer_ok && marker_locality_ok && no_lp_mint && exactly_one_policy_input
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

        // 3. Verify datum update including lp_supply.
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

        // 5. Pool value must EQUAL old + amount exactly.
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + amount

        // 6. LP mint quantity must EXACTLY MATCH the lp_supply
        // delta in the new datum. This binds direction + magnitude in one
        // check: an attacker cannot mint with a Burn redeemer (covered by
        // verify_add_liquidity_datum requiring positive delta), nor mint
        // a different magnitude than the calculation prescribes.
        let mint_qty = assets.quantity_of(mint, datum.lp_token_policy, "aLP")
        let lp_supply_delta = new_datum.lp_supply - datum.lp_supply
        let lp_minted = mint_qty == lp_supply_delta && mint_qty > 0

        // [V12.2+R13 / EXT-12] Per-branch marker_qty pin. The marker
        // minting policy authorises any tx that consumes the canonical
        // pool NFT — so without a per-branch pin, AddLiquidity could co-
        // mint +N markers, park them on a fake policy-validator UTxO,
        // and the attacker would later use that marker-bearing fake
        // policy in a Cancel/Claim to drain the pool. AddLiquidity has
        // no legitimate reason to mint markers; pin to 0.
        let marker_qty =
          assets.quantity_of(
            mint,
            policy_marker_policy_id,
            policy_marker_asset_name,
          )
        let marker_qty_zero = marker_qty == 0

        // EXT-18 marker locality: AddLiquidity has 0 marker inputs and
        // 0 marker outputs — no marker flows through the pool on LP
        // deposit.
        let marker_inputs =
          count_marker_tokens_in_inputs(inputs, policy_marker_policy_id)
        let marker_outputs =
          count_marker_tokens_in_outputs(outputs, policy_marker_policy_id)
        let marker_locality_ok = marker_inputs == 0 && marker_outputs == 0

        // [NN-A-3] LP-token locality. Symmetric with the marker-locality
        // pattern above. The branch verifies the LP MINT quantity (==
        // lp_supply delta) and the ADA value, but without this check it
        // never constrains WHERE the freshly-minted aLP tokens go. A
        // red-team tx deposited ADA but routed the minted aLP INTO the
        // pool's own continuation output, and the validator accepted it —
        // creating an orphaned in-pool LP claim that anyone could later
        // burn-from-pool to withdraw ADA they never deposited. Pin the
        // pool continuation to ZERO aLP: the pool UTxO holds only ADA +
        // the pool NFT, never aLP. Minted LP must land on a wallet output.
        let pool_out_aLP_qty =
          assets.quantity_of(cont_output.value, datum.lp_token_policy, "aLP")
        let pool_out_no_lp = pool_out_aLP_qty == 0

        let no_policy_inputs =
          count_script_inputs(inputs, policy_script_hash) == 0

        amount_positive && datum_ok && immutable_ok && value_ok && lp_minted && marker_qty_zero && marker_locality_ok && pool_out_no_lp && no_policy_inputs
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

        // 4. LP burn quantity is taken from the mint and must
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

        // 7. Pool value must DECREASE by exactly `amount`.
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) - amount

        // 8. Sanity: mint must be strictly negative (burn).
        let direction_ok = mint_qty < 0

        // [V12.2+R13 / EXT-12] Per-branch marker_qty pin. Symmetric with
        // AddLiquidity. RemoveLiquidity has no legitimate reason to mint
        // OR burn markers — only Underwrite / BatchUnderwrite mint,
        // only ProcessClaim / AcceptCancellation / BatchExpireProcess
        // burn. Pin to 0.
        let marker_qty =
          assets.quantity_of(
            mint,
            policy_marker_policy_id,
            policy_marker_asset_name,
          )
        let marker_qty_zero = marker_qty == 0

        // EXT-18 marker locality: 0 marker inputs, 0 marker outputs.
        let marker_inputs =
          count_marker_tokens_in_inputs(inputs, policy_marker_policy_id)
        let marker_outputs =
          count_marker_tokens_in_outputs(outputs, policy_marker_policy_id)
        let marker_locality_ok = marker_inputs == 0 && marker_outputs == 0

        // [NN-A-3] LP-token locality. Symmetric with AddLiquidity and the
        // marker-locality pattern. The withdrawal burns aLP (mint_qty < 0)
        // and shrinks the pool by `amount`, but nothing forbids leaving aLP
        // sitting in the pool continuation. Pinning the continuation to
        // ZERO aLP guarantees burned LP cannot be parked back in the pool
        // and that no orphaned in-pool LP can survive a RemoveLiquidity —
        // the pool UTxO holds only ADA + the pool NFT, never aLP.
        let pool_out_aLP_qty =
          assets.quantity_of(cont_output.value, datum.lp_token_policy, "aLP")
        let pool_out_no_lp = pool_out_aLP_qty == 0

        let no_policy_inputs =
          count_script_inputs(inputs, policy_script_hash) == 0

        amount_positive && withdrawal_safe && datum_ok && immutable_ok && value_ok && direction_ok && marker_qty_zero && marker_locality_ok && pool_out_no_lp && no_policy_inputs
      }

      // -----------------------------------------------------------------------
      // §3.10 BATCH UNDERWRITE: Create N policies in a single tx.
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

        // Same positivity guard as Underwrite. Without this,
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

        // 5. §3.7 Walk policy outputs ONCE, aggregating per-policy
        // fee_total_i (= max(min_utxo, premium_i × fee_bps / 10_000)) and
        // (team_cut_i, partner_cut_i) with silent absorb. Single
        // canonical sum set — no V12 floored/unfloored distinction.
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
            policy_marker_policy_id,
            validity_range,
            total_coverage,
            total_premium,
            datum.protocol_fee_bps,
            team_address,
            own_address,
          )

        // [V12.2+R13 / EXT-13] Mint quantity for the marker policy must
        // equal `batch_totals.matched_policy_count` — the count of
        // WALKER-ACCEPTED policies (NOT a broad output scan as in R12).
        // The R12 broad scan let an attacker mix one walker-accepted
        // policy with one walker-rejected policy (e.g. `time_ok = False`)
        // — broad count = 2 → mint = +2, rejected policy got a real
        // marker without contributing premium, then was used in a
        // synthetic Cancel later. This pin closes that laundering path.
        // Per-policy marker presence on each accepted output is still
        // checked inside the walker (`per_policy_marker_ok`).
        let marker_qty =
          assets.quantity_of(
            mint,
            policy_marker_policy_id,
            policy_marker_asset_name,
          )
        let marker_mint_ok = marker_qty == batch_totals.matched_policy_count

        // EXT-16 sibling-redeemer pairing: marker mint redeemer must
        // be MintMarkers { count == matched_policy_count }.
        let marker_redeemer_ok =
          when marker_mint_redeemer(redeemers, policy_marker_policy_id) is {
            MintMarkers { count } ->
              count == batch_totals.matched_policy_count
            _ -> False
          }

        // EXT-18 marker locality: 0 marker inputs, exactly
        // matched_policy_count marker outputs (one per accepted
        // policy output). The "marker on the matched policy output"
        // is enforced by the walker (per_policy_marker_ok); the
        // aggregate output count caps stray marker leakage.
        let marker_inputs =
          count_marker_tokens_in_inputs(inputs, policy_marker_policy_id)
        let marker_outputs =
          count_marker_tokens_in_outputs(outputs, policy_marker_policy_id)
        let marker_locality_ok =
          marker_inputs == 0 && marker_outputs == batch_totals.matched_policy_count

        // 6. §3.7 Aggregate net pool growth = total_premium −
        // Σ fee_total_i. team_total + partner_totals_sum == fee_total_sum
        // by construction (split helper contract).
        let net_pool_growth = total_premium - batch_totals.fee_total_sum

        // 7. Verify datum update with the per-policy net pool growth.
        let datum_ok =
          verify_underwrite_datum(
            datum.total_liquidity,
            datum.active_coverage,
            new_datum.total_liquidity,
            new_datum.active_coverage,
            net_pool_growth,
            total_coverage,
          )

        // 8. §3.7 Pool value equality — grow by net_pool_growth.
        // The fee_total leaves the pool to team/partner outputs; the floor
        // is inside fee_total so the pool gives back a slight discount on
        // small premiums (LP absorbs the floor cost, V12.2 spec §10.1).
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + net_pool_growth

        // 9. §3.7 Funded check from `batch_totals`: coverage and
        // premium sums match the redeemer; every policy output is at the
        // canonical policy script and carries >= its coverage in lovelace.
        let batch_policies_funded = batch_totals.funded_ok

        // 10. §3.7 Per-policy partner_share_bps invariants folded
        // into shares_ok by the walker.
        let shares_ok = batch_totals.shares_ok

        // 11. §3.7 Team output check on the aggregated sum. Threshold
        // is `team_total` exactly (no floor wrapper) — team_total is the
        // sum of per-policy team_cut_i (which includes silently-absorbed
        // partner cuts).
        let team_output_funded =
          output_to_address_at_least(
            outputs,
            team_address,
            batch_totals.team_total,
          )

        // 12. §3.7 Partner output check on each unique partner
        // address. `partner_totals` only contains entries for policies
        // whose `partner_cut_i > 0` (silently-absorbed policies don't
        // contribute). Each entry has cut_sum >= min_utxo by construction
        // (since each per-policy partner_cut_i ∈ {0, ≥ min_utxo}).
        let partner_outputs_funded =
          list.all(
            batch_totals.partner_totals,
            fn(entry) {
              output_to_address_at_least(outputs, entry.1st, entry.2nd)
            },
          )

        // BatchUnderwrite alias guard. Sourced from the per-policy walker
        // (covers silent-absorb policies whose partner_cut_i == 0 and
        // therefore never enter partner_totals).
        let partner_addresses_not_aliased = batch_totals.aliases_ok

        // 13. Aggregate treasury cut against total_premium
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

        let no_policy_inputs =
          count_script_inputs(inputs, policy_script_hash) == 0

        // [NN-A-3] aLP-mint authorization. BatchUnderwrite must NEITHER mint
        // nor burn aLP — lp_token_policy would otherwise authorize a co-minted
        // aLP on this pool spend with no lp_supply change. See the Underwrite
        // arm for the full rationale.
        let lp_mint_qty = assets.quantity_of(mint, datum.lp_token_policy, "aLP")
        let no_lp_mint = lp_mint_qty == 0

        coverage_positive && premium_positive && premium_ok && can_cover && datum_ok && immutable_ok && value_ok && batch_policies_funded && shares_ok && partner_addresses_not_aliased && team_output_funded && partner_outputs_funded && donation_ok && batch_totals.per_policy_terms_ok && batch_totals.per_policy_marker_ok && marker_mint_ok && marker_redeemer_ok && marker_locality_ok && batch_totals.all_policy_outputs_valid && no_lp_mint && no_policy_inputs
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

        // 3. Verify the consumed policies (a) come from the
        // canonical policy_validator (parameterized hash), (b) bind to
        // THIS pool, and (c) their lovelace sum equals total_returned.
        //
        // The policy script credential is now sourced
        // from the validator's `policy_script_hash` parameter, not a
        // redeemer-supplied field. Pre-fix, an attacker could substitute
        // their own permissive script.
        let own_pool_hash =
          when self_input.output.address.payment_credential is {
            Script(h) -> h
            _ -> #""
          }
        let policies_consumed_total =
          count_script_inputs(inputs, policy_script_hash)
        let policies_consumed = policies_consumed_total >= 1
        let consumed_policies_match =
          consumed_policies_total_to(
            inputs,
            policy_script_hash,
            own_pool_hash,
            datum.pool_nft,
            total_returned,
          )

        // [V12.2+R12 / EXT-09] Every consumed policy input at the
        // policy validator address whose datum binds to THIS pool must
        // hold exactly 1 marker; the mint quantity for the marker
        // policy must equal -N where N is the number of such policies.
        let consumed_policy_count_with_marker =
          list.foldl(
            inputs,
            (0, True),
            fn(input, acc) {
              let (count_acc, all_have_marker) = acc
              when input.output.address.payment_credential is {
                Script(h) ->
                  if h == policy_script_hash {
                    when input.output.datum is {
                      InlineDatum(raw_pdat) -> {
                        expect pdat: PolicyDatum = raw_pdat
                        if pdat.pool_script_hash == own_pool_hash && pdat.pool_nft == datum.pool_nft {
                          let has_marker =
                            assets.quantity_of(
                              input.output.value,
                              policy_marker_policy_id,
                              policy_marker_asset_name,
                            ) == 1
                          (count_acc + 1, all_have_marker && has_marker)
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
        let (consumed_n, all_markers_present) =
          consumed_policy_count_with_marker
        let marker_burn_ok =
          all_markers_present && assets.quantity_of(
            mint,
            policy_marker_policy_id,
            policy_marker_asset_name,
          ) == -consumed_n

        // EXT-16 sibling-redeemer pairing: marker mint redeemer must
        // be BurnForExpire { count == consumed_n }.
        let marker_redeemer_ok =
          when marker_mint_redeemer(redeemers, policy_marker_policy_id) is {
            BurnForExpire { count } -> count == consumed_n
            _ -> False
          }

        // EXT-18 marker locality: exactly consumed_n marker inputs
        // (one per consumed policy), 0 marker outputs.
        let marker_inputs_total =
          count_marker_tokens_in_inputs(inputs, policy_marker_policy_id)
        let marker_outputs_total =
          count_marker_tokens_in_outputs(outputs, policy_marker_policy_id)
        let marker_locality_ok =
          marker_inputs_total == consumed_n && marker_outputs_total == 0

        // 4. Verify datum: active_coverage decremented by total_returned,
        //    total_liquidity stays the same (expired policy funds were
        //    already counted in total_liquidity when underwritten)
        let datum_ok =
          new_datum.total_liquidity == datum.total_liquidity && new_datum.active_coverage == datum.active_coverage - total_returned

        // 5. Verify immutable fields preserved
        let immutable_ok =
          new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft && new_datum.lp_supply == datum.lp_supply

        // 6. Pool value must EQUAL old + total_returned exactly.
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + total_returned

        // 7. Non-negativity (the old new_total >= new_active check
        // was tautological because both fields decrement equally).
        let remains_non_negative =
          new_datum.total_liquidity >= 0 && new_datum.active_coverage >= 0 && total_returned <= datum.active_coverage

        let all_policy_inputs_accounted = policies_consumed_total == consumed_n

        // [NN-A-3] aLP-mint authorization. BatchExpireProcess must NEITHER
        // mint nor burn aLP — lp_token_policy would otherwise authorize a
        // co-minted aLP on this pool spend with no lp_supply change. See the
        // Underwrite arm for the full rationale.
        let lp_mint_qty = assets.quantity_of(mint, datum.lp_token_policy, "aLP")
        let no_lp_mint = lp_mint_qty == 0

        returned_positive && policies_consumed && consumed_policies_match && datum_ok && immutable_ok && value_ok && remains_non_negative && marker_burn_ok && marker_redeemer_ok && marker_locality_ok && no_lp_mint && all_policy_inputs_accounted
      }

      // -----------------------------------------------------------------------
      // ACCEPT CANCELLATION: Settle a Cancel-redeemed policy.
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
        // Resolve the policy script credential via
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

        // [V12.2+R12 / EXT-10] Reject multi-input Cancel. Without this
        // guard, an attacker can pair a legitimate policy input with a
        // synthetic-datum policy input and the pool only accounts for
        // the first one, while the policy-side Cancel arm runs once per
        // input. Single-input policy spend symmetric with Claim.
        let single_policy_input =
          count_script_inputs(inputs, policy_script_hash) == 1

        // [V12.2+R12 / EXT-08] Marker presence + burn check. The
        // consumed policy input must hold exactly 1 marker
        // (policy_marker_policy_id, "AEGIS_POLICY") and the tx mint
        // must contain exactly -1 of that token. Closes the synthetic
        // Cancel direct pool drain: an attacker writes a fake policy
        // UTxO at the policy validator address with a fake datum
        // (premium_paid=1000 ADA), funds it with 2 ADA, calls Cancel
        // → pool refunds 900 ADA. The marker is only mintable via a
        // real Aegis Underwrite that co-spent the pool; a synthetic
        // UTxO cannot acquire one.
        let policy_has_marker =
          assets.quantity_of(
            policy_input.output.value,
            policy_marker_policy_id,
            policy_marker_asset_name,
          ) == 1
        let marker_burn_ok =
          assets.quantity_of(
            mint,
            policy_marker_policy_id,
            policy_marker_asset_name,
          ) == -1

        // EXT-16 sibling-redeemer pairing: marker mint redeemer must
        // be BurnForCancel on AcceptCancellation.
        let marker_redeemer_ok =
          when marker_mint_redeemer(redeemers, policy_marker_policy_id) is {
            BurnForCancel -> True
            _ -> False
          }

        // EXT-18 marker locality: exactly 1 marker input (the
        // cancelled policy), 0 marker outputs.
        let marker_inputs =
          count_marker_tokens_in_inputs(inputs, policy_marker_policy_id)
        let marker_outputs =
          count_marker_tokens_in_outputs(outputs, policy_marker_policy_id)
        let marker_locality_ok = marker_inputs == 1 && marker_outputs == 0

        // 4. Compute the canonical refund (derived; not caller-controlled).
        let refund_amount = calculate_refund(policy_datum.premium_paid)

        // 5. §3.9 Compute the cancellation_fee retention and split it
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

        // 6. §3.9 Cap check on partner_share_bps from the policy
        // datum (set at Underwrite time, immutable for the policy's
        // lifetime). Cancel applies the SAME cap to the cancel-path split.
        let partner_share_in_bounds =
          policy_datum.partner_share_bps >= 0 && policy_datum.partner_share_bps <= partner_share_cap_bps

        // 7. §3.9 Partner-address consistency: nonzero share REQUIRES
        // Some(addr). Mirror of the Underwrite-branch invariant.
        let partner_consistency =
          policy_datum.partner_address != None || policy_datum.partner_share_bps == 0

        // 8. §3.6 Apply Hybrid fee math to the cancellation_fee
        // retention. fee_total floors to min_utxo INSIDE the carve, so
        // the pool's value drops by exactly `fee_total_cancel` (not
        // raw_fee + exogenous pad).
        let fee_total_cancel =
          calculate_fee_total(
            cancellation_fee,
            datum.protocol_fee_bps,
            min_utxo_lovelace,
          )
        let (team_cut, partner_cut) =
          calculate_protocol_fee_split(
            fee_total_cancel,
            policy_datum.partner_share_bps,
            min_utxo_lovelace,
          )

        // 9. Sanity bounds (defensive — guarantees no underflow).
        let bounds_ok =
          refund_amount >= 0 && refund_amount <= datum.total_liquidity && policy_datum.coverage_amount <= datum.active_coverage

        // 10. §3.6 Pool's value decreases by refund_amount AND
        // fee_total_cancel. team_cut + partner_cut sum exactly to
        // fee_total_cancel by helper contract; tracking fee_total here
        // makes the value invariant easier to audit.
        let value_ok =
          assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) - refund_amount - fee_total_cancel

        // 11. §3.6 Datum: total_liquidity drops by refund +
        // fee_total_cancel (sum of team_cut + partner_cut by construction).
        // active_coverage drops by the consumed policy's coverage_amount.
        // lp_supply unchanged.
        let datum_ok =
          new_datum.total_liquidity == datum.total_liquidity - refund_amount - fee_total_cancel && new_datum.active_coverage == datum.active_coverage - policy_datum.coverage_amount

        // 12. Immutable fields preserved (incl. lp_supply — LP supply does
        // NOT change on cancel; only Add/Remove Liquidity move it).
        let immutable_ok =
          new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft && new_datum.lp_supply == datum.lp_supply

        // 13. Solvency post-cancel.
        let remains_non_negative =
          new_datum.total_liquidity >= 0 && new_datum.active_coverage >= 0

        // 14. §3.6 Team output check. Threshold = team_cut
        // exactly (no floor_to_min_utxo wrapper). team_cut >=
        // min_utxo_lovelace by the silent-absorb invariant.
        let team_output_funded =
          output_to_address_at_least(outputs, team_address, team_cut)

        // 15. §3.6 Partner output check with silent absorb on
        // cancel. When partner_cut == 0 (sub-floor → absorbed), the
        // partner output is OMITTED entirely even if partner_address is
        // Some(_). PolicyDatum still records the partner attribution for
        // off-chain analytics.
        let partner_output_funded =
          when policy_datum.partner_address is {
            Some(addr) ->
              if partner_cut > 0 {
                output_to_address_at_least(outputs, addr, partner_cut)
              } else {
                // Silent absorb path: no partner output required.
                True
              }
            None -> True
          }

        // 16. §3.9 Treasury cut on the cancellation fee.
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

        // [FIX R8-DRAIN-1] AcceptCancellation arm: reject if the
        // consumed policy_datum.partner_address aliases team_address /
        // pool / policy_validator. Defense-in-depth: a V12.2+ Underwrite
        // would have already rejected such a policy at creation time,
        // but old V11 policies on chain weren't validated against this
        // primitive and may carry hostile partner_addresses.
        let partner_not_aliased =
          partner_address_not_aliased(
            policy_datum.partner_address,
            team_address,
            own_address,
            policy_script_hash,
          )

        // [NN-A-3] aLP-mint authorization. AcceptCancellation must NEITHER
        // mint nor burn aLP — lp_token_policy would otherwise authorize a
        // co-minted aLP on this pool spend with no lp_supply change. See the
        // Underwrite arm for the full rationale.
        let lp_mint_qty = assets.quantity_of(mint, datum.lp_token_policy, "aLP")
        let no_lp_mint = lp_mint_qty == 0

        policy_targets_this_pool && bounds_ok && value_ok && datum_ok && immutable_ok && remains_non_negative && donation_ok && partner_share_in_bounds && partner_consistency && partner_not_aliased && team_output_funded && partner_output_funded && single_policy_input && policy_has_marker && marker_burn_ok && marker_redeemer_ok && marker_locality_ok && no_lp_mint
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

// [FIX R8-DRAIN-1 regression] partner_address_not_aliased — Round-8
// finding R8-DRAIN-1. Three regression tests covering each of the
// three privileged addresses (team, pool, policy script).

test partner_aliasing_none_passes() {
  let team =
    Address {
      payment_credential: address.VerificationKey(#"aa"),
      stake_credential: None,
    }
  let pool =
    Address {
      payment_credential: Script(#"bb"),
      stake_credential: None,
    }
  partner_address_not_aliased(None, team, pool, #"cc")
}

test partner_aliasing_to_team_fails() {
  let team =
    Address {
      payment_credential: address.VerificationKey(#"aa"),
      stake_credential: None,
    }
  let pool =
    Address {
      payment_credential: Script(#"bb"),
      stake_credential: None,
    }
  // Hostile partner_address == team_address must be rejected.
  partner_address_not_aliased(Some(team), team, pool, #"cc") == False
}

test partner_aliasing_to_pool_fails() {
  let team =
    Address {
      payment_credential: address.VerificationKey(#"aa"),
      stake_credential: None,
    }
  let pool =
    Address {
      payment_credential: Script(#"bb"),
      stake_credential: None,
    }
  // Hostile partner_address == pool_address must be rejected.
  partner_address_not_aliased(Some(pool), team, pool, #"cc") == False
}

test partner_aliasing_to_policy_script_fails() {
  let team =
    Address {
      payment_credential: address.VerificationKey(#"aa"),
      stake_credential: None,
    }
  let pool =
    Address {
      payment_credential: Script(#"bb"),
      stake_credential: None,
    }
  // Hostile partner_address with payment_credential == Script(policy_hash)
  // must be rejected (regardless of stake credential).
  let policy_addr =
    Address {
      payment_credential: Script(#"cc"),
      stake_credential: None,
    }
  partner_address_not_aliased(Some(policy_addr), team, pool, #"cc") == False
}

test partner_aliasing_to_unrelated_passes() {
  let team =
    Address {
      payment_credential: address.VerificationKey(#"aa"),
      stake_credential: None,
    }
  let pool =
    Address {
      payment_credential: Script(#"bb"),
      stake_credential: None,
    }
  // Benign partner_address (different VKH) must pass.
  let benign =
    Address {
      payment_credential: address.VerificationKey(#"dd"),
      stake_credential: None,
    }
  partner_address_not_aliased(Some(benign), team, pool, #"cc")
}

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

// ---------------------------------------------------------------------------
// [NN-A-3] LP-token locality regression tests.
//
// The AddLiquidity and RemoveLiquidity arms now assert the pool
// continuation output carries ZERO aLP tokens:
//   assets.quantity_of(cont_output.value, datum.lp_token_policy, "aLP") == 0
// These tests build a pool-continuation output Value and exercise that
// exact predicate (the same expression the validator ANDs into each
// branch's success conjunction).
//
// Attack closed: a deposit that routes the freshly-minted aLP INTO the
// pool's own continuation output creates an orphaned in-pool LP claim that
// anyone could later burn-from-pool to withdraw ADA they never deposited.
// With pool_out_no_lp pinned True, minted LP can only land on a wallet
// output, and no orphaned in-pool LP can exist to burn.
// ---------------------------------------------------------------------------

// Canonical LP-token policy id used by these locality tests (mirrors
// `lp_token_policy` in the pool datum). Arbitrary deterministic 28-byte
// handle — the assertion only cares about (policy, "aLP") presence.
const nna3_lp_policy: ByteArray =
  #"0402df9c420213421d894b00ee5b23391cb36dc3c2a436b48229c10a"

const nna3_pool_nft_policy: ByteArray =
  #"deadbeef00112233445566778899aabbccddeeff00112233445566"

const nna3_pool_nft_name: ByteArray = #"414547495350"

// A clean pool continuation value: ADA + pool NFT, NO aLP.
fn nna3_pool_value_clean(lovelace: Int) -> assets.Value {
  assets.from_lovelace(lovelace)
    |> assets.add(nna3_pool_nft_policy, nna3_pool_nft_name, 1)
}

// A poisoned pool continuation value: ADA + pool NFT + parked aLP.
fn nna3_pool_value_with_lp(lovelace: Int, lp_qty: Int) -> assets.Value {
  nna3_pool_value_clean(lovelace)
    |> assets.add(nna3_lp_policy, "aLP", lp_qty)
}

// (1) AddLiquidity routing minted aLP INTO the pool continuation now FAILS
// the locality pin (the orphaned-LP attack).
test nna3_add_liquidity_lp_parked_in_pool_fails() {
  let poisoned = nna3_pool_value_with_lp(105_000_000, 5_000_000)
  let pool_out_no_lp =
    assets.quantity_of(poisoned, nna3_lp_policy, "aLP") == 0
  // Attack output leaves aLP in the pool -> predicate is False -> branch
  // rejects.
  pool_out_no_lp == False
}

// (2) RemoveLiquidity with aLP left in / burned-from the pool continuation
// FAILS the locality pin (symmetric).
test nna3_remove_liquidity_lp_left_in_pool_fails() {
  let poisoned = nna3_pool_value_with_lp(95_000_000, 1)
  let pool_out_no_lp =
    assets.quantity_of(poisoned, nna3_lp_policy, "aLP") == 0
  pool_out_no_lp == False
}

// (3) Green-path AddLiquidity: minted aLP goes to a wallet output, pool
// continuation carries 0 aLP -> predicate PASSES.
test nna3_add_liquidity_lp_to_wallet_passes() {
  let clean = nna3_pool_value_clean(105_000_000)
  let pool_out_no_lp =
    assets.quantity_of(clean, nna3_lp_policy, "aLP") == 0
  pool_out_no_lp
}

// (4) Green-path RemoveLiquidity: pool continuation carries 0 aLP after
// the burn -> predicate PASSES.
test nna3_remove_liquidity_clean_pool_passes() {
  let clean = nna3_pool_value_clean(95_000_000)
  let pool_out_no_lp =
    assets.quantity_of(clean, nna3_lp_policy, "aLP") == 0
  pool_out_no_lp
}

// ---------------------------------------------------------------------------
// [NN-A-3 continuation] aLP-mint authorization on the NON-LP pool arms.
//
// `lp_token_policy` (validators/lp_token.ak) authorizes minting "aLP" on
// merely `pool_is_consumed` — ANY input at the pool script hash, not a
// redeemer-specific spend. PR #19 added the aLP-locality pin
// (`pool_out_no_lp`) ONLY to AddLiquidity / RemoveLiquidity. The other five
// arms (Underwrite, ProcessClaim, BatchUnderwrite, BatchExpireProcess,
// AcceptCancellation) freeze `lp_supply` but never inspected the `mint`
// field for aLP. So a tx that spends the pool via a legit arm (e.g.
// Underwrite) could ALSO co-mint N aLP to the attacker's wallet:
// lp_token_policy authorizes it (pool consumed, name "aLP", qty > 0) and the
// Underwrite arm didn't look at the mint — producing aLP with no ADA deposit
// and no lp_supply increment, later burned via RemoveLiquidity to drain ADA.
//
// Fix (mirrors the marker_qty_zero pattern): each non-LP arm now requires
//   assets.quantity_of(mint, datum.lp_token_policy, "aLP") == 0
// i.e. these arms must NEITHER mint nor burn aLP — net-zero. aLP can only
// net-change via Add/Remove, which carry the full LP accounting.
//
// These are full-Transaction tests: they construct a complete, otherwise-
// valid Underwrite / BatchUnderwrite tx and invoke `pool_validator.spend`
// directly. The green-path companion (aLP mint == 0) must stay accepted; the
// exploit (positive aLP co-mint to a non-pool output) must be rejected.
// ---------------------------------------------------------------------------

// Validator parameters for the integration tests.
const nna4_pool_script_hash: ByteArray =
  #"c366b0ea2667b432a432999f54e11978c0ed37c7c4b971067fb1589f"

const nna4_policy_script_hash: ByteArray =
  #"8ea5aed0e4f66e9ce6593fbed30856c8997441b1e5cd8bc3085e943f"

const nna4_marker_policy_id: ByteArray =
  #"9f0e6e2c2a3b4c5d6e7f8091a2b3c4d5e6f70819a2b3c4d5e6f70819"

// A canonical AegisSelf oracle NFT (preprod allowlist head). AegisSelf is the
// only provider whose `is_canonical_oracle_nft` can return True for a fixed
// handle, so the policy-output oracle pin uses it.
const nna4_oracle_nft: ByteArray =
  #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f"

const nna4_attacker_pkh: ByteArray =
  #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

const nna4_tx_id: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000000"

// Underwrite economics (default pool, 200 bps fee):
//   coverage = premium = 100 ADA
//   fee_total = max(2 ADA, 100 ADA * 200/10_000 = 2 ADA) = 2 ADA
//   net_pool_growth = 100 ADA - 2 ADA = 98 ADA
//   team_cut = 2 ADA (solo, partner_share 0)
//   treasury_cut = 100 ADA * 200/10_000 * 2_500/10_000 = 0.5 ADA
const nna4_coverage: Int = 100_000_000

const nna4_premium: Int = 100_000_000

const nna4_pool_in_lovelace: Int = 500_000_000_000

const nna4_net_pool_growth: Int = 98_000_000

const nna4_team_cut: Int = 2_000_000

const nna4_treasury_cut: Int = 500_000

// Validity range covering the policy start_time.
fn nna4_validity() -> ValidityRange {
  Interval {
    lower_bound: IntervalBound {
      bound_type: Finite(1_700_100_000_000),
      is_inclusive: True,
    },
    upper_bound: IntervalBound {
      bound_type: Finite(1_700_100_300_000),
      is_inclusive: True,
    },
  }
}

fn nna4_pool_addr() -> Address {
  Address { payment_credential: Script(nna4_pool_script_hash), stake_credential: None }
}

fn nna4_pool_datum() -> PoolDatum {
  PoolDatum {
    total_liquidity: 1_000_000_000_000,
    active_coverage: 100_000_000_000,
    lp_token_policy: nna3_lp_policy,
    protocol_fee_bps: 200,
    pool_nft: nna3_pool_nft_policy,
    lp_supply: 1_000_000_000_000,
  }
}

// Pool input UTxO: ADA + pool NFT, at the pool script address.
fn nna4_pool_input() -> Input {
  Input {
    output_reference: OutputReference {
      transaction_id: nna4_tx_id,
      output_index: 0,
    },
    output: Output {
      address: nna4_pool_addr(),
      value: assets.from_lovelace(nna4_pool_in_lovelace)
        |> assets.add(nna3_pool_nft_policy, nna3_pool_nft_name, 1),
      datum: InlineDatum(nna4_pool_datum()),
      reference_script: None,
    },
  }
}

// Pool continuation output: grows by net_pool_growth, carries the pool NFT,
// holds ZERO aLP, and embeds the post-Underwrite datum (lp_supply frozen).
fn nna4_pool_continuation() -> Output {
  let new_datum =
    PoolDatum {
      ..nna4_pool_datum(),
      total_liquidity: 1_000_000_000_000 + nna4_net_pool_growth,
      active_coverage: 100_000_000_000 + nna4_coverage,
    }
  Output {
    address: nna4_pool_addr(),
    value: assets.from_lovelace(nna4_pool_in_lovelace + nna4_net_pool_growth)
      |> assets.add(nna3_pool_nft_policy, nna3_pool_nft_name, 1),
    datum: InlineDatum(new_datum),
    reference_script: None,
  }
}

// Newly-created policy output: at the policy script, lovelace == coverage,
// carries exactly one marker, with a canonical (AegisSelf) oracle pin.
fn nna4_policy_output() -> Output {
  let pdat =
    PolicyDatum {
      policy_id: #"aabbccdd",
      insured: nna4_attacker_pkh,
      strike_price: 350_000,
      coverage_amount: nna4_coverage,
      premium_paid: nna4_premium,
      start_time: 1_700_100_100_000,
      expiry_time: 1_700_604_800_000,
      oracle_nft: nna4_oracle_nft,
      pool_script_hash: nna4_pool_script_hash,
      pool_nft: nna3_pool_nft_policy,
      oracle_provider: AegisSelf,
      partner_address: None,
      partner_share_bps: 0,
      risk_class: Barrier,
      receipt_commitment: None,
    }
  Output {
    address: Address {
      payment_credential: Script(nna4_policy_script_hash),
      stake_credential: None,
    },
    value: assets.from_lovelace(nna4_coverage)
      |> assets.add(nna4_marker_policy_id, policy_marker_asset_name, 1),
    datum: InlineDatum(pdat),
    reference_script: None,
  }
}

// Team fee output.
fn nna4_team_output() -> Output {
  Output {
    address: team_address,
    value: assets.from_lovelace(nna4_team_cut),
    datum: NoDatum,
    reference_script: None,
  }
}

// An attacker wallet output that receives co-minted aLP (the exploit sink).
fn nna4_attacker_lp_output(lp_qty: Int) -> Output {
  Output {
    address: Address {
      payment_credential: VerificationKey(nna4_attacker_pkh),
      stake_credential: None,
    },
    value: assets.from_lovelace(min_utxo_lovelace)
      |> assets.add(nna3_lp_policy, "aLP", lp_qty),
    datum: NoDatum,
    reference_script: None,
  }
}

// Build the base mint value (marker +1) and optionally co-mint aLP.
fn nna4_mint(lp_qty: Int) -> assets.Value {
  let base =
    assets.from_asset(nna4_marker_policy_id, policy_marker_asset_name, 1)
  if lp_qty == 0 {
    base
  } else {
    assets.add(base, nna3_lp_policy, "aLP", lp_qty)
  }
}

// Assemble a full single-policy pool-spend transaction shared by the
// Underwrite and BatchUnderwrite cases (their tx bodies are identical; only
// the spend redeemer differs). `lp_qty` controls the aLP co-mint: 0 = clean
// green path; >0 = the exploit (aLP routed to the attacker wallet).
fn nna4_tx(lp_qty: Int) -> Transaction {
  let outputs =
    if lp_qty == 0 {
      [nna4_pool_continuation(), nna4_policy_output(), nna4_team_output()]
    } else {
      [
        nna4_pool_continuation(),
        nna4_policy_output(),
        nna4_team_output(),
        nna4_attacker_lp_output(lp_qty),
      ]
    }
  Transaction {
    ..transaction.placeholder,
    inputs: [nna4_pool_input()],
    outputs: outputs,
    mint: nna4_mint(lp_qty),
    treasury_donation: Some(nna4_treasury_cut),
    validity_range: nna4_validity(),
    redeemers: nna4_marker_redeemers(),
  }
}

// The marker mint redeemer threaded through `redeemers`: `MintMarkers { 1 }`
// for the single-policy Underwrite / BatchUnderwrite paths. The validator
// reads it via `marker_mint_redeemer` (pairs.get_first on Mint purpose).
fn nna4_marker_redeemers() -> Pairs<ScriptPurpose, Redeemer> {
  let r: Data = MintMarkers { count: 1 }
  [Pair(Mint(nna4_marker_policy_id), r)]
}

fn nna4_spend(tx: Transaction) -> Bool {
  pool_validator.spend(
    nna4_policy_script_hash,
    nna4_marker_policy_id,
    Some(nna4_pool_datum()),
    Underwrite { coverage: nna4_coverage, premium: nna4_premium },
    OutputReference { transaction_id: nna4_tx_id, output_index: 0 },
    tx,
  )
}

// GREEN PATH: a well-formed Underwrite with NO aLP co-mint is ACCEPTED.
test nna4_underwrite_no_lp_mint_accepted() {
  nna4_spend(nna4_tx(0)) == True
}

// EXPLOIT: the SAME well-formed Underwrite, but co-minting positive aLP to a
// non-pool (attacker) output, must be REJECTED. Pre-fix the Underwrite arm
// ignores the mint and wrongly ACCEPTS (RED); post-fix `no_lp_mint` rejects.
test nna4_underwrite_co_mint_alp_rejected() {
  nna4_spend(nna4_tx(5_000_000)) == False
}

fn nna4_batch_spend(tx: Transaction) -> Bool {
  pool_validator.spend(
    nna4_policy_script_hash,
    nna4_marker_policy_id,
    Some(nna4_pool_datum()),
    BatchUnderwrite {
      total_coverage: nna4_coverage,
      total_premium: nna4_premium,
    },
    OutputReference { transaction_id: nna4_tx_id, output_index: 0 },
    tx,
  )
}

// GREEN PATH: a well-formed single-policy BatchUnderwrite with NO aLP
// co-mint is ACCEPTED.
test nna4_batch_underwrite_no_lp_mint_accepted() {
  nna4_batch_spend(nna4_tx(0)) == True
}

// EXPLOIT: same BatchUnderwrite co-minting positive aLP to the attacker
// wallet must be REJECTED. RED pre-fix, GREEN post-fix.
test nna4_batch_underwrite_co_mint_alp_rejected() {
  nna4_batch_spend(nna4_tx(5_000_000)) == False
}

