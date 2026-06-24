use aegis/oracle.{resolve_oracle_price}
use aegis/pricing.{calculate_refund}
use aegis/types.{
  AegisSelf, BatchClaim, BatchExpire, BurnForCancel, BurnForClaim, BurnForExpire,
  Cancel, Charli3, Claim, ClaimWithReceipt, Expire, Indigo, MarkerRedeemer,
  OracleProvider, Orcfax, PolicyDatum, PolicyRedeemer, ReceiptWitness,
  cancellation_window, policy_marker_asset_name, receipt_commitment_hash,
  receipt_witness_ok,
}
use aegis/validation.{
  count_script_inputs, find_canonical_pool_output, get_lower_bound,
  get_upper_bound, must_be_signed_by, output_has_min_lovelace,
  sum_lovelace_to_enterprise_pkh,
}
use aiken/collection/pairs
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

use aegis/test_helpers/fixtures
use aiken/collection/list
use cardano/address.{Script}
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, Mint, Output, OutputReference, Redeemer, ScriptPurpose,
  Transaction,
}

// Every policy UTxO consumed at this validator must declare the same
// (oracle_provider, oracle_nft) pair, so a BatchClaim cannot mix feeds.

fn batch_oracles_uniform(
  inputs: List<Input>,
  own_script_hash: ByteArray,
) -> Bool {
  let (_, all_equal) =
    list.foldl(
      inputs,
      (None, True),
      fn(input, acc) {
        let (sentinel, ok) = acc
        when input.output.address.payment_credential is {
          Script(h) ->
            if h == own_script_hash {
              when input.output.datum is {
                InlineDatum(raw_pdat) -> {
                  expect pdat: PolicyDatum = raw_pdat
                  let pair = (pdat.oracle_provider, pdat.oracle_nft)
                  when sentinel is {
                    None -> (Some(pair), ok)
                    Some(s) -> (sentinel, ok && pair == s)
                  }
                }
                _ -> (sentinel, False)
              }
            } else {
              acc
            }
          _ -> acc
        }
      },
    )
  all_equal
}

// ---------------------------------------------------------------------------
// Policy Validator
// ---------------------------------------------------------------------------

/// Shared Claim settlement check. The funds-critical settlement logic
/// (single-input pin, oracle price <= strike, freshness, policy period, payout
/// sufficiency, canonical pool present, marker burn) lives in ONE place; the two
/// claim arms (`Claim`, `ClaimWithReceipt`) differ ONLY in `binding_ok` — the
/// receipt-commitment gate. This keeps the AI-cover binding from forking the
/// audited settlement path.
fn claim_settles(
  datum: PolicyDatum,
  inputs: List<Input>,
  reference_inputs: List<Input>,
  outputs: List<Output>,
  tx_lower: Int,
  tx_upper: Int,
  own_script_hash: ByteArray,
  has_marker: Bool,
  marker_redeemer: MarkerRedeemer,
  binding_ok: Bool,
) -> Bool {
  // Prevent double satisfaction: only one policy UTxO from this script per tx.
  let single_policy_input = count_script_inputs(inputs, own_script_hash) == 1

  // Resolve the oracle price via the provider-uniform dispatcher.
  let price =
    resolve_oracle_price(reference_inputs, datum.oracle_provider, datum.oracle_nft)

  // Crash detected: oracle price at or below the strike.
  let price_below_strike = price.value <= datum.strike_price

  // Both validity-range legs must sit inside the freshness window, and tx_lower
  // must be at or after the observed_at of the reading.
  let oracle_fresh =
    tx_lower >= price.observed_at && tx_lower <= price.valid_until && tx_upper <= price.valid_until

  // Transaction must sit inside the policy period.
  let within_start = tx_lower >= datum.start_time
  let within_expiry = tx_upper <= datum.expiry_time

  // Aggregate payout to insured must be sufficient (enterprise outputs only).
  let payout_valid =
    sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= datum.coverage_amount

  // Require the canonical pool output is present in the tx. The pool side
  // (ProcessClaim) owns the residual conservation equation, so any leak to
  // "change" is impossible; the policy side only ensures the canonical co-spend.
  let pool_present =
    when find_canonical_pool_output(
      outputs,
      datum.pool_script_hash,
      datum.pool_nft,
    ) is {
      Some(_) -> True
      None -> False
    }

  let marker_redeemer_ok =
    when marker_redeemer is {
      BurnForClaim -> True
      _ -> False
    }

  single_policy_input && price_below_strike && oracle_fresh && within_start && within_expiry && payout_valid && pool_present && has_marker && marker_redeemer_ok && binding_ok
}

/// Policy validator parameterized by the policy marker minting policy id.
///
/// [V12.2+R12 / EXT-08, EXT-09] Every spend path (Claim, Cancel, Expire,
/// BatchExpire) requires the consumed policy UTxO to hold exactly 1
/// marker (policy_marker_policy_id, "AEGIS_POLICY"). The marker is
/// minted only by a real Aegis Underwrite (which co-spends the pool);
/// a synthetic policy UTxO at the policy validator address with a fake
/// datum cannot acquire one, so the synthetic-Cancel pool-drain attack
/// (EXT-08) and synthetic-Claim accounting-corruption attack (EXT-09)
/// are closed at this layer in addition to the pool side. BatchClaim
/// remains disabled in V12.2+R12 (inherited from R11).
validator policy_validator(policy_marker_policy_id: ByteArray) {
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
      redeemers,
      ..
    } = self

    // EXT-16 sibling-redeemer pairing on the policy side: the marker
    // mint redeemer dictates which spend variant is permitted. Read
    // once at the top so each branch can pin its own lifecycle.
    expect Some(raw_marker_redeemer) =
      pairs.get_first(redeemers, Mint(policy_marker_policy_id))
    expect marker_redeemer: MarkerRedeemer = raw_marker_redeemer

    // Find own input to determine script hash and value
    expect Some(self_input) =
      inputs
        |> list.find(fn(input) { input.output_reference == own_ref })
    let own_value = self_input.output.value

    // Determine own script hash for counting co-spent policy inputs
    expect Script(own_script_hash) =
      self_input.output.address.payment_credential

    // [V12.2+R12 / EXT-08, EXT-09] Marker presence pin. Every legitimate
    // Aegis policy UTxO carries exactly 1 marker
    // (policy_marker_policy_id, "AEGIS_POLICY") minted by the pool
    // validator at Underwrite / BatchUnderwrite time. Synthetic policy
    // UTxOs (written at this script address with a fake datum by an
    // attacker) cannot acquire one because the marker policy delegates
    // mint authority to the pool validator's spend logic. Required True
    // in every branch (the disabled BatchClaim arm naturally never
    // reaches this check).
    let has_marker =
      assets.quantity_of(
        own_value,
        policy_marker_policy_id,
        policy_marker_asset_name,
      ) == 1

    when redeemer is {
      // -----------------------------------------------------------------------
      // CLAIM: Oracle price <= strike price -> payout to insured
      // -----------------------------------------------------------------------
      Claim -> {
        // A committed (AI-cover) policy MUST be claimed via `ClaimWithReceipt`,
        // revealing its receipt — so the plain Claim path is valid ONLY when the
        // policy carries no commitment. Non-AI policies are unaffected (None).
        let tx_lower = get_lower_bound(validity_range)
        let tx_upper = get_upper_bound(validity_range)
        claim_settles(
          datum,
          inputs,
          reference_inputs,
          outputs,
          tx_lower,
          tx_upper,
          own_script_hash,
          has_marker,
          marker_redeemer,
          datum.receipt_commitment == None,
        )
      }

      // -----------------------------------------------------------------------
      // CLAIM WITH RECEIPT (N5): settle an AI-cover policy by REVEALING the
      // receipt preimage bound into PolicyDatum at creation. Identical
      // settlement to Claim, plus the binding gate: the revealed witness must be
      // well-formed AND hash to the policy's `receipt_commitment`, so the payout
      // names the exact attested Materios receipt + threshold on-chain.
      // -----------------------------------------------------------------------
      ClaimWithReceipt { receipt } -> {
        let tx_lower = get_lower_bound(validity_range)
        let tx_upper = get_upper_bound(validity_range)
        let binding_ok =
          when datum.receipt_commitment is {
            Some(commitment) ->
              receipt_witness_ok(receipt) && commitment == receipt_commitment_hash(
                receipt,
              )
            // A policy with NO commitment cannot use the receipt path.
            None -> False
          }
        claim_settles(
          datum,
          inputs,
          reference_inputs,
          outputs,
          tx_lower,
          tx_upper,
          own_script_hash,
          has_marker,
          marker_redeemer,
          binding_ok,
        )
      }

      // -----------------------------------------------------------------------
      // BATCH CLAIM: disabled in V12.2+R11. Use a single Claim per policy.
      // -----------------------------------------------------------------------
      BatchClaim -> fail @"BatchClaim disabled in V12.2+R11. Use single Claim per policy."

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

        let marker_redeemer_ok =
          when marker_redeemer is {
            BurnForExpire { .. } -> True
            _ -> False
          }

        is_expired && funds_to_pool && has_marker && marker_redeemer_ok
      }

      // -----------------------------------------------------------------------
      // BATCH EXPIRE: Multiple expired policies reclaimed in one transaction
      // -----------------------------------------------------------------------
      BatchExpire -> {
        let has_policies = count_script_inputs(inputs, own_script_hash) >= 1

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

        let marker_redeemer_ok =
          when marker_redeemer is {
            BurnForExpire { .. } -> True
            _ -> False
          }

        has_policies && is_expired && funds_to_pool && has_marker && marker_redeemer_ok
      }

      // -----------------------------------------------------------------------
      // CANCEL: Early cancellation within the allowed window
      // -----------------------------------------------------------------------
      Cancel -> {
        // [V12.2+R12 / EXT-10] Reject multi-input Cancel. Symmetric
        // with Claim's existing single_policy_input guard. Without
        // this, an attacker pairs a legitimate policy input with a
        // synthetic-datum policy input and the pool only accounts for
        // the first one, while Cancel runs once per input.
        let single_policy_input =
          count_script_inputs(inputs, own_script_hash) == 1

        let signed_by_insured =
          must_be_signed_by(extra_signatories, datum.insured)

        let tx_upper = get_upper_bound(validity_range)
        let within_window = tx_upper <= datum.start_time + cancellation_window

        // Reject Cancel if the policy is in-the-money. Otherwise the
        // insured gets free optionality across the cancellation window:
        // Claim if ITM, Cancel if OTM.
        let price =
          resolve_oracle_price(
            reference_inputs,
            datum.oracle_provider,
            datum.oracle_nft,
          )
        let tx_lower = get_lower_bound(validity_range)
        // Same freshness rule as Claim.
        let oracle_fresh =
          tx_lower >= price.observed_at && tx_lower <= price.valid_until && tx_upper <= price.valid_until
        let not_in_the_money = price.value > datum.strike_price

        let refund_amount = calculate_refund(datum.premium_paid)
        let policy_utxo_lovelace = assets.lovelace_of(own_value)

        let insured_payout_valid =
          sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= refund_amount + policy_utxo_lovelace

        let pool_present =
          when find_canonical_pool_output(
            outputs,
            datum.pool_script_hash,
            datum.pool_nft,
          ) is {
            Some(_) -> True
            None -> False
          }

        let marker_redeemer_ok =
          when marker_redeemer is {
            BurnForCancel -> True
            _ -> False
          }

        signed_by_insured && within_window && oracle_fresh && not_in_the_money && insured_payout_valid && pool_present && has_marker && single_policy_input && marker_redeemer_ok
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

test double_satisfaction_two_inputs_fail_check() {
  let count = 2
  count != 1
}

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

// ===========================================================================
// [N1] EVENT_SLOT claims from a Materios-fed feed (Barrier-on-event verified)
//
// A Materios-fed EVENT_SLOT settles through the EXISTING AegisSelf rail. The
// SDK publishes a binary event (`value <= strike` when fired) into the SAME
// Charli3-compatible GenericData datum AegisSelf already uses, at the same
// publisher VKH address, under a canonical AegisSelf NFT. The Claim branch's
// price check is generic over the resolved oracle value:
//
//     let price_below_strike = price.value <= datum.strike_price
//
// so the existing Barrier path settles the event with NO new on-chain
// RiskClass and NO version bump. These end-to-end tests drive the real
// `policy_validator.spend` over a full transaction to lock that in:
//   * triggered (value <= strike)  -> Claim ACCEPTED, pays >= coverage,
//                                      pool present, marker burns (BurnForClaim)
//   * alive     (value >  strike)  -> Claim REJECTED
//   * stale feed (tx past valid_until) -> Claim REJECTED
//   * wrong oracle-NFT pin (non-canonical) -> resolver aborts -> REJECTED
//
// Conservation: the policy side requires the canonical pool output is present
// and that >= coverage flows to the insured; the residual conservation
// equation (cont == own + policy_lovelace - payout) is owned by the pool side
// (ProcessClaim) and is exercised in pool.ak's tests. Here we pin the policy
// side's contribution to that invariant.
// ===========================================================================

// Canonical marker policy id used by these EVENT_SLOT claim tests (28 bytes).
const n1_marker_policy_id: ByteArray =
  #"feedface00112233445566778899aabbccddeeff0011223344556677"

// Strike for the event policy: $0.50 (1e6 scale) — the CANONICAL Materios event
// strike, matching the Python bridge (materios_bridge), the C# InsuranceConstants,
// the aegis-sdk geometry, and surf_watch. For a binary EVENT_SLOT the SDK encodes
// "fired" as a value <= strike and "not fired" as a value > strike.
const n1_strike: Int = 500_000

// Lovelace locked in the policy UTxO (coverage + min-utxo headroom).
const n1_policy_lovelace: Int = 5_002_000_000

// Coverage the insured is owed on a triggered claim.
const n1_coverage: Int = 5_000_000_000

// Feed timing. The publisher stamps created/expiry; the tx validity range must
// sit inside [created, expiry] and inside the policy period.
const n1_created_ms: Int = 1_700_100_000_000

const n1_expiry_ms: Int = 1_700_103_600_000

// Tx validity range, fresh and inside the policy window.
const n1_tx_lower: Int = 1_700_100_100_000

const n1_tx_upper: Int = 1_700_100_400_000

// The event policy datum: AegisSelf-bound (the Materios rail), strike $0.50,
// coverage 5000 ADA, period straddling the tx validity range.
fn n1_policy_datum() -> PolicyDatum {
  PolicyDatum {
    ..fixtures.default_policy_datum_aegis_self(),
    strike_price: n1_strike,
    coverage_amount: n1_coverage,
    start_time: 1_700_000_000_000,
    expiry_time: 1_700_604_800_000,
  }
}

fn n1_own_ref() -> OutputReference {
  OutputReference { transaction_id: fixtures.tx_id_one, output_index: 0 }
}

// The policy input under spend: at the policy script, ADA + exactly one marker.
fn n1_policy_input() -> Input {
  fixtures.policy_input_with_marker(
    fixtures.tx_id_one,
    0,
    n1_policy_lovelace,
    n1_marker_policy_id,
    n1_policy_datum(),
  )
}

// Payout to the insured enterprise address (>= coverage).
fn n1_insured_output() -> Output {
  fixtures.pkh_output(fixtures.insured_pkh, n1_coverage)
}

// Canonical pool continuation output (carries the pool NFT). Its presence is
// the policy-side leg of conservation; lovelace bookkeeping lives on the pool.
fn n1_pool_output() -> Output {
  fixtures.pool_continuation(
    n1_policy_lovelace - n1_coverage,
    True,
    fixtures.default_pool_datum(),
  )
}

// Marker mint redeemer pair: Claim REQUIRES `BurnForClaim` under the marker
// policy id. Any other variant fails `marker_redeemer_ok`.
fn n1_marker_redeemers(
  marker_policy_id: ByteArray,
) -> Pairs<ScriptPurpose, Redeemer> {
  let r: Data = BurnForClaim
  [Pair(Mint(marker_policy_id), r)]
}

// Assemble the full Claim transaction. `feed_value` sets the EVENT_SLOT
// reading; `feed_nft` sets which NFT the feed UTxO carries; `created`/`expiry`
// set feed freshness; `marker_policy_id` sets the burn redeemer's policy id.
fn n1_claim_tx(
  feed_value: Int,
  feed_nft: ByteArray,
  created: Int,
  expiry: Int,
  marker_policy_id: ByteArray,
) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [n1_policy_input()],
    reference_inputs: [
      fixtures.aegis_self_feed_input(feed_nft, feed_value, created, expiry),
    ],
    outputs: [n1_pool_output(), n1_insured_output()],
    validity_range: fixtures.finite_range(n1_tx_lower, n1_tx_upper),
    redeemers: n1_marker_redeemers(marker_policy_id),
  }
}

// Drive the real validator over the Claim path.
fn n1_claim_spend(tx: Transaction) -> Bool {
  policy_validator.spend(
    n1_marker_policy_id,
    Some(n1_policy_datum()),
    Claim,
    n1_own_ref(),
    tx,
  )
}

// GREEN: a triggered EVENT_SLOT (value == strike, the boundary) settles via
// the Barrier path. value <= strike => payout to insured, pool present,
// marker burns. This is the core Barrier-on-EVENT_SLOT acceptance.
test n1_event_slot_triggered_at_strike_pays() {
  let tx =
    n1_claim_tx(
      n1_strike,
      fixtures.aegis_self_ada_nft,
      n1_created_ms,
      n1_expiry_ms,
      n1_marker_policy_id,
    )
  n1_claim_spend(tx) == True
}

// GREEN: strictly below strike (deeper in-the-money event) also settles.
test n1_event_slot_triggered_below_strike_pays() {
  let tx =
    n1_claim_tx(
      n1_strike - 50_000,
      fixtures.aegis_self_ada_nft,
      n1_created_ms,
      n1_expiry_ms,
      n1_marker_policy_id,
    )
  n1_claim_spend(tx) == True
}

// GREEN: the insured actually receives >= coverage. This pins the policy-side
// leg of conservation (payout sufficiency) for the event case.
test n1_event_slot_payout_covers_coverage() {
  let tx =
    n1_claim_tx(
      n1_strike,
      fixtures.aegis_self_ada_nft,
      n1_created_ms,
      n1_expiry_ms,
      n1_marker_policy_id,
    )
  let paid =
    sum_lovelace_to_enterprise_pkh(tx.outputs, fixtures.insured_pkh)
  paid >= n1_coverage && n1_claim_spend(tx) == True
}

// GREEN: the canonical pool output is present (policy-side conservation leg).
test n1_event_slot_pool_present() {
  let tx =
    n1_claim_tx(
      n1_strike,
      fixtures.aegis_self_ada_nft,
      n1_created_ms,
      n1_expiry_ms,
      n1_marker_policy_id,
    )
  when
    find_canonical_pool_output(
      tx.outputs,
      fixtures.pool_script_hash,
      fixtures.pool_nft_policy,
    )
  is {
    Some(_) -> True
    None -> False
  }
}

// RED -> REJECT: an EVENT_SLOT that did NOT fire (value > strike) leaves the
// policy alive; Claim must fail. Same generic Barrier check, opposite side.
test n1_event_slot_alive_above_strike_claim_fails() {
  let tx =
    n1_claim_tx(
      n1_strike + 1,
      fixtures.aegis_self_ada_nft,
      n1_created_ms,
      n1_expiry_ms,
      n1_marker_policy_id,
    )
  n1_claim_spend(tx) == False
}

// GREEN: the DEPLOYED Materios magnitude for a fired event — $0.10 = 100_000
// (1e6 scale) — settles the Claim against the canonical $0.50 = 500_000 strike.
// Pins the ON-CHAIN side of the exact geometry the Python bridge, the C#
// InsuranceConstants, and the aegis-sdk predicate all pin, using the literal
// deployed value (not a relative `n1_strike`-derived one) so a drift in the
// magnitudes is caught here.
test n1_event_slot_deployed_triggered_value_pays() {
  let tx =
    n1_claim_tx(
      100_000,
      fixtures.aegis_self_ada_nft,
      n1_created_ms,
      n1_expiry_ms,
      n1_marker_policy_id,
    )
  n1_claim_spend(tx) == True
}

// RED -> REJECT: the DEPLOYED Materios magnitude for a LIVE event — $1.00 =
// 1_000_000 — is above the $0.50 strike, so the Claim must fail. Together with
// the test above this straddles the 500_000 strike with the real values.
test n1_event_slot_deployed_alive_value_claim_fails() {
  let tx =
    n1_claim_tx(
      1_000_000,
      fixtures.aegis_self_ada_nft,
      n1_created_ms,
      n1_expiry_ms,
      n1_marker_policy_id,
    )
  n1_claim_spend(tx) == False
}

// RED -> REJECT: a stale feed (tx validity range past the publisher expiry)
// must fail freshness even though the event fired. Here valid_until is set
// BEFORE tx_lower so `tx_lower <= valid_until` is false.
test n1_event_slot_stale_feed_claim_fails() {
  let tx =
    n1_claim_tx(
      n1_strike,
      fixtures.aegis_self_ada_nft,
      n1_created_ms,
      // expiry well before the tx lower bound -> stale.
      n1_tx_lower - 1,
      n1_marker_policy_id,
    )
  n1_claim_spend(tx) == False
}

// RED -> ABORT: a feed UTxO carrying a NON-canonical NFT must cause the
// resolver to abort. The datum's `oracle_nft` stays canonical (so the policy
// is well-formed), but the only feed reference input carries a non-canonical
// NFT, so `find_feed_output` finds no match and `find_feed_datum` hits
// `fail @"Aegis-self feed UTxO not found in reference inputs"`. A validator
// abort is NOT the same as returning False — the `fail` test annotation is the
// Aiken idiom asserting that this code path panics (fails closed), which is
// the audit-grade behavior for a wrong-pin feed.
test n1_event_slot_wrong_oracle_nft_pin_claim_fails() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [n1_policy_input()],
      reference_inputs: [
        fixtures.aegis_self_feed_input(
          fixtures.aegis_self_noncanonical_nft,
          n1_strike,
          n1_created_ms,
          n1_expiry_ms,
        ),
      ],
      outputs: [n1_pool_output(), n1_insured_output()],
      validity_range: fixtures.finite_range(n1_tx_lower, n1_tx_upper),
      redeemers: n1_marker_redeemers(n1_marker_policy_id),
    }
  n1_claim_spend(tx)
}

// RED -> REJECT: marker burn redeemer must be exactly BurnForClaim. A wrong
// marker redeemer (BurnForCancel) under an otherwise-valid triggered event
// fails `marker_redeemer_ok`.
test n1_event_slot_wrong_marker_redeemer_claim_fails() {
  let bad: Data = BurnForCancel
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [n1_policy_input()],
      reference_inputs: [
        fixtures.aegis_self_feed_input(
          fixtures.aegis_self_ada_nft,
          n1_strike,
          n1_created_ms,
          n1_expiry_ms,
        ),
      ],
      outputs: [n1_pool_output(), n1_insured_output()],
      validity_range: fixtures.finite_range(n1_tx_lower, n1_tx_upper),
      redeemers: [Pair(Mint(n1_marker_policy_id), bad)],
    }
  n1_claim_spend(tx) == False
}

// RED -> REJECT: missing the policy marker (has_marker == False) fails even a
// well-formed triggered event. Models the synthetic-policy attack surface on
// the event rail.
test n1_event_slot_missing_marker_claim_fails() {
  let unmarked_input =
    fixtures.policy_input(fixtures.tx_id_one, 0, n1_policy_lovelace, n1_policy_datum())
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [unmarked_input],
      reference_inputs: [
        fixtures.aegis_self_feed_input(
          fixtures.aegis_self_ada_nft,
          n1_strike,
          n1_created_ms,
          n1_expiry_ms,
        ),
      ],
      outputs: [n1_pool_output(), n1_insured_output()],
      validity_range: fixtures.finite_range(n1_tx_lower, n1_tx_upper),
      redeemers: n1_marker_redeemers(n1_marker_policy_id),
    }
  n1_claim_spend(tx) == False
}

// ===========================================================================
// N5 — AI-cover receipt-commitment binding (ClaimWithReceipt)
//
// A policy that carries `receipt_commitment: Some(c)` (an AI-cover binding) can
// ONLY be claimed by revealing the receipt preimage that hashes to `c`. These
// tests drive the REAL validator over the committed-claim path.
// ===========================================================================

// A canonical 32-byte receiptId / config hash for the binding tests.
const ai_receipt_id: ByteArray =
  #"1111111111111111111111111111111111111111111111111111111111111111"

const ai_receipt_id_alt: ByteArray =
  #"3333333333333333333333333333333333333333333333333333333333333333"

const ai_config_hash: ByteArray =
  #"2222222222222222222222222222222222222222222222222222222222222222"

const ai_threshold: Int = 700_000

fn ai_witness() -> ReceiptWitness {
  ReceiptWitness {
    receipt_id: ai_receipt_id,
    threshold: ai_threshold,
    config_hash: ai_config_hash,
  }
}

// An AI-cover policy: identical to the N1 event policy but BOUND to the receipt
// commitment derived from `ai_witness()`.
fn ai_policy_datum() -> PolicyDatum {
  PolicyDatum {
    ..n1_policy_datum(),
    receipt_commitment: Some(receipt_commitment_hash(ai_witness())),
  }
}

fn ai_policy_input() -> Input {
  fixtures.policy_input_with_marker(
    fixtures.tx_id_one,
    0,
    n1_policy_lovelace,
    n1_marker_policy_id,
    ai_policy_datum(),
  )
}

// A triggered ($0.10 <= $0.50 strike) Claim tx whose policy input is the
// committed AI-cover policy. The marker burns BurnForClaim, pool present.
fn ai_triggered_tx() -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [ai_policy_input()],
    reference_inputs: [
      fixtures.aegis_self_feed_input(
        fixtures.aegis_self_ada_nft,
        100_000,
        n1_created_ms,
        n1_expiry_ms,
      ),
    ],
    outputs: [n1_pool_output(), n1_insured_output()],
    validity_range: fixtures.finite_range(n1_tx_lower, n1_tx_upper),
    redeemers: n1_marker_redeemers(n1_marker_policy_id),
  }
}

fn ai_spend(tx: Transaction, redeemer: PolicyRedeemer, datum: PolicyDatum) -> Bool {
  policy_validator.spend(
    n1_marker_policy_id,
    Some(datum),
    redeemer,
    n1_own_ref(),
    tx,
  )
}

// GREEN: a committed AI-cover policy settles when ClaimWithReceipt reveals the
// EXACT receipt preimage bound at creation.
test n5_ai_cover_claim_with_matching_receipt_pays() {
  ai_spend(ai_triggered_tx(), ClaimWithReceipt { receipt: ai_witness() }, ai_policy_datum()) == True
}

// RED -> REJECT: a WRONG receiptId (commitment mismatch) cannot settle the
// policy — the payout is bound to the exact attested receipt.
test n5_ai_cover_wrong_receipt_id_claim_fails() {
  let wrong = ReceiptWitness { ..ai_witness(), receipt_id: ai_receipt_id_alt }
  ai_spend(ai_triggered_tx(), ClaimWithReceipt { receipt: wrong }, ai_policy_datum()) == False
}

// RED -> REJECT: a WRONG threshold (commitment mismatch) cannot settle. Binds
// the proven public threshold, not just the receiptId.
test n5_ai_cover_wrong_threshold_claim_fails() {
  let wrong = ReceiptWitness { ..ai_witness(), threshold: ai_threshold + 1 }
  ai_spend(ai_triggered_tx(), ClaimWithReceipt { receipt: wrong }, ai_policy_datum()) == False
}

// RED -> REJECT: the binding cannot be BYPASSED via the plain Claim path — a
// committed policy requires receipt_commitment == None there, which it is not.
test n5_ai_cover_plain_claim_bypass_fails() {
  ai_spend(ai_triggered_tx(), Claim, ai_policy_datum()) == False
}

// RED -> REJECT: a NON-committed (ordinary) policy cannot use the receipt path —
// the None arm of the binding gate is False.
test n5_non_committed_policy_via_receipt_path_fails() {
  let tx =
    n1_claim_tx(
      100_000,
      fixtures.aegis_self_ada_nft,
      n1_created_ms,
      n1_expiry_ms,
      n1_marker_policy_id,
    )
  ai_spend(tx, ClaimWithReceipt { receipt: ai_witness() }, n1_policy_datum()) == False
}

// RED -> REJECT: a structurally malformed witness (receiptId not 32 bytes) is
// rejected even when the policy is committed to that malformed witness's own
// hash — proving `receipt_witness_ok` is load-bearing, not just the hash match.
test n5_ai_cover_malformed_receipt_id_rejected() {
  let bad =
    ReceiptWitness { receipt_id: #"00", threshold: ai_threshold, config_hash: ai_config_hash }
  let datum =
    PolicyDatum {
      ..n1_policy_datum(),
      receipt_commitment: Some(receipt_commitment_hash(bad)),
    }
  let input =
    fixtures.policy_input_with_marker(
      fixtures.tx_id_one,
      0,
      n1_policy_lovelace,
      n1_marker_policy_id,
      datum,
    )
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [input],
      reference_inputs: [
        fixtures.aegis_self_feed_input(
          fixtures.aegis_self_ada_nft,
          100_000,
          n1_created_ms,
          n1_expiry_ms,
        ),
      ],
      outputs: [n1_pool_output(), n1_insured_output()],
      validity_range: fixtures.finite_range(n1_tx_lower, n1_tx_upper),
      redeemers: n1_marker_redeemers(n1_marker_policy_id),
    }
  ai_spend(tx, ClaimWithReceipt { receipt: bad }, datum) == False
}

// UNIT: the commitment distinguishes different receipts (binds receiptId) and
// the structural guard enforces the Bytes32 sizes.
test n5_receipt_commitment_distinguishes_receipts() {
  let a = receipt_commitment_hash(ai_witness())
  let b = receipt_commitment_hash(ReceiptWitness { ..ai_witness(), receipt_id: ai_receipt_id_alt })
  a != b
}

test n5_receipt_witness_ok_enforces_sizes() {
  receipt_witness_ok(ai_witness()) && !receipt_witness_ok(
    ReceiptWitness { ..ai_witness(), receipt_id: #"00" },
  )
}
