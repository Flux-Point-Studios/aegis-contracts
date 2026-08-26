use aegis/oracle.{attested_price}
use aegis/pricing.{calculate_refund}
use aegis/types.{
  AegisSelf, BatchClaim, BatchExpire, BurnForCancel, BurnForClaim, BurnForExpire,
  Cancel, Claim, ClaimWithReceipt, Expire, MarkerRedeemer, PolicyDatum,
  PolicyRedeemer, ReceiptWitness, cancellation_window, max_reading_validity_ms,
  policy_marker_asset_name, receipt_commitment_hash, receipt_witness_ok,
}
use aegis/validation.{
  count_script_inputs, find_canonical_pool_output, get_lower_bound,
  get_upper_bound, must_be_signed_by, output_has_min_lovelace,
  sum_lovelace_to_address, sum_lovelace_to_address_with_inline_datum,
  sum_lovelace_to_enterprise_pkh,
}
use aegis/test_helpers/fixtures
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

use aiken/collection/list
use cardano/address.{Script}
use cardano/assets
use cardano/transaction.{
  Input, Mint, Output, OutputReference, Redeemer, ScriptPurpose, Transaction,
}

// ---------------------------------------------------------------------------
// Oracle reading freshness (V4/V7 claim + cancel)
//
// [#363 K-1] This is the SAME predicate as vault.reading_fresh on the V8 line.
// It was previously inlined at the two use-sites below WITHOUT the upper bound
// on valid_until, so the A-fix (f0849f1) — which only touched vault.reading_fresh
// — left this LIVE V4/V7 path exposed to the K-1 residual (a publisher-written
// `valid_until = observed_at + 100y` stayed claim-fresh forever). Extracted here
// so both arms share one bounded copy and a future edit cannot silently drop the
// ceiling on one of them. Kept as its own fn (not an import of vault.reading_fresh)
// to avoid pulling the V8 vault dependency graph into the V4/V7 validator.
// ---------------------------------------------------------------------------
pub fn oracle_reading_fresh(
  observed_at: Int,
  valid_until: Int,
  tx_lower: Int,
  tx_upper: Int,
) -> Bool {
  and {
    tx_lower >= observed_at,
    tx_lower <= valid_until,
    tx_upper <= valid_until,
    // The publisher's validity window is BOUNDED by the validator, not trusted
    // unbounded — a dead/misconfigured publisher's frozen reading expires.
    valid_until <= observed_at + max_reading_validity_ms,
  }
}

test oracle_reading_fresh_rejects_unbounded_publisher_validity() {
  // The K-1 residual, reproduced at the V4/V7 predicate: a reading whose
  // publisher-written validity outruns the ceiling is NOT fresh, even with the
  // tx snug inside [observed_at, valid_until]. Mirrors
  // vault.reading_fresh_rejects_unbounded_publisher_validity.
  let observed_at = 1_700_000_000_000
  let hundred_years = 100 * 365 * 86_400_000
  !oracle_reading_fresh(
    observed_at,
    observed_at + hundred_years,
    observed_at + 1_000,
    observed_at + 2_000,
  )
}

test oracle_reading_fresh_accepts_honest_70min_window() {
  // The publisher's real convention (valid_until = observed_at + 4_200_000, 70
  // min) is well inside the 2h ceiling and stays fresh.
  let observed_at = 1_700_000_000_000
  oracle_reading_fresh(
    observed_at,
    observed_at + 4_200_000,
    observed_at + 1_000,
    observed_at + 2_000,
  )
}

// ---------------------------------------------------------------------------
// Policy Validator
// ---------------------------------------------------------------------------

/// Shared Claim settlement check. The funds-critical settlement logic
/// (single-input pin, barrier touched, freshness, policy period, payout
/// sufficiency, canonical pool present, marker burn) lives in ONE place; the
/// two claim arms (`Claim`, `ClaimWithReceipt`) differ ONLY in `binding_ok` —
/// the receipt-commitment gate. This keeps the AI-cover binding from forking
/// the audited settlement path. The full V5 semantics are preserved: the
/// 4-arg `resolve_oracle_price(self, …)` (so Pyth resolves), the 12h-grace
/// `barrier_touched` (SEC F-1), and the `payout_address` dispatch (DAO/script
/// beneficiary, both legs SUM not first-match).
fn claim_settles(
  self: Transaction,
  datum: PolicyDatum,
  inputs: List<Input>,
  outputs: List<Output>,
  tx_lower: Int,
  tx_upper: Int,
  own_script_hash: ByteArray,
  observer_script_hash: ByteArray,
  has_marker: Bool,
  marker_redeemer: MarkerRedeemer,
  binding_ok: Bool,
) -> Bool {
  // Prevent double satisfaction: only one policy UTxO from this
  // script may be consumed per transaction.
  let single_policy_input = count_script_inputs(inputs, own_script_hash) == 1

  // [V5 size #315] Read the oracle Price ATTESTED by the oracle_observer
  // (resolved out-of-line) instead of resolving inline — removes the Pyth
  // resolver from the policy validator's compiled size. The freshness gates
  // below (oracle_fresh) stay consumer-side, byte-identical.
  let price =
    attested_price(
      self,
      observer_script_hash,
      datum.oracle_provider,
      datum.oracle_nft,
    )

  // Crash detected: spot at/below strike, OR the trailing-12h low
  // touched the strike — the latter keeps a barrier policy claimable
  // for ~12h after a dip even if spot recovered. `min_price_12h`
  // equals `value` for every provider except AegisSelf, so
  // non-AegisSelf policies retain pure spot-at-claim semantics.
  let barrier_touched =
    price.value <= datum.strike_price || price.min_price_12h <= datum.strike_price && price.low_observed_at >= datum.start_time

  // Both validity-range legs must sit inside the freshness window,
  // and tx_lower must be at or after the observed_at of the reading.
  let oracle_fresh =
    oracle_reading_fresh(
      price.observed_at,
      price.valid_until,
      tx_lower,
      tx_upper,
    )

  // Transaction must sit inside the policy period.
  let within_start = tx_lower >= datum.start_time
  let within_expiry = tx_upper <= datum.expiry_time

  // [V5/V6] Coverage routes to `payout_address` (exact full-Address match)
  // when set — enabling a DAO/script beneficiary — else to the insured's
  // enterprise KEY address (V4 behaviour). When the policy ALSO committed a
  // `payout_datum` (a Plutus/V2-V3 DAO treasury), the coverage output must
  // additionally carry that EXACT inline datum, else a datum-less output would
  // lock at the treasury (the ledger needs a datum to invoke a Plutus spend
  // script). All three helpers SUM across all outputs (never first-match), so a
  // hostile prefix/decoy output can't short-circuit the payout (A-006 / A-013).
  let payout_valid =
    when datum.payout_address is {
      None ->
        sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= datum.coverage_amount
      Some(addr) ->
        when datum.payout_datum is {
          // V5 datum-less coverage (native-script / key treasury).
          None ->
            sum_lovelace_to_address(outputs, addr) >= datum.coverage_amount
          // [V6] Plutus-treasury: pin the exact committed inline datum.
          Some(payout_datum) ->
            sum_lovelace_to_address_with_inline_datum(outputs, addr, payout_datum) >= datum.coverage_amount
        }
    }

  // Require the canonical pool output is present in the tx. The
  // pool side (ProcessClaim) now owns the residual conservation
  // equation: cont == own + policy_lovelace - payout, so any leak
  // to "change" is impossible. Policy side only ensures the tx is
  // co-spent with the canonical pool.
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

  single_policy_input && barrier_touched && oracle_fresh && within_start && within_expiry && payout_valid && pool_present && has_marker && marker_redeemer_ok && binding_ok
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
validator policy_validator(
  policy_marker_policy_id: ByteArray,
  // [V5 size #315] The oracle_observer script hash — the policy reads the
  // attested oracle Price from the observer's withdrawal (via attested_price)
  // instead of inlining resolve_oracle_price/Pyth.
  observer_script_hash: ByteArray,
) {
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
          self,
          datum,
          inputs,
          outputs,
          tx_lower,
          tx_upper,
          own_script_hash,
          observer_script_hash,
          has_marker,
          marker_redeemer,
          datum.receipt_commitment == None,
        )
      }

      // -----------------------------------------------------------------------
      // CLAIM WITH RECEIPT: settle an AI-cover policy by REVEALING the receipt
      // preimage bound into PolicyDatum at creation. Identical settlement to
      // Claim, plus the binding gate: the revealed witness must be well-formed
      // AND hash to the policy's `receipt_commitment`, so the payout names the
      // exact attested Materios receipt + threshold on-chain.
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
          self,
          datum,
          inputs,
          outputs,
          tx_lower,
          tx_upper,
          own_script_hash,
          observer_script_hash,
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
          attested_price(
            self,
            observer_script_hash,
            datum.oracle_provider,
            datum.oracle_nft,
          )
        let tx_lower = get_lower_bound(validity_range)
        // Same freshness rule as Claim.
        let oracle_fresh =
          oracle_reading_fresh(
      price.observed_at,
      price.valid_until,
      tx_lower,
      tx_upper,
    )
        // [12h grace] Mirror Claim's barrier definition: a policy counts as
        // in-the-money — and is therefore NOT cancellable — when spot OR the
        // trailing-12h low is at/under the strike. Gating on spot alone would
        // hand the insured free optionality (Cancel for a refund even though
        // the barrier was touched in the window and they could Claim).
        let not_in_the_money =
          price.value > datum.strike_price && ( price.min_price_12h > datum.strike_price || price.low_observed_at < datum.start_time )

        let refund_amount = calculate_refund(datum.premium_paid)

        // [POOL-FUNDED REPRICE] The policy UTxO's lovelace is now the POOL's
        // coverage (pool-funded at Underwrite), NOT the buyer's collateral. On
        // Cancel it must return to the POOL — the insured receives ONLY the
        // premium refund. The coverage->pool routing is enforced exactly by the
        // pool's AcceptCancellation value_ok (cont == own + policy_lovelace -
        // refund - fee); Cancel is single-input + branch-paired so that always
        // runs. Paying the insured `refund + coverage` here (the old
        // buyer-collateralized semantics) let any user drain the pool by
        // underwrite->cancel — SEC FINDING-1.
        let insured_payout_valid =
          sum_lovelace_to_enterprise_pkh(outputs, datum.insured) >= refund_amount

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

        // [V5] DAO/script-beneficiary policies (payout_address = Some) are NOT
        // cancellable: `insured` is the buyer's personal cancel-authority key,
        // but the DAO funded the premium — a cancellable DAO policy would let
        // the buyer pocket the ~90% refund within the grace window. Such
        // policies run to Claim / Expire only.
        let no_script_beneficiary = datum.payout_address == None

        signed_by_insured && within_window && oracle_fresh && not_in_the_money && insured_payout_valid && pool_present && has_marker && single_policy_input && marker_redeemer_ok && no_script_beneficiary
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

// barrier_touched := spot <= strike || (min_price_12h <= strike && low_observed_at >= start_time)
// not_in_the_money := spot > strike && (min_price_12h > strike || low_observed_at < start_time)

test claim_barrier_touched_via_12h_low() {
  // Spot recovered OTM ($0.50) but the 12h low ($0.30) was observed DURING
  // the policy (after start) -> claimable.
  let strike = 350_000
  let spot = 500_000
  let min_price_12h = 300_000
  let start_time = 1_000_000
  let low_observed_at = 1_500_000
  spot <= strike || min_price_12h <= strike && low_observed_at >= start_time
}

test claim_barrier_pre_start_touch_rejected() {
  // SEC F-1: the 12h low touched the strike, but the touch happened BEFORE
  // the policy started -> NOT claimable (can't insure a past event).
  let strike = 350_000
  let spot = 500_000
  let min_price_12h = 300_000
  let start_time = 2_000_000
  let low_observed_at = 1_500_000
  !(spot <= strike || min_price_12h <= strike && low_observed_at >= start_time)
}

test claim_barrier_both_above_strike_rejected() {
  // Spot AND 12h-low both above strike -> no claim (timestamp irrelevant).
  let strike = 350_000
  let spot = 500_000
  let min_price_12h = 400_000
  let start_time = 1_000_000
  let low_observed_at = 1_500_000
  !(spot <= strike || min_price_12h <= strike && low_observed_at >= start_time)
}

test claim_barrier_spot_itm_still_triggers() {
  // Spot at/below strike triggers regardless of the 12h-low or its time.
  let strike = 350_000
  let spot = 300_000
  let min_price_12h = 500_000
  let start_time = 1_000_000
  let low_observed_at = 500_000
  spot <= strike || min_price_12h <= strike && low_observed_at >= start_time
}

test claim_barrier_non_aegisself_spot_only() {
  // Non-AegisSelf: min_price_12h == spot, low_observed_at == observed_at, so
  // the OR reduces to spot-at-claim. Spot above strike -> no claim.
  let strike = 350_000
  let spot = 500_000
  let min_price_12h = 500_000
  let start_time = 1_000_000
  let low_observed_at = 1_500_000
  !(spot <= strike || min_price_12h <= strike && low_observed_at >= start_time)
}

test cancel_rejected_when_12h_low_itm() {
  // Spot OTM but the 12h low touched the strike DURING the policy -> the
  // barrier fired, so Cancel must be REJECTED. not_in_the_money == False.
  let strike = 350_000
  let spot = 500_000
  let min_price_12h = 300_000
  let start_time = 1_000_000
  let low_observed_at = 1_500_000
  !(spot > strike && ( min_price_12h > strike || low_observed_at < start_time ))
}

test cancel_allowed_when_pre_start_touch() {
  // The only dip in the 12h window predates the policy -> barrier never fired
  // during its life -> Cancel IS allowed. not_in_the_money == True.
  let strike = 350_000
  let spot = 500_000
  let min_price_12h = 300_000
  let start_time = 2_000_000
  let low_observed_at = 1_500_000
  spot > strike && ( min_price_12h > strike || low_observed_at < start_time )
}

test cancel_allowed_when_fully_otm() {
  // Both spot and the 12h low are above strike -> Cancel allowed.
  let strike = 350_000
  let spot = 500_000
  let min_price_12h = 400_000
  let start_time = 1_000_000
  let low_observed_at = 1_500_000
  spot > strike && ( min_price_12h > strike || low_observed_at < start_time )
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
// EVENT_SLOT claims from a Materios-fed feed (Barrier-on-event verified)
//
// A Materios-fed EVENT_SLOT settles through the EXISTING AegisSelf rail. The
// SDK publishes a binary event (`value <= strike` when fired) into the SAME
// Charli3-compatible GenericData datum AegisSelf already uses, at the same
// publisher VKH address, under a canonical AegisSelf NFT. The Claim branch's
// barrier check is generic over the resolved oracle value (for a binary
// EVENT_SLOT `min_price_12h == value`, so the 12h-grace OR collapses to
// `value <= strike`), so the existing Barrier path settles the event with NO
// new on-chain RiskClass and NO version bump. These end-to-end tests drive the
// real `policy_validator.spend` over a full transaction to lock that in:
//   * triggered (value <= strike)  -> Claim ACCEPTED, pays >= coverage,
//                                      pool present, marker burns (BurnForClaim)
//   * alive     (value >  strike)  -> Claim REJECTED
//   * stale feed (tx past valid_until) -> Claim REJECTED
//   * wrong oracle-NFT pin (non-canonical) -> resolver aborts -> REJECTED
// ===========================================================================

// Canonical marker policy id used by these EVENT_SLOT claim tests (28 bytes).
const n1_marker_policy_id: ByteArray =
  #"feedface00112233445566778899aabbccddeeff0011223344556677"

// Strike for the event policy: $0.50 (1e6 scale) — the CANONICAL Materios event
// strike, matching the Python bridge, the aegis-sdk geometry, and surf_watch.
// For a binary EVENT_SLOT the SDK encodes "fired" as a value <= strike and
// "not fired" as a value > strike.
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

const n1_observer_hash: ByteArray =
  #"0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e0b5e"

// Drive the real validator over the Claim path. Every n1 tx is threaded through
// the observer-attestation injector so `attested_price` reads the forwarded ADA
// feed (resolved genuinely from the tx's own reference inputs).
fn n1_claim_spend(tx: Transaction) -> Bool {
  let tx2 =
    fixtures.with_observer_attestation(
      tx,
      n1_observer_hash,
      [(AegisSelf, fixtures.aegis_self_ada_nft())],
    )
  policy_validator.spend(
    n1_marker_policy_id,
    n1_observer_hash,
    Some(n1_policy_datum()),
    Claim,
    n1_own_ref(),
    tx2,
  )
}

// GREEN: a triggered EVENT_SLOT (value == strike, the boundary) settles via
// the Barrier path. value <= strike => payout to insured, pool present,
// marker burns. This is the core Barrier-on-EVENT_SLOT acceptance.
test n1_event_slot_triggered_at_strike_pays() {
  let tx =
    n1_claim_tx(
      n1_strike,
      fixtures.aegis_self_ada_nft(),
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
      fixtures.aegis_self_ada_nft(),
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
      fixtures.aegis_self_ada_nft(),
      n1_created_ms,
      n1_expiry_ms,
      n1_marker_policy_id,
    )
  let paid = sum_lovelace_to_enterprise_pkh(tx.outputs, fixtures.insured_pkh)
  paid >= n1_coverage && n1_claim_spend(tx) == True
}

// GREEN: the canonical pool output is present (policy-side conservation leg).
test n1_event_slot_pool_present() {
  let tx =
    n1_claim_tx(
      n1_strike,
      fixtures.aegis_self_ada_nft(),
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
      fixtures.aegis_self_ada_nft(),
      n1_created_ms,
      n1_expiry_ms,
      n1_marker_policy_id,
    )
  n1_claim_spend(tx) == False
}

// GREEN: the DEPLOYED Materios magnitude for a fired event — $0.10 = 100_000
// (1e6 scale) — settles the Claim against the canonical $0.50 = 500_000 strike.
test n1_event_slot_deployed_triggered_value_pays() {
  let tx =
    n1_claim_tx(
      100_000,
      fixtures.aegis_self_ada_nft(),
      n1_created_ms,
      n1_expiry_ms,
      n1_marker_policy_id,
    )
  n1_claim_spend(tx) == True
}

// RED -> REJECT: the DEPLOYED Materios magnitude for a LIVE event — $1.00 =
// 1_000_000 — is above the $0.50 strike, so the Claim must fail.
test n1_event_slot_deployed_alive_value_claim_fails() {
  let tx =
    n1_claim_tx(
      1_000_000,
      fixtures.aegis_self_ada_nft(),
      n1_created_ms,
      n1_expiry_ms,
      n1_marker_policy_id,
    )
  n1_claim_spend(tx) == False
}

// RED -> REJECT: a stale feed (tx validity range past the publisher expiry)
// must fail freshness even though the event fired.
test n1_event_slot_stale_feed_claim_fails() {
  let tx =
    n1_claim_tx(
      n1_strike,
      fixtures.aegis_self_ada_nft(),
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
// NFT, so `find_feed_output` finds no match and `find_feed_datum` hits its
// `fail`. A validator abort is NOT the same as returning False — the `fail`
// test annotation asserts this code path panics (fails closed).
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
          fixtures.aegis_self_ada_nft(),
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
    fixtures.policy_input(
      fixtures.tx_id_one,
      0,
      n1_policy_lovelace,
      n1_policy_datum(),
    )
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [unmarked_input],
      reference_inputs: [
        fixtures.aegis_self_feed_input(
          fixtures.aegis_self_ada_nft(),
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
// AI-cover receipt-commitment binding (ClaimWithReceipt)
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

// An AI-cover policy: identical to the event policy but BOUND to the receipt
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
        fixtures.aegis_self_ada_nft(),
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

fn ai_spend(
  tx: Transaction,
  redeemer: PolicyRedeemer,
  datum: PolicyDatum,
) -> Bool {
  let tx2 =
    fixtures.with_observer_attestation(
      tx,
      n1_observer_hash,
      [(AegisSelf, fixtures.aegis_self_ada_nft())],
    )
  policy_validator.spend(n1_marker_policy_id, n1_observer_hash, Some(datum), redeemer, n1_own_ref(), tx2)
}

// GREEN: a committed AI-cover policy settles when ClaimWithReceipt reveals the
// EXACT receipt preimage bound at creation.
test n5_ai_cover_claim_with_matching_receipt_pays() {
  ai_spend(
    ai_triggered_tx(),
    ClaimWithReceipt { receipt: ai_witness() },
    ai_policy_datum(),
  ) == True
}

// RED -> REJECT: a WRONG receiptId (commitment mismatch) cannot settle the
// policy — the payout is bound to the exact attested receipt.
test n5_ai_cover_wrong_receipt_id_claim_fails() {
  let wrong = ReceiptWitness { ..ai_witness(), receipt_id: ai_receipt_id_alt }
  ai_spend(
    ai_triggered_tx(),
    ClaimWithReceipt { receipt: wrong },
    ai_policy_datum(),
  ) == False
}

// RED -> REJECT: a WRONG threshold (commitment mismatch) cannot settle. Binds
// the proven public threshold, not just the receiptId.
test n5_ai_cover_wrong_threshold_claim_fails() {
  let wrong = ReceiptWitness { ..ai_witness(), threshold: ai_threshold + 1 }
  ai_spend(
    ai_triggered_tx(),
    ClaimWithReceipt { receipt: wrong },
    ai_policy_datum(),
  ) == False
}

// RED -> REJECT: the binding cannot be BYPASSED via the plain Claim path — a
// committed policy requires receipt_commitment == None there, which it is not.
// This is the drain-hole guard: the field-add + the Claim gate land together.
test n5_ai_cover_plain_claim_bypass_fails() {
  ai_spend(ai_triggered_tx(), Claim, ai_policy_datum()) == False
}

// RED -> REJECT: a NON-committed (ordinary) policy cannot use the receipt path —
// the None arm of the binding gate is False.
test n5_non_committed_policy_via_receipt_path_fails() {
  let tx =
    n1_claim_tx(
      100_000,
      fixtures.aegis_self_ada_nft(),
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
    ReceiptWitness {
      receipt_id: #"00",
      threshold: ai_threshold,
      config_hash: ai_config_hash,
    }
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
          fixtures.aegis_self_ada_nft(),
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
  let b =
    receipt_commitment_hash(
      ReceiptWitness { ..ai_witness(), receipt_id: ai_receipt_id_alt },
    )
  a != b
}

test n5_receipt_witness_ok_enforces_sizes() {
  receipt_witness_ok(ai_witness()) && !receipt_witness_ok(
    ReceiptWitness { ..ai_witness(), receipt_id: #"00" },
  )
}

// ===========================================================================
// Treasury-cover script-credential payout (V5 payout_address, #325)
//
// A DAO treasury hedge forces PolicyDatum.payout_address (field 14) to the
// treasury's NATIVE-SCRIPT address. On Claim the pool pays the coverage
// DATUM-LESS to that script credential; the treasury later spends the NoDatum
// output with its native script. The preprod e2e proof (underwrite 40f42140 ->
// crash bebc7333 -> claim eb62d936 -> spend-back ec59ffce) showed this settles
// end-to-end; these tests drive the REAL `policy_validator.spend` to lock the
// script-credential payout into the validator suite so a refactor can't
// silently break it:
//   * POSITIVE — coverage to the committed script address settles (True).
//   * NEGATIVE — coverage to the insured pkh / a DIFFERENT script / a
//     stake-grafted variant of the committed script all FAIL (the Some-arm
//     uses `sum_lovelace_to_address`, an EXACT full-Address match; A-009).
//   * Cancel of a payout_address=Some policy is REJECTED (no_script_beneficiary),
//     with an otherwise-identical payout_address=None control that ACCEPTS —
//     isolating the rule as the sole discriminator.
// ===========================================================================

// The DAO treasury's native-script hash (28 bytes). Distinct from the pool /
// policy / marker hashes so an address match is unambiguous.
const tc_treasury_hash: ByteArray =
  #"ca11ab1eca11ab1eca11ab1eca11ab1eca11ab1eca11ab1eca11ab1e"

// A SECOND, unrelated treasury hash — the "wrong script" the coverage must NOT
// be divertible to.
const tc_treasury_hash_alt: ByteArray =
  #"d00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeedd00dfeed"

// A treasury-bound policy: the n1 AegisSelf event policy, but with
// payout_address forced to the treasury's native-script address.
fn tc_policy_datum() -> PolicyDatum {
  PolicyDatum {
    ..n1_policy_datum(),
    payout_address: Some(fixtures.script_addr(tc_treasury_hash)),
  }
}

// A triggered ($0.10 <= $0.50 strike) Claim tx for the treasury-bound policy,
// parameterized by its outputs so each test pins where the coverage lands.
fn tc_claim_tx(outputs: List<Output>) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [
      fixtures.policy_input_with_marker(
        fixtures.tx_id_one,
        0,
        n1_policy_lovelace,
        n1_marker_policy_id,
        tc_policy_datum(),
      ),
    ],
    reference_inputs: [
      fixtures.aegis_self_feed_input(
        fixtures.aegis_self_ada_nft(),
        100_000,
        n1_created_ms,
        n1_expiry_ms,
      ),
    ],
    outputs,
    validity_range: fixtures.finite_range(n1_tx_lower, n1_tx_upper),
    redeemers: n1_marker_redeemers(n1_marker_policy_id),
  }
}

// Coverage paid DATUM-LESS to the committed treasury script credential.
fn tc_treasury_output() -> Output {
  fixtures.script_output(tc_treasury_hash, n1_coverage)
}

// GREEN: coverage routed to the committed script-credential payout_address
// settles. This is the core treasury-cover acceptance — the pool pays the
// DAO's native-script treasury, not the insured.
test tc_claim_to_script_payout_pays() {
  let tx = tc_claim_tx([n1_pool_output(), tc_treasury_output()])
  ai_spend(tx, Claim, tc_policy_datum()) == True
}

// RED -> REJECT: paying the INSURED key (the V4 default beneficiary) does NOT
// satisfy a payout_address=Some policy — the Some-arm requires the committed
// treasury address, so a 5000-ADA insured output contributes 0 to it.
test tc_claim_to_insured_instead_of_treasury_fails() {
  let tx = tc_claim_tx([n1_pool_output(), n1_insured_output()])
  ai_spend(tx, Claim, tc_policy_datum()) == False
}

// RED -> REJECT: coverage diverted to a DIFFERENT script address than the one
// committed in payout_address fails closed (the tamper case).
test tc_claim_to_wrong_script_address_fails() {
  let tx =
    tc_claim_tx(
      [n1_pool_output(), fixtures.script_output(tc_treasury_hash_alt, n1_coverage)],
    )
  ai_spend(tx, Claim, tc_policy_datum()) == False
}

// RED -> REJECT: the committed script payment credential with a GRAFTED stake
// credential is NOT the committed enterprise address. `sum_lovelace_to_address`
// matches the FULL address, so the grafted-stake output contributes 0 — closing
// A-009 for the script-payout case (a claim-bot cannot splice its own stake key
// onto the treasury payout).
test tc_claim_to_stake_grafted_treasury_fails() {
  let tx =
    tc_claim_tx(
      [
        n1_pool_output(),
        fixtures.script_output_with_stake(
          tc_treasury_hash,
          fixtures.attacker_stake_pkh,
          n1_coverage,
        ),
      ],
    )
  ai_spend(tx, Claim, tc_policy_datum()) == False
}

// --- Cancel: script-beneficiary policies are NOT cancellable ----------------

// Cancel timing: inside the 1h cancellation window and after start, with an
// OTM feed (value > strike) so `not_in_the_money` holds. Everything below is a
// fully valid Cancel EXCEPT (for the Some variant) the no_script_beneficiary
// rule — isolating that rule as the sole discriminator.
const tc_cancel_tx_lower: Int = 1_700_000_100_000

const tc_cancel_tx_upper: Int = 1_700_000_400_000

const tc_cancel_feed_created: Int = 1_700_000_000_000

const tc_cancel_feed_expiry: Int = 1_700_003_600_000

// Out-of-the-money: 600_000 > the $0.50 = 500_000 strike. For the AegisSelf
// feed min_price_12h defaults to spot, so not_in_the_money holds.
const tc_cancel_otm_value: Int = 600_000

fn tc_cancel_marker_redeemers() -> Pairs<ScriptPurpose, Redeemer> {
  let r: Data = BurnForCancel
  [Pair(Mint(n1_marker_policy_id), r)]
}

// An otherwise-valid Cancel tx for `datum`: single marked policy input, insured
// signature, refund (full premium >= 90% refund) to the insured enterprise
// address, canonical pool present, BurnForCancel marker, OTM fresh feed.
fn tc_cancel_tx(datum: PolicyDatum) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [
      fixtures.policy_input_with_marker(
        fixtures.tx_id_one,
        0,
        n1_policy_lovelace,
        n1_marker_policy_id,
        datum,
      ),
    ],
    reference_inputs: [
      fixtures.aegis_self_feed_input(
        fixtures.aegis_self_ada_nft(),
        tc_cancel_otm_value,
        tc_cancel_feed_created,
        tc_cancel_feed_expiry,
      ),
    ],
    outputs: [
      n1_pool_output(),
      fixtures.pkh_output(fixtures.insured_pkh, n1_policy_datum().premium_paid),
    ],
    validity_range: fixtures.finite_range(tc_cancel_tx_lower, tc_cancel_tx_upper),
    extra_signatories: [fixtures.insured_pkh],
    redeemers: tc_cancel_marker_redeemers(),
  }
}

// RED -> REJECT: a payout_address=Some (DAO/script-beneficiary) policy is NOT
// cancellable. `insured` is the buyer's personal cancel-authority key but the
// DAO funded the premium; a cancellable DAO policy would let the buyer pocket
// the ~90% refund within the grace window. no_script_beneficiary == False.
test tc_cancel_script_beneficiary_rejected() {
  let datum = tc_policy_datum()
  ai_spend(tc_cancel_tx(datum), Cancel, datum) == False
}

// GREEN control: the SAME otherwise-valid Cancel with payout_address = None is
// ACCEPTED. This proves no_script_beneficiary is the SOLE blocker above — not
// an unrelated precondition failure (signature, window, freshness, OTM, refund,
// pool, marker are all satisfied here too).
test tc_cancel_no_beneficiary_control_accepts() {
  let datum = n1_policy_datum()
  ai_spend(tc_cancel_tx(datum), Cancel, datum) == True
}

// ===========================================================================
// Plutus-treasury payout_datum binding (V6 payout_datum, #325)
//
// A Plutus (V1/V2/V3) DAO treasury CANNOT spend a datum-less coverage output —
// the ledger requires a datum to invoke a Plutus spend script. The buyer
// commits `payout_datum: Some(d)` at Underwrite; on Claim the coverage output
// to the Some-payout_address MUST carry `InlineDatum(d)` exactly, so the
// treasury (e.g. Agora — ignores datum CONTENTS, needs A datum) can spend it.
// `payout_datum: None` keeps the V5 datum-less output (native-script / key).
// These drive the REAL `policy_validator.spend`:
//   * POSITIVE — coverage to the committed script address WITH the matching
//     inline datum settles (True).
//   * NEGATIVE — a datum-less output, or one carrying a DIFFERENT datum, FAILS
//     closed (the Some-payout_datum arm uses sum_lovelace_to_address_with_inline_datum).
//   * REGRESSION — payout_datum=None still pays DATUM-LESS (tc_claim_to_script_payout_pays).
// ===========================================================================

// The committed payout_datum. Agora's treasury validator ignores the datum
// CONTENTS but the ledger requires A datum to invoke a Plutus spend script —
// `unit` (Void) is the simplest valid value (the Agora case).
fn tcd_unit_datum() -> Data {
  let v: Data = Void
  v
}

// A DIFFERENT committed datum — proves the bind rejects a substituted datum.
fn tcd_other_datum() -> Data {
  let v: Data = 7
  v
}

// A treasury-bound policy that ALSO commits payout_datum = Some(unit): the n1
// AegisSelf event policy, payout forced to the treasury script with a committed
// inline datum.
fn tcd_datum_policy() -> PolicyDatum {
  PolicyDatum {
    ..n1_policy_datum(),
    payout_address: Some(fixtures.script_addr(tc_treasury_hash)),
    payout_datum: Some(tcd_unit_datum()),
  }
}

// A triggered ($0.10 <= $0.50 strike) Claim tx for the datum-bound policy,
// parameterized by its outputs so each test pins where (and with what datum)
// the coverage lands.
fn tcd_claim_tx(outputs: List<Output>) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [
      fixtures.policy_input_with_marker(
        fixtures.tx_id_one,
        0,
        n1_policy_lovelace,
        n1_marker_policy_id,
        tcd_datum_policy(),
      ),
    ],
    reference_inputs: [
      fixtures.aegis_self_feed_input(
        fixtures.aegis_self_ada_nft(),
        100_000,
        n1_created_ms,
        n1_expiry_ms,
      ),
    ],
    outputs,
    validity_range: fixtures.finite_range(n1_tx_lower, n1_tx_upper),
    redeemers: n1_marker_redeemers(n1_marker_policy_id),
  }
}

// GREEN: coverage to the committed script address carrying the EXACT committed
// inline datum settles — a Plutus DAO treasury can spend it. The core
// payout_datum acceptance.
test tcd_claim_to_script_payout_with_matching_datum_pays() {
  let tx =
    tcd_claim_tx(
      [
        n1_pool_output(),
        fixtures.script_output_with_datum(
          tc_treasury_hash,
          tcd_unit_datum(),
          n1_coverage,
        ),
      ],
    )
  ai_spend(tx, Claim, tcd_datum_policy()) == True
}

// RED -> REJECT: the committed policy demands an inline datum, but the coverage
// output is DATUM-LESS (the V5 native-script shape). A Plutus treasury could
// not spend a datum-less UTxO, so the Claim must fail closed.
test tcd_claim_datumless_output_fails() {
  let tx =
    tcd_claim_tx([n1_pool_output(), fixtures.script_output(tc_treasury_hash, n1_coverage)])
  ai_spend(tx, Claim, tcd_datum_policy()) == False
}

// RED -> REJECT: the coverage output carries a DIFFERENT inline datum than the
// one committed -> fails closed (the substituted-datum tamper case).
test tcd_claim_wrong_datum_fails() {
  let tx =
    tcd_claim_tx(
      [
        n1_pool_output(),
        fixtures.script_output_with_datum(
          tc_treasury_hash,
          tcd_other_datum(),
          n1_coverage,
        ),
      ],
    )
  ai_spend(tx, Claim, tcd_datum_policy()) == False
}

// RED -> REJECT: the right datum but at the WRONG script address fails closed —
// the bind is on the FULL address AND the datum, never one alone.
test tcd_claim_right_datum_wrong_address_fails() {
  let tx =
    tcd_claim_tx(
      [
        n1_pool_output(),
        fixtures.script_output_with_datum(
          tc_treasury_hash_alt,
          tcd_unit_datum(),
          n1_coverage,
        ),
      ],
    )
  ai_spend(tx, Claim, tcd_datum_policy()) == False
}
