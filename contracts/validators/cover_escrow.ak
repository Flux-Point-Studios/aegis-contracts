// =============================================================================
// Aegis Insurance Protocol - Cover Escrow Validator (Zero-Premium Cover)
// Location: contracts/validators/cover_escrow.ak
// Summary: Holds the premium slices harvested from an enrollee's staking
//          rewards (premium_stake withdraw arm) until they buy a real policy.
//          ONE shared script hash for all enrollees; each UTxO carries the
//          enrollee's CoverTerms inline — the SAME Data the enrollee's
//          premium_stake instance bakes as its `cover_terms` param, so the
//          harvest arm and this spend validator pin each other end-to-end.
//
// Redeemers:
//   Convert - permissionless. The tx must run the pool's audited Underwrite
//             conjunction (pinned via the marker mint: markers are only
//             mintable by a real pool spend with branch pairing), and the
//             single freshly-markered policy output must satisfy the
//             enrollee's CoverTerms with premium == the exact sum of all
//             escrow inputs. Everything funds-critical about the policy
//             itself (premium enters the pool, coverage funded, floors,
//             adequacy, oracle mandate, portfolio cap) is enforced by the
//             live Underwrite arm in the same tx — never re-implemented here.
//   Reclaim - signed by the enrollee: free exit of accrued premium.
//
// Anti-double-satisfaction: every escrow input spent in the tx must carry
// the SAME inline datum (two enrollees' escrows can never mix, and a Reclaim
// can never ride along a Convert), the tx mints exactly ONE marker, and
// premium == the full escrow sum — so two escrow batches cannot share one
// policy and one batch cannot fund two.
//
// UTxOs at this script without an inline CoverTerms datum are unspendable by
// construction (donation-burn, standard for datum-carrying scripts).
// =============================================================================

use aegis/test_helpers/fixtures
use aegis/types.{
  AegisSelf, BurnForClaim, Convert, CoverTerms, EscrowRedeemer, MarkerRedeemer,
  MintMarkers, PolicyDatum, Pyth, Reclaim, policy_marker_asset_name,
}
use aegis/validation.{must_be_signed_by}
use aiken/collection/list
use aiken/collection/pairs
use cardano/address.{Script}
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, Mint, NoDatum, Output, OutputReference, Redeemer,
  ScriptPurpose, Transaction,
}

validator cover_escrow(policy_script_hash: ByteArray, marker_policy: ByteArray) {
  spend(
    datum_opt: Option<CoverTerms>,
    redeemer: EscrowRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(terms) = datum_opt
    when redeemer is {
      Reclaim -> must_be_signed_by(self.extra_signatories, terms.user_vkh)
      Convert ->
        convert_settles(terms, own_ref, self, policy_script_hash, marker_policy)
    }
  }

  else(_) {
    fail @"Unsupported purpose for cover_escrow"
  }
}

fn convert_settles(
  terms: CoverTerms,
  own_ref: OutputReference,
  self: Transaction,
  policy_script_hash: ByteArray,
  marker_policy: ByteArray,
) -> Bool {
  // Own input pins the escrow script address and the canonical raw datum
  // for the same-datum fold below.
  expect Some(own_input) = transaction.find_input(self.inputs, own_ref)
  let own_payment = own_input.output.address.payment_credential
  expect Script(own_hash) = own_payment
  expect InlineDatum(own_raw) = own_input.output.datum

  // ONE pass over inputs accumulating (escrow_sum, foreign_hashes):
  // * escrow_sum — every input at this script must carry the SAME inline
  //   datum or the fold fails closed (a Reclaim or another enrollee's escrow
  //   can never ride along a Convert);
  // * foreign_hashes — at most ONE foreign script credential is permitted
  //   (the pool spend the Underwrite requires). A second one is an
  //   OLD-GENERATION escrow (same CoverTerms datum, rotated script hash)
  //   riding this conversion: each generation's premium == Σ(own inputs)
  //   check passes independently, so one policy would absorb both sums and
  //   the tx builder pockets the duplicate.
  let (escrow_lovelace, foreign_script_hashes) =
    list.foldl(
      self.inputs,
      (0, []),
      fn(input, acc) {
        let (sum, foreign) = acc
        when input.output.address.payment_credential is {
          Script(h) ->
            if h == own_hash {
              expect InlineDatum(raw) = input.output.datum
              if raw == own_raw {
                (sum + assets.lovelace_of(input.output.value), foreign)
              } else {
                fail @"mixed escrow datums in one tx"
              }
            } else if list.has(foreign, h) {
              acc
            } else {
              (sum, [h, ..foreign])
            }
          _ -> acc
        }
      },
    )
  let single_foreign_script = list.length(foreign_script_hashes) <= 1

  // Exactly ONE marker minted, under the single-policy Underwrite pairing.
  // Marker mint authority requires a real pool spend with branch pairing
  // (policy_marker.ak), so this pins the tx to the audited Underwrite
  // conjunction without re-implementing any of it.
  let marker_minted =
    assets.quantity_of(self.mint, marker_policy, policy_marker_asset_name) == 1
  expect Some(raw_marker_redeemer) =
    pairs.get_first(self.redeemers, Mint(marker_policy))
  expect marker_redeemer: MarkerRedeemer = raw_marker_redeemer
  let single_underwrite =
    when marker_redeemer is {
      MintMarkers { count } -> count == 1
      _ -> False
    }

  // Exactly one output at the policy script, and it holds the fresh marker.
  expect [policy_out] =
    list.filter(
      self.outputs,
      fn(o) { o.address.payment_credential == Script(policy_script_hash) },
    )
  let policy_holds_marker =
    assets.quantity_of(policy_out.value, marker_policy, policy_marker_asset_name) == 1
  expect InlineDatum(policy_raw) = policy_out.datum
  expect policy: PolicyDatum = policy_raw

  and {
    marker_minted,
    single_underwrite,
    single_foreign_script,
    policy_holds_marker,
    // The policy is FOR the enrollee, paying their enterprise key (V4
    // payout path), with no partner fee-skim, no receipt lock, and no
    // payout redirection a keeper could point at itself.
    policy.insured == terms.user_vkh,
    policy.oracle_nft == terms.oracle_nft,
    // The provider must be AegisSelf. Convert pins oracle_nft but the Underwrite
    // Depeg path reads NO spot at creation and is_canonical_oracle_nft(Pyth, nft)
    // accepts any non-empty handle, so without this a permissionless griefer
    // could mint a real, fully-paid policy on the enrollee's stablecoin NFT with
    // provider=Pyth — one the Claim-time observer can never attest (pyth.resolve
    // finds no feed), burning the accrued escrow into an unclaimable position.
    // The zero-premium product is AegisSelf-resolved Depeg cover; if a
    // multi-provider escrow product ever ships, carry the provider in CoverTerms.
    when policy.oracle_provider is {
      AegisSelf -> True
      _ -> False
    },
    policy.payout_address == None,
    policy.receipt_commitment == None,
    policy.partner_address == None,
    // The trigger floor: Underwrite's floor tables only enforce a MINIMUM
    // premium (deeper strikes lower it, never reject it), so without this a
    // permissionless Convert could burn the escrow on a deep-out-of-the-money
    // strike that satisfies every other check yet can never trigger.
    policy.strike_price >= terms.min_strike,
    policy.expiry_time - policy.start_time >= terms.min_duration_days * 86_400_000,
    // premium/coverage <= max_rate_bps: refuses burning escrow on junk
    // terms (e.g. max_rate_bps=3000 refuses anything above 30% of coverage).
    policy.coverage_amount * terms.max_rate_bps >= policy.premium_paid * 10_000,
    policy.premium_paid == escrow_lovelace,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const ce_escrow_hash: ByteArray =
  #"e5c60e5c60e5c60e5c60e5c60e5c60e5c60e5c60e5c60e5c60e5c60e"

const ce_marker_policy: ByteArray =
  #"3a4dabc0000000000000000000000000000000000000000000000000"

fn ce_terms() -> CoverTerms {
  CoverTerms {
    user_vkh: fixtures.insured_pkh,
    oracle_nft: fixtures.oracle_nft_policy,
    min_strike: 300_000,
    max_rate_bps: 3_000,
    min_duration_days: 7,
  }
}

fn ce_terms_data() -> Data {
  let d: Data = ce_terms()
  d
}

// default_policy_datum: insured=insured_pkh, oracle=oracle_nft_policy,
// coverage 5_000 ADA, premium 200 ADA, duration exactly 7 days — rate 4%
// (400 bps <= 3_000) and duration == the CoverTerms minimum.
fn ce_policy_datum() -> PolicyDatum {
  // The zero-premium product is AegisSelf-resolved Depeg cover (the escrow
  // oracle_nft is always an AegisSelf depeg feed NFT), so every Convert-created
  // policy carries provider AegisSelf — pinned in convert_settles.
  PolicyDatum { ..fixtures.default_policy_datum(), oracle_provider: AegisSelf }
}

fn ce_escrow_input(idx: Int, lovelace: Int, datum: Data) -> Input {
  fixtures.make_input(
    fixtures.tx_id_one,
    idx,
    fixtures.script_addr(ce_escrow_hash),
    assets.from_lovelace(lovelace),
    InlineDatum(datum),
  )
}

fn ce_policy_output(datum: PolicyDatum, with_marker: Bool) -> Output {
  let base = assets.from_lovelace(datum.coverage_amount)
  let value =
    if with_marker {
      assets.add(base, ce_marker_policy, policy_marker_asset_name, 1)
    } else {
      base
    }
  Output {
    address: fixtures.script_addr(fixtures.policy_script_hash),
    value,
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

fn ce_marker_redeemers(r: MarkerRedeemer) -> Pairs<ScriptPurpose, Redeemer> {
  let raw: Data = r
  [Pair(Mint(ce_marker_policy), raw)]
}

fn ce_convert_tx(
  inputs: List<Input>,
  outputs: List<Output>,
  marker_qty: Int,
  marker_redeemer: MarkerRedeemer,
) -> Transaction {
  Transaction {
    ..fixtures.base_tx(),
    inputs: inputs,
    outputs: outputs,
    mint: assets.from_asset(ce_marker_policy, policy_marker_asset_name, marker_qty),
    redeemers: ce_marker_redeemers(marker_redeemer),
  }
}

fn ce_convert(tx: Transaction) -> Bool {
  cover_escrow.spend(
    fixtures.policy_script_hash,
    ce_marker_policy,
    Some(ce_terms()),
    Convert,
    fixtures.out_ref(fixtures.tx_id_one, 0),
    tx,
  )
}

// GREEN: one 200-ADA escrow input buys the 200-ADA-premium policy.
test ce_convert_single_input_settles() {
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(ce_policy_datum(), True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == True
}

// GREEN: two same-datum escrow inputs (120 + 80) fund one 200-ADA premium.
test ce_convert_batched_inputs_settle() {
  let tx =
    ce_convert_tx(
      [
        ce_escrow_input(0, 120_000_000, ce_terms_data()),
        ce_escrow_input(1, 80_000_000, ce_terms_data()),
      ],
      [ce_policy_output(ce_policy_datum(), True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == True
}

// NEGATIVE: a second escrow input carrying ANOTHER enrollee's datum — the
// same-datum fold fails closed (two users' escrows can never mix).
test ce_convert_mixed_datums_rejected() fail {
  let other: Data =
    CoverTerms { ..ce_terms(), user_vkh: fixtures.attacker_pkh }
  let tx =
    ce_convert_tx(
      [
        ce_escrow_input(0, 120_000_000, ce_terms_data()),
        ce_escrow_input(1, 80_000_000, other),
      ],
      [ce_policy_output(ce_policy_datum(), True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx)
}

// NEGATIVE: a datum-less escrow input swept into the Convert.
test ce_convert_datumless_input_rejected() fail {
  let dangling =
    Input {
      output_reference: fixtures.out_ref(fixtures.tx_id_one, 1),
      output: Output {
        address: fixtures.script_addr(ce_escrow_hash),
        value: assets.from_lovelace(80_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    }
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 120_000_000, ce_terms_data()), dangling],
      [ce_policy_output(ce_policy_datum(), True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx)
}

// NEGATIVE: policy premium != escrow sum (keeper skims 50 into change).
test ce_convert_premium_mismatch_rejected() {
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 250_000_000, ce_terms_data())],
      [ce_policy_output(ce_policy_datum(), True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == False
}

// NEGATIVE: policy issued to someone else.
test ce_convert_wrong_insured_rejected() {
  let datum =
    PolicyDatum { ..ce_policy_datum(), insured: fixtures.attacker_pkh }
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(datum, True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == False
}

// NEGATIVE: policy bound to a different oracle feed than the CoverTerms pin.
test ce_convert_wrong_oracle_rejected() {
  let datum =
    PolicyDatum { ..ce_policy_datum(), oracle_nft: fixtures.oracle_nft_policy_alt }
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(datum, True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == False
}

// NEGATIVE (red-team PR#130 HIGH): a permissionless griefer keeps the enrollee's
// Depeg oracle_nft but sets oracle_provider=Pyth. The Underwrite Depeg path reads
// no spot at mint so it settles, but the policy is unclaimable (no observer can
// attest a Pyth reading for a stablecoin NFT). The provider pin rejects it.
test ce_convert_wrong_provider_rejected() {
  let datum = PolicyDatum { ..ce_policy_datum(), oracle_provider: Pyth }
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(datum, True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == False
}

// NEGATIVE: keeper points the payout somewhere else via payout_address.
test ce_convert_payout_redirect_rejected() {
  let datum =
    PolicyDatum {
      ..ce_policy_datum(),
      payout_address: Some(fixtures.pkh_addr(fixtures.attacker_pkh)),
    }
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(datum, True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == False
}

// NEGATIVE: partner attribution would skim the fee side.
test ce_convert_partner_rejected() {
  let datum =
    PolicyDatum {
      ..ce_policy_datum(),
      partner_address: Some(fixtures.pkh_addr(fixtures.attacker_pkh)),
      partner_share_bps: 2_000,
    }
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(datum, True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == False
}

// NEGATIVE: a receipt-locked policy could never be claimed by the enrollee's
// normal path.
test ce_convert_receipt_locked_rejected() {
  let datum =
    PolicyDatum { ..ce_policy_datum(), receipt_commitment: Some(#"beef") }
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(datum, True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == False
}

// NEGATIVE: a deep-out-of-the-money strike below the CoverTerms floor — the
// junk-cover vector: floor tables only enforce premium MINIMUMS (a far
// strike lowers them), so without the min_strike pin this policy would
// satisfy every other check while being economically unclaimable.
test ce_convert_strike_below_floor_rejected() {
  let datum = PolicyDatum { ..ce_policy_datum(), strike_price: 1 }
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(datum, True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == False
}

// NEGATIVE: duration below the CoverTerms minimum (6 days < 7).
test ce_convert_short_duration_rejected() {
  let datum =
    PolicyDatum {
      ..ce_policy_datum(),
      expiry_time: 1_700_000_000_000 + 6 * 86_400_000,
    }
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(datum, True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == False
}

// NEGATIVE: junk terms — premium 40% of coverage vs the 30% CoverTerms cap.
test ce_convert_rate_above_cap_rejected() {
  let datum =
    PolicyDatum { ..ce_policy_datum(), coverage_amount: 500_000_000 }
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(datum, True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == False
}

// NEGATIVE: no marker minted — there is no Underwrite in this tx.
test ce_convert_no_marker_mint_rejected() fail {
  let tx =
    Transaction {
      ..fixtures.base_tx(),
      inputs: [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      outputs: [ce_policy_output(ce_policy_datum(), True)],
    }
  ce_convert(tx)
}

// NEGATIVE: batch pairing (MintMarkers{2}) — one Convert cannot hide inside
// a batch mint.
test ce_convert_batch_mint_rejected() {
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(ce_policy_datum(), True)],
      2,
      MintMarkers { count: 2 },
    )
  ce_convert(tx) == False
}

// NEGATIVE: wrong lifecycle pairing (a claim burn, not an underwrite mint).
test ce_convert_burn_pairing_rejected() {
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(ce_policy_datum(), True)],
      1,
      BurnForClaim,
    )
  ce_convert(tx) == False
}

// NEGATIVE: the policy output does not hold the fresh marker.
test ce_convert_markerless_policy_rejected() {
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data())],
      [ce_policy_output(ce_policy_datum(), False)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == False
}

// GREEN: one foreign script input (the pool spend every real Underwrite
// carries) is allowed alongside the escrow inputs.
test ce_convert_with_pool_input_settles() {
  let pool_input =
    fixtures.make_input(
      fixtures.tx_id_two,
      0,
      fixtures.script_addr(fixtures.pool_script_hash),
      assets.from_lovelace(500_000_000_000),
      NoDatum,
    )
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 200_000_000, ce_terms_data()), pool_input],
      [ce_policy_output(ce_policy_datum(), True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == True
}

// NEGATIVE: an OLD-GENERATION escrow input (same CoverTerms datum, rotated
// escrow script hash) riding the conversion as a SECOND foreign script — the
// cross-generation double-satisfaction: both generations' premium == Σ(own)
// checks would pass on one policy and the builder pockets the duplicate.
test ce_convert_cross_generation_escrow_rejected() {
  let old_generation_hash =
    #"01dee5c101dee5c101dee5c101dee5c101dee5c101dee5c101dee5c1"
  let pool_input =
    fixtures.make_input(
      fixtures.tx_id_two,
      0,
      fixtures.script_addr(fixtures.pool_script_hash),
      assets.from_lovelace(500_000_000_000),
      NoDatum,
    )
  let old_escrow_input =
    fixtures.make_input(
      fixtures.tx_id_two,
      1,
      fixtures.script_addr(old_generation_hash),
      assets.from_lovelace(200_000_000),
      InlineDatum(ce_terms_data()),
    )
  let tx =
    ce_convert_tx(
      [
        ce_escrow_input(0, 200_000_000, ce_terms_data()),
        old_escrow_input,
        pool_input,
      ],
      [ce_policy_output(ce_policy_datum(), True)],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx) == False
}

// NEGATIVE: two policy outputs — the singleton pin fails closed.
test ce_convert_two_policy_outputs_rejected() fail {
  let tx =
    ce_convert_tx(
      [ce_escrow_input(0, 400_000_000, ce_terms_data())],
      [
        ce_policy_output(ce_policy_datum(), True),
        ce_policy_output(ce_policy_datum(), False),
      ],
      1,
      MintMarkers { count: 1 },
    )
  ce_convert(tx)
}

// ---------------------------------------------------------------------------
// Reclaim tests
// ---------------------------------------------------------------------------

fn ce_reclaim(signers: List<ByteArray>) -> Bool {
  cover_escrow.spend(
    fixtures.policy_script_hash,
    ce_marker_policy,
    Some(ce_terms()),
    Reclaim,
    fixtures.out_ref(fixtures.tx_id_one, 0),
    Transaction { ..fixtures.base_tx(), extra_signatories: signers },
  )
}

// GREEN: the enrollee reclaims accrued premium at will.
test ce_reclaim_signed_settles() {
  ce_reclaim([fixtures.insured_pkh]) == True
}

// NEGATIVE: unsigned reclaim.
test ce_reclaim_unsigned_rejected() {
  ce_reclaim([]) == False
}

// NEGATIVE: reclaim signed by someone else.
test ce_reclaim_attacker_rejected() {
  ce_reclaim([fixtures.attacker_pkh]) == False
}
