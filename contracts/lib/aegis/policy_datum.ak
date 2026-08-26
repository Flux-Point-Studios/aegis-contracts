//// Forward-compatible PolicyDatum decoding.
////
//// The vault hash is frozen, so the validator that reads a policy today is the
//// same validator that reads every policy ever written at this address. Both
//// arities therefore occur in production:
////
////   * OLD datum, NEW code — a policy underwritten before a field existed must
////     still settle. The missing tail defaults to its pre-field semantics.
////   * NEW datum, OLD code — the off-chain builder outgrows the deployed vault
////     and appends a field the vault has never heard of. Extra trailing fields
////     are ignored, not fatal.
////
//// `expect pd: PolicyDatum = raw` gives neither: it demands exact arity, so
//// appending one field strands every outstanding policy AND every deployed
//// vault. That is the migration this loop exists to make unnecessary.
////
//// The head (indices 0-13) is REQUIRED — those fields carry the money terms and
//// a policy missing any of them is malformed, not old. Only the Option-typed
//// tail defaults, and only to None, which is exactly each field's
//// before-it-existed behaviour.
////
//// CONSTRAINT ON FUTURE FIELDS: because an already-deployed vault ignores a
//// tail it does not know, an appended field can only ever WIDEN what a policy
//// permits. A field that RESTRICTS settlement is invisible to the vaults
//// already live and must not be added this way.

use aegis/test_helpers/fixtures.{pkh_addr}
use aegis/types.{
  AegisSelf, Barrier, OracleProvider, PolicyDatum, RiskClass, SettlementPins,
}
use aiken/builtin
use aiken/collection/list
use cardano/address.{Address}

/// Decode a policy datum by field index, defaulting the Option tail.
pub fn decode_policy_datum(raw: Data) -> PolicyDatum {
  let Pair(tag, fields) = builtin.un_constr_data(raw)
  expect tag == 0
  expect [
    f_policy_id, f_insured, f_strike_price, f_coverage_amount, f_premium_paid,
    f_start_time, f_expiry_time, f_oracle_nft, f_pool_script_hash, f_pool_nft,
    f_oracle_provider, f_partner_address, f_partner_share_bps, f_risk_class,
    ..tail
  ] = fields
  expect policy_id: ByteArray = f_policy_id
  expect insured: ByteArray = f_insured
  expect strike_price: Int = f_strike_price
  expect coverage_amount: Int = f_coverage_amount
  expect premium_paid: Int = f_premium_paid
  expect start_time: Int = f_start_time
  expect expiry_time: Int = f_expiry_time
  expect oracle_nft: ByteArray = f_oracle_nft
  expect pool_script_hash: ByteArray = f_pool_script_hash
  expect pool_nft: ByteArray = f_pool_nft
  expect oracle_provider: OracleProvider = f_oracle_provider
  expect partner_address: Option<Address> = f_partner_address
  expect partner_share_bps: Int = f_partner_share_bps
  expect risk_class: RiskClass = f_risk_class
  let payout_address: Option<Address> =
    when list.at(tail, 0) is {
      None -> None
      Some(field) -> {
        expect value: Option<Address> = field
        value
      }
    }
  let receipt_commitment: Option<ByteArray> =
    when list.at(tail, 1) is {
      None -> None
      Some(field) -> {
        expect value: Option<ByteArray> = field
        value
      }
    }
  let payout_datum: Option<Data> =
    when list.at(tail, 2) is {
      None -> None
      Some(field) -> {
        expect value: Option<Data> = field
        value
      }
    }
  let settlement_pins: Option<SettlementPins> =
    when list.at(tail, 3) is {
      None -> None
      Some(field) -> decode_settlement_pins(field)
    }
  let extension: Option<Data> =
    when list.at(tail, 4) is {
      None -> None
      Some(field) -> {
        expect value: Option<Data> = field
        value
      }
    }
  PolicyDatum {
    policy_id,
    insured,
    strike_price,
    coverage_amount,
    premium_paid,
    start_time,
    expiry_time,
    oracle_nft,
    pool_script_hash,
    pool_nft,
    oracle_provider,
    partner_address,
    partner_share_bps,
    risk_class,
    payout_address,
    receipt_commitment,
    payout_datum,
    settlement_pins,
    extension,
  }
}

/// [#391 F1] `settlement_pins` is decoded FIELD BY FIELD, like the head, rather
/// than through a blanket `expect value: Option<SettlementPins> = field`.
///
/// MEASURED, and the reason this exists: the blanket cast succeeds wherever the
/// compiler can trace the value's construction — which is every test that
/// builds the datum in the same expression — and CRASHES on the identical bytes
/// once they reach a validator through a transaction's `InlineDatum`, where the
/// cast is opaque and the full runtime check actually runs. Trace, aiken
/// 1.1.22: "the validator crashed / exited prematurely | expect value:
/// Option<SettlementPins> = field". No builder had written a pins tail yet, so
/// the cast had never been evaluated in its non-elided form and the suite was
/// green over a slot that no vault could read: a policy carrying pins was
/// undecodable by the very validator that has to settle it.
///
/// The head has always been decoded this way for the same reason. `Bool` gets
/// its constructor tag read directly rather than a cast, since it is the one
/// field whose Data form is a bare constructor with no payload.
fn decode_settlement_pins(raw: Data) -> Option<SettlementPins> {
  let Pair(opt_tag, opt_fields) = builtin.un_constr_data(raw)
  if opt_tag == 1 {
    None
  } else {
    expect opt_tag == 0
    expect [inner] = opt_fields
    let Pair(pins_tag, f) = builtin.un_constr_data(inner)
    expect pins_tag == 0
    // [#410 / G4] EIGHT fields. The four the vault could never read —
    // pyth_state_nft, pyth_freshness_window_ms, pyth_max_confidence_bps and
    // pyth_reject_absent_confidence — are enforced inside `oracle/pyth.ak`,
    // which runs in `oracle_observer`. The vault only ever sees the observer's
    // attested `Price`, so it is structurally incapable of checking them;
    // carrying them cost 118 B of every policy datum and created a second
    // source of truth that could silently disagree with the observer's compiled
    // values with no arbiter.
    expect [
      f_fallback_feed_id, f_publisher_vkh, f_observer_script_hash,
      f_max_reading_validity_ms, f_fallback_grace_ms,
      f_cancellation_window_ms, f_cancellation_fee_bps, f_claim_waiting_period_ms,
    ] = f
    expect fallback_feed_id: ByteArray = f_fallback_feed_id
    expect publisher_vkh: ByteArray = f_publisher_vkh
    expect observer_script_hash: ByteArray = f_observer_script_hash
    expect max_reading_validity_ms: Int = f_max_reading_validity_ms
    expect fallback_grace_ms: Int = f_fallback_grace_ms
    expect cancellation_window_ms: Int = f_cancellation_window_ms
    expect cancellation_fee_bps: Int = f_cancellation_fee_bps
    expect claim_waiting_period_ms: Int = f_claim_waiting_period_ms
    Some(
      SettlementPins {
        fallback_feed_id,
        publisher_vkh,
        observer_script_hash,
        max_reading_validity_ms,
        fallback_grace_ms,
        cancellation_window_ms,
        cancellation_fee_bps,
        claim_waiting_period_ms,
      },
    )
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const sample_policy_id: ByteArray = #"aabbccdd"

const sample_insured: ByteArray =
  #"00112233445566778899aabbccddeeff00112233445566778899aabb"

const sample_pool_hash: ByteArray =
  #"ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544"

const sample_oracle_nft: ByteArray =
  #"192e7af49c73f13aafd1649b2c2e43574272dd4bb47da5af7260b17f"

const sample_pool_nft: ByteArray =
  #"954aa87d6e15ce01b1988403ed1843e5af9b7b1f70329f90dbbc241a"

const sample_strike: Int = 350_000

const sample_coverage: Int = 5_000_000_000

const sample_premium: Int = 200_000_000

const sample_start: Int = 1_700_000_000_000

const sample_expiry: Int = 1_700_604_800_000

/// Every arity below carries the same policy, so every one of them must decode
/// to exactly this value. Comparing whole records rather than a handful of
/// fields is what makes the tail assertions total.
fn expected_policy() -> PolicyDatum {
  PolicyDatum {
    policy_id: sample_policy_id,
    insured: sample_insured,
    strike_price: sample_strike,
    coverage_amount: sample_coverage,
    premium_paid: sample_premium,
    start_time: sample_start,
    expiry_time: sample_expiry,
    oracle_nft: sample_oracle_nft,
    pool_script_hash: sample_pool_hash,
    pool_nft: sample_pool_nft,
    oracle_provider: AegisSelf,
    partner_address: None,
    partner_share_bps: 0,
    risk_class: Barrier,
    payout_address: None,
    receipt_commitment: None,
    payout_datum: None,
    settlement_pins: None,
    extension: None,
  }
}

/// The V8.2 head: the fourteen fields every policy has carried since V4.
fn head_fields() -> List<Data> {
  let no_partner: Option<Address> = None
  let policy_id: Data = sample_policy_id
  let insured: Data = sample_insured
  let strike_price: Data = sample_strike
  let coverage_amount: Data = sample_coverage
  let premium_paid: Data = sample_premium
  let start_time: Data = sample_start
  let expiry_time: Data = sample_expiry
  let oracle_nft: Data = sample_oracle_nft
  let pool_script_hash: Data = sample_pool_hash
  let pool_nft: Data = sample_pool_nft
  let oracle_provider: Data = AegisSelf
  let partner_address: Data = no_partner
  let partner_share_bps: Data = 0
  let risk_class: Data = Barrier
  [
    policy_id, insured, strike_price, coverage_amount, premium_paid, start_time,
    expiry_time, oracle_nft, pool_script_hash, pool_nft, oracle_provider,
    partner_address, partner_share_bps, risk_class,
  ]
}

/// The three Option fields appended after V4, all at their default.
fn none_tail() -> List<Data> {
  let no_address: Option<Address> = None
  let no_commitment: Option<ByteArray> = None
  let no_datum: Option<Data> = None
  let payout_address: Data = no_address
  let receipt_commitment: Data = no_commitment
  let payout_datum: Data = no_datum
  [payout_address, receipt_commitment, payout_datum]
}

const sample_payout_pkh: ByteArray =
  #"7c3f1e5a908b2d46e1f0a7c58b39d2604e8a1f37bd902c4a6e5f8013"

const sample_commitment: ByteArray =
  #"5b1d0c7e3a49f286c0d5b8e21f7a634095cd8e1b27f40a6d3e9c5817"

/// An Int, so a decoder that mistakes this slot for `receipt_commitment`
/// crashes on `un_b_data` instead of silently returning the wrong field.
/// A function, not a const: `const _: Data = ..` panics aiken 1.1.22.
/// [#390] A stand-in for what the reserved slot will one day carry — E9 sizes it
/// at one 32-byte hash.
fn sample_extension() -> Data {
  let ext: Data = sample_commitment
  ext
}

fn sample_payout_datum() -> Data {
  let inline: Data = 987_654
  inline
}

/// The same three fields all SET, each to a distinguishable value. `None`
/// everywhere is positionally blind — three `None`s are byte-identical, so a
/// decoder reading the tail at the wrong index would still produce the expected
/// record. These values are what pin index 14/15/16 to their own field.
fn some_tail() -> List<Data> {
  let address: Option<Address> = Some(pkh_addr(sample_payout_pkh))
  let commitment: Option<ByteArray> = Some(sample_commitment)
  let inline: Option<Data> = Some(sample_payout_datum())
  let payout_address: Data = address
  let receipt_commitment: Data = commitment
  let payout_datum: Data = inline
  [payout_address, receipt_commitment, payout_datum]
}

fn constr0(fields: List<Data>) -> Data {
  builtin.constr_data(0, fields)
}

/// A V4-era policy: the fourteen-field head and nothing else.
fn legacy_v4_datum() -> Data {
  constr0(head_fields())
}

/// A V5-era policy: head + a SET payout_address, written before
/// receipt_commitment and payout_datum existed.
fn legacy_v5_datum() -> Data {
  constr0(list.concat(head_fields(), list.take(some_tail(), 1)))
}

/// The current seventeen-field shape.
fn current_datum() -> Data {
  constr0(list.concat(head_fields(), none_tail()))
}

/// A policy from a FUTURE builder that appended two fields this vault has never
/// heard of — they sit BEYOND every slot the decoder knows (the pins slot
/// included, at its default). The deployed vault must ignore them, not fail
/// closed.
/// A datum from a builder that has outgrown this decoder. [#390] Index 18 is
/// no longer part of the unknown tail — it is the RESERVED `extension` slot and
/// is decoded as `Option<Data>`, so a future datum must write a well-formed
/// Option there. The genuinely unknown tail now begins at index 19, and the two
/// junk fields below sit in it. That distinction IS the reservation: before the
/// slot existed, anything at index 18 was ignored, and a later field placed
/// there could not be read by a vault already live.
fn future_datum() -> Data {
  let no_pins: Option<SettlementPins> = None
  let pins: Data = no_pins
  let no_ext: Option<Data> = None
  let ext: Data = no_ext
  let unknown_bytes: Data = #"deadbeef"
  let unknown_int: Data = 42
  constr0(
    list.concat(
      list.concat(head_fields(), none_tail()),
      [pins, ext, unknown_bytes, unknown_int],
    ),
  )
}

/// The hazard this module exists to remove: the direct `expect` the vault used
/// rejects a legacy policy outright. Kept as the regression witness — if this
/// ever stops failing, the arity coupling is gone for a reason worth knowing.
test legacy_datum_is_undecodable_by_direct_expect() fail {
  expect _pd: PolicyDatum = legacy_v4_datum()
  True
}

test legacy_v4_datum_decodes_with_defaulted_tail() {
  decode_policy_datum(legacy_v4_datum()) == expected_policy()
}

/// Index 14 is SET and 15/16 are absent, so this pins `payout_address` to its
/// own slot: a decoder reading the tail one step off finds nothing there and
/// defaults to None.
test legacy_v5_datum_decodes_with_defaulted_tail() {
  decode_policy_datum(legacy_v5_datum()) == PolicyDatum {
    ..expected_policy(),
    payout_address: Some(pkh_addr(sample_payout_pkh)),
  }
}

test current_datum_decodes_unchanged() {
  decode_policy_datum(current_datum()) == expected_policy()
}

/// All three tail slots set to distinguishable values — the case that fails if
/// any of index 14/15/16 is read from the wrong position.
test populated_tail_decodes_by_index() {
  decode_policy_datum(constr0(list.concat(head_fields(), some_tail()))) == PolicyDatum {
    ..expected_policy(),
    payout_address: Some(pkh_addr(sample_payout_pkh)),
    receipt_commitment: Some(sample_commitment),
    payout_datum: Some(sample_payout_datum()),
  }
}

test future_datum_ignores_unknown_tail() {
  decode_policy_datum(future_datum()) == expected_policy()
}

/// The pins a V8.2 Underwrite writes — every value distinguishable so record
/// equality is total over all EIGHT fields.
fn sample_pins() -> SettlementPins {
  SettlementPins {
    fallback_feed_id: #"10",
    publisher_vkh: #"b1",
    observer_script_hash: #"d3",
    max_reading_validity_ms: 7_200_000,
    fallback_grace_ms: 1_800_000,
    cancellation_window_ms: 3_600_000,
    cancellation_fee_bps: 1_000,
    claim_waiting_period_ms: 5_400_000,
  }
}

fn pins_tail() -> List<Data> {
  let pins: Option<SettlementPins> = Some(sample_pins())
  let settlement_pins: Data = pins
  [settlement_pins]
}

/// The pre-append proof S1 demands: a policy written TODAY, while the datum
/// still ends at payout_datum (17 fields), must decode with the pins
/// defaulted — old policies keep settling after the append ships.
test seventeen_field_pre_pins_datum_has_no_pins() {
  decode_policy_datum(current_datum()).settlement_pins == None
}

/// An 18-field V8.2 policy: pins present and read from index 17.
test populated_pins_decode_by_index() {
  decode_policy_datum(
    constr0(
      list.concat(list.concat(head_fields(), some_tail()), pins_tail()),
    ),
  ) == PolicyDatum {
    ..expected_policy(),
    payout_address: Some(pkh_addr(sample_payout_pkh)),
    receipt_commitment: Some(sample_commitment),
    payout_datum: Some(sample_payout_datum()),
    settlement_pins: Some(sample_pins()),
    extension: None,
  }
}

/// [#390 / #403 FIX 5] THE PRE-EXTENSION PROOF, and the one that makes the slot
/// a RESERVATION rather than a rename: an 18-field policy — the shape a V8.2
/// Underwrite writes today — decodes with `extension` defaulted, so every
/// policy minted before the slot is ever used still settles against a vault
/// that knows about it.
test eighteen_field_pre_extension_datum_has_no_extension() {
  decode_policy_datum(
    constr0(list.concat(list.concat(head_fields(), some_tail()), pins_tail())),
  ).extension == None
}

/// ...and a 19-field policy carries it, read from index 18. Without this the
/// slot would be indistinguishable from the unknown tail the decoder already
/// ignores, and the reservation would be a comment rather than a decode.
test populated_extension_decodes_by_index() {
  let ext: Option<Data> = Some(sample_extension())
  let ext_field: Data = ext
  decode_policy_datum(
    constr0(
      list.concat(
        list.concat(list.concat(head_fields(), some_tail()), pins_tail()),
        [ext_field],
      ),
    ),
  ) == PolicyDatum {
    ..expected_policy(),
    payout_address: Some(pkh_addr(sample_payout_pkh)),
    receipt_commitment: Some(sample_commitment),
    payout_datum: Some(sample_payout_datum()),
    settlement_pins: Some(sample_pins()),
    extension: Some(sample_extension()),
  }
}

/// Tail fields default when ABSENT; a PRESENT malformed slot is corruption,
/// never an old policy — same rule the V5/V6 slots already enforce.
test garbage_pins_slot_fails_closed() fail {
  let not_pins: Data = 42
  let pd =
    decode_policy_datum(
      constr0(
        list.concat(list.concat(head_fields(), none_tail()), [not_pins]),
      ),
    )
  pd == pd
}

// The fail-closed tests below assert `pd == pd`, which is True whenever
// decoding returns at all — so they can only pass by CRASHING. Two weaker
// forms both pass for the wrong reason: `let _pd = decode(..)` is eliminated
// before it can crash (200 mem, 16100 cpu — the body never ran), and a
// comparison that returns False satisfies `fail` without any rejection.

/// Head fields are money terms — a policy missing one is malformed, not old.
test truncated_head_fails_closed() fail {
  let pd = decode_policy_datum(constr0(list.take(head_fields(), 13)))
  pd == pd
}

test empty_fields_fail_closed() fail {
  let pd = decode_policy_datum(constr0([]))
  pd == pd
}

/// A different constructor is a different type, never a defaultable policy.
test wrong_constructor_fails_closed() fail {
  let pd = decode_policy_datum(builtin.constr_data(1, head_fields()))
  pd == pd
}
