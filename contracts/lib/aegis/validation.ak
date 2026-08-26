use aegis/types.{ScriptHash, VerificationKeyHash}
// =============================================================================
// Aegis Insurance Protocol - Common Validation Functions
// Location: contracts/lib/aegis/validation.ak
// Summary: Reusable validation helpers used across multiple validators.
//          Provides signature checks, time boundary extraction, output
//          searching by address/pkh/script, and value checks.
//          Used by validators/policy.ak, validators/pool.ak, and
//          validators/policy_marker.ak.
// =============================================================================

use aiken/collection/list
use aiken/interval.{Finite}
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, ValidityRange,
}

// ---------------------------------------------------------------------------
// Signature Checks
// ---------------------------------------------------------------------------

/// Check that a specific verification key hash is in the extra signatories.
pub fn must_be_signed_by(
  extra_signatories: List<VerificationKeyHash>,
  pkh: VerificationKeyHash,
) -> Bool {
  list.has(extra_signatories, pkh)
}

// ---------------------------------------------------------------------------
// Time Boundary Extraction
// ---------------------------------------------------------------------------

/// Extract the lower bound from a validity range as a definite POSIX time.
/// Fails if the lower bound is not finite.
pub fn get_lower_bound(range: ValidityRange) -> Int {
  when range.lower_bound.bound_type is {
    Finite(time) -> time
    _ -> fail @"Transaction has no finite lower bound"
  }
}

/// Extract the upper bound from a validity range as a definite POSIX time.
/// Fails if the upper bound is not finite.
pub fn get_upper_bound(range: ValidityRange) -> Int {
  when range.upper_bound.bound_type is {
    Finite(time) -> time
    _ -> fail @"Transaction has no finite upper bound"
  }
}

// ---------------------------------------------------------------------------
// Output Searching
// ---------------------------------------------------------------------------

/// Find the first output going to a specific script hash.
/// Matches on the payment credential of the output address.
pub fn find_output_to_script(
  outputs: List<Output>,
  script_hash: ScriptHash,
) -> Option<Output> {
  list.find(
    outputs,
    fn(output) {
      output.address.payment_credential == Script(script_hash)
    },
  )
}

/// Find the first output going to a specific address.
pub fn find_output_to_address(
  outputs: List<Output>,
  target: Address,
) -> Option<Output> {
  list.find(outputs, fn(output) { output.address == target })
}

/// The legacy `find_output_to_pkh` helper has been removed.
/// Its greedy first-match semantic was the root of two findings:
///   * A-006 — a single payout output satisfied multiple same-insured policies.
///   * A-013 — a hostile prefix output (e.g., a 2-ADA decoy) caused the helper
///             to short-circuit before reaching the legitimate payout, enabling
///             a frontrun-and-DoS attack on Claim/Cancel.
/// All payout / refund call sites now go through `sum_lovelace_to_enterprise_pkh`
/// (or, where stake-credential restrictions don't apply, `sum_lovelace_to_pkh`).
/// If a future caller genuinely needs "find the first output to a PKH", they
/// should write a purpose-specific helper rather than re-introducing this one.
/// Sum the lovelace across ALL outputs going to a given
/// payment key hash. This is the safe primitive for verifying that an insured
/// (or refund recipient) has been paid AT LEAST a required amount: callers
/// compare `sum_lovelace_to_pkh(...) >= required` rather than relying on
/// "the first matching output has enough".
///
/// **Note (A-009):** this helper does NOT constrain `stake_credential`. It is
/// retained for non-payout aggregation (e.g., refund analytics, accounting).
/// For payout outputs that carry value to the insured, callers MUST instead
/// use `sum_lovelace_to_enterprise_pkh` so a hostile claim-bot cannot graft
/// its own stake credential onto the insured's payout and skim staking
/// rewards. See the A-009 finding in SECURITY_AUDIT_REPORT.md.
pub fn sum_lovelace_to_pkh(
  outputs: List<Output>,
  pkh: VerificationKeyHash,
) -> Int {
  list.foldl(
    outputs,
    0,
    fn(out, acc) {
      if out.address.payment_credential == VerificationKey(pkh) {
        acc + assets.lovelace_of(out.value)
      } else {
        acc
      }
    },
  )
}

/// Aggregate lovelace across outputs whose address is an
/// **enterprise** address controlled by `pkh` — i.e., `payment_credential`
/// is the insured's verification key AND `stake_credential` is `None`.
///
/// On Cardano, an address is `(payment, stake)`. Spending is gated by the
/// payment credential, but staking rewards accrue to whoever controls the
/// stake credential. Aegis claim transactions can be assembled by anyone
/// (parametric trigger — once the oracle prints below strike, any keeper
/// or MEV bot can build the tx). A malicious keeper can therefore hand-craft
/// the payout output as
///   `Address(payment = VerificationKey(insured), stake = Some(attacker))`
/// and the insured retains spending control while the attacker farms the
/// staking rewards until the insured re-spends the UTxO.
///
/// Forcing the payout to an enterprise address (no stake credential) closes
/// this hole: there are simply no staking rewards on enterprise UTxOs. The
/// insured can re-spend into a delegated address at their leisure.
pub fn sum_lovelace_to_enterprise_pkh(
  outputs: List<Output>,
  pkh: VerificationKeyHash,
) -> Int {
  list.foldl(
    outputs,
    0,
    fn(out, acc) {
      if out.address.payment_credential == VerificationKey(pkh) && out.address.stake_credential == None {
        acc + assets.lovelace_of(out.value)
      } else {
        acc
      }
    },
  )
}

/// [V5] Sum lovelace across ALL outputs whose FULL address (payment AND stake
/// credential) structurally equals `target`. This is the payout primitive for
/// a `payout_address`-bound policy (e.g. a DAO treasury script).
///
/// The exact-Address match is load-bearing for A-009: the target is committed
/// in the policy datum by the buyer at Underwrite, so a permissionless
/// claim-bot cannot graft its own stake credential onto the payout (a grafted
/// stake makes `out.address != target`, contributing 0). Matching only the
/// payment credential would re-open A-009 for the key case. Like the enterprise
/// helper it MUST sum via `foldl` — never first-match (the A-006 / A-013 lesson
/// that retired `find_output_to_pkh`).
pub fn sum_lovelace_to_address(outputs: List<Output>, target: Address) -> Int {
  list.foldl(
    outputs,
    0,
    fn(out, acc) {
      if out.address == target {
        acc + assets.lovelace_of(out.value)
      } else {
        acc
      }
    },
  )
}

/// [V6 / #325 Plutus-treasury] Sum lovelace across ALL outputs whose FULL
/// address structurally equals `target` AND that carry `InlineDatum(inline)`
/// exactly. This is the payout primitive for a `payout_address`-bound policy
/// that ALSO committed a `payout_datum` (a Plutus/V2-V3 DAO treasury).
///
/// The ledger requires a datum to invoke a Plutus spend script; a datum-less
/// coverage output locks at such a treasury forever. Requiring the committed
/// inline datum (buyer-committed at Underwrite, so a permissionless claim-bot
/// cannot substitute its own) makes the coverage spendable by the treasury's
/// own validator. Like `sum_lovelace_to_address` it MUST sum via `foldl` —
/// never first-match (the A-006 / A-013 lesson) — and pins the FULL address
/// (A-009). Datum equality is structural (`equalsData`), so a treasury that
/// pattern-matches its datum gets exactly the value it expects.
pub fn sum_lovelace_to_address_with_inline_datum(
  outputs: List<Output>,
  target: Address,
  inline: Data,
) -> Int {
  list.foldl(
    outputs,
    0,
    fn(out, acc) {
      if out.address == target && out.datum == InlineDatum(inline) {
        acc + assets.lovelace_of(out.value)
      } else {
        acc
      }
    },
  )
}

// ---------------------------------------------------------------------------
// Input Counting (Double Satisfaction Prevention)
// ---------------------------------------------------------------------------

/// Count the number of inputs from a specific script hash.
/// Used to prevent double satisfaction attacks by ensuring only
/// one input from a given script is consumed per transaction.
pub fn count_script_inputs(inputs: List<Input>, script_hash: ScriptHash) -> Int {
  list.foldl(
    inputs,
    0,
    fn(input, acc) {
      if input.output.address.payment_credential == Script(script_hash) {
        acc + 1
      } else {
        acc
      }
    },
  )
}

// ---------------------------------------------------------------------------
// Value Checks
// ---------------------------------------------------------------------------

/// Check that an output contains at least the specified lovelace amount.
pub fn output_has_min_lovelace(output: Output, min_lovelace: Int) -> Bool {
  assets.lovelace_of(output.value) >= min_lovelace
}

/// Check that an output contains a specific NFT (identified by policy ID).
pub fn output_has_nft(output: Output, nft_policy: ByteArray) -> Bool {
  assets.policies(output.value)
    |> list.has(nft_policy)
}

/// Find the first output going to a specific script hash AND
/// carrying the canonical NFT. This is the safe primitive for routing residuals
/// to "the real pool", as opposed to ANY UTxO at the pool address.
pub fn find_canonical_pool_output(
  outputs: List<Output>,
  script_hash: ScriptHash,
  pool_nft: ByteArray,
) -> Option<Output> {
  list.find(
    outputs,
    fn(output) {
      output.address.payment_credential == Script(script_hash) && output_has_nft(
        output,
        pool_nft,
      )
    },
  )
}

/// Scan the tx inputs for one whose VALUE contains ≥1 of the canonical
/// pool NFT `(pool_nft_policy_id, pool_nft_asset_name)`. Used by
/// `validators/policy_marker.ak` to delegate mint/burn authority to the
/// pool validator's spend logic — only a transaction that consumes the
/// canonical pool UTxO can produce or burn a marker, and the pool's own
/// spend rules constrain what that spend can be (Underwrite /
/// BatchUnderwrite for mint; ProcessClaim / AcceptCancellation /
/// BatchExpireProcess for burn).
///
/// Pinned on the NFT (not the script hash) so the marker is bound to the
/// SPECIFIC canonical pool, not just any UTxO at the pool script address.
/// This is also what breaks the V12.2+R12 parameterization cycle: the
/// one-shot `pool_nft` policy id is computed BEFORE either the pool or
/// the policy validator is parameterized, so the marker policy can
/// reference it without inducing a circular hash dependency.
///
/// Lifted into `lib/aegis/validation.ak` (rather than living inside the
/// marker validator) so the EXT-08 / EXT-09 / EXT-10 / EXT-11 regression
/// tests can exercise this predicate directly with real
/// `Transaction.inputs` fixtures, rather than re-encoding the boolean
/// shape as constants.
pub fn pool_is_consumed_via_nft(
  inputs: List<Input>,
  pool_nft_policy_id: ByteArray,
  pool_nft_asset_name: ByteArray,
) -> Bool {
  list.any(
    inputs,
    fn(input) {
      assets.quantity_of(
        input.output.value,
        pool_nft_policy_id,
        pool_nft_asset_name,
      ) >= 1
    },
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test signed_by_present() {
  let signatories =
    [
      #"aabb00112233445566778899aabb00112233445566778899aabb0011",
      #"ccdd00112233445566778899ccdd00112233445566778899ccdd0011",
    ]
  must_be_signed_by(
    signatories,
    #"aabb00112233445566778899aabb00112233445566778899aabb0011",
  ) == True
}

test signed_by_absent() {
  let signatories =
    [#"aabb00112233445566778899aabb00112233445566778899aabb0011"]
  must_be_signed_by(
    signatories,
    #"ccdd00112233445566778899ccdd00112233445566778899ccdd0011",
  ) == False
}

test signed_by_empty() {
  must_be_signed_by(
    [],
    #"aabb00112233445566778899aabb00112233445566778899aabb0011",
  ) == False
}

// ---------------------------------------------------------------------------
// Security Tests: count_script_inputs (Double Satisfaction Prevention)
// ---------------------------------------------------------------------------

test count_script_inputs_empty_list() {
  count_script_inputs(
    [],
    #"aabb00112233445566778899aabb00112233445566778899aabb0011",
  ) == 0
}

test count_script_inputs_single_match() {
  // Verifies counting a single script input correctly
  let script_hash = #"aabb00112233445566778899aabb00112233445566778899aabb0011"
  let fake_input =
    Input {
      output_reference: OutputReference {
        transaction_id: #"0000000000000000000000000000000000000000000000000000000000000001",
        output_index: 0,
      },
      output: Output {
        address: Address {
          payment_credential: Script(script_hash),
          stake_credential: None,
        },
        value: assets.from_lovelace(5_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    }
  count_script_inputs([fake_input], script_hash) == 1
}

test count_script_inputs_multiple_same_script() {
  // Two inputs from the same script should be counted as 2
  // This is the scenario the double-satisfaction fix prevents
  let script_hash = #"aabb00112233445566778899aabb00112233445566778899aabb0011"
  let make_input =
    fn(idx) {
      Input {
        output_reference: OutputReference {
          transaction_id: #"0000000000000000000000000000000000000000000000000000000000000001",
          output_index: idx,
        },
        output: Output {
          address: Address {
            payment_credential: Script(script_hash),
            stake_credential: None,
          },
          value: assets.from_lovelace(5_000_000),
          datum: NoDatum,
          reference_script: None,
        },
      }
    }
  count_script_inputs([make_input(0), make_input(1)], script_hash) == 2
}

test count_script_inputs_different_scripts_not_counted() {
  // Inputs from different scripts should not be counted
  let target_hash = #"aabb00112233445566778899aabb00112233445566778899aabb0011"
  let other_hash = #"ccdd00112233445566778899ccdd00112233445566778899ccdd0011"
  let other_input =
    Input {
      output_reference: OutputReference {
        transaction_id: #"0000000000000000000000000000000000000000000000000000000000000001",
        output_index: 0,
      },
      output: Output {
        address: Address {
          payment_credential: Script(other_hash),
          stake_credential: None,
        },
        value: assets.from_lovelace(5_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    }
  count_script_inputs([other_input], target_hash) == 0
}

test count_script_inputs_pubkey_inputs_not_counted() {
  // Inputs from pubkey addresses should not be counted
  let target_hash = #"aabb00112233445566778899aabb00112233445566778899aabb0011"
  let pkh_input =
    Input {
      output_reference: OutputReference {
        transaction_id: #"0000000000000000000000000000000000000000000000000000000000000001",
        output_index: 0,
      },
      output: Output {
        address: Address {
          payment_credential: VerificationKey(target_hash),
          stake_credential: None,
        },
        value: assets.from_lovelace(5_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    }
  count_script_inputs([pkh_input], target_hash) == 0
}

// ---------------------------------------------------------------------------
// [V5] sum_lovelace_to_address — exact full-Address payout primitive
// ---------------------------------------------------------------------------

fn addr_output(addr: Address, lovelace: Int) -> Output {
  Output {
    address: addr,
    value: assets.from_lovelace(lovelace),
    datum: NoDatum,
    reference_script: None,
  }
}

test sum_to_address_exact_script_match_accepts() {
  // A DAO treasury SCRIPT address (enterprise) is paid in full — the V4
  // enterprise-PKH helper would have skipped this Script-credential output.
  let target =
    Address { payment_credential: Script(#"abcd"), stake_credential: None }
  sum_lovelace_to_address([addr_output(target, 5_000_000)], target) == 5_000_000
}

test sum_to_address_grafted_stake_rejected() {
  // A-009: a permissionless claim-bot grafts its own stake credential onto the
  // committed script payout. Full-Address equality fails -> contributes 0.
  let target =
    Address { payment_credential: Script(#"abcd"), stake_credential: None }
  let grafted =
    Address {
      payment_credential: Script(#"abcd"),
      stake_credential: Some(Inline(VerificationKey(#"deadbeef"))),
    }
  sum_lovelace_to_address([addr_output(grafted, 5_000_000)], target) == 0
}

test sum_to_address_aggregates_split_outputs() {
  // MUST sum (foldl), never first-match: split payout across two outputs
  // to the exact target still aggregates (A-006 / A-013).
  let target =
    Address { payment_credential: Script(#"abcd"), stake_credential: None }
  sum_lovelace_to_address(
    [addr_output(target, 3_000_000), addr_output(target, 4_000_000)],
    target,
  ) == 7_000_000
}

test sum_to_address_ignores_unrelated() {
  let target =
    Address { payment_credential: Script(#"abcd"), stake_credential: None }
  let other =
    Address { payment_credential: Script(#"ef01"), stake_credential: None }
  sum_lovelace_to_address([addr_output(other, 5_000_000)], target) == 0
}

test sum_to_address_delegated_target_accepts_exact() {
  // A DAO may commit a DELEGATED (base) script address; the exact match
  // including the committed stake credential is accepted.
  let stake = Inline(VerificationKey(#"57a4e0"))
  let target =
    Address { payment_credential: Script(#"abcd"), stake_credential: Some(stake) }
  sum_lovelace_to_address([addr_output(target, 9_000_000)], target) == 9_000_000
}

// ---------------------------------------------------------------------------
// [V6 / #325] sum_lovelace_to_address_with_inline_datum — datum-gated payout
// ---------------------------------------------------------------------------

fn addr_output_with_datum(addr: Address, inline: Data, lovelace: Int) -> Output {
  Output {
    address: addr,
    value: assets.from_lovelace(lovelace),
    datum: InlineDatum(inline),
    reference_script: None,
  }
}

test sum_with_datum_matching_inline_accepts() {
  // Coverage to the committed script address carrying the EXACT committed
  // inline datum is counted — the Plutus treasury can spend it.
  let target =
    Address { payment_credential: Script(#"abcd"), stake_credential: None }
  let d: Data = 42
  sum_lovelace_to_address_with_inline_datum(
    [addr_output_with_datum(target, d, 5_000_000)],
    target,
    d,
  ) == 5_000_000
}

test sum_with_datum_datumless_rejected() {
  // A datum-less output to the committed address contributes 0: a Plutus
  // treasury could not spend it, so the Claim must not count it.
  let target =
    Address { payment_credential: Script(#"abcd"), stake_credential: None }
  let d: Data = 42
  sum_lovelace_to_address_with_inline_datum(
    [addr_output(target, 5_000_000)],
    target,
    d,
  ) == 0
}

test sum_with_datum_mismatched_inline_rejected() {
  // The output carries a DIFFERENT inline datum than committed -> 0.
  let target =
    Address { payment_credential: Script(#"abcd"), stake_credential: None }
  let committed: Data = 42
  let other: Data = 7
  sum_lovelace_to_address_with_inline_datum(
    [addr_output_with_datum(target, other, 5_000_000)],
    target,
    committed,
  ) == 0
}

test sum_with_datum_grafted_stake_rejected() {
  // Exact datum but a grafted stake credential -> full-Address mismatch -> 0.
  let d: Data = 42
  let target =
    Address { payment_credential: Script(#"abcd"), stake_credential: None }
  let grafted =
    Address {
      payment_credential: Script(#"abcd"),
      stake_credential: Some(Inline(VerificationKey(#"deadbeef"))),
    }
  sum_lovelace_to_address_with_inline_datum(
    [addr_output_with_datum(grafted, d, 5_000_000)],
    target,
    d,
  ) == 0
}

test sum_with_datum_aggregates_split_outputs() {
  // Split payout across two exact (address + datum) outputs still aggregates.
  let target =
    Address { payment_credential: Script(#"abcd"), stake_credential: None }
  let d: Data = 42
  sum_lovelace_to_address_with_inline_datum(
    [
      addr_output_with_datum(target, d, 3_000_000),
      addr_output_with_datum(target, d, 4_000_000),
    ],
    target,
    d,
  ) == 7_000_000
}
