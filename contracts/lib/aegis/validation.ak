use aegis/types.{ScriptHash, VerificationKeyHash}
// =============================================================================
// Aegis Insurance Protocol - Common Validation Functions
// Location: contracts/lib/aegis/validation.ak
// Summary: Reusable validation helpers used across multiple validators.
//          Provides signature checks, time boundary extraction, output
//          searching by address/pkh/script, and value checks.
//          Used by validators/policy.ak and validators/pool.ak.
// =============================================================================

use aiken/collection/list
use aiken/interval.{Finite}
use cardano/address.{Address, Credential, Script, VerificationKey}
use cardano/assets
use cardano/transaction.{Input, NoDatum, Output, OutputReference, ValidityRange}

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
  when outputs is {
    [] -> None
    [output, ..rest] ->
      when output.address.payment_credential is {
        Script(hash) ->
          if hash == script_hash {
            Some(output)
          } else {
            find_output_to_script(rest, script_hash)
          }
        _ -> find_output_to_script(rest, script_hash)
      }
  }
}

/// Find the first output going to a specific address.
pub fn find_output_to_address(
  outputs: List<Output>,
  target: Address,
) -> Option<Output> {
  when outputs is {
    [] -> None
    [output, ..rest] ->
      if output.address == target {
        Some(output)
      } else {
        find_output_to_address(rest, target)
      }
  }
}

/// [FIX A-013] The legacy `find_output_to_pkh` helper has been removed.
/// Its greedy first-match semantic was the root of two findings:
///   * A-006 — a single payout output satisfied multiple same-insured policies.
///   * A-013 — a hostile prefix output (e.g., a 2-ADA decoy) caused the helper
///             to short-circuit before reaching the legitimate payout, enabling
///             a frontrun-and-DoS attack on Claim/Cancel.
/// All payout / refund call sites now go through `sum_lovelace_to_enterprise_pkh`
/// (or, where stake-credential restrictions don't apply, `sum_lovelace_to_pkh`).
/// If a future caller genuinely needs "find the first output to a PKH", they
/// should write a purpose-specific helper rather than re-introducing this one.
/// [FIX A-006 / A-013] Sum the lovelace across ALL outputs going to a given
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
      when out.address.payment_credential is {
        VerificationKey(hash) ->
          if hash == pkh {
            acc + assets.lovelace_of(out.value)
          } else {
            acc
          }
        _ -> acc
      }
    },
  )
}

/// [FIX A-009] Aggregate lovelace across outputs whose address is an
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
      when out.address.payment_credential is {
        VerificationKey(hash) ->
          if hash == pkh && out.address.stake_credential == None {
            acc + assets.lovelace_of(out.value)
          } else {
            acc
          }
        _ -> acc
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
      when input.output.address.payment_credential is {
        Script(hash) ->
          if hash == script_hash {
            acc + 1
          } else {
            acc
          }
        _ -> acc
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

/// [FIX A-008] Find the first output going to a specific script hash AND
/// carrying the canonical NFT. This is the safe primitive for routing residuals
/// to "the real pool", as opposed to ANY UTxO at the pool address.
pub fn find_canonical_pool_output(
  outputs: List<Output>,
  script_hash: ScriptHash,
  pool_nft: ByteArray,
) -> Option<Output> {
  when outputs is {
    [] -> None
    [output, ..rest] ->
      when output.address.payment_credential is {
        Script(hash) ->
          if hash == script_hash && output_has_nft(output, pool_nft) {
            Some(output)
          } else {
            find_canonical_pool_output(rest, script_hash, pool_nft)
          }
        _ -> find_canonical_pool_output(rest, script_hash, pool_nft)
      }
  }
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
