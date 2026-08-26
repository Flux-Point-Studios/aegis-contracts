// =============================================================================
// Aegis - Pyth tx-level FIXTURES (#381 V8.1 S0 substrate proof)
//
// Whole-Transaction fixtures for the Pyth Lazer resolve path. Until now the
// only tx-level coverage of `pyth.get_updates` lived inside the vendored lib's
// own tests — every Aegis consumer (aegis/oracle/pyth.resolve, the observer's
// genuineness recompute) was exercised purely at the unit level, which the
// V8.1 design red-team called a "fictional foundation". These fixtures make
// the full path executable in-repo: State NFT reference input (pinned to the
// ACTIVE network module's `pyth_state_nft_policy` — derived, never a literal,
// per the #363 N6 lesson) + the Pyth withdraw-script redeemer carrying a REAL
// signed Lazer message.
//
// `pyth_test_update` is copied byte-for-byte from the vendored lib's own
// fixture (pyth-network/pyth-lazer-cardano lib/pyth.ak `test_update`): a
// production-shape signed Lazer payload carrying three feeds —
//   feed 1   (price ~69509 @ exp),        handle #"01"
//   feed 2   (price 201300331620 @ -8),   handle #"02"
//   feed 112 (price 6946927951449 @ -12), handle #"70"
// timestamp_us = 1772613309000000 (-> observed_at 1772613309000 ms).
// =============================================================================

use aegis/types as aegis_types
use cardano/address.{Address, Script}
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction, Withdraw,
  placeholder,
}
use pyth.{Governance, Pyth}

/// The vendored lib's real signed Lazer update (see module header).
pub const pyth_test_update: ByteArray =
  #"b9011a82db446efb9cf488be308398477ab37d650aeb3e06ad7e2424c31a97b4e318026486f544c2bbe17f85a3a158a4c8b628fa078066d7880b6bfbff8278139bf8e40380efc1f480c5615af3fb673d42287e993da9fbc3506b6e41dfa32950820c2e6cfe0075d3c79340699bb22e4c06000303010000000b00529a23605206000001b10d6c5e520600000280ba0b635206000004f8ff0600070008000900000a0008aa99440600000b20e4d495440600000c0140699bb22e4c0600020000000b00644c6fde2e0000000188a660de2e000000028a17ddde2e00000004f8ff0600070008000900000ae01c1a742e0000000b8898ec732e0000000c0140699bb22e4c0600700000000b00593e2c755106000001000000000000000002000000000000000004f4ff0601d809000000000000070129229ab22e4c0600080100209db4060000000900000a00000000000000000b00000000000000000c0140699bb22e4c0600"

/// The fixture Pyth withdraw-script hash the State datum names.
pub const pyth_test_withdraw_hash: ByteArray = #"900d"

/// Expected values for feed 2 (handle #"02") after Aegis renormalisation:
/// raw 201300331620 @ exponent -8 -> x10^(-8+6) -> floor(/100).
pub const feed2_value_1e6: Int = 2_013_003_316

/// Expected values for feed 112 (handle #"70"):
/// raw 6946927951449 @ exponent -12 -> floor(/10^6).
pub const feed112_value_1e6: Int = 6_946_927

/// update.timestamp_us / 1000.
pub const feed_observed_at_ms: Int = 1_772_613_309_000

/// The Pyth State datum. Only `withdraw_script` (and the deprecated list) are
/// read by get_updates — governance fields are inert for the resolve path.
pub fn pyth_state() -> Pyth {
  Pyth(
    Governance(aegis_types.pyth_state_nft_policy, 0, #"", 0),
    [],
    [],
    pyth_test_withdraw_hash,
  )
}

/// The State NFT reference input: exactly one "Pyth State" token under the
/// ACTIVE network module's pinned policy, at a Script address, inline datum.
pub fn pyth_state_ref_input() -> Input {
  Input(
    OutputReference(#"", 0),
    Output {
      address: Address(Script(#""), None),
      value: assets.from_asset(
        aegis_types.pyth_state_nft_policy,
        "Pyth State",
        1,
      ),
      datum: InlineDatum(pyth_state()),
      reference_script: None,
    },
  )
}

/// A minimal Transaction satisfying `pyth.get_updates(pyth_state_nft_policy, _)`:
/// the State reference input + the Pyth withdraw-script redeemer carrying the
/// signed update. Extend via `..pyth_tx()` for consumer-specific fields.
pub fn pyth_tx() -> Transaction {
  let raw_updates: Data = [pyth_test_update]
  Transaction {
    ..placeholder,
    reference_inputs: [pyth_state_ref_input()],
    redeemers: [
      Pair(Withdraw(Script(pyth_test_withdraw_hash)), raw_updates),
    ],
  }
}

/// As pyth_tx but the redeemer sits under a DIFFERENT withdraw script than the
/// one the State datum names — get_updates must reject it.
pub fn pyth_tx_wrong_withdraw() -> Transaction {
  let raw_updates: Data = [pyth_test_update]
  Transaction {
    ..placeholder,
    reference_inputs: [pyth_state_ref_input()],
    redeemers: [Pair(Withdraw(Script(#"1bad")), raw_updates)],
  }
}

/// As pyth_tx but WITHOUT the State reference input — get_updates must abort.
pub fn pyth_tx_no_state() -> Transaction {
  let raw_updates: Data = [pyth_test_update]
  Transaction {
    ..placeholder,
    redeemers: [
      Pair(Withdraw(Script(pyth_test_withdraw_hash)), raw_updates),
    ],
  }
}
