// =============================================================================
// Aegis - PREPROD Pyth withdraw script (#381 V8.1 S10 / OQ1)
// Location: contracts/validators/pyth_withdraw_preprod.ak
//
// Pyth's REAL mainnet withdraw script compiles the MAINNET State NFT policy
// (c935c937…) and the "Pyth State" name into its body (verified by byte-probe
// of the CIP-33 script on State UTxO 20dedb9c…#0), so it can never resolve a
// preprod State we mint ourselves — the byte-identical-script path is a hard
// limit. This validator is the preprod stand-in with the SAME architecture and
// the SAME trust root: locate the State by a compiled-in NFT policy (ours),
// read trusted_signers from its inline datum, and verify every update in the
// redeemer with the vendored lib's OWN parse_and_verify — the production
// Ed25519 signature over the production envelope, checked on-chain. Only the
// State policy id and this script's hash differ from mainnet; every consumer
// keys off the State datum's withdraw_script field, so nothing else changes.
//
// PREPROD-ONLY. Never name this script in a mainnet State datum — mainnet
// resolves Pyth's own deployment.
//
// Registration: the reward account is registered with a LEGACY StakeRegistration
// cert (no credential witness required), and every non-withdraw purpose fails —
// so deregistration (which DOES require the witness) can never validate, the
// registration is permanent, and the withdrawal path cannot be griefed away.
// =============================================================================

use aegis/test_helpers/pyth_fixtures
use aiken/collection/list
use aiken/interval
use aiken/primitive/bytearray
use cardano/address.{Credential, Script}
use cardano/assets
use cardano/transaction.{InlineDatum, Transaction}
use pyth.{Governance, Pyth}
use pyth/message

validator pyth_withdraw_preprod(state_nft_policy: ByteArray) {
  withdraw(redeemer: Data, _account: Credential, self: Transaction) {
    expect updates: List<ByteArray> = redeemer
    expect Some(state) =
      list.find_map(
        self.reference_inputs,
        fn(input) {
          if assets.has_nft_strict(
            input.output.value,
            state_nft_policy,
            "Pyth State",
          ) {
            expect Script(_) = input.output.address.payment_credential
            expect InlineDatum(d) = input.output.datum
            expect s: Pyth = d
            Some(s)
          } else {
            None
          }
        },
      )
    updates != [] && list.all(
      updates,
      fn(m) {
        let msg =
          message.parse_and_verify(
            m,
            state.trusted_signers,
            self.validity_range,
          )
        // load-bearing consumption — an unused parse result gets elided.
        bytearray.length(msg.signature) == 64
      },
    )
  }

  else(_) {
    fail @"pyth_withdraw_preprod: withdraw only"
  }
}

// ===========================================================================
// Tests ride the REAL production-signed Lazer payload (pyth_fixtures) and the
// REAL signer key from the mainnet State datum (80efc1f4…, valid to epoch-ms
// 1_809_450_000_000 ≈ 2027-05), so a pass here proves the exact signature the
// preprod drill will verify on-chain.
// ===========================================================================

const pw_policy: ByteArray = #"5077aa"

const pw_signer: ByteArray =
  #"80efc1f480c5615af3fb673d42287e993da9fbc3506b6e41dfa32950820c2e6c"

const pw_cred: Credential = Script(#"93d7")

fn pw_state(signer: ByteArray) -> Pyth {
  Pyth {
    governance: Governance {
      wormhole: pw_policy,
      emitter_chain: 0,
      emitter_address: #"",
      seen_sequence: 0,
    },
    trusted_signers: [Pair(signer, interval.before(1_809_450_000_000))],
    deprecated_withdraw_scripts: [],
    withdraw_script: #"93d7",
  }
}

fn pw_tx(signer: ByteArray) -> Transaction {
  let base = pyth_fixtures.pyth_tx()
  let state_in = pyth_fixtures.pyth_state_ref_input()
  let state_out = state_in.output
  Transaction {
    ..base,
    reference_inputs: [
      transaction.Input {
        output_reference: state_in.output_reference,
        output: transaction.Output {
          ..state_out,
          value: assets.from_asset(pw_policy, "Pyth State", 1),
          datum: InlineDatum(pw_state(signer)),
        },
      },
    ],
    validity_range: interval.between(1_772_613_000_000, 1_772_614_000_000),
  }
}

test pw_verifies_real_production_signature() {
  let updates: Data = [pyth_fixtures.pyth_test_update]
  pyth_withdraw_preprod.withdraw(pw_policy, updates, pw_cred, pw_tx(pw_signer))
}

test pw_rejects_tampered_payload() fail {
  // flip the last byte of the signed message — Ed25519 must refuse.
  let m = pyth_fixtures.pyth_test_update
  let n = bytearray.length(m)
  let tampered =
    bytearray.concat(bytearray.take(m, n - 1), #"ff")
  let updates: Data = [tampered]
  pyth_withdraw_preprod.withdraw(pw_policy, updates, pw_cred, pw_tx(pw_signer))
}

test pw_rejects_untrusted_signer() fail {
  // the State datum trusts a DIFFERENT key -> is_trusted False.
  let updates: Data = [pyth_fixtures.pyth_test_update]
  let other =
    #"74313a6525edf99936aa1477e94c72bc5cc617b21745f5f03296f3154461f214"
  pyth_withdraw_preprod.withdraw(pw_policy, updates, pw_cred, pw_tx(other))
}

test pw_rejects_expired_signer_validity() fail {
  // tx validity past the signer's trusted window -> is_trusted False.
  let updates: Data = [pyth_fixtures.pyth_test_update]
  let base = pw_tx(pw_signer)
  let tx =
    Transaction {
      ..base,
      validity_range: interval.between(
        1_809_450_000_001,
        1_809_460_000_000,
      ),
    }
  pyth_withdraw_preprod.withdraw(pw_policy, updates, pw_cred, tx)
}

test pw_rejects_empty_update_list() fail {
  let empty: List<ByteArray> = []
  let updates: Data = empty
  pyth_withdraw_preprod.withdraw(pw_policy, updates, pw_cred, pw_tx(pw_signer))
}

test pw_rejects_missing_state() fail {
  let updates: Data = [pyth_fixtures.pyth_test_update]
  let base = pw_tx(pw_signer)
  let tx = Transaction { ..base, reference_inputs: [] }
  pyth_withdraw_preprod.withdraw(pw_policy, updates, pw_cred, tx)
}
