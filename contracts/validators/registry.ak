use aegis/registry.{
  CancelUpdate, EnactUpdate, ProposeUpdate, RegistryDatum, RegistryRedeemer,
  admin_signed, check_cancel, check_enact, check_propose,
}
use aegis/validation.{get_lower_bound, get_upper_bound}
use aiken/collection/dict
use aiken/collection/list
use cardano/assets
use cardano/transaction.{InlineDatum, OutputReference, Transaction}

// =============================================================================
// Aegis V8 — Governance Registry (#362 §2.2)
// Location: contracts/validators/registry.ak
//
// The single fast-swap surface of the stable-vault architecture. One UTxO,
// identified by a one-shot NFT (reuse `pool_nft.pool_nft` applied with a fresh
// seed + name "AEGIS_REGISTRY"), whose inline `RegistryDatum` names the current
// eligibility `RuleSet`. The vault reads it as a REFERENCE input; nothing here
// can reach LP principal.
//
// State machine (pure, unit-tested in lib/aegis/registry.ak):
//   ProposeUpdate  admin M-of-N; single pending; >=72h timelock from tx.upper;
//                  optional new_admin (the team-multisig -> cMATRA handover)
//   EnactUpdate    permissionless once tx.lower >= effective_after; epoch++
//   CancelUpdate   admin M-of-N; clears pending; arms a 24h re-propose cooldown
//
// This wrapper enforces the UTxO facts the pure checks assume:
//   * the spent input carries the registry NFT (it IS the singleton)
//   * exactly ONE continuation output at the SAME FULL address (payment +
//     stake pinned — no stake-credential grafting) carrying the NFT
//   * non-lovelace value is EXACTLY preserved and lovelace never decreases
//     (no skim, no token injection)
//   * nothing mints/burns under the registry NFT policy (default-deny; the
//     one-shot policy enforces this too — belt and braces)
//   * validity bounds are finite where a check consumes them (the helpers
//     fail closed on infinite bounds)
// =============================================================================

validator registry_validator(
  registry_nft_policy: ByteArray,
  registry_nft_name: ByteArray,
) {
  spend(
    datum: Option<RegistryDatum>,
    redeemer: RegistryRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    let Transaction {
      inputs,
      outputs,
      mint,
      extra_signatories,
      validity_range,
      ..
    } = self

    expect Some(old) = datum
    expect Some(own_input) =
      list.find(inputs, fn(i) { i.output_reference == own_ref })
    let own_addr = own_input.output.address

    // The spent input must be the NFT-bearing singleton — a datum-forged decoy
    // UTxO at this address cannot exercise the state machine.
    let spends_singleton =
      assets.quantity_of(
        own_input.output.value,
        registry_nft_policy,
        registry_nft_name,
      ) == 1

    // Exactly one continuation output at the same FULL address, carrying the
    // NFT, with the successor datum inline.
    expect [cont] = list.filter(outputs, fn(o) { o.address == own_addr })
    let nft_continues =
      assets.quantity_of(cont.value, registry_nft_policy, registry_nft_name) == 1
    expect InlineDatum(raw_new) = cont.datum
    expect new: RegistryDatum = raw_new

    // Value discipline: assets exactly preserved, lovelace never decreases.
    let value_ok = and {
        assets.without_lovelace(cont.value) == assets.without_lovelace(
          own_input.output.value,
        ),
        assets.lovelace_of(cont.value) >= assets.lovelace_of(
          own_input.output.value,
        ),
      }

    // Default-deny: this tx touches nothing under the registry NFT policy.
    let no_registry_mint = dict.is_empty(assets.tokens(mint, registry_nft_policy))

    let signed = admin_signed(old.admin, extra_signatories)

    let transition_ok =
      when redeemer is {
        ProposeUpdate ->
          check_propose(
            old,
            new,
            get_lower_bound(validity_range),
            get_upper_bound(validity_range),
            signed,
          )
        EnactUpdate -> check_enact(old, new, get_lower_bound(validity_range))
        CancelUpdate ->
          check_cancel(old, new, get_upper_bound(validity_range), signed)
      }

    and {
      spends_singleton,
      nft_continues,
      value_ok,
      no_registry_mint,
      transition_ok,
    }
  }

  else(_) {
    fail @"Unsupported purpose for the registry validator"
  }
}
