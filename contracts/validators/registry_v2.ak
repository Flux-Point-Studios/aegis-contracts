use aegis/registry.{
  Admin, CancelUpdate, EnactUpdate, ProposeUpdate, RegistryRedeemer,
  admin_signed,
}
use aegis/registry_v2.{
  Budgets, Fee, Floors, PendingUpdate, RegistryDatum, SettlementPins,
  UnderwriteConfig, check_cancel, check_enact, check_propose,
}
use aegis/test_helpers/fixtures
use aegis/types.{
  AegisSelf, OracleMandate, TrailingLowLeg, cancel_cooldown_ms,
  registry_timelock_ms,
}
use aegis/validation.{get_lower_bound, get_upper_bound}
use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}

// =============================================================================
// Aegis V8.2 — Governance Registry, second generation (#362 §4)
// Location: contracts/validators/registry_v2.ak
//
// The config authority the vault authenticates BY NFT — never by address, never
// by this script's hash. Its datum carries the GOVERNED set (mandates,
// publisher VKH, feed allowlists, floors, admissible providers, budgets, fee
// split, settlement pins) so that much does not have to live in pool_vault's
// compiled hash.
//
// `observer_hash` is in the datum too and is NOT one of them. It is a MIRROR of
// pool_vault's CORE `observer_script_hash`, bound equal to it at Underwrite:
// `attested_price` reads the Price out of the redeemer of `Script(h)`, so the
// identity of that hash IS the price's genuineness, and governing it made the
// Underwrite spot buyer-authored (G10 red-team CRITICAL). This module keeps only
// a SHAPE bound on it — `bytearray.length == 28` — deliberately: the equality
// needs pool_vault's own parameter, which the registry must never learn or the
// two scripts' hashes become mutually dependent. Same argument as the fee sink.
//
// Not everything in the datum is READ, either. `budgets.utilisation_bps` and the
// whole `floors` record are carried and rail-checked but consulted by no
// validator: the book cap is the literal `nc * 3` in vault.ak and the floors are
// compiled constants in floor_table.ak. Enacting them changes nothing today,
// which is a live hazard for the slice that de-constantises them — every value
// silently enacted in the interim would go live at once, with no further
// governance action. Each field's doc comment in lib/aegis/registry_v2.ak says
// which of the two it is.
//
// The state machine is pure and unit-tested in
// lib/aegis/registry_v2.ak; this wrapper enforces the UTxO facts it assumes:
//   * the spent input carries the registry NFT (it IS the singleton)
//   * exactly ONE continuation at the SAME FULL address (payment + stake, so
//     no stake-credential grafting) carrying the NFT with the successor datum
//   * non-lovelace value EXACTLY preserved, lovelace never decreasing
//   * nothing mints or burns under the registry NFT policy (default-deny)
//
// THREE ARMS, AND THE LIST IS FROZEN (V82-IMMUTABLE-CORE §4.5):
//   ProposeUpdate  admin M-of-N; single pending; waits the OLD in-datum
//                  timelock, floored per network
//   EnactUpdate    PERMISSIONLESS once tx.lower >= effective_after; epoch++
//   CancelUpdate   admin M-of-N; clears the pending; arms the re-propose
//                  cooldown as an EXACT window, not an open ray
//
// There is NO relocation arm, and adding one later is a new generation, not an
// append. The hatch would sit inside the room it escapes: relocation would ride
// `check_propose`, which is gated on `admin_signed` AND `cooldown_until`, and
// every brick class this project has actually produced is a brick of exactly
// those two gates. A quorum that can no longer reach M fails `admin_signed`, so
// it fails relocation too; a `cooldown_until` inflated past any reachable
// validity range blocks every propose, so it blocks the relocation propose too.
// The arm is live only where the registry is healthy enough not to need it.
// The freeze is also cheap to reverse: frozen -> relocatable costs ONE vault
// generation and that migration is soft, because RemoveLiquidity reads no
// registry and the outstanding book settles off its own POLICY pins.
//
// The GENESIS datum is deliberately not re-validated by any arm. Genesis is an
// unvalidated payment, so `registry_v2.check_genesis` can only ever run
// off-chain — `offchain/scripts/_common.validate_config_rails` is that mirror.
// Gating ProposeUpdate on the OLD datum's well-formedness would be worse than
// the hole it closes: a malformed genesis config could then never be repaired
// by the transition that exists to replace it. The vault re-checks the rails at
// Underwrite instead, where a hostile config is bounded rather than permanent.
//
// Per-network clock FLOORS come from types.ak (72 h mainnet / 5 min preprod),
// so the network module stays the single operator surface and #361's flip guard
// keeps fingerprinting it. The CEILING is compiled in registry_v2.ak: floors
// alone are one-sided, and an enacted clock of 1e21 freezes governance forever.
// =============================================================================

validator registry_v2_validator(
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

    // The spent input must be the NFT-bearing singleton: a datum-forged decoy
    // UTxO at this address cannot exercise the state machine.
    //
    // IMPLIED, and kept anyway. Exact non-lovelace preservation in `value_ok`
    // forces the continuation's NFT count to equal the input's, so
    // `nft_continues` already pins this one — no transaction can redden this
    // leg alone, and none of the tests below isolates it. It stays because it
    // is the leg that SURVIVES a weakening of `value_ok`: the day someone
    // relaxes exact preservation to admit a donated token, the singleton
    // property would silently leave with it. Belt and braces, stated as such
    // rather than left looking load-bearing.
    let spends_singleton =
      assets.quantity_of(
        own_input.output.value,
        registry_nft_policy,
        registry_nft_name,
      ) == 1

    expect [cont] = list.filter(outputs, fn(o) { o.address == own_addr })
    let nft_continues =
      assets.quantity_of(cont.value, registry_nft_policy, registry_nft_name) == 1
    expect InlineDatum(raw_new) = cont.datum
    expect new: RegistryDatum = raw_new

    // Non-lovelace EXACTLY preserved (a token injection changes it), lovelace
    // never decreasing (a skim would).
    let value_ok = and {
        assets.without_lovelace(cont.value) == assets.without_lovelace(
          own_input.output.value,
        ),
        assets.lovelace_of(cont.value) >= assets.lovelace_of(
          own_input.output.value,
        ),
      }

    // Default-deny. The one-shot policy enforces this too; a second NFT would
    // give a spender two registries to choose which one to obey.
    let no_registry_mint =
      dict.is_empty(assets.tokens(mint, registry_nft_policy))

    let signed = admin_signed(old.admin, extra_signatories)
    let tx_lower = get_lower_bound(validity_range)
    let tx_upper = get_upper_bound(validity_range)

    let transition_ok =
      when redeemer is {
        ProposeUpdate ->
          check_propose(
            old,
            new,
            tx_lower,
            tx_upper,
            signed,
            registry_timelock_ms,
            cancel_cooldown_ms,
          )
        // PERMISSIONLESS by design: once the public notice has elapsed, an
        // admin that has gone quiet must not be able to withhold the update it
        // proposed. `check_enact` re-checks the rails and the admin it writes,
        // so the openness costs nothing.
        EnactUpdate ->
          check_enact(
            old,
            new,
            tx_lower,
            registry_timelock_ms,
            cancel_cooldown_ms,
          )
        CancelUpdate ->
          check_cancel(old, new, tx_lower, tx_upper, signed, cancel_cooldown_ms)
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
    fail @"Unsupported purpose for the V8.2 registry validator"
  }
}

// ===========================================================================
// Tests. The transitions are exhaustively unit-tested in lib/aegis/registry_v2,
// so everything here drives `registry_v2_validator.spend` over a full
// Transaction and moves exactly one STRUCTURAL fact — the layer the pure
// checks assume and cannot see.
// ===========================================================================

const rv2_nft_policy: ByteArray =
  #"11111111111111111111111111111111111111111111111111111111"

const rv2_nft_name: ByteArray = "AEGIS_REGISTRY"

const rv2_script: ByteArray =
  #"22222222222222222222222222222222222222222222222222222222"

const rv2_admin_key: ByteArray =
  #"33333333333333333333333333333333333333333333333333333333"

const rv2_logic_a: ByteArray =
  #"44444444444444444444444444444444444444444444444444444444"

const rv2_logic_b: ByteArray =
  #"55555555555555555555555555555555555555555555555555555555"

const rv2_publisher: ByteArray =
  #"66666666666666666666666666666666666666666666666666666666"

const rv2_observer: ByteArray =
  #"77777777777777777777777777777777777777777777777777777777"

const rv2_state_nft: ByteArray =
  #"88888888888888888888888888888888888888888888888888888888"

const rv2_team_key: ByteArray =
  #"99999999999999999999999999999999999999999999999999999999"

const rv2_primary: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const rv2_lo: Int = 1_700_100_000_000

const rv2_up: Int = 1_700_100_060_000

/// Clocks that sit above the MAINNET floors and below the compiled ceiling, so
/// a network flip cannot change what these fixtures mean.
const rv2_timelock: Int = 300_000_000

const rv2_cooldown: Int = 172_800_000

fn rv2_addr() -> Address {
  Address { payment_credential: Script(rv2_script), stake_credential: None }
}

fn rv2_own_ref() -> OutputReference {
  fixtures.out_ref(#"de", 0)
}

fn rv2_config() -> UnderwriteConfig {
  UnderwriteConfig {
    mandates: [
      OracleMandate {
        primary_nft: rv2_primary,
        fallback_feed_id: #"0006",
        second_leg: TrailingLowLeg,
      },
    ],
    publisher_vkh: rv2_publisher,
    observer_hash: rv2_observer,
    depeg_eligible: [rv2_primary],
    pyth_feed_allowlist: [#"0006"],
    pyth_state_nft: rv2_state_nft,
    floors: Floors {
      min_strike_distance_bps: 1_500,
      min_depeg_distance_bps: 200,
      depeg_strike_lo_bps: 5_000,
      depeg_strike_hi_bps: 9_500,
      min_depeg_spot_bps: 9_900,
    },
    admissible_providers: [AegisSelf],
    budgets: Budgets {
      spot_age_barrier_ms: 600_000,
      spot_age_depeg_ms: 300_000,
      underwrite_span_ms: 1_200_000,
      term_min_ms: 604_800_000,
      term_max_ms: 15_552_000_000,
      min_premium: 2_000_000,
      utilisation_bps: 3_333,
      max_coverage_ratio: 50,
    },
    fee: Fee {
      take_bps: 200,
      treasury_bps: 2_500,
      team_address: Address {
        payment_credential: VerificationKey(rv2_team_key),
        stake_credential: None,
      },
    },
    settlement_pins: SettlementPins {
      reading_validity_ms: 7_200_000,
      pyth_freshness_ms: 4_200_000,
      pyth_max_confidence_bps: 100,
      pyth_reject_absent_confidence: False,
      grace_barrier_ms: 1_800_000,
      grace_depeg_ms: 1_800_000,
      cancellation_window_ms: 3_600_000,
      cancellation_fee_bps: 1_000,
    },
  }
}

/// A recalibrated but well-formed config, so a pending changes something.
fn rv2_config_b() -> UnderwriteConfig {
  let c = rv2_config()
  let b = c.budgets
  UnderwriteConfig {
    ..c,
    budgets: Budgets { ..b, spot_age_barrier_ms: 900_000 },
  }
}

fn rv2_datum() -> RegistryDatum {
  RegistryDatum {
    epoch: 3,
    logic_hash: rv2_logic_a,
    config: rv2_config(),
    pending: None,
    admin: Admin { keys: [rv2_admin_key], threshold: 1 },
    cooldown_until: 0,
    timelock_ms: rv2_timelock,
    cancel_cooldown_ms: rv2_cooldown,
  }
}

fn rv2_pending() -> PendingUpdate {
  PendingUpdate {
    logic_hash: rv2_logic_b,
    config: rv2_config_b(),
    new_admin: None,
    timelock_ms: rv2_timelock,
    cancel_cooldown_ms: rv2_cooldown,
    effective_after: rv2_up + rv2_timelock,
  }
}

fn rv2_armed() -> RegistryDatum {
  RegistryDatum { ..rv2_datum(), pending: Some(rv2_pending()) }
}

fn rv2_enacted(p: PendingUpdate) -> RegistryDatum {
  let old = rv2_datum()
  RegistryDatum {
    ..old,
    epoch: old.epoch + 1,
    logic_hash: p.logic_hash,
    config: p.config,
    pending: None,
  }
}

fn rv2_value(lovelace: Int, nfts: Int) -> assets.Value {
  assets.from_lovelace(lovelace)
    |> assets.add(rv2_nft_policy, rv2_nft_name, nfts)
}

fn rv2_input(value: assets.Value) -> Input {
  Input {
    output_reference: rv2_own_ref(),
    output: Output {
      address: rv2_addr(),
      value,
      datum: InlineDatum(rv2_datum()),
      reference_script: None,
    },
  }
}

fn rv2_cont(address: Address, value: assets.Value, new: RegistryDatum) -> Output {
  Output { address, value, datum: InlineDatum(new), reference_script: None }
}

fn rv2_tx_at(
  input_value: assets.Value,
  cont: Output,
  signers: List<ByteArray>,
  mint: assets.Value,
  lower: Int,
  upper: Int,
) -> Transaction {
  Transaction {
    ..fixtures.base_tx(),
    inputs: [rv2_input(input_value)],
    outputs: [cont],
    mint,
    extra_signatories: signers,
    validity_range: fixtures.finite_range(lower, upper),
  }
}

fn rv2_tx(
  input_value: assets.Value,
  cont: Output,
  signers: List<ByteArray>,
  mint: assets.Value,
) -> Transaction {
  rv2_tx_at(input_value, cont, signers, mint, rv2_lo, rv2_up)
}

fn rv2_run(
  old: RegistryDatum,
  redeemer: RegistryRedeemer,
  tx: Transaction,
) -> Bool {
  registry_v2_validator.spend(
    rv2_nft_policy,
    rv2_nft_name,
    Some(old),
    redeemer,
    rv2_own_ref(),
    tx,
  )
}

/// The happy propose, with only the signer list variable.
fn rv2_propose_tx(signers: List<ByteArray>) -> Transaction {
  rv2_tx(
    rv2_value(5_000_000, 1),
    rv2_cont(rv2_addr(), rv2_value(5_000_000, 1), rv2_armed()),
    signers,
    assets.zero,
  )
}

/// An enact tx whose window opens at `lower` — the only quantity the arm's
/// timing leg reads.
fn rv2_enact_tx(new: RegistryDatum, lower: Int) -> Transaction {
  rv2_tx_at(
    rv2_value(5_000_000, 1),
    rv2_cont(rv2_addr(), rv2_value(5_000_000, 1), new),
    [],
    assets.zero,
    lower,
    lower + 60_000,
  )
}

test rv2_propose_then_enact_cycle() {
  and {
    rv2_run(rv2_datum(), ProposeUpdate, rv2_propose_tx([rv2_admin_key])),
    rv2_run(
      rv2_armed(),
      EnactUpdate,
      rv2_enact_tx(rv2_enacted(rv2_pending()), rv2_up + rv2_timelock),
    ),
  }
}

test rv2_propose_unsigned_rejected() {
  !rv2_run(rv2_datum(), ProposeUpdate, rv2_propose_tx([]))
}

test rv2_enact_is_permissionless_but_still_waits() {
  let enacted = rv2_enacted(rv2_pending())
  and {
    // no signatory at all, and it lands
    rv2_run(rv2_armed(), EnactUpdate, rv2_enact_tx(enacted, rv2_up + rv2_timelock)),
    // one millisecond early, and it does not
    !rv2_run(
      rv2_armed(),
      EnactUpdate,
      rv2_enact_tx(enacted, rv2_up + rv2_timelock - 1),
    ),
  }
}

test rv2_cancel_arms_the_cooldown_and_clears_the_pending() {
  let cleared =
    RegistryDatum {
      ..rv2_armed(),
      pending: None,
      cooldown_until: rv2_up + rv2_cooldown,
    }
  let cont = rv2_cont(rv2_addr(), rv2_value(5_000_000, 1), cleared)
  and {
    rv2_run(
      rv2_armed(),
      CancelUpdate,
      rv2_tx(rv2_value(5_000_000, 1), cont, [rv2_admin_key], assets.zero),
    ),
    !rv2_run(
      rv2_armed(),
      CancelUpdate,
      rv2_tx(rv2_value(5_000_000, 1), cont, [], assets.zero),
    ),
  }
}

test rv2_decoy_input_without_the_nft_rejected() {
  // A second UTxO at the registry address carrying a forged datum but no NFT
  // cannot drive the machine. Rejected by `nft_continues` as well as
  // `spends_singleton` — see the note on the latter; the two cannot be
  // separated while non-lovelace value is exactly preserved.
  !rv2_run(
    rv2_datum(),
    ProposeUpdate,
    rv2_tx(
      rv2_value(5_000_000, 0),
      rv2_cont(rv2_addr(), rv2_value(5_000_000, 0), rv2_armed()),
      [rv2_admin_key],
      assets.zero,
    ),
  )
}

test rv2_continuation_must_carry_the_nft() {
  !rv2_run(
    rv2_datum(),
    ProposeUpdate,
    rv2_tx(
      rv2_value(5_000_000, 1),
      rv2_cont(rv2_addr(), assets.from_lovelace(5_000_000), rv2_armed()),
      [rv2_admin_key],
      assets.zero,
    ),
  )
}

test rv2_lovelace_skim_rejected() {
  !rv2_run(
    rv2_datum(),
    ProposeUpdate,
    rv2_tx(
      rv2_value(5_000_000, 1),
      rv2_cont(rv2_addr(), rv2_value(4_000_000, 1), rv2_armed()),
      [rv2_admin_key],
      assets.zero,
    ),
  )
}

test rv2_token_injection_rejected() {
  // A foreign token riding the continuation moves `without_lovelace`, which is
  // what stops the registry singleton being used as a dust sink.
  let polluted = rv2_value(5_000_000, 1) |> assets.add(rv2_logic_a, "JUNK", 1)
  !rv2_run(
    rv2_datum(),
    ProposeUpdate,
    rv2_tx(
      rv2_value(5_000_000, 1),
      rv2_cont(rv2_addr(), polluted, rv2_armed()),
      [rv2_admin_key],
      assets.zero,
    ),
  )
}

test rv2_registry_mint_rejected() {
  !rv2_run(
    rv2_datum(),
    ProposeUpdate,
    rv2_tx(
      rv2_value(5_000_000, 1),
      rv2_cont(rv2_addr(), rv2_value(5_000_000, 1), rv2_armed()),
      [rv2_admin_key],
      assets.from_asset(rv2_nft_policy, "AEGIS_REGISTRY_2", 1),
    ),
  )
}

test rv2_stake_grafted_continuation_rejected() fail {
  // Same payment credential, a stake credential grafted on. The continuation
  // filter matches the FULL address, so nothing matches and the arm aborts —
  // rather than letting an admin re-address the singleton's rewards.
  let grafted =
    Address {
      payment_credential: Script(rv2_script),
      stake_credential: Some(Inline(VerificationKey(rv2_admin_key))),
    }
  rv2_run(
    rv2_datum(),
    ProposeUpdate,
    rv2_tx(
      rv2_value(5_000_000, 1),
      rv2_cont(grafted, rv2_value(5_000_000, 1), rv2_armed()),
      [rv2_admin_key],
      assets.zero,
    ),
  )
}

test rv2_datumless_continuation_rejected() fail {
  rv2_run(
    rv2_datum(),
    ProposeUpdate,
    rv2_tx(
      rv2_value(5_000_000, 1),
      Output {
        address: rv2_addr(),
        value: rv2_value(5_000_000, 1),
        datum: NoDatum,
        reference_script: None,
      },
      [rv2_admin_key],
      assets.zero,
    ),
  )
}

test rv2_out_of_rail_pending_config_cannot_enact() {
  // The rails are re-checked at enact, so a pending that never passed propose
  // — the only source of one is a planted genesis — still cannot land.
  let c = rv2_config()
  let b = c.budgets
  let hostile =
    UnderwriteConfig { ..c, budgets: Budgets { ..b, utilisation_bps: 9_999 } }
  let p = PendingUpdate { ..rv2_pending(), config: hostile }
  !rv2_run(
    RegistryDatum { ..rv2_datum(), pending: Some(p) },
    EnactUpdate,
    rv2_enact_tx(rv2_enacted(p), rv2_up + rv2_timelock),
  )
}
