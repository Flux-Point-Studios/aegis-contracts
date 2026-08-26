// =============================================================================
// Aegis Insurance Protocol - Security Test Fixtures
// Location: contracts/lib/aegis/test_helpers/fixtures.ak
// Test-only. Reusable Transaction / Input / Output / Datum builders for the
// security_tests modules.
// =============================================================================

use aegis/oracle.{Attestation, create_oracle_datum, resolve_oracle_price}
use aegis/oracle/charli3.{create_oracle_datum_with_min}
use aegis/oracle/types as oracle_types
use aegis/types.{
  AegisSelf, Barrier, Charli3, OracleProvider, Orcfax, PolicyDatum, PoolDatum,
  SettlementPins, aegis_self_canonical_nfts, aegis_self_publisher_vkh,
  orcfax_ada_usd_feed_id, orcfax_fs_asset_name, orcfax_fsp_asset_name,
  policy_marker_asset_name,
}
use aiken/builtin
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/interval.{Finite, Interval, IntervalBound}
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets
use cardano/transaction.{
  Datum, InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
  ValidityRange, Withdraw,
}

// ---------------------------------------------------------------------------
// Canonical test identities
// ---------------------------------------------------------------------------

pub const policy_script_hash: ScriptHash =
  #"8ea5aed0e4f66e9ce6593fbed30856c8997441b1e5cd8bc3085e943f"

pub const pool_script_hash: ScriptHash =
  #"c366b0ea2667b432a432999f54e11978c0ed37c7c4b971067fb1589f"

pub const lp_token_policy_id: ByteArray =
  #"0402df9c420213421d894b00ee5b23391cb36dc3c2a436b48229c10a"

/// The canonical Charli3 ADA/USD NFT policy id, taken from the ACTIVE network
/// module. The parser pins this handle, so the fixture must round-trip with
/// whatever the compiled profile declares. Use `oracle_nft_policy_alt`
/// (declared below) when a test needs a deliberately *non*-canonical NFT
/// (e.g., spoofing checks).
///
/// [#363 F5] Was a hardcoded preprod literal while its own doc comment claimed
/// it "matches types.charli3_ada_usd_nft_policy" — the same latent defect as
/// `aegis_self_ada_nft`. Every test routing through it went dark the moment the
/// profile it was copied from stopped being the compiled one.
pub const oracle_nft_policy: ByteArray = types.charli3_ada_usd_nft_policy

pub const pool_nft_policy: ByteArray =
  #"deadbeef00112233445566778899aabbccddeeff00112233445566"

pub const pool_nft_name: ByteArray = #"414547495350"

pub const insured_pkh: ByteArray =
  #"00112233445566778899aabbccddeeff00112233445566778899aabb"

pub const attacker_pkh: ByteArray =
  #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

pub const tx_id_zero: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000000"

pub const tx_id_one: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000001"

pub const tx_id_two: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000002"

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

pub fn script_addr(hash: ScriptHash) -> Address {
  Address { payment_credential: Script(hash), stake_credential: None }
}

pub fn pkh_addr(pkh: ByteArray) -> Address {
  Address { payment_credential: VerificationKey(pkh), stake_credential: None }
}

// ---------------------------------------------------------------------------
// Datum builders
// ---------------------------------------------------------------------------

pub fn default_policy_datum() -> PolicyDatum {
  PolicyDatum {
    policy_id: #"aabbccdd",
    insured: insured_pkh,
    strike_price: 350_000,
    coverage_amount: 5_000_000_000,
    premium_paid: 200_000_000,
    start_time: 1_700_000_000_000,
    expiry_time: 1_700_604_800_000,
    oracle_nft: oracle_nft_policy,
    pool_script_hash,
    pool_nft: pool_nft_policy,
    oracle_provider: Charli3,
    // Default fixtures are solo policies (no partner). Specific
    // tests construct datums with `partner_address: Some(_)` via record
    // spread.
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

/// Re-encode a policy in its V4-era on-chain shape: the fourteen-field head and
/// no tail. This is the literal CBOR of every policy underwritten before
/// `payout_address` existed, and those UTxOs are still spendable, so any
/// validator that settles policies has to read this arity.
///
/// The three appended fields all default to `None`, which is each one's
/// before-it-existed behaviour — so a datum built from a `pd` whose tail is
/// already `None` must settle exactly as `pd` does.
pub fn legacy_head_datum(pd: PolicyDatum) -> Data {
  builtin.constr_data(0, list.take(policy_datum_fields(pd), 14))
}

/// Re-encode a policy in its pre-`settlement_pins` shape: the seventeen-field
/// constr a not-yet-upgraded tx builder still writes at Underwrite. Pins are
/// Option-tail, so this datum must bind and later settle with pins = None.
pub fn pre_pins_datum(pd: PolicyDatum) -> Data {
  builtin.constr_data(0, list.take(policy_datum_fields(pd), 17))
}

fn policy_datum_fields(pd: PolicyDatum) -> List<Data> {
  let raw: Data = pd
  let Pair(_tag, fields) = builtin.un_constr_data(raw)
  fields
}

/// Crafted policy datum used for the A-001 drain attack.
/// Strike is set absurdly high so any oracle reading triggers Claim.
pub fn synthetic_attack_policy_datum() -> PolicyDatum {
  PolicyDatum {
    policy_id: #"61747461636b",
    insured: attacker_pkh,
    strike_price: 999_999_999_999,
    coverage_amount: 2_000_000,
    premium_paid: 0,
    start_time: 0,
    expiry_time: 99_999_999_999_999,
    oracle_nft: oracle_nft_policy,
    pool_script_hash,
    pool_nft: pool_nft_policy,
    oracle_provider: Charli3,
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

/// Variant policy-datum builder: same as `default_policy_datum` but
/// bound to Orcfax instead of Charli3. The `oracle_nft` field carries an
/// Orcfax FSP script hash (NOT an NFT policy id) — semantics branch on
/// `oracle_provider`. Used by the v6 multi-provider security tests.
pub fn default_policy_datum_orcfax() -> PolicyDatum {
  PolicyDatum {
    ..default_policy_datum(),
    oracle_nft: orcfax_fsp_hash_test,
    oracle_provider: Orcfax,
  }
}

/// Mock Orcfax FSP script hash used by tests. On preprod the live
/// deploy will pin this to the deployed mock validator's hash; on preview
/// and mainnet it pins to the canonical Orcfax FSP hash. This test fixture
/// uses an arbitrary deterministic byte string so test assertions are
/// reproducible without depending on any external state.
pub const orcfax_fsp_hash_test: ByteArray =
  #"0690081bc113f74e04640ea78a87d88abbd2f18831c44c4064524230"

/// Mock Orcfax FS validator/policy hash used by tests. In production
/// this hash is dynamic — the consumer reads it from the FSP datum at
/// claim time. The mock fixtures hardwire it for deterministic test inputs.
pub const orcfax_fs_hash_test: ByteArray =
  #"193ee65211bb39193ee65211bb39193ee65211bb39193ee65211bb39"

/// Test-only feed_id matching `orcfax_ada_usd_feed_id` — re-exposed
/// here so test cases can compare against a named constant rather than
/// re-typing the hex.
pub const orcfax_test_feed_id: ByteArray = orcfax_ada_usd_feed_id

/// Build a mock Orcfax FSP UTxO whose inline datum is `bytes(fs_hash)`.
/// The FSP NFT (asset_name = `orcfax_fsp_asset_name`) lives under the FSP
/// script's own hash policy. Mirrors the production Orcfax shape: the FSP
/// datum is an opaque byte array whose value is the dynamic FS validator
/// hash.
pub fn orcfax_fsp_input(target_fs_hash: ByteArray) -> Input {
  let fsp_value =
    assets.from_lovelace(2_000_000)
      |> assets.add(orcfax_fsp_hash_test, orcfax_fsp_asset_name, 1)
  make_input(
    tx_id_two,
    1,
    Address {
      payment_credential: Script(orcfax_fsp_hash_test),
      stake_credential: None,
    },
    fsp_value,
    InlineDatum(target_fs_hash),
  )
}

/// Build a mock Orcfax FS UTxO carrying the FS NFT and a
/// `FsDat<Rational>` inline datum. The FS NFT policy equals the FS validator
/// hash itself (Orcfax's design); the FS asset name is the empty bytestring
/// (`orcfax_fs_asset_name`).
///
/// `feed_id` defaults to `orcfax_ada_usd_feed_id` (`"CER/ADA-USD/"`).
/// `(num, denom)` encodes the price as `num/denom` (USD per 1 ADA).
/// `created_at` is POSIX milliseconds.
pub fn orcfax_fs_input(num: Int, denom: Int, created_at: Int) -> Input {
  orcfax_fs_input_with_feed(num, denom, created_at, orcfax_ada_usd_feed_id)
}

/// Same as `orcfax_fs_input` but accepts an explicit feed_id. Used by
/// negative tests (wrong feed, ADA-USDM trailing-slash defense, etc.).
pub fn orcfax_fs_input_with_feed(
  num: Int,
  denom: Int,
  created_at: Int,
  feed_id: ByteArray,
) -> Input {
  // Build the FsDat<Rational> shape inline via raw record literal. We use a
  // local copy of the Orcfax types here to keep test_helpers free of any
  // dependency on `aegis/oracle/orcfax` (which would create a circular
  // module dep through the validators).
  let rational_body = OrcfaxFixtureRational { num, denom }
  let stmt = OrcfaxFixtureStatement { feed_id, created_at, body: rational_body }
  let fs_dat = OrcfaxFixtureFsDat { statement: stmt, context: 0 }
  let fs_value =
    assets.from_lovelace(2_000_000)
      |> assets.add(orcfax_fs_hash_test, orcfax_fs_asset_name, 1)
  make_input(
    tx_id_two,
    2,
    Address {
      payment_credential: Script(orcfax_fs_hash_test),
      stake_credential: None,
    },
    fs_value,
    InlineDatum(fs_dat),
  )
}

/// Test-only mirror of `aegis/oracle/orcfax.Statement<t>`. The CBOR encoding
/// of this struct must match the production type byte-for-byte (positional
/// fields, same ordering) so the same `expect fs_dat: RationalFsDat = idat`
/// decode resolves transparently. We re-declare here rather than importing
/// to avoid a circular module dep through `aegis/oracle`.
pub type OrcfaxFixtureStatement<t> {
  feed_id: ByteArray,
  created_at: Int,
  body: t,
}

/// Test-only mirror of `aegis/oracle/orcfax.Rational`.
pub type OrcfaxFixtureRational {
  num: Int,
  denom: Int,
}

/// Test-only mirror of `aegis/oracle/orcfax.FsDat<t>`.
pub type OrcfaxFixtureFsDat<t> {
  statement: OrcfaxFixtureStatement<t>,
  context: Data,
}

pub fn default_pool_datum() -> PoolDatum {
  PoolDatum {
    total_liquidity: 1_000_000_000_000,
    active_coverage: 100_000_000_000,
    lp_token_policy: lp_token_policy_id,
    protocol_fee_bps: 200,
    pool_nft: pool_nft_policy,
    lp_supply: 1_000_000_000_000,
    reserve: 0,
  }
}

// ---------------------------------------------------------------------------
// Input / Output builders
// ---------------------------------------------------------------------------

pub fn out_ref(tx_id: ByteArray, idx: Int) -> OutputReference {
  OutputReference { transaction_id: tx_id, output_index: idx }
}

pub fn make_input(
  tx_id: ByteArray,
  idx: Int,
  address: Address,
  value: assets.Value,
  datum: Datum,
) -> Input {
  Input {
    output_reference: out_ref(tx_id, idx),
    output: Output { address, value, datum, reference_script: None },
  }
}

pub fn pkh_output(pkh: ByteArray, lovelace: Int) -> Output {
  Output {
    address: pkh_addr(pkh),
    value: assets.from_lovelace(lovelace),
    datum: NoDatum,
    reference_script: None,
  }
}

// ---------------------------------------------------------------------------
// Stake-credential grafting fixtures.
// ---------------------------------------------------------------------------

/// An output paid to `pkh` BUT with a stake credential — i.e. NOT an
/// enterprise address. Models the A-009 attack output where the claim-bot
/// has spliced its own stake credential onto the insured's payout.
pub fn pkh_output_with_stake(
  pkh: ByteArray,
  stake_pkh: ByteArray,
  lovelace: Int,
) -> Output {
  Output {
    address: Address {
      payment_credential: VerificationKey(pkh),
      stake_credential: Some(Inline(VerificationKey(stake_pkh))),
    },
    value: assets.from_lovelace(lovelace),
    datum: NoDatum,
    reference_script: None,
  }
}

/// A canonical attacker stake credential used in A-009 fixtures.
pub const attacker_stake_pkh: ByteArray =
  #"badf00dbadf00dbadf00dbadf00dbadf00dbadf00dbadf00dbadf00d"

/// A datum-less coverage output paid to a SCRIPT-credential enterprise address
/// (stake None). This is the exact shape the treasury-cover pilot pays coverage
/// to: a native-script DAO treasury spends a `NoDatum` output. The script
/// analogue of `pkh_output`.
pub fn script_output(hash: ScriptHash, lovelace: Int) -> Output {
  Output {
    address: script_addr(hash),
    value: assets.from_lovelace(lovelace),
    datum: NoDatum,
    reference_script: None,
  }
}

/// A coverage output paid to the script PAYMENT credential but with a grafted
/// stake credential — i.e. NOT the committed enterprise script address. The
/// script analogue of `pkh_output_with_stake`: models the A-009 stake-graft
/// attack against a `payout_address`-bound (script) policy. `sum_lovelace_to_address`
/// matches the FULL address, so this contributes 0.
pub fn script_output_with_stake(
  hash: ScriptHash,
  stake_pkh: ByteArray,
  lovelace: Int,
) -> Output {
  Output {
    address: Address {
      payment_credential: Script(hash),
      stake_credential: Some(Inline(VerificationKey(stake_pkh))),
    },
    value: assets.from_lovelace(lovelace),
    datum: NoDatum,
    reference_script: None,
  }
}

/// [V6 / #325] A coverage output paid to a SCRIPT-credential enterprise address
/// carrying `InlineDatum(inline)`. This is the exact shape a Plutus (V2/V3) DAO
/// treasury cover pays coverage to: the committed `payout_datum` rides as the
/// output's inline datum so the treasury's own validator can spend it.
pub fn script_output_with_datum(
  hash: ScriptHash,
  inline: Data,
  lovelace: Int,
) -> Output {
  Output {
    address: script_addr(hash),
    value: assets.from_lovelace(lovelace),
    datum: InlineDatum(inline),
    reference_script: None,
  }
}

// ---------------------------------------------------------------------------
// Variant policy datum builders for batch oracle uniformity tests.
// ---------------------------------------------------------------------------

/// A second oracle NFT policy, distinct from `oracle_nft_policy`. Used to
/// model a BatchClaim that mixes two policies bound to different oracle
/// feeds (e.g., ADA/USD + DJED/USD).
pub const oracle_nft_policy_alt: ByteArray =
  #"0123456789abcdef0123456789abcdef0123456789abcdef01234567"

/// A policy datum identical to `default_policy_datum` except for the
/// `oracle_nft` field, which points at `oracle_nft_policy_alt`.
pub fn default_policy_datum_alt_oracle() -> PolicyDatum {
  PolicyDatum { ..default_policy_datum(), oracle_nft: oracle_nft_policy_alt }
}

pub fn pool_continuation(
  lovelace: Int,
  with_nft: Bool,
  datum: PoolDatum,
) -> Output {
  let base_value = assets.from_lovelace(lovelace)
  let value =
    if with_nft {
      assets.add(base_value, pool_nft_policy, pool_nft_name, 1)
    } else {
      base_value
    }
  Output {
    address: script_addr(pool_script_hash),
    value,
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

pub fn policy_input(
  tx_id: ByteArray,
  idx: Int,
  lovelace: Int,
  datum: PolicyDatum,
) -> Input {
  make_input(
    tx_id,
    idx,
    script_addr(policy_script_hash),
    assets.from_lovelace(lovelace),
    InlineDatum(datum),
  )
}

pub fn pool_input(
  tx_id: ByteArray,
  idx: Int,
  lovelace: Int,
  datum: PoolDatum,
) -> Input {
  make_input(
    tx_id,
    idx,
    script_addr(pool_script_hash),
    assets.add(
      assets.from_lovelace(lovelace),
      pool_nft_policy,
      pool_nft_name,
      1,
    ),
    InlineDatum(datum),
  )
}

pub fn oracle_ref_input(price: Int, timestamp: Int, expiry: Int) -> Input {
  oracle_ref_input_at(types.charli3_oracle_script_hash, price, timestamp, expiry)
}

/// [#363 R4] The same canonical-NFT oracle UTxO, parked at an ARBITRARY script
/// address. This is the A-016 attack shape: anyone may output to any address, so
/// the NFT-policy pin alone is not enough — the finder must ALSO require the
/// canonical oracle script hash. Without a fixture that can express a wrong
/// address, no test could ever exercise that leg.
pub fn oracle_ref_input_at(
  script_hash: ByteArray,
  price: Int,
  timestamp: Int,
  expiry: Int,
) -> Input {
  let datum = create_oracle_datum(price, timestamp, expiry)
  make_input(
    tx_id_two,
    0,
    Address {
      payment_credential: Script(script_hash),
      stake_credential: None,
    },
    assets.add(
      assets.from_lovelace(2_000_000),
      oracle_nft_policy,
      #"4f5241434c45",
      1,
    ),
    InlineDatum(datum),
  )
}

// ---------------------------------------------------------------------------
// Validity range helpers
// ---------------------------------------------------------------------------

pub fn finite_range(lower: Int, upper: Int) -> ValidityRange {
  Interval {
    lower_bound: IntervalBound { bound_type: Finite(lower), is_inclusive: True },
    upper_bound: IntervalBound { bound_type: Finite(upper), is_inclusive: True },
  }
}

// ---------------------------------------------------------------------------
// Base transaction
// ---------------------------------------------------------------------------

pub fn base_tx() -> Transaction {
  Transaction {
    ..transaction.placeholder,
    validity_range: finite_range(1_700_100_000_000, 1_700_100_300_000),
  }
}

// ---------------------------------------------------------------------------
// AegisSelf / Materios EVENT_SLOT fixtures
// ---------------------------------------------------------------------------

/// Canonical AegisSelf ADA/USD NFT policy id (first entry of
/// `aegis_self_canonical_nfts`). A Materios EVENT_SLOT feed reuses this same
/// publisher-NFT trust anchor; the field semantics are identical to a price
/// feed because the on-chain Claim check is generic over the oracle value.
/// DERIVED from the ACTIVE network module, never a hardcoded literal (#363 F5).
/// The doc above always CLAIMED "first entry of aegis_self_canonical_nfts" but
/// the value was pinned to a stale preprod feed (d2f08410…) that the V8B
/// re-parameterization retired — canonical on NEITHER network. Every suite
/// inheriting this fixture (policy/pool/tc/n1/n5/nna4/allowlist/oracle/mandate)
/// therefore aborted at `expect list.has(aegis_self_canonical_nfts, …)`, which
/// is what left 55 tests — including the LIVE MAINNET V7 guards — permanently
/// dark. Deriving it makes the fixtures correct under either network module.
pub fn aegis_self_ada_nft() -> ByteArray {
  expect [nft, ..] = aegis_self_canonical_nfts
  nft
}

/// A non-canonical NFT policy id used by the wrong-pin negative test. It is
/// NOT a member of `aegis_self_canonical_nfts`, so `find_feed_datum`'s
/// `expect list.has(...)` aborts before the address check even runs.
pub const aegis_self_noncanonical_nft: ByteArray =
  #"00112233445566778899001122334455667788990011223344556677"

/// A policy datum bound to the AegisSelf rail (the rail a Materios EVENT_SLOT
/// settles through). Same shape as `default_policy_datum` but provider =
/// AegisSelf and `oracle_nft` = the canonical AegisSelf publisher NFT.
pub fn default_policy_datum_aegis_self() -> PolicyDatum {
  PolicyDatum {
    ..default_policy_datum(),
    oracle_nft: aegis_self_ada_nft(),
    oracle_provider: AegisSelf,
  }
}

/// Build the canonical AegisSelf / Materios EVENT_SLOT feed reference input.
///
/// The UTxO sits at the publisher VKH address (`aegis_self_publisher_vkh`),
/// carries a token under `nft_policy`, and embeds the Charli3-compatible
/// GenericData datum produced by `create_oracle_datum`. For an EVENT_SLOT the
/// `value` is the binary event encoding (`<= strike` when the event fired);
/// the parser path is byte-for-byte identical to a price feed.
/// [#363 F1] A feed carrying the FULL 5-key AegisSelf datum — trailing-12h low
/// at key 3 and its observation time at key 4.
///
/// `aegis_self_feed_input` below emits only 3 keys, so `min_price_12h` defaults
/// to spot and `low_observed_at` to `created_ms`. Under those defaults
/// `barrier_touched`'s retro disjunct can never fire independently of the spot
/// disjunct, which made the back-date retro-capture attack INEXPRESSIBLE in the
/// suite — neither the vulnerability nor any fix for it was exercised. Use this
/// builder for any test that reasons about the 12h low.
pub fn aegis_self_feed_input_full(
  nft_policy: ByteArray,
  value: Int,
  created_ms: Int,
  expiry_ms: Int,
  min_price_12h: Int,
  low_observed_at: Int,
) -> Input {
  let datum =
    create_oracle_datum_with_min(
      value,
      created_ms,
      expiry_ms,
      min_price_12h,
      low_observed_at,
    )
  make_input(
    tx_id_two,
    0,
    Address {
      payment_credential: VerificationKey(aegis_self_publisher_vkh),
      stake_credential: None,
    },
    assets.add(assets.from_lovelace(2_000_000), nft_policy, #"4145474953", 1),
    InlineDatum(datum),
  )
}

/// [#391 F1] `pd` re-encoded with a `settlement_pins` tail carrying `wait_ms`
/// as its claim waiting period and `fallback_feed_id` as its Pyth fallback.
/// Every other pin is a distinguishable placeholder: those two are the only
/// pins a validator reads today, and giving the rest real-looking values would
/// suggest a pins-copy the vault does not yet verify.
///
/// [V8.2 G5] `fallback_feed_id` is an ARGUMENT rather than the `#"10"` literal
/// it used to be. It is the feed settlement resolves the Pyth leg against, so a
/// fixture that pinned one constant regardless of what the scenario's governed
/// mandate armed could only ever exercise the mismatch — which is the very case
/// Underwrite now refuses.
///
/// Field-by-field through `builtin.constr_data`, the construction
/// `policy_datum.populated_pins_decode_by_index` already proves decodes. The
/// obvious alternative — `PolicyDatum { ..pd, settlement_pins: Some(..) }` cast
/// to Data — decodes correctly when `decode_policy_datum` is called on it
/// directly and CRASHES that same `expect` when the identical value reaches it
/// through a transaction's `InlineDatum`. Aiken 1.1.22 on this box; the working
/// form is the one the decoder's own suite uses.
pub fn policy_datum_with_pins(
  pd: PolicyDatum,
  wait_ms: Int,
  fallback_feed_id: ByteArray,
) -> Data {
  let pins: Option<SettlementPins> =
    Some(
      SettlementPins {
        fallback_feed_id,
        publisher_vkh: #"b1",
        observer_script_hash: #"d3",
        max_reading_validity_ms: 7_200_000,
        fallback_grace_ms: 1_800_000,
        cancellation_window_ms: 3_600_000,
        cancellation_fee_bps: 1_000,
        claim_waiting_period_ms: wait_ms,
      },
    )
  let policy_id: Data = pd.policy_id
  let insured: Data = pd.insured
  let strike_price: Data = pd.strike_price
  let coverage_amount: Data = pd.coverage_amount
  let premium_paid: Data = pd.premium_paid
  let start_time: Data = pd.start_time
  let expiry_time: Data = pd.expiry_time
  let oracle_nft: Data = pd.oracle_nft
  let pool_script_hash: Data = pd.pool_script_hash
  let pool_nft: Data = pd.pool_nft
  let oracle_provider: Data = pd.oracle_provider
  let partner_address: Data = pd.partner_address
  let partner_share_bps: Data = pd.partner_share_bps
  let risk_class: Data = pd.risk_class
  let payout_address: Data = pd.payout_address
  let receipt_commitment: Data = pd.receipt_commitment
  let payout_datum: Data = pd.payout_datum
  let settlement_pins: Data = pins
  builtin.constr_data(
    0,
    [
      policy_id, insured, strike_price, coverage_amount, premium_paid,
      start_time, expiry_time, oracle_nft, pool_script_hash, pool_nft,
      oracle_provider, partner_address, partner_share_bps, risk_class,
      payout_address, receipt_commitment, payout_datum, settlement_pins,
    ],
  )
}

pub fn aegis_self_feed_input(
  nft_policy: ByteArray,
  value: Int,
  created_ms: Int,
  expiry_ms: Int,
) -> Input {
  // [#391 R2 F1] THREE keys — the shape the PRODUCTION publisher writes for
  // every feed except ADA/USD (`publisher/main.py::TRAILING_LOW_PAIR`), and the
  // shape it falls back to even on ADA/USD during a Pyth-failover tick or a
  // history-I/O error. Round 1 converted this fixture to five keys to make its
  // own hardening pass; that edited the WITNESS, and the datum shape running on
  // mainnet stopped being tested at all. `aegis_self_feed_input_full` carries
  // the five-key shape. Both are real and the suite carries both.
  let datum = create_oracle_datum(value, created_ms, expiry_ms)
  make_input(
    tx_id_two,
    0,
    Address {
      payment_credential: VerificationKey(aegis_self_publisher_vkh),
      stake_credential: None,
    },
    assets.add(
      assets.from_lovelace(2_000_000),
      nft_policy,
      #"4145474953", // "AEGIS"
      1,
    ),
    InlineDatum(datum),
  )
}

/// [V5 size #315] Splice the oracle-observer's withdrawal + attestation redeemer
/// into `tx`, attesting the GENUINE readings of `feeds` (resolved from
/// `tx.reference_inputs` via the SAME `resolve_oracle_price` the observer runs).
/// This is the exact tx shape the off-chain builder + `oracle_observer` produce;
/// every pool/policy test exercising an oracle path threads its tx through this
/// so `attested_price` can read the forwarded Price. A feed absent from the
/// reference inputs makes `resolve_oracle_price` abort here — modelling the
/// fail-closed observer for wrong/missing-feed negative tests.
pub fn with_observer_attestation(
  tx: Transaction,
  observer_script_hash: ByteArray,
  feeds: List<(OracleProvider, ByteArray)>,
) -> Transaction {
  let obs_cred = Script(observer_script_hash)
  let attestations =
    list.map(
      feeds,
      fn(f) {
        Attestation {
          provider: f.1st,
          oracle_nft: f.2nd,
          price: resolve_oracle_price(tx, tx.reference_inputs, f.1st, f.2nd),
        }
      },
    )
  let att_redeemer: Data = attestations
  Transaction {
    ..tx,
    withdrawals: [Pair(obs_cred, 0), ..tx.withdrawals],
    redeemers: [Pair(Withdraw(obs_cred), att_redeemer), ..tx.redeemers],
  }
}

/// The same splice, with the Price AUTHORED BY THE CALLER instead of resolved
/// from the reference inputs. This is the whole capability a script an attacker
/// controls has: a stake script that answers True for any withdrawal-0 puts
/// whatever bytes it likes in that redeemer, and `attested_price` derives 100%
/// of a reading's genuineness from the IDENTITY of the leaf it reads. So the
/// only question a test can usefully ask is which hash the vault resolves.
pub fn with_forged_attestation(
  tx: Transaction,
  observer_script_hash: ByteArray,
  provider: OracleProvider,
  oracle_nft: ByteArray,
  price: oracle_types.Price,
) -> Transaction {
  let obs_cred = Script(observer_script_hash)
  let att: Data = [Attestation { provider, oracle_nft, price }]
  Transaction {
    ..tx,
    withdrawals: [Pair(obs_cred, 0), ..tx.withdrawals],
    redeemers: [Pair(Withdraw(obs_cred), att), ..tx.redeemers],
  }
}

/// Value carrying exactly `qty` policy markers under `marker_policy_id`.
pub fn marker_value(marker_policy_id: ByteArray, qty: Int) -> assets.Value {
  assets.from_asset(marker_policy_id, policy_marker_asset_name, qty)
}

/// A policy input at the policy script carrying ADA + exactly one marker and
/// the given datum. The marker is the R12 presence pin every legitimate
/// policy UTxO holds; without it the Claim branch's `has_marker` fails.
pub fn policy_input_with_marker(
  tx_id: ByteArray,
  idx: Int,
  lovelace: Int,
  marker_policy_id: ByteArray,
  datum: PolicyDatum,
) -> Input {
  make_input(
    tx_id,
    idx,
    script_addr(policy_script_hash),
    assets.from_lovelace(lovelace)
      |> assets.merge(marker_value(marker_policy_id, 1)),
    InlineDatum(datum),
  )
}
