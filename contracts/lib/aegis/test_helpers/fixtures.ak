// =============================================================================
// Aegis Insurance Protocol - Security Test Fixtures
// Location: contracts/lib/aegis/test_helpers/fixtures.ak
// Test-only. Reusable Transaction / Input / Output / Datum builders for the
// security_tests modules.
// =============================================================================

use aegis/oracle.{create_oracle_datum}
use aegis/types.{
  Charli3, Orcfax, PolicyDatum, PoolDatum, orcfax_ada_usd_feed_id,
  orcfax_fs_asset_name, orcfax_fsp_asset_name,
}
use aiken/crypto.{ScriptHash}
use aiken/interval.{Finite, Interval, IntervalBound}
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets
use cardano/transaction.{
  Datum, InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
  ValidityRange,
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

/// [v6.0.2 / A-026-class fix] The canonical Charli3 ADA/USD NFT policy id
/// (matches `types.charli3_ada_usd_nft_policy`). Pre-fix, this fixture
/// used an arbitrary 28-byte placeholder; the parser pin now requires the
/// canonical value, so the fixture must round-trip with the real handle.
/// Use `oracle_nft_policy_alt` (declared below) when a test needs a
/// deliberately *non*-canonical NFT (e.g., spoofing checks).
pub const oracle_nft_policy: ByteArray =
  #"886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e"

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
  }
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
  }
}

/// [v6] Variant policy-datum builder: same as `default_policy_datum` but
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

/// [v6] Mock Orcfax FSP script hash used by tests. On preprod the live
/// deploy will pin this to the deployed mock validator's hash; on preview
/// and mainnet it pins to the canonical Orcfax FSP hash. This test fixture
/// uses an arbitrary deterministic byte string so test assertions are
/// reproducible without depending on any external state.
pub const orcfax_fsp_hash_test: ByteArray =
  #"0690081bc113f74e04640ea78a87d88abbd2f18831c44c4064524230"

/// [v6] Mock Orcfax FS validator/policy hash used by tests. In production
/// this hash is dynamic — the consumer reads it from the FSP datum at
/// claim time. The mock fixtures hardwire it for deterministic test inputs.
pub const orcfax_fs_hash_test: ByteArray =
  #"193ee65211bb39193ee65211bb39193ee65211bb39193ee65211bb39"

/// [v6] Test-only feed_id matching `orcfax_ada_usd_feed_id` — re-exposed
/// here so test cases can compare against a named constant rather than
/// re-typing the hex.
pub const orcfax_test_feed_id: ByteArray = orcfax_ada_usd_feed_id

/// [v6] Build a mock Orcfax FSP UTxO whose inline datum is `bytes(fs_hash)`.
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

/// [v6] Build a mock Orcfax FS UTxO carrying the FS NFT and a
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

/// [v6] Same as `orcfax_fs_input` but accepts an explicit feed_id. Used by
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
// [FIX A-009] Stake-credential grafting fixtures.
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

// ---------------------------------------------------------------------------
// [FIX A-012] Variant policy datum builders for batch oracle uniformity tests.
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
  let datum = create_oracle_datum(price, timestamp, expiry)
  // [FIX A-016] The oracle finder now requires the input to be at the
  // canonical Charli3 oracle script hash. Use that hash here so the
  // fixture round-trips (`sanity_oracle_lookup_works_with_canonical_fixture`).
  make_input(
    tx_id_two,
    0,
    Address {
      payment_credential: Script(types.charli3_oracle_script_hash),
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
