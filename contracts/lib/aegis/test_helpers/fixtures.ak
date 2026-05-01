// =============================================================================
// Aegis Insurance Protocol - Security Test Fixtures
// Location: contracts/lib/aegis/test_helpers/fixtures.ak
// Test-only. Reusable Transaction / Input / Output / Datum builders for the
// security_tests modules.
// =============================================================================

use aegis/oracle.{create_oracle_datum}
use aegis/types
use aegis/types.{PolicyDatum, PoolDatum}
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

pub const oracle_nft_policy: ByteArray =
  #"a665bb42594646eaaed8ed59ada592fb8300775df916a4a5406ffa96"

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
  }
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
  PolicyDatum {
    ..default_policy_datum(),
    oracle_nft: oracle_nft_policy_alt,
  }
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
    assets.add(assets.from_lovelace(lovelace), pool_nft_policy, pool_nft_name, 1),
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
