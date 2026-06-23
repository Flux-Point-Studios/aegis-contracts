use aiken/collection/list
use aiken/crypto.{Blake2b_224, Hash, Script, VerificationKey}
use aiken/primitive/bytearray
use cardano/address.{Address, VerificationKey as PaymentVKCred}
use aegis/types/preprod as network

pub type VerificationKeyHash =
  Hash<Blake2b_224, VerificationKey>

pub type ScriptHash =
  Hash<Blake2b_224, Script>

pub type OracleProvider {
  Charli3
  Orcfax
  AegisSelf
  Indigo
}

/// Risk class of a policy — selects which on-chain premium-floor table the
/// Underwrite branch dispatches to (and how the trigger is parameterized).
///
///   * `Barrier` — one-touch down-and-in barrier on a *price* (ADA crash,
///     Indigo CDP liquidation, Surf liquidation). Pays `coverage` if the
///     underlying touches `strike = spot × (1 − d)` at any fresh oracle
///     observation in `[start, expiry]`. Premium floor is strike-distance-,
///     duration- and vol-aware (GBM first-passage at the conservative σ=85%
///     grade), and Underwrite reads a fresh oracle reference input to derive
///     the strike distance `d`.
///   * `Depeg` — a stablecoin leaving its peg. The trigger strike is a fixed
///     band below the peg (e.g. 0.95 × peg); the premium is hazard- (Poisson-)
///     driven and duration-only, so Underwrite does NOT need a spot read for
///     this class — only a strike-band sanity check.
///
/// Set at Underwrite, immutable for the policy's life. Folding both classes
/// into one datum lets a single pool-funded validator back every product line
/// while charging each its correct actuarial floor.
pub type RiskClass {
  Barrier
  Depeg
}

pub type PolicyDatum {
  policy_id: ByteArray,
  insured: VerificationKeyHash,
  strike_price: Int,
  coverage_amount: Int,
  premium_paid: Int,
  start_time: Int,
  expiry_time: Int,
  oracle_nft: ByteArray,
  pool_script_hash: ScriptHash,
  pool_nft: ByteArray,
  oracle_provider: OracleProvider,
  partner_address: Option<Address>,
  partner_share_bps: Int,
  risk_class: RiskClass,
}

pub type PoolDatum {
  total_liquidity: Int,
  active_coverage: Int,
  lp_token_policy: ByteArray,
  protocol_fee_bps: Int,
  pool_nft: ByteArray,
  lp_supply: Int,
}

pub type PolicyRedeemer {
  Claim
  BatchClaim
  Expire
  BatchExpire
  Cancel
}

pub type PoolRedeemer {
  Underwrite { coverage: Int, premium: Int }
  ProcessClaim { payout: Int }
  AddLiquidity { amount: Int }
  RemoveLiquidity { amount: Int }
  BatchUnderwrite { total_coverage: Int, total_premium: Int }
  BatchExpireProcess { total_returned: Int }
  AcceptCancellation
}

pub type LPTokenRedeemer {
  MintLP
  BurnLP
}

pub type MarkerRedeemer {
  MintMarkers { count: Int }
  BurnForClaim
  BurnForCancel
  BurnForExpire { count: Int }
}

// `"AEGIS_POLICY"` (12 bytes) — discriminator on marker policy id.
pub const policy_marker_asset_name: ByteArray =
  #"41454749535f504f4c494359"

// ---------------------------------------------------------------------------
// Cross-network protocol constants
// ---------------------------------------------------------------------------

pub const max_coverage_ratio: Int = 50

pub const cancellation_window: Int = 3_600_000

pub const cancellation_fee_bps: Int = 1_000

pub const price_scale: Int = 1_000_000

pub const min_utxo_lovelace: Int = 2_000_000

// 25% of the 2% protocol fee = 0.5% of premium routes via Conway
// treasury_donation. Pinned by validator hash, not datum.
pub const treasury_share_bps: Int = 2_500

pub const orcfax_ada_usd_feed_id: ByteArray = #"4345522f4144412d5553442f"

pub const orcfax_fs_asset_name: ByteArray = #""

pub const orcfax_fsp_asset_name: ByteArray = #"000de140"

// v7 widened to 70 min based on empirical mainnet observation
// (mean 45 min, p95 51 min, max 55 min).
pub const orcfax_freshness_window_ms: Int = 70 * 60 * 1_000

// 2000 bps of protocol fee = 20% of fee = 0.4% of premium max per partner.
pub const partner_share_cap_bps: Int = 2_000

// ---------------------------------------------------------------------------
// Per-network re-exports
//
// Switch to mainnet by changing the `use` line above to `aegis/types/mainnet`.
// That single edit is the only human-operator surface for network promotion;
// validator hashes rotate, making the change observable on chain.
// ---------------------------------------------------------------------------

pub const min_premium: Int = network.min_premium

pub const charli3_oracle_script_hash: ByteArray =
  network.charli3_oracle_script_hash

pub const charli3_ada_usd_nft_policy: ByteArray =
  network.charli3_ada_usd_nft_policy

pub const orcfax_fsp_script_hash: ByteArray = network.orcfax_fsp_script_hash

pub const aegis_self_publisher_vkh: ByteArray = network.aegis_self_publisher_vkh

pub const aegis_self_canonical_nfts: List<ByteArray> =
  network.aegis_self_canonical_nfts

pub const indigo_canonical_nfts: List<ByteArray> = network.indigo_canonical_nfts

// [POOL-FUNDED REPRICE] Established-stablecoin feeds eligible for the Depeg
// premium floor. The Underwrite Depeg branch pins the policy's oracle_nft to
// this set so the cheap duration-only floor can't be applied to a price
// barrier (ADA/BTC/CDP) or an under-priced Cardano-native depeg.
pub const depeg_eligible_nfts: List<ByteArray> = network.depeg_eligible_nfts

pub const indigo_oracle_script_hashes: List<ByteArray> =
  network.indigo_oracle_script_hashes

pub const team_address: Address = network.team_address

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test policy_datum_construction() {
  let datum =
    PolicyDatum {
      policy_id: #"aabb",
      insured: #"0011223344556677889900112233445566778899001122334455667788",
      strike_price: 350_000,
      coverage_amount: 5_000_000_000,
      premium_paid: 100_000_000,
      start_time: 1_700_000_000_000,
      expiry_time: 1_700_604_800_000,
      oracle_nft: #"886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e",
      pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
      pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
      oracle_provider: Charli3,
      partner_address: None,
      partner_share_bps: 0,
      risk_class: Barrier,
    }
  datum.strike_price == 350_000 && datum.coverage_amount == 5_000_000_000
}

test pool_datum_construction() {
  let datum =
    PoolDatum {
      total_liquidity: 100_000_000_000,
      active_coverage: 20_000_000_000,
      lp_token_policy: #"aabb",
      protocol_fee_bps: 200,
      pool_nft: #"ccdd",
      lp_supply: 100_000_000_000,
    }
  datum.total_liquidity == 100_000_000_000 && datum.protocol_fee_bps == 200
}

test constants_are_reasonable() {
  min_premium == 2_000_000 && max_coverage_ratio == 50 && cancellation_window == 3_600_000 && cancellation_fee_bps == 1_000
}

test orcfax_freshness_window_widened_for_v7() {
  orcfax_freshness_window_ms == 4_200_000 && orcfax_freshness_window_ms > 65 * 60 * 1_000
}

test aegis_self_publisher_vkh_is_28_bytes() {
  let len_ok = bytearray.length(aegis_self_publisher_vkh) == 28
  let value_ok =
    aegis_self_publisher_vkh == #"6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152"
  len_ok && value_ok
}

test policy_datum_aegis_self_variant_constructs() {
  let datum =
    PolicyDatum {
      policy_id: #"aabb",
      insured: #"0011223344556677889900112233445566778899001122334455667788",
      strike_price: 1_000_000,
      coverage_amount: 10_000_000_000,
      premium_paid: 100_000_000,
      start_time: 1_700_000_000_000,
      expiry_time: 1_700_604_800_000,
      oracle_nft: #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
      pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
      pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
      oracle_provider: AegisSelf,
      partner_address: None,
      partner_share_bps: 0,
      risk_class: Barrier,
    }
  let is_aegis_self =
    when datum.oracle_provider is {
      AegisSelf -> True
      _ -> False
    }
  datum.strike_price == 1_000_000 && is_aegis_self
}

test allowlist_accepts_ada_usd() {
  list.has(
    aegis_self_canonical_nfts,
    #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
  )
}

test allowlist_accepts_btc_usd() {
  list.has(
    aegis_self_canonical_nfts,
    #"ae304e27806536dbbc222115c2b543e845f99bd8c7a3a01669f2d7bd",
  )
}

test allowlist_accepts_eth_usd() {
  list.has(
    aegis_self_canonical_nfts,
    #"d80aa1a72a46813b5045e163751076d54551fac4a6f8d720e15807ad",
  )
}

test allowlist_accepts_usdc_usd() {
  list.has(
    aegis_self_canonical_nfts,
    #"860faa663d8a3ae3071d61f95464340c0e49c1f47f56db76441df7a0",
  )
}

test allowlist_accepts_usdt_usd() {
  list.has(
    aegis_self_canonical_nfts,
    #"a4093bfc7758b86ca1b96df842367bce96cb954650a392020246c0cb",
  )
}

test allowlist_rejects_non_canonical_nft() {
  !list.has(
    aegis_self_canonical_nfts,
    #"00112233445566778899001122334455667788990011223344556677",
  )
}

test allowlist_rejects_empty_nft() {
  !list.has(aegis_self_canonical_nfts, #"")
}

// Drift guard: any allowlist change must consciously edit this pin.
// Preprod = 9 (5 spot + 4 Surf event slots); mainnet = 10 (5 spot + iUSD
// relay + 4 Surf event slots). Discriminated on the profile's publisher
// VKH so the same test is correct under either shim.
test allowlist_size_pinned_per_profile() {
  let n = list.length(aegis_self_canonical_nfts)
  if aegis_self_publisher_vkh == #"6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152" {
    // preprod
    n == 9
  } else {
    // mainnet (publisher vkh bb09f432…)
    n == 10
  }
}

test team_address_payment_credential_28_bytes() {
  when team_address.payment_credential is {
    PaymentVKCred(h) -> bytearray.length(h) == 28
    _ -> False
  }
}

test team_address_has_stake_credential() {
  team_address.stake_credential != None
}

test partner_share_cap_bps_is_2000() {
  partner_share_cap_bps == 2_000
}

test policy_datum_v12_no_partner() {
  let datum =
    PolicyDatum {
      policy_id: #"aabb",
      insured: #"0011223344556677889900112233445566778899001122334455667788",
      strike_price: 350_000,
      coverage_amount: 5_000_000_000,
      premium_paid: 100_000_000,
      start_time: 1_700_000_000_000,
      expiry_time: 1_700_604_800_000,
      oracle_nft: #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
      pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
      pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
      oracle_provider: AegisSelf,
      partner_address: None,
      partner_share_bps: 0,
      risk_class: Barrier,
    }
  datum.partner_share_bps == 0 && datum.partner_address == None
}

test policy_datum_v12_with_partner() {
  let datum =
    PolicyDatum {
      policy_id: #"aabb",
      insured: #"0011223344556677889900112233445566778899001122334455667788",
      strike_price: 350_000,
      coverage_amount: 5_000_000_000,
      premium_paid: 100_000_000,
      start_time: 1_700_000_000_000,
      expiry_time: 1_700_604_800_000,
      oracle_nft: #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
      pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
      pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
      oracle_provider: AegisSelf,
      partner_address: Some(team_address),
      partner_share_bps: 2_000,
      risk_class: Barrier,
    }
  datum.partner_share_bps == 2_000
}

test policy_datum_indigo_variant_constructs() {
  let datum =
    PolicyDatum {
      policy_id: #"aabb",
      insured: #"0011223344556677889900112233445566778899001122334455667788",
      strike_price: 1_000_000,
      coverage_amount: 10_000_000_000,
      premium_paid: 100_000_000,
      start_time: 1_700_000_000_000,
      expiry_time: 1_700_604_800_000,
      oracle_nft: #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
      pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
      pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
      oracle_provider: Indigo,
      partner_address: None,
      partner_share_bps: 0,
      risk_class: Barrier,
    }
  let is_indigo =
    when datum.oracle_provider is {
      Indigo -> True
      _ -> False
    }
  datum.strike_price == 1_000_000 && is_indigo
}

test indigo_canonical_nfts_size_is_exactly_four() {
  list.length(indigo_canonical_nfts) == 4
}

test indigo_oracle_script_hashes_size_matches_nft_count() {
  list.length(indigo_oracle_script_hashes) == list.length(indigo_canonical_nfts)
}

test indigo_accepts_iusd_preprod_nft() {
  list.has(
    indigo_canonical_nfts,
    #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
  )
}

test indigo_accepts_ibtc_preprod_nft() {
  list.has(
    indigo_canonical_nfts,
    #"1e66200fca30b83d5937b67b896fa46f1adac98922555f9e791c1c83",
  )
}

test indigo_accepts_ieth_preprod_nft() {
  list.has(
    indigo_canonical_nfts,
    #"e81e84a5d34137bcbc2ba73f1b4e735ac0cc375f0bfeb5e98a397102",
  )
}

test indigo_accepts_isol_preprod_nft() {
  list.has(
    indigo_canonical_nfts,
    #"875cea49cb6963ad462187f77dcc5b4d458a66d7eb9a646c2c5405a7",
  )
}

test indigo_rejects_unknown_nft() {
  !list.has(
    indigo_canonical_nfts,
    #"00112233445566778899001122334455667788990011223344556677",
  )
}

test indigo_rejects_empty_nft() {
  !list.has(indigo_canonical_nfts, #"")
}

test indigo_disjoint_from_aegis_self() {
  !list.has(
    indigo_canonical_nfts,
    #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
  ) && !list.has(
    aegis_self_canonical_nfts,
    #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
  )
}

test indigo_oracle_script_hash_first_entry_is_28_bytes() {
  when indigo_oracle_script_hashes is {
    [first, ..] -> bytearray.length(first) == 28
    [] -> False
  }
}

test indigo_canonical_nft_first_entry_is_28_bytes() {
  when indigo_canonical_nfts is {
    [first, ..] -> bytearray.length(first) == 28
    [] -> False
  }
}

// Structural guards that hold across every legitimate allowlist size: all
// entries are 28-byte policy ids and the Surf event slots are present on
// the active profile (preprod slot 5 / mainnet slot 6 = SURF1).
test aegis_self_canonical_nfts_all_entries_28_bytes() {
  list.all(aegis_self_canonical_nfts, fn(n) { bytearray.length(n) == 28 })
}

test allowlist_accepts_surf_event_slot_1() {
  if aegis_self_publisher_vkh == #"6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152" {
    // preprod SURF1/EVT (mint tx bdff0f13…)
    list.has(
      aegis_self_canonical_nfts,
      #"7b53817a1cda197ca26883a25adb51631f3368094c721751ae9ceb23",
    )
  } else {
    // mainnet SURF1/EVT (mint tx eff6efe8…)
    list.has(
      aegis_self_canonical_nfts,
      #"c2f62874c860e1fc87bae0043066e551153f30fcc5d9944a370e8f8d",
    )
  }
}
