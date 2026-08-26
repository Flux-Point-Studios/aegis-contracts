use cardano/address.{
  Address, from_verification_key, with_delegation_key,
}

pub const min_premium: Int = 2_000_000

/// [#363] beacon-swap governance timelock — SHORT on preprod so the full
/// ProposeUpdate -> EnactUpdate cycle can be proven on-chain in-session
/// (mainnet = 72h). POSIX ms.
pub const registry_timelock_ms: Int = 300_000

/// [#363] CancelUpdate re-propose cooldown — SHORT on preprod (mainnet = 24h).
pub const cancel_cooldown_ms: Int = 120_000

pub const charli3_oracle_script_hash: ByteArray =
  #"221ee21e9607f766e1e1223248f67320014825169a1d98eb34c6f658"

pub const charli3_ada_usd_nft_policy: ByteArray =
  #"886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e"

pub const orcfax_fsp_script_hash: ByteArray =
  #"0690081bc113f74e04640ea78a87d88abbd2f18831c44c4064524230"

// [V8 preprod-ceremony re-param] operator acct1 VKH — the ceremony operator
// controls the feed publisher address so a fresh feed can be published without
// the (unreachable) original preprod publisher key. PREPROD-ONLY test value.
pub const aegis_self_publisher_vkh: ByteArray =
  #"f3a07c9464bd7d8f3e54370fc414ef731c36a51e67316d21fecb2ffb"

// Slots 0-4: ADA/BTC/ETH/USDC/USDT spot feeds. Slots 5-8: Surf event-trigger
// slots (AEGIS_PRICE_FEED_SURF<N>_EVT_V1, minted tx bdff0f13… 2026-06-13) —
// binary liquidation-state feeds ($1.00 armed / $0.10 on a classified
// on-chain liquidation; policies strike at $0.50). The validator gates on
// policy-id membership only.
// [V8 preprod-ceremony re-param] the operator-minted one-shot FEED NFT
// (AEGIS_FEED_V8, tx 176c054e) — the ceremony's self-published ADA/USD feed sits
// at the operator publisher address carrying this token. PREPROD-ONLY test value.
pub const aegis_self_canonical_nfts: List<ByteArray> =
  [
    #"525621f5636b8de697d5d4c0c832cf77b2836bf0d688d1ceae620e88",
    // [#363 N2] The depeg feeds MUST also be canonical: Depeg Underwrite now
    // resolves the same pinned feed the Claim judges on, via attested_price,
    // which gates on this list. MAINNET already satisfied
    // `depeg_eligible_nfts ⊆ aegis_self_canonical_nfts`; preprod had drifted,
    // which would have made Depeg cover unbuyable here. Pinned by the
    // `depeg_feeds_are_canonical` test in types.ak.
    #"5d7ede22de207a4814bfc8a9ce3b97808e82eb8772ff3e29ac685040",
    #"6902b0c8e891f584992c1912d71aab6717b5441978a453c4b227dc23",
    // [V8H 2026-08-13] BTC and ETH APPENDED, not inserted. The list is
    // positional with the fallback slots below, so mainnet's 1/2 ordering would
    // silently re-aim ADA's, USDC's and USDT's fallbacks at the wrong Pyth ids.
    // Identities from api/oracles/aegis_self.py's preprod map.
    //
    // Until V8H these two were sellable NOWHERE on preprod: absent from the
    // mandate, `_assert_pyth_fallback_covered` refused them, so BTC/ETH cover
    // could be neither sold nor proven on the network that exists to prove it.
    // Adding them costs a GENERATION, measured: this list is compiled into
    // oracle_observer, whose hash is a pool_vault compile param, whose hash is
    // a pool_stake compile param. It is not a governed field and no registry
    // transition reaches it (see the mandate note in types.ak).
    #"f56403486730980da9d82ebccf16035225eae9c570678e6fe0077e18",
    #"df219f325fa0afdd02687b9e1d6016b106bdf12c2748796ef7b256ec",
  ]

/// [#363 F5] Drift guard for the list ABOVE, declared beside it so any allowlist
/// edit must consciously update this too. Pinned PER-NETWORK: the old guard in
/// types.ak branched on a hardcoded publisher VKH that had drifted, so preprod
/// silently fell to the mainnet arm and the pin could never pass.
pub const canonical_nft_count: Int = 5

// [#381 V8.1 S5] Positional with the list above: slot 0 = ADA/USD
// (AEGIS_FEED_V8), slot 1 = USDC, slot 2 = USDT, slot 3 = BTC, slot 4 = ETH.
// The id PER ASSET matches mainnet (ADA 10, BTC 01, ETH 02, USDC 07, USDT 08);
// the SLOT ORDER does not, because preprod grew ADA/USDC/USDT first and
// appending is what keeps those three pairings intact. (pair identities per
// api/oracles/aegis_self.py preprod map). The FEED-ID side is stable across
// preprod re-parameterizations (only the primary NFTs rotate), so it is
// literal-pinned in network_parity_tests unlike the NFT bytes.
pub const pyth_fallback_feed_ids_by_slot: List<ByteArray> =
  [
    #"10",
    #"07",
    #"08",
    #"01",
    #"02",
  ]

// [V8.2] THE CEREMONY'S ROLE <-> PURPOSE MAP, and it lives HERE on purpose.
//
// Distinctness is not identity. Rotating the three oracle trust roots around a
// cycle leaves every role with a DISTINCT purpose and every policy answering to
// its own witness, so nothing in v8_anchors could see it — only the ASSIGNMENT
// was wrong, and no rule said what the assignment should be. It cannot be
// declared beside the anchors either: `AEGIS_ANCHORS_JSON` is the documented
// mainnet route and it replaces the anchors wholesale, while this const is
// committed, compiled and already the source the mandate answers to.
//
// POSITIONAL with `aegis_self_canonical_nfts`: the ceremony identity role that
// owns each mandate slot, #"" for a slot the ceremony mints no identity for. A
// feed role's POLICY must be the allowlist entry at its own index.
pub const ceremony_role_by_slot: List<ByteArray> =
  [
    #"666565642e6164615f757364",
    // feed.ada_usd
    #"666565642e757364635f757364",
    // feed.usdc_usd
    #"666565642e757364745f757364",
    // feed.usdt_usd
    // [V8H] Positional with aegis_self_canonical_nfts, appended in the same
    // order the allowlist appended BTC and ETH.
    #"666565642e6274635f757364",
    // feed.btc_usd
    #"666565642e6574685f757364",
    // feed.eth_usd
  ]

// Flat (role, ASSET NAME) pairs for EVERY ceremony identity role, feed or not.
// The one-shot asset names are `<PURPOSE>_<GENERATION>` and BOTH halves are
// declared here, in one map, because a second list for the generation is the
// defect this map already exists to fix. It binds the NAME the way
// `ceremony_role_by_slot` binds the POLICY: a pool one-shot in the registry slot
// keeps a distinct purpose and a valid seed, and a role carrying the RIGHT
// purpose from a PREVIOUS generation keeps a valid witness too — a native feed
// policy id is blake2b-224 over the key alone, so the asset name is not an input
// to it and nothing else in the ceremony can see the stale label.
//
// The lineages are per-network: the preprod ADA/USD feed is AEGIS_FEED_V8 and
// the mainnet one is AEGIS_PRICE_FEED_V1.
pub const ceremony_role_names: List<ByteArray> =
  [
    #"706f6f6c", #"41454749535f504f4f4c5f563849",
    // pool -> AEGIS_POOL_V8I
    #"7265676973747279", #"41454749535f52454749535452595f563849",
    // registry -> AEGIS_REGISTRY_V8I
    #"666565642e6164615f757364", #"41454749535f50524943455f464545445f4144415f5553445f5631",
    // feed.ada_usd -> AEGIS_PRICE_FEED_ADA_USD_V1
    #"666565642e757364635f757364",
    #"41454749535f50524943455f464545445f555344435f5553445f5631",
    // feed.usdc_usd -> AEGIS_PRICE_FEED_USDC_USD_V1
    #"666565642e757364745f757364",
    #"41454749535f50524943455f464545445f555344545f5553445f5631",
    // feed.usdt_usd -> AEGIS_PRICE_FEED_USDT_USD_V1
    // [V8H] Positional with aegis_self_canonical_nfts, so these two arrive in
    // the same order the allowlist appended them.
    #"666565642e6274635f757364",
    #"41454749535f50524943455f464545445f4254435f5553445f5631",
    // feed.btc_usd -> AEGIS_PRICE_FEED_BTC_USD_V1
    #"666565642e6574685f757364",
    #"41454749535f50524943455f464545445f4554485f5553445f5631",
    // feed.eth_usd -> AEGIS_PRICE_FEED_ETH_USD_V1
  ]

// [POOL-FUNDED REPRICE] Established-stablecoin feeds eligible for the cheap
// duration-only Depeg premium floor (USDC, USDT — slots 3,4 of the AegisSelf
// allowlist). The Underwrite Depeg branch requires the policy's oracle_nft to
// be a member; this pins risk_class=Depeg to a genuine $1-pegged feed so it
// CANNOT be applied to an ADA/BTC price barrier (which would bypass the
// barrier floor) or to a fatter-tail Cardano-native coin (which the λ=0.08
// established floor under-prices). Native depeg stays blocked on-chain until a
// native-tier floor ships.
pub const depeg_eligible_nfts: List<ByteArray> =
  [
    #"5d7ede22de207a4814bfc8a9ce3b97808e82eb8772ff3e29ac685040",
    #"6902b0c8e891f584992c1912d71aab6717b5441978a453c4b227dc23",
  ]

// [#381 V8.1 S10/OQ1] Pyth State NFT policy on PREPROD — the SELF-PROVISIONED
// State (Pyth has no preprod deployment; their withdraw script compiles the
// MAINNET State policy into its body, so a byte-identical preprod re-host is
// impossible). Minted 2026-07-31, tx 967f1d05…#0 at
// addr_test1wr4l0pmc0gfnr7ln7qcsk0smxl64vq8h6vhl228mkwfp96qlasf29: datum is
// the live mainnet Pyth datum (same governance, same production trusted
// signer 80efc1f4… valid to ~2027-05) with withdraw_script swapped to
// pyth_withdraw_preprod (ebf78778…, reward account registered, non-withdraw
// purposes always fail so it can never be deregistered). ON-CHAIN PROVEN:
// tx e20b82cf… ran the withdraw script over the REAL production-signed Lazer
// update, valid_contract=True. Operator-sig mint policy = burn+re-mint
// recoverable under this SAME id.
pub const pyth_state_nft_policy: ByteArray =
  #"ce5b19147723c07887bac24c1c8f0fd06d4164ea7e7751d045b02ecf"

// [#381 V8.1 S1] Explicit allowlist of Pyth Lazer feed-ids Aegis will accept
// as a policy's oracle handle (big-endian bytes; ADA/USD = feed 16 = #"10").
// Scope (user decision 2026-07-30, OQ4 resolved): every AegisSelf spot
// feed with a Pyth equivalent — BTC=1, ETH=2, USDC=7, USDT=8, ADA=16
// (ids verified against the live Lazer symbols registry; see
// api/policies.py PYTH_SPOT_FEED_IDS). Per-pair basis haircut +
// per-class confidence ceilings stay OQ2-calibration-gated. An unlisted
// feed-id fails is_canonical_oracle_nft closed.
pub const pyth_canonical_feed_ids: List<ByteArray> =
  [#"01", #"02", #"07", #"08", #"10"]

pub const team_address: Address =
  from_verification_key(
    #"c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe",
  )
    |> with_delegation_key(
        #"757f0678d8b83f9a1373a38cb9800d0f862951305b4d221e69bccab2",
      )
