use cardano/address.{
  Address, from_verification_key, with_delegation_key,
}

pub const min_premium: Int = 20_000_000

/// [#363] beacon-swap governance timelock — 72h on mainnet: every rules/admin
/// change gives LPs at least a 72h notice + exit window before it takes effect.
/// POSIX ms.
pub const registry_timelock_ms: Int = 259_200_000

/// [#363] CancelUpdate re-propose cooldown — 24h on mainnet (stops
/// cancel->re-propose churn keeping a perpetual pending window).
pub const cancel_cooldown_ms: Int = 86_400_000

// Charli3 is soft-disabled in V12.2; placeholders kept so the type
// surface compiles. Replace before any mainnet path takes Charli3 live.
pub const charli3_oracle_script_hash: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000"

pub const charli3_ada_usd_nft_policy: ByteArray =
  #"08c56c0fa73748a23c3bc1d9e6a60a4187416fc4ff8fe3475506990e"

// Orcfax FSP — same hash across networks per `docs.orcfax.io/consume`.
pub const orcfax_fsp_script_hash: ByteArray =
  #"8793893b5dda6a513ba63c80e9d7b2d4f108060c11979bfc7d863ff0"

// Publisher VKH — late-bound. Mint mainnet AEGIS_PRICE_FEED_* NFTs from a
// fresh wallet, then fill in. Zero-VKH placeholder fails closed at validation.
pub const aegis_self_publisher_vkh: ByteArray =
  #"bb09f43245759995440388db9ef3f8a614246e8da1dd9bd053261347"

// AegisSelf publisher NFT allowlist (one-shot policy ids minted under
// publisher VKH bb09f432). Slots 0-4: ADA/BTC/ETH/USDC/USDT spot feeds;
// slot 5: Indigo iUSD CDP relay feed (AEGIS_PRICE_FEED_IUSD_USD_V1);
// slots 6-9: Surf event-trigger slots (AEGIS_PRICE_FEED_SURF<N>_EVT_V1,
// minted tx eff6efe8… 2026-06-13) — binary liquidation-state feeds
// ($1.00 armed / $0.10 on a classified on-chain liquidation; policies
// strike at $0.50). slot 10: USDM/USD depeg feed
// (AEGIS_PRICE_FEED_USDM_USD_V1, mint tx d27a8961… 2026-07-01) — Mehen USDM
// is DEX-priced (no CEX), published via dex_source. The validator gates on
// policy-id membership only.
pub const aegis_self_canonical_nfts: List<ByteArray> =
  [
    #"9ea4f1d76c7cc552a0925ac190bb5bc170bcb6d86a1bbb04c5859631",
    #"99e8fe4f9d2a4a85f5e3f20d37b10048ce54e4a03e56d9fd492163b3",
    #"a8c5354a4813f2b3f60836839b8842a9422186f4f15511790ec95f9c",
    #"c855c7619c999f60f023ab513733bb4fc9508d33b0062be353834630",
    #"531bc8aaac5dbf0a27e4c53d28b327ddfa2e1750ac7de774c791175d",
    #"f6458f3b7a6b2027fe89c39a622956336ec3253b7d65971f0cb64b02",
    #"c2f62874c860e1fc87bae0043066e551153f30fcc5d9944a370e8f8d",
    #"f4e78f3636248838c2d5c6578062cfb78f385482b0078de7aff5cc3b",
    #"68a1b0c1dab38159e9aae015c2c577a8da3661f921410dbad6276b2f",
    #"47c16934540cdead6045f947b1a7fd4b910bc0352a269b11800d0bed",
    #"b99998ba0353f47137fb9499da624b63a855d60719d4902777312439",
  ]


/// [#363 F5] Drift guard for the list ABOVE, declared beside it so any allowlist
/// edit must consciously update this too. Pinned PER-NETWORK.
pub const canonical_nft_count: Int = 11

// [#381 V8.1 S5] Pyth Lazer fallback feed-id per canonical slot, POSITIONAL
// with the list above (same index = same feed); #"" = no fallback, the pair is
// AegisSelf-only. Slots 0-4 = ADA/BTC/ETH/USDC/USDT.
//
// Slot 5 (iUSD relay) = #"10" (Lazer ADA/USD). This REVERSES the original
// "falling back reintroduces the basis risk the relay exists to kill" note,
// which had the direction backwards: Indigo's own liquidation oracle IS Pyth
// Lazer ADA/USD (api/indigo.py:806, verified against a mainnet CDP tx), and the
// relay exists only to republish Indigo's Pyth-attested price onto an AegisSelf
// feed so validators that could not read Pyth would trigger on it. Settling the
// fallback on feed 16 lands on the EXACT price Indigo liquidates at — the proxy
// IS the property — so it removes basis rather than adding it. Without it, an
// Indigo CDP policy cannot settle at all while OUR publisher is silent,
// whatever Indigo settles on.
//
// Slots 6-9 (Surf event binaries) and slot 10 (USDM) keep #"": no price oracle
// publishes an in-house liquidation-state classifier, and Pyth Lazer's registry
// carries no Cardano-native stable. Those two are genuine feed absence, not
// doctrine.
pub const pyth_fallback_feed_ids_by_slot: List<ByteArray> =
  [
    #"10",
    #"01",
    #"02",
    #"07",
    #"08",
    #"10",
    #"",
    #"",
    #"",
    #"",
    #"",
  ]

// [V8.2] THE CEREMONY'S ROLE <-> PURPOSE MAP. See types/preprod.ak for why it
// is declared here and not beside the anchors: `AEGIS_ANCHORS_JSON` replaces the
// anchors wholesale and is the documented mainnet route, so the assignment a
// rotation gets wrong has to live somewhere the anchors file cannot reach.
//
// POSITIONAL with `aegis_self_canonical_nfts` above. Slots 0/3/4 are the three
// spot feeds the V8.2 mandate carries; every other slot is a feed this ceremony
// mints no identity for (BTC, ETH, the iUSD relay, the four Surf binaries and
// USDM all predate it), and #"" says so rather than leaving it to a length.
pub const ceremony_role_by_slot: List<ByteArray> =
  [
    #"666565642e6164615f757364",
    // feed.ada_usd
    #"", #"", #"666565642e757364635f757364",
    // feed.usdc_usd
    #"666565642e757364745f757364",
    // feed.usdt_usd
    #"", #"", #"", #"", #"", #"",
  ]

// Flat (role, ASSET NAME) pairs — see types/preprod.ak for why the generation
// label is declared here beside the purpose rather than in a second list. The
// mainnet ADA/USD trust root was AEGIS_PRICE_FEED_V1 until the 2026-08-19
// re-mint; the operator ruled on 2026-08-18 (WORK.md Decisions,
// does-the-re-minted-mainnet-ada-usd-feed) that the re-minted feed takes
// AEGIS_PRICE_FEED_ADA_USD_V1 so both networks name it the same way, and this
// declaration was thirteen hours older than that ruling. The map stays
// per-network because declaring a
// preprod trust root for a mainnet ceremony (or the reverse) is refused by the
// name it carries, not only by the allowlist it is absent from.
pub const ceremony_role_names: List<ByteArray> =
  [
    #"706f6f6c", #"41454749535f504f4f4c5f5638324d",
    // pool -> AEGIS_POOL_V82M
    #"7265676973747279", #"41454749535f52454749535452595f5638324d",
    // registry -> AEGIS_REGISTRY_V82M
    #"666565642e6164615f757364", #"41454749535f50524943455f464545445f4144415f5553445f5631",
    // feed.ada_usd -> AEGIS_PRICE_FEED_ADA_USD_V1
    #"666565642e757364635f757364",
    #"41454749535f50524943455f464545445f555344435f5553445f5631",
    // feed.usdc_usd -> AEGIS_PRICE_FEED_USDC_USD_V1
    #"666565642e757364745f757364",
    #"41454749535f50524943455f464545445f555344545f5553445f5631",
    // feed.usdt_usd -> AEGIS_PRICE_FEED_USDT_USD_V1
    //
    // BTC and ETH are named here and DELIBERATELY absent from
    // `ceremony_role_by_slot` above, which is what says this ceremony mints no
    // identity for them. The two constants answer different questions: the slot
    // map says WHICH allowlist entries this ceremony fills, this map says what
    // asset name a role's NFT carries. The second is true of a feed minted long
    // before the ceremony, and it is the only thing that can answer for the
    // name: `identity_census.identity_bindings` accounts a native role's name
    // against exactly this declaration, so leaving them out left two live
    // mainnet identities with a policy id the chain proves and a name nothing
    // in the tree does. Naming them ADDS a check — assert_role_carries_its_
    // declared_name now covers them too — rather than removing one.
    #"666565642e6274635f757364",
    #"41454749535f50524943455f464545445f4254435f5553445f5631",
    // feed.btc_usd -> AEGIS_PRICE_FEED_BTC_USD_V1  (predates this ceremony)
    #"666565642e6574685f757364",
    #"41454749535f50524943455f464545445f4554485f5553445f5631",
    // feed.eth_usd -> AEGIS_PRICE_FEED_ETH_USD_V1  (predates this ceremony)
  ]

// [POOL-FUNDED REPRICE] Established-stablecoin feeds eligible for the Depeg
// premium floor (USDC, USDT — slots 3,4; USDM — slot 10 of the mainnet
// AegisSelf allowlist). See preprod.ak for the rationale: pins risk_class=Depeg
// to a genuine $1 feed.
pub const depeg_eligible_nfts: List<ByteArray> =
  [
    #"c855c7619c999f60f023ab513733bb4fc9508d33b0062be353834630",
    #"531bc8aaac5dbf0a27e4c53d28b327ddfa2e1750ac7de774c791175d",
    #"b99998ba0353f47137fb9499da624b63a855d60719d4902777312439",
  ]

// [Pyth Wave 1] Pyth State NFT policy id on Cardano MAINNET. VERIFIED on
// mainnet: the "Pyth State" token lives under this policy at script address
// addr1w9kskr8xl3pndssgxa72sk5e5lsc455r5wcervgfhmae4vgpyhzl4. This is the
// `pyth_id` passed to `pyth.get_updates`. 28-byte Blake2b-224 policy hash.
pub const pyth_state_nft_policy: ByteArray =
  #"c935c937d0deda8975142c7b77aeef8f8cd48791e89a8ca7a0edc154"

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

// Flux Point Studios mainnet team wallet
// addr1q9s6m9d8yedfcf53yhq5j5zsg0s58wpzamwexrxpfelgz2wgk0s9l9fqc93tyc8zu4z7hp9dlska2kew9trdg8nscjcq3sk5s3
pub const team_address: Address =
  from_verification_key(
    #"61ad95a7265a9c269125c149505043e143b822eedd930cc14e7e8129",
  )
    |> with_delegation_key(
        #"c8b3e05f9520c162b260e2e545eb84adfc2dd55b2e2ac6d41e70c4b0",
      )
