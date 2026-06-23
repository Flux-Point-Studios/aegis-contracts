use cardano/address.{
  Address, from_verification_key, with_delegation_key,
}

pub const min_premium: Int = 20_000_000

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
// strike at $0.50). The validator gates on policy-id membership only.
pub const aegis_self_canonical_nfts: List<ByteArray> =
  [
    #"f0f14cd0dd1cae52398360e3e4001375000032cb392cb3efeb342301",
    #"99e8fe4f9d2a4a85f5e3f20d37b10048ce54e4a03e56d9fd492163b3",
    #"a8c5354a4813f2b3f60836839b8842a9422186f4f15511790ec95f9c",
    #"a8231f0c10b514659fd590f6ee7420acf4e145cce36909a7f5fe1c5e",
    #"82a324a3de0be7bc9c4b8450db5350cf0479fa1393eb8eee2481c652",
    #"f6458f3b7a6b2027fe89c39a622956336ec3253b7d65971f0cb64b02",
    #"c2f62874c860e1fc87bae0043066e551153f30fcc5d9944a370e8f8d",
    #"f4e78f3636248838c2d5c6578062cfb78f385482b0078de7aff5cc3b",
    #"68a1b0c1dab38159e9aae015c2c577a8da3661f921410dbad6276b2f",
    #"47c16934540cdead6045f947b1a7fd4b910bc0352a269b11800d0bed",
  ]

// Indigo canonical iAsset oracle NFT policy ids on mainnet (live, Koios-
// validated 2026-05-12). Ordering load-bearing: 0=iUSD, 1=iBTC, 2=iETH,
// 3=iSOL. Paired with indigo_oracle_script_hashes by index.
pub const indigo_canonical_nfts: List<ByteArray> =
  [
    #"e3455f2715338b454fb853442f72dc03b98396854f97510027fe22ff",
    #"408f13b240f57c3473b5727a68a88c50c1b6bb15c0c10912008dc59e",
    #"6c9497ffd7e8baf86c3c0d6fcd43c524daa49ad5fceba26d715468e9",
    #"107992fe118ef6ae341ae0996f355124e03a8fccdcade60692175df2",
  ]

pub const indigo_oracle_script_hashes: List<ByteArray> =
  [
    #"1042576d1de963437bd4bb50dcd91459756e6812b7c06dd543a332c8",
    #"d27ad3ed7b073018d429e57c2f8d1f52445aa241e280e6da149a91b4",
    #"f350350cd40d0d8e8744f2c6cad54a0abc9d51f107f57fb95c181a3f",
    #"e3c50817e0fbaab03e4411249cfcb22aa004844e9ad86ca4d76524bc",
  ]

// [POOL-FUNDED REPRICE] Established-stablecoin feeds eligible for the Depeg
// premium floor (USDC, USDT — slots 3,4 of the mainnet AegisSelf allowlist).
// See preprod.ak for the rationale: pins risk_class=Depeg to a genuine $1 feed.
pub const depeg_eligible_nfts: List<ByteArray> =
  [
    #"a8231f0c10b514659fd590f6ee7420acf4e145cce36909a7f5fe1c5e",
    #"82a324a3de0be7bc9c4b8450db5350cf0479fa1393eb8eee2481c652",
  ]

// Flux Point Studios mainnet team wallet
// addr1q9s6m9d8yedfcf53yhq5j5zsg0s58wpzamwexrxpfelgz2wgk0s9l9fqc93tyc8zu4z7hp9dlska2kew9trdg8nscjcq3sk5s3
pub const team_address: Address =
  from_verification_key(
    #"61ad95a7265a9c269125c149505043e143b822eedd930cc14e7e8129",
  )
    |> with_delegation_key(
        #"c8b3e05f9520c162b260e2e545eb84adfc2dd55b2e2ac6d41e70c4b0",
      )
