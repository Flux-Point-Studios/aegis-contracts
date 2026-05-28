use cardano/address.{
  Address, from_verification_key, with_delegation_key,
}

pub const min_premium: Int = 2_000_000

pub const charli3_oracle_script_hash: ByteArray =
  #"221ee21e9607f766e1e1223248f67320014825169a1d98eb34c6f658"

pub const charli3_ada_usd_nft_policy: ByteArray =
  #"886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e"

pub const orcfax_fsp_script_hash: ByteArray =
  #"0690081bc113f74e04640ea78a87d88abbd2f18831c44c4064524230"

pub const aegis_self_publisher_vkh: ByteArray =
  #"6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152"

pub const aegis_self_canonical_nfts: List<ByteArray> =
  [
    #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
    #"ae304e27806536dbbc222115c2b543e845f99bd8c7a3a01669f2d7bd",
    #"d80aa1a72a46813b5045e163751076d54551fac4a6f8d720e15807ad",
    #"860faa663d8a3ae3071d61f95464340c0e49c1f47f56db76441df7a0",
    #"a4093bfc7758b86ca1b96df842367bce96cb954650a392020246c0cb",
  ]

pub const indigo_canonical_nfts: List<ByteArray> =
  [
    #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
    #"1e66200fca30b83d5937b67b896fa46f1adac98922555f9e791c1c83",
    #"e81e84a5d34137bcbc2ba73f1b4e735ac0cc375f0bfeb5e98a397102",
    #"875cea49cb6963ad462187f77dcc5b4d458a66d7eb9a646c2c5405a7",
  ]

pub const indigo_oracle_script_hashes: List<ByteArray> =
  [
    #"d27ccc13fab5b782984a3d1f99353197ca1a81be069941ffc003ee75",
    #"d27ccc13fab5b782984a3d1f99353197ca1a81be069941ffc003ee75",
    #"d27ccc13fab5b782984a3d1f99353197ca1a81be069941ffc003ee75",
    #"d27ccc13fab5b782984a3d1f99353197ca1a81be069941ffc003ee75",
  ]

pub const team_address: Address =
  from_verification_key(
    #"c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe",
  )
    |> with_delegation_key(
        #"757f0678d8b83f9a1373a38cb9800d0f862951305b4d221e69bccab2",
      )
