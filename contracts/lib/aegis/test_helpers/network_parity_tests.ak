// =============================================================================
// Aegis Insurance Protocol - Cross-network constant parity tests
// Location: contracts/lib/aegis/test_helpers/network_parity_tests.ak
// Test-only.
//
// [#363 R4] Restores FALSIFIABILITY to the network-pinned constants.
//
// The F5 pass (abcfe33) fixed a real problem — test fixtures hardcoded one
// profile's oracle inventory, so 55 tests went dark the moment that profile was
// re-parameterized — by making every fixture DERIVE from the active network
// module. That was correct, but it removed the last thing anchoring those
// constants to a known value: each fixture test is now self-consistent with
// whatever the constant happens to hold. Substituting an attacker-controlled
// publisher VKH or feed policy id leaves the whole suite green.
//
// `canonical_nft_count` does not close this. The count is re-exported from the
// SAME module as the list it guards, so it catches an unaccompanied length edit
// and nothing else — never a value substitution, never a cross-network mixup.
//
// The compensating control cited when those pins were demoted is the #361
// deploy-time network-flip fingerprint. That control lives outside contracts/,
// and nothing in the test surface verifies it exists, runs, or covers these
// specific constants. #360 was precisely this failure mode reaching mainnet: a
// validator compiled against preprod constants, breaking every V7 Barrier
// policy in phase 2.
//
// The trick that makes a value pin work under BOTH network modules: reference
// the profile modules DIRECTLY rather than through `aegis/types`'s `network`
// alias. These assertions then evaluate identically whichever profile is
// active, so they are green on both while still being falsifiable.
//
// MAINNET values are pinned by literal because they guard real funds and rotate
// only at a ceremony. PREPROD values are pinned only by DISTINCTNESS from
// mainnet — a wrong preprod constant costs a failed testnet tx, and pinning it
// by literal would mean editing this file at every preprod re-parameterization,
// which is the churn F5 was right to remove.
// =============================================================================

use aegis/types.{OracleMandate} as aegis_types
use aegis/types/mainnet
use aegis/types/preprod
use aiken/collection/list
use aiken/primitive/bytearray

// ---------------------------------------------------------------------------
// Mainnet identity — literal pins on the fund-guarding values
// ---------------------------------------------------------------------------

test mainnet_publisher_vkh_is_pinned() {
  // The publisher credential is one half of the AegisSelf trust handshake: a
  // feed UTxO resolves only at THIS payment credential. A wrong value here
  // either bricks every mainnet AegisSelf policy or, if it is a key someone
  // else controls, hands them the price feed the validator settles on.
  mainnet.aegis_self_publisher_vkh == #"bb09f43245759995440388db9ef3f8a614246e8da1dd9bd053261347"
}

test mainnet_canonical_allowlist_is_pinned() {
  // [#363 R4] Pins ALL ELEVEN entries, not just slot 0. The first version of
  // this file pinned only the primary feed and the three depeg feeds, leaving
  // SEVEN of eleven substitutable with a fully green suite — and I claimed in
  // 73f1e46 that "the mainnet side is closed", which was false. Proven by
  // mutation: slot 1 -> deadbeef left 818/818 green.
  //
  // This list IS the oracle trust root. `find_feed_output` resolves a feed by
  // policy-id membership here PLUS the publisher payment credential, and anyone
  // may send a UTxO to a known address — so a forged policy id admitted to this
  // list is a complete oracle compromise, not a degraded feed.
  //
  // Slots: 0-4 ADA/BTC/ETH/USDC/USDT spot, 5 iUSD CDP relay, 6-9 Surf event
  // slots, 10 USDM depeg.
  //
  // [V8.2M 2026-08-19] Slots 0, 3 and 4 moved: the V8.2 mainnet ceremony
  // re-minted ADA, USDC and USDT under a TIMELOCKED native policy
  // (all[sig bb09f432, before 195622854], mint 2cea1f57) so the allowlist can
  // never gain a twelfth entry from the publisher key alone. The retired ids
  // are pinned below rather than deleted — this is the one file that can prove
  // the substitution was the ceremony's and not an attacker's, and slots 1, 2
  // and 5-10 holding still is half of that proof.
  mainnet.aegis_self_canonical_nfts == [
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
}

test mainnet_depeg_feeds_are_pinned() {
  // USDC, USDT, USDM. These decide which feeds may take the cheap duration-only
  // Depeg floor; an extra entry here is a mispriced product line.
  //
  // [V8.2M 2026-08-19] USDC and USDT follow the allowlist re-mint above; USDM
  // was NOT re-minted and must not move, which is the assertion that keeps this
  // from reading as "three ids changed, presumably fine".
  mainnet.depeg_eligible_nfts == [
    #"c855c7619c999f60f023ab513733bb4fc9508d33b0062be353834630",
    #"531bc8aaac5dbf0a27e4c53d28b327ddfa2e1750ac7de774c791175d",
    #"b99998ba0353f47137fb9499da624b63a855d60719d4902777312439",
  ]
}

test mainnet_retired_feed_ids_are_gone() {
  // The three ids the V8.2M ceremony replaced, kept as an explicit NEGATIVE so
  // the substitution above is falsifiable in both directions. A pin alone only
  // says "the list equals X"; re-pinning it is a one-line edit, and the edit
  // that would matter is the one that quietly restores the pre-ceremony trust
  // root. These policies are seed-bound one-shots under a key the ceremony
  // proved was never persisted, so nothing can re-mint into them — but the
  // validator resolves a feed by POLICY-ID MEMBERSHIP, so a list that admits
  // them again admits every NFT they already minted.
  let retired =
    [
      #"f0f14cd0dd1cae52398360e3e4001375000032cb392cb3efeb342301",
      #"a8231f0c10b514659fd590f6ee7420acf4e145cce36909a7f5fe1c5e",
      #"82a324a3de0be7bc9c4b8450db5350cf0479fa1393eb8eee2481c652",
    ]
  list.all(
    retired,
    fn(n) {
      !list.has(mainnet.aegis_self_canonical_nfts, n) && !list.has(
        mainnet.depeg_eligible_nfts,
        n,
      )
    },
  )
}

test mainnet_min_premium_is_pinned() {
  mainnet.min_premium == 20_000_000
}

test mainnet_timelocks_are_pinned() {
  // 72h notice + 24h re-propose cooldown is the LP exit guarantee the whole V8
  // governance story rests on. Shortening it is a silent removal of that right.
  mainnet.registry_timelock_ms == 259_200_000 && mainnet.cancel_cooldown_ms == 86_400_000
}

// ---------------------------------------------------------------------------
// Cross-profile distinctness — catches a mixup in EITHER direction
// ---------------------------------------------------------------------------

test profiles_do_not_share_a_publisher_vkh() {
  preprod.aegis_self_publisher_vkh != mainnet.aegis_self_publisher_vkh
}

test profiles_do_not_share_a_feed() {
  // Any shared entry means one profile's validator would accept the other's
  // feed — the #360 wrong-constants class, detectable here rather than in
  // phase 2 on chain.
  list.all(
    preprod.aegis_self_canonical_nfts,
    fn(n) { !list.has(mainnet.aegis_self_canonical_nfts, n) },
  )
}

test profiles_do_not_share_a_team_address() {
  preprod.team_address != mainnet.team_address
}

test preprod_timelocks_are_strictly_shorter_than_mainnet() {
  // Preprod is deliberately short so a Propose -> Enact cycle can be proven
  // in-session. If the two ever converge, either preprod became unprovable or
  // mainnet lost its notice period.
  preprod.registry_timelock_ms < mainnet.registry_timelock_ms && preprod.cancel_cooldown_ms < mainnet.cancel_cooldown_ms
}

// ---------------------------------------------------------------------------
// Structural invariants asserted on BOTH profiles, not just the active one
// ---------------------------------------------------------------------------

test both_profiles_have_canonical_depeg_feeds() {
  // `depeg_feeds_are_canonical` in types.ak checks only the ACTIVE module, so
  // a broken inactive profile ships green and fails at its own ceremony.
  and {
    list.all(
      preprod.depeg_eligible_nfts,
      fn(n) { list.has(preprod.aegis_self_canonical_nfts, n) },
    ),
    list.all(
      mainnet.depeg_eligible_nfts,
      fn(n) { list.has(mainnet.aegis_self_canonical_nfts, n) },
    ),
  }
}

test both_profiles_have_consistent_canonical_counts() {
  list.length(preprod.aegis_self_canonical_nfts) == preprod.canonical_nft_count && list.length(
    mainnet.aegis_self_canonical_nfts,
  ) == mainnet.canonical_nft_count
}

test both_profiles_have_well_formed_publisher_vkhs() {
  bytearray.length(preprod.aegis_self_publisher_vkh) == 28 && bytearray.length(
    mainnet.aegis_self_publisher_vkh,
  ) == 28
}

test both_profiles_have_28_byte_feed_policies() {
  and {
    list.all(
      preprod.aegis_self_canonical_nfts,
      fn(n) { bytearray.length(n) == 28 },
    ),
    list.all(
      mainnet.aegis_self_canonical_nfts,
      fn(n) { bytearray.length(n) == 28 },
    ),
  }
}

// [#381 V8.1 S1] The Pyth feed-id allowlists are pinned by LITERAL on both
// profiles. They are deliberately EQUAL — Lazer feed-ids are network-agnostic
// (ADA/USD = 16 = #"10" everywhere); what differs per network is the State
// NFT policy, pinned above. Any widening must edit BOTH pins consciously
// (genesis scope is ADA/USD-only per the V8.1 spec / OQ2 basis gate).
test s1_parity_pyth_feed_allowlists_pinned() {
  // BTC/ETH/USDC/USDT/ADA — the 5 AegisSelf spot feeds with verified Lazer
  // equivalents (OQ4 resolved 2026-07-30: stables in scope, calibration-gated).
  let pinned = [#"01", #"02", #"07", #"08", #"10"]
  mainnet.pyth_canonical_feed_ids == pinned && preprod.pyth_canonical_feed_ids == pinned
}

// ---------------------------------------------------------------------------
// [#381 V8.1 S5] Mandate-map coupling invariants. The fallback feed-id maps
// are literal-pinned on BOTH profiles (unlike the primary NFT bytes, the
// feed-id side does not rotate with a re-parameterization), and the coupling
// to the Pyth allowlist is enforced in the SAFETY direction everywhere:
// every mandated fallback id must be canonical, or settle_price's
// is_canonical gate bricks the fallback exactly when the outage needs it.
// On MAINNET the coupling is exact (image == allowlist, as sets). On preprod
// the allowlist is deliberately wider (5 ids on both profiles, pinned above)
// than the 3-primary image: the width is what lets the real-Lazer-payload
// fixtures (feeds 1/2) run under the preprod module, and an allowlisted-but-
// unmandated id is inert on-chain — settle_price requires a mandate entry.
// ---------------------------------------------------------------------------

test s5_parity_fallback_maps_pinned() {
  // slot-positional truth: mainnet 0-4 = ADA/BTC/ETH/USDC/USDT; slot 5 = the
  // iUSD relay, which falls back to #"10" (Lazer ADA/USD) because that is the
  // EXACT price Indigo liquidates at — the relay only republishes Indigo's
  // Pyth-attested price, so the fallback removes basis rather than adding it.
  // Slots 6-9 (Surf event binaries) and 10 (USDM) have NO fallback and cannot:
  // no price oracle publishes a liquidation-state classifier, and Lazer carries
  // no Cardano-native stable.
  //
  // preprod slots 0-2 = ADA/USDC/USDT, then BTC and ETH APPENDED at V8H rather
  // than inserted at mainnet's 1/2. The two profiles deliberately do NOT share
  // an ordering: the slot index is what `list.map2` zips against, so inserting
  // to match mainnet would repoint every live preprod policy at another asset's
  // feed. Parity here means "each profile pins ITS OWN order", never "the two
  // orders agree".
  let mainnet_pinned =
    [#"10", #"01", #"02", #"07", #"08", #"10", #"", #"", #"", #"", #""]
  let preprod_pinned = [#"10", #"07", #"08", #"01", #"02"]
  and {
    mainnet.pyth_fallback_feed_ids_by_slot == mainnet_pinned,
    preprod.pyth_fallback_feed_ids_by_slot == preprod_pinned,
  }
}

test s5_parity_fallback_map_lengths_match_canonical() {
  // list.map2 TRUNCATES on length mismatch: appending a 12th canonical NFT
  // without extending the fallback map would silently drop its mandate entry
  // (feed unmandated -> cover unbuyable, fail-closed but DARK). This makes
  // that drift loud on both profiles.
  and {
    list.length(mainnet.pyth_fallback_feed_ids_by_slot) == mainnet.canonical_nft_count,
    list.length(mainnet.aegis_self_canonical_nfts) == mainnet.canonical_nft_count,
    list.length(preprod.pyth_fallback_feed_ids_by_slot) == preprod.canonical_nft_count,
    list.length(preprod.aegis_self_canonical_nfts) == preprod.canonical_nft_count,
  }
}

test s5_parity_mandate_image_subset_of_allowlist() {
  // SAFETY direction, both profiles: every non-empty fallback id resolves the
  // confidence-gated canonical Pyth reader.
  let image_ok =
    fn(fallbacks: List<ByteArray>, allowlist: List<ByteArray>) {
      list.all(
        fallbacks,
        fn(fb) { fb == #"" || list.has(allowlist, fb) },
      )
    }
  and {
    image_ok(
      mainnet.pyth_fallback_feed_ids_by_slot,
      mainnet.pyth_canonical_feed_ids,
    ),
    image_ok(
      preprod.pyth_fallback_feed_ids_by_slot,
      preprod.pyth_canonical_feed_ids,
    ),
  }
}

test s5_parity_mainnet_image_equals_allowlist() {
  // EXACT SET coupling on the fund-guarding profile, in both directions: every
  // mandated fallback resolves the canonical reader, and every allowlisted feed
  // is named by at least one mandate entry (dead allowlist width = silent
  // resolve surface).
  //
  // Set equality, NOT a bijection. The map is legitimately many-to-one: the ADA
  // spot slot and the iUSD relay slot both settle on Lazer ADA/USD, because
  // both ARE ADA/USD prices. The former uniqueness assertion encoded an
  // accident of the 1:1 era, never a security property — the properties that
  // guard funds are the two subset directions below.
  let image =
    list.filter(mainnet.pyth_fallback_feed_ids_by_slot, fn(fb) { fb != #"" })
  and {
    list.all(image, fn(fb) { list.has(mainnet.pyth_canonical_feed_ids, fb) }),
    list.all(
      mainnet.pyth_canonical_feed_ids,
      fn(allowed) { list.has(image, allowed) },
    ),
  }
}

test s5_active_mandate_entries_zip_soundly() {
  // The builder the ceremony consumes: one entry per canonical primary, in
  // slot order, no duplicate primaries, under the ACTIVE network module.
  let entries = aegis_types.oracle_mandate_entries()
  and {
    list.length(entries) == aegis_types.canonical_nft_count,
    list.map(entries, fn(m: OracleMandate) { m.primary_nft }) == aegis_types.aegis_self_canonical_nfts,
    list.map(entries, fn(m: OracleMandate) { m.fallback_feed_id }) == aegis_types.pyth_fallback_feed_ids_by_slot,
    list.all(
      entries,
      fn(m: OracleMandate) {
        list.count(
          entries,
          fn(x: OracleMandate) { x.primary_nft == m.primary_nft },
        ) == 1
      },
    ),
  }
}
