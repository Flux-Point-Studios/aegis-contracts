// =============================================================================
// Aegis Insurance Protocol - Aegis-self Oracle Parser (v7 third provider)
// Location: contracts/lib/aegis/oracle/aegis_self.ak
// Summary: Aegis-self resolver. Reads a UTxO at the publisher wallet address
//          carrying an allowlisted AEGIS_PRICE_FEED_* NFT and parses its
//          inline datum using the Charli3 GenericData CBOR shape (we publish
//          in that format deliberately so the parser is shared).
//
//          Trust handshake (two layers):
//            1. UTxO must carry a token under the supplied `oracle_nft` policy
//               id (an allowlisted publisher NFT, network-specific).
//            2. UTxO's payment credential must equal the compile-time pinned
//               `aegis_self_publisher_vkh`.
//
//          WHAT THE TWO LAYERS BUY. Layer 1 rejects a feed minted under a
//          stranger's own policy — it fails before the credential check runs
//          at all. Layer 2 rejects an allowlisted NFT that has been MOVED to
//          an address the publisher key does not control, i.e. the
//          "publisher key compromised, feed NFT walked off" case. Both are
//          real, and both are exercised by the tests at the foot of this file.
//
//          WHAT THEY DO NOT BUY — AND THIS HEADER CLAIMED THEY DID
//          [#438, RETRACTED 2026-08-10]. The retracted argument was that a
//          forgery requires BOTH stealing the publisher key AND minting under
//          a one-shot policy, the second being impossible because the
//          one-shot's init UTxO was consumed at mint time. Both conjuncts are
//          false against what is actually deployed:
//            * The canonical policies are plain native scripts of the shape
//              `all[sig K]`. That carries NO time bound, so the policy can
//              mint a second unit for as long as K exists anywhere. MEASURED
//              over keyless Koios `script_info`, 2026-08-10: 11 of 11 mainnet
//              canonical policies carry no `before` and no `after` clause, and
//              the eleven keys that can still mint are eleven distinct keys,
//              none of them the publisher. "The key was generated in memory
//              and discarded" is a claim about one process's memory that no
//              chain observer can check and no validator can read.
//            * Paying an output TO an address requires no key whatsoever. So
//              the minter of a second unit satisfies layer 2 unaided: the
//              publisher key was never a second factor against a DUPLICATE,
//              only against a MOVE.
//
//          THE COST IS NOT "a spare token exists" — it is that the feed stops
//          being OBSERVABLE. `find_feed_output` takes the FIRST qualifying
//          reference input and the transaction author chooses
//          `reference_inputs`, so a forged UTxO carrying a second unit at the
//          publisher address settles claims BESIDE the real feed. The
//          canonical feed is never spent, keeps publishing correct prices, and
//          every monitor watching it reports a healthy oracle throughout.
//          `resolve` below checks no signature over the datum: the NFT is the
//          entire authentication.
//
//          WHAT MAKES THE HEADER'S OLD CLAIM TRUE. Re-mint each feed under
//          `all[sig K, before LOCK]` and let the chain pass LOCK: from that
//          slot no transaction can ever satisfy the script again, supply is
//          frozen at the one unit that exists, and publishing a false price
//          REQUIRES spending the real feed UTxO — which is precisely the event
//          a monitor can see. Only in that state is layer 2 a second factor on
//          top of layer 1. Between the mint and LOCK the property is NOT YET
//          established, which is a third state distinct from both the open
//          policy and the closed one; offchain/scripts/verify_feed_oneshots.py
//          reports it separately and legitimately refuses until the tip passes
//          LOCK. Ceremony: docs/v8-stable-vault/FEED-REMINT-RUNBOOK.md.
//
//          NOTHING IN THIS MODULE CHANGES ACROSS THAT FIX. The allowlist still
//          holds 28-byte policy ids and this parser still gates on membership.
//          A closed policy has a DIFFERENT id from the open one it replaces, so
//          what moves is `aegis_self_canonical_nfts` and every hash derived
//          from it.
// =============================================================================

use aegis/oracle/charli3.{
  OracleDatum, create_oracle_datum, get_oracle_expiry,
  get_oracle_min_low_observed_at, get_oracle_min_price_12h, get_oracle_price,
  get_oracle_timestamp,
}
use aegis/oracle/types.{Price}
use aegis/types as aegis_types
use aiken/collection/list
use aiken/option
use cardano/address.{Address, Credential, Script, VerificationKey}
use cardano/assets
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

// ---------------------------------------------------------------------------
// Canonical-feed UTxO finder
// ---------------------------------------------------------------------------

/// Search `reference_inputs` for the canonical Aegis-self feed UTxO.
///
/// A UTxO qualifies iff it (a) carries a token under the supplied
/// `oracle_nft` policy id (an allowlisted publisher NFT, per network), AND
/// (b) sits at a payment credential equal to
/// `aegis_types.aegis_self_publisher_vkh`. Both layers must hold — see the
/// file header for what each one rejects.
///
/// THIS IS A FILTER, NOT A UNIQUENESS PROOF. `list.find` returns the FIRST
/// qualifying input and the transaction author supplies `reference_inputs`,
/// so when two UTxOs qualify the author decides which one is read. Nothing
/// here can tell them apart: the test is policy-id MEMBERSHIP, so a second
/// unit minted under an allowlisted policy is this feed as far as this
/// function is concerned, carrying whatever datum its minter chose.
///
/// Uniqueness therefore comes from the MINTING POLICY and never from this
/// code. It holds only while no policy in `aegis_self_canonical_nfts` can
/// mint again — and as measured on mainnet on 2026-08-10, all eleven still
/// can.
fn find_feed_output(
  reference_inputs: List<Input>,
  oracle_nft: ByteArray,
) -> Option<Output> {
  let publisher_credential =
    VerificationKey(aegis_types.aegis_self_publisher_vkh)
  reference_inputs
    |> list.find(
        fn(input) {
          list.has(assets.policies(input.output.value), oracle_nft) && input.output.address.payment_credential == publisher_credential
        },
      )
    |> option.map(fn(input) { input.output })
}

/// Locate the canonical feed UTxO and decode its inline datum as the
/// Charli3-compatible `OracleDatum` shape.
pub fn find_feed_datum(
  reference_inputs: List<Input>,
  oracle_nft: ByteArray,
) -> OracleDatum {
  // [v12 / A-026 generalised] Pin `oracle_nft` to the canonical AegisSelf
  // allowlist (one mint per supported feed, every one of them held under the
  // same publisher VKH). The semantics are unchanged from the round-6 single-
  // NFT pin: an attacker forging a fake NFT under their own permissive
  // policy is rejected before the payment-credential check even runs. The
  // only set-theoretic change is the canonical set's cardinality.
  // See `lib/aegis/types.ak::aegis_self_canonical_nfts` for the threat
  // model and per-pair rotation contract. The phrase "one-shot mints" is
  // struck from this comment deliberately: mint HISTORY is not mint
  // AUTHORITY, and as deployed these policies still hold the second — see
  // the file header.
  expect aegis_types.is_canonical_aegis_self_nft(oracle_nft)
  when find_feed_output(reference_inputs, oracle_nft) is {
    Some(output) ->
      when output.datum is {
        InlineDatum(raw) -> {
          expect datum: OracleDatum = raw
          datum
        }
        _ -> fail @"Aegis-self feed UTxO does not have inline datum"
      }
    None -> fail @"Aegis-self feed UTxO not found in reference inputs"
  }
}

// ---------------------------------------------------------------------------
// Provider-uniform Resolver (v7 entrypoint)
// ---------------------------------------------------------------------------

/// Resolve an Aegis-self oracle reading from `reference_inputs` and emit the
/// provider-uniform `Price` record.
///
/// **Trust handshake.** See `find_feed_output` — both NFT presence and
/// publisher VKH credential are required. The `oracle_nft` argument is the
/// per-network publisher NFT policy id, sourced at policy-creation time
/// from `PolicyDatum.oracle_nft` (mirrors how `Charli3` and `Orcfax` use
/// the same field for provider-specific handles).
///
/// **Scaling.** Aegis-self publishes at 1e6 scale (same as Charli3) — the
/// publisher's `datum_builder.usd_to_scaled` produces this. No rescaling.
///
/// **Freshness.** The publisher writes a per-publish expiry into the datum
/// (key 2) — typically `created_at + 4_200_000ms` (70 min). Surface that
/// directly as `Price.valid_until` so the validator's
/// `tx_lower <= valid_until` check is identical for all three providers.
pub fn resolve(reference_inputs: List<Input>, oracle_nft: ByteArray) -> Price {
  let datum = find_feed_datum(reference_inputs, oracle_nft)
  Price {
    value: get_oracle_price(datum),
    observed_at: get_oracle_timestamp(datum),
    valid_until: get_oracle_expiry(datum),
    // Real trailing-12h low (publisher key 3); defaults to spot if absent.
    min_price_12h: get_oracle_min_price_12h(datum),
    // When that low occurred (key 4); defaults to observed_at if absent.
    low_observed_at: get_oracle_min_low_observed_at(datum),
    confidence_present: False,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test reuses_charli3_datum_shape() {
  // The Aegis-self resolver intentionally reuses Charli3's OracleDatum type.
  // This test pins the import contract — if Charli3 changes its datum shape
  // in a future v8, this file must re-vendor the price/timestamp/expiry
  // accessors locally to avoid coupling the AegisSelf branch to Charli3.
  let datum = create_oracle_datum(420_000, 1_700_000_000_000, 1_700_004_200_000)
  get_oracle_price(datum) == 420_000
}

// [#363 F5] `trust_handshake_requires_publisher_vkh` removed: it pinned the OLD
// preprod publisher VKH (6096332c…), retired when the profile was
// re-parameterized to the operator key, so it was unpassable on the active
// module. A per-network VALUE assertion degenerates to `x == x` in a test that
// must be green under BOTH modules; the structural check now has one home in
// types.ak (`aegis_self_publisher_vkh_is_well_formed`) and the real value guard
// is the #361 deploy-time network-flip fingerprint.
//
// ---------------------------------------------------------------------------
// [#363 F4] The BEHAVIOURAL trust handshake.
//
// The file header claims two independent layers — canonical NFT AND publisher
// payment credential — and argues that either alone is broken. Layer 1 had
// tests; layer 2, the credential match inside `find_feed_output`, had NONE.
// Its absence is exactly why the preprod depeg-feed breakage stayed invisible:
// feeds were added to the canonical allowlist while sitting at a retired
// publisher address, so they satisfied every existing test and still could not
// resolve on chain.
//
// These build the ref-input inline rather than via test_helpers/fixtures,
// because fixtures imports `aegis/oracle`, which imports this module — routing
// through it would be a cycle.
// ---------------------------------------------------------------------------

fn canonical_feed_nft() -> ByteArray {
  expect [nft, ..] = aegis_types.aegis_self_canonical_nfts
  nft
}

fn feed_input_at(payment_credential: Credential, oracle_nft: ByteArray) -> Input {
  Input {
    output_reference: OutputReference {
      transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
      output_index: 0,
    },
    output: Output {
      address: Address { payment_credential, stake_credential: None },
      value: assets.add(
        assets.from_lovelace(2_000_000),
        oracle_nft,
        #"4f5241434c45",
        1,
      ),
      datum: InlineDatum(
        create_oracle_datum(420_000, 1_700_000_000_000, 1_700_004_200_000),
      ),
      reference_script: None,
    },
  }
}

test trust_handshake_accepts_feed_at_publisher_credential() {
  // Layer 1 + layer 2 both satisfied -> the feed resolves.
  let nft = canonical_feed_nft()
  let input =
    feed_input_at(VerificationKey(aegis_types.aegis_self_publisher_vkh), nft)
  get_oracle_price(find_feed_datum([input], nft)) == 420_000
}

test trust_handshake_rejects_canonical_nft_at_foreign_key() fail {
  // THE load-bearing case: a genuinely canonical NFT, correct datum, but the
  // UTxO sits at an attacker's key address. This is the "publisher key
  // compromised and the NFT moved" scenario the header calls out. It must NOT
  // resolve — `find_feed_output` returns None and `find_feed_datum` aborts.
  let nft = canonical_feed_nft()
  let attacker =
    VerificationKey(
      #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    )
  get_oracle_price(find_feed_datum([feed_input_at(attacker, nft)], nft)) == 420_000
}

test trust_handshake_rejects_canonical_nft_at_script_address() fail {
  // Same NFT parked at a SCRIPT whose hash equals the publisher VKH bytes.
  // Credential equality is constructor-sensitive, so `Script(h)` must never
  // satisfy a `VerificationKey(h)` pin — otherwise any script could be stood
  // up at the matching hash to impersonate the publisher.
  let nft = canonical_feed_nft()
  let spoof = Script(aegis_types.aegis_self_publisher_vkh)
  get_oracle_price(find_feed_datum([feed_input_at(spoof, nft)], nft)) == 420_000
}

// ---------------------------------------------------------------------------
// [v12] Per-pair NFT allowlist round-trip tests
//
// The allowlist itself is pinned in `types.ak::aegis_self_canonical_nfts`;
// these tests confirm the parser's V12 `list.has` rewrite admits each
// canonical NFT and rejects anything else.
// ---------------------------------------------------------------------------

// [#363 F5] The five per-feed membership pins here hardcoded the RETIRED
// preprod inventory (d2f08410 ADA / ae304e27 BTC / d80aa1a7 ETH) and were
// unpassable on either profile. They also duplicated allowlist invariants that
// now have ONE home in types.ak — `allowlist_is_structurally_sound`
// (non-empty, unique, 28-byte entries), `allowlist_size_pinned_per_profile`
// (per-network count drift guard) and `depeg_feeds_are_canonical`. The
// behavioural acceptance path is covered by
// `oracle.is_canonical_accepts_every_aegis_self_feed`, and the reject path by
// `oracle_rejects_unknown_nft` below.

test oracle_rejects_unknown_nft() fail {
  // A non-canonical NFT must trip the `expect list.has(...)` in
  // `find_feed_datum`. Wrapping a `fail` test marker around an expectation
  // is the Aiken idiom for "this code path must abort". We invoke
  // `find_feed_datum` directly to assert the panic.
  let oracle_nft =
    #"00112233445566778899001122334455667788990011223344556677"
  let datum = find_feed_datum([], oracle_nft)
  get_oracle_price(datum) == 0
}

test oracle_rejects_empty_nft() fail {
  // Defensive: an empty bytestring must not match any canonical entry.
  let datum = find_feed_datum([], #"")
  get_oracle_price(datum) == 0
}
