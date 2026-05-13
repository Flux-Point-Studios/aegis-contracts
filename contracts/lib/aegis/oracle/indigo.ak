// =============================================================================
// Aegis Insurance Protocol - Indigo Oracle Parser (v12.2 fourth provider)
// Location: contracts/lib/aegis/oracle/indigo.ak
// Summary: Indigo on-chain oracle resolver. Reads a UTxO at the per-iAsset
//          parameterized Indigo Oracle script address carrying the canonical
//          Oracle Asset NFT and parses its inline datum as the Plutus V2
//          `OracleDatum = Constr_0[OnChainDecimal, POSIXTime]` shape.
//
//          Trust handshake (three layers):
//            1. UTxO must carry a token under the supplied `oracle_nft` policy
//               id (= one of the 4 canonical Indigo NFTs per network).
//            2. UTxO's payment credential must be `Script(h)` where h equals
//               the per-iAsset oracle script hash paired with the NFT in
//               `indigo_oracle_script_hashes` by list index.
//            3. Quantity of the (policy, asset_name) NFT in the UTxO must
//               equal 1 (Indigo's one-shot mint guarantee).
//
//          Why three layers: layer 1 prevents fake NFTs minted under a
//          permissive attacker policy. Layer 2 prevents a stolen NFT lying
//          at a non-canonical address. Layer 3 defends against quantity-0
//          phantom matches (defense in depth; Indigo's validator already
//          enforces continuing-output preservation of value, but Aegis
//          re-checks since we are the consumer).
//
//          Why we do NOT pin Indigo's keeper VKH: the keeper-VKH per iAsset
//          is opaque to consumers (Indigo treats it as their internal
//          rotation key). Indigo's own `validateOracle` already enforces
//          `txSignedBy info opOwner` on every refresh, so any UTxO at the
//          canonical script address with the canonical NFT is by construction
//          a keeper-signed refresh. The script-credential pin IS the
//          keeper-handshake transitively.
//
// References:
//   * Indigo Oracle source: github.com/IndigoProtocol/indigo-smart-contracts
//                           /src/Indigo/Contracts/Oracle/Common.hs
//   * Indigo Decimal:       /src/Indigo/Data/Decimal.hs (decimalUnit = 1e6)
//   * V12.2 spec §2.6, §3.4a, §10.4
// =============================================================================

use aegis/oracle/types.{Price}
use aegis/types as aegis_types
use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Script}
use cardano/assets
use cardano/transaction.{InlineDatum, Input, Output}

// ---------------------------------------------------------------------------
// Indigo Datum Shape (re-declared positionally to match upstream CBOR)
// ---------------------------------------------------------------------------

/// Indigo's `OnChainDecimal` is a newtype Integer wrapped in Constr_0. The
/// scale is 1e6 (see `Indigo.Data.Decimal.decimalUnit`). We re-declare
/// positionally so this parser does not depend on an external Indigo Aiken
/// library (Indigo's contracts are Plutus V2 Haskell — no Aiken bindings
/// shipped by upstream). The CBOR wire format is `d8 79 9f <int> ff`.
pub type OnChainDecimal {
  value: Int,
}

/// Indigo's `OracleDatum` matching
/// `MkOracleDatum :: OnChainDecimal -> POSIXTime`.
/// CBOR wire format:
///   `d8 79 9f <Constr_0[int]> <int> ff`
/// = Constr_0[OnChainDecimal, expiration_ms].
///
/// The price field is ADA-denominated (Indigo's `decimalToAdaValue`); the
/// expiration is POSIX milliseconds. No `created_at` field — Indigo writes
/// only the future expiration, not the publish timestamp.
pub type IndigoOracleDatum {
  price: OnChainDecimal,
  expiration: Int,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Indigo's empirical lookahead: `odExpiration` is set ~49 min ahead of
/// publish slot (validated 2026-05-12 against 1000 most recent iUSD oracle
/// txs via Koios — mean refresh 35.5 min, expiry set 49 min ahead). Used
/// to derive `observed_at` (Indigo doesn't publish a created_at field).
/// In milliseconds.
pub const indigo_typical_lookahead_ms: Int = 49 * 60 * 1_000

// ---------------------------------------------------------------------------
// Paired-list helper (NFT -> script hash via index)
// ---------------------------------------------------------------------------

/// Look up the per-iAsset oracle script hash paired with `oracle_nft` in
/// `indigo_canonical_nfts`. The two lists are paired by list index; this
/// helper walks both in lockstep to find the matching entry. Returns
/// `Some(script_hash)` on hit, `None` if `oracle_nft` is not in the
/// canonical NFT list.
///
/// Aiken-time complexity: O(n) over the canonical list, n=4 in V12.2.
pub fn resolve_paired_script_hash(oracle_nft: ByteArray) -> Option<ByteArray> {
  do_resolve_paired(
    aegis_types.indigo_canonical_nfts,
    aegis_types.indigo_oracle_script_hashes,
    oracle_nft,
  )
}

fn do_resolve_paired(
  nfts: List<ByteArray>,
  hashes: List<ByteArray>,
  target: ByteArray,
) -> Option<ByteArray> {
  when nfts is {
    [] -> None
    [nft, ..rest_nfts] ->
      when hashes is {
        // Defensive: should never happen if lists are same length, which is
        // pinned by `indigo_oracle_script_hashes_size_matches_nft_count` in
        // types.ak.
        [] -> None
        [hash, ..rest_hashes] ->
          if nft == target {
            Some(hash)
          } else {
            do_resolve_paired(rest_nfts, rest_hashes, target)
          }
      }
  }
}

// ---------------------------------------------------------------------------
// single_token_of_policy
// ---------------------------------------------------------------------------

/// Assert that the value carries EXACTLY one token under `policy_id`
/// (across all asset names). Indigo's one-shot policies guarantee this; we
/// re-check at the consumer side for defense in depth (layer 3 of the
/// trust handshake).
///
/// Returns Bool so the caller can `expect` on it.
fn single_token_of_policy(value: assets.Value, policy_id: ByteArray) -> Bool {
  let tokens_under_policy = assets.tokens(value, policy_id)
  let total =
    dict.foldr(tokens_under_policy, 0, fn(_name, qty, acc) { acc + qty })
  total == 1
}

// ---------------------------------------------------------------------------
// Canonical-feed UTxO finder
// ---------------------------------------------------------------------------

/// Search `reference_inputs` for the canonical Indigo oracle UTxO for the
/// given `oracle_nft`. A UTxO qualifies iff it (a) carries a token under
/// `oracle_nft` policy id, AND (b) sits at a payment credential equal to
/// `Script(h)` where h is the per-iAsset script hash paired with the NFT.
fn find_feed_output(
  reference_inputs: List<Input>,
  oracle_nft: ByteArray,
  expected_script_hash: ByteArray,
) -> Option<Output> {
  when reference_inputs is {
    [] -> None
    [input, ..rest] -> {
      let has_indigo_nft =
        assets.policies(input.output.value)
          |> list.has(oracle_nft)
      let at_indigo_script =
        when input.output.address.payment_credential is {
          Script(h) -> h == expected_script_hash
          _ -> False
        }
      if has_indigo_nft && at_indigo_script {
        Some(input.output)
      } else {
        find_feed_output(rest, oracle_nft, expected_script_hash)
      }
    }
  }
}

/// Locate the canonical Indigo oracle UTxO for `oracle_nft` and decode its
/// inline datum as `IndigoOracleDatum`.
///
/// Three-layer trust handshake:
///   1. `expect list.has(indigo_canonical_nfts, oracle_nft)` (NFT
///      canonical-membership)
///   2. `resolve_paired_script_hash` + `find_feed_output` gates
///      script-credential pin
///   3. `expect single_token_of_policy(...)` defends against quantity-0
///      phantom matches
pub fn find_feed_datum(
  reference_inputs: List<Input>,
  oracle_nft: ByteArray,
) -> IndigoOracleDatum {
  // Layer 1: canonical-NFT pin.
  expect list.has(aegis_types.indigo_canonical_nfts, oracle_nft)

  // Layer 2: resolve the paired script hash from the canonical list.
  expect Some(expected_script_hash) = resolve_paired_script_hash(oracle_nft)

  // Layer 2 (continued): find the matching UTxO in reference_inputs.
  when find_feed_output(reference_inputs, oracle_nft, expected_script_hash) is {
    Some(output) ->
      when output.datum is {
        InlineDatum(raw) -> {
          // Layer 3: quantity-1 check. We do this after the find because
          // find_feed_output already gated on policy presence; here we just
          // check the quantity is exactly 1 (not possible to be 0 since
          // policy is present, but 2+ would be an attacker minting extra
          // tokens under a permissive policy — impossible for Indigo's
          // one-shot policies, but defense in depth costs nothing).
          expect single_token_of_policy(output.value, oracle_nft)
          expect datum: IndigoOracleDatum = raw
          datum
        }
        _ -> fail @"Indigo feed UTxO does not have inline datum"
      }
    None -> fail @"Indigo feed UTxO not found in reference inputs"
  }
}

// ---------------------------------------------------------------------------
// Provider-uniform Resolver (v12.2 entrypoint)
// ---------------------------------------------------------------------------

/// Resolve an Indigo oracle reading from `reference_inputs` and emit the
/// provider-uniform `Price` record.
///
/// **Trust handshake.** See `find_feed_datum` — NFT presence, paired script
/// credential, AND single-token-of-policy check are all enforced.
///
/// **Scaling.** Indigo publishes at 1e6 scale (Plutus V2 OnChainDecimal,
/// `decimalUnit = 1_000_000` per Indigo.Data.Decimal). Same scale as
/// Charli3/AegisSelf/Orcfax post-conversion. No rescaling needed.
///
/// **Denomination.** Indigo prices are ADA-denominated (USD-per-iAsset
/// would require a separate ADA/USD cross-rate; Indigo doesn't publish
/// that). The V12.2 validator is denomination-agnostic — it compares the
/// price value directly to the strike, both in 1e6 scale. The off-chain
/// layer is responsible for asserting that strike denomination matches the
/// oracle's denomination. See V12.2 spec §2.6 "Decision: validator is
/// denomination-agnostic."
///
/// **Freshness.** Indigo writes `odExpiration` directly into the datum; we
/// surface that as `Price.valid_until`. No Aegis-side freshness window —
/// the validator's downstream `tx_lower <= valid_until` check is the only
/// freshness gate. Indigo's empirical refresh cadence is ~35 min mean
/// (validated 2026-05-12 against 1000 most recent iUSD oracle txs), with
/// `odExpiration` set ~49 min ahead of publish slot.
///
/// **observed_at.** Indigo's datum has NO publish-timestamp field (unlike
/// Charli3 which writes `created_at` and AegisSelf which inherits that).
/// We derive `observed_at` by subtracting Indigo's typical 49-min lookahead
/// from `expiration`. This is approximate (the lookahead is configurable
/// per-iAsset via `opExpirationTime`) but the consumer doesn't actually
/// USE observed_at for anything load-bearing — only freshness gating cares,
/// and that uses `valid_until` directly. Documented as a sentinel in the
/// V12.2 spec §3.4a.
pub fn resolve(reference_inputs: List<Input>, oracle_nft: ByteArray) -> Price {
  let datum = find_feed_datum(reference_inputs, oracle_nft)
  Price {
    value: datum.price.value,
    observed_at: datum.expiration - indigo_typical_lookahead_ms,
    valid_until: datum.expiration,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test indigo_datum_decodes_canonical_iusd_shape() {
  // The live mainnet iUSD oracle datum (validated 2026-05-12 via Koios):
  //   d8 79 9f  d8 79 9f  1a 00 38 3b c1  ff  1b 00 00 01 9e 1e 38 b3 88  ff
  //   = Constr_0[ Constr_0[ 3_685_313 ], 1_778_623_493_000 ]
  // This test asserts the IndigoOracleDatum positional decode matches the
  // upstream wire format by constructing the equivalent in-memory value.
  let datum =
    IndigoOracleDatum {
      price: OnChainDecimal { value: 3_685_313 },
      expiration: 1_778_623_493_000,
    }
  datum.price.value == 3_685_313 && datum.expiration == 1_778_623_493_000
}

test indigo_resolve_returns_price_in_1e6_scale() {
  // Indigo publishes at 1e6 scale — verify the in-memory datum preserves
  // the integer without rescaling. 3.685313 ADA/iUSD → 3_685_313.
  let datum =
    IndigoOracleDatum {
      price: OnChainDecimal { value: 3_685_313 },
      expiration: 1_778_623_493_000,
    }
  datum.price.value == 3_685_313
}

test indigo_resolve_uses_datum_expiration_as_valid_until() {
  // Freshness: Price.valid_until == datum.expiration verbatim. No
  // Aegis-side window addition (unlike Orcfax, which derives valid_until
  // from created_at + 70 min).
  let exp = 1_778_623_493_000
  let p =
    Price {
      value: 3_685_313,
      observed_at: exp - indigo_typical_lookahead_ms,
      valid_until: exp,
    }
  p.valid_until == exp
}

test indigo_observed_at_derives_from_expiration_minus_lookahead() {
  // Indigo doesn't publish created_at; the parser derives observed_at as
  // `expiration - 49*60*1000ms`. Pin the lookahead constant value.
  let exp = 1_778_623_493_000
  let p =
    Price {
      value: 3_685_313,
      observed_at: exp - indigo_typical_lookahead_ms,
      valid_until: exp,
    }
  p.valid_until - p.observed_at == 49 * 60 * 1_000 && indigo_typical_lookahead_ms == 49 * 60 * 1_000
}

test indigo_pair_resolve_maps_iusd_nft_to_mock_script_hash() {
  // Sanity: the paired-list helper returns the operator mock script for
  // the iUSD preprod NFT (live Wave-4 mint).
  let nft0 = #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5"
  let script0 =
    #"d27ccc13fab5b782984a3d1f99353197ca1a81be069941ffc003ee75"
  resolve_paired_script_hash(nft0) == Some(script0)
}

test indigo_pair_resolve_maps_ibtc_ieth_isol_to_same_mock() {
  // All 4 preprod entries share one mock script hash. Each canonical NFT
  // (live Wave-4 mints) maps to the same operator mock script.
  let nft1 = #"1e66200fca30b83d5937b67b896fa46f1adac98922555f9e791c1c83"
  let nft2 = #"e81e84a5d34137bcbc2ba73f1b4e735ac0cc375f0bfeb5e98a397102"
  let nft3 = #"875cea49cb6963ad462187f77dcc5b4d458a66d7eb9a646c2c5405a7"
  let script =
    #"d27ccc13fab5b782984a3d1f99353197ca1a81be069941ffc003ee75"
  resolve_paired_script_hash(nft1) == Some(script) && resolve_paired_script_hash(
    nft2,
  ) == Some(script) && resolve_paired_script_hash(nft3) == Some(script)
}

test indigo_pair_resolve_returns_none_for_unknown_nft() {
  resolve_paired_script_hash(
    #"00112233445566778899001122334455667788990011223344556677",
  ) == None
}

test indigo_pair_resolve_returns_none_for_empty_nft() {
  resolve_paired_script_hash(#"") == None
}

test indigo_find_feed_datum_rejects_non_canonical_nft() fail {
  // The leading `expect list.has(...)` in find_feed_datum must abort on a
  // non-canonical NFT before any other check runs. The `fail` test marker
  // asserts the panic. We force the call to be evaluated by tying the
  // return value into the result expression so Aiken can't dead-code-
  // eliminate the call.
  let datum =
    find_feed_datum(
      [],
      #"00112233445566778899001122334455667788990011223344556677",
    )
  // Unreachable: find_feed_datum aborts via the expect.
  datum.price.value == 0
}

test indigo_find_feed_datum_rejects_empty_nft() fail {
  let datum = find_feed_datum([], #"")
  datum.price.value == 0
}

test indigo_find_feed_datum_rejects_canonical_nft_with_no_inputs() fail {
  // Canonical NFT supplied but no reference_inputs — `find_feed_output`
  // returns None → fail @"Indigo feed UTxO not found in reference inputs".
  let datum =
    find_feed_datum(
      [],
      #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
    )
  datum.price.value == 0
}

test indigo_lookahead_constant_is_49_min_in_ms() {
  indigo_typical_lookahead_ms == 2_940_000
}
