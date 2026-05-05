// =============================================================================
// Aegis Insurance Protocol - Aegis-self Oracle Parser (v7 third provider)
// Location: contracts/lib/aegis/oracle/aegis_self.ak
// Summary: Aegis-self resolver. Reads a UTxO at the publisher wallet address
//          carrying the AEGIS_PRICE_FEED_V1 NFT and parses its inline datum
//          using the Charli3 GenericData CBOR shape (we publish in that format
//          deliberately so the parser is shared).
//
//          Trust handshake (two layers):
//            1. UTxO must carry a token under the supplied `oracle_nft` policy
//               id (= our one-shot-minted publisher NFT, network-specific).
//            2. UTxO's payment credential must equal the compile-time pinned
//               `aegis_self_publisher_vkh`.
//
//          Why both layers: (1) alone is broken if the publisher key is
//          compromised and the NFT is moved to an attacker UTxO. (2) alone
//          is broken if anyone can mint a token at the publisher's address.
//          Together they require the attacker to BOTH steal the publisher
//          key AND mint under our parameterized one-shot policy (impossible
//          since the one-shot init UTxO was already consumed at mint time).
// =============================================================================

use aegis/oracle/charli3.{
  OracleDatum, create_oracle_datum, get_oracle_expiry, get_oracle_price,
  get_oracle_timestamp,
}
use aegis/oracle/types.{Price}
use aegis/types as aegis_types
use aiken/collection/list
use cardano/address.{VerificationKey}
use cardano/assets
use cardano/transaction.{InlineDatum, Input, Output}

// ---------------------------------------------------------------------------
// Canonical-feed UTxO finder
// ---------------------------------------------------------------------------

/// Search `reference_inputs` for the canonical Aegis-self feed UTxO.
///
/// A UTxO qualifies iff it (a) carries a token under the supplied
/// `oracle_nft` policy id (our publisher NFT, parameterized one-shot
/// per network), AND (b) sits at a payment credential equal to
/// `aegis_types.aegis_self_publisher_vkh`. Both layers must hold —
/// see file-header comment for the "why both" argument.
fn find_feed_output(
  reference_inputs: List<Input>,
  oracle_nft: ByteArray,
) -> Option<Output> {
  when reference_inputs is {
    [] -> None
    [input, ..rest] -> {
      let has_publisher_nft =
        assets.policies(input.output.value)
          |> list.has(oracle_nft)
      let at_publisher_credential =
        when input.output.address.payment_credential is {
          VerificationKey(vkh) -> vkh == aegis_types.aegis_self_publisher_vkh
          _ -> False
        }
      if has_publisher_nft && at_publisher_credential {
        Some(input.output)
      } else {
        find_feed_output(rest, oracle_nft)
      }
    }
  }
}

/// Locate the canonical feed UTxO and decode its inline datum as the
/// Charli3-compatible `OracleDatum` shape.
pub fn find_feed_datum(
  reference_inputs: List<Input>,
  oracle_nft: ByteArray,
) -> OracleDatum {
  // [v6.0.2 / A-026 fix] Pin `oracle_nft` to the canonical AegisSelf
  // publisher NFT. The pre-fix file-header comment claimed the trust
  // handshake "requires the attacker to BOTH steal the publisher key AND
  // mint under our parameterized one-shot policy" — that argument was
  // wrong because `oracle_nft` was caller-controlled per policy. With
  // this pin in place, an attacker forging a fake NFT under their own
  // permissive policy is rejected before the payment-credential check
  // even runs.
  expect oracle_nft == aegis_types.aegis_self_nft_policy
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
pub fn resolve(
  reference_inputs: List<Input>,
  oracle_nft: ByteArray,
) -> Price {
  let datum = find_feed_datum(reference_inputs, oracle_nft)
  Price {
    value: get_oracle_price(datum),
    observed_at: get_oracle_timestamp(datum),
    valid_until: get_oracle_expiry(datum),
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

test trust_handshake_requires_publisher_vkh() {
  // The publisher VKH must equal the constant; if the constant ever rotates
  // (e.g., separate mainnet mnemonic in v7+) the trust binding is the place
  // to update it.
  aegis_types.aegis_self_publisher_vkh ==
    #"6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152"
}
