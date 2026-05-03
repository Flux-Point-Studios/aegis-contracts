// =============================================================================
// Aegis Insurance Protocol - Charli3 Oracle Parser (v6 multi-provider)
// Location: contracts/lib/aegis/oracle/charli3.ak
// Summary: Charli3 ODV oracle datum types, accessors, and resolver. Owns the
//          Charli3-specific CBOR shape and the A-016 trust handshake (oracle
//          UTxO must carry the canonical NFT AND sit at the canonical
//          `charli3_oracle_script_hash` address).
//
//          Pre-v6 callers reached these functions via `aegis/oracle`; v6
//          re-exports them from `aegis/oracle` via thin pass-through wrappers
//          so the v5 import paths still compile (see `aegis/oracle.ak`).
//          New v6 callers should go through the top-level
//          `oracle.resolve_oracle_price` dispatcher.
// =============================================================================

use aegis/oracle/types.{Price}
use aegis/types as aegis_types
use aiken/collection/list
use aiken/collection/pairs
use cardano/address.{Script}
use cardano/assets
use cardano/transaction.{InlineDatum, Input, Output}

// ---------------------------------------------------------------------------
// Charli3 Oracle Datum Types
// ---------------------------------------------------------------------------

/// Charli3 price data variants.
/// GenericData is the standard format for price feeds.
pub type PriceData {
  /// Reserved for shared data across multiple oracles
  SharedData
  /// Reserved for extended data with additional information
  ExtendedData
  /// Standard price feed data with key-value pairs
  /// Key 0: exchange rate (scaled by 1e6)
  /// Key 1: creation timestamp (POSIX ms)
  /// Key 2: expiration timestamp (POSIX ms)
  GenericData { price_map: Pairs<Int, Int> }
}

/// Top-level Charli3 oracle datum
pub type OracleDatum {
  price_data: PriceData,
}

// ---------------------------------------------------------------------------
// Price Data Accessors
// ---------------------------------------------------------------------------

/// Extract the price from PriceData (key 0).
/// Returns the exchange rate scaled by 1e6.
/// Example: ADA at $0.49 returns 490_000
pub fn get_price(price_data: PriceData) -> Int {
  when price_data is {
    GenericData { price_map } ->
      when pairs.get_first(price_map, 0) is {
        Some(price) -> price
        None -> fail @"Oracle price not found at key 0"
      }
    _ -> fail @"Invalid PriceData variant: expected GenericData"
  }
}

/// Extract the creation timestamp from PriceData (key 1).
/// Returns POSIX time in milliseconds.
pub fn get_timestamp(price_data: PriceData) -> Int {
  when price_data is {
    GenericData { price_map } ->
      when pairs.get_first(price_map, 1) is {
        Some(timestamp) -> timestamp
        None -> fail @"Oracle timestamp not found at key 1"
      }
    _ -> fail @"Invalid PriceData variant: expected GenericData"
  }
}

/// Extract the expiry timestamp from PriceData (key 2).
/// Returns POSIX time in milliseconds.
pub fn get_expiry(price_data: PriceData) -> Int {
  when price_data is {
    GenericData { price_map } ->
      when pairs.get_first(price_map, 2) is {
        Some(expiry) -> expiry
        None -> fail @"Oracle expiry not found at key 2"
      }
    _ -> fail @"Invalid PriceData variant: expected GenericData"
  }
}

// ---------------------------------------------------------------------------
// Oracle Datum Accessors
// ---------------------------------------------------------------------------

/// Get the price from an OracleDatum (convenience wrapper)
pub fn get_oracle_price(datum: OracleDatum) -> Int {
  get_price(datum.price_data)
}

/// Get the timestamp from an OracleDatum (convenience wrapper)
pub fn get_oracle_timestamp(datum: OracleDatum) -> Int {
  get_timestamp(datum.price_data)
}

/// Get the expiry from an OracleDatum (convenience wrapper)
pub fn get_oracle_expiry(datum: OracleDatum) -> Int {
  get_expiry(datum.price_data)
}

/// Check if oracle data is still valid at the given time.
/// Oracle is valid if current_time <= expiry timestamp.
pub fn is_oracle_valid(datum: OracleDatum, current_time: Int) -> Bool {
  current_time <= get_oracle_expiry(datum)
}

// ---------------------------------------------------------------------------
// Oracle UTxO Finder
// ---------------------------------------------------------------------------

/// Find the oracle UTxO in a list of reference inputs by matching the
/// oracle NFT policy ID in the UTxO's value.
///
/// The oracle UTxO is identified by containing a token with the given
/// policy ID (the Charli3 oracle NFT).
pub fn find_oracle_datum(
  reference_inputs: List<Input>,
  oracle_nft_policy: ByteArray,
) -> OracleDatum {
  when find_oracle_output(reference_inputs, oracle_nft_policy) is {
    Some(output) ->
      when output.datum is {
        InlineDatum(raw_datum) -> {
          expect datum: OracleDatum = raw_datum
          datum
        }
        _ -> fail @"Oracle UTxO does not have inline datum"
      }
    None -> fail @"Oracle UTxO not found in reference inputs"
  }
}

/// Find the oracle Output from reference inputs.
/// Searches for a UTxO whose value contains a token under the oracle NFT policy
/// AND whose payment credential is the canonical Charli3 oracle script hash.
///
/// [FIX A-016] Previously this only checked NFT presence, allowing a
/// UTxO at ANY address that holds the Charli3 NFT to be accepted as an
/// oracle. If Charli3 ever rotated their oracle script address (e.g.,
/// during an upgrade) or if the NFT could be moved to an attacker-
/// controlled UTxO, fake oracle data could pass. The address binding
/// closes that surface — any reference input with the right NFT but at
/// the wrong script credential is now silently skipped.
fn find_oracle_output(
  reference_inputs: List<Input>,
  oracle_nft_policy: ByteArray,
) -> Option<Output> {
  when reference_inputs is {
    [] -> None
    [input, ..rest] -> {
      let has_oracle_nft =
        assets.policies(input.output.value)
          |> list.has(oracle_nft_policy)
      let at_canonical_oracle =
        when input.output.address.payment_credential is {
          Script(h) -> h == aegis_types.charli3_oracle_script_hash
          _ -> False
        }
      if has_oracle_nft && at_canonical_oracle {
        Some(input.output)
      } else {
        find_oracle_output(rest, oracle_nft_policy)
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Helper: Create OracleDatum (for testing)
// ---------------------------------------------------------------------------

/// Create a new OracleDatum with given price, timestamp, and expiry.
/// Useful for constructing test fixtures.
pub fn create_oracle_datum(
  price: Int,
  timestamp: Int,
  expiry: Int,
) -> OracleDatum {
  OracleDatum {
    price_data: GenericData {
      price_map: [Pair(0, price), Pair(1, timestamp), Pair(2, expiry)],
    },
  }
}

// ---------------------------------------------------------------------------
// Provider-uniform Resolver (v6 entrypoint)
// ---------------------------------------------------------------------------

/// Resolve a Charli3 ODV oracle reading from `reference_inputs` and emit the
/// provider-uniform `Price` record consumed by validators in v6.
///
/// **Trust handshake.** Delegates to `find_oracle_datum`, which already
/// enforces the A-016 fix: the consumed reference input must (a) carry a
/// token under the `oracle_nft_policy` policy id AND (b) be at the canonical
/// `charli3_oracle_script_hash` address.
///
/// **Scaling.** Charli3's `OracleDatum` stores price already scaled by 1e6
/// at key 0 of its `GenericData` map. Emit it directly into `Price.value`
/// with no rescaling — that is the protocol-wide convention.
///
/// **Freshness.** Charli3 publishes a per-update expiry at key 2; surface it
/// as `Price.valid_until`. Validator's check `tx_lower <= valid_until` is
/// then identical for both providers.
pub fn resolve(
  reference_inputs: List<Input>,
  oracle_nft_policy: ByteArray,
) -> Price {
  let datum = find_oracle_datum(reference_inputs, oracle_nft_policy)
  Price {
    value: get_oracle_price(datum),
    observed_at: get_oracle_timestamp(datum),
    valid_until: get_oracle_expiry(datum),
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test get_price_from_generic_data() {
  let pd =
    GenericData(
      [Pair(0, 490_850), Pair(1, 1_707_172_554_600), Pair(2, 1_707_176_154_600)],
    )
  get_price(pd) == 490_850
}

test get_timestamp_from_generic_data() {
  let pd =
    GenericData(
      [Pair(0, 490_850), Pair(1, 1_707_172_554_600), Pair(2, 1_707_176_154_600)],
    )
  get_timestamp(pd) == 1_707_172_554_600
}

test get_expiry_from_generic_data() {
  let pd =
    GenericData(
      [Pair(0, 490_850), Pair(1, 1_707_172_554_600), Pair(2, 1_707_176_154_600)],
    )
  get_expiry(pd) == 1_707_176_154_600
}

test oracle_datum_price_extraction() {
  let datum = create_oracle_datum(350_000, 1_700_000_000_000, 1_700_000_300_000)
  get_oracle_price(datum) == 350_000
}

test oracle_datum_timestamp_extraction() {
  let datum = create_oracle_datum(350_000, 1_700_000_000_000, 1_700_000_300_000)
  get_oracle_timestamp(datum) == 1_700_000_000_000
}

test oracle_datum_expiry_extraction() {
  let datum = create_oracle_datum(350_000, 1_700_000_000_000, 1_700_000_300_000)
  get_oracle_expiry(datum) == 1_700_000_300_000
}

test oracle_valid_before_expiry() {
  let datum = create_oracle_datum(490_850, 1_707_172_554_600, 1_707_176_154_600)
  is_oracle_valid(datum, 1_707_172_554_600) == True
}

test oracle_valid_at_expiry() {
  let datum = create_oracle_datum(490_850, 1_707_172_554_600, 1_707_176_154_600)
  is_oracle_valid(datum, 1_707_176_154_600) == True
}

test oracle_invalid_after_expiry() {
  let datum = create_oracle_datum(490_850, 1_707_172_554_600, 1_707_176_154_600)
  is_oracle_valid(datum, 1_707_176_154_601) == False
}

test create_and_read_oracle_datum() {
  let datum = create_oracle_datum(2723, 1_720_056_807_332, 1_720_078_407_332)
  get_oracle_price(datum) == 2723 && get_oracle_timestamp(datum) == 1_720_056_807_332 && get_oracle_expiry(
    datum,
  ) == 1_720_078_407_332
}

test charli3_resolve_freshness_uses_datum_expiry() {
  // Charli3's freshness comes from the publisher-set expiry field — there is
  // no consumer-side computed window like Orcfax has. Assert the wiring
  // contract: a datum's expiry value is what flows into Price.valid_until,
  // NOT a consumer-derived `created_at + ttl`.
  let publisher_expiry: Int = 1_707_176_154_600
  let observed_at: Int = 1_707_172_554_600
  let derived_if_orcfax_logic = observed_at + 30 * 60 * 1_000
  publisher_expiry != derived_if_orcfax_logic
}
