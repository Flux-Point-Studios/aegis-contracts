# N1 — EVENT_SLOT settles through the existing Barrier path (no new on-chain RiskClass)

> Decision record for [aegis-parametric-insurance#66] / [aegis-contracts#5].
> Status: **decided — reuse existing rail, no version bump.**

## Question

A Materios-fed **EVENT_SLOT** feed represents a binary parametric event
("did X happen?") rather than a continuous price. Does settling such a feed
on-chain require a new on-chain `RiskClass::Event` (or a new `OracleProvider`
variant, datum field, or validator version bump), or does it settle through
the **existing Barrier path** unchanged?

## Finding: it settles through the existing Barrier path. No on-chain change.

Two facts, verified against the code on `main`, make this conclusive.

### 1. There is no on-chain `RiskClass` to extend in the first place.

`contracts/lib/aegis/types.ak` defines `OracleProvider`, `PolicyDatum`,
`PolicyRedeemer`, `PoolRedeemer`, etc. — there is **no `RiskClass` type
anywhere in the validators**. `RiskClass` (`'Barrier'`, `'Event'`, …) is an
**SDK / off-chain** concept that selects *which feed* a policy binds to and how
the off-chain layer encodes the reading. On-chain, a policy carries a
`strike_price` and an `oracle_provider`/`oracle_nft` handle, and the Claim
branch compares a resolved oracle `value` against the strike. "Barrier" vs
"Event" is therefore not a distinction the chain can observe and does not need
to.

### 2. The Claim check is generic over the resolved oracle value.

`contracts/validators/policy.ak`, Claim branch:

```aiken
// Resolve the oracle price via the provider-uniform dispatcher.
let price =
  resolve_oracle_price(
    reference_inputs,
    datum.oracle_provider,
    datum.oracle_nft,
  )

// Crash detected: oracle price at or below the strike.
let price_below_strike = price.value <= datum.strike_price
```

`price.value <= datum.strike_price` is the **Barrier predicate**. It does not
care whether `price.value` came from a continuous ADA/USD price or from a
binary EVENT_SLOT encoding. A Materios EVENT_SLOT that has **fired** publishes
a `value <= strike`; one that has **not fired** publishes a `value > strike`.
Binary semantics map cleanly onto the existing `<=` comparison — there is no
expressiveness gap that would require an `Event` variant.

### 3. The EVENT_SLOT feed reuses the AegisSelf rail and datum byte-for-byte.

The pinned seam (aligned with N0/N2) is the existing **AegisSelf** trust model:

- **Datum shape** (`contracts/lib/aegis/oracle/charli3.ak`, reused by
  `aegis_self.ak`): the Charli3-compatible `GenericData` map
  `{0: value, 1: created_ms, 2: expiry_ms}`, CBOR-encoded as
  `Tag 121([ Tag 123([ {0,1,2} ]) ])` — i.e.
  `OracleDatum { price_data: GenericData { price_map: [Pair(0,_), Pair(1,_), Pair(2,_)] } }`.
- **Trust handshake** (`contracts/lib/aegis/oracle/aegis_self.ak::find_feed_output`):
  the feed UTxO must (a) carry a token under a **canonical AegisSelf NFT**
  (`aegis_self_canonical_nfts`) AND (b) sit at the compile-time pinned
  `aegis_self_publisher_vkh`. Trusted-publisher model — **no on-chain root
  check** (same as AegisSelf today; the publisher is the trust anchor).
- **Freshness** flows from the datum's key-2 expiry into `Price.valid_until`,
  and the validator's existing `tx_lower/tx_upper <= valid_until` check applies
  unchanged.

Because Materios publishes EVENT_SLOT readings into this **same datum, same
publisher VKH, same canonical-NFT gate**, the resolver, the freshness check,
and the Barrier comparison are all reused verbatim.

## Consequence

A Materios-fed EVENT_SLOT policy is just an `oracle_provider: AegisSelf` policy
whose strike encodes the binary trigger threshold. The full claim lifecycle —
single-policy-input guard, oracle resolution, `value <= strike`, freshness,
policy-period bounds, payout-to-insured, canonical-pool-present, marker burn
(`BurnForClaim`) — runs unchanged.

- **No new `RiskClass`** on-chain (none exists; the distinction is SDK-side).
- **No new `OracleProvider`** variant (reuses `AegisSelf`).
- **No `PolicyDatum` field** added.
- **No validator version bump** and **no validator-hash rotation.**

## When we *would* introduce `RiskClass::Event`

For traceability, an on-chain `Event` distinction would only be justified by a
concrete gap, e.g.:

- a binary semantic the `<=`-against-strike Barrier predicate genuinely cannot
  express (e.g. an equality / set-membership / multi-outcome payout that is not
  monotone in a single scalar), or
- an **on-chain provenance** requirement (e.g. a feed-root / attestation that
  must be checked in the validator rather than trusted via the publisher VKH).

Neither holds for the Materios EVENT_SLOT seam as specified, so no new variant
is introduced.

## Tests

End-to-end tests drive the real `policy_validator.spend` over a full Materios
EVENT_SLOT claim transaction (see `contracts/validators/policy.ak`, the
`n1_event_slot_*` tests, and the shared fixtures
`aegis_self_feed_input` / `default_policy_datum_aegis_self` /
`policy_input_with_marker` in
`contracts/lib/aegis/test_helpers/fixtures.ak`):

- triggered (`value <= strike`) → Claim **accepted**, pays `>= coverage`,
  canonical pool present, marker burns via `BurnForClaim`;
- alive (`value > strike`) → Claim **rejected**;
- stale feed (tx past `valid_until`) → **rejected**;
- wrong oracle-NFT pin (non-canonical NFT) → resolver aborts → **rejected**;
- wrong marker redeemer / missing marker → **rejected**.
