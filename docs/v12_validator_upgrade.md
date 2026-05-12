# Aegis V12 — Multi-Pair Oracle Allowlist + Protocol Fee Mechanism (Architectural Specification)

| Field | Value |
| --- | --- |
| Document | `D:/aegis/docs/v12_validator_upgrade.md` |
| Branch | `feat/v12-multi-pair-oracle` (already created, do not switch) |
| Parent commit | V11 staging head `c57a568` |
| Author | PACT Architect |
| Date | 2026-05-09 (revision 3: D7 floor, D8 B2 confirm, D9 full base-address confirm, D10 BatchUnderwrite in-scope) |
| Status | Design contract for the implementation waves (sealed when Wave 2 starts) |
| Implementation waves | 6 (see Section 11) |
| Scope | TWO coordinated trust-anchor rotations: (a) AegisSelf NFT allowlist widening, (b) protocol-fee extraction mechanism. Auditor reviews both as a single unit. |

---

## Table of Contents

1. Executive summary
2. Threat model
3. Aiken diff
   - 3.1 NFT allowlist (`types.ak`)
   - 3.2 Allowlist consumer (`aegis_self.ak`)
   - 3.3 Test additions (NFT allowlist)
   - 3.4 No other Aiken files change (NFT allowlist)
   - 3.5 Protocol-fee compile-time constants (`types.ak`)
   - 3.6 `PolicyDatum` extension (`types.ak`)
   - 3.7 `pricing.ak` helper additions
   - 3.8 `pool.ak` Underwrite branch diff (fee split outputs)
   - 3.9 `pool.ak` AcceptCancellation branch diff
   - 3.10 `pool.ak` BatchUnderwrite branch diff
   - 3.11 Where ProcessClaim and BatchExpireProcess intentionally do NOT change
4. Validator hash rotation table
5. Off-chain wiring
   - 5.1 Pair identifier convention
   - 5.2 `api/chain.py` — per-pair NFT policy constants
   - 5.3 `api/oracles/aegis_self.py` — pair-aware resolver
   - 5.4 `api/oracles/dispatcher.py` — thread pair through
   - 5.5 Build endpoints — pair + protocol-fee partner fields
   - 5.6 `GET /api/oracle/aegis-self/price?pair=`
   - 5.7 Files NOT changing
   - 5.8 `api/chain.py` — team address constant
   - 5.9 `api/policies.py` — fee-split output construction
6. Frontend changes
7. Env-var rotation table
8. Deploy procedure
9. V11 cutover plan
10. Test plan (TDD-first)
11. Rollout phases and file ownership
12. Open questions for the operator
13. Inconsistencies / surprises in the brief
14. V12 protocol-fee economics summary

---

## 1. Executive Summary

V12 ships two coordinated trust-anchor rotations under a single audit pass and a single deploy radius:

**(a) AegisSelf NFT allowlist widening.** The AegisSelf trust anchor is widened from a single canonical NFT (ADA/USD) to a closed compile-time allowlist of five canonical NFTs (ADA/USD, BTC/USD, ETH/USD, USDT/USD, USDC/USD), unlocking multi-asset crash protection on the same validator surface. The same on-chain `policy_validator` and `pool_validator` are reused with no semantic change: the validator still does a strict `oracle_price_scaled <= strike_price` check, but the resolver now accepts any UTxO carrying a token under any of five pinned policy ids (instead of exactly one). All five NFTs are one-shot mints under the same canonical publisher VKH, all minted with `quantity: 1` and the mint keys discarded — so the trust anchor is strictly equivalent to the round-6 single-NFT pin (A-026 / A-027), just enlarged from a singleton set to a five-element set.

**(b) Protocol-fee extraction mechanism.** V11 contracts route 100% of premium to the pool's lovelace and have NO path for the team to collect the 2% `protocol_fee_bps` — the 2% is silently absorbed into the pool's "phantom" lovelace (in the pool UTxO's value but NOT counted in `total_liquidity`), unreachable by team OR LPs OR users. V12 introduces a compile-time-pinned team address (per-network constant in `types.ak`) plus an optional caller-supplied partner address (Option<Address> field on `PolicyDatum`, capped at 20% of the protocol fee). Underwrite and AcceptCancellation both enforce that the 2% protocol fee is paid to the team output (and the partner output when specified) as a transaction-level invariant; the pool's lovelace continuation now equals `old + net_premium` (was `old + premium`). The 0.5% Cardano-treasury donation via Conway `treasury_donation` is unchanged.

**Composite economics for a 100-ADA premium, solo policy (no partner):** 98 ADA → pool, 2 ADA → team wallet, 0.5 ADA → Cardano treasury, 0 ADA → partner. Submitter pays 100.5 ADA. User-visible fee: 2.5% (was 0.5% in V11 phantom-stuck shape).

**Composite economics for a 100-ADA premium, partner @ 20%:** 98 ADA → pool, 1.6 ADA → team, 0.4 ADA → partner, 0.5 ADA → Cardano treasury. Submitter pays 100.5 ADA. User-visible fee: 2.5% (unchanged regardless of partner split).

Both validator hashes rotate as a side effect of the constant changes in `lib/aegis/types.ak`; `lp_token_policy` and `pool_nft_policy` chain off the new `pool_validator` hash so all four hashes rotate together (same rotation pattern as round 6). Off-chain the resolver, dispatcher, build endpoints, frontend BuyPanel, and `/api/oracle/aegis-self/price` route all gain a `pair` parameter (default ADA for backwards compatibility). The build endpoints accept new optional `partner_address` and `partner_share_bps` fields (defaults `None` / `0`). Cutover is a hard cut to V12; V11's four preprod test policies remain claimable via raw CLI against the V11 validator hash but are filtered out of the dApp's `/api/policies` list by pool-NFT policy id. Mainnet remains gated on auditor sign-off.

---

## 2. Threat Model

### 2.1 Restating the round-6 trust anchor

Round 6 (A-026 / A-027, closed 2026-05-04, audited by Hever — see `docs/audit/SECURITY_AUDIT_REPORT.md` round 6) replaced the original "publisher VKH only" trust handshake with a two-layer pin: the resolver now requires both (a) the UTxO to carry a token under a compile-time-pinned NFT policy id, AND (b) the UTxO to sit at a compile-time-pinned publisher payment credential. The single-NFT pin closed the surface where an attacker mints a fake NFT under their own permissive policy and outputs it at the publisher VKH address. The pre-fix two-layer argument ("attacker needs to BOTH compromise the publisher key AND mint under our parameterized one-shot policy") was wrong because the `oracle_nft` byte string was caller-controlled per-policy — the validator only checked that *some* token under the supplied policy id was present, not that the policy id itself was canonical.

### 2.2 What V12 changes about the trust anchor

V12 replaces the single canonical NFT policy id with a closed five-element allowlist. The relevant logic flips from `==` against one constant to `list.has` against a five-element compile-time list, with no other change to the trust handshake:

```aiken
// V11
expect oracle_nft == aegis_types.aegis_self_nft_policy

// V12
expect list.has(aegis_types.aegis_self_canonical_nfts, oracle_nft)
```

The publisher VKH leg (which gates the UTxO's payment credential) is unchanged.

### 2.3 Why allowlist expansion preserves the round-6 anchor

Each of the five canonical NFTs has identical trust properties to the round-6 single NFT:

1. **One-shot mint, `quantity: 1` permanent.** Each NFT is minted via the existing `pool_nft.ak` minting policy parameterized over an init UTxO that was consumed at mint time. Re-minting under the same policy id is mathematically impossible because the parameterizing init UTxO has been spent and the policy validator's mint branch requires that exact UTxO ref in the consumed inputs. Burns leave the asset at quantity zero but a fresh mint cannot occur — the policy is dead. So each NFT has exactly one canonical UTxO carrying it at any moment, and the publisher service spends-and-rolls that UTxO forward at every publish (same pattern as the V11 ADA/USD feed; see `publisher/main.py`).
2. **Same canonical publisher VKH (`6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152`).** All five NFTs were minted at outputs back to the publisher's base address. The on-chain `find_feed_output` (line 45 of `aegis_self.ak`) still requires the UTxO's payment credential to equal `aegis_self_publisher_vkh` — so the second trust leg gates all five NFTs equally.
3. **Mint authority keys discarded post-mint.** The publisher mnemonic-derived signing key signed each one-shot mint and is the only party with authority over future publishes; the *minting* authority for each NFT policy is the consumed init UTxO and cannot be re-exercised even by a key-compromised publisher.
4. **Compile-time closed set.** The five policy ids are encoded as a `List<ByteArray>` constant in `lib/aegis/types.ak`. Adding a sixth NFT requires a validator-hash rotation, which is the visible governance signal mirroring V11's "rotation IS the curated whitelist" pattern for `OracleProvider`. There is no per-policy or per-redeemer way for a caller to extend the allowlist at runtime.

### 2.4 What V12 does NOT change about the attacker's options

| Attack | V11 defense | V12 defense |
|---|---|---|
| Attacker mints a fake NFT under an attacker-chosen policy and outputs it at the publisher VKH | `expect oracle_nft == aegis_self_nft_policy` rejects the policy id | `expect list.has(aegis_self_canonical_nfts, oracle_nft)` rejects the policy id (attacker's policy is not in the five-element list) |
| Attacker compromises the publisher signing key and publishes a stale price | Out of scope — the publisher key compromise is bounded by what the publisher could already do today (sign a stale price). The validator's freshness gate (`tx_lower <= valid_until`) still requires the datum's `expiry` field, written 70 min into the future at publish time, to not have elapsed. | Identical — the V12 change touches only the NFT-allowlist leg. |
| Attacker rolls a key-compromised publisher's NFT to a non-publisher address and reads the feed from there | `find_feed_output` rejects: payment credential check fails | Identical — V12 does not touch the publisher-VKH leg. |
| Attacker re-mints one of the five NFTs under the same policy id | Mathematically blocked by the one-shot mint policy: the init UTxO is already spent | Identical |
| Caller crafts a `PolicyDatum` with `oracle_nft` set to a non-canonical policy id | At Underwrite time the pool validator's `oracle_pinned` check rejects it; at Claim time the `aegis_self` parser's `expect list.has(...)` rejects it | Identical (rule expanded but still applied) |

The attacker's "publisher key compromise" surface is unchanged. The attacker's "fake NFT under attacker-chosen policy" surface is unchanged. The only set-theoretic difference is that there are now five canonical UTxOs the parser is willing to read from instead of one, and each of those five has the same trust shape.

### 2.5 Per-policy binding semantics

A given `PolicyDatum.oracle_nft` is set at Underwrite time and is immutable for the policy's lifetime. So a policy underwritten with `oracle_nft = AEGIS_PRICE_FEED_BTC_USD_V1` can only claim against the BTC/USD feed; the validator's `list.has` check accepts the policy's pinned NFT but the same `find_feed_output` selects the unique UTxO carrying that specific NFT at the publisher credential. There is no cross-pair contamination: a BTC-bound policy reads BTC prices only. The same trust handshake the insured agreed to at premium-payment time is the one enforced at claim time — the existing v6 immutability argument on `PolicyDatum.oracle_provider` extends to `oracle_nft` unchanged.

---

## 3. Aiken Diff

### 3.1 `contracts/lib/aegis/types.ak`

The current file declares `aegis_self_nft_policy` as a single `ByteArray` constant at line 452. V12 replaces it with a five-element `List<ByteArray>` constant. The constant name changes from singular to plural to make the diff obvious in subsequent waves; consumers in `aegis_self.ak` are updated in lockstep (Section 3.2).

The five-element list is **ordered** alphabetically by symbol for diff stability: ADA, BTC, ETH, USDC, USDT. Aiken's `list.has` is order-agnostic, but lock-stepping the source order makes the diff reviewable. Each entry's hex literal is left-padded with `#""` so a typo (e.g. 27-byte instead of 28-byte) trips Aiken's parser, not a runtime check.

**Before (lines 429-453):**

```aiken
/// [v6.0.2 / A-026 fix] AegisSelf canonical publisher NFT policy id.
///
/// One-shot-minted per network (current preprod value below). The parser
/// now rejects any `oracle_nft` that does not equal this constant, closing
/// the surface where an attacker mints a fake NFT under their own permissive
/// policy and outputs it at the publisher VKH address (which anyone can do
/// — Cardano addresses accept inbound outputs from any sender; only spending
/// is gated by the payment credential).
///
/// **Why the original two-layer handshake was insufficient.** The header
/// of `aegis/oracle/aegis_self.ak` claimed the trust handshake "requires
/// the attacker to BOTH steal the publisher key AND mint under our
/// parameterized one-shot policy." That argument was wrong: the parser
/// only checked that the UTxO contained a token under the *caller-supplied*
/// `oracle_nft` policy id, not that the policy id was canonical. An
/// attacker minting under a fresh permissive policy and referencing the
/// resulting UTxO bypassed both legs.
///
/// **Per-network rotation.** The publisher NFT is a one-shot minted via
/// the `pool_nft.ak` validator parameterized over an init UTxO consumed
/// at mint time; a fresh mint per network produces a different policy id.
/// Update this constant per build target. Current value: preprod
/// `AEGIS_PRICE_FEED_V1`.
pub const aegis_self_nft_policy: ByteArray =
  #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f"
```

**After (replaces the same block):**

```aiken
/// [v12 / A-026 generalised] AegisSelf canonical publisher NFT allowlist.
///
/// Five one-shot mints under the SAME canonical publisher VKH, one per
/// supported pair (ADA/USD, BTC/USD, ETH/USD, USDC/USD, USDT/USD). Each
/// NFT has `quantity: 1` permanent and its mint authority is the consumed
/// init UTxO of `pool_nft.ak`, already spent — so re-minting is impossible
/// even with a publisher-key compromise. The parser at
/// `aegis/oracle/aegis_self.ak` rejects any `oracle_nft` that is not a
/// member of this list, preserving the round-6 A-026 trust anchor — the
/// only set-theoretic change is that the canonical set now has five
/// elements instead of one.
///
/// **Per-policy binding.** `PolicyDatum.oracle_nft` is frozen at
/// Underwrite time, so a BTC-bound policy reads BTC prices only and an
/// ADA-bound policy reads ADA prices only. No cross-pair contamination.
///
/// **Order.** Alphabetical by symbol (ADA, BTC, ETH, USDC, USDT) for diff
/// stability. `list.has` is order-agnostic so the on-chain semantics do
/// not depend on the order; this is a maintenance convention only.
///
/// **Per-network rotation.** Values below are preprod. Mainnet flips to
/// fresh one-shot mints during the mainnet deploy and rotates the
/// validator hash as the visible trust signal.
pub const aegis_self_canonical_nfts: List<ByteArray> =
  [
    // ADA/USD — asset name "AEGIS_PRICE_FEED_V1"
    #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
    // BTC/USD — asset name "AEGIS_PRICE_FEED_BTC_USD_V1"
    #"ae304e27806536dbbc222115c2b543e845f99bd8c7a3a01669f2d7bd",
    // ETH/USD — asset name "AEGIS_PRICE_FEED_ETH_USD_V1"
    #"d80aa1a72a46813b5045e163751076d54551fac4a6f8d720e15807ad",
    // USDC/USD — asset name "AEGIS_PRICE_FEED_USDC_USD_V1"
    #"860faa663d8a3ae3071d61f95464340c0e49c1f47f56db76441df7a0",
    // USDT/USD — asset name "AEGIS_PRICE_FEED_USDT_USD_V1"
    #"a4093bfc7758b86ca1b96df842367bce96cb954650a392020246c0cb",
  ]
```

The existing test `policy_datum_aegis_self_variant_constructs` (lines 513-535) keeps the original hex literal for `oracle_nft` (the ADA/USD policy id) and still compiles because that literal is the first element of the new list. No test deletion is required.

### 3.2 `contracts/lib/aegis/oracle/aegis_self.ak`

The current file imports `aiken/collection/list` at line 29 and already calls `list.has(oracle_nft)` at line 54 (in `find_feed_output`, against the policies of the UTxO's value). The V12 change is at line 83 only — the `expect` that pins the caller-supplied `oracle_nft` against the canonical constant.

**Before (lines 75-83):**

```aiken
  // [v6.0.2 / A-026 fix] Pin `oracle_nft` to the canonical AegisSelf
  // publisher NFT. The pre-fix file-header comment claimed the trust
  // handshake "requires the attacker to BOTH steal the publisher key AND
  // mint under our parameterized one-shot policy" — that argument was
  // wrong because `oracle_nft` was caller-controlled per policy. With
  // this pin in place, an attacker forging a fake NFT under their own
  // permissive policy is rejected before the payment-credential check
  // even runs.
  expect oracle_nft == aegis_types.aegis_self_nft_policy
```

**After (replaces the same block):**

```aiken
  // [v12 / A-026 generalised] Pin `oracle_nft` to the canonical AegisSelf
  // allowlist (five one-shot mints under the same publisher VKH, one per
  // supported pair). The semantics are unchanged from the round-6 single-
  // NFT pin: an attacker forging a fake NFT under their own permissive
  // policy is rejected before the payment-credential check even runs. The
  // only set-theoretic change is the canonical set's cardinality (5 vs 1).
  // See `lib/aegis/types.ak::aegis_self_canonical_nfts` for the threat
  // model and per-pair rotation contract.
  expect list.has(aegis_types.aegis_self_canonical_nfts, oracle_nft)
```

The `use aiken/collection/list` import on line 29 already exists; no import change is required. `list.has` is also used in the same file at line 54 (against `assets.policies(input.output.value)`), confirming it is the right stdlib function and confirming the calling convention `list.has(list, element) -> Bool`.

### 3.3 Test additions (Wave 2 Aiken agent's responsibility)

Three new tests in `aegis_self.ak`'s test block (or a sibling test module under `contracts/lib/aegis/oracle/aegis_self_tests.ak` if the file gets large). All three should be written BEFORE the diff in Section 3.1/3.2 lands (TDD-first):

```aiken
test allowlist_accepts_ada_usd() {
  // First element of the canonical list.
  list.has(
    aegis_types.aegis_self_canonical_nfts,
    #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
  )
}

test allowlist_accepts_btc_usd() {
  list.has(
    aegis_types.aegis_self_canonical_nfts,
    #"ae304e27806536dbbc222115c2b543e845f99bd8c7a3a01669f2d7bd",
  )
}

test allowlist_rejects_unknown_nft() {
  // Random 28-byte hex string not in the canonical list.
  !list.has(
    aegis_types.aegis_self_canonical_nfts,
    #"0011223344556677889900112233445566778899001122334455667788",
  )
}
```

The five per-pair acceptance tests (ADA, BTC, ETH, USDC, USDT) and the negative-case rejection test are the core regression surface. The full UTxO-based spend-path test (with a reference input carrying the right NFT, the wrong NFT, etc.) belongs in a Wave 2 fixture file under `contracts/lib/aegis/test_helpers/`.

### 3.4 No other Aiken files change (NFT allowlist scope)

For the NFT-allowlist-only scope, the `policy_validator` and `pool_validator` validators (under `contracts/validators/`) do not need source changes — they read the canonical NFT allowlist transitively via the `aegis_self.ak::find_feed_datum` call chain. The on-chain `Underwrite` redeemer's `oracle_pinned` check (introduced in round 6, see `validators/pool.ak`) also routes through the same parser, so widening the allowlist there happens automatically through the type-level dependency on `lib/aegis/types.ak`.

(Note: the protocol-fee mechanism §3.5–§3.10 below DOES change `validators/pool.ak` and `lib/aegis/types.ak::PolicyDatum` and `lib/aegis/pricing.ak`. So in the full V12 scope, multiple validator files change. The "no other files" claim above is local to the NFT allowlist diff.)

That said, both validator hashes rotate because they consume `lib/aegis/types.ak` (importing modules pick up the new constant in their compiled blob). This is the visible governance signal — the validator hash bytes change, so the deployed reference scripts at the V11 hashes do not satisfy the V12 hashes.

---

### 3.5 Protocol-fee compile-time constants (`types.ak`)

Two new compile-time constants land at the bottom of the existing Protocol Constants block in `lib/aegis/types.ak` (after `treasury_share_bps` at line 283). They use the same pinning pattern as `treasury_share_bps` and `aegis_self_publisher_vkh`: validator-hash-pinned, rotation = redeploy.

The team address requires a per-network split mirroring the existing AEGIS_NETWORK build pattern (today the codebase pins individual `_preprod`/`_mainnet` constants and selects via build-time env — see `aegis_self_publisher_vkh` at line 426 with its `Network coverage` docstring explaining that single VKH works across networks because BIP-44 derivation is network-agnostic; the team address is NOT BIP-44-derived, so it MUST split). The publisher_vkh is `ByteArray` because `Hash<Blake2b_224, VerificationKey>` is an opaque alias (line 422-425); the team Address is a full `Address` record (payment_credential + stake_credential), so it imports the `cardano/address` types and stores both halves natively.

**Diff against `lib/aegis/types.ak`** (insert AFTER line 453, the existing `aegis_self_nft_policy` block — note: by Wave 2 land-time this block has already become `aegis_self_canonical_nfts` per §3.1):

```aiken
// ---------------------------------------------------------------------------
// Protocol Fee Routing (Aegis v12)
// ---------------------------------------------------------------------------

/// [v12] Team wallet address that receives the team's share of the 2%
/// protocol fee on every Underwrite / BatchUnderwrite / AcceptCancellation
/// tx. Compile-time pinned per network — rotation = new validator hash =
/// new deploy, same security pattern as `aegis_self_nft_policy_preprod`
/// vs `_mainnet` (visible governance signal in the script hash bytes).
///
/// The fee path: each fee-bearing branch checks that the tx outputs contain
/// at least one entry with `address == team_address` carrying lovelace
/// >= team_cut, where team_cut = floor(premium * protocol_fee_bps / 10_000)
/// minus partner_cut (see `pricing.calculate_protocol_fee_split`). The
/// validator does NOT check the stake credential of the routed output —
/// the address record is the full `Address` value (payment + stake), so
/// the equality check matches the full base-address shape the operator
/// configured.
///
/// **Why a compile-time constant and not a `PoolDatum` field.** Same
/// argument as `treasury_share_bps`: the economic destination is pinned
/// by validator hash. An operator who could mutate the team address via
/// datum could silently redirect fees mid-flight; pinning it at compile
/// time forces a visible redeploy + audit step on any rotation.
///
/// **Address shape decode.** Both addresses below are CIP-19 base type-0
/// addresses: 1-byte header + 28-byte payment VKH + 28-byte stake VKH.
/// They were decoded from the operator-supplied bech32 strings using the
/// helper script at `docs/architecture/_decode_addresses.py` (kept in the
/// repo so the Wave 2 agent and the auditor can re-derive the bytes).
/// Operator confirmations:
///   * Preprod = `addr_test1qrph8epfa8dg6wjwmls873g0xllyjnlt3hh08nv9kcrw9ln40ur83k9c87dpxuar3jucqrg0sc54zvzmf53pu6due2eqa5m8d2`
///     (operator signing wallet, confirmed in V12 architect handoff session)
///   * Mainnet = `addr1q9s6m9d8yedfcf53yhq5j5zsg0s58wpzamwexrxpfelgz2wgk0s9l9fqc93tyc8zu4z7hp9dlska2kew9trdg8nscjcq3sk5s3`
///     (Flux Point Studios team wallet)
pub const team_address_preprod: Address =
  Address {
    payment_credential: VerificationKey(
      #"c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe",
    ),
    stake_credential: Some(
      Inline(
        VerificationKey(
          #"757f0678d8b83f9a1373a38cb9800d0f862951305b4d221e69bccab2",
        ),
      ),
    ),
  }

pub const team_address_mainnet: Address =
  Address {
    payment_credential: VerificationKey(
      #"61ad95a7265a9c269125c149505043e143b822eedd930cc14e7e8129",
    ),
    stake_credential: Some(
      Inline(
        VerificationKey(
          #"c8b3e05f9520c162b260e2e545eb84adfc2dd55b2e2ac6d41e70c4b0",
        ),
      ),
    ),
  }

/// [v12] Active-network team address. Set per build target.
///
/// Currently pinned to preprod; promoting to mainnet flips this to
/// `team_address_mainnet` and rotates the validator hash. Same selection
/// shape as `orcfax_fsp_script_hash` (line 399) — a single active-network
/// constant whose value is edited per build.
pub const team_address: Address = team_address_preprod

/// [v12] Maximum partner share of the protocol fee, in basis points of the
/// protocol fee (not of the premium). 2000 bps = 20% of the 2% protocol
/// fee = 0.4% of the premium maximum to any partner. The validator rejects
/// any `PolicyDatum.partner_share_bps > partner_share_cap_bps` at
/// Underwrite / BatchUnderwrite / AcceptCancellation time.
///
/// The cap is a defense-in-depth measure: caller-supplied `partner_address`
/// is a self-pwn surface (a caller diverting their own fees away from the
/// team into a wallet they don't control), but a careless integrator could
/// set `partner_share_bps = 10_000` and route 100% of the protocol fee to
/// the partner, leaving the team with nothing. The cap pins the floor on
/// team revenue at 80% of the protocol fee (1.6% of premium).
pub const partner_share_cap_bps: Int = 2_000
```

**Imports** at the top of `types.ak`. The current imports at line 9-10 are:

```aiken
use aiken/crypto.{Blake2b_224, Hash, Script, VerificationKey}
use aiken/primitive/bytearray
```

The naming consideration: `aiken/crypto` exports `VerificationKey` as a phantom-type marker (used only as a type parameter in `Hash<Blake2b_224, VerificationKey>`); `cardano/address` exports `VerificationKey` as a `Credential` constructor that takes a `Hash<Blake2b_224, VerificationKey>` (= ByteArray, since `Hash` is a transparent alias per `aiken/crypto.ak` line 51). Aiken does NOT support `use module.{Symbol as Alias}` syntax for individual symbols — only `use module as alias` for whole modules. So a name clash on `VerificationKey` would shadow.

Empirical check: `lib/aegis/validation.ak` line 1 imports `VerificationKeyHash` from `aegis/types` AND line 13 imports `VerificationKey` from `cardano/address` — these coexist because the `aiken/crypto.VerificationKey` phantom-type is NOT directly imported (only `VerificationKeyHash` aliased over it). The `Hash<Blake2b_224, _>` annotation in `validation.ak` is achieved via the imported alias.

**Recommended import change for `types.ak`:** drop `VerificationKey` from the `aiken/crypto` import (it's used at line 18 only — as a phantom-type marker in the `VerificationKeyHash` alias definition; that line can stay as-is because `aiken/crypto.{Hash, Blake2b_224}` is still imported, and the bare identifier `VerificationKey` inside `Hash<Blake2b_224, VerificationKey>` refers to whatever `VerificationKey` is in scope — which would now be the `cardano/address` constructor). Wait — this CAN'T work because `cardano/address.VerificationKey` is a constructor of `Credential`, not a type-level identifier suitable for `Hash<Blake2b_224, _>` phantom-parameterization.

**Real solution.** Two paths:

**Path A — keep `aiken/crypto.VerificationKey` in scope for the `VerificationKeyHash` alias; reference the address constructor via the credential module qualifier.** Aiken supports module-qualified type references: `cardano/address.VerificationKey(...)`. Verify with the wave-2 agent — this is the cleanest path if it compiles.

**Path B — give up on Address literals; build the team_address via the smart constructor `from_verification_key(<bytes>).with_delegation_key(<bytes>)`.** No name collision: the smart constructors are unambiguous function calls. Final diff:

```aiken
use cardano/address.{Address, from_verification_key, with_delegation_key}

pub const team_address_preprod: Address =
  from_verification_key(
    #"c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe",
  )
    |> with_delegation_key(
        #"757f0678d8b83f9a1373a38cb9800d0f862951305b4d221e69bccab2",
      )

pub const team_address_mainnet: Address =
  from_verification_key(
    #"61ad95a7265a9c269125c149505043e143b822eedd930cc14e7e8129",
  )
    |> with_delegation_key(
        #"c8b3e05f9520c162b260e2e545eb84adfc2dd55b2e2ac6d41e70c4b0",
      )
```

**Recommended: Path B.** The smart-constructor form is what `cardano/address.ak` lines 38-46 / 49-57 provide for exactly this use case; the pipe syntax (`|>`) is idiomatic Aiken (used throughout the codebase, e.g. `policy.ak:137`); and it avoids the import-name shadow entirely. The struct-literal form in my earlier diff above (`Address { payment_credential: ..., stake_credential: ... }`) is also valid IF the name-clash is resolved via path A, but path B is shorter and clearer.

**D9 — operator confirmation: lock the FULL base address (payment_vkh + stake_vkh), Path B form.** Per operator decision D9, the validator pins the full 56-byte base address (28-byte payment VKH + 28-byte stake VKH) at compile time, NOT a payment-credential-only equality. Rotation requires a new validator deploy. The Wave 2 agent uses Path B (`from_verification_key |> with_delegation_key`). The decoded VKH bytes from `docs/architecture/_decode_addresses.py` are pinned verbatim:

- **Preprod team address** (`addr_test1qrph8epfa8dg6wjwmls873g0xllyjnlt3hh08nv9kcrw9ln40ur83k9c87dpxuar3jucqrg0sc54zvzmf53pu6due2eqa5m8d2`):
  - payment_vkh = `c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe`
  - stake_vkh = `757f0678d8b83f9a1373a38cb9800d0f862951305b4d221e69bccab2`
- **Mainnet team address** (`addr1q9s6m9d8yedfcf53yhq5j5zsg0s58wpzamwexrxpfelgz2wgk0s9l9fqc93tyc8zu4z7hp9dlska2kew9trdg8nscjcq3sk5s3`):
  - payment_vkh = `61ad95a7265a9c269125c149505043e143b822eedd930cc14e7e8129`
  - stake_vkh = `c8b3e05f9520c162b260e2e545eb84adfc2dd55b2e2ac6d41e70c4b0`

Operational consequence: an operator who delegates the team wallet to a new stake pool (rotating the stake VKH while keeping the payment VKH) MUST rebuild and redeploy the validator. This is the operator-blessed cost of pinning the full address — full-address pinning eliminates the entire class of "same-payment-but-different-stake" exfiltration shapes the validator equality check would otherwise admit.

Wave 2 agent picks Path A vs Path B based on what compiles; this doc gives both versions. Per D9 the Path B pinning is the recommended form. The decoded VKH bytes are identical either way.

**Address tests** (defensive, in the same `types.ak` test block):

```aiken
// Note: the `VerificationKey` constructor pattern below references the
// cardano/address Credential.VerificationKey. Under Path A (struct literals)
// this requires the import disambiguation; under Path B (smart constructors)
// the test pattern-matches on the constructed Address record's payment_credential
// field, which is structurally identical.
test team_address_preprod_payment_credential_28_bytes() {
  // Defensive length pin. A typo in the hex literal would silently bypass
  // the equality check at Underwrite time and route fees to an attacker.
  when team_address_preprod.payment_credential is {
    VerificationKey(h) -> bytearray.length(h) == 28
    _ -> False
  }
}

test team_address_mainnet_payment_credential_28_bytes() {
  when team_address_mainnet.payment_credential is {
    VerificationKey(h) -> bytearray.length(h) == 28
    _ -> False
  }
}

test team_address_preprod_has_stake_credential() {
  // The team address is a BASE address (payment + stake), not enterprise.
  // If the smart constructor or struct literal drops the stake leg, this
  // test catches it.
  team_address_preprod.stake_credential != None
}

test partner_share_cap_bps_is_2000() {
  partner_share_cap_bps == 2_000
}
```

### 3.6 `PolicyDatum` extension (`types.ak`)

`PolicyDatum` (line 93-135) gains two new fields at the END of the schema (positional append, mirroring the v6 `oracle_provider` append pattern documented at line 86-92). Appending at the end keeps the diff diff-friendly and follows the existing migration semantics — V11 policies that decode under the V12 schema fail the `expect pdat: PolicyDatum = raw_pdat` check, which is the intended hard-cut behavior (V11 policies are stranded at the V11 validator hash, per §9).

**Diff against `lib/aegis/types.ak`** at line 134, immediately before the closing `}`:

```aiken
  /// [v12 NEW] Optional partner address that receives a share of the 2%
  /// protocol fee. Set at policy-creation time and immutable. None means
  /// the entire 2% fee flows to `team_address` (solo policy); Some(addr)
  /// requires `partner_share_bps > 0` and routes the partner_cut to that
  /// address.
  ///
  /// Trust model: caller-supplied. Anyone can set any address. A caller
  /// setting an attacker-controlled `partner_address` is self-pwning
  /// (diverting their own fees away from the team to a wallet they don't
  /// control); the protocol incurs no risk. Partner registry / lookup is
  /// a frontend UX concern (post-V12 follow-up — see Section 11 rollout).
  partner_address: Option<Address>,
  /// [v12 NEW] Partner share of the protocol fee in basis points of the
  /// fee (NOT of the premium). 0..=2000 (capped by validator at
  /// `partner_share_cap_bps`). Set at policy-creation time and immutable.
  ///
  /// Validator invariants:
  ///   * `partner_share_bps >= 0` (defensive; rejects signed-int weirdness)
  ///   * `partner_share_bps <= partner_share_cap_bps` (= 2000 bps = 20% of fee)
  ///   * `partner_address == None` => `partner_share_bps == 0`
  ///   * `partner_address == Some(_)` => no lower-bound on partner_share_bps;
  ///     a 0-share partner is legal (treated as a "credit" — partner is
  ///     recorded in the datum for analytics but receives no lovelace)
  partner_share_bps: Int,
```

**Datum-size impact.** A bech32 base address decodes to 57 raw bytes (header + 28 payment + 28 stake). In CBOR encoding inside a Plutus Constr, the `Address` is encoded as a nested `Constr_0(Constr_0(...), Constr_0(Constr_0(Constr_0(...))))` — payment_credential, then `Some(Inline(...))`. The on-chain CBOR size is approximately 90 bytes for an `Option<Address>` set to `Some(base_address)`. The added `partner_share_bps: Int` is 1-9 CBOR bytes depending on magnitude (typically 2 bytes for values <256). Total datum growth: **~92 bytes when partner is Some, ~5 bytes when partner is None**.

Policy UTxO min-utxo lovelace at Cardano's current `utxoCostPerByte = 4310 lovelace/byte` (Conway protocol param): worst-case 92 bytes × 4310 = ~396_520 lovelace = **~0.4 ADA increment**. Negligible relative to the policy's coverage (typically 10-500 ADA) and within the existing `MIN_UTXO_LOVELACE = 2_000_000` floor (line 270 of `types.ak`). No min-utxo adjustment required.

**Backwards compatibility.** V11 `PolicyDatum` has 11 positional fields (added `oracle_provider` to v5's 10-field schema; see `types.ak` line 86-92 docstring); V12 has 13 fields (`partner_address`, `partner_share_bps` appended). V11 policies do not decode under the V12 schema — the `expect pdat: PolicyDatum = raw_pdat` check fails on field-count mismatch. This is fine because of the hard-cut cutover (§9). Wave 2 agent updates the existing `policy_datum_construction` test (line 459-475) and `policy_datum_aegis_self_variant_constructs` test (line 513-535) to include the two new fields. New construction tests:

```aiken
test policy_datum_v12_no_partner() {
  let datum =
    PolicyDatum {
      policy_id: #"aabb",
      insured: #"0011223344556677889900112233445566778899001122334455667788",
      strike_price: 350_000,
      coverage_amount: 5_000_000_000,
      premium_paid: 100_000_000,
      start_time: 1_700_000_000_000,
      expiry_time: 1_700_604_800_000,
      oracle_nft: #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
      pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
      pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
      oracle_provider: AegisSelf,
      partner_address: None,
      partner_share_bps: 0,
    }
  datum.partner_share_bps == 0 && datum.partner_address == None
}

test policy_datum_v12_with_partner() {
  // partner_address pointing at the V12 team address itself — synthetic
  // example; in production the partner would be a distinct integrator.
  let datum =
    PolicyDatum {
      policy_id: #"aabb",
      insured: #"0011223344556677889900112233445566778899001122334455667788",
      strike_price: 350_000,
      coverage_amount: 5_000_000_000,
      premium_paid: 100_000_000,
      start_time: 1_700_000_000_000,
      expiry_time: 1_700_604_800_000,
      oracle_nft: #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
      pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
      pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
      oracle_provider: AegisSelf,
      partner_address: Some(team_address_preprod),
      partner_share_bps: 2_000,
    }
  datum.partner_share_bps == 2_000
}
```

### 3.7 `pricing.ak` helper additions

`lib/aegis/pricing.ak` gains a single new helper that splits a protocol fee into team and partner cuts. Mirror the existing two-stage division convention of `calculate_treasury_cut` (line 76-82) so rounding semantics match.

**Diff against `lib/aegis/pricing.ak`** at line 82 (immediately after `calculate_treasury_cut`):

```aiken
/// [v12] Split a protocol fee into team and partner cuts.
///
/// Returns `(team_cut, partner_cut)` such that
///   `team_cut + partner_cut == calculate_protocol_fee(premium, protocol_fee_bps)`
/// (exactly, with no rounding drift between the two halves).
///
/// `partner_share_bps` is in bps OF THE FEE (not of the premium). At the
/// V12 defaults (`protocol_fee_bps = 200`, `partner_share_bps = 0..=2000`),
/// partner_cut is 0..=0.4% of premium and team_cut is 1.6..=2.0% of premium.
///
/// Floor-rounding convention: any fractional lovelace from the multi-stage
/// division accrues to `team_cut` (not partner). Rationale: the team is the
/// protocol's economic baseline; partners are a routing detail. A single
/// floor in partner_cut and a subtraction-derived team_cut guarantees the
/// invariant `team_cut + partner_cut == total_fee` holds exactly without a
/// double-rounding ambiguity.
pub fn calculate_protocol_fee_split(
  premium: Int,
  protocol_fee_bps: Int,
  partner_share_bps: Int,
) -> (Int, Int) {
  let total_fee = calculate_protocol_fee(premium, protocol_fee_bps)
  let partner_cut = total_fee * partner_share_bps / 10_000
  let team_cut = total_fee - partner_cut
  (team_cut, partner_cut)
}
```

**Test additions** in the existing `pricing.ak` test block (lines ~250-304):

```aiken
// ---------------------------------------------------------------------------
// Protocol Fee Split Tests
// ---------------------------------------------------------------------------

test fee_split_solo_policy_routes_full_fee_to_team() {
  // 100 ADA premium, 2% fee = 2 ADA, no partner -> team gets full 2 ADA.
  let (team, partner) = calculate_protocol_fee_split(100_000_000, 200, 0)
  team == 2_000_000 && partner == 0
}

test fee_split_partner_at_max_cap() {
  // 100 ADA premium, 2% fee = 2 ADA, partner @ 20% -> partner 0.4, team 1.6.
  let (team, partner) = calculate_protocol_fee_split(100_000_000, 200, 2_000)
  team == 1_600_000 && partner == 400_000
}

test fee_split_sum_equals_total_fee_exact() {
  // Cross-check the invariant: split sums exactly to the total fee
  // regardless of partner_share_bps.
  let premium = 250_000_000
  let total_fee = calculate_protocol_fee(premium, 200)
  let (team, partner) = calculate_protocol_fee_split(premium, 200, 1_337)
  team + partner == total_fee
}

test fee_split_zero_premium_yields_zero_both_sides() {
  let (team, partner) = calculate_protocol_fee_split(0, 200, 1_000)
  team == 0 && partner == 0
}

test fee_split_zero_fee_yields_zero_both_sides() {
  let (team, partner) = calculate_protocol_fee_split(100_000_000, 0, 2_000)
  team == 0 && partner == 0
}

test fee_split_partner_share_zero_routes_full_fee_to_team() {
  // Distinct from solo: partner_address may be Some(_) but share == 0.
  // The split function does not see the address; it just respects the bps.
  let (team, partner) = calculate_protocol_fee_split(100_000_000, 200, 0)
  team == 2_000_000 && partner == 0
}
```

### 3.8 `pool.ak` Underwrite branch diff (fee split outputs)

The Underwrite branch (lines 295-384) gains three new invariants and changes the pool value-equality check:

1. **Pool continuation now equals `old + net_premium`** (was `old + premium`). This is the breaking change: in V11 the pool's lovelace grew by the full premium (silently absorbing the 2% protocol fee as phantom liquidity); in V12 the pool's lovelace grows by net_premium only, and the 2% is routed to required outputs.

2. **Team output check.** The tx outputs must contain at least one entry with `address == team_address` and lovelace >= team_cut. The check uses an equality (not a sum-across-outputs) — exactly one team output is required, value >= team_cut.

3. **Partner output check.** If `policy_datum.partner_address == Some(addr)`, an output at `addr` with lovelace >= partner_cut is required. If `None`, `partner_share_bps == 0` is required (no partner output check, but `partner_share_bps > 0` with `None` address is rejected).

4. **Partner share cap check.** `0 <= partner_share_bps <= partner_share_cap_bps`.

The validator reads `partner_address` and `partner_share_bps` from the NEW policy output's datum (the policy being created by this Underwrite tx — these fields are part of the new `PolicyDatum`). The values are inspected inside `policy_output_matches_underwrite` (line 172-231) and threaded back to the top-level branch as helper outputs.

**Inspection of current Underwrite branch.** Key lines:

- Line 321: `let net = net_premium(premium, datum.protocol_fee_bps)` — net premium already computed.
- Line 342-343: `let value_ok = assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + premium` — the V11 strict equality on full premium. **This changes to `+ net`.**
- Line 354-363: `policy_output_matches_underwrite(...)` — the function returns Bool; in V12 it must additionally extract the new policy datum's `partner_address` and `partner_share_bps` so the Underwrite branch can apply the team/partner output checks. Refactor `policy_output_matches_underwrite` to return `Option<(Address, Int)>` (the new policy's partner_address + partner_share_bps, or None if no matching policy output was found) — or add a sibling helper that performs the partner read and is called in parallel.

**Diff sketch.** Insert AFTER existing `policy_funded` computation (line 363) and BEFORE `donation_ok` (line 371):

```aiken
// [v12] Compute the protocol-fee split. Both cuts derive from the redeemer's
// `premium` and the pool datum's `protocol_fee_bps`, plus the NEW policy
// datum's `partner_share_bps`. The new policy datum's `partner_address` is
// extracted in parallel via `policy_output_partner_fields(outputs, ...)`,
// returning `(partner_address, partner_share_bps)`. If the helper returns
// None, the Underwrite tx has no matching policy output and `policy_funded`
// would already have rejected it; we still defensively return False here.
expect Some((new_partner_address, new_partner_share_bps)) =
  policy_output_partner_fields(
    outputs,
    own_pool_hash,
    datum.pool_nft,
    policy_script_hash,
    coverage,
    premium,
  )

// [v12] Cap check on partner_share_bps. Defense-in-depth alongside the
// canonical-datum pin in `policy_output_matches_underwrite`.
let partner_share_in_bounds =
  new_partner_share_bps >= 0 && new_partner_share_bps <= partner_share_cap_bps

// [v12] Partner-address consistency: nonzero share REQUIRES Some(addr).
let partner_consistency =
  when new_partner_address is {
    Some(_) -> True
    None -> new_partner_share_bps == 0
  }

// [v12] Compute the (team_cut, partner_cut) split.
let (team_cut, partner_cut) =
  calculate_protocol_fee_split(
    premium,
    datum.protocol_fee_bps,
    new_partner_share_bps,
  )

// [v12 / D7] Min-utxo floor on the team output. The lower bound enforced
// by the validator is `max(min_utxo_lovelace, team_cut)`. When team_cut
// is below the 2-ADA floor (small premiums, < 100 ADA at protocol_fee_bps =
// 200), the submitter's wallet pays the floor-pad subsidy — exactly the
// same submitter-source pattern used for the Conway `treasury_donation`
// (sourced from submitter inputs, not from the pool, not from the
// premium). The pool's `total_liquidity` and physical lovelace still
// grow by exactly `net_premium = premium - team_cut - partner_cut`
// (NOT minus the floored amounts) — the floor pad is exogenous to pool
// accounting.
let team_required_lovelace =
  if team_cut > min_utxo_lovelace { team_cut } else { min_utxo_lovelace }

// [v12] Team output check. Exactly: an output exists at team_address with
// lovelace >= team_required_lovelace. Using `list.any` matches the existing
// find-style pattern in this file (lines 280-289); the comparison must be
// on full Address equality (payment + stake), not just payment_credential.
let team_output_funded =
  list.any(
    outputs,
    fn(out) {
      out.address == team_address &&
        assets.lovelace_of(out.value) >= team_required_lovelace
    },
  )

// [v12 / D7] Min-utxo floor on the partner output. Same submitter-pad
// semantics as the team output: when partner_cut < 2 ADA, the submitter
// pays the difference from their own wallet inputs. partner_cut itself
// (the lovelace the pool yields away) is unchanged by the floor — the
// pool grows by net_premium regardless of whether the partner's output
// was floor-padded.
let partner_required_lovelace =
  if partner_cut > min_utxo_lovelace { partner_cut } else { min_utxo_lovelace }

// [v12] Partner output check. If partner_address is Some(addr), an output
// at addr with lovelace >= partner_required_lovelace is required. If
// None, this passes trivially (partner_consistency above already enforces
// share == 0 in the None case, so partner_cut == 0 and there's nothing
// to route).
let partner_output_funded =
  when new_partner_address is {
    Some(addr) ->
      list.any(
        outputs,
        fn(out) {
          out.address == addr &&
            assets.lovelace_of(out.value) >= partner_required_lovelace
        },
      )
    None -> True
  }
```

**Floor math walkthrough.** For a 100-ADA premium with `partner_share_bps = 2000` (20% cap):

- `team_cut = 1.6 ADA` (below floor) → `team_required_lovelace = 2 ADA` → submitter subsidizes 0.4 ADA from their own wallet inputs.
- `partner_cut = 0.4 ADA` (below floor) → `partner_required_lovelace = 2 ADA` → submitter subsidizes 1.6 ADA.
- Pool grows by `net_premium = 100 - 1.6 - 0.4 = 98 ADA` (unaffected by the floor padding — pool accounting is honest against the percentage-calculated cuts).
- Submitter total cost: `100 (premium) + 0.4 (team pad) + 1.6 (partner pad) + 0.5 (Cardano treasury) = 102.5 ADA`.

For a 200-ADA premium, no partner: `team_cut = 4 ADA` (above floor) → exact, no subsidy. Submitter cost = `200 + 0 + 1 = 201 ADA`.

For a 50-ADA premium, no partner: `team_cut = 1 ADA` (below floor) → `team_required_lovelace = 2 ADA` → submitter pays 1 ADA pad. Submitter cost = `50 + 1 + 0.25 = 51.25 ADA`.

**Constant reference.** `min_utxo_lovelace: Int = 2_000_000` already exists at `lib/aegis/types.ak:270` (lowercase per Aiken idiom; no rename required). The Wave 2 agent imports it alongside `treasury_share_bps`:

```aiken
use aegis/types.{
  ..., min_utxo_lovelace, treasury_share_bps, partner_share_cap_bps,
  team_address,
}
```

And modify `value_ok` (line 342-343):

```aiken
// [v12] Pool continuation grows by net_premium ONLY. The 2% protocol fee
// is routed to team_output + partner_output (above). Pre-V12 this was
// `+ premium` and the 2% sat as phantom lovelace in the pool — unreachable
// by team OR LPs (since `total_liquidity` only counted `net`).
let value_ok =
  assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + net
```

And extend the final conjunction:

```aiken
coverage_positive && premium_positive && premium_ok && can_cover && datum_ok && immutable_ok && value_ok && policy_funded && donation_ok && partner_share_in_bounds && partner_consistency && team_output_funded && partner_output_funded
```

**New helper `policy_output_partner_fields`.** Mirrors `policy_output_matches_underwrite` (line 172-231) but returns the new policy datum's `(partner_address, partner_share_bps)` tuple instead of a Bool. Wave 2 agent's call whether to (a) extract these from `policy_output_matches_underwrite` by changing its return type to `Option<(Address, Int)>`, or (b) write a parallel `policy_output_partner_fields` helper. Option (a) is fewer LOC and removes the double-walk over outputs; option (b) keeps the existing helper's contract stable. **Recommended: option (a)** — refactor `policy_output_matches_underwrite` to return `Option<(Option<Address>, Int)>` (Some when a matching policy output was found, with the partner fields extracted; None otherwise), and update the call site at line 354 to bind the tuple.

**Existing oracle_pinned check.** Line 124-125 / 205-206 already binds `pdat.oracle_nft == canonical_oracle_nft(pdat.oracle_provider)` inside both `policy_output_matches_underwrite` and `batch_policies_match_totals`. No V12 change to this check; the canonical_oracle_nft dispatcher in `oracle.ak::canonical_oracle_nft` (line 96-102) already reads `aegis_self_nft_policy` → in V12 this becomes a `list.has(aegis_self_canonical_nfts, pdat.oracle_nft)` check (NOT a single-element equality), see §3.2. The Wave 2 agent updates `canonical_oracle_nft` to return a list and updates the callers' equality `==` check to `list.has(...)`.

### 3.9 `pool.ak` AcceptCancellation branch diff

The AcceptCancellation branch (lines 746-824) requires the same 2%/0.5% split treatment on the cancellation fee retention (currently lines 808-822 only handle the treasury_donation cut).

**Critical inspection of the current cancel flow** (verified against `pool.ak` lines 727-824 and `policy.ak` lines 338-398 and `api/policies.py` lines 2900-3068):

| Actor | Lovelace in | Lovelace out |
|---|---|---|
| Pool input | `old_pool` | — |
| Policy input | `coverage` (only — policy holds coverage, not premium) | — |
| Submitter wallet inputs | ≥ fee + treasury_donation | — |
| Pool continuation output | — | `old_pool - refund` (validator strict equality, line 791-792) |
| Insured payout output | — | `refund + coverage` (= `0.9*premium + coverage`, off-chain `api/policies.py:3023`) |
| Submitter change + Cardano treasury | — | balance |

The 10% cancellation retention is `cancellation_fee = 0.1 * premium`. Where does it physically live AFTER cancel? It does NOT flow out of the pool: at Underwrite time the pool absorbed the FULL premium (`+ premium`) but the datum's `total_liquidity` only credited `+ net_premium = + 0.98 * premium`. So the pool's physical lovelace at Underwrite had `premium - net_premium = 0.02 * premium` of phantom liquidity. Then at cancel, the pool's lovelace decreases by `refund = 0.9 * premium`, but `total_liquidity` decreases by `refund` too — so the "phantom" 0.02 * premium STAYS in the pool's physical lovelace (still phantom — uncounted in `total_liquidity`). Then the 0.1 * premium retention also stays in the pool's phantom lovelace (the pool started with `+premium`, lost `refund = 0.9*premium`, net `+ 0.1 * premium`; of that `0.1 * premium`, the `total_liquidity` is at `+ 0.98 * premium - 0.9 * premium = + 0.08 * premium`, leaving `0.02 * premium` phantom which is the SAME 2% protocol fee phantom from Underwrite). So in V11 the 10% retention is **already in `total_liquidity` accruing to LPs**, and the 2% protocol fee is **phantom** — same situation as Underwrite.

**V12 change.** Two design choices for where the protocol fee cut on cancel comes from:

**Choice A — cut from the original premium** (parallel to Underwrite's semantics): apply the same 2%/0.5% split on `policy_datum.premium_paid` as if the Underwrite were running fresh. Math per 100-ADA premium:

- Pool change: `-refund - team_cut - partner_cut + 0` (the 2% was already paid out at Underwrite — no, wait, in V12 the 2% was paid out at Underwrite so the pool already has only `net_premium` of that premium, not `premium`. So at cancel, the 2% fee no longer exists in the pool to be split. Choice A is unviable in V12 because the protocol fee was already extracted at Underwrite.)

**Choice B — cut from the 10% retention** (V12-native): the 10% cancellation fee was credited to `total_liquidity` at cancel time (since at Underwrite the policy contributed `net_premium = 0.98 * premium` to `total_liquidity`; at cancel `total_liquidity` decreases by `refund = 0.9 * premium`, net delta `+ 0.08 * premium` retained as LP-claimable liquidity). The V12 cancel applies a 2%-of-PREMIUM fee on top of this — `team_cut + partner_cut = 0.02 * premium` extracted to team/partner at cancel time, in addition to the Underwrite-time extraction. Per 100-ADA premium:

| Phase | Pool delta (lovelace) | Pool delta (total_liquidity) | Team cumulative | Partner cumulative |
|---|---|---|---|---|
| Underwrite | + 98 | + 98 | + 2 | + 0 (solo) |
| Cancel | - 90 (refund) - 2 (V12 cancel cut) = -92 | - 90 (refund) - 2 (V12 cancel cut) = - 92 | + 2 (extra) | + 0 |
| **Net** | **+ 6** | **+ 6** | **+ 4** | **+ 0** |

So the LP ends up with `+ 6 ADA per cancel` (the 10% retention minus the 4% total team take from premium across Underwrite + Cancel). The team takes 4% of the original premium on the cancel path. This DOUBLES the team's take on cancelled policies.

**Choice B doubles the cancel-path team fee.** Two ways to reconcile:

**Choice B1** — keep doubled: team takes 4% on cancel, partner takes 0.8% (capped at 2 × 0.4%). LP ends with 6% retention (rather than V11's 10% retention). **This is opinionated; cancel becomes more punitive for the protocol's LP take.**

**Choice B2** — split ONCE on the 10% retention, not the full premium: at cancel, compute the protocol-fee cut on the `cancellation_fee = 0.1 * premium` (the actual retention), not on the original premium. So team gets `0.1 * premium * 200 / 10_000 = 0.002 * premium = 0.2 ADA on 100 ADA premium`. Partner @ 20% gets `0.04 ADA`. LP keeps `0.1 * premium - 0.002 * premium = 0.098 * premium = 9.8 ADA`. The total fee on cancel matches the Underwrite-style ratio applied to the smaller cancel-retention base.

| Phase (B2) | Pool delta (lovelace) | Pool delta (total_liquidity) | Team cumulative | Partner cumulative |
|---|---|---|---|---|
| Underwrite | + 98 | + 98 | + 2 | + 0 (solo) |
| Cancel | - 90 (refund) - 0.2 (V12 B2 cancel cut) = -90.2 | - 90 (refund) - 0.2 (V12 B2 cancel cut) = -90.2 | + 0.2 (extra) | + 0 |
| **Net** | **+ 7.8** | **+ 7.8** | **+ 2.2** | **+ 0** |

LP keeps `7.8 ADA` (compared to V11's `8 ADA` which was the same 10% retention minus the phantom 2%; the V12 visibility shifts the 2% out of phantom and into the team output). Team takes a small extra cut.

**Recommendation: B2** — split applied to the cancel-fee retention (`cancellation_fee_bps * premium / 10_000 = 0.1 * premium`), not to the original premium. Rationale:

1. **Economic intent.** The 2% protocol fee on Underwrite is "team's cut of the user signing up." The cancel is an unwinding — the LP keeps a 10% premium retention as compensation for opportunity cost. Charging the same flat-rate 2%-of-PREMIUM cut on cancel doubles the team's take from policies that are cancelled, which is economically odd (you're penalizing cancellation, not pricing it).
2. **Validator simplicity.** B2's cut is computed from a single base — the cancellation_fee, which is already derived in the validator (line 782 of pool.ak via `calculate_refund(policy_datum.premium_paid)`).
3. **LP fairness.** B2 keeps the LP's economic exposure to cancel matched against the V11 expectation (10% retention minus the protocol fee), instead of changing the LP yield curve on cancels.

**B2 spec.** Add to AcceptCancellation branch, AFTER `refund_amount` (line 782) and BEFORE the existing `treasury_donation` check (line 815):

```aiken
// [v12] The cancellation fee retention is the difference between the policy's
// premium_paid and the refund — currently 10% of premium. Apply the same
// 2%/partner split to this retention as Underwrite applies to the full
// premium.
let cancellation_fee = policy_datum.premium_paid - refund_amount

// [v12] Cap check on partner_share_bps from the policy datum (set at
// Underwrite time, immutable for the policy's lifetime).
let partner_share_in_bounds =
  policy_datum.partner_share_bps >= 0 &&
    policy_datum.partner_share_bps <= partner_share_cap_bps

// [v12] Partner-address consistency: nonzero share REQUIRES Some(addr).
let partner_consistency =
  when policy_datum.partner_address is {
    Some(_) -> True
    None -> policy_datum.partner_share_bps == 0
  }

// [v12] Split: team_cut and partner_cut computed against the cancellation
// fee (10% of premium), NOT the full premium. The 2% protocol fee on the
// full premium was already extracted at Underwrite (and routed to team +
// partner there). At cancel, the 2% applies only to the 10% retention so
// the LP yield curve on cancels matches V11 minus the per-event cut.
let (team_cut, partner_cut) =
  calculate_protocol_fee_split(
    cancellation_fee,
    datum.protocol_fee_bps,
    policy_datum.partner_share_bps,
  )

// [v12 / D7] Min-utxo floor on the cancel-path team output. Same
// submitter-pad semantics as Underwrite (§3.8): when the cancel cut is
// below 2 ADA — which is the typical case because the cancel cut is
// 2% of the 10% retention = 0.2% of premium — the canceller's wallet
// pays the floor-pad. The canceller is the user requesting cancellation
// (the policy holder); they are signing the tx and supplying the wallet
// inputs that bridge the floor gap. The POOL does NOT subsidise (its
// value invariant is `- refund - team_cut - partner_cut` based on the
// percentage-calculated cuts, not the floored amounts) and the INSURED's
// refund (the 90% returned to them) is NOT touched by the pad either.
let team_required_lovelace =
  if team_cut > min_utxo_lovelace { team_cut } else { min_utxo_lovelace }

// [v12] Team output check. Same shape as Underwrite §3.8 — an output at
// team_address with lovelace >= team_required_lovelace.
let team_output_funded =
  list.any(
    outputs,
    fn(out) {
      out.address == team_address &&
        assets.lovelace_of(out.value) >= team_required_lovelace
    },
  )

// [v12 / D7] Min-utxo floor on the cancel-path partner output. Same
// canceller-pad semantics.
let partner_required_lovelace =
  if partner_cut > min_utxo_lovelace { partner_cut } else { min_utxo_lovelace }

// [v12] Partner output check. Same shape as Underwrite §3.8.
let partner_output_funded =
  when policy_datum.partner_address is {
    Some(addr) ->
      list.any(
        outputs,
        fn(out) {
          out.address == addr &&
            assets.lovelace_of(out.value) >= partner_required_lovelace
        },
      )
    None -> True
  }
```

**Cancel-path floor math walkthrough.** For a 100-ADA cancelled solo policy (no partner):

- The 10% retention is `cancellation_fee = 10 ADA`.
- `team_cut = 0.02 * 10 = 0.2 ADA` (well below the 2-ADA floor).
- `team_required_lovelace = 2 ADA` → canceller pays an extra `1.8 ADA` from their wallet to satisfy the floor.
- Pool's lovelace and `total_liquidity` both still decrease by exactly `refund + team_cut + partner_cut = 90.0 + 0.2 + 0 = 90.2 ADA` (percentage-calculated, NOT floored).
- LP keeps `9.8 ADA` of the cancel-fee retention in the pool (10 ADA retention − 0.2 ADA team cut).

For a 100-ADA cancelled policy with partner at 20% cap:

- `team_cut = 0.16 ADA`, `partner_cut = 0.04 ADA` (both below floor).
- Canceller pays `team_pad = 1.84 ADA` + `partner_pad = 1.96 ADA` = `3.8 ADA` total subsidy.
- Pool decreases by exactly `90 + 0.16 + 0.04 = 90.2 ADA`, identical to the solo case.

The pool's economic delta on cancel is constant w.r.t. the partner split (LP yield is shielded from partner routing); the canceller's wallet absorbs the floor padding entirely.

And modify the value_ok check (line 791-792). The pool now also funds the team_cut and partner_cut (cumulatively `floor(cancellation_fee * 200 / 10_000) = 0.002 * premium` on 100-ADA premium, ~0.2 ADA). So the pool continuation is:

```aiken
// [v12] Pool's value decreases by refund_amount AND the team+partner cuts
// extracted from the cancellation fee retention. The refund goes to the
// insured; team_cut/partner_cut go to their respective outputs.
let value_ok =
  assets.lovelace_of(cont_output.value) ==
    assets.lovelace_of(own_value) - refund_amount - team_cut - partner_cut
```

And update the datum_ok check (line 796-797). `total_liquidity` decreases by `refund + team_cut + partner_cut` (since LP's claim on the pool decreases by exactly the lovelace flowing out):

```aiken
// [v12] total_liquidity decreases by (refund + team_cut + partner_cut)
// since all three flow out of the pool. active_coverage drop unchanged.
let datum_ok =
  new_datum.total_liquidity ==
    datum.total_liquidity - refund_amount - team_cut - partner_cut &&
    new_datum.active_coverage ==
      datum.active_coverage - policy_datum.coverage_amount
```

And the existing `treasury_donation` (line 815-821) is now computed against `cancellation_fee` rather than `premium_paid * 1_000 / 10_000` — wait, those are the same numerically. Line 816 has `let required_donation = policy_datum.premium_paid * 1_000 / 10_000 * treasury_share_bps / 10_000` which is equivalent to `cancellation_fee * treasury_share_bps / 10_000`. Re-express for clarity:

```aiken
// [v12] Treasury cut is 25% of the protocol-fee cut on the cancellation
// fee retention. Re-expressed against `cancellation_fee` for clarity
// (numerically identical to V11's premium-based form, since the
// cancellation_fee IS premium * cancellation_fee_bps / 10_000).
let required_donation =
  cancellation_fee * datum.protocol_fee_bps / 10_000 * treasury_share_bps / 10_000
let donation_ok =
  when treasury_donation is {
    Some(amt) -> amt >= required_donation
    None -> required_donation == 0
  }
```

Final AcceptCancellation conjunction:

```aiken
policy_targets_this_pool && bounds_ok && value_ok && datum_ok && immutable_ok && remains_non_negative && donation_ok && partner_share_in_bounds && partner_consistency && team_output_funded && partner_output_funded
```

### 3.10 `pool.ak` BatchUnderwrite branch diff (full design)

**D10 scope decision.** Per operator decision D10, BatchUnderwrite is **IN SCOPE for V12** — both on-chain validator and off-chain build path. UI wiring is deferred (the dApp's v0 BuyPanel doesn't exercise BatchUnderwrite — operator-only path via auto-claim / batch tools), but the validator + backend must be correct so the UI can wire later without re-deploying.

This is the longest and most security-critical addition to the V12 diff. The auditor's primary focus per the cover letter.

#### 3.10.1 Existing BatchUnderwrite branch (lines 567-656 of `pool.ak`, quoted verbatim)

```aiken
// -----------------------------------------------------------------------
// BATCH UNDERWRITE: Create N policies in a single transaction
// Same logic as Underwrite but with aggregate totals.
// -----------------------------------------------------------------------
BatchUnderwrite { total_coverage, total_premium } -> {
  expect Some(cont_output) = pool_output

  // 1. Parse the new pool datum
  expect InlineDatum(raw_new_datum) = cont_output.datum
  expect new_datum: PoolDatum = raw_new_datum

  // [FIX A-024] Same positivity guard as Underwrite. Without this,
  // a BatchUnderwrite with `total_coverage < 0` would shrink the
  // pool's active_coverage and corrupt accounting.
  let coverage_positive = total_coverage > 0
  let premium_positive = total_premium > 0

  // 2. Verify premium is adequate (use aggregate amounts)
  let premium_ok = is_premium_adequate(total_premium, total_coverage)

  // 3. Verify pool can cover the total coverage
  let can_cover =
    can_underwrite(
      datum.total_liquidity,
      datum.active_coverage,
      total_coverage,
    )

  // 4. Net premium after protocol fee
  let net = net_premium(total_premium, datum.protocol_fee_bps)

  // 5. Verify datum update (same math, aggregate amounts)
  let datum_ok =
    verify_underwrite_datum(
      datum.total_liquidity,
      datum.active_coverage,
      new_datum.total_liquidity,
      new_datum.active_coverage,
      net,
      total_coverage,
    )

  // 6. Verify immutable fields preserved
  let immutable_ok =
    new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft && new_datum.lp_supply == datum.lp_supply

  // 7. [FIX A-007] Pool value must EQUAL old + total_premium exactly.
  let value_ok =
    assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + total_premium

  // 8. [FIX A-004] BatchUnderwrite must create policy outputs that
  // collectively match the redeemer's totals. We verify the SUM of
  // coverages across all policy outputs at any script address that
  // bind to this pool equals total_coverage, and likewise for premium.
  let own_pool_hash =
    when self_input.output.address.payment_credential is {
      Script(h) -> h
      _ -> #""
    }
  let batch_policies_funded =
    batch_policies_match_totals(
      outputs,
      own_pool_hash,
      datum.pool_nft,
      policy_script_hash,
      validity_range,
      total_coverage,
      total_premium,
    )

  // 9. [FIX A-021] Aggregate treasury cut = floor(total_premium *
  // protocol_fee_bps * treasury_share_bps / 1e8). Aggregating in one
  // shot (rather than summing per-policy cuts) matches the off-chain
  // builder's single-donation field; per-policy cuts would re-introduce
  // a multi-claim double-satisfaction shape and waste min-fee bytes.
  let required_donation =
    calculate_treasury_cut(
      total_premium,
      datum.protocol_fee_bps,
      treasury_share_bps,
    )
  let donation_ok =
    when treasury_donation is {
      Some(amt) -> amt >= required_donation
      None -> required_donation == 0
    }

  coverage_positive && premium_positive && premium_ok && can_cover && datum_ok && immutable_ok && value_ok && batch_policies_funded && donation_ok
}
```

#### 3.10.2 V12 design decisions for BatchUnderwrite

The four operator-flagged sub-questions resolved with their recommendations adopted:

**(1) Per-policy floor vs aggregate floor.** **Per-policy floor.** For each policy in the batch, `team_cut_i_required = max(min_utxo_lovelace, team_cut_i)` is computed individually. The team output's required lovelace is `sum_i(team_cut_i_required)`. Rationale: per-policy floor keeps each policy's submitter-subsidy math identical to a solo Underwrite — a user who batches 5 small policies sees the same per-policy floor pad as if they had submitted 5 separate Underwrite txs. Aggregate-then-floor would let a batch of 5 policies with `team_cut_i = 1.6 ADA` each (sum = 8 ADA, above floor) avoid all floor padding — saving the submitter ~2 ADA but creating inconsistent solo-vs-batch economics. The per-policy floor convention is what the operator-blessed D10 says explicitly.

**(2) Per-partner output consolidation.** **Validator accepts both (one-per-policy OR one-aggregated-per-partner)** — the validator's check is on the sum of lovelace routed to each unique partner address being `>= sum_i(partner_cut_i_required for policies with that partner_address)`. The tx builder can emit either form. Rationale: many batch-builder integrators (e.g. Strike's referral code routing 100% of partners through the integrator's single address) will naturally produce a single aggregated partner output per unique partner. Forcing one-output-per-policy would waste min-utxo bytes and complicate the integrator's tx-builder. The validator's `list.any` over outputs with a `>= sum` check already handles aggregated outputs natively.

**(3) Single team output for entire batch.** **Validator accepts a SINGLE aggregated team output ≥ sum of per-policy floored team cuts.** The validator does NOT require N team outputs; it requires ONE. (It does not reject N either, but the natural off-chain shape is one team output for the batch.) Rationale: team_address is global. There's only one team. Splitting into N outputs would waste 28+ bytes of CBOR per output (the team address re-encoded N times) and N × 2-ADA-floor padding overhead.

**(4) Mixed partner / no-partner batches.** **Per-policy enforcement.** For each policy:
- if `partner_address == Some(addr)`: contribute `partner_cut_i_required = max(min_utxo, partner_cut_i)` to that address's aggregate
- if `partner_address == None`: contribute zero (and validator rejects if `partner_share_bps > 0` per the standard partner consistency check)

So a batch of 5 policies with [partner_X, partner_X, None, partner_Y, None] must emit: one team output ≥ sum of 5 floored team_cuts + one partner_X output ≥ sum of 2 floored partner_cut_X + one partner_Y output ≥ 1 floored partner_cut_Y. Three required outputs total (or more — splits permitted).

#### 3.10.3 Helper signatures and refactor plan

The Wave 2 agent extends `batch_policies_match_totals` (lines 84-149 of `pool.ak`) to also walk per-policy fee data. Recommended return type:

```aiken
type BatchFeeTotals {
  cov_sum: Int,
  prem_sum: Int,
  funded_ok: Bool,
  team_total: Int,              // sum of per-policy floored team_cut_i
  partner_totals: List<(Address, Int)>,  // (partner_address, sum of floored cuts)
  shares_ok: Bool,              // True iff all policies pass partner_share_bps in [0, cap] AND consistency
}

fn batch_policies_match_totals_v12(
  outputs: List<Output>,
  own_pool_hash: ByteArray,
  own_pool_nft: ByteArray,
  policy_script_hash: ByteArray,
  validity_range: ValidityRange,
  total_coverage: Int,
  total_premium: Int,
  protocol_fee_bps: Int,
) -> BatchFeeTotals
```

The Aiken stdlib lacks a `Map<Address, Int>` constructor, so the partner aggregation is done via an `List<(Address, Int)>` accumulator: for each policy with `partner_address = Some(addr)`, look up `addr` in the accumulator and either bump its existing value or append a new entry. Aiken pattern:

```aiken
fn accumulate_partner(
  acc: List<(Address, Int)>,
  addr: Address,
  amt: Int,
) -> List<(Address, Int)> {
  when list.find(acc, fn(pair) { pair.1st == addr }) is {
    Some(_) ->
      list.map(
        acc,
        fn(pair) {
          if pair.1st == addr {
            (addr, pair.2nd + amt)
          } else {
            pair
          }
        },
      )
    None -> list.push(acc, (addr, amt))
  }
}
```

(Wave 2 agent may use `list.foldl` with an alternate pattern if more idiomatic in current Aiken; the above is illustrative. Note: the address-equality check on `pair.1st == addr` is correct because `Address` is a structural record — Aiken's equality is structural on records.)

#### 3.10.4 V12 BatchUnderwrite branch (full Aiken diff)

The replacement BatchUnderwrite branch:

```aiken
// -----------------------------------------------------------------------
// [v12] BATCH UNDERWRITE: Create N policies in a single transaction
// Same logic as Underwrite but with per-policy fee aggregation across
// the batch. Each policy in the batch carries its own (partner_address,
// partner_share_bps) in its PolicyDatum; the validator aggregates the
// per-policy floored team and partner cuts into a per-address required
// sum, then checks the tx outputs contain at least one output to each
// required address with value >= that address's required sum.
// -----------------------------------------------------------------------
BatchUnderwrite { total_coverage, total_premium } -> {
  expect Some(cont_output) = pool_output

  // 1. Parse the new pool datum
  expect InlineDatum(raw_new_datum) = cont_output.datum
  expect new_datum: PoolDatum = raw_new_datum

  // [FIX A-024] Same positivity guard as Underwrite.
  let coverage_positive = total_coverage > 0
  let premium_positive = total_premium > 0

  // 2. Verify premium is adequate (use aggregate amounts)
  let premium_ok = is_premium_adequate(total_premium, total_coverage)

  // 3. Verify pool can cover the total coverage
  let can_cover =
    can_underwrite(
      datum.total_liquidity,
      datum.active_coverage,
      total_coverage,
    )

  // 4. Verify immutable fields preserved
  let immutable_ok =
    new_datum.lp_token_policy == datum.lp_token_policy && new_datum.protocol_fee_bps == datum.protocol_fee_bps && new_datum.pool_nft == datum.pool_nft && new_datum.lp_supply == datum.lp_supply

  // 5. Walk policy outputs, aggregating per-policy team_cut and
  // partner_cut totals (each floored to min_utxo individually), and
  // verifying per-policy partner_share_bps invariants.
  let own_pool_hash =
    when self_input.output.address.payment_credential is {
      Script(h) -> h
      _ -> #""
    }
  let batch_totals =
    batch_policies_match_totals_v12(
      outputs,
      own_pool_hash,
      datum.pool_nft,
      policy_script_hash,
      validity_range,
      total_coverage,
      total_premium,
      datum.protocol_fee_bps,
    )

  // 6. [v12] Per-policy net_premium sum, NOT a single net_premium on the
  // aggregate. Per-policy floor-rounding of partner_cut would otherwise
  // drift against an aggregate net_premium calc — Wave 2 agent must
  // compute per-policy and sum so the value_ok check is exact.
  //
  // NOTE: With the V12 fee-split convention (partner_cut floors, team_cut
  // derives by subtraction so team+partner == total_fee), per-policy
  // net_premium_i = premium_i - team_cut_i - partner_cut_i is exact
  // (no per-policy drift). The sum across all policies equals
  // sum(premium_i) - sum(team_cut_i) - sum(partner_cut_i) =
  // total_premium - sum(team_cut_i) - sum(partner_cut_i). The accumulator
  // in `batch_policies_match_totals_v12` returns these sums; we re-derive
  // total_net here for the value_ok and datum_ok checks.
  let total_net =
    total_premium - batch_totals.team_total - sum_partner_cuts(
      batch_totals.partner_totals,
    )

  // IMPORTANT: `team_total` and `partner_totals` above are the FLOORED
  // (min-utxo-padded) sums — used for the per-address output checks.
  // For the pool's value-equality invariant we need the UNFLOORED
  // (percentage-calculated) sums, because the pool's value reduction is
  // by the percentage cuts only; the floor pads come from the submitter,
  // not the pool. The Wave 2 agent threads BOTH sums through:
  //   team_total_floored        - for the team_output_funded check
  //   team_total_unfloored      - for value_ok and total_net
  //   partner_totals_floored    - for partner_outputs_funded check
  //   partner_totals_unfloored  - for value_ok and total_net
  // (The accumulator returns 4 fields; spec above abbreviated for brevity.)

  // 7. Verify datum update with the per-policy net premium sum
  let datum_ok =
    verify_underwrite_datum(
      datum.total_liquidity,
      datum.active_coverage,
      new_datum.total_liquidity,
      new_datum.active_coverage,
      total_net,
      total_coverage,
    )

  // 8. [v12] Pool value equality — grow by total_net, NOT by total_premium.
  // The team and partner cuts (percentage-calculated, not floored) are
  // routed to the team/partner outputs. The 2% premium-fee delta exits
  // the pool; floor pads come from the submitter and never touch the
  // pool value invariant.
  let value_ok =
    assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + total_net

  // 9. [v12] Funded check from `batch_totals`: coverage sum and premium sum
  // match; every policy output is at the canonical policy script + carries
  // >= its coverage in lovelace.
  let batch_policies_funded = batch_totals.funded_ok

  // 10. [v12] Per-policy partner_share_bps invariants (cap, consistency,
  // non-negativity) folded into `batch_totals.shares_ok` by the walker.
  let shares_ok = batch_totals.shares_ok

  // 11. [v12] Team output check on the aggregated sum (single team output
  // ≥ sum of per-policy floored team cuts; or N team outputs whose lovelace
  // collectively reaches the sum — validator allows either, but `list.any`
  // with a `>=` check accepts both shapes naturally if the tx emits one
  // aggregated output, which is the off-chain default).
  let team_output_funded =
    list.any(
      outputs,
      fn(out) {
        out.address == team_address &&
          assets.lovelace_of(out.value) >= batch_totals.team_total
      },
    )

  // 12. [v12] Partner output check: for each unique partner_address in the
  // accumulator, an output at that address with value ≥ its aggregated cut.
  // Aggregated form (one output per unique partner) is the natural builder
  // shape; validator accepts split outputs too (would require sum-over-
  // outputs match rather than list.any). Wave 2 agent's call whether to
  // use sum-or-any; `list.any` with a `>=` check accepts the aggregated
  // shape and would reject a split-across-N shape. **Recommended:** use
  // `list.any` (aggregated mandatory). Operator decision deferred to Wave
  // 2; both options documented.
  let partner_outputs_funded =
    list.all(
      batch_totals.partner_totals,
      fn(entry) {
        let (addr, cut_sum) = entry
        list.any(
          outputs,
          fn(out) {
            out.address == addr && assets.lovelace_of(out.value) >= cut_sum
          },
        )
      },
    )

  // 13. [FIX A-021] Aggregate treasury cut against total_premium (unchanged
  // numerically from V11; the cut already represents the protocol fee × the
  // treasury share, both in bps, multiplied against the FULL premium).
  let required_donation =
    calculate_treasury_cut(
      total_premium,
      datum.protocol_fee_bps,
      treasury_share_bps,
    )
  let donation_ok =
    when treasury_donation is {
      Some(amt) -> amt >= required_donation
      None -> required_donation == 0
    }

  coverage_positive && premium_positive && premium_ok && can_cover && datum_ok && immutable_ok && value_ok && batch_policies_funded && shares_ok && team_output_funded && partner_outputs_funded && donation_ok
}
```

A small helper `sum_partner_cuts` is used above. It returns the sum of all aggregated partner cuts (used for `total_net` derivation):

```aiken
fn sum_partner_cuts(entries: List<(Address, Int)>) -> Int {
  list.foldl(entries, 0, fn(entry, acc) { acc + entry.2nd })
}
```

#### 3.10.5 Validator-level one-line invariant

The BatchUnderwrite branch's team-output aggregation invariant, stated as a single line:

> **Exactly one or more outputs at `team_address` exist in the tx, whose lovelace sum is ≥ `Σ_i max(min_utxo_lovelace, floor(premium_i × protocol_fee_bps × (10_000 − partner_share_bps_i) / 100_000_000))` summed over all policy outputs in the batch.**

In practice, the validator implementation uses a `list.any` with `>=` check against a single aggregated output (the off-chain builder always emits one team output per batch). Both shapes pass — the validator accepts a single output ≥ sum and accepts N outputs whose total ≥ sum, though only the single-output shape is exercised in practice.

#### 3.10.6 Pseudocode summary (auditor-readable)

```
for each policy_output_i in tx_outputs where output is at policy_script_hash:
  load PolicyDatum from output
  enforce: partner_share_bps_i in [0, partner_share_cap_bps]
  enforce: partner_address_i is None implies partner_share_bps_i == 0
  compute team_cut_i, partner_cut_i = calculate_protocol_fee_split(premium_i, fee_bps, partner_share_bps_i)
  team_total += max(min_utxo, team_cut_i)
  if partner_address_i is Some(addr):
    partner_totals[addr] += max(min_utxo, partner_cut_i)
  cov_sum += coverage_amount_i
  prem_sum += premium_paid_i

enforce: cov_sum == total_coverage
enforce: prem_sum == total_premium

enforce: exists output at team_address with lovelace >= team_total
for each (addr, cut_sum) in partner_totals.entries:
  enforce: exists output at addr with lovelace >= cut_sum

enforce: pool_continuation.lovelace == own_value.lovelace + (total_premium - Σ team_cut_i - Σ partner_cut_i)
  (NB: percentage-calculated cuts, NOT floored — pool's value invariant is exogenous to the floor pads)

enforce: new_datum.total_liquidity == old.total_liquidity + (total_premium - Σ team_cut_i - Σ partner_cut_i)
enforce: new_datum.active_coverage == old.active_coverage + total_coverage
enforce: treasury_donation >= calculate_treasury_cut(total_premium, fee_bps, treasury_share_bps)
```

#### 3.10.7 Test cases (positive + negative)

Replaces the 4 BatchUnderwrite test stubs in §10.4 with the following expanded test set. All TDD-first:

**Positive cases:**

1. `batch_underwrite_three_solo_policies_aggregates_team_output` — 3 policies, premiums 100 ADA each, no partners. Single team output present with `>= 3 × 2 ADA = 6 ADA`. No partner outputs. Pool grows by `3 × 98 = 294 ADA`.
2. `batch_underwrite_three_policies_same_partner_consolidated` — 3 policies, all `partner_address = Some(addr_X)`, all `partner_share_bps = 2000`. Single team output ≥ `3 × 1.6 = 4.8 ADA` (above floor) and single partner_X output `≥ 3 × max(2, 0.4) = 6 ADA` (floor pad applied per-policy: each policy's partner cut floors to 2 ADA, sum = 6 ADA).
3. `batch_underwrite_three_policies_distinct_partners` — 3 policies with `partner_address` = Some(addr_X), Some(addr_Y), Some(addr_Z) and `partner_share_bps = 2000` each. Single team output ≥ 4.8 ADA + 3 partner outputs each ≥ 2 ADA (floor).
4. `batch_underwrite_mixed_partner_and_no_partner` — 5 policies: 2 with `partner_X` @ 2000 bps, 1 solo, 1 with `partner_Y` @ 1000 bps, 1 solo. Single team output ≥ sum of 5 floored team cuts. Two partner outputs (one for X aggregating 2 cuts, one for Y carrying 1 cut). All floored individually per-policy.
5. `batch_underwrite_large_batch_with_no_floor_padding` — 5 policies, premiums 500 ADA each, all solo. team_cut_i = 10 ADA each (well above floor). team output ≥ 50 ADA. No floor pad anywhere.

**Negative cases (validator must reject):**

6. `batch_underwrite_fails_when_team_output_short_by_one_lovelace` — team output present at team_address but lovelace == required − 1. Reject.
7. `batch_underwrite_fails_when_team_output_at_wrong_address` — output present at a different address with the right lovelace; no output at team_address. Reject.
8. `batch_underwrite_fails_when_partner_output_missing_entirely` — one policy has `partner_address = Some(addr_X)` but no output at addr_X in tx. Reject.
9. `batch_underwrite_fails_when_partner_share_exceeds_cap_in_any_policy` — 4 policies fine, 1 has `partner_share_bps = 2001`. Reject (shares_ok = False, fails the whole batch).
10. `batch_underwrite_fails_when_pool_value_off_by_floor_pad` — the off-chain builder mis-accounts and reduces the pool by the floored cut sum (instead of the unfloored cut sum). Pool continuation value is short. Reject.
11. `batch_underwrite_fails_when_pool_value_inflated_by_phantom_2pct` — a V11-shape build path tries to grow the pool by total_premium instead of total_net. Reject.
12. `batch_underwrite_fails_when_per_policy_floor_drift_attempted` — attacker submits a batch where they compute team_total as `max(min_utxo, sum_team_cuts)` (aggregate-then-floor) instead of `sum(max(min_utxo, team_cut_i))` (per-policy-then-sum). Validator rejects because the per-policy floor is what's enforced.
13. `batch_underwrite_fails_when_partner_address_aggregated_short` — 3 policies same partner address, each partner_cut_i = 5 ADA (above floor). Builder emits ONE consolidated partner output but with only 10 ADA instead of 15. Reject.

#### 3.10.8 Off-chain wiring for BatchUnderwrite (Wave 3 — V12-in-scope, not deferred)

Per D10, the off-chain `api/policies.py::build_batch_underwrite_tx` must be V12-correct. The function builds the BatchUnderwrite tx for a list of `(coverage_i, premium_i, partner_address_i, partner_share_bps_i)` policies and a shared submitter wallet.

Logic:

```python
def add_batch_protocol_fee_outputs(
    builder: pyc.TransactionBuilder,
    *,
    policies: list[tuple[int, int, Optional[pyc.Address], int]],
    protocol_fee_bps: int,
    network: str = AEGIS_NETWORK,
) -> None:
    """Append the aggregated team output and per-unique-partner aggregated
    outputs to the tx builder for a BatchUnderwrite tx.

    Per D10 / §3.10:
      * Per-policy floor applied individually (each policy's cut is floored
        to min_utxo BEFORE summing).
      * Single team output for the entire batch (sum of per-policy floored
        team cuts).
      * One output per unique partner_address (sum of per-policy floored
        partner cuts targeting that address).
    """
    team_address = resolve_team_address(network)
    team_total = 0
    partner_totals: dict[bytes, int] = {}   # keyed by partner_address bytes
    partner_addr_lookup: dict[bytes, pyc.Address] = {}

    for coverage, premium, partner_addr, partner_share_bps in policies:
        team_cut, partner_cut = calculate_protocol_fee_split(
            premium, protocol_fee_bps, partner_share_bps,
        )
        team_total += max(MIN_UTXO_LOVELACE, team_cut)
        if partner_addr is not None:
            key = bytes(partner_addr.to_primitive())  # stable key
            partner_addr_lookup[key] = partner_addr
            partner_totals[key] = partner_totals.get(key, 0) + max(
                MIN_UTXO_LOVELACE, partner_cut,
            )

    # Single team output
    builder.add_output(
        pyc.TransactionOutput(address=team_address, amount=team_total)
    )

    # One output per unique partner address
    for key, cut_sum in partner_totals.items():
        builder.add_output(
            pyc.TransactionOutput(
                address=partner_addr_lookup[key],
                amount=cut_sum,
            )
        )
```

**Pytest cases for the off-chain builder (Wave 3):**

1. `test_batch_fee_outputs_three_solo_policies` — emits 1 team output ≥ 6 ADA.
2. `test_batch_fee_outputs_three_same_partner_consolidated` — emits 1 team + 1 partner output.
3. `test_batch_fee_outputs_three_distinct_partners` — emits 1 team + 3 partner outputs.
4. `test_batch_fee_outputs_mixed_partner_and_solo` — emits 1 team + 2 partner outputs (one per unique non-None partner).
5. `test_batch_fee_outputs_per_policy_floor_matches_validator` — explicit assertion: a 5-policy batch with `team_cut_i = 1.6 ADA` each produces a 10-ADA team output (5 × 2 ADA floor each), NOT an 8-ADA output (sum-then-floor).
6. `test_batch_fee_outputs_rejects_partner_share_above_cap_preflight` — at least one policy with `partner_share_bps = 2001` → builder raises ValueError before submit.

#### 3.10.9 Operator-visible economics for BatchUnderwrite

A 5-policy batch with 2 partners (3 solo + 1 partner_X @ 20% + 1 partner_Y @ 20%), all 100-ADA premiums:

| Policy | premium | partner_address | partner_share_bps | team_cut (raw) | team_cut (floored) | partner_cut (raw) | partner_cut (floored) |
|---|---|---|---|---|---|---|---|
| 1 | 100 ADA | None | 0 | 2 ADA | **2 ADA** | 0 | n/a |
| 2 | 100 ADA | None | 0 | 2 ADA | **2 ADA** | 0 | n/a |
| 3 | 100 ADA | None | 0 | 2 ADA | **2 ADA** | 0 | n/a |
| 4 | 100 ADA | Some(X) | 2000 | 1.6 ADA | **2 ADA** | 0.4 ADA | **2 ADA** |
| 5 | 100 ADA | Some(Y) | 2000 | 1.6 ADA | **2 ADA** | 0.4 ADA | **2 ADA** |

Required outputs (validator enforces):

| Address | Required lovelace |
|---|---|
| `team_address` | `2 + 2 + 2 + 2 + 2 = 10 ADA` (sum of floored team cuts) |
| `partner_X` | `2 ADA` (single policy's floored partner cut) |
| `partner_Y` | `2 ADA` (single policy's floored partner cut) |

Pool growth (percentage-calculated, no floor):

- `total_premium = 5 × 100 = 500 ADA`
- `Σ team_cut_i = 2 + 2 + 2 + 1.6 + 1.6 = 9.2 ADA`
- `Σ partner_cut_i = 0 + 0 + 0 + 0.4 + 0.4 = 0.8 ADA`
- `total_net = 500 − 9.2 − 0.8 = 490 ADA`
- Pool's lovelace grows by `+ 490 ADA` and `total_liquidity` grows by `+ 490 ADA`.

Submitter cost (assuming submitter is also the policy creator pool-wide):

- Premium: `500 ADA`
- Team floor pad: `10 − 9.2 = 0.8 ADA`
- Partner floor pads: `(2 − 0.4) + (2 − 0.4) = 3.2 ADA`
- Conway treasury donation: `500 × 0.5% = 2.5 ADA`
- **Total submitter outflow:** `500 + 0.8 + 3.2 + 2.5 = 506.5 ADA`

LP economics: pool grows by `490 ADA` for `500 ADA` of premium inflow + `10 + 4 = 14 ADA` exogenous floor pads from submitter that flow through to team/partners (untouched by the pool).

#### 3.10.10 Operator note on BatchUnderwrite UI deferral

Per D10, the validator + backend ship in V12. UI wiring is deferred. The off-chain `build_batch_underwrite_tx` function is V12-correct and unit-tested. The dApp's BuyPanel does NOT call it in v0; only operator-controlled batch tooling (auto-claim, batch issuance scripts) exercises it. When the UI is wired in V12.1, no validator redeploy or backend change is required — the V12 surface is already complete.

### 3.11 Where ProcessClaim and BatchExpireProcess intentionally do NOT change

**ProcessClaim** (lines 389-466 of `pool.ak`): zero protocol fee. The user receives the full canonical payout (`payout == policy_datum.coverage_amount`, line 433). No team or partner cut on claim. Unchanged from V11. This is by design — the user paid for insurance; the insurance pays out without further deduction.

**Expire / BatchExpireProcess** (lines 661-715 of `pool.ak`): no protocol fee. The expired policy's pre-funded coverage returns to the pool (`policy_utxo_lovelace` flows into the pool, line 706-707). The premium was already extracted at Underwrite (team got their cut, treasury got theirs). On expire the LP keeps the coverage residual + the original `net_premium` retained at Underwrite — same as V11. No new fee.

**Cancel / AcceptCancellation**: see §3.9. The cancel-time cut applies to the cancellation_fee retention only (B2 choice).

The validator hashes still rotate for ProcessClaim and BatchExpireProcess because they share `lib/aegis/types.ak` and `pricing.ak` with the changed branches — the rotation is a side effect of the imported module bytes changing, not a branch-level semantic shift.

---

## 4. Validator Hash Rotation Table

All four hashes rotate. The new values are produced by Wave 2 (Aiken build) and pasted back into this table by the Aiken agent before Wave 3 (off-chain wiring) starts.

| Hash | V11 value (preprod, from `api/chain.py:55,70,82`) | V12 value | Source of truth |
|---|---|---|---|
| `policy_validator` | `8fe45e44339417ad27ca6cd1662d771a0c224fc0052189647321a3f5` | TBD (Wave 2) | `contracts/plutus.json` after `aiken build` |
| `pool_validator` | `41cc5c53a899a9b69d62f2a946c17285203b32f9a373b0eeaf09650f` | TBD (Wave 2) | `contracts/plutus.json` after `aiken build` |
| `lp_token_policy` | `cd8048bf0d926c65a8b9422106aab8ff48c2c1eb24b27c04044ec004` | TBD (Wave 2) | `contracts/plutus.json` after `aiken build` |
| `pool_nft_policy` | (compile-time-derived from the operator's init UTxO; populated by `AEGIS_POOL_NFT_POLICY_ID`) | TBD (Wave 4, after operator mints) | `scripts/init_pool_nft.py` output |

`pool_nft_policy` is special: it is not a hash of a fixed validator but the parameterized hash of `pool_nft.ak` against the operator's chosen init UTxO. So a fresh deploy with a fresh init UTxO gives a fresh `pool_nft_policy`. This is by design — it is the per-deploy uniqueness anchor.

The pool script address bech32 also rotates (it is the `addr_test1...` envelope of the new `pool_validator` hash); Wave 2 emits it alongside the raw hash.

---

## 5. Off-Chain Wiring

### 5.1 Pair identifier convention

V12 introduces a `pair: str` parameter threaded through the resolver, dispatcher, build endpoints, and price endpoint. The canonical value is a **lowercase no-separator symbol pair**: `"adausd"`, `"btcusd"`, `"ethusd"`, `"usdcusd"`, `"usdtusd"`. Rationale:

- URL-safe without escaping (no `/`, no uppercase round-trip ambiguity across browsers).
- Matches the established AegisSelf publisher's `.env` naming convention (`AEGIS_PUBLISHER_BTC_USD_FEED_NFT` etc.).
- Disambiguates from human-readable display strings (`"ADA/USD"`) used in the frontend, which are not safe for env vars or query strings.

The dispatcher's `parse_pair_label` (Section 5.3) accepts case-insensitive variants and the legacy uppercase-with-slash form (`"ADA/USD"`, `"BTC/USD"`) for backwards compatibility, normalizing to the canonical lowercase form. The default when the field is absent or empty is `"adausd"`, preserving V11 behavior unchanged.

### 5.2 `api/chain.py` — new per-pair NFT policy constants

Today `chain.py` declares `AEGIS_SELF_PUBLISHER_NFT_PREPROD/PREVIEW/MAINNET` for the singleton ADA/USD pair (lines 226-237). V12 adds four more per-pair preprod constants and lifts the per-network split to a per-pair-per-network split.

**Diff sketch (Wave 3 agent writes):**

```python
# Per-pair publisher NFT policy ids (preprod). All five one-shot mints under
# the same publisher VKH; quantity: 1 permanent each. Env-overridable so the
# operator can patch a single pair without a code change.
AEGIS_SELF_PUBLISHER_NFT_ADA_USD_PREPROD: str = os.environ.get(
    "AEGIS_SELF_PUBLISHER_NFT_ADA_USD_PREPROD",
    "d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
)
AEGIS_SELF_PUBLISHER_NFT_BTC_USD_PREPROD: str = os.environ.get(
    "AEGIS_SELF_PUBLISHER_NFT_BTC_USD_PREPROD",
    "ae304e27806536dbbc222115c2b543e845f99bd8c7a3a01669f2d7bd",
)
AEGIS_SELF_PUBLISHER_NFT_ETH_USD_PREPROD: str = os.environ.get(
    "AEGIS_SELF_PUBLISHER_NFT_ETH_USD_PREPROD",
    "d80aa1a72a46813b5045e163751076d54551fac4a6f8d720e15807ad",
)
AEGIS_SELF_PUBLISHER_NFT_USDC_USD_PREPROD: str = os.environ.get(
    "AEGIS_SELF_PUBLISHER_NFT_USDC_USD_PREPROD",
    "860faa663d8a3ae3071d61f95464340c0e49c1f47f56db76441df7a0",
)
AEGIS_SELF_PUBLISHER_NFT_USDT_USD_PREPROD: str = os.environ.get(
    "AEGIS_SELF_PUBLISHER_NFT_USDT_USD_PREPROD",
    "a4093bfc7758b86ca1b96df842367bce96cb954650a392020246c0cb",
)
# Preview / mainnet remain empty until a per-network deploy mints them.
# A helper resolve_publisher_nft(pair, network) -> str centralises the lookup.
```

The original `AEGIS_SELF_PUBLISHER_NFT_PREPROD` alias remains pointing at the ADA/USD value for backwards-compat with V11 callers; new code uses the per-pair constants.

Per-pair asset names (`AEGIS_PRICE_FEED_V1`, `AEGIS_PRICE_FEED_BTC_USD_V1`, etc.) are useful for logs and Blockfrost queries but the validator does **not** check them — only policy id. Adding them as a `dict[str, bytes]` constant is recommended for diagnostic clarity but not load-bearing.

### 5.3 `api/oracles/aegis_self.py` — pair-aware resolver

The current `_network_publisher_nft()` (line 58-77) returns one NFT per network; it must become `_network_publisher_nft(pair: str)` returning the right NFT per (pair, network). Same for `find_oracle_utxo` (line 97), `parse_oracle_datum` (line 267), and `resolve_aegis_self_oracle` (line 307).

**Contract for `find_oracle_utxo(context, pair="adausd")`:**

1. Look up the per-pair publisher NFT policy id via `_network_publisher_nft(pair)`. Raises `ValueError` if the pair is unknown or the per-network constant is empty.
2. Query the publisher base address for UTxOs (logic unchanged from V11).
3. Filter for UTxOs carrying a token under the looked-up NFT policy id. (V11's `_has_publisher_nft` helper is reused unchanged — it already takes the target policy as a parameter; just pass the per-pair value.)
4. Pick the freshest by datum key 1 (publish timestamp).
5. Return the UTxO or None.

**Contract for `resolve_aegis_self_oracle(context, pair="adausd", oracle_nft_policy_id=None)`:**

- The `oracle_nft_policy_id` cross-check (line 330-337) now compares against the per-pair canonical NFT, not the global ADA/USD constant. So a BTC-bound policy that surfaces a BTC NFT policy id in `PolicyDatum.oracle_nft` round-trips against the BTC pair lookup.
- The returned `parsed` dict gains a `feed` field reflecting the pair (e.g. `"BTC/USD"` instead of hardcoded `"ADA/USD"`).
- The `pair` parameter is the source of truth for which NFT to look up; `oracle_nft_policy_id` is the integrity cross-check. They must agree.

### 5.4 `api/oracles/dispatcher.py` — thread the pair through

The dispatcher's `resolve_oracle(context, provider, *, oracle_nft=None, network=None, chain_now_ms=None)` (line 160) gains a `pair: str = "adausd"` keyword argument. Only the AegisSelf branch (line 235-247) consumes it; Charli3 and Orcfax ignore the parameter (their feed is implicitly the per-network ADA/USD feed; cross-pair coverage for those providers is out of scope for V12 and tracked as a follow-up).

A new `parse_pair_label(label: Optional[str]) -> str` helper accepts:

| Input | Normalized output |
|---|---|
| `None`, `""`, `"   "` | `"adausd"` (default) |
| `"adausd"`, `"AdaUsd"`, `"ADA/USD"`, `"ada/usd"`, `"ada-usd"`, `"ADA-USD"` | `"adausd"` |
| `"btcusd"`, `"BTC/USD"`, `"btc-usd"` | `"btcusd"` |
| `"ethusd"`, `"ETH/USD"`, `"eth-usd"` | `"ethusd"` |
| `"usdcusd"`, `"USDC/USD"`, `"usdc-usd"` | `"usdcusd"` |
| `"usdtusd"`, `"USDT/USD"`, `"usdt-usd"` | `"usdtusd"` |
| Anything else | `raise ValueError(...)` |

### 5.5 Build endpoints

Three build endpoints accept a new optional `asset: str` body field that maps to the dispatcher's `pair` parameter:

| Endpoint | Source file | New field | Default | Threads to |
|---|---|---|---|---|
| `POST /api/policies/create/build` | `server.py:1258` | `asset: str = "ADA"` | `"ADA"` | `build_create_policy_tx(..., pair=parse_pair_label(asset))` |
| `POST /api/depeg/protect/build` | `server.py:3471` | `asset: str = "USDC"` for depeg | `"USDC"` | same |
| `POST /api/lending/protect-loan/build` | `server.py:3598` | `asset: str = "ADA"` | `"ADA"` | same |

The `BuildCreatePolicyRequest` (`server.py:717`) gains an `asset: str` field with the same description / default contract. The internal `build_create_policy_tx` adds a `pair` keyword argument that:

- Sets `PolicyDatum.oracle_nft` to the per-pair NFT policy id (from `_network_publisher_nft(pair)`).
- Passes `pair` through to the dispatcher at pre-flight resolution time, so the strike comparison uses the right feed.
- Defaults to the V11 behavior when `pair == "adausd"`.

Two notes:

- The user-facing `asset` field accepts `"ADA"`, `"BTC"`, `"ETH"`, `"USDC"`, `"USDT"` (uppercase symbol). The handler normalises it to `<symbol>USD` lowercase before calling `parse_pair_label`. Frontend sends the symbol; backend computes the pair.
- For `/api/depeg/protect/build`, the existing `stablecoin` body field (`"DJED" | "iUSD" | "USDA" | "USDM" | "USDC"`) coexists with the new `asset` field for V12 only — the dispatcher uses `asset` for oracle routing, while `stablecoin` retains its display meaning. Cleanup of the redundant field is tracked as a V12.1 follow-up.

### 5.6 `GET /api/oracle/aegis-self/price?pair=...`

The existing route (`server.py:1579`) gains an optional `pair: str = "adausd"` query param. The handler calls `resolve_aegis_self_oracle(context, pair=pair)` and returns the parsed datum. Backwards compatibility: `GET /api/oracle/aegis-self/price` without `pair` still returns ADA/USD. Adding `?pair=btcusd` returns BTC/USD.

Frontend polling code uses the param to drive per-asset price ticks.

### 5.7 Files NOT changing

- `api/oracles/charli3.py` — Charli3 path is single-pair (ADA/USD); not in V12 scope.
- `api/oracles/orcfax.py` — same.
- `api/policies.py` claim / expire builders — they read `PolicyDatum.oracle_nft` from the consumed policy UTxO and route via the dispatcher; the dispatcher needs the pair to look up the right NFT for the cross-check, so `pair` must be derivable from the consumed datum's `oracle_nft`. A helper `pair_for_nft(oracle_nft: bytes) -> str` (reverse-lookup table over the five canonical NFTs) lives in `oracles/aegis_self.py` and is called by the dispatcher's AegisSelf branch when `pair` is not explicitly supplied. This keeps the claim flow ergonomic — callers do not need to know the pair, only the consumed `oracle_nft`.
- `api/policies.py` `cancel_policy` (the AcceptCancellation builder) DOES change — see §5.9, it must now add team + partner outputs and update its treasury_cut math. Documented here for explicit non-coverage by §5.7 vs §5.9.

### 5.8 `api/chain.py` — team address constant

`api/chain.py` already has the per-network split pattern for `AEGIS_SELF_PUBLISHER_NFT_PREPROD` / `_MAINNET` (line 226-237). Mirror that pattern for the team address.

**Diff against `api/chain.py`** at the same env-loaded constants section:

```python
# Per-network team wallet address that receives the team's share of the 2%
# protocol fee on every Underwrite / BatchUnderwrite / AcceptCancellation tx.
# Mirrors the compile-time `team_address_preprod` / `_mainnet` constants in
# the Aiken `lib/aegis/types.ak` — these env-loaded values must EQUAL the
# bech32 envelopes of those compile-time constants, or off-chain builds will
# emit team outputs the validator rejects.
AEGIS_TEAM_ADDRESS_PREPROD: str = os.environ.get(
    "AEGIS_TEAM_ADDRESS_PREPROD",
    "addr_test1qrph8epfa8dg6wjwmls873g0xllyjnlt3hh08nv9kcrw9ln40ur83k9c87dpxuar3jucqrg0sc54zvzmf53pu6due2eqa5m8d2",
)
AEGIS_TEAM_ADDRESS_MAINNET: str = os.environ.get(
    "AEGIS_TEAM_ADDRESS_MAINNET",
    "addr1q9s6m9d8yedfcf53yhq5j5zsg0s58wpzamwexrxpfelgz2wgk0s9l9fqc93tyc8zu4z7hp9dlska2kew9trdg8nscjcq3sk5s3",
)

def resolve_team_address(network: str = AEGIS_NETWORK) -> pyc.Address:
    """Return the active-network team address as a parsed pycardano Address.

    Tied to the compile-time `team_address` constant in `lib/aegis/types.ak`
    (which is `team_address_preprod` or `_mainnet` depending on the active
    build target). The bech32 envelope here must round-trip through PyCardano
    and decode to the same payment_credential + stake_credential pair that
    the Aiken validator pins.
    """
    if network == "mainnet":
        bech = AEGIS_TEAM_ADDRESS_MAINNET
    else:
        bech = AEGIS_TEAM_ADDRESS_PREPROD
    return pyc.Address.from_primitive(bech)
```

The wave-3 agent verifies (via a startup assertion or a dedicated test) that `pyc.Address.from_primitive(AEGIS_TEAM_ADDRESS_PREPROD).payment_part.payload.hex() == "c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe"` — closing the loop on the compile-time/run-time agreement.

### 5.9 `api/policies.py` — fee-split output construction

Every tx builder that emits Underwrite, BatchUnderwrite, or AcceptCancellation must now add the team + partner outputs. Affected functions in `api/policies.py`:

| Function | Line range | Branch | New outputs |
|---|---|---|---|
| `create_policy` (legacy) | 1100-1525 | Underwrite | team + optional partner |
| `build_create_policy_tx` (non-custodial) | 3099-3450 | Underwrite | team + optional partner |
| `cancel_policy` (legacy) | 2780-3068 | AcceptCancellation | team + optional partner |
| `build_cancel_policy_tx` (non-custodial) | (sibling to `build_create_policy_tx`) | AcceptCancellation | team + optional partner |
| `build_batch_underwrite_tx` (or sibling) | (line ~1551+) | BatchUnderwrite | aggregated team output + per-unique-partner aggregated outputs — V12-in-scope per D10 (see §3.10.8 for the full helper spec and pytest cases) |

**Common helper** (in `api/policies.py` or a new `api/_fees.py` if isolation is preferred):

```python
def calculate_protocol_fee_split(
    premium_lovelace: int,
    protocol_fee_bps: int,
    partner_share_bps: int,
) -> tuple[int, int]:
    """Mirror of the Aiken `pricing.calculate_protocol_fee_split` helper.

    Returns (team_cut_lovelace, partner_cut_lovelace).

    Off-chain rounding MUST match on-chain rounding exactly. The Aiken
    helper applies `floor` on `partner_cut` and derives `team_cut` by
    subtraction; this Python helper does the same.
    """
    total_fee = premium_lovelace * protocol_fee_bps // 10_000
    partner_cut = total_fee * partner_share_bps // 10_000
    team_cut = total_fee - partner_cut
    return team_cut, partner_cut


def add_protocol_fee_outputs(
    builder: pyc.TransactionBuilder,
    *,
    premium_lovelace: int,
    protocol_fee_bps: int,
    partner_address: Optional[pyc.Address],
    partner_share_bps: int,
    network: str = AEGIS_NETWORK,
) -> None:
    """Append the team output (always) and partner output (if applicable)
    to the tx builder. Called by every Underwrite / AcceptCancellation site.

    The team output's lovelace must be EXACTLY team_cut (overshoots are
    allowed by the validator's `>= team_cut` check, but exact matches
    minimize tx size and avoid the wallet-side over-funding tax).
    """
    team_address = resolve_team_address(network)
    team_cut, partner_cut = calculate_protocol_fee_split(
        premium_lovelace, protocol_fee_bps, partner_share_bps,
    )
    if team_cut > 0:
        builder.add_output(
            pyc.TransactionOutput(
                address=team_address,
                amount=team_cut,
            )
        )
    if partner_address is not None and partner_cut > 0:
        # Min-utxo constraint: if partner_cut < MIN_UTXO_LOVELACE (2 ADA),
        # the tx will fail at submit. Validator-rejected pre-flight check:
        if partner_cut < MIN_UTXO_LOVELACE:
            raise ValueError(
                f"Partner cut {partner_cut} < min-utxo {MIN_UTXO_LOVELACE}; "
                f"increase premium or partner_share_bps, or omit partner."
            )
        builder.add_output(
            pyc.TransactionOutput(
                address=partner_address,
                amount=partner_cut,
            )
        )
```

**Min-utxo warning.** At a 100-ADA premium with `partner_share_bps = 2000`, partner_cut = 0.4 ADA, which is BELOW the 2-ADA min-utxo. The builder must reject this with a clear 400 error rather than emitting a tx the chain rejects. **Practical floor**: partner outputs require a premium large enough that `0.02 * partner_share_bps / 10_000 * premium >= 2 ADA`. For partner_share_bps = 2000, that's `0.004 * premium >= 2 ADA` => `premium >= 500 ADA`. Below this floor, the off-chain builder MUST set `partner_share_bps = 0` and route the full 2% to team (or reject the tx).

**Team output min-utxo.** At a 2-ADA premium (the minimum), the team_cut = 0.04 ADA, also below min-utxo. The builder must either (a) round the team output up to 2 ADA (overshoot is validator-accepted), or (b) reject the tx. **Recommended: round up to MIN_UTXO_LOVELACE for the team output and adjust the change accordingly.** This is a small subsidy to small-policy buyers; cleaner than rejecting policies under ~100 ADA premium.

**Build endpoint signature additions.** For `POST /api/policies/create/build` (request schema at `server.py:717`, `BuildCreatePolicyRequest`):

```ts
{
  // ...existing fields,
  asset?: 'ADA' | 'BTC' | 'ETH' | 'USDC' | 'USDT';  // §5.5
  partner_address?: string;     // optional bech32; omit for solo policies. Validated for network match (preprod vs mainnet bech32) and decode-cleanly.
  partner_share_bps?: number;   // optional 0..=2000; default 0. Pre-flight check: rejects >2000 with 400 before chain.
}
```

Same shape for `POST /api/depeg/protect/build`, `POST /api/lending/protect-loan/build`, and the cancel-builder if it accepts new optional fields (it shouldn't — cancel's partner is taken from the consumed PolicyDatum, not from request body).

**Tx total balance check (off-chain).** The wave-3 agent adds a builder-side assertion:

```
sum(inputs) - sum(outputs) - tx_fee - treasury_donation == 0
```

For Underwrite specifically:
```
pool_growth + team_cut + partner_cut + treasury_donation + tx_fee + change
  == premium + coverage + (existing wallet input value)
```

Where:
- `pool_growth = net_premium`
- `team_cut + partner_cut = premium * protocol_fee_bps / 10_000`
- `treasury_donation = premium * protocol_fee_bps * treasury_share_bps / 1e8`

A divergence between this off-chain expectation and the on-chain validator rules is the most common failure mode in v0 (we hit this twice in v6 / v7 — see SECURITY_AUDIT_REPORT.md round 6 build-time diagnostics). The wave-3 agent's balance assertion catches it pre-submit.

**For BatchUnderwrite, the equivalent invariant (per D10 / §3.10.8):**

```
pool_growth = total_premium - Σ team_cut_i - Σ partner_cut_i        (percentage-calculated)
team_output_lovelace >= Σ max(min_utxo, team_cut_i)                  (per-policy floor)
for each unique partner_address P:
  partner_output_lovelace[P] >= Σ_{i: partner_i == P} max(min_utxo, partner_cut_i)
treasury_donation >= total_premium * fee_bps * treasury_share_bps / 1e8
submitter_outflow = total_premium + (Σ floored team cuts - Σ team_cut_i)
                                  + Σ_P [partner_output_lovelace[P] - Σ_{i: partner_i == P} partner_cut_i]
                                  + treasury_donation
                                  + tx_fee
                                  + (any change diff)
```

The submitter's wallet bridges the floor pads. The pool's value invariant uses the percentage-calculated cuts only. The Wave 3 agent's BatchUnderwrite balance test asserts all four equations.

---

## 6. Frontend Changes

### 6.1 BuyPanel asset selector

`frontend/src/components/panels/BuyPanel.tsx` (235 lines today, single-asset ADA-only) gains an asset selector chip row immediately above the Coverage slider. The chip row mirrors the existing Duration chip pattern (`BuyPanel.tsx:163-170`) for visual consistency.

**Component shape (Wave 5 agent writes):**

```tsx
const ASSETS = ['ADA', 'BTC', 'ETH', 'USDC', 'USDT'] as const;
type Asset = typeof ASSETS[number];
const [asset, setAsset] = useState<Asset>('ADA');
// ...
<div className="field">
  <div className="field-label">
    <span>Asset</span>
    <span className="val">{asset}/USD</span>
  </div>
  <div className="chips">
    {ASSETS.map(a => (
      <button
        key={a}
        className={`chip ${asset === a ? 'active' : ''}`}
        onClick={() => setAsset(a)}
        data-testid={`buy-panel-asset-${a.toLowerCase()}`}
      >
        {a}
      </button>
    ))}
  </div>
</div>
```

### 6.2 Per-asset price wiring

The existing `price` and `util` props are sourced from a parent component poll against `/api/oracle/price` (ADA/USD). V12 adds a per-asset poll keyed by the selected asset:

- A new `useAegisSelfPrice(pair)` hook (under `frontend/src/hooks/`) polls `GET /api/oracle/aegis-self/price?pair=<pair>` on a 10 s interval; mirrors the existing `useTokenAnalysis` debounce pattern.
- BuyPanel calls the hook with the selected asset's pair and uses the returned price for `strike = price * (1 - strikePct / 100)`.
- During the brief window between asset toggle and first response, the panel falls back to the previous asset's price with a "loading" subtitle (mirroring the `optimisticPremium` fallback at line 79-82).

### 6.3 Threading `asset` to the build endpoint

`BuildCreatePolicyArgs` (in `frontend/src/api/client.ts:92-99`) gains a new optional field `asset?: 'ADA' | 'BTC' | 'ETH' | 'USDC' | 'USDT'` (default `'ADA'`). The `buildCreate` implementation at line 590 passes it through as the body's `asset` field.

The BuyPanel's `onBuy` callback signature widens from `{ coverage, strike, premium, days }` to `{ coverage, strike, premium, days, asset }`; the parent (`App.tsx`) forwards `asset` to `client.policies.buildCreate(...)`.

### 6.4 Premium quote refetch on asset change

The existing `useEffect` at line 98-115 re-quotes on `(coverage, days)`. V12 leaves the API's premium curve as-is — premium does not change per asset (the curve is `coverage * 0.04 * min(days/7, 5)`, denominated in ADA). The displayed strike value, however, recomputes per asset from the live price.

If the operator decides per-asset premium curves are needed (e.g. higher premium for BTC due to higher volatility), that is a V12.1 backend change — premiumcurve is a backend concern, not a BuyPanel concern.

### 6.5 Partner address handling

**v0 — no partner UI.** `BuyPanel.tsx` makes no UI change for partner fields. The buy flow always passes `partner_address: undefined` and `partner_share_bps: 0` to `client.policies.buildCreate(...)`. Every solo policy gets the full 2% routed to the team_address. This matches the V12 launch shape — partners are not in the dApp yet.

**Post-V12 / V12.1 — `/partners` tab.** The operator has indicated a dedicated `/partners` tab is the eventual home for partner discovery and code redemption (operator-owned UX). The shape of the integration:

- Partners register an address (bech32) and a code (e.g. "AEGIS-ACME-2026") via a manual or self-serve flow.
- Users entering the partner code in BuyPanel (new chip / input above the asset selector) get `partner_address` and `partner_share_bps` auto-populated from a backend lookup.
- The auto-populated values are passed to `buildCreate` exactly as in v0, so the validator/build-endpoint contract is identical.

The partner registry storage, code redemption rules, and UI shape are explicitly **out of V12 scope** (tracked as a V12.1 follow-up).

**Frontend validation invariants** (Wave 5 enforces, even though there is no partner UI in v0 — these protect against future regressions):

- If `partner_share_bps > 0`, `partner_address` MUST be set (and be a valid bech32 for the active network).
- If `partner_share_bps > 2000`, reject pre-flight with a clear error (mirror the backend's 400 response).
- If `partner_share_bps < 0`, reject (defensive).

---

## 7. Env-Var Rotation Table

### 7.1 Railway API (`api/`)

| Env var | V11 value (preprod) | V12 value | Source |
|---|---|---|---|
| `AEGIS_POLICY_SCRIPT_HASH` | `8fe45e44339417ad27ca6cd1662d771a0c224fc0052189647321a3f5` | TBD (Wave 2) | Wave 2 Aiken build output |
| `AEGIS_POLICY_SCRIPT_ADDRESS` | `addr_test1wz87ghjyxw2p0tf8efkdze3dwudqcgj0cqzjrztywvs68aguf3yp5` | TBD (Wave 2) | bech32 envelope of the new policy hash |
| `AEGIS_POOL_SCRIPT_HASH` | `41cc5c53a899a9b69d62f2a946c17285203b32f9a373b0eeaf09650f` | TBD (Wave 2) | Wave 2 Aiken build output |
| `AEGIS_POOL_ADDRESS` | `addr_test1wpquchzn4zv6nd5avte2j3kpw2zjqwejlx3h8v8w4uyk2rccsz7cu` | TBD (Wave 2) | bech32 envelope of the new pool hash |
| `AEGIS_LP_TOKEN_SCRIPT_HASH` | `cd8048bf0d926c65a8b9422106aab8ff48c2c1eb24b27c04044ec004` | TBD (Wave 2) | Wave 2 Aiken build output |
| `AEGIS_POOL_NFT_POLICY_ID` | (current V11 preprod value) | TBD (Wave 4) | Operator mints fresh pool NFT |
| `AEGIS_POOL_NFT_ASSET_NAME` | `AEGIS_POOL_V9` | `AEGIS_POOL_V12` | new asset name for visible V12 signal |
| `AEGIS_POOL_REF_UTXO` | V11 ref UTxO | TBD (Wave 4) | Operator publishes new pool ref script |
| `AEGIS_POLICY_REF_UTXO` | V11 ref UTxO | TBD (Wave 4) | Operator publishes new policy ref script |
| `AEGIS_LP_REF_UTXO` | V11 ref UTxO | TBD (Wave 4) | Operator publishes new LP ref script |
| `AEGIS_POOL_UTXO` (init pool UTxO ref) | V11 init UTxO | TBD (Wave 4) | Operator initialises new pool |
| `AEGIS_SELF_PUBLISHER_NFT_PREPROD` | `d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f` | unchanged (ADA/USD value remains for V11 compat alias) | n/a |
| `AEGIS_SELF_PUBLISHER_NFT_ADA_USD_PREPROD` (new) | n/a | `d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f` | static |
| `AEGIS_SELF_PUBLISHER_NFT_BTC_USD_PREPROD` (new) | n/a | `ae304e27806536dbbc222115c2b543e845f99bd8c7a3a01669f2d7bd` | static |
| `AEGIS_SELF_PUBLISHER_NFT_ETH_USD_PREPROD` (new) | n/a | `d80aa1a72a46813b5045e163751076d54551fac4a6f8d720e15807ad` | static |
| `AEGIS_SELF_PUBLISHER_NFT_USDC_USD_PREPROD` (new) | n/a | `860faa663d8a3ae3071d61f95464340c0e49c1f47f56db76441df7a0` | static |
| `AEGIS_SELF_PUBLISHER_NFT_USDT_USD_PREPROD` (new) | n/a | `a4093bfc7758b86ca1b96df842367bce96cb954650a392020246c0cb` | static |
| `AEGIS_TEAM_ADDRESS_PREPROD` (new) | n/a | `addr_test1qrph8epfa8dg6wjwmls873g0xllyjnlt3hh08nv9kcrw9ln40ur83k9c87dpxuar3jucqrg0sc54zvzmf53pu6due2eqa5m8d2` | operator-confirmed signing wallet; round-trip checked against Aiken `team_address_preprod` constant |
| `AEGIS_TEAM_ADDRESS_MAINNET` (new) | n/a | `addr1q9s6m9d8yedfcf53yhq5j5zsg0s58wpzamwexrxpfelgz2wgk0s9l9fqc93tyc8zu4z7hp9dlska2kew9trdg8nscjcq3sk5s3` | Flux Point Studios team wallet; round-trip checked against Aiken `team_address_mainnet` constant |

**Note on team-address rotation.** The Railway env-loaded `AEGIS_TEAM_ADDRESS_*` values are off-chain mirrors of compile-time-pinned Aiken constants (`team_address_preprod` / `team_address_mainnet` in `lib/aegis/types.ak`). Rotation of the on-chain pin = new validator hash = new deploy. The env var is overridable for local testing but in production MUST match the compile-time constant; the Wave-3 agent ships a startup assertion that fails fast if the env value doesn't round-trip to the pinned VKH bytes. Operators rotating the team address rotate it in `types.ak` first, rebuild via Wave 2, then update the env var.

### 7.2 Vercel frontend (`frontend/`)

| Env var | V11 value | V12 value | Notes |
|---|---|---|---|
| `VITE_POOL_NFT_POLICY_ID` | V11 preprod pool NFT policy id | TBD (Wave 4) | Used by frontend's V11/V12 filter — when set, frontend only shows policies whose `pool_nft_policy_id` matches this value, transparently hiding V11 policies from the user list |
| `VITE_API_BASE_URL` | `https://aegis-api-production-fa61.up.railway.app` | unchanged | n/a |

### 7.3 Publisher (`publisher/.env`)

No changes required for V12 itself — the publisher service already maintains all five canonical NFTs after the Node2 publisher work (per the brief). The publisher's `.env` already has `AEGIS_PRICE_FEED_V1_POLICY_ID`, `AEGIS_PRICE_FEED_BTC_USD_V1_POLICY_ID`, etc.

---

## 8. Deploy Procedure

The operator (human) executes these steps in order. Each step is gated on the previous step's success criterion.

| # | Action | Owner | Success criterion |
|---|---|---|---|
| 1 | Wave 2 lands new Aiken artifacts (`plutus.json`, new `policy_validator` + `pool_validator` hashes, new `lp_token_policy` hash) | Aiken agent (Wave 2) | All Aiken tests green; `aiken build` produces a fresh `plutus.json`; new hashes pasted into Section 4 table |
| 2 | Operator mints the new pool NFT (one-shot via `scripts/init_pool_nft.py` with new init UTxO) | Operator | New `pool_nft_policy` hash recorded; pool NFT visible in operator wallet |
| 3 | Operator publishes the 5 new ref scripts (policy validator, pool validator, lp_token, pool_nft, premium_collector) | Operator | 5 ref UTxOs visible on preprod; `AEGIS_*_REF_UTXO` values recorded |
| 4 | Operator initialises the new pool UTxO with fresh state via `scripts/init_pool.py` | Operator | Pool UTxO at the new pool address visible on preprod carrying the new pool NFT and fresh `PoolDatum` |
| 5 | Update Railway env vars (paste the rotation table values from Section 7.1) — INCLUDING `AEGIS_TEAM_ADDRESS_PREPROD` if not already set to the default bech32 | Operator | Railway dashboard reflects all V12 values; team-address env var verified to round-trip to the pinned VKH (Wave 3 startup assertion) |
| 6 | Redeploy Railway API (`railway up` from `D:/aegis/api`) | Operator | `https://aegis-api-production-fa61.up.railway.app/health` returns 200 with the new pool hash |
| 7 | Update Vercel staging env vars (Section 7.2) | Operator | Vercel dashboard reflects `VITE_POOL_NFT_POLICY_ID` for V12 |
| 8 | Redeploy Vercel staging (`vercel --prod` from `D:/aegis/frontend`) | Operator | `https://aegis-frontend-preprod.vercel.app` loads with the asset selector visible |
| 9 | Smoke-test all 5 assets via the staging URL (build → sign → submit one policy per asset, watch claim flow on at least one) | Operator + Wave 6 e2e harness | 5 tx hashes recorded; preprod chain shows the 5 new policies; oracle prices match exchange medians within tolerance; **for at least one tx, verify the team output is present at `AEGIS_TEAM_ADDRESS_PREPROD` with the expected `2% * premium` lovelace (Cardanoscan check)** |

**No NEW deploy steps for the protocol-fee mechanism.** The team_address is compile-time-pinned in the Aiken sources, so no separate publish step. The env-var rotation (step 5) covers the off-chain mirror. The smoke-test (step 9) gains a Cardanoscan verification of the team output's presence — guards against an off-chain/on-chain mismatch silently sending fees to the wrong place.

The deploy is reversible by repointing the Railway / Vercel env vars back to V11 values; the V11 validator hashes still exist on chain so the rollback path is intact.

---

## 9. V11 Cutover Plan

V12 is a **hard cut, delete-from-UI** cutover. The decision is intentional and irreversible from a UX standpoint (subject to operator override per Section 12).

### 9.1 What happens to V11 policies

Two preprod test wallets currently hold four V11 test policies with a combined premium of ~97 ADA. These policies remain claimable forever via raw CLI against the V11 validator hashes (which stay published on the preprod chain). The CLI escape hatch:

1. Construct the claim tx manually via `cardano-cli` or `pycardano` against the V11 `policy_validator` hash (`8fe45e44339417ad27ca6cd1662d771a0c224fc0052189647321a3f5`).
2. Attach the V11 oracle reference UTxO (V11 publisher NFT under policy `d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f`).
3. Sign + submit. Validator passes; payout flows to insured PKH.

This is documented in the operator runbook at `D:/aegis-runbooks/v11_legacy_claim.md` (created in Wave 6 by the docs agent). No code changes required to keep this path open.

### 9.2 What happens in the dApp

The dApp's `GET /api/policies` endpoint filters by `pool_nft_policy_id == V12_value` (server-side filter; the frontend never sees V11 policies). The relevant change is in `api/server.py` at the policies endpoint — a single `if utxo_pool_nft_policy_hex != CANONICAL_POOL_NFT_POLICY_ID: continue` line filters at the iteration boundary. V11 policies are not "deleted" — they are invisible in the dApp's list view.

The frontend's `MyPolicies` panel renders only V12 policies; the user does not see V11 policies and does not have a self-serve cancel/claim UI for them. Test users are notified out-of-band (Discord) that the CLI escape hatch is the recovery path.

### 9.3 Why hard-cut instead of dual-mode

Dual-mode (showing both V11 and V12 policies in the dApp simultaneously, with the per-policy datum carrying the right pool hash) was considered and rejected:

- Doubles the test surface (every claim / cancel / expire path must work against two pool hashes).
- Confuses the UX (which validator is my policy bound to?).
- Premium adequacy for V11 policies is locked at V11 prices, so a UI showing them alongside V12 policies suggests they can be re-priced — they cannot.
- The premium loss is small (~97 ADA) and the affected wallets are operator-controlled test wallets; no external user impact.

### 9.4 Cancel windows on V11

The two V11 test policies that are still within their 1-hour cancellation window can be cancelled via the CLI escape hatch for a 90% refund. Beyond the window, the only recovery is Claim (if the strike triggers) or Expire (after the expiry timestamp).

---

## 10. Test Plan (TDD-first)

Each subsequent wave writes the relevant test cases BEFORE the implementation. The full test surface:

### 10.1 Aiken (Wave 2)

`contracts/lib/aegis/oracle/aegis_self_tests.ak` (or appended to `aegis_self.ak`):

1. `allowlist_accepts_ada_usd` — first element accepted.
2. `allowlist_accepts_btc_usd` — second element accepted.
3. `allowlist_accepts_eth_usd` — third element accepted.
4. `allowlist_accepts_usdc_usd` — fourth element accepted.
5. `allowlist_accepts_usdt_usd` — fifth element accepted.
6. `allowlist_rejects_non_canonical_nft` — random 28-byte hex must fail.
7. `allowlist_size_is_exactly_five` — guards against accidental drift (e.g., a sixth NFT slipping in unaudited).
8. `find_feed_datum_routes_to_btc_when_btc_nft_supplied` — full UTxO fixture test with two reference inputs (one carrying BTC NFT, one carrying ADA NFT); supply BTC `oracle_nft` and verify the parser picks the BTC UTxO.

A fixture file `contracts/lib/aegis/test_helpers/feed_fixtures.ak` may be added with helper constructors for per-pair UTxO references.

### 10.2 Backend (Wave 3)

`api/tests/oracles/test_aegis_self_per_pair.py`:

1. `test_resolve_aegis_self_oracle_ada_default` — calls `resolve_aegis_self_oracle(context)` with no `pair` argument, asserts ADA/USD UTxO returned.
2. `test_resolve_aegis_self_oracle_btc_explicit` — passes `pair="btcusd"`, asserts BTC UTxO returned.
3. `test_resolve_aegis_self_oracle_unknown_pair_raises` — `pair="ltcusd"` raises `ValueError`.
4. `test_oracle_nft_cross_check_per_pair` — passes BTC NFT bytes as `oracle_nft_policy_id` with `pair="btcusd"`, asserts no `ValueError`; mismatched pair/NFT raises.
5. `test_pair_for_nft_reverse_lookup` — every canonical NFT round-trips to the right pair.

`api/tests/test_dispatcher_pair_threading.py`:

1. `test_dispatcher_aegis_self_routes_per_pair` — mocks `_aegis_self.resolve_aegis_self_oracle`; asserts `pair` is forwarded.
2. `test_dispatcher_charli3_ignores_pair` — Charli3 branch doesn't consume `pair`.
3. `test_parse_pair_label_normalisation` — all variants from Section 5.4 table normalise correctly.

`api/tests/test_build_endpoints_v12.py`:

1. `test_create_build_with_asset_btc_emits_btc_nft_in_datum` — POSTs with `asset="BTC"`, asserts the returned `tx_cbor` decodes to a `PolicyDatum` whose `oracle_nft` matches the BTC canonical policy id.
2. Same for ADA, ETH, USDC, USDT (5 tests total).
3. `test_create_build_with_unknown_asset_returns_400` — `asset="LTC"` returns 400.
4. `test_create_build_without_asset_defaults_to_ada` — V11-compat: body without `asset` field works and pins ADA NFT.

`api/tests/test_aegis_self_price_endpoint.py`:

1. `test_price_endpoint_default_returns_ada` — no `pair` query param returns ADA price.
2. `test_price_endpoint_with_pair_btc_returns_btc` — `?pair=btcusd` returns BTC.
3. Same for ETH, USDC, USDT.

### 10.3 Frontend (Wave 5)

`frontend/tests/components/BuyPanel.test.tsx`:

1. `renders five asset chips with ADA active by default`.
2. `clicking BTC chip flips active state and triggers re-fetch of /api/oracle/aegis-self/price?pair=btcusd`.
3. `onBuy callback fires with asset:"BTC" when BTC is selected`.
4. `premium quote does not refetch when asset changes` (asserts the curve is asset-agnostic).
5. `strike computation reflects per-asset live price`.

`frontend/tests/api/client.test.ts`:

1. `buildCreate posts asset:"ADA" by default`.
2. `buildCreate posts asset:"BTC" when args.asset === "BTC"`.

### 10.4 Aiken — protocol-fee mechanism (Wave 2)

These tests cover §3.5–§3.10. All TDD-first (written before the implementation lands).

`contracts/lib/aegis/pricing.ak` (appended to existing test block):

1. `fee_split_solo_policy_routes_full_fee_to_team` — `partner_share_bps = 0`, assert `team_cut = total_fee`, `partner_cut = 0`.
2. `fee_split_partner_at_max_cap` — `partner_share_bps = 2000`, assert team = 80% of fee, partner = 20%.
3. `fee_split_sum_equals_total_fee_exact` — invariant `team + partner == total_fee` for an arbitrary mid-range partner_share_bps (1337).
4. `fee_split_zero_premium_yields_zero` — both cuts are 0.
5. `fee_split_zero_fee_yields_zero` — both cuts are 0 even with partner_share_bps > 0.
6. `fee_split_partner_share_zero_routes_full_fee_to_team` — distinct from solo: address may be Some(_) but share == 0.

`contracts/lib/aegis/types.ak` (appended):

7. `team_address_preprod_payment_credential_28_bytes` — defensive length pin.
8. `team_address_mainnet_payment_credential_28_bytes` — defensive length pin.
9. `partner_share_cap_bps_is_2000` — constant value pin.

`contracts/validators/pool.ak` Underwrite branch:

10. `underwrite_with_no_partner_routes_full_2pct_to_team` — `partner_address: None`, `partner_share_bps: 0`. Assert team output present at `team_address` with exactly 2% of premium; no partner output required.
11. `underwrite_with_partner_at_max_split` — `partner_share_bps: 2000`. Assert team gets 1.6%, partner gets 0.4%.
12. `underwrite_with_partner_at_0_share` — `partner_address: Some(addr)`, `partner_share_bps: 0`. Assert team gets full 2%, no partner output required.
13. `underwrite_fails_when_partner_share_exceeds_cap` — `partner_share_bps: 2001`, assert validator rejects.
14. `underwrite_fails_when_partner_share_set_but_no_address` — `partner_address: None`, `partner_share_bps: 1000`, assert validator rejects.
15. `underwrite_fails_when_partner_share_negative` — `partner_share_bps: -1`, assert validator rejects.
16. `underwrite_fails_when_team_output_missing` — no output at team_address, assert validator rejects.
17. `underwrite_fails_when_team_output_short` — output at team_address with lovelace < team_cut, assert validator rejects.
18. `underwrite_fails_when_team_output_at_wrong_address` — output at a non-team address (even matching team payment_credential but different stake_credential), assert validator rejects.
19. `underwrite_fails_when_partner_output_short` — output at partner_address with lovelace < partner_cut, assert validator rejects.
20. `underwrite_pool_continuation_grows_by_net_premium_not_premium` — assert `cont_pool == old_pool + net_premium`, NOT `+ premium`. (This is the breaking change vs V11.)

`contracts/validators/pool.ak` AcceptCancellation branch (parallel set):

21. `cancel_with_no_partner_routes_2pct_of_cancellation_fee_to_team` — assert team output present with exactly `0.02 * cancellation_fee = 0.002 * premium`.
22. `cancel_with_partner_at_max_split` — partner gets `0.2 * 0.02 * cancellation_fee`.
23. `cancel_fails_when_team_output_missing`.
24. `cancel_fails_when_team_output_short`.
25. `cancel_fails_when_partner_output_missing_for_some_partner_address`.
26. `cancel_pool_value_decreases_by_refund_plus_team_plus_partner_cuts` — assert `cont_pool == old_pool - refund - team_cut - partner_cut`, NOT just `- refund`. (V11 only subtracted refund; V12 also subtracts the cancel-time team/partner cuts.)
27. `cancel_total_liquidity_decreases_by_refund_plus_team_plus_partner_cuts` — assert new datum's `total_liquidity` matches.

`contracts/validators/pool.ak` BatchUnderwrite branch — **see §3.10.7 for the full 13-test set** (5 positive + 8 negative). The original 4 stubs in this section are superseded by §3.10.7 per D10. Summary list (full case detail in §3.10.7):

28. `batch_underwrite_three_solo_policies_aggregates_team_output` — positive: single aggregated team output ≥ sum of per-policy floored team cuts.
29. `batch_underwrite_three_policies_same_partner_consolidated` — positive: single team + single partner output, both ≥ aggregated cut.
30. `batch_underwrite_three_policies_distinct_partners` — positive: single team output + 3 partner outputs.
31. `batch_underwrite_mixed_partner_and_no_partner` — positive: 5-policy mixed scenario.
32. `batch_underwrite_large_batch_with_no_floor_padding` — positive: 500-ADA premiums avoid floor pads entirely.
33. `batch_underwrite_fails_when_team_output_short_by_one_lovelace` — negative.
34. `batch_underwrite_fails_when_team_output_at_wrong_address` — negative.
35. `batch_underwrite_fails_when_partner_output_missing_entirely` — negative.
36. `batch_underwrite_fails_when_partner_share_exceeds_cap_in_any_policy` — negative.
37. `batch_underwrite_fails_when_pool_value_off_by_floor_pad` — negative.
38. `batch_underwrite_fails_when_pool_value_inflated_by_phantom_2pct` — negative.
39. `batch_underwrite_fails_when_per_policy_floor_drift_attempted` — negative (the sum-then-floor fee-bypass attack).
40. `batch_underwrite_fails_when_partner_address_aggregated_short` — negative.

The total Aiken-test count for the protocol-fee mechanism rises from ~31 to ~40 (counting the BatchUnderwrite expansion from 4 to 13). Updated count is reflected in the cover letter.

### 10.5 Backend — protocol-fee mechanism (Wave 3)

`api/tests/test_fee_split_helper.py`:

1. `test_calculate_protocol_fee_split_solo_matches_aiken` — 100 ADA premium, 200 bps fee, 0 bps partner -> (2_000_000, 0).
2. `test_calculate_protocol_fee_split_partner_max_matches_aiken` — 100 ADA premium, 200 bps fee, 2000 bps partner -> (1_600_000, 400_000).
3. `test_calculate_protocol_fee_split_rounding_floor_matches_aiken` — premium chosen to provoke fractional cut (e.g. premium = 12_345_678, partner_share_bps = 1337). Compare against an Aiken-computed reference value.
4. `test_add_protocol_fee_outputs_emits_team_output` — mock builder, assert team output added with correct address + amount.
5. `test_add_protocol_fee_outputs_skips_partner_when_none` — partner_address=None, assert no partner output appended.
6. `test_add_protocol_fee_outputs_rejects_partner_cut_below_min_utxo` — small premium + max partner share, assert ValueError.

`api/tests/test_build_endpoints_v12_fees.py`:

7. `test_create_build_default_partner_share_zero` — body without partner fields defaults to `partner_share_bps=0`, `partner_address=None`. PolicyDatum reflects this.
8. `test_create_build_passes_partner_address_through_to_datum` — body with `partner_address` set, assert PolicyDatum's `partner_address` is `Some(addr)`.
9. `test_create_build_rejects_partner_share_above_cap` — `partner_share_bps=2001`, assert 400 client error pre-flight.
10. `test_create_build_rejects_negative_partner_share` — `partner_share_bps=-1`, assert 400.
11. `test_create_build_rejects_partner_share_with_no_address` — `partner_share_bps=1000`, `partner_address=null`, assert 400.
12. `test_create_build_adds_team_output_with_correct_amount` — inspect returned tx CBOR, assert team output present at the expected `AEGIS_TEAM_ADDRESS_PREPROD` with `2% * premium` lovelace.
13. `test_create_build_balance_invariant` — tx total balance check: `pool_growth + team_cut + partner_cut + treasury_donation + tx_fee + change == sum(inputs)`.

`api/tests/test_team_address_resolver.py`:

14. `test_resolve_team_address_preprod_round_trips` — call `resolve_team_address("preprod")`, assert the resulting `pyc.Address.payment_part.payload.hex() == "c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe"`. This is the off-chain mirror of the compile-time Aiken constant pin.
15. `test_resolve_team_address_mainnet_round_trips` — same for mainnet, asserting payment VKH hex `61ad95a7265a9c269125c149505043e143b822eedd930cc14e7e8129`.
16. `test_team_address_constant_matches_env_var` — if `AEGIS_TEAM_ADDRESS_PREPROD` env var is set, assert it equals the bech32 string of the resolved address. (Guards against an operator-supplied env var diverging from the compile-time constant — would break Underwrite tx submission.)

`api/tests/test_cancel_policy_v12_fees.py`:

17. `test_cancel_emits_team_output_for_cancellation_fee_cut` — solo policy cancel, assert team output present with `0.002 * premium` lovelace.
18. `test_cancel_emits_partner_output_when_policy_has_partner` — cancelled policy carries `partner_address = Some(addr)`, assert partner output added with `0.0004 * premium` lovelace (at max partner share).
19. `test_cancel_pool_continuation_decreases_by_refund_plus_cuts` — assert pool output lovelace == `old_pool - refund - team_cut - partner_cut`.

### 10.6 Frontend — protocol-fee mechanism (Wave 5)

`frontend/tests/components/BuyPanel.test.tsx`:

1. `default buy flow sets partner_address: undefined and partner_share_bps: 0` — assert the `onBuy` callback fires with no partner fields (or both fields explicitly undefined/0).
2. `client.policies.buildCreate body omits partner fields when not provided` — mock fetch, assert request body has neither `partner_address` nor `partner_share_bps`, OR has them at the default (undefined / 0).

(Wave 5 also defensively adds frontend-side pre-flight rejection for `partner_share_bps > 2000` / `< 0` / `> 0 with no address`, even though no UI emits these — they're insurance against a future bug.)

### 10.7 End-to-end (Wave 6)

`api/tests/e2e/test_v12_btc_policy_lifecycle.py`:

1. Build a BTC policy via `/api/policies/create/build` with `asset="BTC"`.
2. Sign locally with the test wallet's signing key.
3. Submit via `/api/tx/submit`.
4. Poll `/api/policies` until the new policy appears.
5. Assert the policy's `oracle_nft` matches the canonical BTC NFT policy id.

Run this same test for each of the four non-ADA assets so the wave produces five preprod tx hashes (one per asset).

A claim e2e is descoped to V12.1 because triggering a real-world strike requires a price drop. Instead, an Aegis-internal mock-price-drop test against the publisher service confirms the claim path.

---

## 11. Rollout Phases and File Ownership

Six waves. Wave 1 is this design doc. Subsequent waves are gated on the previous wave's success criterion. No two waves share file ownership.

| Wave | Owner | Files touched | Success criterion |
|---|---|---|---|
| 1 (this doc) | Architect | `docs/v12_validator_upgrade.md`, `docs/communications/AUDITOR_NOTIFY_V12_2026-05-11.md` | Both docs landed on the `feat/v12-multi-pair-oracle` branch; auditor email sent |
| 2 | Aiken agent | `contracts/lib/aegis/types.ak` (NFT allowlist + team_address constants + PolicyDatum partner fields), `contracts/lib/aegis/oracle/aegis_self.ak` (allowlist `list.has`), `contracts/lib/aegis/oracle.ak` (`canonical_oracle_nft` returns List), `contracts/lib/aegis/pricing.ak` (new `calculate_protocol_fee_split` helper + tests), `contracts/validators/pool.ak` (Underwrite + AcceptCancellation + BatchUnderwrite fee-split outputs), new `contracts/lib/aegis/oracle/aegis_self_tests.ak` (or appended tests), regenerated `contracts/plutus.json` | `aiken check` and `aiken build` both green; all new tests pass (≈31 protocol-fee tests + 8 NFT-allowlist tests); new validator hashes pasted into Section 4 |
| 3 | Backend agent | `api/chain.py` (NFT constants + team address resolver), `api/oracles/aegis_self.py`, `api/oracles/dispatcher.py`, `api/policies.py` (Underwrite + Cancel build paths add team/partner outputs), `api/server.py` (3 build endpoints + price endpoint; new `partner_address` and `partner_share_bps` optional fields), all new test files | All backend tests green; CI on Railway runs cleanly |
| 4 | Operator (human) | None — runbook execution only | All 9 deploy steps in Section 8 complete; 5 preprod tx hashes recorded; team output appears at the configured `AEGIS_TEAM_ADDRESS_PREPROD` for each Underwrite tx (visible on Cardanoscan) |
| 5 | Frontend agent | `frontend/src/api/client.ts` (`BuildCreatePolicyArgs`, `buildCreate` body — adds `asset`, `partner_address?`, `partner_share_bps?`), `frontend/src/components/panels/BuyPanel.tsx`, new `frontend/src/hooks/useAegisSelfPrice.ts`, `frontend/src/App.tsx` (forwards `asset`), all new test files | All frontend tests green; manual smoke on staging URL across 5 assets clean; partner fields default to undefined / 0 in v0 |
| 6 | Docs / e2e agent | `docs/v12_validator_upgrade.md` (Section 4 hash table finalised), `D:/aegis-runbooks/v11_legacy_claim.md` (CLI escape hatch), `api/tests/e2e/test_v12_btc_policy_lifecycle.py` and 4 sibling per-asset e2e tests, plus 1 fee-split e2e (assert team output present in a real preprod tx) | 5 green e2e tx hashes on preprod; runbook reviewed by operator; team-output presence confirmed via Cardanoscan |

**Follow-up (V12.1, post-V12 deploy)**: The `/partners` tab — partner registry, code redemption, and BuyPanel partner-input UI. Operator owns the UX. Not in V12 deploy radius.

### 11.1 BatchUnderwrite deploy + cutover note (D10)

Per operator decision D10, BatchUnderwrite is **V12-on-chain-complete + V12-off-chain-complete + V12.1-UI-wired**. The Aiken validator branch and the backend `build_batch_underwrite_tx` ship in V12 (Waves 2 and 3 respectively); the dApp UI (auto-claim batch tooling or a future operator dashboard) wires in V12.1 without requiring a validator redeploy. Implications:

- **Wave 2** ships the full BatchUnderwrite branch per §3.10.4 — about 130 lines net replacement.
- **Wave 2** ships the test set per §3.10.7 — 13 tests (5 positive + 8 negative).
- **Wave 3** ships the off-chain `add_batch_protocol_fee_outputs` helper per §3.10.8 — about 40 lines net new + 6 pytest cases.
- **Wave 4** does NOT require a separate BatchUnderwrite smoke test (the validator branch is exercised by an internal preprod test only if the operator runs `scripts/batch_test.py` manually — the success criterion is the Aiken test set, not a preprod tx hash).
- **Wave 5** does NOT add UI for BatchUnderwrite; the BuyPanel still uses single-policy Underwrite.
- **Wave 6** does NOT require a BatchUnderwrite e2e — the auditor sign-off + Aiken test pass + pytest pass are the V12 release criteria.

When V12.1 wires the BatchUnderwrite UI (potentially an auto-claim batch tool, partner-routing batch issuance, or an LP-side batch closer), the on-chain validator is already correct and the off-chain builder is already shipped. No re-deploy. Same validator hashes.

Concurrency rule: Waves 2 and 5 cannot run in parallel because they share the `frontend/src/api/client.ts` argument type contract for `asset` (Wave 5 depends on Wave 3's backend rolling out so the build endpoint accepts the new field). Waves 3 and 5 also cannot run in parallel for the same reason. Waves 2 and 3 CAN run in parallel up until the hash rotation table is needed — Wave 3 can stub the new env-var names while Wave 2 produces the hashes.

---

## 12. Open Questions for the Operator

The following items need a binary operator decision before downstream waves can land. Each is flagged with the wave that blocks on it.

1. **(Blocks Wave 4)** Confirm `AEGIS_POOL_NFT_ASSET_NAME` rotation from `AEGIS_POOL_V9` to `AEGIS_POOL_V12`. Default proposal is to rotate so the on-chain asset name visibly tracks the V12 deploy; alternative is to keep `AEGIS_POOL_V9` so the asset name does not track validator versions. **Recommended: rotate to `AEGIS_POOL_V12`** for visible governance.
2. **(Blocks Wave 3)** Confirm the canonical pair-label format. This doc specifies lowercase no-separator (`"adausd"`). Alternative is uppercase-with-slash (`"ADA/USD"`). **Recommended: lowercase no-separator** because it is URL/env safe; the dispatcher's `parse_pair_label` accepts both forms for backwards compat.
3. **(Blocks Wave 5)** Confirm BuyPanel asset chip order. This doc specifies alphabetical (ADA, BTC, ETH, USDC, USDT). Alternative is by market cap or by expected user demand (ADA first, BTC second, ETH third, USDC/USDT last because stablecoin-vs-USD insurance is a depeg surface). **Recommended: ADA, BTC, ETH, USDC, USDT** to match the on-chain constant order.
4. **(Blocks Wave 4)** Confirm the V11 policy cutover plan in Section 9. The proposal is hard-cut-delete-from-UI with CLI escape hatch. **Alternative: dual-mode display** with a clear "Legacy V11" badge. Dual-mode doubles the test surface and is explicitly recommended against, but the operator may prefer it for the optics of "no policy left behind." **Recommended: hard-cut.**
5. **(Blocks Wave 3)** Confirm per-asset premium curve. V12 keeps the V11 premium curve (`coverage * 0.04 * min(days/7, 5)`) asset-agnostic. **Alternative: per-asset multiplier table** (e.g. BTC * 1.2 due to higher volatility). **Recommended: keep V11 curve for V12; per-asset multipliers tracked as V12.1.**
6. **(Blocks Wave 2)** Confirm the canonical list constant name `aegis_self_canonical_nfts`. Alternatives: `aegis_self_nft_allowlist`, `aegis_self_canonical_oracle_nfts`. **Recommended: `aegis_self_canonical_nfts`** because it parallels the V11 name `aegis_self_nft_policy` (singular -> plural).
7. **(Blocks Wave 3)** Confirm whether the existing `AEGIS_SELF_PUBLISHER_NFT_PREPROD` env var alias (pointing at the ADA/USD value) should be preserved or deleted post-V12. **Recommended: preserve** for V11-compat callers; deprecate in V12.1 once all callers are migrated.
8. **(Blocks Wave 6)** Confirm the e2e claim test scope. Real-world strike triggers are out of scope for V12 e2e (requires a price drop in nature); the proposal is to run a mock-price-drop test against the publisher service for one asset only. **Alternative: ship V12 without a claim e2e, document the gap.** **Recommended: mock-price-drop test for BTC.**

### Protocol-fee mechanism open questions

9. **[RESOLVED via D8]** ~~Confirm the cancel-time fee design choice: B2 vs B1.~~ **Operator confirmed B2** — take the protocol fee from the 10% cancel-fee retention (NOT the original premium). Cumulative team take per cancelled 100-ADA policy = `2 ADA (Underwrite) + 0.2 ADA (Cancel) = 2.2 ADA`. The same min-utxo floor logic from D7 applies — both team and partner cuts on cancel are subject to the 2-ADA floor with submitter (canceller) subsidy. See §3.9 for the validator math + the cancel-path floor walkthrough.

10. **[RESOLVED via D9]** ~~Confirm the team_address shape — full base Address vs payment-credential-only equality.~~ **Operator confirmed full base address** (payment_vkh + stake_vkh, both 28-byte VKHs). Rotation requires new validator deploy. Path B smart-constructor form (`from_verification_key |> with_delegation_key`) is the implementation pattern. See §3.5 for the decoded VKH bytes (verbatim from `docs/architecture/_decode_addresses.py`) and §3.5 confirmation block.

11. **[RESOLVED via D7]** ~~Confirm the minimum-utxo handling for small-premium policies.~~ **Operator confirmed the 2-ADA floor with submitter-paid subsidy** — each fee output must be `>= max(min_utxo_lovelace, calculated_cut)`. The 2-ADA floor applies to BOTH team and partner outputs. When the percentage-calculated cut is below the floor, the submitter's wallet pays the floor-pad subsidy — mirroring the existing Conway `treasury_donation` pattern (sourced from submitter inputs, not the pool, not the premium). Pool's `total_liquidity` and physical lovelace both still grow by exactly `net_premium = premium - calculated_team_cut - calculated_partner_cut` (NOT minus the floored amounts). Same rule applied on AcceptCancellation per D8. See §3.8 / §3.9 / §3.10 for math walkthroughs.

12. **(Blocks Wave 3)** Confirm the partner_share_cap_bps value of 2000 (20% of fee = 0.4% of premium max). Alternatives: 5000 (50% = 1% max), 1000 (10% = 0.2% max), 0 (no partners ever; cap removes the feature). **Recommended: 2000** as per operator's binding decision D2 in the V12 architect handoff.

13. **(Blocks Wave 5)** Confirm v0 ships with NO partner UI in BuyPanel. Solo policies only. `/partners` tab is V12.1. **Recommended: confirm.** Adding the partner UI in V12 doubles the Wave 5 surface and pushes the V12 ship date.

14. **(Blocks Wave 2)** Confirm `treasury_share_bps` and `cancellation_fee_bps` remain at V11 values (`2500` and `1000` respectively). V12 does not propose changing the Cardano-treasury cut or the cancellation-fee retention. **Recommended: confirm.** The fee-mechanism scope is the team+partner extraction only.

### BatchUnderwrite open questions (new — surfaced by D10)

15. **(Blocks Wave 2)** Confirm the **per-policy floor** convention for BatchUnderwrite (§3.10.2 decision 1). Operator's recommendation in D10 was per-policy floor — each policy's `team_cut_i` and `partner_cut_i` independently get `max(min_utxo, _)`, then the per-policy floored cuts sum into the aggregated required output. This is what §3.10 specifies. The alternative (sum-then-floor) is rejected because it would let a batch of 5 policies with `team_cut_i = 1.6 ADA` (sum = 8 ADA, above floor) avoid all per-policy floor padding, creating inconsistent solo-vs-batch economics. **Confirm per-policy floor.** Document the tradeoff for future operator override if needed.

16. **(Blocks Wave 2)** Confirm the **single team output** convention for BatchUnderwrite (§3.10.2 decision 3). The validator accepts ONE aggregated team output `≥ sum_i(team_cut_i_required)`. The validator also tolerates N team outputs whose sum ≥ requirement, but the off-chain builder always emits exactly one. **Confirm single aggregated team output is the canonical builder shape.**

17. **(Blocks Wave 2)** Confirm the **per-unique-partner consolidated output** convention for BatchUnderwrite (§3.10.2 decision 2). The validator accepts ONE output per unique partner_address `≥ sum_i(partner_cut_i_required for that partner)`. If 5 policies in the batch share the same partner_address, the tx emits ONE consolidated partner output. If they have different addresses, the tx emits N partner outputs (one per unique address). **Confirm consolidated-per-partner is the canonical builder shape.**

18. **(Blocks Wave 2)** Confirm BatchUnderwrite shipping in **V12-on-chain-complete + V12-off-chain-complete + V12.1-UI-wired** form per §11.1. UI deferred (BuyPanel does NOT call BatchUnderwrite in v0; operator-controlled batch tooling does). Backend + validator must be V12-correct so V12.1 UI wiring requires no re-deploy. **Operator-flagged in D10; confirm.**

---

## 13. Inconsistencies / Surprises in the Brief

These are flagged for the operator. None are blocking — they are notes from grounding the design against the actual code.

- The brief specifies "compile-time pinned, same security level — each NFT is still tied to the same one-shot mint policy under the canonical publisher VKH." The phrasing "the same one-shot mint policy" risks confusion: each of the five NFTs is under a **different** one-shot mint policy (one per pair — that is why each has a distinct policy id). What is shared is the publisher VKH (the *outputs* land at the publisher's address) and the mint pattern (the `pool_nft.ak` validator parameterized over a different init UTxO each time). The diff text in Section 3.1 is phrased carefully to reflect this.
- The brief mentions "frontend redesign" path conventions but the actual frontend at `frontend/src/components/panels/BuyPanel.tsx` already has the chip pattern (`days` chips at lines 163-170). No new design conventions are needed; V12 reuses the existing chip CSS class.
- The brief lists `POOL_NFT_ASSET_NAME` in the Railway rotation table but the existing constant `AEGIS_POOL_NFT_ASSET_NAME` at `chain.py:103-105` carries the default `"AEGIS_POOL_V9"`. The brief does not specify a new asset name; this doc proposes `AEGIS_POOL_V12` (Section 7.1 / Open Question 1).
- The brief references "premium_collector" as one of the 5 new ref scripts to publish but the V11 codebase does not have a `premium_collector` validator (the premium currently flows directly to the pool via the Underwrite branch). If this is a planned addition for V12, it is undocumented in the brief and the codebase. **This doc treats the 5 ref scripts as: policy validator, pool validator, lp_token policy, pool_nft policy, and one of the AegisSelf-related artifacts (publisher mint or feed UTxO).** Operator should confirm or correct the list (flagged as a minor inconsistency, not blocking the design).
- The brief specifies the `expect` change is at "line 83" of `aegis_self.ak` — that matches the current file exactly. Confirmed.
- The brief says "Confirm `list.has` is the right stdlib function (check the existing imports in `aegis_self.ak`)." Confirmed: `aegis_self.ak:29` already imports `aiken/collection/list`, and `aegis_self.ak:54` already uses `list.has(oracle_nft)` against `assets.policies(input.output.value)`. The V12 change reuses the same stdlib function in the same calling convention (`list.has(list, element)`).
- The brief mentions a separate Claude on Node2 published the BTC/ETH/USDT/USDC feeds. The verification path is to query the publisher base address `addr_test1qpsfvvev87wp3qzlmvw33xm564zfwpyllvj5vkwdg43zz5kr0wnh0wdqfaz5ydkgljysaj5lr9kzlqf4l7a2fpqalxjqn8s06k` and confirm five distinct policy ids each at `quantity: 1` matching the table. This is implicit in Wave 4's deploy procedure and not separately blocking, but the Wave 2 Aiken agent should confirm before pinning hex literals in `types.ak` (a copy-paste typo in any one of the 28-byte hex strings would silently turn into "no UTxO matches" at claim time and is the highest-risk surface in this design).

### 13.1 V12 protocol-fee mechanism — additional notes

The protocol-fee mechanism (§3.5–§3.10) was added in revision 2 of this doc after the operator surfaced the missing extraction path during the V12 NFT-allowlist lockdown. Inconsistencies caught during grounding:

- **V11's "phantom" 2% protocol fee.** Reading `pool.ak` line 343 against `pricing.ak::net_premium`: at Underwrite the pool's physical lovelace grows by the FULL premium (`+ premium`), but `total_liquidity` in the datum only grows by `+ net_premium` (= 0.98 * premium). The 2% delta sits in the pool's lovelace, unreachable by team OR LPs OR users. The V12 fix changes the pool-value invariant to `+ net_premium` and adds required team/partner outputs equal to the extracted 2%. No phantom liquidity remains. This was NOT flagged in any prior audit; it is a silent dilution of nobody's claim. Worth a brief note in the V12 mainnet announcement.
- **AcceptCancellation flow trace (verified).** The cancel flow walks: pool input `old_pool` + policy input `coverage` (NOT premium+coverage — `api/policies.py:1465` confirms the policy UTxO holds only `coverage`) + submitter wallet inputs => outputs: pool continuation `old_pool - refund` (strict equality, `pool.ak:792`), insured payout `refund + coverage` (`api/policies.py:3023`), submitter change + Cardano treasury. The 10% cancellation retention is implicit — at Underwrite the pool kept the full premium (incl. 2% phantom and 8% kept in `total_liquidity`), at cancel the pool releases only `refund = 0.9 * premium`, so the pool retains `0.1 * premium`. In V11, `0.08 * premium` of that retention shows up in `total_liquidity` (LP-claimable), and `0.02 * premium` is phantom. In V12 we extract the same `0.02 * premium` to team+partner at cancel time (the §3.9 / B2 spec applies the same 2% split to the cancellation_fee retention, NOT to the original premium — see §3.9 for the math comparison).
- **No V11 "cancel-time fee" existed in the validator.** `pool.ak:808-822` already had `treasury_donation` enforcement at cancel time (0.5% of premium = 25% of 2% protocol fee), so V12's cancel-time team fee is the natural extension of the same fee infrastructure. The treasury cut math is numerically identical between V11 and V12 (re-expressed against `cancellation_fee` for clarity; see §3.9 inline comment).
- **Address shape.** The team_address Aiken constants store the FULL `Address` (payment_credential + stake_credential), not just a payment VKH. This means an operator who delegates the team wallet to a different stake pool (changing the stake_credential) would need a validator-hash rotation. Operator likely wants to know this; we did NOT include a "payment-credential-only equality check" because it would forfeit the validator-pinned stake routing. **Operator decision**: lock the full base address (current design), OR loosen to payment-credential-only matching. Recommended: lock full address.
- **User-visible fee increase.** V11's user-visible fee was 0.5% (Cardano treasury donation; the 2% protocol fee was phantom-stuck and effectively 0% extracted). V12's user-visible fee is 2.5% (2% to team + 0.5% to Cardano). This is the first version where the team collects revenue. **Operator-blessed change** per the V12 revision-2 brief; deserves a line in the V12 mainnet announcement.
- **Operator's "compile-time-pinned per network" intent — verified consistent with pattern.** The existing `aegis_self_publisher_vkh` constant is per-network-agnostic (BIP-44 derivation gives the same VKH across testnet and mainnet, only the network header byte differs); the team_address is per-network-distinct (mainnet wallet is a separate base address from the preprod operator signing wallet). The doc adds `team_address_preprod` and `team_address_mainnet` as twin compile-time constants, and `team_address` as the active-network selector (mirroring `orcfax_fsp_script_hash` selector at line 399). Wave 2 agent updates the selector pointer per build target.
- **Partner output min-utxo trap — RESOLVED via D7.** Originally the design rejected small premiums or required `premium >= 500 ADA` for partner shares to clear the 2-ADA floor. **D7 supersedes this** — per operator decision, the validator enforces `>= max(min_utxo_lovelace, calculated_cut)` and the submitter's wallet pays the floor-pad subsidy for any cut below 2 ADA. So a 100-ADA premium with `partner_share_bps = 2000` IS now buildable: team_cut = 1.6 ADA pads to 2 ADA (submitter pays 0.4 ADA pad), partner_cut = 0.4 ADA pads to 2 ADA (submitter pays 1.6 ADA pad). Submitter total = 100 + 0.4 + 1.6 + 0.5 = 102.5 ADA. Off-chain builder no longer rejects sub-500-ADA premiums; it computes and adds the pad from the submitter's input set. See §3.8 / §3.9 / §3.10 for the math.

### 13.2 BatchUnderwrite coordinated-fee semantics (auditor pointer)

The V12 deploy now covers **three fee-bearing branches with coordinated fee semantics**: Underwrite, AcceptCancellation, and BatchUnderwrite. The auditor's review surface is therefore broader than the original V12 brief implied:

- Underwrite (§3.8) — single team output with per-policy floor on a single policy.
- AcceptCancellation (§3.9) — single team output with floor on the cancel-time cut from the 10% retention (B2 design); canceller wallet pays the pad.
- BatchUnderwrite (§3.10) — aggregated team output across N policies, aggregated partner outputs per unique partner_address, **per-policy floor** before summing (so a 5-policy batch with `team_cut_i = 1.6 ADA` each requires a team output ≥ 10 ADA, NOT 8 ADA).

The per-policy floor convention is the most security-critical V12 design decision after the team_address pin. An attacker who submits a malformed batch (5 policies, sum-then-floor accounting) would short the team output by `5 × 0.4 ADA = 2 ADA` per batch, draining the team's revenue silently. The validator's per-policy sum-of-floored-cuts check closes this surface. This is highlighted for the auditor in the cover letter.

Operator-blessed BatchUnderwrite cutover: validator + backend ship in V12; UI ships in V12.1; no validator redeploy when the UI lands. See §11.1 for the rollout consequence.

---

## 14. V12 Protocol-Fee Economics Summary

A cross-reference table summarising the V11 -> V12 economic change. Verified against `pool.ak`, `policy.ak`, `pricing.ak`, and `api/policies.py` line numbers cited inline.

### 14.1 Per 100-ADA premium, solo policy (no partner)

| Destination | V11 | V12 | Path |
|---|---|---|---|
| Pool (LPs) lovelace | +100 ADA at Underwrite | +98 ADA at Underwrite | `cont_pool == old_pool + premium` (V11) vs `+ net_premium` (V12) |
| Pool `total_liquidity` datum | +98 ADA | +98 ADA | unchanged — `net_premium` already in V11 |
| Pool phantom lovelace | +2 ADA (stuck) | 0 (extracted) | V12 fix — no phantom remains |
| Team wallet | 0 (no path) | +2 ADA | new V12 required output to compile-time `team_address` |
| Partner wallet | 0 | 0 (no partner) | `partner_address: None`, `partner_share_bps: 0` |
| Cardano treasury | +0.5 ADA | +0.5 ADA | Conway `treasury_donation`, sourced from submitter wallet |
| **User pays** | **100.5 ADA** | **100.5 ADA** | same submitter cost |
| **User-visible fee** | **0.5%** | **2.5%** | first version where team collects |

### 14.2 Per 100-ADA premium, partner @ 20% (max)

| Destination | V12 | Path |
|---|---|---|
| Pool (LPs) | +98 ADA | unchanged |
| Team wallet | +1.6 ADA | 2% × 80% = 80% of fee |
| Partner wallet | +0.4 ADA | 2% × 20% = 20% of fee (cap-bound) |
| Cardano treasury | +0.5 ADA | unchanged |
| **User pays** | **100.5 ADA** | unchanged |
| **User-visible fee** | **2.5%** | unchanged regardless of partner split |

### 14.3 Per 100-ADA cancelled policy, solo (B2 design)

| Destination | V11 net | V12 net | Path |
|---|---|---|---|
| Pool (LPs) lovelace | +8 ADA (Underwrite +100, refund −90, phantom 2 stuck) | +5.8 ADA (Underwrite +98, refund −90, V12 cancel cut −0.2, plus 2 ADA team paid at Underwrite already) | see §3.9 trace |
| Pool `total_liquidity` | +8 ADA (V11 net_premium 98 − refund 90) | +7.8 ADA (V12 net_premium 98 − refund 90 − cancel cut 0.2) | new datum invariant |
| Team wallet cumulative | 0 (V11 has no path) | +2.2 ADA (Underwrite cut 2 + cancel cut 0.2) | 2 paths |
| Partner wallet | 0 | 0 (solo) | n/a |
| Cardano treasury | +0.5 ADA at Underwrite, +0.5*0.1 = +0.05 ADA at cancel = +0.55 ADA cumulative | same | unchanged numerics |
| User refund received | 90 ADA | 90 ADA | unchanged |

The LP delta on cancel: V11 = +8 ADA (split between counted `total_liquidity` 8 and phantom 0 because phantom 2 stays in pool but no longer counted as Underwrite-time addition); V12 = +5.8 ADA visible. Difference: V12's 2 ADA team cut at Underwrite is gone from the pool's physical lovelace (paid out), so the LP physical claim is lower BUT the `total_liquidity` invariant is honest — the LP's claim on the pool is now exactly what `total_liquidity` says it is. **V12 makes pool accounting honest;** V11 had a 2% silent dilution per policy that LPs technically couldn't see or extract.

### 14.4 Per 100-ADA claimed policy (in-the-money)

| Destination | V11 | V12 | Path |
|---|---|---|---|
| User (insured) | coverage (e.g. 5000 ADA) | coverage (same) | `policy.Claim` -> insured PKH |
| Pool delta (claim) | -coverage | -coverage | `pool.ProcessClaim` strict equality |
| Team wallet | 0 (no claim-time fee) | 0 (no claim-time fee) | unchanged — claims are users' insurance payouts |
| Partner wallet | 0 | 0 | unchanged |

**No protocol fee on claim — by design.** The team already collected on Underwrite; charging again on payout would be double-dipping. V11 and V12 are identical on ProcessClaim semantics. ProcessClaim and BatchExpireProcess are explicitly unchanged in V12 (see §3.11).

### 14.5 Per 5-policy BatchUnderwrite with mixed partners (per D10)

3 solo policies + 1 partner_X @ 20% + 1 partner_Y @ 20%, all 100-ADA premium.

| Component | Lovelace | Path |
|---|---|---|
| Total premium contributed by submitter | 500 ADA | sum across 5 policies |
| `team_total` (sum of per-policy floored team cuts) | 10 ADA | 5 × max(2, 1.6 or 2) — every policy floors to 2 ADA |
| `partner_X_total` | 2 ADA | 1 × max(2, 0.4) |
| `partner_Y_total` | 2 ADA | 1 × max(2, 0.4) |
| Pool growth (`total_net`) | 490 ADA | `500 − Σ team_cut_i (unfloored) − Σ partner_cut_i (unfloored) = 500 − 9.2 − 0.8` |
| Treasury donation | 2.5 ADA | `0.5% × 500 = 2.5 ADA` Conway field, sourced from submitter |
| **Floor pads paid by submitter** | **4 ADA** | `(10 − 9.2) + (2 − 0.4) + (2 − 0.4) = 0.8 + 1.6 + 1.6` |
| **Total submitter outflow** | **506.5 ADA** | `500 + 4 + 2.5` (premium + pads + treasury) |

LP delta on the batch: pool grows by exactly `+ 490 ADA` (honest accounting — no phantom liquidity). The submitter's effective fee burden is the difference between submitter outflow (506.5 ADA) and policy value delivered (5 × 100 ADA + 4 ADA floor pads which flow to team/partners but don't reach the user) = 6.5 ADA = 1.3% per policy effective. Without the floor pads, the user-visible fee would be 2.5% × 5 policies = 2.5 ADA total above premium (the treasury); the pads add 4 ADA. The pad efficiency improves with larger premiums (a 500-ADA per-policy batch has no pads, so submitter pays only `5 × 500 × 1.005 = 2512.5 ADA` and the effective fee is exactly 2.5%).
