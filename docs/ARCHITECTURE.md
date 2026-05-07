# Aegis On-Chain Architecture

## Protocol summary

Aegis is parametric ADA price-crash insurance. A user (the **insured**) buys a policy that pays out a fixed `coverage_amount` of ADA if the ADA/USD oracle price drops below a `strike_price` during the policy's lifetime. The oracle source is policy-bound: each policy elects one of three providers at creation time — **multi-oracle (Charli3 primary, Orcfax secondary, AegisSelf publisher-of-last-resort)** — and the trust handshake stays pinned to that provider for the policy's lifetime. Liquidity providers (LPs) underwrite policies in aggregate via a shared pool; their capital backs every policy proportionally. The protocol earns a configurable fee on each premium (default 2%), of which a fixed share (default 25% = 0.5% of premium) is donated to the Cardano protocol treasury via the Conway-era `treasury_donation` body field — enforced cryptographically.

## Multi-oracle dispatcher (v6 + v7)

`aegis/oracle.ak` is a **thin dispatcher**. It owns the public entrypoint `resolve_oracle_price(reference_inputs, provider, oracle_nft) -> Price` and the `canonical_oracle_nft(provider) -> ByteArray` helper. The actual CBOR parsing and the per-provider trust handshake live in three submodules under [`contracts/lib/aegis/oracle/`](../contracts/lib/aegis/oracle/):

| Module | Provider | Constr | Trust handshake |
|---|---|---|---|
| [`oracle/charli3.ak`](../contracts/lib/aegis/oracle/charli3.ak) | Charli3 (primary) | `Charli3 = 0` | NFT under canonical `charli3_ada_usd_nft_policy` AND output at canonical Charli3 oracle script address (A-016 + Round-6 NFT pin) |
| [`oracle/orcfax.ak`](../contracts/lib/aegis/oracle/orcfax.ak) | Orcfax (secondary) | `Orcfax = 1` | FSP UTxO at canonical `orcfax_fsp_script_hash` (per network) → pointer indirection → FS UTxO with `FsDat<Rational>` |
| [`oracle/aegis_self.ak`](../contracts/lib/aegis/oracle/aegis_self.ak) | AegisSelf (Flux Point Studios self-publish) | `AegisSelf = 2` | UTxO carries `aegis_self_nft_policy` token AND payment credential equals compile-time `aegis_self_publisher_vkh` |

A provider-uniform [`oracle/types.ak::Price`](../contracts/lib/aegis/oracle/types.ak) record is the shared output shape. Validator code never sees provider-specific datum quirks. Adding a fourth provider in v8 (Pyth Lazer is the candidate) requires a new submodule + a new variant in `OracleProvider` + one new branch in the dispatcher's `when ... is { ... }` — **the `when`-exhaustivity check IS the curated whitelist**, and adding a variant rotates every validator hash automatically.

The v6.0.2 round-6 fix added a second pin: the Underwrite-time `pdat.oracle_nft == canonical_oracle_nft(pdat.oracle_provider)` check. This closes the A-026 / A-027 root cause where parsers pinned their own credential layer but accepted any caller-supplied `oracle_nft`, letting an attacker mint under their own permissive policy and bypass the second leg.

## Validator topology

Three validators plus one one-shot minting policy:

```
        ┌──────────────────────┐
        │   pool_validator     │ — the shared liquidity pool. Singleton UTxO
        │   (parameterized     │   identified by the pool NFT (A-011).
        │   over policy_hash)  │
        └──────────┬───────────┘
                   │ co-spent with policy on Claim/Cancel/Expire
                   │ standalone on Underwrite/AddLiquidity/RemoveLiquidity
        ┌──────────┴───────────┐
        │  policy_validator    │ — per-policy UTxO. Each insurance contract is
        │                      │   one of these, datum-bound to the canonical
        └──────────────────────┘   pool via pool_script_hash + pool_nft.

        ┌──────────────────────┐
        │  lp_token.lp_token_  │ — mint policy gating LP tokens. Requires the
        │  policy              │   pool validator to be co-spent in any tx.
        │  (parameterized      │
        │  over pool_hash)     │
        └──────────────────────┘

        ┌──────────────────────┐
        │  pool_nft.pool_nft   │ — one-shot mint that creates the canonical
        │  (parameterized      │   pool NFT during operator deployment. Once
        │  over init_utxo +    │   the init UTxO is consumed, no second mint
        │  token_name)         │   is possible (A-011).
        └──────────────────────┘
```

The policy validator is byte-stable across deployments unless a shared library it imports changes. The pool validator's hash rotates whenever the policy hash changes (because pool is parameterized over it). The lp_token hash cascades from the pool. This deliberate factoring lets the policy validator stay stable for most reviews.

## Datum schemas (`contracts/lib/aegis/types.ak`)

### `PolicyDatum` (Constr 0, 11 fields — v6 schema)

| Field | Type | Purpose |
|---|---|---|
| `policy_id` | ByteArray | Off-chain identifier (hash of original terms). Not used for uniqueness on chain. |
| `insured` | VerificationKeyHash | The beneficiary — payouts must land at an enterprise address with this hash (A-009). |
| `strike_price` | Int | Trigger price in 1e6-scaled USD (e.g., $0.35 = 350_000). |
| `coverage_amount` | Int | Maximum payout in lovelace. The policy UTxO holds at least this many lovelace as collateral (A-004). |
| `premium_paid` | Int | Premium contributed by the insured at Underwrite. Used by Cancel for the canonical 90% refund derivation (A-020). |
| `start_time` | Int | Policy effective start in POSIX ms. Must lie within tx validity range at Underwrite (A-015). |
| `expiry_time` | Int | Policy expiration in POSIX ms. Must be strictly greater than start_time (A-015). |
| `oracle_nft` | ByteArray | Provider-dependent canonical handle (see below). Bound at creation. **Round-6 fix:** Underwrite now requires `oracle_nft == canonical_oracle_nft(oracle_provider)` so an attacker can't supply an arbitrary policy id. |
| `pool_script_hash` | ByteArray | Hash of the pool validator this policy is bound to. Used for routing residuals (A-008). |
| `pool_nft` | ByteArray | NFT policy id of the canonical pool. Combined with `pool_script_hash`, uniquely identifies the pool UTxO (A-008). |
| `oracle_provider` | OracleProvider | [v6 NEW — 11th field] Sum-type tag (`Charli3 \| Orcfax \| AegisSelf`). Selects the dispatcher arm + the trust handshake at Claim/Cancel/Expire time. Pinned at policy creation, immutable for the policy's lifetime. |

**`oracle_nft` semantics by provider:**

| `oracle_provider` | What `oracle_nft` is |
|---|---|
| `Charli3` | Charli3 ADA/USD oracle NFT policy id (`charli3_ada_usd_nft_policy`) |
| `Orcfax` | Per-network FSP script hash (`orcfax_fsp_script_hash`) |
| `AegisSelf` | Per-network publisher NFT policy id (`aegis_self_nft_policy`, e.g., `AEGIS_PRICE_FEED_V1`) |

### `PoolDatum` (Constr 0, 6 fields)

| Field | Type | Purpose |
|---|---|---|
| `total_liquidity` | Int | Total lovelace deposited by LPs. |
| `active_coverage` | Int | Lovelace reserved as coverage for active policies. Pool is solvent iff `total_liquidity >= active_coverage`. |
| `lp_token_policy` | ByteArray | LP token mint policy hash. Set at init, immutable thereafter. |
| `protocol_fee_bps` | Int | Protocol fee in basis points (default 200 = 2%). Set at init, immutable. |
| `pool_nft` | ByteArray | Canonical pool NFT policy id. Set at init, immutable. |
| `lp_supply` | Int | Outstanding aLP token supply (A-003). Tracked on-chain so the validator can verify exact mint/burn quantities. |

## Redeemer flows

### Pool redeemers (`contracts/lib/aegis/types.ak`)

| Redeemer | Constr | Branch |
|---|---|---|
| `Underwrite { coverage, premium }` | 0 | Reserve coverage, collect premium. Treasury donation enforced. |
| `ProcessClaim { payout }` | 1 | Pool-side of an insurance payout. Co-spent with `policy.Claim`. **[v6.0.2 / L-006 fix]** `policy_script` field dropped from redeemer; pool now uses parameterized `policy_script_hash`. |
| `AddLiquidity { amount }` | 2 | Deposit ADA, mint aLP. |
| `RemoveLiquidity { amount }` | 3 | Burn aLP, withdraw ADA. |
| `BatchUnderwrite { total_coverage, total_premium }` | 4 | Multi-policy single-tx underwrite. Treasury donation enforced (aggregate). |
| `BatchExpireProcess { total_returned }` | 5 | Pool-side of batch expiry; expired policies' premiums return to LPs. **[v6.0.2 / L-006 fix]** `policy_script` field dropped. |
| `AcceptCancellation` | 6 | Pool-side of a cancellation; canonical 90% refund derived on-chain (A-020). Treasury donation enforced. **[v6.0.2 / L-006 fix]** `policy_script` field dropped. |

### Policy redeemers

| Redeemer | Constr | Branch |
|---|---|---|
| `Claim` | 0 | Single-policy claim. Verifies oracle in-the-money + payout matches coverage. Round-6 fix: now requires `tx_lower >= price.observed_at` (L-003). |
| `BatchClaim` | 1 | Batched claims. Requires uniform `(oracle_provider, oracle_nft)` across all batched policies (A-012, generalized in v6). |
| `Expire` | 2 | Reclaim premium after policy expires unclaimed (premium goes to pool, LPs profit). |
| `BatchExpire` | 3 | Batched expiry. |
| `Cancel` | 4 | Cancel within the 1-hour window; 10% fee retained, 90% premium refunded. Out-of-the-money guard (A-010). Round-6 fix: now requires `tx_lower >= price.observed_at` (L-003). |

## Key invariants enforced on-chain

### Pool value conservation
- `Underwrite`: `lovelace_of(cont_pool) == lovelace_of(old_pool) + premium` (A-007)
- `ProcessClaim`: `lovelace_of(cont_pool) == lovelace_of(old_pool) - payout` (A-007)
- `AcceptCancellation`: `lovelace_of(cont_pool) == lovelace_of(old_pool) - refund` (A-007 / A-020)
- `AddLiquidity`: `lovelace_of(cont_pool) == lovelace_of(old_pool) + amount` (A-007)
- `RemoveLiquidity`: `lovelace_of(cont_pool) == lovelace_of(old_pool) - amount` (A-002 / A-007)

All pool branches require the continuation output to be at the pool address AND carry the canonical pool NFT. `find_canonical_pool_output` (`contracts/lib/aegis/validation.ak`) is the shared primitive. (A-008)

### Policy output binding (Underwrite)
- The new policy output must be at the **policy_validator script address** (A-022). Pool validator is parameterized with `policy_script_hash` to enforce this.
- Datum must bind to OUR pool: `pdat.pool_script_hash == own_pool_hash && pdat.pool_nft == own_pool_nft` (A-008).
- **[v6.0.2 / A-026, A-027, Charli3 NFT pin]** Datum's `oracle_nft` MUST equal `canonical_oracle_nft(pdat.oracle_provider)` — closes the parser-bypass class where the parsers pinned their own handshake but accepted any caller-supplied policy id.
- Coverage + premium fields must equal the redeemer's coverage + premium (A-001).
- Lovelace held in the policy output must be `>= coverage` (A-004).
- Policy's `start_time` must lie within tx validity range; `expiry_time > start_time` (A-015).
- **Exactly one** policy output must match — count-of-1 fold guards against multi-policy under-accounting (A-025).
- Coverage and premium are positive (A-024).
- Coverage / premium ratio enforced via multiplication form `coverage <= premium * 50` (A-014).

### Treasury donation (Conway-era)
- Underwrite, BatchUnderwrite, AcceptCancellation: `tx.treasury_donation >= calculate_treasury_cut(amount, fee_bps, share_bps)`.
- The pool is the single point of fee enforcement; double-satisfaction is structurally impossible because there is only ever one pool input per tx (A-011).
- Donation lovelace flows from submitter wallet inputs, NOT from premium that enters the pool — strict pool value conservation holds.

### Oracle integration (multi-oracle)
- `resolve_oracle_price` (`contracts/lib/aegis/oracle.ak`) dispatches on `oracle_provider` and delegates to the per-provider parser. Each parser's trust handshake includes a canonical-NFT/credential pin (A-016 for Charli3, plus the Round-6 NFT pin extending it; A-027 for Orcfax FSP script hash; A-026 for AegisSelf publisher VKH).
- Claim / BatchClaim / Cancel branches verify oracle freshness against the resolved `Price.valid_until`. Round 6 added the lower-bound `tx_lower >= price.observed_at` check at all 3 sites (L-003), so a tx with a backdated lower bound can no longer reach an oracle reading from before the policy started.
- BatchClaim verifies all batched policies reference the same `(oracle_provider, oracle_nft)` tuple (A-012, generalized in v6).
- `orcfax_freshness_window_ms` is `4_200_000` (70 min) — widened from 30 min in v7 based on empirical mainnet measurement (1h heartbeat, p95 51 min).

### Payout destination
- `sum_lovelace_to_enterprise_pkh(outputs, datum.insured)` — payouts must land at an **enterprise address** (no stake credential) keyed to the insured's pkh (A-009). Stake-grafted addresses are silently skipped, blocking stake-credential hijacking.

### Cancellation guard
- Cancel rejected if oracle price is currently below strike (in-the-money) — prevents underwriter cherry-picking (A-010).
- Cancel rejected if tx upper bound exceeds `start_time + cancellation_window` (1 hour).

## Cross-cutting design choices

- **Datum-mutable parameters are minimized.** Most economic terms (treasury_share_bps, canonical oracle handles, publisher VKH) are compile-time constants pinned by the validator hash. Operator can't silently change them post-deploy without a hash rotation visible to the chain.
- **One-shot pool NFT** binds the pool to a specific operator-chosen init UTxO. The minting policy is parameterized over `(init_utxo, token_name)`, so the NFT policy id deterministically rotates per deployment.
- **Reference scripts (CIP-33)** are used everywhere: every multi-validator tx references the deployed validator via `reference_inputs` rather than embedding the script. This keeps tx size small and the validator code unforgeable per-tx.
- **Conway-era only.** Plutus V3 throughout. Older eras (Babbage, Alonzo) are not supported.

## Test coverage

`contracts/lib/aegis/test_helpers/security_tests.ak` houses the `green_a_NNN_*` and `green_v6_*` / `green_v7_*` family of green-path tests, one or more per audit finding. These complement the per-module unit tests in `pricing.ak`, `pool.ak`, oracle parsers, etc. Total: **222 tests, all passing** as of v6.0.2-redteam-round6.

## Deployment topology

Each deployment (v0 through v6.0.2) consumes ~6 ADA in fees + ~50 ADA locked across reference scripts and the bootstrap pool UTxO. The current live state (v6.0.2) is documented in [`deploy/deploy-state.preprod.json`](../deploy/deploy-state.preprod.json). Previous versions' deploy states are archived in [`deploy/archive/`](../deploy/archive/) for forensic reproduction of pre-fix attack surfaces.
