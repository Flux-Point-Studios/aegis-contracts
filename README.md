# Aegis Smart Contracts

**Aegis** is a parametric crypto-insurance protocol on Cardano. This repository is the
public home of the on-chain code — the Aiken validators, library helpers, fixtures, the
full security history, and the red-team scripts documenting the attacks tried against it.

The protocol is **live on Cardano mainnet** (V12.2 + R17). The off-chain backend (API,
monitoring bot, frontend, SDK) lives in a separate repository and is not included here.

- **Status:** mainnet-live · `Plutus V3` (Conway) · Aiken `v1.1.22+39d6b04`
- **External audit:** TESTNET-**GREEN** — an external third party (EXT-01…EXT-21 closed)
- **Tests:** 473 Aiken tests, 0 failures (`aiken check`)
- **Final pre-launch gate:** mainnet live-fire red-team — 160+ real-ADA attacks, all rejected, zero value extracted ([report](redteam/MAINNET_LIVE_FIRE_REDTEAM.md))

---

## How it works

A buyer pays a premium to open a **policy** parameterized by a strike price, coverage
amount, and duration. Liquidity providers fund a shared **pool** that underwrites those
policies and earns the premiums. If the insured condition triggers within the policy
window — verified on-chain against a trusted price oracle — the policy pays out from the
pool; otherwise the coverage expires and the premium stays with the LPs.

Everything is non-custodial: users sign with their own wallet (CIP-30), the pool is a
single NFT-identified UTxO, and each policy is an independent UTxO with its own datum.

### Validators

| Validator | Responsibility |
|-----------|----------------|
| `pool.ak` | Liquidity pool: `Underwrite`, `BatchUnderwrite`, `ProcessClaim`, `AddLiquidity`, `RemoveLiquidity`, `BatchExpireProcess`. Holds the fee carve + Conway treasury donation. |
| `policy.ak` | Per-policy lifecycle: `Claim`, `BatchClaim`, `Cancel`, `Expire`, `BatchExpire`. |
| `lp_token.ak` | LP-receipt mint policy (parameterized over the pool hash). |
| `policy_marker.ak` | Per-policy marker token enforcing lifecycle branch-pairing (mint authority pinned to a real pool spend). |
| `pool_nft.ak` | One-shot NFT that uniquely identifies the canonical pool UTxO. |

### Price oracle — AegisSelf (self-hosted)

Aegis runs its **own self-hosted oracle**. A dedicated publisher wallet posts signed
price feeds (ADA/USD + BTC/USD/ETH/USD/USDC/USDT) on-chain as Charli3-compatible datums;
validators consume them as reference inputs and authenticate them against a compile-time
**publisher-VKH + NFT allowlist** (`lib/aegis/oracle/aegis_self.ak`). On mainnet this is
the sole price source. Legacy third-party oracle parsers (Charli3, Orcfax) remain in the
tree behind the `OracleProvider` sum type but are **disabled at the canonical-NFT gate**,
so no policy can be created against them. iAsset products bind Indigo's on-chain price
oracle directly (three-layer NFT + script-credential + freshness handshake).

### Core security invariants (enforced on-chain)

- **Marker branch-pairing** — every lifecycle branch is paired via a per-branch marker
  redeemer read sibling-style from the transaction; closes the lifecycle-mismatch and
  double-claim classes.
- **LP-token locality** — minted LP receipts must land in a wallet, never the pool
  continuation; the pool output is pinned to carry zero LP (symmetric to the marker pins).
- **Pool-NFT authentication** — the canonical pool is the one UTxO bearing the one-shot
  NFT; it cannot be relocated, and a non-NFT "shadow" UTxO at the script address can never
  be spent as a pool.
- **Mint authority** — markers and LP tokens are only mintable by a transaction that
  *spends* the canonical-NFT pool UTxO; a read-only reference input does not authorize.
- **Exact value conservation** — premium funding, fee/partner splits, and pool deltas are
  checked for exact conservation; double-satisfaction is blocked by per-branch counting.

The full mechanism spec (fee economics, Indigo binding, batch accounting) is in
[`docs/v12.2_validator_upgrade.md`](docs/v12.2_validator_upgrade.md).

---

## Security

Aegis custodies pooled capital, so the validators went through a deep, layered assurance
process — all completed before mainnet launch.

| Layer | Coverage | Outcome |
|-------|----------|---------|
| Internal red-team (Rounds 1–17) | Adversarial review of every redeemer, V5 → V12.2+R17 | All findings closed with regression tests |
| External audit | External third party (contracts scope) | TESTNET-**GREEN**; EXT-01…EXT-21 closed |
| Symbolic execution | Z3-backed formal slice of core spend/mint paths | 27/27 properties proven |
| Property / differential fuzzing | Aiken property tests + Python differential fuzzer | No invariant violations |
| **Mainnet live-fire** | 4 autonomous agents vs the live deployment, real ADA | **0 exploits, 0 value extracted** |

**Mainnet live-fire red-team (final gate).** Four autonomous agents — three independent,
one orchestrating multi-wallet collusion — replayed the *entire* historical attack corpus
and invented new vectors, building and submitting **160+ real-ADA transactions** to
mainnet across validator-logic, economic/oracle, API, and coordinated-collusion surfaces.
**Every adversarial transaction was rejected on-chain.** The one issue found (LP-token
locality) was fixed — both the mint-authority and continuation-locality halves — and
**re-verified closed by reproducing the deployed script hash byte-for-byte from source.**
Full catalog: [`redteam/MAINNET_LIVE_FIRE_REDTEAM.md`](redteam/MAINNET_LIVE_FIRE_REDTEAM.md).
The V3 cascade was re-run against the catalog (2026-06-08) with a marker-aware claim/cancel
lifecycle pass against a live on-chain policy — all adversarial transactions rejected.

The finding-by-finding history across all internal rounds is in
[`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md); each finding
cites the on-chain transaction that demonstrated it pre-fix and the redeploy that rejects
it. Round-specific reports live under [`redteam/`](redteam/).

---

## Deployed on mainnet (V12.2 + R17 · V3 cascade)

Validators are parameterized in a cascade (pool NFT → marker → policy → pool → LP), so
each has a profile-independent **base** hash and a deployed **applied** hash. Both are
reproducible from a clean checkout on the mainnet build profile (the live-fire report
documents the byte-for-byte reproduction). The current deployment is the **V3 cascade** —
adding the Indigo iUSD relay feed as the 6th AegisSelf canonical NFT re-parameterized
every hash below; the validator *logic* is unchanged from R17.

| Validator | Applied hash (deployed) | Reference UTxO |
|-----------|-------------------------|----------------|
| `pool_validator` | `792b5c5bd5d36e8d43e0bdca84d2494150ebbb1c23889d8476ca3651` | [`4e75c919…#0`](https://cexplorer.io/tx/4e75c9192a1304857201e593fc9625d908f33caec6e35caabb871f3d4c16f1ab) |
| `policy_validator` | `5fc5ee32cddc0bb659c4e16ec0d9f1335ce884b6cf3e432c084234db` | [`76fdf0b9…#0`](https://cexplorer.io/tx/76fdf0b904ad2d41a75bbdfabf8f01ae26aeeb62bbb003128afb8513681e4a5a) |
| `policy_marker` | `99ef049570d2e49d7af979a81df5f0f023e2adeb526f8f957be92f7d` | [`91800fdb…#0`](https://cexplorer.io/tx/91800fdb0ec5693dca7bee8812363f9397924a318aab5795c47376028831a69c) |
| `lp_token_policy` | `c2bed58062161970fb48f17b0dccba281b950b5e04a3eea5fefdf85d` | [`550f77b8…#0`](https://cexplorer.io/tx/550f77b83c82036c0a3b25a05bf334d738277e2837adf0761a55ee37e14301d1) |

| | |
|---|---|
| Pool script address | `addr1w9ujkhzm6hfkar2ruz7u4pxjf9q4p6amrs3c38vywm9rv5gsgtjfa` |
| Policy script address | `addr1w90utm3jehwqhdjecnskasxe7ye4e6yykm8nusevppprfkc2wxq3k` |
| Pool NFT | `d71ffa88abe78092a5cba794d2f20ab86ca61bbbede36ca58c065778` (`AEGIS_POOL_V3`) |
| Canonical pool UTxO | [`75cf754b…#0`](https://cexplorer.io/tx/75cf754b7b8672d327c4032109d2c90a81f65915cdc4408ca3ed13af36b53188) |
| AegisSelf publisher VKH (compile-pinned) | `bb09f43245759995440388db9ef3f8a614246e8da1dd9bd053261347` |
| Minimum premium | 100 ADA |

**Base (pre-parameterization) hashes** — the ceremony preflight gate reproduces these
exactly from the canonical source before any on-chain step:
`pool_validator 080c9a9c…` · `policy_validator 4b2f5f73…` · `policy_marker 4e99e1ab…` ·
`lp_token_policy 1acbea2d…`.

---

## Build & verify

```bash
# Install the pinned compiler
aikup install v1.1.22

cd contracts
aiken check        # 473 tests, 0 failures
aiken build        # regenerates plutus.json (preprod dev profile)
```

The repository's committed `plutus.json` is the **preprod** dev-profile blueprint (the
test suite is preprod-pinned). Mainnet artifacts are built by selecting the mainnet
profile in `lib/aegis/types.ak` and are pinned in the deploy record above; the live-fire
report shows the deployed hashes reproduced byte-for-byte from source.

Audit entry points:
- [`contracts/validators/`](contracts/validators/) — `policy.ak` + `pool.ak` hold ~95% of the surface.
- [`docs/v12.2_validator_upgrade.md`](docs/v12.2_validator_upgrade.md) — full mechanism spec.
- [`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md) — finding history.
- [`docs/GREEN_PATH_PROOFS.md`](docs/GREEN_PATH_PROOFS.md) — on-chain proof that every user-facing branch executes correctly.
- [`redteam/`](redteam/) — attack scripts + per-round reports, including the [mainnet live-fire report](redteam/MAINNET_LIVE_FIRE_REDTEAM.md).

---

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Security disclosure

See [`SECURITY.md`](SECURITY.md). For new findings, **do not open a public issue** — email
security@fluxpointstudios.com (PGP key on request).
