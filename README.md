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

## Deployed on mainnet (V12.2 + R17 · 20-ADA floor)

Validators are parameterized in a cascade (pool NFT → marker → policy → pool → LP), so
each has a profile-independent **base** hash and a deployed **applied** hash. Both are
reproducible byte-for-byte from a clean checkout on the mainnet build profile under the
pinned compiler. The live deployment sets the minimum-premium floor to **20 ADA**
(`min_premium` in `aegis/types/mainnet.ak`); the validator *logic* is byte-identical to
the R17 review.

| Validator | Applied hash (deployed) | Reference UTxO |
|-----------|-------------------------|----------------|
| `pool_validator` | `1b0fd819c3199d13098e75f7204f6de4aca4d6baedc34867477171a3` | [`6e9f7a27…#0`](https://cexplorer.io/tx/6e9f7a273600b9d45786d831fbf0cd5b8597dd8451cff2e71017ca5d7a97145b) |
| `policy_validator` | `6cfd457e82ac0377e53ee32f16f5b4345d02b6af1abf9572d73424ba` | [`72b09c72…#0`](https://cexplorer.io/tx/72b09c726f47ac0cc6a9387e1ecc0618715f8ce42c7306328821ee23a936b098) |
| `policy_marker` | `3e04eb23074f0fd1346d370ea290fb228981abef51a16d5ffa1e398f` | [`fc1249ce…#0`](https://cexplorer.io/tx/fc1249ce4d93b2ad8b334df7f87362494078093fd88e5dc706c6117c5464bbde) |
| `lp_token_policy` | `96932a82c7b8f2b8ed914d041ecedd16048df5b65ccfc70dbb4a1120` | [`710de6b2…#0`](https://cexplorer.io/tx/710de6b2402bd9d3db1a329ea2bdf25b88f2c6c38c8e952e3d6d4ab8b4cdb1b5) |

| | |
|---|---|
| Pool script address | `addr1wydslkqecvve6ycf3e6lwgz0dhj2efxkhtkuxjr8gachrgc8zx7vf` |
| Policy script address | `addr1w9k063t7s2kqxal98m3j79h4ks696q4k4udtl9tj6u6zfwsp2r2ye` |
| Pool NFT | `efd4de6bc34f026f5da839ca5544e4077e433ddc25715929cfab2ae2` (`AEGIS_POOL`) |
| Canonical pool UTxO | [`fb940e80…#0`](https://cexplorer.io/tx/fb940e8097bec2dacf3215eecb58c8adcfe600c2bf8f628ab7a4cf30dae2eea2) |
| AegisSelf publisher VKH (compile-pinned) | `bb09f43245759995440388db9ef3f8a614246e8da1dd9bd053261347` |
| Minimum premium | 20 ADA |

**Base (pre-parameterization) hashes** — the ceremony preflight gate reproduces these
exactly from the canonical source before any on-chain step:
`pool_validator cf30ca20…` · `policy_validator 4b2f5f73…` · `policy_marker 4e99e1ab…` ·
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
