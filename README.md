# Aegis Smart Contracts

**Aegis** is a parametric crypto-insurance protocol on Cardano. This repository is the
public home of the on-chain code — the Aiken validators, library helpers, fixtures, the
full security history, and the red-team scripts documenting the attacks tried against it.

The protocol is **live on Cardano mainnet** (V12.2 + R17). The off-chain backend (API,
monitoring bot, frontend, SDK) lives in a separate repository and is not included here.

- **Status:** mainnet-live · `Plutus V3` (Conway) · Aiken `v1.1.22+39d6b04`
- **External audit:** TESTNET-**GREEN** — UTxO Company / Anastasia Labs engineers (EXT-01…EXT-21 closed)
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
| External audit | UTxO Company / Anastasia Labs (contracts scope) | TESTNET-**GREEN**; EXT-01…EXT-21 closed |
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

The finding-by-finding history across all internal rounds is in
[`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md); each finding
cites the on-chain transaction that demonstrated it pre-fix and the redeploy that rejects
it. Round-specific reports live under [`redteam/`](redteam/).

---

## Deployed on mainnet (V12.2 + R17)

Validators are parameterized in a cascade (pool NFT → marker → policy → pool → LP), so
each has a profile-independent **base** hash and a deployed **applied** hash. Both are
reproducible from a clean checkout on the mainnet build profile (the live-fire report
documents the byte-for-byte reproduction).

| Validator | Applied hash (deployed) | Reference UTxO |
|-----------|-------------------------|----------------|
| `pool_validator` | `a2e4f9619b52ee7bf0a4862eff56e3b0f17fe2b7191525a8b08b58c4` | [`4a85f550…#0`](https://cexplorer.io/tx/4a85f5503866f2d5cd13049d99b3aef57ec05156a84009417d0a136d6f55accd) |
| `policy_validator` | `f776a841b01dffc98eb95e80f8c2a07a81f6b8d13aaf7dd3d3dab972` | [`9fafd340…#0`](https://cexplorer.io/tx/9fafd34040a9cb648c323813c366e2fa861f7ae8383db60f2b86b19ea8ce98d7) |
| `policy_marker` | `feff14aefc4b13183c840931e1830ff4efe7f049cbc2017f7214c0ea` | [`314518b9…#0`](https://cexplorer.io/tx/314518b93c318d4ec088a5e251acebc76e8781676fe8435a591ea17992cf5570) |
| `lp_token_policy` | `86846fc23aeb4edf9df13c4e32c48318af3e001922e19a199f50e281` | [`de006fa6…#0`](https://cexplorer.io/tx/de006fa674a26d365974b23cfcc091eec1a4b78455abbfcd26ac0a1e3bbbcc11) |

| | |
|---|---|
| Pool script address | `addr1wx3wf7tpndfwu7ls5jrzal6kuwc0zllzkuv32fdgkz9433qah34wa` |
| Policy script address | `addr1w8mhd2zpkqwlljvwh90gp7xz5pagra4c6ya27lwn60dtjusd2fcnw` |
| Pool NFT | `17f0b39cbc75ca4a34deb1ed0c311ed27d5275822c3b3c9257a066d3` (`AEGIS_POOL_V2`) |
| Canonical pool UTxO | [`f3b851b5…#0`](https://cexplorer.io/tx/f3b851b557da2dd058807651feb4771e60452ea097ac03835aef50592ee4fd4c) |
| AegisSelf publisher VKH (compile-pinned) | `bb09f43245759995440388db9ef3f8a614246e8da1dd9bd053261347` |
| Minimum premium | 100 ADA |

**Base (pre-parameterization) hashes** — the ceremony preflight gate reproduces these
exactly from the canonical source before any on-chain step:
`pool_validator 2fdab37b…` · `policy_validator b4a7859b…` · `policy_marker 4e99e1ab…` ·
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
