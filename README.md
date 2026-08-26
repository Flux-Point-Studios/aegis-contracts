# Aegis Smart Contracts

**Aegis** is a parametric crypto-insurance protocol on Cardano. This repository is the
public home of the on-chain code — the Aiken validators, library helpers, fixtures, the
full security history, and the red-team scripts documenting the attacks tried against it.

The protocol is **live on Cardano mainnet** (generation **V8.2M**). The off-chain backend
(API, keeper, publisher, frontend, SDK) lives in a separate repository and is not
included here.

- **Status:** mainnet-live · `Plutus V3` (Conway) · Aiken `v1.1.22+39d6b04`
- **Generation:** V8.2M "stable vault" (August 2026 ceremony). Governed configuration
  lives in a registry datum, off the vault's compile-parameter surface, so mandate and
  calibration changes are registry transactions rather than address migrations.
- **Tests:** 1,162 Aiken tests, 0 failures (`aiken check`)
- **Security history:** external audit TESTNET-**GREEN** (EXT-01…EXT-21 closed) and a
  160+-transaction mainnet live-fire red-team, both completed against the prior
  generation and carried forward as the regression corpus — see [Security](#security).

---

## How it works

A buyer pays a premium to open a **policy** parameterized by a strike price, coverage
amount, and duration. Liquidity providers fund a shared **pool** that underwrites those
policies and earns the premiums. If the insured condition triggers within the policy
window — verified on-chain against a price oracle consumed as a reference input — the
policy pays out from the pool; otherwise the coverage expires and the premium stays with
the LPs.

Everything is non-custodial: users sign with their own wallet (CIP-30), the pool is a
single NFT-identified UTxO, and each policy is an independent UTxO with its own datum.

### Validators (V8.2M, deployed)

| Validator | Responsibility |
|-----------|----------------|
| `pool_vault.ak` | The pool: `Underwrite`, `Claim`, `AcceptCancellation`, `Expire`, LP legs, revenue deposit. Every spend must re-emit the one-shot pool NFT at the same address — the check sits above the redeemer dispatch, so no arm can relocate the vault. |
| `policy_v8.ak` | Policy custody. A policy UTxO is spendable only in a transaction that burns exactly its marker (`net_marker == -policy_ins`), which is what freezes the policy datum between sale and settlement. |
| `policy_marker.ak` | One marker per policy. Settling a policy burns its marker and consumes the UTxO, so double payout is refused by the ledger's double-spend rule before validator logic runs. |
| `oracle_observer.ak` | Withdraw-0 observer: re-derives the oracle price once per transaction and attests it; every consumer in the same transaction reads the validated attestation instead of re-resolving. |
| `eligibility_logic.ak` | The actuarial curve, reached through a withdraw-0 whose hash the registry datum names. It takes zero compile parameters, so a curve rotation never moves the vault address. |
| `registry_v2.ak` | Governance: `ProposeUpdate` (2-of-3 admin) → 72 h timelock → `EnactUpdate` (permissionless) → `CancelUpdate`. `config_within_rails` bounds every value a quorum can write. |
| `lp_token.ak` | aLP mint and burn against pool backing, with a virtual-share offset guarding the first deposit. |
| `pool_nft.ak` / `pool_stake.ak` | One-shot pool identity, and the stake credential of the vault's base address so pooled ADA can be delegated. |
| `lib/aegis/oracle/` | AegisSelf resolver (NFT-authenticated, publisher-credential-filtered reference inputs), Pyth Lazer (Ed25519 signatures verified in-script), and the second-leg fallback. |

`pool.ak` and `policy.ak` are the prior generation's validators, retained for the
security-history record and declared undeployable in the size budget.

### Price oracles

The primary source is **AegisSelf**, a self-hosted oracle: a dedicated publisher posts
signed price feeds (ADA, BTC, ETH, USDC, USDT against USD) as NFT-authenticated UTxOs.
Validators consume them as reference inputs and authenticate the NFT policy and the
publisher credential (`lib/aegis/oracle/aegis_self.ak`). Any number of settlements can
read one print in the same block, because a reference input is read, never spent.

Each trading pair's governed **mandate** can arm a second leg. A `PythPullLeg` requires
the buyer to supply a signed Pyth Lazer payload in the sale transaction itself, verified
in-script (`lib/aegis/oracle/pyth.ak`), and the sale settles on the *minimum* of the two
legs — a stale primary print is capped by the fresher pull, so a slow publisher stops
denying sales without ever widening what a claim can extract.

### Core security invariants (enforced on-chain)

- **A claim is a spend.** A settled policy ceases to exist, so re-claiming it is refused
  by the ledger's double-spend rule at phase 1, before validator logic runs. The marker
  burn (`net_marker == -policy_ins`, one per policy UTxO, the UTxO carrying its own)
  binds each settlement to exactly one policy in batched transactions.
- **Terms freeze at sale.** Changing a datum means spending the UTxO, and the only
  admissible spend burns the policy. Settlement reads no governed config (Invariant S):
  the terms it enforces are the exact bytes written at sale.
- **No relocation arm.** Every vault spend re-emits the pool NFT at the same full
  address, checked above the redeemer dispatch.
- **Payouts land at enterprise addresses.** Claims are permissionlessly assembled, so a
  hostile keeper could otherwise graft its own stake credential onto the payout and farm
  the rewards; forcing the payout address to carry no stake part closes that (A-009).
- **The registry is NFT-authenticated and never co-located.** The vault authenticates
  the registry UTxO by its one-shot NFT and refuses one parked at its own address, so a
  registry-shaped datum cannot pose as governance and an NFT-bearing UTxO cannot count
  as pool backing.
- **Exact value conservation** on every arm, with double-satisfaction blocked by
  per-branch counting and payout non-aliasing.

---

## Security

Aegis custodies pooled capital, so the validators went through a layered assurance
process. The table below was completed across the prior generation (V5 → V12.2+R17);
its regression corpus is carried forward into the V8.2M suite.

| Layer | Coverage | Outcome |
|-------|----------|---------|
| Internal red-team (Rounds 1–17) | Adversarial review of every redeemer, V5 → V12.2+R17 | All findings closed with regression tests |
| External audit | External third party (contracts scope) | TESTNET-**GREEN**; EXT-01…EXT-21 closed |
| Symbolic execution | Z3-backed formal slice of core spend/mint paths | 27/27 properties proven |
| Property / differential fuzzing | Aiken property tests + Python differential fuzzer | No invariant violations |
| **Mainnet live-fire** | 4 autonomous agents vs the live deployment, real ADA | **0 exploits, 0 value extracted** |

**Mainnet live-fire red-team.** Four autonomous agents — three independent, one
orchestrating multi-wallet collusion — replayed the *entire* historical attack corpus
and invented new vectors, building and submitting **160+ real-ADA transactions** to
mainnet across validator-logic, economic/oracle, API, and coordinated-collusion
surfaces. **Every adversarial transaction was rejected on-chain.** Full catalog:
[`redteam/MAINNET_LIVE_FIRE_REDTEAM.md`](redteam/MAINNET_LIVE_FIRE_REDTEAM.md).

The V8.2M generation adds its own gate regime, enforced on every change: per-network
script-size budgets measured on the *applied* artifacts, a hash-surface census that
perturbs each compiled constant and records whether the deployed hashes move, an
identity census binding every identity-shaped constant to a seed, a derivation, or a
chain confirmation, and declared on-chain/off-chain pair checks with parity commands.

The finding-by-finding history across all internal rounds is in
[`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md); each finding
cites the on-chain transaction that demonstrated it pre-fix and the redeploy that rejects
it. Round-specific reports live under [`redteam/`](redteam/).

---

## Deployed on mainnet (V8.2M)

Validators are parameterized in a dependency cascade, so each has a
profile-independent **base** hash and a deployed **applied** hash. The applied hashes
below are confirmed against the chain by the ceremony tooling (each script body fetched
from its reference UTxO and re-hashed) and reproduce byte-for-byte from this source
under the pinned compiler.

| Validator | Applied hash (deployed) |
|-----------|-------------------------|
| `pool_vault` | `0e364fcc7103e87db8931022b54d7a5cf8f076cd5ac34f9ed80a2f08` |
| `pool_stake` | `6362389663890c505fd3336028aa11c436ec66d9f7fc60ab96bcbbef` |
| `oracle_observer` | `ad48febbe5f2eda323c41e999f792433b34d1ac3f258b821dc402400` |
| `eligibility_logic` | `38891cb63a88a9ae91e2805a641a16ed3df35186cb0e029c1b608326` |
| `registry_v2` | `44b5d9029c2b29394be1d496278be8c82304b0d48cd58ffb2083e0ef` |
| `policy_v8` | `f3bd82482f42d3a2e021b5be90ce3c96cdbcf1d72406ad255559ef54` |
| `policy_marker` | `854eee734700448ac3ad0114a679c3f6d0e0276a47f2dffe2941b529` |
| `lp_token` | `aa7a2503416853219f827403a9f51c972e503b8c87e764ad19464571` |

| | |
|---|---|
| Vault address (pool_vault + pool_stake) | `addr1xy8rvn7vwyp7sldcjvgz9d2d0fw03urke4dvxnu7mq9z7zrrvgufvcufp3g9l5envq525ywyxmkxdk0hl3s2h94uh0hslxzswn` |
| Registry address | `addr1w9zttkgzns4jjw2tu82fvfutaryzxp9s6jxdtrlmyzp7pmc9mcekk` |
| Pool NFT | `3bb7c0ff962e9030fc00b0cdaf8f9d541bdba47cd8fae3d4e5eaaad1` (`AEGIS_POOL_V82M`) |
| Registry NFT | `aa85ff9021657da94beb3fbafa1c509a5e0d0d5c6e8aefc65dfe98ef` (`AEGIS_REGISTRY_V82M`) |
| AegisSelf publisher VKH (compile-pinned) | `bb09f43245759995440388db9ef3f8a614246e8da1dd9bd053261347` |
| Governance | 2-of-3 admin · 72 h enact timelock · 24 h cancel cooldown · `EnactUpdate` permissionless |

Oracle feed NFT policies (one-shot, one unit each, held at the publisher):

| Feed | Policy |
|------|--------|
| ADA/USD | `9ea4f1d76c7cc552a0925ac190bb5bc170bcb6d86a1bbb04c5859631` |
| BTC/USD | `99e8fe4f9d2a4a85f5e3f20d37b10048ce54e4a03e56d9fd492163b3` |
| ETH/USD | `a8c5354a4813f2b3f60836839b8842a9422186f4f15511790ec95f9c` |
| USDC/USD | `c855c7619c999f60f023ab513733bb4fc9508d33b0062be353834630` |
| USDT/USD | `531bc8aaac5dbf0a27e4c53d28b327ddfa2e1750ac7de774c791175d` |

Premium floors, term bounds, budgets, and per-pair oracle mandates are **governed
values** in the registry datum, changeable only through the 2-of-3 + timelock state
machine above.

---

## Build & verify

```bash
# Install the pinned compiler
aikup install v1.1.22

cd contracts
aiken check        # 1,162 tests, 0 failures
aiken build        # regenerates plutus.json
```

The committed `plutus.json` is the **preprod** blueprint: the tree keeps
`use aegis/types/preprod as network` in `contracts/lib/aegis/types.ak` at rest, and the
test suite is preprod-pinned. Mainnet artifacts are built by switching that line to
`use aegis/types/mainnet as network` and rebuilding; the deployed hashes above reproduce
from exactly that build under the pinned compiler.

Audit entry points:
- [`contracts/validators/pool_vault.ak`](contracts/validators/pool_vault.ak) and
  [`contracts/lib/aegis/vault.ak`](contracts/lib/aegis/vault.ak) — the pool surface.
- [`contracts/validators/registry_v2.ak`](contracts/validators/registry_v2.ak) and
  [`contracts/lib/aegis/registry_v2.ak`](contracts/lib/aegis/registry_v2.ak) — governance
  and the rails on every governed value.
- [`contracts/lib/aegis/oracle/`](contracts/lib/aegis/oracle/) — the oracle resolvers.
- [`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md) — finding
  history (prior generations).
- [`redteam/`](redteam/) — attack scripts and per-round reports, including the
  [mainnet live-fire report](redteam/MAINNET_LIVE_FIRE_REDTEAM.md).
- [`docs/v12.2_validator_upgrade.md`](docs/v12.2_validator_upgrade.md) — mechanism spec
  of the prior generation, kept for the record.

---

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Security disclosure

See [`SECURITY.md`](SECURITY.md). For new findings, **do not open a public issue** — email
security@fluxpointstudios.com (PGP key on request).
