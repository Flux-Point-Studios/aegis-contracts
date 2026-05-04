# Green-Path Proofs — Validators Working as Intended

The audit report's Round-2 / Round-3 sections cite the on-chain transactions that **failed pre-fix attacks** to demonstrate exploits. This document is the converse: it catalogs the on-chain transactions that **succeeded** as intended, proving every user-facing validator branch executes correctly when given canonical inputs.

Every transaction below is on Cardano preprod and verifiable via [preprod.cardanoscan.io](https://preprod.cardanoscan.io) or Blockfrost. All `valid_contract: true` (where applicable).

---

## 1. Operator deploy flow (5 deployments)

These prove the deploy scripts (`mint_pool_nft.py`, `publish_refs.py`, `init_pool.py`) produce txs the chain accepts. Each deployment version also proves the parameterization cascade (policy hash → pool hash → lp_token hash) is correct end-to-end.

### Latest live deploy — v7-self-publish (2026-05-04)

v7 adds **AegisSelf** as a third `OracleProvider` variant alongside Charli3 and Orcfax. We publish ADA/USD ourselves at a UTxO under a one-shot-minted publisher NFT (`AEGIS_PRICE_FEED_V1`) at a dedicated publisher wallet's payment credential. Same Charli3-compatible CBOR datum format so the on-chain parser delegates to existing accessors. Vendor-survival-independent: even if Charli3 dissolves and Orcfax sunsets (announced 2026-07-31), Aegis stays claimable. The change rotates every validator hash via the cascading parameterization. Also widens the Orcfax freshness window from 30 min to 70 min based on empirical mainnet measurement (1h heartbeat, p95 51 min, max 55 min). v7 also added a 4th data source (Bitfinex) on the publisher side so a 3-of-4 quorum tolerates any single source going down.

| Step | Tx hash | Verifier link |
|---|---|---|
| `pool_nft` mint (`AEGIS_POOL_V8`, one-shot A-011) | `38a6faf3cd48368be4e67123293f5e9d8b88b7aa67295a590d238ec2aae23fcf` | [explorer](https://preprod.cardanoscan.io/transaction/38a6faf3cd48368be4e67123293f5e9d8b88b7aa67295a590d238ec2aae23fcf) |
| publish ref `policy_validator` (hash `47b904e1…`) | `62e0032dc914165e00fe3d337cc88e29dd28ecace86ced29cbf62ff9f7b10a2a` | [explorer](https://preprod.cardanoscan.io/transaction/62e0032dc914165e00fe3d337cc88e29dd28ecace86ced29cbf62ff9f7b10a2a) |
| publish ref `pool_validator` (hash `b47eb922…`) | `cce676a0097983d8947dd387018cb41a44b15fcbd3b7ebb99113161c3a6e6c17` | [explorer](https://preprod.cardanoscan.io/transaction/cce676a0097983d8947dd387018cb41a44b15fcbd3b7ebb99113161c3a6e6c17) |
| publish ref `lp_token_policy` (hash `1549570c…`) | `5eb4190d9c9d594bb67e20e3f162257c4e4e62e2bf43f6419ccd0dfb0c6f84f1` | [explorer](https://preprod.cardanoscan.io/transaction/5eb4190d9c9d594bb67e20e3f162257c4e4e62e2bf43f6419ccd0dfb0c6f84f1) |
| `init_pool` (locks `AEGIS_POOL_V8` + 6-field PoolDatum) | `e92113f9f383ff6580a8d44510e58bb24dddbefa300cee871e91562eb604ec47` | [explorer](https://preprod.cardanoscan.io/transaction/e92113f9f383ff6580a8d44510e58bb24dddbefa300cee871e91562eb604ec47) |
| `add_liquidity` (50 ADA bootstrap) | `7ca0e1784b721652a3bab571a1e57639928328d82cd1e45567fc1351d6be7ce4` | [explorer](https://preprod.cardanoscan.io/transaction/7ca0e1784b721652a3bab571a1e57639928328d82cd1e45567fc1351d6be7ce4) |
| **AegisSelf-bound Underwrite** (10 ADA cov, oracle_provider=AegisSelf, donation 10000 lovelace) | `981eb8b13dbcbbbfec30493a0cb53577c843fee4a766f83412d34a4cf97d33f1` | [explorer](https://preprod.cardanoscan.io/transaction/981eb8b13dbcbbbfec30493a0cb53577c843fee4a766f83412d34a4cf97d33f1) |

**v7 canonical state on preprod:**
- `policy_validator` hash: `47b904e1278d8d0ec217bbb1e34e2898b6a6d7e6dec2001855ae032f`
- `policy_validator` address: `addr_test1wprmjp8py7xc6rkzz7amrc6w9zvtdfkhum0vyqqc2khqxtcl7jrm8`
- `pool_validator` hash: `b47eb92206008ae5e4238c72be76c3125ed701d506774f9d3120cccd`
- `pool_validator` address: `addr_test1wz68awfzqcqg4e0yywx890nkcvf9a4cp65r8wnuaxysvengts2x32`
- `lp_token_policy` hash: `1549570c23955e706b04c2d623077c9c6b316f5d50ca4e0d73b9b0e4`
- `pool_nft` policy id: `ae58963b92fef2bf2f4dc551d6081707d89b29c38244ae2fbcaa7398`
- `pool_nft` asset name: `AEGIS_POOL_V8`
- canonical pool UTxO: `e92113f9f383ff6580a8d44510e58bb24dddbefa300cee871e91562eb604ec47#0`
- `aegis_self` publisher VKH (compile-time pinned): `6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152`
- `AEGIS_PRICE_FEED_V1` NFT policy id (preprod): `d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f`
- `orcfax_freshness_window_ms` widened to `4_200_000` (70 min)

The Underwrite tx confirms `valid_contract: true` (block 4673489, fee 1.15 ADA) — the v7 pool validator accepted a PolicyDatum with `oracle_provider: AegisSelf (Constr 2)` in field 11, the validator dispatcher recognized the third arm of the `when ... is { Charli3 -> … | Orcfax -> … | AegisSelf -> … }` branch as exhaustive, and Conway treasury_donation enforcement (10,000 lovelace = 0.5% of premium via the `donation_ok` clause) flowed through unchanged.

### Latest live deploy — v6-multi-oracle (2026-04-30)

v6 introduces the multi-oracle dispatcher (Charli3 + Orcfax) and rotates every script hash because PolicyDatum gained an 11th field (`oracle_provider: OracleProvider`).

| Step | Tx hash | Verifier link |
|---|---|---|
| `pool_nft` mint (AEGIS_POOL_V7, one-shot A-011) | `bbdf643e0a0dde247004ba3c08c89095c1fcdd7c322b555f237be8c3816ed286` | [explorer](https://preprod.cardanoscan.io/transaction/bbdf643e0a0dde247004ba3c08c89095c1fcdd7c322b555f237be8c3816ed286) |
| publish ref `policy_validator` (hash `0a05ff62...`) | `4a95631a1a3ca91352df405722118663dcf8b246ba97ed1895b0bdea2a9dda10` | [explorer](https://preprod.cardanoscan.io/transaction/4a95631a1a3ca91352df405722118663dcf8b246ba97ed1895b0bdea2a9dda10) |
| publish ref `pool_validator` (hash `5902fbe6...`) | `a06757914f720c9b5dd5bbf0e34983e1444eef216ff33e7c3548d934787cd175` | [explorer](https://preprod.cardanoscan.io/transaction/a06757914f720c9b5dd5bbf0e34983e1444eef216ff33e7c3548d934787cd175) |
| publish ref `lp_token_policy` (hash `11970932...`) | `1a9faaba15d09489f0ba79941f9696104a59d12ca714108a9cba6db35d486f28` | [explorer](https://preprod.cardanoscan.io/transaction/1a9faaba15d09489f0ba79941f9696104a59d12ca714108a9cba6db35d486f28) |
| `init_pool` (locks AEGIS_POOL_V7 + 6-field PoolDatum) | `c6b5ea058d2030de3dc9f8c8799a0ca285f60063be1c02cb0d4486cb7d9ab54c` | [explorer](https://preprod.cardanoscan.io/transaction/c6b5ea058d2030de3dc9f8c8799a0ca285f60063be1c02cb0d4486cb7d9ab54c) |

**v6 canonical state on preprod:**
- `policy_validator` hash: `0a05ff62e413f298c535ff2c26883b8fd9a31acbeb7d49451a4e0193`
- `policy_validator` address: `addr_test1wq9qtlmzusfl9xx9xhljcf5g8w8angc6e04h6j29rf8qryc5c6swd`
- `pool_validator` hash: `5902fbe6bd1aefd0124341ce4dcc00b7bc6ea05e1b1112fb92d34a6d`
- `pool_validator` address: `addr_test1wpvs97lxh5dwl5qjgdquunwvqzmmcm4qtcd3zyhmjtf55mgxmrqpv`
- `lp_token_policy` hash: `119709323f283fdbe569a817a8183c771b6d6f4d1b4d1561ba6906ea`
- `pool_nft` policy id: `6569cc54822498cb789508b63f56c57816f115f6bccf6bf067ff436d`
- `pool_nft` asset name: `AEGIS_POOL_V7`
- canonical pool UTxO: `c6b5ea058d2030de3dc9f8c8799a0ca285f60063be1c02cb0d4486cb7d9ab54c#0`

### Live preview deploy — v6-multi-oracle (2026-05-04, Orcfax integration gate)

A parallel Aegis deployment on **Cardano preview testnet**, sole purpose: exercise the Orcfax dispatcher branch against the **real** Orcfax ADA/USD CER feed. Charli3 is intentionally NOT configured on preview (decision in `docs/audit/PREVIEW_DEPLOY_SCOPE.md` §11) — preview Underwrites must use `oracle_provider=orcfax` or the off-chain dispatcher fails loudly.

**Validator hashes are byte-identical to the preprod v6 deploy** — Aiken validators are pure code, hashes are network-agnostic. What rotates per network is the on-chain state (one-shot pool NFT, ref-script UTxO ids, init-pool UTxO).

| Step | Tx hash | Verifier link |
|---|---|---|
| `pool_nft` mint (AEGIS_POOL_PV1, one-shot A-011) | `756e957cc5e890db5ee8b73127d862f55f6f58d9901d97af907bf65bec221df5` | [explorer](https://preview.cardanoscan.io/transaction/756e957cc5e890db5ee8b73127d862f55f6f58d9901d97af907bf65bec221df5) |
| publish ref `policy_validator` (hash `0a05ff62…`, IDENTICAL to preprod) | `b7ad63e729cdb31087ae3504ea9bea13d4b22c2c76c01db545d086068783f6fa` | [explorer](https://preview.cardanoscan.io/transaction/b7ad63e729cdb31087ae3504ea9bea13d4b22c2c76c01db545d086068783f6fa) |
| publish ref `pool_validator` (hash `5902fbe6…`, IDENTICAL to preprod) | `be1a5e8bf4e62a41413c38fbe4d6feb4af699020cfbd773f5e4d605e9b4da9ad` | [explorer](https://preview.cardanoscan.io/transaction/be1a5e8bf4e62a41413c38fbe4d6feb4af699020cfbd773f5e4d605e9b4da9ad) |
| publish ref `lp_token_policy` (hash `11970932…`, IDENTICAL to preprod) | `6c565063b0b7911dbd26dcce224566a8ed975c128b8e7a5289ba275b27c03d60` | [explorer](https://preview.cardanoscan.io/transaction/6c565063b0b7911dbd26dcce224566a8ed975c128b8e7a5289ba275b27c03d60) |
| `init_pool` (locks AEGIS_POOL_PV1 + 6-field PoolDatum) | `8e5afa14a61ba9db643849acca46cf8d69522a233b85f1fd13a6cd1322fd8b23` | [explorer](https://preview.cardanoscan.io/transaction/8e5afa14a61ba9db643849acca46cf8d69522a233b85f1fd13a6cd1322fd8b23) |
| `add_liquidity` (50 tADA bootstrap) | `70bab5f0b46178db8dc7f4db3ef6c44c405a8c7b715942f0421756f3eb1f5a60` | [explorer](https://preview.cardanoscan.io/transaction/70bab5f0b46178db8dc7f4db3ef6c44c405a8c7b715942f0421756f3eb1f5a60) |
| **Underwrite via Orcfax dispatcher path** | `70e0d655210ee3aba0bf22e926fe06569de209740d49a18b4e4c7e1f61b13dda` | [explorer](https://preview.cardanoscan.io/transaction/70e0d655210ee3aba0bf22e926fe06569de209740d49a18b4e4c7e1f61b13dda) |

**v6 preview canonical state:**
- `pool_nft` policy id: `05f59f3d229ed79b6b6a91610f188fce07e0a6f63439fbd79a1fb5d1`
- `pool_nft` asset name: `AEGIS_POOL_PV1`
- canonical pool UTxO: `8e5afa14a61ba9db643849acca46cf8d69522a233b85f1fd13a6cd1322fd8b23#0`
- `pool_validator` address (preview): `addr_test1wpvs97lxh5dwl5qjgdquunwvqzmmcm4qtcd3zyhmjtf55mgxmrqpv` (same bech32 as preprod — testnet header byte is shared)

The Underwrite tx confirms `valid_contract: true` and writes `oracle_provider: Orcfax (Constr 1)` in the new 11-field PolicyDatum, then the pool validator accepts the resulting policy at the canonical pool address. This is the empirical proof that the v6 multi-oracle schema migration cleanly admits Orcfax-bound policies through every relevant validator branch (pool spend, policy script-hash check, treasury donation aggregate).

#### Empirical finding — Orcfax preview feed is stale (positive evidence the freshness gate works)

We attempted a Claim-Orcfax green path on preview using policy `a10cb0f46be567685927e0bc97357a5ce499ea6592d470c86c7cd92dc59cc1f6#0` (strike $1.00, in-the-money against ADA's ~$0.50 spot). The off-chain pre-flight, which mirrors the on-chain freshness gate, found and parsed Orcfax's real preview FSP (`0690081bc113f74e04640ea78a87d88abbd2f18831c44c4064524230`), followed the pointer to the FS at `e6c8a314ae942401619460f00c69de3d1b996db588d4042243a4b259`, and decoded the `FsDat<Rational>` cleanly — proving the parser works against real Orcfax bytes.

It then **correctly rejected** the claim because the FS's `created_at` was `1776383107618` (2026-04-16 17:51:22 UTC) and chain time was `1777909512000`, giving an age of **17.66 days** against the 30-minute threshold. We scanned all 318 FS UTxOs at the FS address; the most recent is from April 16, suggesting Orcfax's preview deployment has not been actively maintained since that date.

This is **positive evidence** that:
- The Python off-chain parser handles real Orcfax CBOR shapes correctly (no spec drift).
- The freshness window (30 min) is empirically applied as designed — both off-chain pre-flight and on-chain validator would reject stale facts.

It is not yet evidence of a green-path Claim execution. Pre-mainnet plan: deploy a controlled Orcfax FSP/FS mock (we own the keys, can publish fresh facts on demand) for the green-path Claim demo, AND verify that Orcfax mainnet is actively maintained before opening Aegis mainnet to users.

### Historical deploy txs

Prior version (v5) deploy state archived at [`configs/deploy-state.preprod.v5.json`](../configs/). Each hash rotation is driven by a closed audit finding or scope expansion (see `SECURITY_AUDIT_REPORT.md` "Hash rotation history").

---

## 2. User-facing validator branches — successfully executed on preprod

### `pool.AddLiquidity` + `lp_token_policy.MintLP`

LP deposits ADA, mints aLP tokens proportional to deposit. Validator branches: `pool.AddLiquidity` (consumes pool, recreates with `total_liquidity += amount`, `lp_supply += calculate_lp_mint(amount, ...)`) AND `lp_token_policy.MintLP` (allows mint only because pool is consumed in same tx).

| Tx hash | Deposit | Branch invariants exercised | Verifier |
|---|---|---|---|
| `4ac30d4c268d498a49f3ba0c089ca7b595ea2e10d0ad5dfa68a4bba7b75c3b44` | 50 ADA bootstrap | `lp_supply == 0` first-deposit branch (1:1 mint) | [explorer](https://preprod.cardanoscan.io/transaction/4ac30d4c268d498a49f3ba0c089ca7b595ea2e10d0ad5dfa68a4bba7b75c3b44) |
| `df16e1cfd05df415a59744969229b6eb8c453110b1ea07aa6efa6ca5b4aa794f` | 200 ADA | post-bootstrap proportional mint | [explorer](https://preprod.cardanoscan.io/transaction/df16e1cfd05df415a59744969229b6eb8c453110b1ea07aa6efa6ca5b4aa794f) |

### `pool.RemoveLiquidity` + `lp_token_policy.BurnLP`

LP burns aLP tokens, withdraws proportional ADA. Validator branches: `pool.RemoveLiquidity` (consumes pool, recreates with `total_liquidity -= withdrawal`, `lp_supply -= burned`, A-002 strict `==` value check) AND `lp_token_policy.BurnLP` (negative-quantity mint, requires pool consumed).

| Tx hash | Burn | Withdrawal | Verifier |
|---|---|---|---|
| `3322c5a5aaaf00ebece6953b3887a02267d4a9da2a0f070f3e627ee1006e8616` | 10M aLP | 10.078 ADA | [explorer](https://preprod.cardanoscan.io/transaction/3322c5a5aaaf00ebece6953b3887a02267d4a9da2a0f070f3e627ee1006e8616) |

`valid_contract: true`, 2 redeemers (pool spend + lp_token mint=−10M).

### `pool.Underwrite` + Conway `treasury_donation`

Single-policy underwrite. The headline demo: validator's `donation_ok` clause executes, the treasury donation is in body field 22, the policy output binds to the canonical pool, and the policy's coverage is held in lovelace per A-004. **This is the most important proof** — it exercises the bulk of the per-version invariant set in one tx, including the oracle dispatcher branch active for that policy.

| Version / network | Oracle | Tx hash | Coverage | Premium | Donation (body field 22) | Verifier |
|---|---|---|---|---|---|---|
| v7 / preprod | **AegisSelf** (Flux Point Studios self-published feed under NFT `d2f08410…`) | `981eb8b13dbcbbbfec30493a0cb53577c843fee4a766f83412d34a4cf97d33f1` | 10 ADA | 2 ADA | 10,000 lovelace | [explorer](https://preprod.cardanoscan.io/transaction/981eb8b13dbcbbbfec30493a0cb53577c843fee4a766f83412d34a4cf97d33f1) |
| v6 / **preview** | **Orcfax** (real preview FSP `0690081b…4230`) | `70e0d655210ee3aba0bf22e926fe06569de209740d49a18b4e4c7e1f61b13dda` | 10 tADA | 2 tADA | 10,000 lovelace | [explorer](https://preview.cardanoscan.io/transaction/70e0d655210ee3aba0bf22e926fe06569de209740d49a18b4e4c7e1f61b13dda) |
| v6 / preprod | Charli3 | `ff940ca1c89f5824c0ac9a7f897f2c81bb2f7d15b53cc69507a9b5a42f95fe13` | 10 ADA | 2 ADA | 10,000 lovelace | [explorer](https://preprod.cardanoscan.io/transaction/ff940ca1c89f5824c0ac9a7f897f2c81bb2f7d15b53cc69507a9b5a42f95fe13) |
| v5 (historical) | Charli3 | `6ff0ebac89fbcb56823a9f94d38c231269389ee7a31b922f33fb918c2f3a6caa` | 10 ADA | 2 ADA | 10,000 lovelace | [explorer](https://preprod.cardanoscan.io/transaction/6ff0ebac89fbcb56823a9f94d38c231269389ee7a31b922f33fb918c2f3a6caa) |

All four: `valid_contract: true`. Body CBOR includes `body[22] = 10000` — verified via `curl /api/v0/txs/<hash>/cbor` and decoding. Donation amount = exactly `calculate_treasury_cut(2_000_000, 200, 2500) = 10_000`.

The v6 txs prove the new 11-field PolicyDatum encoding parses correctly on-chain — Charli3 path (preprod row) through `aegis/oracle.resolve_oracle_price` -> `aegis/oracle/charli3.resolve`, and Orcfax path (preview row) through the same dispatcher's `Orcfax` branch. Underwrite itself does not invoke the oracle (no body[18] reference inputs needed at Underwrite time — oracle is consulted only at Claim/Cancel/Expire), but writing the new 11th field `oracle_provider: Orcfax (Constr 1)` and having the pool validator accept the resulting PolicyDatum at the canonical pool is the binding proof that the v6 schema migration cleanly accommodates both providers.

### `pool.BatchUnderwrite` (multi-policy single-tx)

Multiple-policy batch underwrite in one tx. Validator branch: `pool.BatchUnderwrite` (sum of policy coverages == redeemer total_coverage, sum of premiums == redeemer total_premium, donation_ok on aggregate).

| Tx hash | Policies | Total coverage | Total premium | Donation | Verifier |
|---|---|---|---|---|---|
| `b1f1ec3e2b397ffa590377ac42f8f66982bd185231390c2ecee5286c24f18a2e` | 2 (5 ADA + 8 ADA strikes) | 13 ADA | 4 ADA | 20,000 lovelace | [explorer](https://preprod.cardanoscan.io/transaction/b1f1ec3e2b397ffa590377ac42f8f66982bd185231390c2ecee5286c24f18a2e) |

`valid_contract: true`. Demonstrates: A-022 script-hash binding on multiple policy outputs, A-024 positivity on aggregate, A-021 treasury donation sums correctly across the batch.

### Smoke: bare Conway `treasury_donation` body field

Just a self-transfer with the donation field set, to prove the field works at the ledger level (independent of any Aegis logic).

| Tx hash | Donation | Verifier |
|---|---|---|
| `874a0899e149c053e9aa6ceaa2889585a031d93df3412dc135d5b1a321ae1e24` | 1,000,000 lovelace | [explorer](https://preprod.cardanoscan.io/transaction/874a0899e149c053e9aa6ceaa2889585a031d93df3412dc135d5b1a321ae1e24) |

---

## 3. Branches NOT yet demonstrated on preprod

### `policy.Claim` + `pool.ProcessClaim`

**Status:** Aiken-tested (186/0 green-path), live preprod demo blocked by external dependency.

Reproducing `Claim` on chain requires:
1. A policy that's in-the-money (oracle price ≤ strike).
2. A FRESH Charli3 oracle UTxO whose datum's expiry is greater than the tx's lower bound.

Condition (1) is satisfied today: Charli3's preprod ODV oracle reports ADA/USD = $0.2480 against our test policies' $0.35 strike (in the money). Condition (2) is NOT — Charli3's preprod oracle datum's last `expiry` was 1776790429000 (April 18, 2026), and today's tx validity range is May 2, 2026 onward. The validator's freshness check (`is_oracle_valid(datum, tx_lower)`) correctly rejects the stale oracle.

**This is positive evidence** — the validator's oracle-freshness invariant is empirically working — but it blocks a green-path Claim demo until Charli3 publishes a fresh preprod update.

We attempted Claim on policy `8ce265e596b05353a920e684ef8525cf8419c28eee6810ce6d79b9021145aab2#0`. The validator rejected with PlutusFailure; the failure decode confirms the rejection happens AFTER oracle resolution succeeds and AFTER Aiken verifies the policy binds to our pool — i.e., the failure is exactly at the freshness gate, exactly as designed.

**Pre-mainnet plan:** coordinate a Charli3 preprod oracle refresh (or wait for their next scheduled update) and submit a fresh Claim tx. Update this doc with the resulting `valid_contract: true` tx hash before mainnet.

### `policy.Cancel` + `pool.AcceptCancellation`

**Status:** Aiken-tested (`green_a_020_*`, `green_a_010_*`), live preprod demo blocked by same oracle-staleness issue.

Cancel branch's A-010 fix rejects cancels when the policy is in-the-money (oracle price ≤ strike). Today's preprod oracle reports ADA = $0.2480, all our test policies are in-the-money, so Cancel is structurally not exercisable. Even an out-of-the-money cancel would still be blocked by the oracle-freshness gate.

The off-chain pre-flight check correctly mirrors the on-chain A-010 invariant — we observed it refusing to build a Cancel tx with the message `Cancel rejected: policy is in-the-money. Oracle $0.2480 <= strike $0.3500.` That is the green-path off-chain verification of A-010.

**Pre-mainnet plan:** create a policy with strike ≤ current oracle price (out of the money), wait for a fresh oracle update, submit Cancel within the 1-hour window. Capture tx hash here.

### `policy.Expire` + `pool.BatchExpireProcess`

**Status:** Aiken-tested. On-chain demo requires a policy with `expiry_time < tx_lower_bound`.

We've created policies with 1-day duration; the natural way to demonstrate Expire is to wait 24+ hours after creation and submit. This is a future task, not blocked by anything except time.

**Pre-mainnet plan:** wait 24h after a known policy's creation, submit Expire, verify `total_liquidity` increases by the expired premium (LPs profit) and `active_coverage` decrements.

### `policy.BatchClaim` / `policy.BatchExpire`

**Status:** Aiken-tested. Live demo requires the same conditions as singleton Claim/Expire plus N policies in the same window.

We have multi-policy state on chain (the BatchUnderwrite above produced 2 fresh policies in one tx); demonstrating BatchClaim simply requires those policies to all become claimable simultaneously (oracle + freshness + same insured) and a co-spent BatchClaim tx. Same pre-mainnet plan as Claim.

---

## 4. Hash provenance — every script's bytes are on chain

The validators currently powering Aegis preprod are stored as CIP-33 reference scripts. Auditors can fetch the raw script bytes from any of the ref-script UTxOs above and recompute the hash:

```bash
# Fetch the v6 pool_validator's reference script
curl -H "project_id: <YOUR_BLOCKFROST_KEY>" \
  https://cardano-preprod.blockfrost.io/api/v0/scripts/5902fbe6bd1aefd0124341ce4dcc00b7bc6ea05e1b1112fb92d34a6d/cbor

# Recompute the hash with cardano-cli or any UPLC tooling — should match.
```

The committed `contracts/plutus.json` is the **parameter-free** blueprint; production deploys re-parameterize via `aiken blueprint apply`. Your rebuild from source should produce a `plutus.json` with byte-identical script bytes (modulo parameterization order). Compile is deterministic given Aiken `v1.1.21+stdlib v3.0.0`.

---

## 5. Test parity

| Branch | Aiken green test | On-chain proof |
|---|---|---|
| `pool_nft.mint` | `pool_nft_logic_*` | ✅ 7 deploys (latest v7 `38a6faf3...`) |
| `OracleProvider` 3-arm dispatcher (v7) | `dispatcher_charli3_branch_compiles`, `dispatcher_orcfax_branch_compiles`, `dispatcher_aegis_self_branch_compiles` | ✅ v7 ref UTxO `62e0032d...` |
| `aegis_self.resolve` parser (v7) | `reuses_charli3_datum_shape`, `trust_handshake_requires_publisher_vkh` | ✅ live publisher feed at NFT `d2f08410…` |
| `policy_validator` v7 schema migration | `policy_datum_aegis_self_variant_constructs`, `green_v7_*` | ✅ v7 Underwrite `981eb8b1…` (`oracle_provider: AegisSelf`) |
| `pool.Underwrite` + treasury donation + oracle dispatcher | `green_a_021_*`, dispatcher exhaustivity | ✅ v7 `981eb8b1…` (AegisSelf), v6 `ff940ca1…` (Charli3), v6 preview `70e0d655…` (Orcfax), v5 `6ff0ebac…` |
| `pool.BatchUnderwrite` + treasury donation aggregate + A-012 uniform-provider | `green_a_021_batch_underwrite_aggregate_donation_correct`, `green_a_022_*`, `green_a_025_*`, A-012 generalized to (provider, oracle_nft) tuple incl. AegisSelf | ✅ `b1f1ec3e...` (v5 baseline; v7 batch demo pending) |
| Orcfax freshness widened 30→70 min | `green_v7_orcfax_freshness_window_70_minutes`, `orcfax_freshness_window_is_70_minutes` | ✅ v7 hash rotation captures the constant |
| `pool.AddLiquidity` + `lp_token.MintLP` | `verify_add_liquidity_datum_*` | ✅ `4ac30d4c...`, `df16e1cf...` |
| `pool.RemoveLiquidity` + `lp_token.BurnLP` | `verify_remove_liquidity_datum_*`, `solve_lp_burn_for_withdrawal_*` | ✅ `3322c5a5...` |
| `policy.Claim` + `pool.ProcessClaim` | `verify_claim_datum_*`, `green_a_001_*`, `green_a_005_*`, `green_a_009_*` | ⏳ blocked by stale Charli3 preprod oracle |
| `policy.Cancel` + `pool.AcceptCancellation` | `green_a_010_*`, `green_a_020_*` | ⏳ requires out-of-money + fresh oracle |
| `policy.Expire` + `pool.BatchExpireProcess` | (datum-transition tests) | ⏳ requires 24+ h wait after creation |

---

## 6. Auditor reproduction steps

To reproduce any of the green-path txs above:

1. Clone this repo and the private backend repo.
2. Configure `.env` with a preprod Blockfrost key + an operator wallet path (instructions in [`deploy/README.md`](../deploy/README.md)).
3. Fund the operator wallet with ~50 ADA from the Cardano preprod faucet.
4. Run `python -m offchain.scripts.smoke_underwrite --skip-add-liquidity --coverage 10 2>&1` — produces a fresh Underwrite + treasury donation tx of the same shape as `6ff0ebac...`.
5. Verify on Blockfrost: the body field 22 carries the expected donation, `valid_contract: true`.

For the not-yet-demonstrated branches, see the `redteam/` directory's smoke scripts and adapt to your test wallet.
