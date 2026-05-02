# Green-Path Proofs — Validators Working as Intended

The audit report's Round-2 / Round-3 sections cite the on-chain transactions that **failed pre-fix attacks** to demonstrate exploits. This document is the converse: it catalogs the on-chain transactions that **succeeded** as intended, proving every user-facing validator branch executes correctly when given canonical inputs.

Every transaction below is on Cardano preprod and verifiable via [preprod.cardanoscan.io](https://preprod.cardanoscan.io) or Blockfrost. All `valid_contract: true` (where applicable).

---

## 1. Operator deploy flow (5 deployments)

These prove the deploy scripts (`mint_pool_nft.py`, `publish_refs.py`, `init_pool.py`) produce txs the chain accepts. Each deployment version also proves the parameterization cascade (policy hash → pool hash → lp_token hash) is correct end-to-end.

### Latest live deploy — v5

| Step | Tx hash | Verifier link |
|---|---|---|
| `pool_nft` mint (one-shot, A-011) | `75a60bc896ac7a820f844df20a9ee5101355e8e8f3ae81667b29038c6620b53e` | [explorer](https://preprod.cardanoscan.io/transaction/75a60bc896ac7a820f844df20a9ee5101355e8e8f3ae81667b29038c6620b53e) |
| publish ref `policy_validator` (carryover from v4) | `4c8e91df115b4354ad880271ad0e918e013c5653985160350b5643cc14d9c354` | [explorer](https://preprod.cardanoscan.io/transaction/4c8e91df115b4354ad880271ad0e918e013c5653985160350b5643cc14d9c354) |
| publish ref `pool_validator` | `b6d1e7c25b624e7dfc7f6fd9b08b2589e621695e9734eb0dcb5173bf63868b52` | [explorer](https://preprod.cardanoscan.io/transaction/b6d1e7c25b624e7dfc7f6fd9b08b2589e621695e9734eb0dcb5173bf63868b52) |
| publish ref `lp_token_policy` | `714004aefb267b4b5ef5977cc694db4b2f7f3c8a9d16d9368da3e26fc61cf43d` | [explorer](https://preprod.cardanoscan.io/transaction/714004aefb267b4b5ef5977cc694db4b2f7f3c8a9d16d9368da3e26fc61cf43d) |
| `init_pool` (locks NFT + datum) | `6d8dd3cae2a782a397a073a84294120237555caed361a696ebeae0a39282e81e` | [explorer](https://preprod.cardanoscan.io/transaction/6d8dd3cae2a782a397a073a84294120237555caed361a696ebeae0a39282e81e) |

### Historical deploy txs

Prior versions' deploy hashes are in [`deploy/archive/deploy-state.preprod.v0..v4.json`](../deploy/archive/). Each rotation was driven by a closed audit finding (see `SECURITY_AUDIT_REPORT.md` "Hash rotation history").

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

Single-policy underwrite. The headline demo: validator's `donation_ok` clause executes, the treasury donation is in body field 22, the policy output binds to the canonical pool, and the policy's coverage is held in lovelace per A-004. **This is the most important proof** — it exercises the bulk of the v5 invariant set in one tx.

| Tx hash | Coverage | Premium | Donation (body field 22) | Verifier |
|---|---|---|---|---|
| `6ff0ebac89fbcb56823a9f94d38c231269389ee7a31b922f33fb918c2f3a6caa` | 10 ADA | 2 ADA | 10,000 lovelace | [explorer](https://preprod.cardanoscan.io/transaction/6ff0ebac89fbcb56823a9f94d38c231269389ee7a31b922f33fb918c2f3a6caa) |

`valid_contract: true`. Body CBOR includes `body[22] = 10000` — verified via `curl /api/v0/txs/<hash>/cbor` and decoding. Donation amount = exactly `calculate_treasury_cut(2_000_000, 200, 2500) = 10_000`.

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
# Fetch the pool_validator's reference script
curl -H "project_id: <YOUR_BLOCKFROST_KEY>" \
  https://cardano-preprod.blockfrost.io/api/v0/scripts/c7cf3d90e885ddc54d1187edd491d68d1e1c2bd5cb7b2c986f632377/cbor

# Recompute the hash with cardano-cli or any UPLC tooling — should match.
```

The committed `contracts/plutus.json` is the **parameter-free** blueprint; production deploys re-parameterize via `aiken blueprint apply`. Your rebuild from source should produce a `plutus.json` with byte-identical script bytes (modulo parameterization order). Compile is deterministic given Aiken `v1.1.21+stdlib v3.0.0`.

---

## 5. Test parity

| Branch | Aiken green test | On-chain proof |
|---|---|---|
| `pool_nft.mint` | `pool_nft_logic_*` | ✅ 5 deploys |
| `policy_validator` byte-stability across deploys | (n/a) | ✅ ref UTxO `4c8e91df...c14d9c354` carried v4 → v5 |
| `pool.Underwrite` + treasury donation | `green_a_021_*` | ✅ `6ff0ebac...` |
| `pool.BatchUnderwrite` + treasury donation aggregate | `green_a_021_batch_underwrite_aggregate_donation_correct`, `green_a_022_*`, `green_a_025_*` | ✅ `b1f1ec3e...` |
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
