# Aegis V12.2 + Round-7 — Auditor Handoff

**Date:** 2026-05-12
**From:** Flux Point Studios (`security@fluxpointstudios.com`)
**Branch (this repo):** [`feat/v12.2-hybrid-fee-r7`](https://github.com/Flux-Point-Studios/aegis-contracts/tree/feat/v12.2-hybrid-fee-r7)
**Live on:** Cardano preprod (mainnet candidate, awaiting your sign-off)
**Test posture:** 351/351 Aiken tests green, 0 failures

---

## TL;DR

V12.2 is the active mainnet candidate. It extends V12 (which you reviewed on `feat/v12-multi-pair-oracle`) with four coordinated changes, then a Round-7 follow-up fixed one HIGH (Indigo BatchClaim non-exhaustive switch) and one MED (cancel-cycle LP drain at preprod min_premium floor). Both fixes are in-tree, on-chain, and regressioned against rounds 1-6.

This branch is ready for your review. We'd like sign-off on V12.2 + R7 as the mainnet-deployable version.

---

## Reading order

1. **[`README.md`](../../README.md)** — file tree, hash table, quick-start commands.
2. **[`docs/v12.2_validator_upgrade.md`](../v12.2_validator_upgrade.md)** — full 14-section V12.2 + R7 spec.
   - §1 — worked fee examples (20-ADA / 100-ADA / 500-ADA premiums with and without partner).
   - §2.6 — Indigo on-chain architecture (3-layer trust handshake, 4 mainnet iAssets + 4 preprod mocks, datum CBOR shape).
   - §3 — per-redeemer changes (Underwrite + AcceptCancellation + BatchUnderwrite).
   - §7 + §7.1.1 — env rotation tables, including R7-B cascaded hash rotation.
   - §8 — 10 property-style test invariants + 1 R7-B regression invariant.
   - §13 — spec-vs-code resolutions (incl. Aiken-on-Windows silent-failure gotchas).
3. **[`redteam/V12.2_ROUND_7_REPORT.md`](../../redteam/V12.2_ROUND_7_REPORT.md)** — Round 7 findings + regression vs rounds 1-6.
4. **[`docs/audit/SECURITY_AUDIT_REPORT.md`](../audit/SECURITY_AUDIT_REPORT.md)** — full audit history including V12 + V12.2 + R7 sections appended at the bottom.

---

## What changed since V12

### V12.2 — four coordinated changes (2026-05-11)

| Change | Files | What |
|---|---|---|
| **A. Hybrid fee model** | `pricing.ak::calculate_fee_total`, `pricing.ak::calculate_protocol_fee_split`, `pool.ak` Underwrite + AcceptCancellation + BatchUnderwrite branches | `fee_total = max(min_utxo_lovelace, raw_fee)` carved from premium. Pool grows by `premium − fee_total`. Replaces V12's confusing "team min-utxo floor pad" output emitted by the submitter. LP absorbs the floor shortfall on small premiums (≤20 ADA); identical to a pure 2% fee from 100 ADA up. |
| **B. Silent partner_cut absorb** | `pricing.ak::calculate_protocol_fee_split` | When `partner_cut_raw < min_utxo_lovelace`, partner output is dropped and team_cut absorbs the full fee_total. Datum still records `partner_address` for analytics. Invariant: `team_cut + partner_cut == fee_total` exactly. |
| **C. Indigo as 4th OracleProvider** | `types.ak::OracleProvider { Indigo }`, `types.ak::indigo_canonical_nfts`, `types.ak::indigo_oracle_script_hashes`, `oracle/indigo.ak` (NEW), `oracle.ak::resolve_oracle_price` (4-arm dispatcher) | Constructor index 3. Direct-binds Indigo's on-chain price-oracle UTxOs for 4 iAssets (iUSD/iBTC/iETH/iSOL). 3-layer trust handshake: NFT pin + paired script credential pin + single-token-of-policy. Datum: `OracleDatum { price: PriceData { price: Int }, expiration: PosixTimeMs }`. Freshness: `tx_lower <= datum.expiration`. |
| **D. Soft-disable Charli3 + Orcfax** | `aegis_self.ak::is_canonical_oracle_nft` (returns `False` for both providers' canonical lists) | Parser modules + sum-type variants remain in tree. No new policy can be created against either provider — rejected at the canonical-NFT gate. Reactivation is a 2-line diff. |

### Round 7 — V12.2 red-team (2026-05-12)

Two internal red-team sessions on the V12.2 branch produced 2 fixed findings + 1 INFO:

| Finding | Severity | Status | Where | What |
|---|---|---|---|---|
| **R7-A** | MED | **FIXED** | `types.ak:290-307` (`min_premium` constant) | At preprod's `min_premium = 2_000_000`, `raw_fee = 0.04 ADA < min_utxo` so `fee_total` is floored to 2 ADA. Pool gains 0 at underwrite, pool loses 3.8 ADA at cancel (refund + cancellation_fee_bps). Asymmetric drain ratio: attacker burns 0.2 ADA, LP loses 3.8 ADA per cycle (19×). **Fix:** per-network `min_premium` comment-toggle; mainnet at 100_000_000 (threshold where `raw_fee >= min_utxo` so Hybrid floor stops kicking in). Preprod stays at 2_000_000 (dev-convenient; small TVL bounds impact). Tests: `redteam_round_7_r7_a_min_premium_cancel_costs_lp_3_8_ada`, `redteam_round_7_r7_a_min_premium_cycle_net_pool_delta_negative`, `redteam_round_7_r7_a_attacker_burn_below_lp_loss`. |
| **R7-B** | HIGH | **FIXED** | `validators/policy.ak:84-99` (`batch_oracles_uniform`) | Switch listed Charli3 / Orcfax / AegisSelf arms with `_ -> False` wildcard; an Indigo BatchClaim fell through to `False` and the entire batch tx rejected. Single-policy Indigo claim was unaffected (sentinel `seen` guard skips the equality check for the first element). **Pure availability defect, no fund extraction**. **Fix:** added `(Indigo, Indigo) -> True` as the 4th arm + explicit `Indigo` variant import in `policy.ak`'s `use aegis/types.{...}` block (the import was the silent-failure trigger in §13 R7-INFO-1). Test: `redteam_round_7_r7_b_batch_oracles_uniform_accepts_indigo_pair` + regression-lock `..._accepts_aegis_self_pair`. |
| **R7-INFO-1** | INFO | Documented | `docs/v12.2_validator_upgrade.md` §13 | Aiken-on-Windows silent failure: `aiken check` exits 1 with empty stdout when a sum-type variant is missing from a consumer's `use aegis/types.{...}` import. Same gotcha as Wave 2's `calculate_fee_total` miss. Documented for future reviewers. |

**Regression vs rounds 1-6**: full re-run of prior security tests, no regressions. Round 1 (initial) → Round 6 (red-team round 6) all stay green.

---

## What changed on chain (preprod)

### V12.2 Wave 4.3 (deployed 2026-05-11)

Pre-R7 V12.2 deploy. Pool NFT asset `AEGIS_POOL_V12_2` (policy `a4bc0a17…`). Live `/api/pool` confirmed all V12.2 invariants. No real user policies underwritten — pool was empty (no `add_liquidity` yet). Smoke tests verified the dispatcher + Indigo binding for all 4 iAssets + 5 AegisSelf assets. All 9 stayed at the pool-empty downstream gate, which is expected.

### V12.2 + R7 redeploy (2026-05-12)

R7-B re-rotates `policy_validator` hash; the cascade through parameterization re-rotates `pool_validator` + `lp_token_policy`. Five-tx sequence:

| Step | Tx hash | Purpose |
|---|---|---|
| 1 | [`aa611f72…c573a736`](https://preprod.cexplorer.io/tx/aa611f722b776c7a568df27fbad2604289f482111167d08e7eb31195c573a736) | Publish ref `policy_validator` (`2e4eecf5…`, R7-B unparameterized) |
| 2 | [`6f277e8d…ee3c76a8e`](https://preprod.cexplorer.io/tx/6f277e8d8acb0f41fddae807a23427b89d631b26aa7f50315bf08ecee3c76a8e) | Publish ref `pool_validator` (`87523125…`, parameterized over new policy hash) |
| 3 | [`54df7a1a…6c63ce21c`](https://preprod.cexplorer.io/tx/54df7a1a302d4384c02aebc6b5102c9e119d1e429d684a47d3964076c63ce21c) | Publish ref `lp_token_policy` (`02727d8e…`, parameterized over new pool hash) |
| 4 | [`70d0c52d…d4418d2`](https://preprod.cexplorer.io/tx/70d0c52d2738fe7ec41e52d579a7f6190fc24feae762612b309fba3d9d4418d2) | Mint pool NFT (`1cde17c2…` / `AEGIS_POOL_V12_2_R7`) |
| 5 | [`168ed7a0…39eb7a06`](https://preprod.cexplorer.io/tx/168ed7a06e8aedd94419b9bfc0f5ce6e0985c25d0cd85c9c56c8219339eb7a06) | Init pool — 100 ADA bootstrap, fresh PoolDatum |

Operator wallet spent ~169 ADA (100 bootstrap + 67 ref-script min-utxo locks + 1.2 fees + 0.2 pool NFT). All txs `valid_contract: true`. Live `/api/pool` endpoint at `https://aegis-api-production-fa61.up.railway.app/api/pool` returns the new state on chain.

**Wave 4.3 zombie state**: three Wave 4.3 ref UTxOs + the old pool UTxO + old pool NFT all remain at OLD addresses. No PolicyDatum binds to them, so they're harmless zombies (~67 ADA of operator-recoverable ADA, not blocking anything).

---

## Hash table (V12.2 + R7 — current mainnet candidate)

| Artifact | Hash / value |
|---|---|
| Branch (this repo) | `feat/v12.2-hybrid-fee-r7` |
| `policy_validator` (unparameterized) | `2e4eecf58646dd1140369994fabcfecbf94d348ae537140bb22288c4` |
| `pool_validator` (parameterized over policy hash) | `87523125bef320c159898ab5418a126da469821ffdc8074b0e40469f` |
| `lp_token_policy` (parameterized over pool hash) | `02727d8e16ff220243d99cf774277205e3be245202ca99f677563802` |
| `pool_nft.mint` (parameterized over init UTxO + asset name) | `1cde17c2102937a35219f9530b13fed38fc0591bb87562f913f67c06` |
| Pool NFT asset name | `AEGIS_POOL_V12_2_R7` |
| Policy script address (preprod) | `addr_test1wqhyam84serd6y2qx6vef74ulm9ljnf53tjnw9qtkg3g33q63k26d` |
| Pool script address (preprod) | `addr_test1wzr4yvf9hmejps2e3x9t2sv2zfk6g6vzrl7usp6tpeqyd8cjza6jx` |
| Init pool UTxO | `168ed7a06e8aedd94419b9bfc0f5ce6e0985c25d0cd85c9c56c8219339eb7a06#0` |
| AegisSelf publisher VKH (compile-time pinned) | `6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152` |

Mainnet Indigo canonical anchors (compile-time pinned, NOT env-overridable) listed in `README.md` and `docs/v12.2_validator_upgrade.md` §2.6.

---

## What we'd like sign-off on

1. **V12.2.A** Hybrid fee carve — verify `fee_total = max(min_utxo, raw_fee)` invariant holds across Underwrite + AcceptCancellation + BatchUnderwrite, and that `pool_growth = premium − fee_total` is conserved.
2. **V12.2.B** Silent partner_cut absorb — verify `team_cut + partner_cut == fee_total` exactly across all (premium, partner_share_bps, min_utxo) combinations, including the floor-trip case.
3. **V12.2.C** Indigo binding — verify the 3-layer trust handshake (NFT pin + paired script credential + single-token-of-policy) is sufficient against the threat model of (a) attacker mints under a different policy id, (b) attacker re-deploys an Indigo-shaped UTxO at a different script address, (c) attacker mints multiple tokens under the canonical policy id.
4. **V12.2.D** Soft-disable Charli3 + Orcfax — confirm that the soft-disable at the NFT gate is the correct surface (vs e.g. removing the parser modules entirely), and that reactivation is a clean 2-line diff.
5. **R7-A** Mainnet `min_premium = 100_000_000` — confirm that 100 ADA premium is the right threshold to neutralise the cancel-cycle drain, and that the per-network comment-toggle pattern is acceptable for the mainnet deploy procedure.
6. **R7-B** `(Indigo, Indigo) -> True` arm — confirm that the BatchClaim provider-uniformity check is correct with the new arm, and that no other batch branches need parallel arms added.

We're also open to any audit findings on the V12 surface that R7 didn't surface — the V12 audit (`feat/v12-multi-pair-oracle`) was paused mid-review; this branch supersedes it, but anything you'd called out before is still in scope.

---

## What's NOT in this audit (already noted in `SECURITY.md`)

- Off-chain FastAPI / monitoring bot / frontend / SDK (A-017, separate review).
- Materios cross-chain attestation bridge (A-018, deferred to post-v1).
- v8 relay-presigned-auth artifacts (`auth_witness_validator`, `auth_witness_nft`) — these are NOT in V12 / V12.2 scope. The v8 audit you did on `dd3e5a7` stands separately; v8 is currently in soak mode pending mainnet.

---

## Communication

- **For audit findings**: email `security@fluxpointstudios.com` (PGP key on request).
- **For clarifications**: same channel.
- **Bounty**: scoped for post-mainnet; severe findings will be acknowledged with attribution and discretionary reward at maintainer's option until the program is announced.

Thank you for the time on V12 — the R7 round caught both the Indigo BatchClaim gap AND the cancel-cycle drain because of your prior coverage of the batch surface and the floor pattern. Looking forward to your V12.2 + R7 review.

— Flux Point Studios
