# Aegis Smart Contracts — On-Chain Audit Repository

**Aegis** is a parametric crypto-insurance protocol on Cardano. This repository contains the on-chain code (Aiken validators, lib helpers, fixtures), the security audit report covering 7 internal rounds + a v8 / V12 / V12.2 deploy series, the V12.2 spec, the V12.2 Round-7 red-team report, deploy artifacts proving the contracts are live on Cardano preprod, and red-team scripts documenting the attacks tried.

This repo is the **audit handoff package** for an external auditor. The off-chain backend (FastAPI server, monitoring bot, frontend, SDK) is intentionally NOT in this repo — those components are scheduled for a separate off-chain audit and are not in scope here.

---

## V12.2 + Round-7 — current scope (auditor entry point)

**Branch:** [`feat/v12.2-hybrid-fee-r7`](https://github.com/Flux-Point-Studios/aegis-contracts/tree/feat/v12.2-hybrid-fee-r7) (cut from `feat/v12-multi-pair-oracle` 2026-05-12).

V12.2 is a coordinated upgrade over V12 covering four changes for one audit pass. The Round-7 follow-up fixes one HIGH and one MED finding from the V12.2 red-team round.

**A. Hybrid fee model (`pricing.ak`).** Replaces V12's "team min-utxo floor pad" UX confusion. `fee_total = max(min_utxo_lovelace, raw_fee)` is computed once, then carved from the premium: `pool_growth = premium − fee_total`. The floor lives inside the carve. Per 20-ADA premium: pool +18.00 ADA, team +2.00 ADA (LP absorbs the −1.60 ADA shortfall vs raw fee × 2%). Per ≥100-ADA premium: identical to a pure 2% fee. Conway treasury_donation (0.5% of premium) is unchanged.

**B. Silent partner_cut absorb.** When `partner_cut_raw < min_utxo`, the partner output is dropped (datum still records the address for analytics) and team_cut absorbs the full fee_total. Eliminates the V12 partner-floor-pad emission path (per 500-ADA premium with partner @ 15%: V12 emitted +2 ADA partner output; V12.2 absorbs).

**C. Indigo as 4th OracleProvider (constructor index 3).** Direct-binds Indigo's on-chain price-oracle UTxOs (NOT the Indigo REST API). Four iAssets supported: iUSD / iBTC / iETH / iSOL — each at a per-iAsset parameterized Indigo oracle script address, each pinned by a canonical NFT (mainnet: 4 distinct policy ids; preprod: 4 mock NFTs minted out-of-band by an always-succeeds Plutus V3 mock script). Three-layer trust handshake (`lib/aegis/oracle/indigo.ak`): NFT policy-id in canonical list + paired script credential pin + single-token-of-policy. Freshness pinned via `OracleDatum.expiration` against `tx_lower`.

**D. Soft-disable Charli3 + Orcfax.** `aegis_self.ak::is_canonical_oracle_nft(Charli3 | Orcfax, _) → False`. Both providers remain in tree (parser modules + `OracleProvider` variants) so reactivation is a 2-line diff if those feeds come back; the live binding surface is rejected at the canonical-NFT gate, preventing any V12.2 policy from being created against them.

**Round-7 R7-A (`types.ak`, 2026-05-12).** `min_premium` becomes a per-network comment-toggle. Preprod stays at `2_000_000` (dev-convenient — exercises the full fee_total floor path so red-team tests stay reproducible). Mainnet: `100_000_000` (= 100 ADA, threshold where `raw_fee = premium × 200 / 10_000 ≥ min_utxo` so the Hybrid floor stops kicking in). Neutralises the cancel-cycle LP-drain at the floor threshold (≤3.8 ADA per cycle vs 0.2 ADA attacker burn — asymmetric drain ratio 19×).

**Round-7 R7-B (`validators/policy.ak`, 2026-05-12).** Added `(Indigo, Indigo) -> True` as the 4th arm of `batch_oracles_uniform`. Original V12 switch listed only Charli3/Orcfax/AegisSelf; an Indigo BatchClaim fell through to `_ -> False` and the entire batch tx rejected. Single-policy Indigo claim was unaffected — the `seen` sentinel guard skips the equality check for the first element. Test surface: `redteam_round_7_r7_b_batch_oracles_uniform_accepts_indigo_pair` (positive) + `..._accepts_aegis_self_pair` (regression-lock).

Full spec: [`docs/v12.2_validator_upgrade.md`](docs/v12.2_validator_upgrade.md) (3950 lines, 14 sections). Round-7 report: [`redteam/V12.2_ROUND_7_REPORT.md`](redteam/V12.2_ROUND_7_REPORT.md).

---

## What's in the box

```
aegis-contracts/
├── README.md                            # This file
├── LICENSE                              # Apache-2.0
├── SECURITY.md                          # Responsible disclosure
├── contracts/                           # Aiken project — the audit target
│   ├── aiken.toml                       # Aiken v1.1.21 + stdlib v3.0.0
│   ├── plutus.json                      # Compiled blueprint (post-R7-B build, 85,310 bytes)
│   ├── validators/
│   │   ├── policy.ak                    # Per-policy lifecycle (Claim / Cancel / Expire / batch variants)
│   │   ├── pool.ak                      # Liquidity pool + Underwrite + treasury donation + Hybrid fee carve
│   │   ├── lp_token.ak                  # LP-token mint policy (parameterized over pool hash)
│   │   └── pool_nft.ak                  # One-shot pool-identifier NFT (A-011 fix)
│   ├── lib/aegis/
│   │   ├── types.ak                     # Datum + redeemer schemas, protocol constants, canonical-NFT pins, Indigo bindings
│   │   ├── pricing.ak                   # Hybrid fee_total + protocol-fee split (team / partner with silent absorb)
│   │   ├── pool.ak                      # Datum-transition helpers, LP math
│   │   ├── oracle.ak                    # Multi-oracle dispatcher (Charli3 + Orcfax + AegisSelf + Indigo)
│   │   ├── oracle/                      # Per-provider parsers
│   │   │   ├── types.ak                 # Provider-uniform Price record
│   │   │   ├── charli3.ak               # Charli3 parser (soft-disabled at NFT gate in V12.2)
│   │   │   ├── orcfax.ak                # Orcfax FSP→FS parser (soft-disabled at NFT gate in V12.2)
│   │   │   ├── aegis_self.ak            # AegisSelf self-publish parser (5-NFT allowlist, ADA/BTC/ETH/USDC/USDT)
│   │   │   └── indigo.ak                # NEW V12.2 — Indigo on-chain price oracle (iUSD/iBTC/iETH/iSOL)
│   │   ├── validation.ak                # Shared signature/time/output helpers
│   │   └── test_helpers/                # Fixtures + security tests (351 tests, 0 failures)
│   └── README.md                        # Build + test instructions
├── docs/
│   ├── ARCHITECTURE.md                  # On-chain protocol architecture
│   ├── BACKEND_INTERACTION.md           # How the off-chain backend calls the validators
│   ├── AUDITING_GUIDE.md                # Starting points + scope for the external auditor
│   ├── GREEN_PATH_PROOFS.md             # On-chain txs proving every user-facing branch executes correctly
│   ├── v12_validator_upgrade.md         # V12 spec — historical (kept for delta-readability vs V12.2)
│   ├── v12.2_validator_upgrade.md       # V12.2 spec — 14 sections, includes §7.1.1 R7-B re-rotation + §13 spec-vs-code resolutions
│   ├── communications/
│   │   └── AUDITOR_NOTIFY_V12_2026-05-11.md   # V12 handoff letter (V12.2 + R7 details now live in V12.2 spec + this README)
│   └── audit/
│       ├── SECURITY_AUDIT_REPORT.md     # 41 findings tracked across 7 internal rounds, 27 closed, 12 deferred with rationale, V12.2 + R7 sections appended
│       ├── TREASURY_DONATION_SCOPE.md   # Conway donation feature design
│       ├── RELAY_PRESIGNED_AUTH_SCOPE.md   # v8 auto-claim relay design (out of V12.2 scope; preserved for context)
│       └── ORCFAX_INTEGRATION_SCOPE.md  # Multi-oracle redundancy design (v6, now soft-disabled in V12.2)
├── deploy/
│   ├── README.md                        # Operator deploy runbook
│   ├── deploy-state.preprod.json        # Live V12.2 + R7 state (Cardano preprod, 2026-05-12)
│   ├── archive/                         # v0..v8 historical deploy states
│   └── scripts/                         # mint_pool_nft, publish_refs, init_pool, _common
└── redteam/
    ├── README.md                        # Reproduction notes
    ├── V12.2_ROUND_7_REPORT.md          # NEW — Round 7 report: 0 CRITICAL, 1 HIGH (R7-B fixed), 1 MED (R7-A fixed), 1 INFO
    ├── redteam_a021.py                  # Phantom policy at trash address (A-021, fixed v2)
    ├── redteam_a023_donation.py         # Donation underpay attempts (rejected)
    ├── redteam_a024_negcoverage.py      # Negative-coverage Underwrite (A-024, fixed v3)
    ├── redteam_round3.py                # A-014/015/016 boundaries + A-025 multi-policy
    ├── smoke_donation.py                # Body-level Conway donation smoke
    └── smoke_underwrite.py              # Full green-path Underwrite + donation
```

---

## Audit posture (2026-05-12)

- **Total findings to date:** 41 (across 7 rounds of internal red-team)
- **Closed:** 27 — A-001..A-016 + A-019..A-027 + L-003 + L-006 + Charli3 NFT pin extension + R7-A + R7-B
- **Open:** 14 — 1 HIGH (L-002, batch-expire multi-policy aggregation — likely MED in practice), the rest MED/LOW/INFO with documented deferral rationale (see [`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md) and [`redteam/V12.2_ROUND_7_REPORT.md`](redteam/V12.2_ROUND_7_REPORT.md)). No CRITICAL findings open.
  - **A-017** (Info) — off-chain components (FastAPI / bot / frontend / SDK) outside this audit's scope; planned separate review.
  - **A-018** (Info) — Materios cross-chain attestation bridge — DEFERRED to post-v1 roadmap.
  - **L-001 / L-002 / L-005 / L-007 / A-028 / A-029** — round-6 deferrals with documented rationale.
  - **ECON-1..ECON-4** — round-6 economic findings (DoS-shaped, no fund extraction).
  - **R7-INFO-1** — Round 7 informational, see `redteam/V12.2_ROUND_7_REPORT.md`.
- **Aiken test count:** 351 / 0 (all green; verified by `aiken check` on `feat/v12.2-hybrid-fee-r7`). V12 was 286, V12.2-pre-R7 was 345, R7 added 6 (3 R7-A + 3 R7-B regression).
- **Plutus version:** V3 (Conway era)

The full finding-by-finding writeup is in [`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md). Every red-team round finding includes the on-chain transaction hash that empirically demonstrated the exploit on Cardano preprod (or the test/PoC trace where a live demonstration was infeasible), plus the redeploy hash that demonstrably rejects the same attack code.

---

## What's deployed (live on Cardano preprod, V12.2 + R7)

This is **V12.2 + Round-7** — the post-R7-B redeploy (live 2026-05-12 from `feat/v12.2-hybrid-fee-and-aegis-self-only` at `82b6ce0`). See [`deploy/deploy-state.preprod.json`](deploy/deploy-state.preprod.json) for the full record.

| Artifact | Hash / id |
|---|---|
| `policy_validator` (unparameterized) | `2e4eecf58646dd1140369994fabcfecbf94d348ae537140bb22288c4` |
| `policy_validator` ref UTxO | [`aa611f722b776c7a568df27fbad2604289f482111167d08e7eb31195c573a736#0`](https://preprod.cexplorer.io/tx/aa611f722b776c7a568df27fbad2604289f482111167d08e7eb31195c573a736) |
| Policy script address | `addr_test1wqhyam84serd6y2qx6vef74ulm9ljnf53tjnw9qtkg3g33q63k26d` |
| `pool_validator` (parameterized over policy hash) | `87523125bef320c159898ab5418a126da469821ffdc8074b0e40469f` |
| `pool_validator` ref UTxO | [`6f277e8d8acb0f41fddae807a23427b89d631b26aa7f50315bf08ecee3c76a8e#0`](https://preprod.cexplorer.io/tx/6f277e8d8acb0f41fddae807a23427b89d631b26aa7f50315bf08ecee3c76a8e) |
| Pool script address | `addr_test1wzr4yvf9hmejps2e3x9t2sv2zfk6g6vzrl7usp6tpeqyd8cjza6jx` |
| `lp_token_policy` (parameterized over pool hash) | `02727d8e16ff220243d99cf774277205e3be245202ca99f677563802` |
| `lp_token_policy` ref UTxO | [`54df7a1a302d4384c02aebc6b5102c9e119d1e429d684a47d3964076c63ce21c#0`](https://preprod.cexplorer.io/tx/54df7a1a302d4384c02aebc6b5102c9e119d1e429d684a47d3964076c63ce21c) |
| Pool NFT | `1cde17c2102937a35219f9530b13fed38fc0591bb87562f913f67c06` (`AEGIS_POOL_V12_2_R7`) |
| Pool UTxO (init, 100 ADA bootstrap) | [`168ed7a06e8aedd94419b9bfc0f5ce6e0985c25d0cd85c9c56c8219339eb7a06#0`](https://preprod.cexplorer.io/tx/168ed7a06e8aedd94419b9bfc0f5ce6e0985c25d0cd85c9c56c8219339eb7a06) |
| AegisSelf publisher VKH (compile-time pinned) | `6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152` |
| `AEGIS_PRICE_FEED_V1` NFT (ADA preprod) | `d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f` |
| `AEGIS_PRICE_FEED_BTC_USD_V1` NFT (preprod) | `ae304e2727432f8d7c5f7e29b1cfeb9619f93b32fcb0ee9c0669f2d7bd` |
| `AEGIS_PRICE_FEED_ETH_USD_V1` NFT (preprod) | `d80aa1a7c14e6f0c12a3e2cb33d7e29be1f8e58d31d49b3a2e15807ad` |
| `AEGIS_PRICE_FEED_USDC_USD_V1` NFT (preprod) | `860faa663d8a3ae3071d61f95464340c0e49c1f47f56db76441df7a0` |
| `AEGIS_PRICE_FEED_USDT_USD_V1` NFT (preprod) | `a4093bfc7758b86ca1b96df842367bce96cb954650a392020246c0cb` |
| Indigo iUSD oracle NFT (preprod mock) | `b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5` |
| Indigo iBTC oracle NFT (preprod mock) | `1e66200fca30b83d5937b67b896fa46f1adac98922555f9e791c1c83` |
| Indigo iETH oracle NFT (preprod mock) | `e81e84a5d34137bcbc2ba73f1b4e735ac0cc375f0bfeb5e98a397102` |
| Indigo iSOL oracle NFT (preprod mock) | `875cea49cb6963ad462187f77dcc5b4d458a66d7eb9a646c2c5405a7` |
| Indigo shared mock oracle script (preprod) | `d27ccc13fab5b782984a3d1f99353197ca1a81be069941ffc003ee75` |

**Mainnet Indigo canonical anchors** (compile-time pinned in `types.ak`, not env-overridable):
- iUSD: `e3455f2715338b454fb853442f72dc03b98396854f97510027fe22ff` / `iUSD20220626193835`
- iBTC: `c48cbb3d5e57ed56e276bc45f99ab39abe94e6cd7ac39fb402da47ad` / `iBTC20221219191302`
- iETH: `9eaca25c0676ff14fcafcbb4ec5f17a3447b6db5478a45bb44dc7616` / `iETH20221219191302`
- iSOL: `c70e96f76a99a3c2a35dd11ddf24e7989b9b1de9eafb1d39157e1ad1` / `iSOL_ORACLE`

These are validated facts about Indigo's mainnet deployment (verified via Koios `asset_utxos` against the per-iAsset parameterized oracle script addresses listed in `docs/v12.2_validator_upgrade.md` §2.6); operator-override would be an audit incident.

---

## Quick start (auditor)

1. Install Aiken `v1.1.21+`:
   ```bash
   curl --proto '=https' --tlsv1.2 -LsSf https://install.aiken-lang.org | sh
   aikup install v1.1.21
   ```
2. Build + test:
   ```bash
   cd contracts
   aiken check        # runs 351 tests
   aiken build        # produces plutus.json (85,310 bytes)
   ```
3. Read the V12.2 spec **first**, then the Round-7 report:
   - [`docs/v12.2_validator_upgrade.md`](docs/v12.2_validator_upgrade.md) — full 14-section spec, includes §1 worked examples (fee economics), §2.6 Indigo on-chain architecture, §7 env rotation table, §7.1.1 R7-B re-rotation, §13 spec-vs-code resolutions
   - [`redteam/V12.2_ROUND_7_REPORT.md`](redteam/V12.2_ROUND_7_REPORT.md) — Round 7 findings (R7-A min_premium cancel-cycle, R7-B Indigo BatchClaim) + regression vs rounds 1-6
4. Read the audit report:
   - [`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md) — full history
   - Cross-reference cited validator file:line references against the source
   - For Round-2 / Round-3 / Round-6 / Round-7 findings, verify the on-chain **pre-fix** tx via [preprod.cexplorer.io](https://preprod.cexplorer.io)
   - For the **post-fix green path** (validators working as intended), see [`docs/GREEN_PATH_PROOFS.md`](docs/GREEN_PATH_PROOFS.md)
5. Audit the contracts:
   - Primary: [`contracts/validators/`](contracts/validators/) (`policy.ak` + `pool.ak` are where 95% of the audit surface lives)
   - Hot spots for V12.2 + R7:
     - `pool.ak::Underwrite` branch — Hybrid fee carve + silent partner_cut absorb (§3.1 of spec)
     - `pool.ak::AcceptCancellation` branch — cancel-side fee carve (§3.2)
     - `pool.ak::BatchUnderwrite` branch — per-policy floor + aggregated outputs (§3.3, MOST CRITICAL)
     - `policy.ak::batch_oracles_uniform` — R7-B Indigo arm added (line 84-99)
     - `lib/aegis/oracle/indigo.ak` — NEW Indigo parser + 3-layer trust handshake
     - `types.ak::min_premium` — R7-A per-network comment toggle (line 290-307)
   - Fixtures + tests: [`contracts/lib/aegis/test_helpers/`](contracts/lib/aegis/test_helpers/) — 351 tests, R7 additions at lines 1843..1971
6. Read [`docs/AUDITING_GUIDE.md`](docs/AUDITING_GUIDE.md) for finding priorities, attack-surface taxonomy, and reproduction guidance.

---

## Test invariants (V12.2 §8)

Ten property-style invariants, each paired with positive + negative Aiken tests + Python mirrors + Vitest cross-checks:

1. **Premium conservation** — `premium == (premium − fee_total) + team_cut + partner_cut`
2. **Hybrid floor monotonicity** — `fee_total >= raw_fee` and `fee_total >= min_utxo_lovelace`
3. **Silent absorb invariant** — `team_cut + partner_cut == fee_total` exactly (no leakage)
4. **Partner cap** — `partner_share_bps <= partner_share_cap_bps = 2000` (20% of fee = 0.4% of premium)
5. **Pool growth** — `cont_pool == old_pool + net_pool_growth` (where `net_pool_growth = premium − fee_total`)
6. **Liquidity accounting** — `cont_total_liquidity == old_total_liquidity + net_pool_growth` (no phantom lovelace)
7. **Treasury donation** — Conway body field 22 equals exactly `treasury_share_bps × premium / 1e8`
8. **Indigo NFT canonical-membership** at Underwrite (`oracle_nft` ∈ `indigo_canonical_nfts`)
9. **Indigo script-credential binding** — UTxO must be at the paired Indigo script address
10. **Indigo freshness** — `tx_lower <= datum.expiration`

R7-B regression: invariant 11 (BatchClaim provider-uniformity for Indigo) — `same_provider == True` for any `(Indigo, Indigo)` pair.

---

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Security disclosure

See [`SECURITY.md`](SECURITY.md). For new findings: **do not file a public issue.** Email security@fluxpointstudios.com (PGP key on request).
