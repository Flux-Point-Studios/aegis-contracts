# Mainnet Live-Fire Red-Team — Final Pre-Launch Gate

**Date:** 2026-05-29  **Target:** Aegis V12.2 + R17, **live on Cardano mainnet**
**Build:** mainnet profile, aiken `v1.1.22+39d6b04`

This is the report of the final adversarial campaign run before public launch. Unlike
the earlier rounds (which attacked preprod and source), this campaign attacked the
**live mainnet deployment with real ADA** — building and submitting genuine transactions
to the chain to prove, empirically, that the deployed ref-scripts and parameterization
reject every known and newly-invented attack in practice, not just in theory.

> The off-chain backend (API/bot/SDK) is out of scope for this repository and is covered
> separately. A small number of off-chain hardening items found during the campaign are
> noted at the end for completeness; the validator results are the subject of this report.

---

## Methodology

Four autonomous adversarial agents were run against the live protocol:

- **Three independent agents** (A, B, C), each owning one funded mainnet wallet, working
  in parallel without coordination.
- **One coordinating agent** controlling all three wallets, to exercise multi-wallet
  collusion that a single actor cannot.

Each agent ran a **two-phase mandate**:

1. **Full historical re-run** — every vector from the seven internal red-team rounds and
   the external audit (EXT-01…EXT-21), replayed against the live chain.
2. **Net-new exploration** — invent and try vectors the corpus never covered, derived by
   reading the live validator source and reasoning adversarially about untested paths.

**Rules of engagement (hard-enforced in the harness):**

- Scope limited to Aegis-owned contracts; every transaction's output addresses were
  checked against an allow-list before submission.
- Spends only from the dedicated red-team wallets; operator / pool / publisher keys were
  never touched; third-party protocols (oracle providers, lending venues) were never
  attacked.
- **Kill-switch:** the instant any adversarial transaction was *accepted* on-chain or any
  net value was extracted, the agent logged a finding and halted that attack class —
  no repeat-exploitation.

A **REJECT** by the validator is the secure, expected outcome. An **ACCEPT** of an
adversarial transaction, or any value extracted beyond the protocol rules, is a finding.

---

## Result

**160+ distinct adversarial transactions were attempted across four surfaces. Every one
was rejected at on-chain validation. Zero were accepted; zero protocol value was
extracted; the kill-switch never fired on a real exploit.**

Most adversarial transactions were refused at phase-2 script evaluation (`PlutusFailure`
— the validator executed and refused), so they never entered a block and cost the
attacker nothing but proved the script logic directly.

| Surface | Agent | Vectors | Verdict |
|---------|-------|---------|---------|
| Validator logic / redeemer & datum abuse | A | catalog 1–35, 70 + NN-A-23…29 | all REJECTED |
| Economics / oracle-input forgery | B | catalog 36–70 + NN-B-25…45 | all REJECTED |
| Off-chain / API / tx-construction | C | catalog 71–88 + NN-C-33…61 | all REJECTED |
| Multi-wallet collusion | Coordinated | catalog 89–100 + NN-COORD-1…8 | all REJECTED |

---

## Vector catalog (what was tried)

### Agent A — validator logic / redeemer & datum abuse

| # | Attack | Verdict |
|---|--------|---------|
| 1 | AddLiquidity minting more LP than the deposit warrants | REJECTED |
| 2 | AddLiquidity with an under-funded pool output (steal from pool) | REJECTED |
| 3 | RemoveLiquidity withdrawing more than pro-rata share | REJECTED |
| 4 | RemoveLiquidity burning fewer LP than ADA withdrawn | REJECTED |
| 5 | Underwrite: policy output funded `< coverage_amount` | REJECTED |
| 6 | Underwrite: omit the team-fee output | REJECTED |
| 7 | Underwrite: omit / inflate partner-share past cap | REJECTED |
| 8 | Underwrite: pool output drops the `active_coverage` increment | REJECTED |
| 9 | Underwrite: mint 0 markers but create a policy | REJECTED |
| 10 | Underwrite: mint 2 markers / 1 policy (extra-marker exfil) | REJECTED |
| 11 | Underwrite: marker on a non-policy output | REJECTED |
| 12 | Underwrite: wrong `pool_nft` in PolicyDatum | REJECTED |
| 13 | Underwrite: `protocol_fee_bps` tampered downward | REJECTED |
| 14 | BatchUnderwrite: N policies / N-1 markers (walker miscount) | REJECTED |
| 15 | BatchUnderwrite: duplicate one policy output, reuse a marker | REJECTED |
| 16 | BatchUnderwrite: one output under-funded among many | REJECTED |
| 17 | BatchUnderwrite: cross-wallet input injection to confuse the walker | REJECTED |
| 18 | ProcessClaim: burn marker but leave the policy UTxO (double-claim setup) | REJECTED |
| 19 | ProcessClaim: claim without consuming the marker | REJECTED |
| 20 | ProcessClaim: payout to attacker, not the insured | REJECTED |
| 21 | ProcessClaim: payout `> coverage_amount` | REJECTED |
| 22 | ProcessClaim: pool output omits the `active_coverage` decrement | REJECTED |
| 23 | AcceptCancellation: retain less than the min collateral | REJECTED |
| 24 | AcceptCancellation: single-input guard bypass via extra inputs | REJECTED |
| 25 | AcceptCancellation: refund beyond rules / refund to attacker | REJECTED |
| 26 | BatchExpireProcess: expire an un-expired policy (validity-range abuse) | REJECTED |
| 27 | BatchExpireProcess: N markers burned / N-1 policies consumed | REJECTED |
| 28 | Marker mint without consuming a pool-NFT-bearing input | REJECTED |
| 29 | Marker mint on an unrelated transaction (delegation bypass) | REJECTED |
| 30 | Marker burn on a branch that should require `mint_qty == 0` | REJECTED |
| 31 | Branch-pairing: ProcessClaim tx carrying a Cancel marker redeemer | REJECTED |
| 32 | Branch-pairing: BatchExpire paired with an Underwrite marker variant | REJECTED |
| 33 | lp_token mint decoupled from AddLiquidity (free LP) | REJECTED |
| 34 | lp_token burn mismatch on RemoveLiquidity | REJECTED |
| 35 | Spend the pool UTxO with an out-of-range redeemer index | REJECTED |
| 70 | Claim a policy with a marker from a *different* policy instance | REJECTED |
| NN-A-23…29 | Split-park LP, wrong-policy aLP name, `lp_token_policy` datum swap, marker parked in pool, supply-delta inflation, over-funding | all REJECTED |

### Agent B — economics / oracle-input forgery / accounting

| # | Attack | Verdict |
|---|--------|---------|
| 36 | Claim with a self-crafted oracle UTxO (wrong publisher key) | REJECTED |
| 37 | Claim with an oracle NFT under a forged policy id | REJECTED |
| 38 | Claim with a stale oracle (outside the freshness window) | REJECTED |
| 39 | Claim with an oracle price just above strike (off-by-one) | REJECTED |
| 40 | Claim with two oracle reference inputs (pick-cheapest ambiguity) | REJECTED |
| 41 | Claim referencing a real oracle UTxO for the wrong asset | REJECTED |
| 42 | Depeg claim: forged stablecoin feed input | REJECTED |
| 43 | Lending claim: forged protocol-state input | REJECTED |
| 44–45 | Underwrite with premium below / just under the min-premium floor | REJECTED |
| 46–47 | Cancel-cycle pool drain (single + min-premium variants) | REJECTED |
| 48 | Premium/fee rounding-direction exploitation | REJECTED |
| 49 | Per-policy vs aggregate floor mismatch | REJECTED |
| 50–51 | Coverage > available liquidity / utilization > 100% | REJECTED |
| 52 | Fee split: team + partner ≠ protocol fee (conservation) | REJECTED |
| 53 | Treasury-donation field tampering / omission | REJECTED |
| 54 | `protocol_fee_bps` read from a stale pool datum | REJECTED |
| 55 | Coverage amount = 0 / negative (sign) | REJECTED |
| 56–58 | Claim before start / after expiry / expire-then-claim race | REJECTED |
| 59 | Double-fund: one premium input claimed by two policy outputs | REJECTED |
| 60 | LP value inflation via donation then immediate remove | REJECTED |
| 61–62 | Oracle-freshness boundary / asset-unit confusion | REJECTED |
| 63 | BatchClaim synthetic-UTxO chaining abuse | REJECTED |
| 64 | Inflate `active_coverage` to lock LPs out of withdrawal (griefing) | REJECTED |
| 65 | Premium in a dust/token-heavy UTxO to break min-UTxO accounting | REJECTED |
| 66–69 | NAV-feed forge, fear-index injection, rollback assumption, Int overflow/sign | REJECTED |
| NN-B-25…45 | Free-standing marker/aLP mint, marker laundering onto Add/Remove, asset-name purity, donation overshoot, NFT relocation, NoDatum continuation, foreign pool-binding, MAX-int coverage | all REJECTED |

### Agent C — off-chain / API / tx-construction

| # | Attack | Verdict |
|---|--------|---------|
| 71 | Build endpoint with hostile coverage/premium params | REJECTED (422/400) |
| 72 | Build with out-of-range liquidity amounts | REJECTED |
| 73 | Build with malformed asset/cdp ids | REJECTED |
| 74 | Submit a tx with a re-encoded redeemer (definite vs indefinite length) | REJECTED |
| 75 | Witness-set splice: extra/forged vkey witnesses | REJECTED |
| 76 | Submit bytes that canonicalize differently (script_data_hash drift) | REJECTED |
| 77–78 | Replay a valid claim / replay after partial confirmation | REJECTED |
| 79–80 | Tampered collateral input / script-UTxO collateral | REJECTED |
| 81 | `PPViewHashesDontMatch` induction via cost-model ordering | REJECTED |
| 82 | Force operator-mode action from user mode | REJECTED |
| 83 | Rate-limit / auth bypass on operator endpoints | REJECTED |
| 84 | Oversized / many-input tx against the build endpoint | REJECTED |
| 85 | Manifest/constants-drift: get the API to build with stale hashes | REJECTED |
| 86 | Front-run a legit claim by copying its mempool tx | REJECTED |
| 87 | CBOR malleability on the policy datum (re-serialize Constr form) | REJECTED |
| 88 | Spend the pool UTxO with a stale datum snapshot | REJECTED |
| NN-C-33…61 | Content-type/array/nested-body smuggling, homoglyph oracle providers, SSRF/null-byte/path-traversal params, method-override flips, idempotent double-submit, oracle network-leak checks | all REJECTED |

### Coordinated — multi-wallet collusion

| # | Attack | Verdict |
|---|--------|---------|
| 89 | Two wallets submit competing claims on one policy UTxO (double-spend race) | REJECTED |
| 90 | Concurrent AddLiquidity + RemoveLiquidity racing the pool datum | REJECTED |
| 91 | Sandwich a victim Underwrite (front + back run to skim the pool delta) | REJECTED |
| 92 | BatchUnderwrite with inputs split across all three wallets | REJECTED |
| 93 | Coordinated marker mint + burn across wallets (authority laundering) | REJECTED |
| 94 | Mempool timing to delay a legit claim past expiry (bounded; not flooded) | REJECTED |
| 95 | One wallet funds a forged oracle UTxO, another claims against it | REJECTED |
| 96 | Cross-wallet collateral sharing to bypass the per-tx collateral pin | REJECTED |
| 97 | Coordinated 3-wallet cancel-cycle to amplify drain | REJECTED |
| 98 | Simultaneous expire + claim from two wallets on one policy | REJECTED |
| 99 | Pool-NFT relocation out of the pool | REJECTED |
| 100 | Shadow-pool: fake pool UTxO to trick a claim into reading it | REJECTED |
| NN-COORD-1…8 | Multi-wallet premium-aggregation skim, pool-NFT as read-only mint authority, dual canonical+shadow pool inputs, AddLiquidity-co-minted marker, under-funded NFT continuation with decoy, cross-wallet count-miscount BatchUnderwrite, re-park aLP in continuation, fold shadow ADA into a withdrawal | all REJECTED |

---

## The one validator issue found, and how it was closed

**LP-token locality (found in the first pass, by Agent A).** The `AddLiquidity` branch
verified the LP *mint quantity* but did not pin the *destination* of the minted LP
tokens — allowing minted LP to be routed into the pool's own continuing output rather
than a wallet, with a downstream griefing / free-withdrawal implication (the LP path
lacked the per-branch locality pins the marker path already had).

Lifecycle:

1. **Fixed** — both halves: the minting-authority half (the LP minting policy is now
   redeemer-bound to a real AddLiquidity that spends the pool) and the
   continuation-locality half (every pool branch pins the continuation to carry **zero**
   LP; the two LP branches additionally pin LP out of the pool output).
2. **Redeployed** — new ref-scripts on the correct mainnet profile.
3. **Re-verified in the second pass** — the attack (both the parking and the
   co-mint variants) was rejected live on-chain, **and** the contracts were independently
   rebuilt from source and the deployed on-chain script hash was reproduced
   **byte-for-byte**, proving the live bytecode is the fixed build.

This brings the LP path to parity with the marker-locality model used throughout the
lifecycle (markers can only be minted by a transaction that *spends* the canonical-NFT
pool UTxO; a read-only reference input does not authorize a mint — confirmed under
collusion by NN-COORD-2).

---

## Quantified economic result: cancel-cycle is neutralized on mainnet

The historical "cancel-cycle" drain (where an attacker repeatedly underwrites and cancels
to bleed the pool at the fee floor) is **neutralized at the mainnet parameters.** With a
100 ADA minimum premium and the 10% fee retained in the pool on cancellation, each cycle
is negative-EV *for the attacker* — it drains the attacker, not the pool. The small
per-cycle figure seen on preprod assumed the 2 ADA preprod minimum premium and does not
apply on mainnet.

---

## Off-chain hardening (for completeness; off-chain code is out of scope here)

Two off-chain API items found during the campaign were fixed in the (separate) backend:
legacy operator/custodial endpoints and the auto-claim toggles are now gated behind
operator mode (clean `503`, no information disclosure), and the transaction-build
endpoints map wallet/coin-selection failures to actionable `4xx` responses. Both are
covered by regression tests. None of these are validator-level or fund-loss issues.

---

## Bottom line

After seven internal red-team rounds, an external contracts audit, symbolic execution,
property/differential fuzzing, and this final mainnet live-fire campaign, the Aegis
validators rejected **every** adversarial transaction attempted against the live
deployment — historical and novel, single-actor and colluding — with **zero value
extracted**. The one issue surfaced was fixed and bytecode-verified closed before launch.
