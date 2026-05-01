# Security Audit Report: Aegis Parametric Insurance Protocol

**Date:** April 30, 2026
**Validator Versions:**
- `policy.policy_validator` — v0.1.0
- `pool.pool_validator` — v0.1.0
- `lp_token.lp_token_policy` — v0.1.0
- `policy_simple.simple_claim` — diagnostic-only
- `pool_nft.pool_nft` — v0.1.0 (NEW, A-011 one-shot mint)

**Script Hashes (post-A-025 v5, 2026-04-30):**
- Policy Validator: `b63091c33ee34451f59f3186bd493db39cc46387b04be59d616e146b` (rotated in v4 by A-014/A-016 propagating into pricing.ak / oracle.ak)
- Pool Validator:   `c7cf3d90e885ddc54d1187edd491d68d1e1c2bd5cb7b2c986f632377` (post-A-025; parameterized by `policy_script_hash`)
- LP Token Policy:  `08ca63fe64473b547dcce9279770bbbcd0a39ff8525082dc48eefc7a` (parameterized by post-A-025 pool hash)
- Pool NFT: `4720c6e6a56c44a71f8d0da2fabcac48bc4a531357313990f2f47f93` (asset name `AEGIS_POOL_V6`, minted via the one-shot policy at the v5 init UTxO)
- Simple Claim (diagnostic, **MOVED OUT OF MAIN PROJECT — A-019**): `60ff74f29208a88c83a7b4c68a6c335ec0ebe835f89c5a95db3eec8f` — now lives in a separate Aiken project at `D:/aegis/contracts-diagnostics/` and is gated to preprod-only by the off-chain harness. Not present in `D:/aegis/contracts/plutus.json`.

**Hash rotation history:**
- `policy.policy_validator`: `532740d2...` (Priority-1 baseline) → `d492179e...` (post-A-009/A-010/A-012/A-013, since stable). Byte-stable across all subsequent deployments by deliberate factoring — donation enforcement and policy-script binding both live on the pool side.
- `pool.pool_validator`: `54280b3f...` → `ac734c26...` (A-020, AcceptCancellation) → `e067903b...` (v1-treasury, donation_ok) → `4e321754...` (v2-a022, parameterized over policy_script_hash).
- `lp_token.lp_token_policy`: `5052905c...` (parameter-free baseline) cascades with pool's hash via parameterization — currently `ffa6d4ad...`.
- `pool_nft.pool_nft`: re-parameterized per deploy with the operator's init UTxO; current `9e56198e...`.

**Audit Status:** 🟢 **A-001..A-016 + A-019..A-025 closed across v0..v5. 22 of 24 findings remediated. Remaining: A-017 (Info — off-chain audit pending) and A-018 (Info — Materios bridge deferred to post-v1 roadmap). Mainnet readiness: pending external auditor sign-off + the off-chain audit pass.**

**Live red-team summary across 3 rounds (2026-04-30):**
- **Round 1 (static + Aiken):** A-001..A-020 documented. 15 fixed in v0/v1.
- **Round 2 (live preprod attacks on v1-treasury):** A-021 HIGH (phantom policy at trash address — `c32d7a85...0c092ccc57d973` ACCEPTED on v1, FIXED v2). A-022 LOW (output-ordering tailList halt, subsumed by A-021 fix). A-024 MEDIUM (negative-coverage shrinks active_coverage — `01a1067cd496...0eb8ba1632a179cf04459a` ACCEPTED on v2, FIXED v3).
- **Round 3 (live preprod attacks on v3/v4 + creative Hackathon-tier attacks):** A-014 (ratio truncation, FIXED v4). A-015 (no start_time bound — replays R3-B/C/D rejected, FIXED v4). A-016 (oracle script-hash binding, FIXED v4). **A-025 HIGH** (multi-policy single-Underwrite under-accounting — `b1400c64...846ece02cd6f0a1` ACCEPTED on v4, FIXED v5). A-018 deferred to post-v1.

All discovered exploits replayed against the corresponding fixed deploys → REJECTED. Each fix preserved the legitimate green-path (verified by post-fix Underwrite tx).

---

## Executive Summary

This report documents an internal red-team security audit of the Aegis Parametric Insurance Protocol — an Aiken / Plutus V3 parametric crypto insurance system on Cardano. The protocol comprises three on-chain validators (policy, pool, LP token) plus off-chain transaction-building, monitoring bot, and SDK components.

The audit was conducted by Flux Point Studios as an internal pre-audit ahead of engaging an external auditor and ahead of mainnet deployment. Scope is limited to the on-chain validators and their interactions; off-chain components are noted but not analyzed in depth.

**Three critical-severity findings, five high-severity findings, five medium, three low, and two informational items were identified.** At least one finding (A-001) permitted unconditional drain of the entire liquidity pool by any participant in a single transaction. **As of 2026-04-30 the eight Priority-1 findings (A-001 through A-008, including all three CRITICAL and all five HIGH items) are closed in-contract; see the [Remediation Summary](#remediation-summary-2026-04-30) below.** The remaining medium and low findings (A-009 through A-016) are still open under a parallel work stream. **The protocol is not safe for mainnet until those findings are closed and an external auditor has signed off on the remediated set.**

### Audit Scope

| Component | Location | Lines | Description |
|-----------|----------|-------|-------------|
| **Policy Validator** | `contracts/validators/policy.ak` | 417 | Per-policy UTxO lifecycle (Claim / BatchClaim / Expire / BatchExpire / Cancel) |
| **Pool Validator** | `contracts/validators/pool.ak` | 355 | Shared liquidity pool (Underwrite / BatchUnderwrite / ProcessClaim / BatchExpireProcess / AddLiquidity / RemoveLiquidity) |
| **LP Token Policy** | `contracts/validators/lp_token.ak` | 95 | Mint / burn authorization, parameterized by pool script hash |
| **Simple Claim** (diagnostic) | `contracts/validators/policy_simple.ak` | 101 | Minimal claim-only diagnostic validator (NOT for production) |
| **Type Definitions** | `contracts/lib/aegis/types.ak` | 203 | All on-chain datum + redeemer types, protocol constants |
| **Oracle Integration** | `contracts/lib/aegis/oracle.ak` | 234 | Charli3 GenericData parsing + reference-input lookup |
| **Pool Math & Validation** | `contracts/lib/aegis/pool.ak` | 369 | LP token math, solvency invariants, datum-transition checks |
| **Pricing** | `contracts/lib/aegis/pricing.ak` | 219 | Premium adequacy, protocol fee, cancellation refund |
| **Validation Helpers** | `contracts/lib/aegis/validation.ak` | 293 | Shared signature / time / output / value helpers |
| **Total Aiken LOC** | | **2,286** | |

### Out of Scope

- Off-chain transaction builders (`api/server.py`, `offchain/src/*`, `sdk/src/*`)
- The Aegis monitoring bot (`bot/monitor.py`)
- The Aegis frontend (`frontend/src/*`)
- The Materios cross-chain attestation bridge (`api/attestation.py`)
- The Charli3 oracle implementation itself (treated as a trusted external dependency)
- Off-chain integrations with Indigo, Liqwid, Danogo, Surf, FluidTokens

### Key Findings

| ID | Vulnerability | Severity | Status |
|----|--------------|----------|--------|
| A-001 | Pool drainable via attacker-crafted policy UTxO and unchecked `ProcessClaim` payout | **CRITICAL** | 🟢 Fixed (2026-04-30) |
| A-002 | `RemoveLiquidity` value check uses `≤` instead of `==`, allowing pool drain on single LP burn | **CRITICAL** | 🟢 Fixed (2026-04-30) |
| A-003 | Pool deposit/withdraw don't bind to LP mint direction, allowing free LP token mint | **CRITICAL** | 🟢 Fixed (2026-04-30) |
| A-004 | `Underwrite` doesn't require corresponding policy UTxO output, enables `active_coverage` griefing | High | 🟢 Fixed (2026-04-30) |
| A-005 | Pool `ProcessClaim` solvency check is mathematically equivalent to pre-state | High | 🟢 Fixed (2026-04-30) |
| A-006 | `BatchClaim` allows single payout output to satisfy multiple same-insured policies | High | 🟢 Fixed (2026-04-30) |
| A-007 | `AddLiquidity` value check uses `≥` instead of `==`, dilutes existing LPs | High | 🟢 Fixed (2026-04-30) |
| A-008 | Policy validator's pool-output search by script hash only, missing NFT verification | High | 🟢 Fixed (2026-04-30) |
| A-009 | Stake credential hijacking on claim payout outputs | Medium | 🟢 Fixed (2026-04-30) |
| A-010 | `Cancel` permitted during in-the-money state allows underwriter cherry-picking | Medium | 🟢 Fixed (2026-04-30) |
| A-011 | No on-chain enforcement of single canonical pool (multiple pool UTxOs possible) | Medium | 🟢 Fixed (2026-04-30) |
| A-012 | `BatchClaim` does not enforce uniform oracle reference across batched policies | Medium | 🟢 Fixed (2026-04-30) |
| A-013 | `find_output_to_pkh` greedy first-match enables payout collisions | Medium | 🟢 Fixed (2026-04-30) |
| A-014 | Ratio truncation allows ~1 lovelace over-leverage per policy | Low | 📝 Documented |
| A-015 | No upper bound on policy `start_time` enables unusual but non-exploitable policies | Low | 🔴 Open |
| A-016 | Charli3 oracle UTxO trust is implicit (NFT-only verification) | Low | 🔴 Open |
| A-017 | Off-chain components (FastAPI, bot, SDK) outside this audit's scope | Info | 📝 Documented |
| A-018 | Cross-chain attestation (Materios bridge) outside this audit's scope | Info | 📝 Documented |
| A-019 | Diagnostic `policy_simple.ak` validator in production tree (operational risk) | Medium | 🟢 Fixed (2026-04-30) — moved to separate `contracts-diagnostics/` Aiken project + preprod-only off-chain gate |
| A-020 | Cancel structurally unbuildable post-A-008 (no PoolRedeemer fits cancellation pattern) | High | 🟢 Fixed (2026-04-30) — added `PoolRedeemer.AcceptCancellation`, rewired off-chain Cancel + SDK |

### Risk Summary

**Pre-existing fixes (F-001 through F-009)** addressed an earlier round of internal review:

| Fix | Title | Severity | Source |
|-----|-------|----------|--------|
| F-001 | Double satisfaction on Claim (single-input enforcement) | High | Code comment, `policy.ak:71` |
| F-002 | Remainder-to-pool bypass on Claim | High | Code comment, `policy.ak:102` |
| F-003 | Expire skim attack (full value to pool) | High | Code comment, `policy.ak:188` |
| F-004 | `ProcessClaim` policy-consumption requirement | High | Code comment, `pool.ak:125` |
| F-005 | LP mint direction enforcement | Medium | Code comment, `lp_token.ak:42` |
| F-007 | Pool solvency check after claim | High | Code comment, `pool.ak:148` (see A-005 — the fix is **logically equivalent to pre-state** and does NOT add safety) |
| F-008 | Coverage / premium ratio truncation | Low | Test comment, `pricing.ak:178` |
| F-009 | Cancel window boundary | Low | Test comment, `policy.ak:386` |

These fixes are present in the audited code. **However, this audit identifies a new class of issues that the existing fixes do not cover** — most notably the apocalyptic A-001 (pool drain) and A-002 (LP withdraw drain), neither of which are caught by F-001 through F-009.

---

## Remediation Summary (2026-04-30)

Priority-1 remediation (findings A-001 through A-008) was completed on 2026-04-30 in a single coordinated pass over the Aiken contracts. The apocalyptic A-001 (single-tx pool drain via attacker-crafted policy + unbounded `ProcessClaim` payout) is closed: the pool validator now reads the consumed policy's datum and requires `payout == policy.coverage_amount` together with `policy.pool_nft == own.pool_nft` and `policy.pool_script_hash == own_pool_hash`. A-002, A-003, and A-007 are closed by tightening every pool value check to exact equality and binding LP mint/burn magnitude to the datum's new `lp_supply` field. A-004 is closed by requiring a matching policy UTxO output on every `Underwrite` (and a sum-of-coverages check on `BatchUnderwrite`). A-005 is closed by extending `verify_claim_datum` with non-negativity and `payout ≤ old_active` constraints. A-006 is closed by replacing `find_output_to_pkh` with the aggregating `sum_lovelace_to_pkh`. A-008 is closed by adding a `pool_nft` field to `PolicyDatum` and routing every policy-side residual through the new `find_canonical_pool_output` helper. Findings A-009 through A-018 are still open and being worked on by a parallel stream (Priority-2 in flight; Priority-3/4 to follow).

### Test Snapshot

| Phase | Total | Passed | Failed |
|-------|-------|--------|--------|
| Pre-fix baseline | 113 | 112 | 1 (`red_true_a_005_verify_claim_datum_rejects_excessive_payout`) |
| Post-fix final | 125 | 125 | 0 |
| **Net change** | **+12** | **+13** | **−1** |

All 12 new tests live in `lib/aegis/test_helpers/security_tests.ak` and assert that each Priority-1 attack vector is now rejected (or, for A-005 and A-007, that the legitimate path still passes). No pre-existing test regressed.

### Datum Schema Migration

Two breaking on-chain datum changes were introduced. Off-chain transaction builders and the SDK must be updated before any deployment:

- **`PolicyDatum`** — new field at the END: `pool_nft: ByteArray`. Carries the canonical pool's identifying NFT policy ID; required so that `Claim` / `BatchClaim` / `Expire` / `BatchExpire` / `Cancel` can route residuals only to the canonical pool UTxO (closes A-008).
- **`PoolDatum`** — new field at the END: `lp_supply: Int`. Tracks outstanding aLP supply so that the pool validator can verify the exact mint/burn magnitude on `AddLiquidity` and `RemoveLiquidity` (closes A-003).

A separate work stream is updating `offchain/src/*`, `sdk/src/*`, and `api/server.py` to emit these new fields. Until that ships, the new compiled validators will reject every transaction the old transaction builders produce — this is intentional.

### Files Touched

| File | Role |
|------|------|
| `contracts/lib/aegis/types.ak` | Added `pool_nft` to `PolicyDatum`; added `lp_supply` to `PoolDatum` |
| `contracts/lib/aegis/pool.ak` | Strengthened `verify_claim_datum` (non-negativity, `payout ≤ old_active`) |
| `contracts/lib/aegis/validation.ak` | Added `sum_lovelace_to_pkh`; added `find_canonical_pool_output` |
| `contracts/validators/pool.ak` | All value checks `==`; LP magnitude bound; policy-output match on `Underwrite`; coverage / pool-NFT match on `ProcessClaim` and `BatchExpireProcess` |
| `contracts/validators/policy.ak` | Switched residual lookups to `find_canonical_pool_output`; switched payout aggregation to `sum_lovelace_to_pkh` |
| `contracts/lib/aegis/test_helpers/fixtures.ak` *(new)* | Canonical fixtures: pools, policies, oracle UTxOs, attack payloads |
| `contracts/lib/aegis/test_helpers/security_tests.ak` *(new)* | 12 green security tests + 5 sanity tests; all green |

### Open Work (NOT covered by this remediation)

A-009 through A-013 (Priority-2: stake hijacking, in-the-money cancel, single-canonical-pool enforcement, batch oracle uniformity, helper greediness — note A-013's `sum_lovelace_to_pkh` switch was already made as part of A-006, but the residual A-013 cleanup is on the Priority-2 list) and A-014 through A-016 (Priority-3/4) remain 🔴 Open. A-017 / A-018 are scope notes (off-chain and Materios bridge respectively) and remain 📝 Documented.

The protocol is **still not safe for mainnet** until Priority-2/3/4 are closed and an external auditor (Anastasia Labs / MLabs / Tweag or equivalent) has signed off on the full remediated contract set.

---

## Contract Architecture

### Validator Topology

```
┌──────────────────────┐        ┌─────────────────────┐        ┌──────────────────┐
│  Policy Validator    │        │   Pool Validator    │        │ LP Token Policy  │
│  policy.ak           │◄──────►│   pool.ak           │◄───────│  lp_token.ak     │
│                      │        │                     │        │ (parameterized)  │
│ Spend a policy UTxO  │        │ Spend pool UTxO     │        │ Mint/burn aLP on │
│ via Claim/BatchClaim │        │ via Underwrite/     │        │ pool consumption │
│ /Expire/BatchExpire/ │        │ ProcessClaim/Add/   │        │                  │
│ Cancel               │        │ Remove/Batch*       │        │                  │
└──────────────────────┘        └─────────────────────┘        └──────────────────┘
       │                                  │                              │
       │ pool_script_hash                 │ lp_token_policy              │ pool_script_hash
       │ (in PolicyDatum)                 │ (in PoolDatum)               │ (compile-time param)
       └──────────────────────────────────┴──────────────────────────────┘

      Reference input:                                       External dependency:
      Charli3 ADA/USD oracle UTxO ────────────────────►      Charli3 oracle script
      (CIP-31, never consumed)
```

### Datum Structures

#### PolicyDatum (`types.ak:29`)

```aiken
pub type PolicyDatum {
  policy_id: ByteArray,                  // hash of concatenated terms
  insured: VerificationKeyHash,          // beneficiary pubkey hash
  strike_price: Int,                     // ADA/USD trigger (×1e6)
  coverage_amount: Int,                  // payout cap (lovelace)
  premium_paid: Int,                     // premium escrowed (lovelace)
  start_time: Int,                       // POSIX ms — earliest valid claim
  expiry_time: Int,                      // POSIX ms — latest valid claim
  oracle_nft: ByteArray,                 // Charli3 feed NFT policy ID
  pool_script_hash: ScriptHash,          // where residual returns
  pool_nft: ByteArray,                   // [ADDED 2026-04-30] canonical pool NFT — closes A-008
}
```

**Auditor note:** Originally the datum carried `pool_script_hash` but not the canonical `pool_nft`, which is what A-008 flagged. The `pool_nft` field has been added as part of the 2026-04-30 Priority-1 remediation; `Claim` / `BatchClaim` / `Expire` / `BatchExpire` / `Cancel` now route residuals via `find_canonical_pool_output(pool_script_hash, pool_nft)`.

#### PoolDatum (`types.ak:58`)

```aiken
pub type PoolDatum {
  total_liquidity: Int,                  // ADA deposited by LPs (lovelace)
  active_coverage: Int,                  // ADA reserved for active policies (lovelace)
  lp_token_policy: ByteArray,            // aLP minting policy ID
  protocol_fee_bps: Int,                 // 200 = 2%
  pool_nft: ByteArray,                   // identifies THIS pool UTxO (uniqueness)
  lp_supply: Int,                        // [ADDED 2026-04-30] outstanding aLP supply — closes A-003
}
```

**Auditor note:** Pool initialization (creating the canonical pool with the NFT) is not enforced on-chain — see finding **A-011** (still open). The `lp_supply` field was added as part of the 2026-04-30 Priority-1 remediation so that `AddLiquidity` and `RemoveLiquidity` can verify the exact mint/burn magnitude.

### Redeemer Structures

#### PolicyRedeemer (`types.ak:76`)

```aiken
pub type PolicyRedeemer {
  Claim         // single — oracle ≤ strike, in window → pays insured
  BatchClaim    // multi — N policies in one tx (see A-006)
  Expire        // tx_lower > expiry → returns full UTxO to pool
  BatchExpire   // multi-expire
  Cancel        // signed by insured, within 1h grace → 90% refund
}
```

#### PoolRedeemer (`types.ak:94`)

```aiken
pub type PoolRedeemer {
  Underwrite      { coverage: Int, premium: Int }
  BatchUnderwrite { total_coverage: Int, total_premium: Int }
  ProcessClaim    { payout: Int, policy_script: ScriptHash }
  BatchExpireProcess { total_returned: Int, policy_script: ScriptHash }
  AddLiquidity    { amount: Int }
  RemoveLiquidity { amount: Int }
}
```

#### LPTokenRedeemer (`types.ak:140`)

```aiken
pub type LPTokenRedeemer { MintLP, BurnLP }
```

### Protocol Constants (`types.ak:152`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `min_premium` | 2,000,000 (2 ADA) | Floor on premium |
| `max_coverage_ratio` | 50 | Coverage ÷ premium ≤ 50× |
| `cancellation_window` | 3,600,000 ms (1 h) | Free-cancellation grace |
| `cancellation_fee_bps` | 1,000 (10%) | Cancellation penalty |
| `price_scale` | 1,000,000 | Charli3 price scale |
| `min_utxo_lovelace` | 2,000,000 (2 ADA) | Cardano min-UTxO |

### Security Properties (intended)

1. **Single-input claim** — only one policy UTxO from the policy validator may be consumed per `Claim` redeemer (F-001).
2. **Value preservation** — all funds leaving a policy UTxO are accounted for: payout to insured + remainder to pool (F-002, F-003).
3. **Premium adequacy** — every policy meets minimum premium and maximum coverage-to-premium ratio.
4. **Pool solvency** — `total_liquidity ≥ active_coverage` at all times (intended; see A-005 for failure mode).
5. **LP authorization** — aLP tokens may only be minted/burned when the pool is being consumed (parameterized minting policy).
6. **Oracle freshness** — claim transactions require `oracle_expiry > tx_lower_bound`.
7. **Time bounds** — claims fall within `[start_time, expiry_time]`; cancellations within `[start_time, start_time + cancellation_window]`; expirations after `expiry_time`.
8. **Datum integrity** — pool datum updates are arithmetically constrained (`new_total = old_total ± delta`).

The findings below describe how each of these properties can be violated in the current code.

---

## Methodology

### Threat Model

The audit assumes the following adversary capabilities:

1. **Public chain access.** Any participant can submit any transaction to the Cardano mempool.
2. **Mempool observation.** Adversaries can observe pending transactions and front-run / sandwich them.
3. **Arbitrary input construction.** An attacker can construct any combination of inputs, outputs, datums, and redeemers within Cardano's protocol rules.
4. **Wealth.** Adversaries are willing to spend reasonable amounts of ADA (up to ~5% of pool TVL) on griefing or theft attacks.
5. **Charli3 oracle integrity.** The Charli3 ODV oracle is treated as TRUSTED — i.e., the audit does not consider attacks on Charli3 itself, only how Aegis consumes Charli3 data.
6. **No keys compromised.** Attackers do not control LP, insured, or protocol multisig keys directly. They may control any number of fresh wallets.

### Attack Surface Categories

The audit examined the following attack categories systematically:

| # | Category | Examples |
|---|----------|----------|
| 1 | Datum forgery | Crafting policy UTxOs without paying premium |
| 2 | Value preservation bypass | Stealing residual on Claim/Expire/Cancel |
| 3 | Double satisfaction | One output satisfying multiple validator obligations |
| 4 | Pool-state manipulation | Drain via direct pool spend |
| 5 | LP token attacks | Free mint, wrong-direction mint, dilution |
| 6 | Oracle reference attacks | Substitution, staleness, cross-feed confusion |
| 7 | Time / validity range | Slot vs POSIX edge cases, infinite bounds |
| 8 | Concurrency / MEV | Front-running, batched-tx race conditions |
| 9 | Economic griefing | DoS by reserving capacity, fee siphons |
| 10 | Cross-validator boundary | Mismatched assumptions between policy, pool, LP |
| 11 | Address / credential attacks | Stake hijacking, address spoofing |
| 12 | Integer overflow / division | Truncation, division-by-zero |

The findings below cite the relevant category for each issue.

### Process

1. **Source review.** Every line of every Aiken file in `lib/aegis/` and `validators/` was read and traced.
2. **Cross-validator analysis.** Each redeemer's assumptions about the OTHER validators were tested.
3. **PoC construction.** For each suspected issue, a concrete attack transaction was constructed mentally and traced through every check.
4. **Existing-fix validation.** The fixes documented as F-001 through F-009 were re-verified — A-005 demonstrates one such fix is non-functional.

---

## Vulnerability Analysis & Findings

### A-001: Pool Drainable via Attacker-Crafted Policy UTxO and Unchecked ProcessClaim Payout

**Severity:** 🔴 **CRITICAL**
**Impact:** Total loss of pool funds (any participant)
**Likelihood:** Trivial
**Categories:** 1 (datum forgery), 4 (pool drain), 10 (cross-validator boundary)

**Location:**
- `contracts/validators/pool.ak:115` (`ProcessClaim` handler)
- `contracts/validators/policy.ak:69` (`Claim` handler)

**Description**

The pool's `ProcessClaim` redeemer accepts an arbitrary `payout: Int` parameter and decrements the pool by that amount. The only sanity check on `payout` is that it is positive and that **some** policy UTxO from `policy_script` was consumed in the same transaction:

```aiken
// pool.ak:115
ProcessClaim { payout, policy_script } -> {
  ...
  let payout_positive = payout > 0
  let policy_consumed = count_script_inputs(inputs, policy_script) >= 1
  ...
  let value_ok =
    assets.lovelace_of(cont_output.value) >= assets.lovelace_of(own_value) - payout
  let remains_solvent = new_datum.total_liquidity >= new_datum.active_coverage
  payout_positive && policy_consumed && datum_ok && immutable_ok && value_ok && remains_solvent
}
```

There is **no check that `payout` matches the consumed policy's `coverage_amount`**, and **no check that the consumed policy was legitimately created via the pool's `Underwrite` flow**. Any UTxO sitting at the policy validator's address is treated as a "policy" for the purposes of `count_script_inputs`.

**An attacker can therefore:**

1. Send a small amount of ADA (≥ min UTxO) to the policy validator address with a freely-chosen `PolicyDatum`.
2. In a single subsequent transaction, spend that synthetic policy via `Claim` AND spend the real pool via `ProcessClaim { payout: <pool_total> }`.
3. Pay themselves the entire pool.

The policy validator's `Claim` checks all pass against a self-constructed datum:

| Check | How it's bypassed |
|-------|-------------------|
| `single_policy_input` | Attacker consumes only their own synthetic policy |
| `price_below_strike` | Attacker sets `strike_price = 999_999_999_999` so any oracle reading passes |
| `oracle_fresh` | Real Charli3 oracle UTxO is used as reference input |
| `within_start` | Attacker sets `start_time = 0` |
| `within_expiry` | Attacker sets `expiry_time = 99_999_999_999_999` |
| `payout_valid` | The output to `insured` (attacker) is `≥ coverage_amount` (which is small, e.g., 2 ADA) — overpaying is allowed by `output_has_min_lovelace` |
| `pool_receives_remainder` | Synthetic policy UTxO has value 2 ADA; coverage is 2 ADA; expected_remainder = 0 → check trivially passes |

The pool validator's `ProcessClaim` checks also pass:

| Check | How it's bypassed |
|-------|-------------------|
| `payout_positive` | `payout = pool_total` is positive |
| `policy_consumed` | The synthetic policy IS consumed; F-004 is satisfied |
| `datum_ok` | Attacker constructs `new_total = old_total - pool_total`, `new_active = old_active - pool_total` to satisfy `verify_claim_datum` |
| `immutable_ok` | Attacker preserves `lp_token_policy`, `protocol_fee_bps`, `pool_nft` |
| `value_ok` | New continuation pool UTxO has value ≥ `old_value - pool_total` (i.e., effectively zero — attacker takes everything) |
| `remains_solvent` | `new_total >= new_active` after both decrement by the same amount; see **A-005** |

**Proof of Concept**

```python
# Pseudocode — single transaction draining the entire pool

# Step 1 (independent, can be done much earlier):
# Send 2 ADA to policy_validator with crafted PolicyDatum:
synthetic_policy_datum = PolicyDatum(
    policy_id          = blake2b("attack"),
    insured            = ATTACKER_PKH,
    strike_price       = 999_999_999_999,    # always above any oracle reading
    coverage_amount    = 2_000_000,          # 2 ADA
    premium_paid       = 0,                  # not checked on-chain
    start_time         = 0,
    expiry_time        = 99_999_999_999_999,
    oracle_nft         = CHARLI3_ADA_USD_NFT,
    pool_script_hash   = AEGIS_POOL_SCRIPT_HASH,
)
synthetic_policy_utxo = build_utxo(
    address  = policy_validator_address,
    value    = lovelace(2_000_000),
    datum    = inline(synthetic_policy_datum),
)
submit_tx(outputs=[synthetic_policy_utxo])

# Step 2 — drain transaction:
drain_tx = Transaction(
    inputs = [
        synthetic_policy_utxo,    # Redeemer: PolicyRedeemer.Claim
        real_pool_utxo,           # Redeemer: PoolRedeemer.ProcessClaim {
                                  #   payout: real_pool_utxo.lovelace - 2_000_000,
                                  #   policy_script: POLICY_SCRIPT_HASH,
                                  # }
    ],
    reference_inputs = [charli3_oracle_utxo],
    outputs = [
        # Pay attacker the entire pool minus a small continuation
        Output(addr=ATTACKER_ADDR, value=lovelace(pool_total - 4_000_000)),
        # Pool continuation with the NFT, datum decremented to ~0
        Output(
            addr  = pool_validator_address,
            value = lovelace(2_000_000) + pool_nft,
            datum = inline(PoolDatum(
                total_liquidity   = 0,           # was: pool_total
                active_coverage   = old_active - (pool_total - 2_000_000),  # may go negative
                lp_token_policy   = old.lp_token_policy,
                protocol_fee_bps  = old.protocol_fee_bps,
                pool_nft          = old.pool_nft,
            )),
        ),
        # 2 ADA "remainder" to pool from the synthetic policy (claim path requires this)
        # Already satisfied by the pool continuation containing ≥0 lovelace.
    ],
    validity_range = (now, now + 5min),
)
submit_tx(drain_tx)
# Result: attacker receives ~entire pool. Cost: 2 ADA + tx fee.
```

**Recommendation**

The pool validator must verify that the consumed policy's `coverage_amount` matches the requested `payout` AND that the consumed policy was created through the protocol. Recommended fix:

```aiken
// In pool.ak ProcessClaim — replace `policy_consumed` with:
expect Some(policy_input) =
  list.find(inputs, fn(i) {
    when i.output.address.payment_credential is {
      Script(h) -> h == policy_script
      _ -> False
    }
  })

// Parse the policy datum
expect InlineDatum(raw_policy_datum) = policy_input.output.datum
expect policy_datum: PolicyDatum = raw_policy_datum

// Critical: payout MUST equal the policy's coverage amount
let payout_matches_coverage = payout == policy_datum.coverage_amount

// Critical: policy must point back to THIS pool (prevents fake policies for unrelated pools)
expect Script(own_pool_hash) = own_input.output.address.payment_credential
let policy_targets_this_pool = policy_datum.pool_script_hash == own_pool_hash
```

Additionally, the protocol should require an on-chain proof that the policy's `active_coverage` reservation exists in the pool — most easily by tagging policies with a unique mint (a "policy NFT") that can only be minted by the pool when underwriting. See companion fix in **A-004**.

**Status:** 🟢 **FIXED (2026-04-30)** — verified by `green_a_001_synthetic_policy_drain_is_rejected` and `green_a_001_pool_nft_binding_rejects_unrelated_pool` in `lib/aegis/test_helpers/security_tests.ak`.

Detailed change list:

- `validators/pool.ak` `ProcessClaim` now reads the consumed policy's inline datum and requires `payout == policy.coverage_amount`, `policy.pool_nft == own.pool_nft`, and `policy.pool_script_hash == own_pool_hash`.
- `validators/pool.ak` `BatchExpireProcess` similarly verifies that the sum of consumed-policy values equals `total_returned` via `batch_policies_match_totals`.
- `lib/aegis/types.ak` `PolicyDatum` extended with `pool_nft: ByteArray` so `ProcessClaim` can verify the policy and the pool refer to the same canonical pool UTxO.

---

### A-002: RemoveLiquidity Value-Conservation Check Uses `≤` Instead of `==`, Allowing Pool Drain on Single LP Burn

**Severity:** 🔴 **CRITICAL**
**Impact:** Total loss of pool funds via 1 LP token
**Likelihood:** Trivial (any LP holder)
**Categories:** 4 (pool drain), 5 (LP token attacks)

**Location:** `contracts/validators/pool.ak:225`

**Description**

The `RemoveLiquidity` redeemer's value check uses `≤`:

```aiken
// pool.ak:225
RemoveLiquidity { amount } -> {
  ...
  // 6. Verify output value decreased by withdrawal
  let value_ok =
    assets.lovelace_of(cont_output.value) <= assets.lovelace_of(own_value) - amount
  ...
}
```

This permits the new pool UTxO to have **any value less than or equal to** `own_value - amount`. Because Cardano's transaction-level value conservation forces every input lovelace to appear in some output, any "missing" lovelace from the pool continuation flows to other (attacker-controlled) outputs.

**An attacker holding even 1 LP token can:**

1. Submit `RemoveLiquidity { amount: 1 }` (datum decrements by 1 lovelace).
2. Build the continuation pool UTxO with as little as the min-UTxO ADA (~2 ADA).
3. Receive the entire remaining pool balance minus min-UTxO to their own wallet.

**Proof of Concept**

```python
# Attacker holds 1 aLP token (acquired by depositing 1 ADA legitimately, or any other means).
old_pool_value = 100_000_000_000_000   # 100k ADA in pool
attacker_lp    = 1                     # 1 lovelace-equivalent of LP

drain_tx = Transaction(
    inputs = [real_pool_utxo],         # Redeemer: PoolRedeemer.RemoveLiquidity { amount: 1 }
    mint   = { lp_token_policy: -1 },  # burn 1 aLP token; LP redeemer = BurnLP
    outputs = [
        # Attacker grabs ~all the pool
        Output(addr=ATTACKER_ADDR, value=lovelace(99_999_998_000_000)),
        # Pool continuation has the NFT but only min UTxO
        Output(
            addr  = pool_validator_address,
            value = lovelace(2_000_000) + pool_nft,
            datum = inline(PoolDatum(
                total_liquidity   = old_total - 1,      # decrements by exactly 1
                active_coverage   = old_active,
                lp_token_policy   = old.lp_token_policy,
                protocol_fee_bps  = old.protocol_fee_bps,
                pool_nft          = old.pool_nft,
            )),
        ),
    ],
)

# All checks pass:
#  - amount_positive:        1 > 0                                   ✓
#  - withdrawal_safe:        old_total - 1 >= old_active             ✓
#  - datum_ok:               new_total == old_total - 1              ✓
#  - immutable_ok:           NFT/policy/fee preserved                ✓
#  - value_ok:               2_000_000 ≤ old_value - 1 = HUGE        ✓ (the bug)
#  - lp_burned:              lp_token_policy in mint                 ✓
# LP token policy:
#  - BurnLP & mint_quantity == -1 < 0                                ✓
#  - pool_is_consumed                                                ✓

submit_tx(drain_tx)
# Attacker walks away with ~99,997 ADA. Pool now holds 2 ADA but datum claims old_total - 1.
```

After this attack, the pool's datum claims a `total_liquidity` of nearly 100k ADA but the UTxO only has 2 ADA. All future operations that rely on the datum (subsequent claims, withdrawals) will fail at value-balance time, but the attacker has already extracted the funds.

**Recommendation**

Use exact equality on the value check:

```aiken
// pool.ak:225 — replace with:
let value_ok =
  assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) - amount
```

Apply the same `==` rule to **every** pool value check (`AddLiquidity`, `Underwrite`, `BatchUnderwrite`, `ProcessClaim`, `BatchExpireProcess`). See companion finding **A-007** for `AddLiquidity`.

Additionally, require the LP burn quantity to equal `amount` (currently the LP token policy only checks the sign, not the magnitude). The pool validator should compute `expected_lp_burn = calculate_lp_to_burn_for(amount)` from the canonical formula and assert `mint_quantity == -expected_lp_burn`.

**Status:** 🟢 **FIXED (2026-04-30)** — verified by `green_a_002_remove_liquidity_lp_burn_amount_mismatch_rejected` and `green_a_002_legitimate_proportional_withdrawal_accepted` in `lib/aegis/test_helpers/security_tests.ak`.

Detailed change list:

- `validators/pool.ak` `RemoveLiquidity` value check changed from `<=` to `==`.
- LP burn quantity is now bound to the withdrawal via `verify_remove_liquidity_datum`, which calls `calculate_withdrawal` and requires the mint quantity to equal `new.lp_supply - old.lp_supply` (with sign).
- All other pool value checks (`Underwrite`, `BatchUnderwrite`, `ProcessClaim`, `BatchExpireProcess`, `AddLiquidity`) tightened to `==` in the same pass — see A-007.

---

### A-003: Pool Deposit/Withdraw Don't Bind to LP Mint Direction, Allowing Free LP Token Mint

**Severity:** 🔴 **CRITICAL**
**Impact:** Free LP token issuance → indirect pool drain via subsequent withdraw
**Likelihood:** Trivial
**Categories:** 5 (LP token attacks), 10 (cross-validator boundary)

**Location:**
- `contracts/validators/pool.ak:188` (`AddLiquidity` lp_minted check)
- `contracts/validators/pool.ak:233` (`RemoveLiquidity` lp_burned check)
- `contracts/validators/lp_token.ak:42` (`MintLP` / `BurnLP` magnitude not bound)

**Description**

The pool validator's `AddLiquidity` and `RemoveLiquidity` handlers verify only that the LP token policy ID **appears in** the transaction's `mint` field — not the direction (mint vs burn) or the magnitude:

```aiken
// pool.ak:188 (AddLiquidity)
let lp_minted =
  assets.policies(mint)
    |> list.has(datum.lp_token_policy)

// pool.ak:233 (RemoveLiquidity)
let lp_burned =
  assets.policies(mint)
    |> list.has(datum.lp_token_policy)
```

Since the `mint` field can contain a positive (mint) or negative (burn) quantity, an attacker can **invoke `RemoveLiquidity` while actually MINTING new LP tokens** (or vice-versa). The LP token policy itself runs only once per transaction with a single redeemer, so its `MintLP / BurnLP` enforcement only sees the *sign*, not the *intent*:

```aiken
// lp_token.ak:42
when redeemer is {
  MintLP -> pool_is_consumed && mint_quantity > 0
  BurnLP -> pool_is_consumed && mint_quantity < 0
}
```

**An attacker can:**

1. Submit a transaction with `PoolRedeemer.RemoveLiquidity { amount }` (withdraws ADA from the pool).
2. Use `LPTokenRedeemer.MintLP` on the LP token policy with a positive mint quantity (mints fresh LP tokens to the attacker).
3. The pool's `lp_burned` check passes because the LP policy ID is "in mint" (just with a positive sign).
4. The LP policy's `MintLP` check passes because `mint_quantity > 0` and the pool is consumed.

Result: the attacker withdraws ADA from the pool AND receives free new LP tokens that they can later redeem for more ADA.

**Proof of Concept**

```python
# Step 1 — Free LP mint via RemoveLiquidity
attack_tx = Transaction(
    inputs = [real_pool_utxo],
    redeemers = {
        real_pool_utxo: PoolRedeemer.RemoveLiquidity { amount: 1 },
        # LP token policy redeemer:
        lp_token_policy: LPTokenRedeemer.MintLP,
    },
    mint = { lp_token_policy: +1_000_000 },   # MINT 1 million aLP, not burn
    outputs = [
        Output(addr=ATTACKER_ADDR, value=lovelace(1) + lp_tokens(1_000_000)),
        # Pool continuation: total_liquidity decremented by 1
        Output(addr=pool_addr, value=..., datum=inline(...)),
    ],
)
# All pool checks pass:
#   amount_positive: 1 > 0                                                  ✓
#   withdrawal_safe: total - 1 >= active                                    ✓
#   datum_ok:        new_total == old_total - 1                             ✓
#   value_ok:        new_value <= old_value - 1                             ✓ (A-002)
#   lp_burned:       lp_token_policy in [lp_token_policy] = True            ✓ (the bug)
# LP token policy passes:
#   MintLP & mint_quantity == +1_000_000 > 0                                ✓
#   pool_is_consumed                                                        ✓

# Step 2 — Withdraw against the freely-minted LP tokens
withdraw_tx = Transaction(
    inputs = [real_pool_utxo_v2],
    redeemers = {
        real_pool_utxo_v2: PoolRedeemer.RemoveLiquidity { amount: 1_000_000 },
        lp_token_policy: LPTokenRedeemer.BurnLP,
    },
    mint = { lp_token_policy: -1_000_000 },   # actually burn this time
    ...
)
# Or — combined with A-002 — drain the pool entirely in step 1 alone.
```

This finding **compounds** with A-002: the attacker mints free LP tokens AND drains the pool's actual lovelace in the same transaction.

**Recommendation**

Both pool and LP-token validators must agree on direction AND magnitude.

In `pool.ak`, replace the bare `list.has` checks with explicit direction + magnitude:

```aiken
// AddLiquidity — verify positive mint of EXACTLY the expected LP amount
let expected_lp = calculate_lp_mint(amount, datum.total_liquidity, lp_supply)  // requires LP supply tracking
let lp_minted = assets.quantity_of(mint, datum.lp_token_policy, ASSET_NAME) == expected_lp

// RemoveLiquidity — verify negative mint of EXACTLY the expected burn amount
let expected_burn = calculate_lp_to_burn(amount, datum.total_liquidity, lp_supply)
let lp_burned = assets.quantity_of(mint, datum.lp_token_policy, ASSET_NAME) == -expected_burn
```

To implement this, the pool datum must track `lp_supply`. The LP token name must also be canonicalized (currently the LP policy uses `assets.reduce` over **all** asset names under the policy — see A-003 secondary issue).

**Status:** 🟢 **FIXED (2026-04-30)** — verified by `green_a_003_burn_during_addliquidity_rejected` and `green_a_003_mint_during_removeliquidity_rejected` in `lib/aegis/test_helpers/security_tests.ak`.

Detailed change list:

- `lib/aegis/types.ak` `PoolDatum` extended with `lp_supply: Int` (outstanding aLP supply).
- `validators/pool.ak` `AddLiquidity` and `RemoveLiquidity` now read the exact mint quantity from the transaction and require it to equal `new.lp_supply - old.lp_supply` (signed). Direction and magnitude are bound on both sides.
- `verify_add_liquidity_datum` / `verify_remove_liquidity_datum` enforce magnitude via `calculate_lp_mint` / `calculate_withdrawal` against the new `lp_supply` field.

---

### A-004: Underwrite Doesn't Require Corresponding Policy UTxO Output, Enables active_coverage Griefing

**Severity:** 🔴 **HIGH**
**Impact:** Permanent pool DoS for ~2% of pool TVL
**Likelihood:** Trivial
**Categories:** 9 (economic griefing), 10 (cross-validator boundary)

**Location:** `contracts/validators/pool.ak:73` (`Underwrite` handler)

**Description**

The `Underwrite` redeemer increments `active_coverage` in the pool datum and ingests the premium, but does **not** verify that a corresponding policy UTxO is created at the policy validator address:

```aiken
// pool.ak:73
Underwrite { coverage, premium } -> {
  expect Some(cont_output) = pool_output
  ...
  let premium_ok = is_premium_adequate(premium, coverage)
  let can_cover = can_underwrite(datum.total_liquidity, datum.active_coverage, coverage)
  let net = net_premium(premium, datum.protocol_fee_bps)
  let datum_ok = verify_underwrite_datum(...)        // datum-only check
  let immutable_ok = ...
  let value_ok = pool_value >= old_value + premium   // pool just gets the premium
  premium_ok && can_cover && datum_ok && immutable_ok && value_ok
}
```

There is **no enforcement that an `Output` with `address == policy_validator_address` exists** with matching `coverage_amount`. An attacker can:

1. Spend the pool with `Underwrite { coverage: A, premium: P }`.
2. Set the new pool datum to `active_coverage += A` and `total_liquidity += net_premium`.
3. Provide value to the pool of `+P` (the premium).
4. Create no policy output at all — the redeemer succeeds.

The premium-adequacy check (`coverage / premium ≤ 50`) limits the leverage but not the absolute magnitude. With the minimum 2 ADA premium, attacker can lock 100 ADA of `active_coverage` per attack at ~2% cost.

To fully exhaust a 100,000 ADA pool's `active_coverage` headroom, the attacker spends ~2,000 ADA in premiums (2%). Once `active_coverage == total_liquidity`, no further legitimate underwriting is possible. There is **no on-chain mechanism to release the bogus reservation** because:

- `BatchExpireProcess` requires consuming a real policy UTxO (which the attacker never created).
- `ProcessClaim` requires consuming a real policy UTxO (same).

The only recovery path is for legitimate LPs to add liquidity until `total_liquidity` exceeds bogus `active_coverage` — but the attacker can immediately re-grief the new headroom for the same 2% cost.

**Proof of Concept**

```python
# Pool currently has 100,000 ADA total, 0 active. Attacker wants to grief.
attack_tx = Transaction(
    inputs = [real_pool_utxo],   # Redeemer: PoolRedeemer.Underwrite { coverage: 100, premium: 2 }
    outputs = [
        Output(
            addr  = pool_validator_address,
            value = old_value + lovelace(2_000_000),   # +2 ADA premium
            datum = inline(PoolDatum(
                total_liquidity = old_total + (2_000_000 - 40_000),   # net premium (2% fee)
                active_coverage = old_active + 100_000_000,           # +100 ADA reserved
                ...immutable...
            )),
        ),
        # NO policy output — but the redeemer doesn't require one.
    ],
)
submit_tx(attack_tx)

# Repeat ~1,000 times to lock 100k ADA of active_coverage. Total cost: ~2,000 ADA in premiums.
# The pool is now 100% utilized by phantom reservations.
# can_underwrite() returns False for any further legitimate user.
```

**Recommendation**

The `Underwrite` redeemer must require a policy UTxO output with matching coverage:

```aiken
// pool.ak — inside Underwrite handler:

// Find the new policy UTxO at the policy validator address
expect Some(policy_out) =
  list.find(outputs, fn(out) {
    when out.address.payment_credential is {
      Script(h) -> h == own_datum.policy_script_hash  // requires policy_script_hash in PoolDatum
      _ -> False
    }
  })

// Parse the new policy datum
expect InlineDatum(raw_pdat) = policy_out.datum
expect new_policy_datum: PolicyDatum = raw_pdat

// The policy must exactly match the underwrite parameters
let policy_coverage_matches = new_policy_datum.coverage_amount == coverage
let policy_premium_matches  = new_policy_datum.premium_paid == premium
let policy_value_funds_payout = assets.lovelace_of(policy_out.value) >= coverage  // pool reserves coverage in the policy UTxO

// And the policy must not be already in-the-money (anti-frontrunning):
//   strike_price < oracle_price_at_creation_time
// (off-chain caller passes oracle price as part of redeemer or via reference input)
```

**Status:** 🟢 **FIXED (2026-04-30)** — verified by `green_a_004_underwrite_with_no_policy_output_rejected` in `lib/aegis/test_helpers/security_tests.ak`.

Detailed change list:

- `validators/pool.ak` adds the `policy_output_matches_underwrite` helper, which verifies that an output exists at a script address whose inline `PolicyDatum` carries this pool's `pool_nft` and matches the redeemer's `coverage` and `premium`.
- `Underwrite` now requires `policy_output_matches_underwrite` to succeed; absent or mismatched policy outputs cause the redeemer to fail.
- `BatchUnderwrite` uses `batch_policies_match_totals`: the sum of the policy coverages on the output side must equal the redeemer's `total_coverage` (and similarly for premium).
- The in-the-money guard at policy creation is deferred to Priority-2 (tracked under A-010 and A-015).

---

### A-005: Pool ProcessClaim Solvency Check Is Mathematically Equivalent to Pre-State (F-007 Is Non-Functional)

**Severity:** 🔴 **HIGH**
**Impact:** False sense of security; the named "solvency check" provides no protection
**Likelihood:** N/A (definitional)
**Categories:** 10 (cross-validator boundary), 12 (math edge)

**Location:** `contracts/validators/pool.ak:148`

**Description**

The fix labelled F-007 in the code intends to enforce solvency after a claim:

```aiken
// pool.ak:148
// [FIX F-007] Verify pool remains solvent after claim
let remains_solvent = new_datum.total_liquidity >= new_datum.active_coverage
```

However, the `verify_claim_datum` function (called immediately above) requires:

```aiken
// pool.ak:104 (lib/aegis/pool.ak)
new_total == old_total - payout
new_active == old_active - payout
```

**Both fields decrement by exactly the same `payout`.** Therefore:

```
new_total - new_active
  = (old_total - payout) - (old_active - payout)
  = old_total - old_active
```

So `new_total >= new_active` **if and only if** `old_total >= old_active`. Since the previous transaction must have left the pool solvent, the F-007 check is **always satisfied** regardless of `payout`. It catches no actual misuse.

In particular, when combined with **A-001**, an attacker can pass `payout = 999_999_999_999` and both `new_total` and `new_active` go deeply negative — but `new_total - new_active` is still equal to the old positive difference, so the "solvency" check passes.

**Proof of Concept**

```aiken
// In aegis/pool.ak — already documented in tests:
test verify_claim_datum_allows_excessive_payout_math() {
  let new_total = 1_000_000_000 - 600_000_000      // = 400M
  let new_active = 500_000_000 - 600_000_000       // = -100M
  let datum_passes = verify_claim_datum(
    1_000_000_000, 500_000_000, new_total, new_active, 600_000_000,
  )
  let active_negative = new_active < 0
  // Test asserts both are true — i.e., the datum check passes despite negative active.
  datum_passes && active_negative
}
```

Note the existing test asserts `datum_passes && active_negative` is true, demonstrating the math IS broken. The F-007 check intends to catch this — but as shown above, it cannot.

**Recommendation**

Replace the F-007 line with a check that the post-state is non-negative:

```aiken
let remains_solvent =
     new_datum.total_liquidity >= 0
  && new_datum.active_coverage >= 0
  && new_datum.total_liquidity >= new_datum.active_coverage
```

Better still, rewrite `verify_claim_datum` to require `payout ≤ old_active` (you can only pay out from active coverage):

```aiken
// In lib/aegis/pool.ak
pub fn verify_claim_datum(
  old_total: Int, old_active: Int,
  new_total: Int, new_active: Int,
  payout: Int,
) -> Bool {
  payout >= 0
    && payout <= old_active                                // payout cannot exceed reserved coverage
    && new_total == old_total - payout
    && new_active == old_active - payout
    && new_total >= 0
    && new_active >= 0
}
```

**Status:** 🟢 **FIXED (2026-04-30)** — verified by `green_a_005_verify_claim_datum_rejects_excessive_payout`, `green_a_005_verify_claim_datum_rejects_negative_payout`, and `green_a_005_verify_claim_datum_accepts_legitimate` in `lib/aegis/test_helpers/security_tests.ak`.

Detailed change list:

- `lib/aegis/pool.ak` `verify_claim_datum` extended to additionally require `payout >= 0`, `payout <= old_active`, `new_total >= 0`, and `new_active >= 0`.
- `validators/pool.ak` `ProcessClaim`'s `remains_solvent` clause is now meaningful: combined with the strengthened `verify_claim_datum`, an excessive `payout` is rejected at the datum-transition layer rather than at a downstream tautology.
- The pre-fix red test `red_true_a_005_verify_claim_datum_rejects_excessive_payout` (which asserted the broken behaviour) has been replaced with the three green tests above.

---

### A-006: BatchClaim Allows Single Payout Output to Satisfy Multiple Same-Insured Policies

**Severity:** 🔴 **HIGH**
**Impact:** Insured loses payouts; protocol's `active_coverage` becomes overstated, restricting LPs
**Likelihood:** Moderate (only same-insured + batched scenario)
**Categories:** 3 (double satisfaction)

**Location:** `contracts/validators/policy.ak:132` (`BatchClaim` handler)

**Description**

`BatchClaim` allows multiple policy UTxOs to be consumed in a single transaction. For each consumed policy, the validator independently checks:

```aiken
// policy.ak:153
let payout_output = find_output_to_pkh(outputs, datum.insured)
let payout_valid =
  when payout_output is {
    Some(output) -> output_has_min_lovelace(output, datum.coverage_amount)
    None -> False
  }
```

`find_output_to_pkh` returns the **first** output whose `payment_credential` matches the given PKH. If two batched policies share the same `insured` PKH (e.g., a single user with multiple policies, or two policies merged onto one wallet), both per-policy checks reference **the same output**. A single payout of `max(coverage_a, coverage_b)` lovelace satisfies both.

The accompanying code comment ("the pool validator's ProcessClaim ensures the total payout matches the sum of all coverages") is **incorrect**: `ProcessClaim` accepts a single `payout` parameter and decrements the pool by that amount, with no requirement that it equals the sum of consumed coverages.

**Consequences:**

- The batched claimer is short-paid (gets `max(cov_a, cov_b)` instead of `cov_a + cov_b`).
- The pool's `active_coverage` decrements by only `payout`, not by the sum of all consumed coverages — so `active_coverage` is permanently **overstated** by the difference. Future LPs are restricted from withdrawing funds that are no longer reserved.

This is **not directly exploitable for theft** (the protocol effectively absorbs the difference), but it permanently breaks pool accounting.

**Proof of Concept**

```python
# Two policies both insured to ATTACKER_PKH:
policy_a = PolicyDatum(insured=ATTACKER_PKH, coverage_amount=5_000_000_000, ...)
policy_b = PolicyDatum(insured=ATTACKER_PKH, coverage_amount=5_000_000_000, ...)

batch_claim_tx = Transaction(
    inputs = [policy_a_utxo, policy_b_utxo, real_pool_utxo],
    redeemers = {
        policy_a_utxo: PolicyRedeemer.BatchClaim,
        policy_b_utxo: PolicyRedeemer.BatchClaim,
        real_pool_utxo: PoolRedeemer.ProcessClaim { payout: 5_000_000_000, policy_script: ... },
    },
    outputs = [
        # Single payout of 5 ADA satisfies BOTH per-policy payout_valid checks
        Output(addr=ATTACKER_ADDR, value=lovelace(5_000_000_000)),
        # Pool continuation: decremented by 5 ADA only (not 10)
        Output(addr=pool_addr, value=..., datum=inline(PoolDatum(
            total_liquidity = old_total - 5_000_000_000,
            active_coverage = old_active - 5_000_000_000,    # should be -10
            ...
        ))),
    ],
)
# Both policies consumed; both per-policy checks reference output[0] (5 ADA);
# both pass output_has_min_lovelace(coverage_amount=5_000_000_000).
# Pool decrements by only 5 ADA. Active coverage now overstated by 5 ADA permanently.
```

**Recommendation**

Per-policy payout enforcement must scale with the batch size. The standard fix is to have each policy's check require the output's value to be **the sum** of all batched coverages, OR to require N distinct outputs (one per policy).

Recommended approach — require a **per-policy** output, indexed by policy_id:

```aiken
// In BatchClaim handler — replace find_output_to_pkh with an indexed search:
let payout_output =
  list.find(outputs, fn(out) {
    when out.address.payment_credential is {
      VerificationKey(pkh) ->
        pkh == datum.insured
        // Tag the output with the policy_id via a datum or token to uniquely identify it
        && output_carries_tag(out, datum.policy_id)
      _ -> False
    }
  })
```

Alternatively, mint a one-shot "claim receipt" NFT keyed to `policy_id` and require the payout output to carry it.

**Status:** 🟢 **FIXED (2026-04-30)** — verified by `green_a_006_sum_aggregates_multiple_outputs_to_same_pkh`, `green_a_006_decoy_first_output_does_not_reduce_total`, and `green_a_006_unrelated_outputs_excluded` in `lib/aegis/test_helpers/security_tests.ak`.

Detailed change list:

- `lib/aegis/validation.ak` adds `sum_lovelace_to_pkh`, which folds over all outputs and returns the total lovelace addressed to the given pubkey hash.
- `validators/policy.ak` `Claim`, `BatchClaim`, and `Cancel` all switched from `find_output_to_pkh` (greedy first-match) to `sum_lovelace_to_pkh` for payout/refund verification.
- This single change closes both the A-006 batch-collision exploit and the A-013 decoy-output DoS variant (A-013 remains tracked as 🔴 Open for the residual greedy-match cleanup elsewhere in the codebase).

---

### A-007: AddLiquidity Value Check Uses `≥` Instead of `==`, Dilutes Existing LPs

**Severity:** 🔴 **HIGH**
**Impact:** LPs receive fewer LP tokens than fair share; subsequent withdrawers get short-changed
**Likelihood:** Moderate (LP / off-chain bug, also exploitable)
**Categories:** 4 (pool-state manipulation), 12 (math edge)

**Location:** `contracts/validators/pool.ak:184`

**Description**

The `AddLiquidity` value check uses `≥`:

```aiken
// pool.ak:184
let value_ok =
  assets.lovelace_of(cont_output.value) >= assets.lovelace_of(own_value) + amount
```

This permits the new pool UTxO to hold **more** than `own_value + amount`. Datum-wise, however, `total_liquidity` increments by exactly `amount` (per `verify_add_liquidity_datum`). Excess deposit is "in the pool but not counted in the datum".

**Consequences:**

1. **LPs are silently diluted.** If a depositor accidentally (or maliciously) sends `amount + extra` lovelace, only `amount` is credited to `total_liquidity`. The next LP-supply / total-liquidity ratio computation ignores the `extra`, distributing it across all existing aLP holders pro-rata.
2. **Subsequent calculations drift.** `calculate_withdrawal(lp_burned, total_liquidity, lp_supply)` uses datum's `total_liquidity`, which is now under-counted. Withdrawers receive less than the true pool share.

**Proof of Concept**

```python
# An attacker depositing 1 ADA but sending 100 ADA causes 99 ADA of "phantom" liquidity:
add_tx = Transaction(
    inputs = [real_pool_utxo],
    redeemers = {real_pool_utxo: PoolRedeemer.AddLiquidity { amount: 1_000_000 }},
    outputs = [
        Output(
            addr  = pool_addr,
            value = old_value + lovelace(100_000_000),   # +100 ADA actual
            datum = inline(PoolDatum(
                total_liquidity = old_total + 1_000_000,  # only +1 ADA in datum
                ...
            )),
        ),
    ],
    mint = { lp_token_policy: +1_000_000 },              # mint 1 ADA worth of aLP
)
# value_ok: new_value (old + 100M) >= old + 1M  → True  (BUG)
# Result: pool has +100M lovelace, datum says +1M, attacker holds 1M aLP.
# Other LPs benefit, but the attacker's 1M aLP is now under-valued at withdrawal time.
```

This is also exploitable as a **gift attack** to inflate friendly LPs' apparent yield, or as a **wallet honeypot** to trick a legitimate depositor into "donating" excess to the pool.

**Recommendation**

Use exact equality on the value check, identical to the A-002 fix:

```aiken
let value_ok =
  assets.lovelace_of(cont_output.value) == assets.lovelace_of(own_value) + amount
```

Apply uniformly to **all** pool redeemer value checks.

**Status:** 🟢 **FIXED (2026-04-30)** — verified by `green_a_007_add_liquidity_with_lp_supply_increment_correct` and `green_a_007_add_liquidity_with_under_minted_lp_rejected` in `lib/aegis/test_helpers/security_tests.ak`.

Detailed change list:

- `validators/pool.ak` `AddLiquidity` value check changed from `>=` to `==`.
- The same equality discipline was applied to `Underwrite`, `BatchUnderwrite`, `ProcessClaim`, `BatchExpireProcess`, and `RemoveLiquidity` (the latter under A-002).
- The mint magnitude on `AddLiquidity` is now bound to `new.lp_supply - old.lp_supply` via the new `PoolDatum.lp_supply` field (paired with A-003), so over-deposit can no longer "leak" excess into pool value without a corresponding LP-supply increment.

---

### A-008: Policy Validator's Pool-Output Search by Script Hash Only, Missing NFT Verification

**Severity:** 🔴 **HIGH**
**Impact:** Residuals from Claim/Expire/Cancel can be deposited to a fake pool UTxO at the same script address, locking the funds permanently
**Likelihood:** Low–Moderate (requires building a fake pool UTxO at the script address)
**Categories:** 2 (value preservation bypass), 11 (address attacks)

**Location:**
- `contracts/validators/policy.ak:111` (Claim residual)
- `contracts/validators/policy.ak:163` (BatchClaim residual)
- `contracts/validators/policy.ak:193` (Expire)
- `contracts/validators/policy.ak:222` (BatchExpire)
- `contracts/validators/policy.ak:264` (Cancel)
- `contracts/lib/aegis/validation.ak:57` (`find_output_to_script` helper)

**Description**

When the policy validator routes residual funds to "the pool", it uses `find_output_to_script(outputs, datum.pool_script_hash)`. This returns the **first** output whose payment credential is a Script with matching hash — but does **not** verify the output carries the canonical `pool_nft`.

```aiken
// validation.ak:57
pub fn find_output_to_script(
  outputs: List<Output>,
  script_hash: ScriptHash,
) -> Option<Output> {
  ...
  Script(hash) ->
    if hash == script_hash {
      Some(output)              // first match wins; no NFT check
    } else { ... }
  ...
}
```

Any UTxO at the pool validator address satisfies the check, including a brand-new, attacker-created UTxO that is not the canonical pool. The pool validator only fires on `spend`, so creating such a fake pool UTxO is permitted by the protocol.

**Consequences:**

- An attacker can construct a Claim/Expire/Cancel transaction where the "pool residual" output is a fresh, attacker-controlled UTxO at the pool address (containing only min-UTxO ADA + the residual). This UTxO does not carry the pool_nft, so it cannot be spent by the pool validator's redeemers without violating the `pool_output` continuation NFT check at pool.ak:62 — meaning the funds become permanently stuck.
- Worse: the policy is consumed, the user loses their position, and the pool's `active_coverage` is never decremented (because `ProcessClaim` was not invoked).

This is essentially a **funds-burning DoS** that costs the attacker only the policy-side actions they were going to do anyway.

**Proof of Concept**

```python
expire_attack_tx = Transaction(
    inputs = [policy_utxo],   # Redeemer: PolicyRedeemer.Expire
    outputs = [
        # Fake "pool" output at the right script address but WITHOUT the pool_nft
        Output(
            addr  = pool_validator_address,
            value = lovelace(policy_utxo.value),   # full residual
            datum = NoDatum,                       # not even a valid PoolDatum
        ),
    ],
    validity_range = (after_expiry, after_expiry + 5min),
)
# policy.Expire checks:
#   is_expired:   tx_lower > expiry_time         ✓
#   funds_to_pool: pool_output is Some(...)       ✓ (matches by script_hash)
#                  pool_output has min lovelace   ✓
# Tx succeeds. Residual is now stuck in a pool-address UTxO that the pool validator
# cannot spend (no NFT, no datum, no redeemer path).
```

**Recommendation**

Tighten `find_output_to_script` to require the canonical pool NFT, or introduce a dedicated `find_canonical_pool_output` helper:

```aiken
// validation.ak — new helper:
pub fn find_canonical_pool_output(
  outputs: List<Output>,
  script_hash: ScriptHash,
  pool_nft: ByteArray,
) -> Option<Output> {
  list.find(outputs, fn(out) {
    when out.address.payment_credential is {
      Script(hash) ->
        hash == script_hash
        && (assets.policies(out.value) |> list.has(pool_nft))
      _ -> False
    }
  })
}
```

To use this helper, the policy datum must carry the `pool_nft` (currently it carries `pool_script_hash` only). Add a `pool_nft: ByteArray` field to `PolicyDatum` and verify it on every Claim/Expire/Cancel.

**Status:** 🟢 **FIXED (2026-04-30)** — verified by `green_a_008_find_canonical_pool_output_requires_nft` and `green_a_008_find_canonical_pool_output_returns_none_if_only_fake` in `lib/aegis/test_helpers/security_tests.ak`.

Detailed change list:

- `lib/aegis/types.ak` `PolicyDatum` extended with `pool_nft: ByteArray` (the canonical pool's identifying NFT policy ID).
- `lib/aegis/validation.ak` adds the `find_canonical_pool_output` helper, which requires both the script-hash match AND the presence of the canonical pool NFT in the output's value.
- `validators/policy.ak` `Claim`, `BatchClaim`, `Expire`, `BatchExpire`, and `Cancel` all switched from `find_output_to_script` to `find_canonical_pool_output`. A non-NFT-bearing pool-script-address output can no longer absorb residuals.

---

### A-009: Stake Credential Hijacking on Claim Payout Outputs

**Severity:** ⚠️ **MEDIUM**
**Impact:** Staking rewards on the insured's payout flow to the attacker's stake credential until the insured re-spends the UTxO
**Likelihood:** Moderate (requires attacker to build the claim tx — feasible since claims are open to any submitter)
**Categories:** 11 (address attacks)

**Location:**
- `contracts/lib/aegis/validation.ak:93` (`find_output_to_pkh` matches on payment credential only)
- `contracts/validators/policy.ak:94` (Claim payout check)

**Description**

`find_output_to_pkh` matches an output's `payment_credential`, ignoring the `stake_credential`. A Cardano address is `(payment, stake)` — funds are *spendable* by the payment credential's holder, but **staking rewards** flow to whoever controls the `stake_credential`.

Since Aegis claims can be submitted by anyone (parametric trigger — once the oracle prints below strike, any keeper / MEV bot / arbitrageur can build the claim tx), the *builder* of the claim tx chooses the stake credential of the payout output. A malicious keeper can route the staking rewards on the insured's payout to their own stake credential. The insured retains spending control but does not realize the staking is misdirected.

The economic loss is limited to ~5% APY × time-until-respend. For an insured who leaves the payout at rest (e.g., as collateral), this can compound.

**Proof of Concept**

```python
# Insured's actual address: (insured_pkh, insured_stake_cred)
# Attacker (claim-bot) builds the claim tx output with:
malicious_payout = Output(
    addr = Address(
        payment_credential = VerificationKey(insured_pkh),    # insured controls spending
        stake_credential   = SomeStakeCred(attacker_stake),   # rewards go to attacker
    ),
    value = lovelace(coverage_amount),
    datum = NoDatum,
)
# policy.Claim's find_output_to_pkh(outputs, insured_pkh) matches the payment_credential
# component. payout_valid passes. The policy is consumed; insured got their ADA at the right
# spending key — but staking is hijacked.
```

**Recommendation**

Either (1) require that the payout output's address fully matches a value the insured pre-committed to, or (2) require the payout output's stake credential to match the insured's reverse-resolved canonical stake credential (impossible on-chain), or (3) force the payout output to be **enterprise** (no stake credential):

```aiken
// In policy.ak Claim handler — use a stricter address match:
let payout_output =
  list.find(outputs, fn(out) {
    out.address.payment_credential == VerificationKey(datum.insured)
      && out.address.stake_credential == None        // require enterprise address
  })
```

Add an optional `insured_stake_cred: Option<StakeCredential>` to PolicyDatum and require an exact match if present.

**Status:** 🟢 **FIXED** (2026-04-30) — verified by `green_a_009_enterprise_payout_accepted`, `green_a_009_grafted_stake_payout_excluded`, `green_a_009_grafted_payout_alongside_enterprise_only_counts_enterprise`, plus the migrated `green_a_013_*` and `green_a_006_*` aggregate-helper tests. **Approach taken:** Option (3) — strict enterprise-only payouts. We did NOT add `insured_stake_cred` to `PolicyDatum` because (a) it would require re-mapping every off-chain builder ahead of the Priority-2 deadline, and (b) the report flags Option (3) as preferred for simplicity. The insured retains the freedom to re-spend the payout UTxO into any delegated address afterwards.

**Change list:**

- `lib/aegis/validation.ak` adds `sum_lovelace_to_enterprise_pkh` — aggregates lovelace across outputs whose `payment_credential` is the insured's verification key AND whose `stake_credential` is `None`. The legacy `sum_lovelace_to_pkh` helper is kept (with a doc-comment caveat) for non-payout aggregation; the legacy `find_output_to_pkh` helper is removed entirely (closes A-013, see below).
- `validators/policy.ak` `Claim`, `BatchClaim`, and `Cancel` payout / refund checks all switched from `sum_lovelace_to_pkh` to `sum_lovelace_to_enterprise_pkh`. Any tx whose output to the insured carries a stake credential is now silently ignored by the helper, so the aggregate sum will be insufficient and the validator will reject.
- `validators/policy_simple.ak` (diagnostic-only) likewise migrated to `sum_lovelace_to_enterprise_pkh` for parity — even the fallback path is now safe.

---

### A-010: Cancel Permitted During In-the-Money State Allows Underwriter Cherry-Picking

**Severity:** ⚠️ **MEDIUM**
**Impact:** Insured can cancel a policy that's already claimable, getting 90% premium back instead of the full coverage payout — but underwriters lose the upside they were premium-paid for
**Likelihood:** Moderate (requires price drop within first hour after underwrite)
**Categories:** 9 (economic griefing)

**Location:** `contracts/validators/policy.ak:239` (`Cancel` handler)

**Description**

The `Cancel` redeemer enforces only:
1. Signed by `insured`.
2. `tx_upper ≤ start_time + cancellation_window` (1 hour).

It does **not** check whether the oracle price has crossed the strike — i.e., whether the policy is currently "claimable". Within the 1-hour cancellation window, the insured can wait for the oracle to print, then choose:
- **Claim** — receive full `coverage_amount`.
- **Cancel** — receive 90% of `premium_paid` back.

For an insured who paid a small premium for large coverage (the standard parametric use case — premium ≈ 4% of coverage), cancelling is rarely better than claiming. But the *option to cancel* effectively gives the insured a **free 1-hour optionality window** that underwriters did not price in.

Worse: a sophisticated insured can monitor the oracle and:
- If price *rose* (out-of-the-money) → cancel for 90% premium back, recoup most of the cost.
- If price *fell* (in-the-money) → claim for full coverage.

The 10% cancellation fee is supposed to discount this optionality, but it's a flat 10% — for short-window policies the fee may be too low, and for long-window policies it's grossly excessive (which is its own problem — see economic-design notes).

**Proof of Concept**

```python
# Insured buys 100 ADA coverage for 4 ADA premium.
# Within the first hour, oracle prints between strike+ε and strike-ε:
#   - If oracle prints below strike → claim for 100 ADA payout (net +96).
#   - If oracle stays above strike → cancel for 3.6 ADA refund (net -0.4).
# The expected loss to underwriters is ~50% × (100 − 4) − 50% × 0.4 ≈ +47.8 ADA per policy
# in the insured's favor (when the strike is near-the-money for the first hour).
```

**Recommendation**

Either:

1. **Disallow cancellation when the policy is in-the-money:** require `Cancel` to additionally check `oracle_price > strike_price` (with the oracle treated identically to `Claim`).
2. **Increase the cancellation fee to reflect optionality:** make the fee scale with `(strike_price − oracle_price_at_cancel) / strike_price` so cherry-picking has a real cost.
3. **Shorten the cancellation window** to a few minutes, or remove it entirely. The argument for a window (UX safety net for accidental purchases) is weak when the protocol is a derivative.

Recommended fix code:

```aiken
// policy.ak Cancel handler — add an in-the-money guard:
let oracle_datum = find_oracle_datum(reference_inputs, datum.oracle_nft)
let oracle_price = get_oracle_price(oracle_datum)
let not_in_the_money = oracle_price > datum.strike_price

signed_by_insured && within_window && not_in_the_money && refund_valid && remainder_to_pool
```

**Status:** 🟢 **FIXED** (2026-04-30) — verified by `green_a_010_cancel_otm_passes_in_the_money_guard`, `green_a_010_cancel_itm_fails_in_the_money_guard`, `green_a_010_cancel_at_strike_boundary_is_in_the_money`, `green_a_010_cancel_window_constant_is_one_hour`. **Approach taken:** Option (1) — disallow cancellation when the policy is in-the-money. Options (2) and (3) (scaled fee, shorter window) were rejected because (2) requires economic re-modeling that's out of scope for the Priority-2 pass, and (3) would degrade the legitimate UX use case (accidental purchases). Option (1) is symmetric to Claim's trigger condition and therefore the cleanest fix.

**Change list:**

- `validators/policy.ak` `Cancel` handler now resolves the oracle datum from `reference_inputs` via `find_oracle_datum` (using `datum.oracle_nft`), reads `oracle_price`, and requires `oracle_price > datum.strike_price` before the cancellation succeeds. The freshness check (`is_oracle_valid(oracle_datum, tx_lower)`) is included so a stale oracle cannot be used to bypass the guard. Cancel transactions must now reference the oracle UTxO, mirroring Claim's reference-input requirement.

---

### A-011: No On-Chain Enforcement of Single Canonical Pool

**Severity:** ⚠️ **MEDIUM**
**Impact:** Multiple pool UTxOs could exist, each with separate liquidity; UX confusion and potential fund loss
**Likelihood:** Low (requires off-chain misconfiguration or malicious initial setup)
**Categories:** 10 (cross-validator boundary)

**Location:** `contracts/validators/pool.ak` (initialization not enforced)

**Description**

Aegis assumes a **single canonical pool UTxO** identified by the `pool_nft`. The pool_nft is checked on continuation (`output_has_nft(output, datum.pool_nft)`) — so existing pool spends preserve the NFT. However, there is no on-chain mechanism that prevents multiple pool UTxOs from existing simultaneously.

If the pool's NFT minting policy is loosely configured (or the NFT is a fungible token rather than a true one-shot), multiple pool UTxOs at the same script address could exist with different `pool_nft` values, or with the same value but conflicting datums. Policies created against one pool would cite that pool's `pool_script_hash` (and per recommendations in A-008, `pool_nft`) — but nothing prevents a second pool from existing.

This is primarily a **configuration / governance concern** — the protocol is safe **if and only if** the NFT minting policy is a proper one-shot script (typically using a `tx_outref` parameter to bind the NFT to a specific input).

**Recommendation**

1. The Aegis deployment script must use a one-shot NFT minting policy parameterized by a specific UTxO reference at initialization. This is standard practice.
2. The NFT minting policy must be reviewed and its compiled hash documented in deployment artifacts.
3. Document the pool `pool_nft` value as part of the protocol parameters, and have the off-chain code (and any auditors) verify the canonical pool UTxO carries this exact NFT.

**Status:** 🟢 **FIXED** (2026-04-30) — verified by `pool_nft_logic_consumed_and_one_minted`, `pool_nft_logic_init_utxo_not_consumed_rejected`, `pool_nft_logic_more_than_one_token_minted_rejected`, `pool_nft_logic_extra_asset_name_under_policy_rejected`, `pool_nft_logic_burn_path_negative_quantity`, `pool_nft_logic_zero_mint_rejected`, plus the cross-cutting `green_a_011_pool_nft_is_required_for_canonical_output` and `green_a_011_pool_nft_policy_id_carried_in_pool_datum`.

**Change list:**

- `validators/pool_nft.ak` (NEW) — a one-shot minting policy parameterized by an `OutputReference` and an asset-name `ByteArray`. The mint path requires (a) the parameterized init UTxO is consumed in the tx, (b) `quantity_of(mint, policy_id, token_name) == 1`, and (c) the **total** quantity minted under the policy id equals 1 (to block "graft an extra asset name onto the same mint" attempts). A burn path (`total < 0`) is permitted as a safety valve in case the canonical pool ever needs retirement; the pool validator gates whether such a burn is well-formed via its spend logic.
- The deployment flow is documented in a comment at the top of `pool_nft.ak`: pick an init UTxO, parameterize, compile, and submit the canonical pool-creation tx that consumes it. Once spent, the parameter can never be re-satisfied — a true one-shot.
- `PoolDatum.pool_nft` and `PolicyDatum.pool_nft` are unchanged: they hold the compiled minting policy id of `pool_nft.ak` (parameterized for this deployment), and the existing `find_canonical_pool_output` helper enforces its presence on every residual at the pool address.

---

### A-012: BatchClaim Does Not Enforce Uniform Oracle Reference Across Batched Policies

**Severity:** ⚠️ **MEDIUM**
**Impact:** Policies with different oracle_nft values can be batched together if their individual oracle datums all happen to be in reference_inputs — but the batched validation does not enforce that the SAME oracle was checked against all policies
**Likelihood:** Low (requires unusual policy mix)
**Categories:** 6 (oracle reference attacks)

**Location:** `contracts/validators/policy.ak:138` (`BatchClaim` oracle handling)

**Description**

In `BatchClaim`, each consumed policy independently runs the same handler, calling `find_oracle_datum(reference_inputs, datum.oracle_nft)` with **its own** oracle_nft. If all policies in the batch share an oracle_nft, this is fine. But there is no validator-level enforcement that all batched policies use the same feed.

If the off-chain code accidentally batches policies with different oracle feeds (e.g., DJED depeg + ADA crash), each policy resolves its own oracle independently. This is technically correct but:

1. Increases the surface for off-chain bugs (mixing depeg + crash policies).
2. Allows constructing batches where one feed is fresh (passes `oracle_fresh`) and another is stale — but the batched policies' `payout_valid` references the same outputs, intersecting with **A-006** above.

**Proof of Concept** *(scenario, not exploit)*

A user has three policies:
- Policy 1: ADA/USD strike 0.40, oracle = Charli3 ADA/USD.
- Policy 2: DJED/USD strike 0.95, oracle = Charli3 DJED/USD.
- Policy 3: ADA/USD strike 0.30, oracle = Charli3 ADA/USD.

In a `BatchClaim` tx, the user includes all three policies, both Charli3 oracles in reference_inputs, and a single payout output. Each policy independently:
- Locates ITS oracle (correct).
- Verifies its strike, freshness, time bounds.
- Checks payout_output for the user's PKH (the same output for all three).

If the single payout output is just enough to cover Policy 1's coverage, Policies 2 and 3 are also "satisfied" (per A-006), and their `active_coverage` is over-decremented in the pool's accounting.

**Recommendation**

For BatchClaim, either:

1. Require all policies in the batch to share the same `oracle_nft` (validator-level check via redeemer-level batched datum).
2. Move oracle resolution into the pool's `ProcessClaim` and pass the policy's oracle_nft along with the payout amount, so that all policies in a batch can be verified at once.

Combined with the **A-006** fix (per-policy outputs tagged by policy_id), this becomes more straightforward.

**Status:** 🟢 **FIXED** (2026-04-30) — verified by `green_a_012_two_policies_same_oracle_are_uniform`, `green_a_012_two_policies_different_oracles_not_uniform`, `green_a_012_alt_oracle_fixture_distinct_from_default`. **Approach taken:** Option (1) — validator-level uniformity check across all consumed policies. We did NOT move oracle resolution into the pool (Option 2) because the pool's ProcessClaim is now strictly per-policy after the A-001 fix; threading multiple oracle resolutions through pool would re-introduce the cross-policy coupling the Priority-1 pass deliberately removed.

**Change list:**

- `validators/policy.ak` adds a new local helper `batch_oracles_uniform(inputs, own_script_hash)` that walks every input at the policy validator address, extracts each policy's `oracle_nft` from its inline datum, and returns `True` iff all extracted values are byte-equal. The empty-batch case is `True` because the surrounding redeemer already enforces `count_script_inputs >= 1`.
- `BatchClaim` adds `oracle_uniform` to its conjunction. A tx that batches a Charli3 ADA/USD policy with a Charli3 DJED/USD policy will now fail the uniformity check, even if both oracle UTxOs are present in `reference_inputs` and each individual policy's lookup succeeds. This eliminates the "stale oracle hides among fresh oracles" surface from the audit's PoC.

---

### A-013: find_output_to_pkh Greedy First-Match Enables Payout Collisions

**Severity:** ⚠️ **MEDIUM**
**Impact:** Magnifies A-006 and A-009 by making "the first matching output" the binding semantics
**Likelihood:** Linked to A-006
**Categories:** 3 (double satisfaction), 11 (address attacks)

**Location:** `contracts/lib/aegis/validation.ak:93`

**Description**

The helper returns the first matching output:

```aiken
pub fn find_output_to_pkh(
  outputs: List<Output>,
  pkh: VerificationKeyHash,
) -> Option<Output> {
  when outputs is {
    [] -> None
    [output, ..rest] ->
      when output.address.payment_credential is {
        VerificationKey(hash) ->
          if hash == pkh {
            Some(output)        // first match wins
          } else { ... }
        ...
      }
  }
}
```

This semantic — "any output to the PKH" — is loose enough that:
- Two policies sharing an insured (A-006) both reference the same first-matching output.
- An attacker can prepend a "decoy" tiny output to the insured's PKH to cause `output_has_min_lovelace` to fail on a legitimate claim (DoS).

The DoS variant: build a Claim tx where the first output to the insured is min-UTxO (2 ADA) and the actual payout is at index N. `find_output_to_pkh` returns the first (2 ADA), `output_has_min_lovelace(coverage_amount)` fails, the entire claim tx is rejected. The attacker has now "frozen" the policy until expiry.

**Proof of Concept**

```python
# Attacker monitors the mempool. They see a legitimate Claim tx pending:
legit_claim_tx = Transaction(
    inputs = [policy_utxo, ...],
    outputs = [
        Output(addr=Address(insured_pkh, ...), value=lovelace(5_000_000_000)),  # full payout
        ...
    ],
)

# Attacker frontruns with a tx that adds a decoy output to the same insured PKH:
attack_tx = Transaction(
    inputs = [policy_utxo, ...],   # consumes the same policy first
    outputs = [
        Output(addr=Address(insured_pkh, ...), value=lovelace(2_000_000)),    # decoy 2 ADA
        Output(addr=Address(insured_pkh, ...), value=lovelace(4_998_000_000)),# rest
        ...
    ],
)
# Policy.Claim sees: find_output_to_pkh returns the FIRST output (2 ADA).
#   output_has_min_lovelace(2_000_000, coverage=5_000_000_000) → FALSE.
#   payout_valid → FALSE → Claim REJECTED.
# Policy is not consumed. Attacker can now wait until expiry to take it via Expire.
```

This DoS-by-frontrun is a real concern in adversarial mempool environments.

**Recommendation**

Replace `find_output_to_pkh` (greedy first-match) with `sum_lovelace_to_pkh` (aggregate):

```aiken
pub fn sum_lovelace_to_pkh(
  outputs: List<Output>,
  pkh: VerificationKeyHash,
) -> Int {
  list.foldl(outputs, 0, fn(out, acc) {
    when out.address.payment_credential is {
      VerificationKey(hash) ->
        if hash == pkh { acc + assets.lovelace_of(out.value) }
        else { acc }
      _ -> acc
    }
  })
}
```

Then in policy.Claim:

```aiken
let payout_valid = sum_lovelace_to_pkh(outputs, datum.insured) >= datum.coverage_amount
```

This eliminates both the same-PKH double-counting (A-006) and the decoy-output DoS variants.

**Status:** 🟢 **FIXED** (2026-04-30) — verified by `green_a_013_decoy_then_real_payout_is_now_accepted`, `green_a_013_decoy_only_still_rejected`, plus the previously-landed `green_a_006_decoy_first_output_does_not_reduce_total`. The substantive helper migration was already completed in the Priority-1 pass (A-006); the Priority-2 close-out is the **removal** of the legacy `find_output_to_pkh` helper from the codebase plus migration of the diagnostic `policy_simple.ak` fallback.

**Change list:**

- `lib/aegis/validation.ak` deletes the `find_output_to_pkh` helper entirely. A doc-comment in its place records the rationale and points future contributors at the safe primitives (`sum_lovelace_to_pkh`, `sum_lovelace_to_enterprise_pkh`).
- `validators/policy.ak` import list cleaned up: `find_output_to_pkh` and the unused `find_output_to_script` are gone; only the safe helpers are imported.
- `validators/policy_simple.ak` (the diagnostic fallback) migrated from `find_output_to_pkh` + `output_has_min_lovelace` to a single aggregate `sum_lovelace_to_enterprise_pkh` check. The diagnostic now matches production semantics for both A-009 and A-013, so a tx that succeeds against `simple_claim` is also safe against the full validator's payout invariant (modulo the omitted freshness / time / pool-residual checks that the diagnostic deliberately drops).
- A `grep` over `validators/` and `lib/aegis/` for `find_output_to_pkh` returns zero hits in code (only doc-comments referencing the historical name remain).

---

### A-014: Ratio Truncation Allows ~1 Lovelace Over-Leverage Per Policy

**Severity:** ℹ️ **LOW**
**Impact:** ≤ 1 ADA additional pool exposure per policy, at minimum-premium tier
**Likelihood:** Universal (mathematical artifact)
**Categories:** 12 (math edge)

**Location:** `contracts/lib/aegis/pricing.ak:26`

**Description**

This finding is **already documented** in the test suite (`pricing.ak:178`):

```aiken
test ratio_truncation_allows_slight_over_coverage() {
  // premium = 2 ADA, coverage = 100.000001 ADA -> integer ratio = 50 (passes!)
  is_premium_adequate(2_000_000, 100_000_001) == True
}
```

`is_ratio_acceptable` uses integer division:

```aiken
pub fn is_ratio_acceptable(premium: Int, coverage: Int) -> Bool {
  if premium <= 0 { False }
  else { coverage / premium <= max_coverage_ratio }
}
```

`100_000_001 / 2_000_000 == 50` (truncated). The actual ratio is 50.0000005. The protocol allows 1 lovelace of coverage above the documented 50× cap.

**Recommendation**

Use multiplication-style comparison to avoid truncation:

```aiken
pub fn is_ratio_acceptable(premium: Int, coverage: Int) -> Bool {
  premium > 0 && coverage <= premium * max_coverage_ratio
}
```

**Status:** 📝 **Documented** — keep as low priority; fix in next release.

---

### A-015: No Upper Bound on Policy `start_time` Enables Unusual But Non-Exploitable Policies

**Severity:** ℹ️ **LOW**
**Impact:** Policies can be created with `start_time` in the past or far future; minor UX confusion
**Likelihood:** Trivial (any user)
**Categories:** 7 (time / validity range)

**Location:** `contracts/validators/policy.ak:69` (Claim) — `tx_lower ≥ datum.start_time` accepts past start times

**Description**

There is no upper bound on `start_time` at policy creation. A policy with `start_time = 0` is "active from the dawn of time"; a policy with `start_time = 99_999_999_999_999` is "active in the year 5138". Neither breaks anything directly, but it creates surface for confusion in the off-chain UX.

For instance, a policy with `start_time` in the past has its cancellation window already closed (since `start_time + cancellation_window` is also in the past). A user might purchase such a policy and find they cannot cancel it.

**Recommendation**

Enforce a sensible bound during `Underwrite` (per A-004 fix):

```aiken
// In pool.ak Underwrite — when validating the new policy datum:
let start_in_window =
  new_policy_datum.start_time >= tx_lower
    && new_policy_datum.start_time <= tx_upper
let expiry_in_future = new_policy_datum.expiry_time > new_policy_datum.start_time
```

**Status:** 🔴 **OPEN** — low priority; fix alongside A-004.

---

### A-016: Charli3 Oracle UTxO Trust Is Implicit (NFT-Only Verification)

**Severity:** ℹ️ **LOW**
**Impact:** Aegis depends on Charli3's NFT minting policy uniqueness; if Charli3 issues NFTs broadly or if the NFT can be moved to attacker-controlled UTxO, oracle data could be forged
**Likelihood:** External (depends on Charli3)
**Categories:** 6 (oracle reference attacks)

**Location:** `contracts/lib/aegis/oracle.ak:115` (`find_oracle_datum`)

**Description**

`find_oracle_datum` resolves the oracle UTxO by NFT presence only:

```aiken
let has_oracle_nft =
  assets.policies(input.output.value)
    |> list.has(oracle_nft_policy)
```

It does not verify:
1. The UTxO's address (i.e., that it is at the canonical Charli3 oracle script address).
2. That the oracle NFT is a true one-shot (only one such UTxO exists at any time).

If Charli3's NFT minting policy could be invoked to produce additional NFTs, OR if the NFT could be moved out of the Charli3 oracle script, an attacker could place a fake oracle datum at any address and Aegis would consume it.

**This is mitigated by Charli3's design** — they use one-shot NFT minting policies and the NFT is locked at their oracle validator. **However, Aegis's on-chain code does not enforce this.** Should Charli3 ever rotate their oracle script address (e.g., during an upgrade), Aegis would silently accept oracle data from any UTxO holding the old NFT.

**Recommendation**

Add an explicit address check in `find_oracle_output`:

```aiken
fn find_oracle_output(
  reference_inputs: List<Input>,
  oracle_nft_policy: ByteArray,
  expected_oracle_script: ScriptHash,    // pass canonical Charli3 script hash
) -> Option<Output> {
  ...
  let has_oracle_nft =
    assets.policies(input.output.value)
      |> list.has(oracle_nft_policy)
  let at_expected_address =
    when input.output.address.payment_credential is {
      Script(h) -> h == expected_oracle_script
      _ -> False
    }
  if has_oracle_nft && at_expected_address {
    Some(input.output)
  } else { ... }
}
```

Add `expected_oracle_script: ScriptHash` to PolicyDatum and pin it at policy creation.

**Status:** 🔴 **OPEN** — review after upstream Charli3 audit.

---

### A-017: Off-Chain Components (FastAPI, Bot, SDK) Outside This Audit's Scope

**Severity:** ℹ️ **INFO**

The Aegis protocol includes:
- A FastAPI backend (`api/server.py` + helpers) that signs and submits transactions.
- A monitoring bot (`bot/monitor.py`) that polls oracle, policies, and CDP feeds.
- An off-chain SDK (`sdk/src/*`) used by integrators.

These components handle private keys, network endpoints, and user-facing logic. They are **outside this audit's scope** but represent significant risk surface:

- Private key management (does the FastAPI server hold a hot wallet?).
- Off-chain pricing oracle (is the premium calculation server-side and could be manipulated?).
- Replay protection on API endpoints.
- Authorization on auto-heal / batch operations.

**Recommendation**

Conduct a separate off-chain security review covering:
1. Key management (HSM, env vars, signing service).
2. API authentication and rate limiting.
3. Idempotency on tx-submission endpoints.
4. Oracle price freshness checks at the API layer.
5. Bot replay/idempotency for alerts.

---

### A-018: Cross-Chain Attestation (Materios Bridge) Outside This Audit's Scope

**Severity:** ℹ️ **INFO**
**Status:** 🗓️ **DEFERRED to post-v1-launch roadmap (2026-04-30 decision)**

`api/attestation.py` integrates with the Materios cross-chain attestation bridge (label-8746 anchored to Cardano L1). The bridge introduces:

- A second consensus surface (Materios committee).
- Potential replay vectors (re-anchoring an old attestation).
- Trust assumptions on the Materios committee composition.

This is outside the on-chain Aegis audit scope. **Recommendation:** Audit Materios separately. Treat the bridge as a trust-boundary in any Aegis security claims.

**Decision (2026-04-30):** Aegis v1 public launch ships WITHOUT Materios attestation enabled by default — the bridge is a feature flag for cross-chain claim attestation that can light up after Materios's own audit cycle. Treat A-018 as a roadmap item to be re-opened during the cross-chain integration phase.

---

### A-019: Diagnostic `policy_simple.ak` Validator in Production Project

**Severity:** ⚠️ **MEDIUM** (operational risk, not a code-level vulnerability)
**Categories:** 9 (operational), 11 (deployment hygiene)

**Surfaced by:** the Priority-2 remediation stream (e), 2026-04-30.

**Description**

`policy_simple.ak` is a stripped-down claim-only validator that deliberately omits F-001 (single-script-input), oracle freshness, time-window enforcement, and pool-residual canonicalization (A-008). It exists only to A/B-test which production check is responsible for a Plutus runtime error during preprod claim debugging. Its compiled hash was being published in the production `plutus.json` blueprint, creating a live operational risk: a misconfigured deploy could place this script on mainnet, where every policy at its address would be a free-for-all claimable. External auditors typically rate "diagnostic code in production tree" as Medium operational risk by default and bill for the extended audit scope.

**Resolution**

The validator (and its lib dependencies — `oracle.ak`, `types.ak`, `validation.ak`) was moved to a sibling Aiken project at `D:/aegis/contracts-diagnostics/` with its own `aiken.toml`, `plutus.json`, README warning, and 24 (passing) unit tests. The off-chain harness `api/simple_claim.py` was updated to:

1. Load the script from the new diagnostic project's `plutus.json` (not the main one).
2. Hard-fail on import if `AEGIS_NETWORK` is mainnet — verified working: `AEGIS_NETWORK=mainnet` raises `RuntimeError`, `AEGIS_NETWORK=preprod` loads successfully and reports the correct hash `60ff74f29208a88c83a7b4c68a6c335ec0ebe835f89c5a95db3eec8f`.

**Status:** 🟢 **FIXED (2026-04-30)** — verified by:
- `D:/aegis/contracts-diagnostics/aiken.toml` + `validators/policy_simple.ak` present, separate project compiles cleanly, 24/24 tests green.
- `D:/aegis/contracts/plutus.json` no longer contains `policy_simple.simple_claim` (verified via `grep`).
- `D:/aegis/api/simple_claim.py` line ~62 hard-codes `PLUTUS_JSON_PATH = Path("D:/aegis/contracts-diagnostics/plutus.json")` and the `AEGIS_NETWORK` guard at line ~71 raises `RuntimeError` on mainnet.

The diagnostic capability is fully preserved for preprod debugging; production audit surface is reduced.

---

### A-020: Cancel Structurally Unbuildable Post-A-008 (No PoolRedeemer Fits Cancellation Pattern)

**Severity:** 🔴 **HIGH**
**Impact:** Policy cancellation is a documented product feature but cannot be executed on-chain; insured users are forced to wait for expiry.
**Likelihood:** N/A (definitional — affects every cancellation attempt)
**Categories:** 10 (cross-validator boundary)

**Surfaced by:** the off-chain remediation stream (d), 2026-04-30, while attempting to wire `cancel_policy` against the post-Priority-1 schema.

**Description**

The Priority-1 A-008 fix forced `policy.Cancel` to route its residual via `find_canonical_pool_output(outputs, pool_script_hash, pool_nft)` — i.e., the cancellation residual must land on a UTxO carrying the canonical pool NFT. Because the pool NFT is unique to the live pool UTxO (post-A-011 one-shot mint), the only way to satisfy the check is to **co-spend the pool** and produce a continuation output with the NFT preserved. However, the pool validator's six existing redeemers all impose state-transition constraints incompatible with cancellation:

- `Underwrite` requires a fresh policy output and increments `active_coverage`.
- `ProcessClaim` requires a Claim-redeemed policy with matching coverage and decrements both `total_liquidity` and `active_coverage` by `payout`.
- `AddLiquidity` / `RemoveLiquidity` require LP token mint changes.
- `BatchUnderwrite` requires fresh policy outputs summing to `total_coverage`.
- `BatchExpireProcess` requires `BatchExpire`-redeemed policy inputs.

None of these accommodate "consume a Cancel-redeemed policy, decrement `active_coverage` by the policy's coverage, send 90% of premium back to the insured, retain 10% as cancellation fee." Any attempt to construct a Cancel transaction with the existing redeemer set is rejected on-chain, leaving the insured with no path to early termination.

**Resolution**

A new pool redeemer `AcceptCancellation { policy_script: ScriptHash }` (CONSTR_6) was added to `PoolRedeemer` in `lib/aegis/types.ak`. The pool validator's branch implements the symmetric counterpart of `policy.Cancel`:

1. **Locate the consumed Cancel-redeemed policy** at `policy_script` and parse its `PolicyDatum`.
2. **Anti-A-001 binding**: assert `policy.pool_script_hash == own_pool_hash && policy.pool_nft == datum.pool_nft`. A policy bound to a different pool cannot drain this pool through cancellation.
3. **Derive the canonical refund** on-chain: `refund = calculate_refund(policy.premium_paid)` (currently 90%). The redeemer carries no caller-controlled refund field, so a hostile builder cannot inflate it.
4. **Bounds**: `refund >= 0`, `refund <= old.total_liquidity`, `policy.coverage_amount <= old.active_coverage`.
5. **Pool value**: `cont_output.value == own_value - refund` (pool LOSES exactly the refund).
6. **Datum**: `new.total_liquidity == old.total_liquidity - refund && new.active_coverage == old.active_coverage - policy.coverage_amount`. `lp_supply` unchanged.
7. **Immutables preserved** including `lp_supply`.
8. **Solvency**: `new.total_liquidity >= 0 && new.active_coverage >= 0`.

The 10% cancellation fee remains in the pool's lovelace surplus by virtue of the underwrite's existing accounting pattern: at underwrite, `total_liquidity` gained `net_premium` (premium minus protocol fee), and on cancel only 90% returns; the residual 8% (10% cancellation fee minus the previously-counted 2% protocol fee) is the LP-redeemable retention.

**Off-chain re-wire (also delivered 2026-04-30):**

- `D:/aegis/offchain/src/aegis/types.py` — added `AcceptCancellationRedeemer` (CONSTR_ID = 6).
- `D:/aegis/offchain/src/aegis/tx_builder.py:build_cancel_tx` — replaced the previous `NotImplementedError` raise with a full multi-validator builder that consumes policy + pool, produces the insured payout (refund + policy's pre-funded value as enterprise address per A-009), and recreates the canonical pool UTxO with the new datum.
- `D:/aegis/offchain/src/aegis/policy_manager.py:cancel_policy` — replaced `NotImplementedError` with the wired call into `tx_builder.build_cancel_tx` plus pre-flight bounds checks and a TTL clamp that keeps `tx_upper` inside the cancellation window.
- `D:/aegis/api/policies.py:cancel_policy` — same treatment for the FastAPI endpoint, plus an A-010 oracle out-of-the-money pre-flight that mirrors the on-chain check (so we don't waste fees on a tx that would be rejected for ITM).
- `D:/aegis/sdk/src/types.ts` + `D:/aegis/sdk/src/cbor.ts` + `D:/aegis/sdk/src/index.ts` — added `AcceptCancellationRedeemer` interface, `encodeAcceptCancellationRedeemer` CBOR encoder, and re-export.

**Verification:**

- `aiken check` → 150 / 150 / 0 (8 new `green_a_020_*` tests cover refund derivation, pool value invariant, active_coverage decrement, total_liquidity decrement, lp_supply immutability, anti-A-001 pool binding, refund-overflow rejection, coverage-underflow rejection).
- `aiken check` (diagnostics project) → 24 / 24 / 0.
- Off-chain `pytest -q` → 203 / 203 / 0 (no regressions).
- TypeScript SDK `tsc` → exit 0.
- `api/policies.py` smoke-imports clean, `simple_claim` correctly refuses `AEGIS_NETWORK=mainnet`.

**Status:** 🟢 **FIXED (2026-04-30)** — verified by the test results above. Pool validator hash rotated `54280b3f…` → `ac734c2674e8c30f37d9e73be2ff82523c31653db1a7aeef8520fcb9` to reflect the new branch; `chain.py`, `sdk/src/constants.ts`, and `D:/aegis/api/policies.py` have been updated with the new hash and address.

---

## Test Coverage Summary

### Existing Aiken Unit Tests (in repo)

| Module | Tests | Coverage |
|--------|-------|----------|
| `contracts/lib/aegis/types.ak` | 3 | Datum/redeemer construction sanity |
| `contracts/lib/aegis/oracle.ak` | 10 | Oracle parsing, freshness, datum extraction |
| `contracts/lib/aegis/pricing.ak` | 19 | Premium adequacy, ratio, fees, refunds, edge cases |
| `contracts/lib/aegis/pool.ak` | 18 | LP math, solvency, datum verification, security tests |
| `contracts/lib/aegis/validation.ak` | 8 | Signature, count_script_inputs, helpers |
| `contracts/validators/policy.ak` | 13 | Claim/Expire/Cancel boundary checks |
| `contracts/validators/pool.ak` | 4 | Underwrite/withdraw smoke tests |
| `contracts/validators/lp_token.ak` | 2 | Redeemer construction |
| **Total** | **~77** | Helper-level. NO end-to-end transaction tests. |

### Off-Chain Test Suite

| File | Purpose |
|------|---------|
| `offchain/tests/test_oracle.py` | Oracle parsing |
| `offchain/tests/test_policy_manager.py` | Policy lifecycle |
| `offchain/tests/test_pool_manager.py` | Pool operations |
| `offchain/tests/test_pricing.py` | Off-chain premium math |
| `offchain/tests/test_tx_builder.py` | Transaction building |
| `offchain/tests/test_types.py` | Type round-trips |
| `offchain/tests/test_monitor.py` | Bot logic |

**Coverage gap (as originally audited):** the test suite did NOT include negative tests for the Priority-1 attack vectors. As of the 2026-04-30 remediation, all eight Priority-1 findings have at least one dedicated green security test in `lib/aegis/test_helpers/security_tests.ak` (12 tests in total + 5 sanity tests). Total Aiken test count: **125 / 125 passed**.

| Finding | Coverage | Test name(s) |
|---------|----------|--------------|
| A-001 | ✅ | `green_a_001_synthetic_policy_drain_is_rejected`, `green_a_001_pool_nft_binding_rejects_unrelated_pool` |
| A-002 | ✅ | `green_a_002_remove_liquidity_lp_burn_amount_mismatch_rejected`, `green_a_002_legitimate_proportional_withdrawal_accepted` |
| A-003 | ✅ | `green_a_003_burn_during_addliquidity_rejected`, `green_a_003_mint_during_removeliquidity_rejected` |
| A-004 | ✅ | `green_a_004_underwrite_with_no_policy_output_rejected` |
| A-005 | ✅ | `green_a_005_verify_claim_datum_rejects_excessive_payout`, `green_a_005_verify_claim_datum_rejects_negative_payout`, `green_a_005_verify_claim_datum_accepts_legitimate` |
| A-006 | ✅ | `green_a_006_sum_aggregates_multiple_outputs_to_same_pkh`, `green_a_006_decoy_first_output_does_not_reduce_total`, `green_a_006_unrelated_outputs_excluded` |
| A-007 | ✅ | `green_a_007_add_liquidity_with_lp_supply_increment_correct`, `green_a_007_add_liquidity_with_under_minted_lp_rejected` |
| A-008 | ✅ | `green_a_008_find_canonical_pool_output_requires_nft`, `green_a_008_find_canonical_pool_output_returns_none_if_only_fake` |
| A-009 — A-016 | ⏳ | Negative tests to be added alongside Priority-2/3/4 remediation |

### Outstanding Negative Tests (Priority-2/3/4)

These should be added in lockstep with the Priority-2/3/4 fixes:

```aiken
test claim_payout_must_be_enterprise_address() fail { /* A-009 */ }
test cancel_in_the_money_fails() fail { /* A-010 */ }
test single_canonical_pool_enforced() fail { /* A-011 */ }
test batch_claim_oracle_uniformity() fail { /* A-012 */ }
test residual_find_output_to_pkh_callers_cleaned_up() { /* A-013 */ }
test ratio_check_no_truncation() { /* A-014 */ }
test policy_start_time_within_validity() fail { /* A-015 */ }
test charli3_oracle_script_hash_pinned() fail { /* A-016 */ }
```

After Priority-2/3/4 remediation, all of the above MUST also be in the green-pass set (i.e., the validator correctly REJECTS each attack).

---

## Remediation Roadmap

> **Note (2026-04-30):** The original roadmap below split Priority-1 as A-001..A-005 and Priority-2 as A-006..A-008 + A-013. The actual Priority-1 remediation pass closed A-001 through A-008 in a single coordinated effort (A-013's `sum_lovelace_to_pkh` switch was made as part of A-006). Status columns below reflect this.

### Priority 1 — Block mainnet deployment

| Finding | Effort | Status | Notes |
|---------|--------|--------|-------|
| **A-001** | Medium | 🟢 Fixed (2026-04-30) | Datum-level link between policy and pool; coverage match enforced on ProcessClaim |
| **A-002** | Trivial | 🟢 Fixed (2026-04-30) | One-character fix: `<=` → `==` |
| **A-003** | Medium | 🟢 Fixed (2026-04-30) | LP supply tracking in PoolDatum + magnitude-bound mint/burn |
| **A-004** | Medium | 🟢 Fixed (2026-04-30) | Policy-output verification in Underwrite |
| **A-005** | Trivial | 🟢 Fixed (2026-04-30) | `verify_claim_datum` extended with non-negativity and `payout ≤ old_active` |
| **A-006** | Medium | 🟢 Fixed (2026-04-30) | Replaced `find_output_to_pkh` with `sum_lovelace_to_pkh` |
| **A-007** | Trivial | 🟢 Fixed (2026-04-30) | All pool value checks tightened to `==` |
| **A-008** | Small | 🟢 Fixed (2026-04-30) | `pool_nft` added to PolicyDatum + `find_canonical_pool_output` helper |

### Priority 2 — Remediate before external audit

| Finding | Effort | Status |
|---------|--------|--------|
| A-009 | Small | 🔴 Open (in flight) |
| A-010 | Small | 🔴 Open (in flight) |
| A-011 | Configuration (review NFT minting policy) | 🔴 Open (in flight) |
| A-012 | Medium (rework BatchClaim oracle handling) | 🔴 Open (in flight) |
| A-013 | Small (residual cleanup of remaining `find_output_to_pkh` callers; partial coverage achieved via A-006 fix) | 🔴 Open (in flight) |

### Priority 3/4 — Polish before TVL grows

| Finding | Effort | Status |
|---------|--------|--------|
| A-014 | Trivial | 🔴 Open |
| A-015 | Small | 🔴 Open |
| A-016 | Small (pin Charli3 script hash) | 🔴 Open |

### Recommended Remediation Order

1. ✅ **Datum schema changes first** — Add `pool_nft` to PolicyDatum; add `lp_supply` to PoolDatum. (Affects A-001, A-003, A-008.) **Done 2026-04-30.**
2. ✅ **Pool redeemer hardening** — Tighten value checks (`==` not `≤` / `≥`), bind LP mint magnitude, add policy-output requirement to Underwrite, add coverage match to ProcessClaim. (A-001, A-002, A-003, A-004, A-005, A-007.) **Done 2026-04-30.**
3. 🟡 **Policy validator hardening** — Switch `find_output_to_pkh` to `sum_lovelace_to_pkh` (✅ done as part of A-006); verify pool_nft on residual (✅ done as part of A-008); add in-the-money check to Cancel (🔴 Priority-2, A-010); cleanup any remaining greedy-match callers (🔴 Priority-2, A-013).
4. 🔴 **Helper / library** — Fix ratio truncation; pin oracle script hash. (A-014, A-016.)
5. **Re-test and re-audit.** All findings must have negative tests in green (✅ for Priority-1 — 12 new green tests in `lib/aegis/test_helpers/security_tests.ak`); engage external auditor for the full remediated set once Priority-2/3/4 are closed.

---

## Contract Architecture Diagrams

### Tx Spec — Buy Policy (Underwrite)

```
INPUTS                                               OUTPUTS
─────────────────────────────────────────────       ─────────────────────────────────────────────
[0] Wallet UTxO                                      [0] Policy UTxO @ policy_validator
    value: premium + min_utxo_ada + fee                  value: coverage_amount
    redeemer: n/a (pubkey)                               datum: PolicyDatum { ... }
                                                     [1] Pool UTxO @ pool_validator
[1] Pool UTxO @ pool_validator                           value: prev + premium
    value: total_pool                                    datum: PoolDatum { liq+net_premium, active+coverage }
    redeemer: PoolRedeemer.Underwrite                [2] Change → Wallet
                                                     [3] (POST-FIX A-004) Policy NFT mint to Pool
REDEEMERS                                            VALIDITY: now + 0..5 min
─────────────────────────────────────────────       SIGNERS:  user_pkh
- Pool: Underwrite { coverage, premium }            FIX REQUIRED: A-004 (policy output)
```

### Tx Spec — Claim

```
INPUTS                                               OUTPUTS
─────────────────────────────────────────────       ─────────────────────────────────────────────
[0] Policy UTxO                                      [0] Insured wallet (enterprise addr)
    redeemer: PolicyRedeemer.Claim                       value: coverage_amount
                                                         (POST-FIX A-009: enterprise only)
[1] Pool UTxO @ pool_validator                       [1] Pool UTxO @ pool_validator (with pool_nft)
    redeemer: PoolRedeemer.ProcessClaim {                value: prev - coverage_amount  (POST-FIX A-002)
      payout: coverage_amount,                           datum: { liq -= cov, active -= cov }
      policy_script: POLICY_HASH                     [2] Policy residual → Pool (POST-FIX A-008)
    }                                                    value: policy_value - coverage_amount
                                                         carries pool_nft
REFERENCE INPUTS
─────────────────────────────────────────────       VALIDITY: oracle_expiry > tx_lower
[ref] Charli3 Oracle UTxO (NFT match)                          start_time ≤ tx_lower ≤ tx_upper ≤ expiry_time
                                                     SIGNERS:  none (parametric)
                                                     FIX REQUIRED: A-001, A-002, A-005, A-008, A-009
```

### Tx Spec — Add Liquidity

```
INPUTS                                               OUTPUTS
─────────────────────────────────────────────       ─────────────────────────────────────────────
[0] LP wallet UTxO                                   [0] Pool UTxO @ pool_validator (with pool_nft)
[1] Pool UTxO @ pool_validator                           value: prev + amount  (POST-FIX A-007: ==)
    redeemer: PoolRedeemer.AddLiquidity { amount }       datum: { liq += amount, lp_supply += minted }
                                                     [1] aLP tokens → LP wallet
                                                     [2] Change → LP wallet

MINT                                                 VALIDITY: now + 0..5 min
─────────────────────────────────────────────       SIGNERS:  lp_pkh
+ aLP × calculate_lp_mint(...)                       FIX REQUIRED: A-003 (mint magnitude bound), A-007 (== value)
  redeemer: LPTokenRedeemer.MintLP
```

### Tx Spec — Remove Liquidity

```
INPUTS                                               OUTPUTS
─────────────────────────────────────────────       ─────────────────────────────────────────────
[0] LP wallet UTxO (with aLP to burn)                [0] Pool UTxO (with pool_nft)
[1] Pool UTxO @ pool_validator                           value: prev - withdrawal  (POST-FIX A-002: ==)
    redeemer: PoolRedeemer.RemoveLiquidity { amt }       datum: { liq -= amt, lp_supply -= burned }
                                                     [1] Withdrawal → LP wallet
                                                     [2] Change → LP wallet

MINT                                                 VALIDITY: now + 0..5 min
─────────────────────────────────────────────       SIGNERS:  lp_pkh
− aLP × expected_burn                                FIX REQUIRED: A-002, A-003 (mint magnitude bound)
  redeemer: LPTokenRedeemer.BurnLP
```

---

## Conclusion

Aegis demonstrates competent Aiken authorship with thoughtful structure (separation of policy / pool / LP, parameterized minting policy, reference-input oracle integration). The pre-existing fixes (F-001 through F-009) show that the team has internalized core Cardano security patterns (double satisfaction, value preservation, single continuation).

As originally audited, the protocol was not safe for mainnet: three critical findings (A-001, A-002, A-003) each enabled single-transaction drainage of the entire liquidity pool by any participant, and A-004 through A-008 each represented independently exploitable issues at HIGH severity. **All eight of those Priority-1 findings were remediated in-contract on 2026-04-30** (see the Remediation Summary section above and the per-finding Status blocks). The remaining open findings (A-009 through A-016) are medium-to-low severity and are being worked through under a parallel stream; the protocol is still not safe for mainnet until they close and an external auditor signs off.

The root cause across most of the Priority-1 findings was **insufficient cross-validator binding**:

- The pool validator did not require evidence that policies it underwrote actually existed or that policies it paid out for were legitimately created.
- The LP token policy did not enforce direction or magnitude in coordination with the pool validator's redeemer choice.
- Datums lacked identifiers (policy NFTs, oracle script hashes, full pool NFT references) that would let one validator verify the other's state at consumption time.

The 2026-04-30 remediation addresses all three classes via a single coordinated pass: `pool_nft` was added to `PolicyDatum`, `lp_supply` was added to `PoolDatum`, every value/magnitude check was tightened to exact equality, and the pool validator now reads each consumed policy's datum on `ProcessClaim` / `BatchExpireProcess` to verify coverage and pool-binding. The remediation took medium effort — most fixes were localized — and 12 new negative tests were added to keep them green.

**Recommended next steps:**

1. ✅ **Implement Priority 1 fixes (A-001 through A-008). — DONE 2026-04-30.** All eight Priority-1 findings (the three CRITICALs and the five HIGHs) are closed in the Aiken contracts. New compiled hashes are documented at the top of this report and in Appendix A.
2. ✅ **Add the negative test suite outlined above. — DONE 2026-04-30.** Twelve new green security tests (one per Priority-1 finding, plus extra coverage for A-005, A-006, and A-007 boundary conditions) are in `lib/aegis/test_helpers/security_tests.ak`. The pre-fix red test for A-005 has been retired. Total Aiken test count rose from 113 (1 failing) to 125 (0 failing).
3. **Implement Priority 2 fixes (A-009 through A-013).** In flight under a parallel work stream. Stake-credential hardening, in-the-money cancel guard, single-canonical-pool review, BatchClaim oracle uniformity, and the residual `find_output_to_pkh` cleanup.
4. **Implement Priority 3/4 fixes (A-014 through A-016).** Ratio-truncation, `start_time` upper bound, and the explicit Charli3 oracle script-hash pin.
5. **Re-run this audit internally, confirm all findings closed.** Once the off-chain transaction builders are updated for the new `pool_nft` / `lp_supply` datum fields, run end-to-end mainnet-fork tests covering every redeemer.
6. **Engage an external Cardano-experienced auditor** (Anastasia Labs, MLabs, Tweag, or equivalent) for the full remediated contract set.
7. **Only then proceed to mainnet.**

The 2,286 lines of Aiken originally under audit have grown to roughly 2,500 with the new fields and helpers, plus 527 lines of test fixtures and security tests. The Priority-1 remediation closed the cross-validator boundary issues that were the protocol's weakest surface; what remains is hardening against the more specialized attack vectors covered in A-009 through A-016.

---

## Appendix A: File Inventory & Hashes

```
Aiken project: aegis/insurance v0.1.0
Compiler:      aiken v1.1.21
Plutus:        v3
License:       Apache-2.0

Validators (compiled, post-Priority-1 remediation, 2026-04-30):
  policy.policy_validator           sha256: 532740d2b5dd5742541429b3bf09130dbed95f36144fa43a9d629c46
  pool.pool_validator               sha256: 54280b3fc0e1d0902de3fcb3be207ff593e74e65695645f968ef90a1
  lp_token.lp_token_policy          sha256: 5052905c3748192210411b32425de847530a5c03320936106c22e036 (parameterized)
  policy_simple.simple_claim        sha256: 28a2e400e0376dfbc8698e3c44f2796fa402e0eea99bc6510644c7e5 (diagnostic)

Pre-remediation hashes (for historical reference):
  policy.policy_validator           sha256: 8ea5aed0e4f66e9ce6593fbed30856c8997441b1e5cd8bc3085e943f
  pool.pool_validator               sha256: c366b0ea2667b432a432999f54e11978c0ed37c7c4b971067fb1589f
  lp_token.lp_token_policy          sha256: 0402df9c420213421d894b00ee5b23391cb36dc3c2a436b48229c10a
  policy_simple.simple_claim        sha256: 4bab272cfdbe1bd33a4e2699e2bc3463856246870b896b783b08f0ec

Source files (line counts, post-remediation):
  lib/aegis/types.ak                                     216
  lib/aegis/oracle.ak                                    234
  lib/aegis/pricing.ak                                   219
  lib/aegis/pool.ak                                      440
  lib/aegis/validation.ak                                348
  lib/aegis/test_helpers/fixtures.ak                     230  (test-only, new in remediation)
  lib/aegis/test_helpers/security_tests.ak               297  (test-only, new in remediation)
  validators/policy.ak                                   415
  validators/pool.ak                                     576
  validators/lp_token.ak                                  95
  validators/policy_simple.ak                            101  (diagnostic — NOT for production)
  TOTAL (production + test helpers)                    3,171
  TOTAL (production validators + libraries only)       2,644
```

---

## Appendix B: References

- [Aiken Language Documentation](https://aiken-lang.org/)
- [Cardano Plutus V3 Specification](https://github.com/IntersectMBO/plutus)
- [CIP-31: Reference Inputs](https://cips.cardano.org/cips/cip31/)
- [CIP-32: Inline Datums](https://cips.cardano.org/cips/cip32/)
- [CIP-33: Reference Scripts](https://cips.cardano.org/cips/cip33/)
- [Charli3 ODV Documentation](https://docs.charli3.io/)
- [Common Cardano Smart Contract Vulnerabilities — MLabs](https://github.com/mlabs-haskell/audit-resources)
- [Reference audit: SaturnSwap Hydra Orderbook](https://github.com/Flux-Point-Studios/hydra-orderbook-audit/blob/main/docs/SECURITY_AUDIT_REPORT.md) — format template

---

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| **CIP-31 / Reference Input** | A UTxO consumed-as-witness without spending it; allows arbitrarily many concurrent reads of the same datum |
| **Double satisfaction** | When one transaction output satisfies the requirements of multiple validators, leading to one entity being paid for the obligations of several |
| **Datum** | The data attached to a UTxO, used by validators to make decisions |
| **Redeemer** | The data passed alongside a spend action, telling the validator which code path to take |
| **Plutus V3** | The third version of the Plutus on-chain smart-contract platform; introduces cleaner script context, improved cost model |
| **NFT (one-shot)** | A non-fungible token whose minting policy is parameterized by a specific UTxO reference, ensuring exactly one NFT can ever be minted |
| **Pool drain** | An attack that allows extracting all (or substantially all) of a pool's lovelace |
| **Active coverage** | The portion of pool liquidity reserved for outstanding policy payouts |
| **Solvency** | The invariant `total_liquidity ≥ active_coverage` |
| **MEV (Maximum Extractable Value)** | Value extractable by transaction ordering; on Cardano this is bounded by the slot leader's discretion |

---

## Round 2: Live Red-Team on v1-treasury Preprod Deployment (2026-04-30)

After v1-treasury was deployed (post-A-020 + new Conway treasury_donation feature), we ran a second-round live penetration test against the deployed validators on Cardano preprod. Test methodology: build attack transactions in Python using the operator wallet, submit to the live preprod node, observe whether the validator accepts. This complements the static red-team that produced A-001..A-020 with empirical, on-chain proof-of-exploitability.

**Outcome:** Two new findings (A-021 HIGH, A-022 LOW). Both fixed in v2-a022 redeploy. Six attack vectors confirmed properly mitigated.

### A-021: Pool Active-Coverage Lock via Phantom Policy at Trash Script Address

**Severity:** **HIGH** (capacity-reduction attack; cost-to-damage ratio ~1:1)
**Status:** **FIXED in v2-a022 (2026-04-30)**
**Confirmed exploit on chain:** `c32d7a858bbe6d5c6ca29a502c063bcf4104072e1909dd63e20c092ccc57d973` (preprod)

#### Description

`policy_output_matches_underwrite` (`pool.ak:119`) and `batch_policies_match_totals` (`pool.ak:79`) accept ANY `Script(_)` payment credential for the new policy output. The original A-004 fix added datum-content checks (pool_script_hash, pool_nft, coverage_amount, premium_paid match, lovelace ≥ coverage), but did NOT bind the OUTPUT'S OWN script-hash to the policy_validator's hash.

Comment in `pool.ak:130-131` even acknowledged the gap explicitly:
> "We don't know the policy validator's hash at compile time inside the pool validator, so the binding is by datum content + pool_nft."

#### Exploitation

The attacker constructs a normal-looking Underwrite tx but routes the policy output to ANY script address that has no spend purpose (e.g., the lp_token mint policy hash). The pool validator's `policy_funded` check passes because:
- `Script(_)` matches ANY script credential
- The PolicyDatum CBOR is correct (the attacker pays for it)
- The policy output holds the full coverage in lovelace (the attacker pays for it)

**Demonstrated attack:** preprod tx `c32d7a858bbe6d5c6ca29a502c063bcf4104072e1909dd63e20c092ccc57d973`. Operator wallet submitted Underwrite with policy output routed to `addr_test1wzlgdhfnt8q8hfh6ll8rjvwfke6zwnwd68ztdt8aurz78gg93j2jq` (the lp_token mint policy hash; no spend purpose). Tx accepted by validator. Pool's `active_coverage` inflated by 5 ADA. The "policy" UTxO at the lp_token address is permanently locked because lp_token has no spend interpretation.

```python
# api/offchain/scripts/redteam_a021.py — exact attack code (lines 130-138)
trash_script_hash = pyc.ScriptHash(bytes.fromhex(LP_TOKEN_POLICY_HASH))
trash_address = pyc.Address(payment_part=trash_script_hash, network=...)
builder.add_output(pyc.TransactionOutput(
    address=trash_address,        # NOT policy_validator address
    amount=coverage_lovelace,     # passes lovelace ≥ coverage
    datum=policy_datum,           # passes content-bind checks
))
```

#### Impact

An attacker can permanently lock pool capacity at near-1:1 cost. For each unit of coverage they "burn":
- They pay `coverage` ADA into a permanently-locked UTxO
- They pay `premium` (~2% of coverage)
- They pay treasury donation (~0.5% of premium)
- They pay tx fees (~1.2 ADA)

Total cost ≈ `coverage * 1.026`. Damage to protocol = `coverage` of pool capacity reduced. The `active_coverage` field grows monotonically with attacker activity, since Claim/Cancel/Expire all require a SPENDABLE policy and a phantom policy at a non-policy script address cannot be spent. Eventually `active_coverage = total_liquidity`, the pool refuses all new underwrites, and only legitimate Claims (which decrement active_coverage on legitimate policies) restore capacity. If the attacker phantoms more than legitimate users claim, capacity converges to zero.

#### Remediation (v2-a022)

Pool validator parameterized with `policy_script_hash: ByteArray`:

```aiken
validator pool_validator(policy_script_hash: ByteArray) {
  spend(...) { ... }
}
```

Both `policy_output_matches_underwrite` and `batch_policies_match_totals` now check the script credential:

```aiken
when out.address.payment_credential is {
  Script(h) -> if h == policy_script_hash {
    // ...existing datum-content checks...
  } else {
    False  // wrong script hash → reject
  }
  _ -> False
}
```

Off-chain `publish_refs.py` applies the deployed policy_validator hash (`d492179e...49c358d7`) as the parameter via `aiken blueprint apply` before publishing the pool ref UTxO.

**Verification on chain:**
- Pre-fix: tx `c32d7a85...` ACCEPTED, A-021 confirmed exploitable.
- Post-fix (v2-a022): same attack code submitted against new pool_validator hash `4e32175419695a627d3b49f82d96f87c330da45ffb2627409354446f` → REJECTED with `PlutusFailure`. Validator's `donation_ok && policy_funded` short-circuits at `policy_funded == False` because the trash address's hash differs from the parameterized policy_script_hash.
- Green path verified: legitimate Underwrite tx `a48041e986d7cb57d95d18ef2cd15860e4579619d7626b0bf04a31bbd2c71565` succeeded with body field 22 = 10,000 lovelace donation, `valid_contract: True`.

#### Tests

`green_a_022_correct_policy_script_hash_accepted`, `green_a_022_wrong_script_hash_rejected`, `green_a_022_lp_token_address_rejected`, `green_a_022_pool_continuation_skipped_no_taillist_halt`. Total Aiken green-path: 168.

---

### A-022: `force tailList []` Halt on Out-of-Order Outputs (Validator Fragility)

**Severity:** **LOW** (DoS-against-self; not exploitable)
**Status:** **FIXED in v2-a022 (subsumed by A-021 fix)**
**Reproduced on chain:** `8a4c5dc0...589dcec7f` initially failed with this error before output ordering was corrected off-chain.

#### Description

`policy_output_matches_underwrite` did `list.any(outputs, fn(out) { ... expect pdat: PolicyDatum = raw_pdat ... })`. The `expect` is a HARD assertion in Aiken — when applied to an output whose datum is a different schema (e.g., the pool's continuation output, which carries a 6-field `PoolDatum`), the deserializer walks the constructor fields and calls Plutus builtin `tailList` on the missing tail. On an empty list this errors with `force tailList []` and **halts the entire validator script**, not just the predicate.

Practical effect: if the pool's continuation output appears in the outputs list BEFORE the policy output, the validator's whole `policy_funded` check crashes before reaching the matching policy output. `list.any` cannot short-circuit because the failure precedes the predicate's return.

#### Demonstrated reproduction

Initial Underwrite attempts failed at the validator with `Caused by: force tailList []`. The off-chain code added the pool output first (line 753-770 of `policies.py`) then the policy output (line 772-787). Reordering — policy output first, then pool — let `list.any` short-circuit on the legitimate match before encountering the pool output, and the tx succeeded (`8a4c5dc0...589dcec7f`).

#### Impact

- **Self-DoS only.** A user (or attacker) building a tx with outputs in the wrong order produces a tx that the validator rejects. Honest users' wallets just need to add the policy output first.
- **Co-spend fragility.** Combining an Aegis Underwrite with a third-party script-output in the same tx required careful ordering. Hard to weaponize against another user (the attacker can't influence the victim's tx-build path), but a real ergonomic gap.
- **Not a fund-loss attack.** No drain, no inflation, no double-spend.

#### Remediation (v2-a022)

The A-021 fix subsumes this. With `Script(h) -> if h == policy_script_hash`, outputs at the pool's own script address (which have a different hash) are skipped via the `else { False }` branch BEFORE the `expect pdat: PolicyDatum = raw_pdat` decode runs. The decoder is now only ever exercised on outputs where the script credential matches, which by construction means a policy output with the correct datum schema.

#### Tests

`green_a_022_pool_continuation_skipped_no_taillist_halt` covers this property at the helper level.

---

### A-024: Negative Coverage in Underwrite Redeemer Permits active_coverage Shrink

**Severity:** **MEDIUM** (state corruption; no direct profit but corrupts pool accounting)
**Status:** **FIXED in v3-a024 (2026-04-30)**
**Confirmed exploit on chain:** `01a1067cd496a31f069e0355717fe2ab1c4ebd5b2e0eb8ba1632a179cf04459a` (preprod, v2-a022)

#### Description

`is_ratio_acceptable` (`pricing.ak`) computes `coverage / premium <= max_coverage_ratio` where Aiken's `divideInteger` floors toward negative infinity. For `coverage = -5_000_000, premium = 2_000_000`: `-5_000_000 / 2_000_000 = -3 <= 50` evaluates True. The check passes for arbitrary negative coverage.

`verify_underwrite_datum` (`pool.ak::lib`) requires `new_active == old_active + coverage` with no non-negativity bound on `coverage` or `new_active`. Combined with the ratio bypass, an attacker submits an Underwrite with `coverage = -N` lovelace and the pool's `active_coverage` decrements by `N`.

#### Exploitation

Live attack on v2-a022 (preprod): operator wallet submitted Underwrite with `UnderwriteRedeemer { coverage: -5_000_000, premium: 2_000_000 }`. Pool active_coverage went from 10,000,000 to 5,000,000 in a single 2 ADA premium tx. The "policy" output at the policy_validator address holds a PolicyDatum with `coverage_amount: -5_000_000` (which makes no semantic sense but type-checks as Int).

#### Impact

- **Apparent capacity inflation.** `available = total_liquidity - active_coverage`. Shrinking active_coverage inflates the pool's reported available capacity, misleading legitimate underwriters about how much real coverage the pool can back.
- **Accounting drift.** Once active_coverage diverges from the real sum of legitimate policy coverage_amounts, downstream protocol behavior is undefined. Eventually a legitimate Claim might attempt to decrement active_coverage past 0 (rejected by `verify_claim_datum`'s `new_active >= 0`), but multiple drifting txs could leave pool state inconsistent.
- **Cost to attacker:** 2 ADA premium + 1.2 ADA fees + 0.01 ADA donation. Each attack reduces active_coverage by an attacker-chosen amount. **No direct profit**, but corrupts protocol accounting at near-zero cost.

#### Remediation (v3-a024)

Pool validator's Underwrite + BatchUnderwrite branches gain explicit positivity guards:

```aiken
let coverage_positive = coverage > 0
let premium_positive = premium > 0

// ANDed into the branch's final return:
coverage_positive && premium_positive && premium_ok && can_cover && ...
```

Same fix on BatchUnderwrite using `total_coverage > 0` and `total_premium > 0`.

**Verification on chain:**
- Pre-fix: tx `01a1067cd496...` ACCEPTED on v2-a022, A-024 confirmed exploitable.
- Post-fix (v3-a024): replay of identical attack code against new pool_validator hash `04febf255e10f6bb97c26bc00adcba648f0a57006654c3f602123ee8` → REJECTED with PlutusFailure.

#### Tests

`green_a_024_negative_coverage_rejected`, `green_a_024_zero_coverage_rejected`, `green_a_024_positive_coverage_accepted`, `green_a_024_negative_premium_rejected`, `green_a_024_batch_negative_total_coverage_rejected`. Total Aiken green-path: 173.

#### Lessons

The original `is_ratio_acceptable` check was inherited from positive-only-domain assumptions that didn't survive negative inputs. Aiken's flooring division semantics differ from C-style truncation; any check of the form `a / b <= K` is unsafe without prior `a >= 0` and `b > 0` guards. Audit checklist update: **for every divisor / ratio check, audit that both operands are bounded.**

---

### A-025: Multi-Policy Single-Underwrite Under-Accounting via `list.any` Short-Circuit

**Severity:** **HIGH** (silent insolvency surface — pool's `active_coverage` accounting drifts from real liability)
**Status:** **FIXED in v5-a025 (2026-04-30)**
**Confirmed exploit on chain:** `b1400c6474dbecf2ad65a3ccdabac94c6a967e026d31ea128846ece02cd6f0a1` (preprod, v4)

#### Description

`policy_output_matches_underwrite` (`pool.ak`) used `list.any` to verify *at least one* output matches the policy criteria. `list.any` short-circuits on the first match. An attacker can attach N legitimate policy outputs (each with its own funded coverage in lovelace and a valid PolicyDatum binding to our pool) to a single Underwrite transaction. The validator passes the policy_funded check on the FIRST match and never iterates to detect the extras. Pool's `active_coverage` grows by exactly ONE redeemer-coverage; the other N-1 policies are stranded liability that the pool's accounting never tracked.

#### Exploitation

Live attack on v4-a014-a015-a016 (preprod): operator submitted Underwrite with `coverage = 5_000_000, premium = 2_000_000`, plus THREE policy outputs at the policy_validator address (each holding 5 ADA collateral, each with a valid PolicyDatum). Tx accepted. Pool's `active_coverage` went from 0 → 5_000_000. But there are now 3 distinct claimable policies on chain, sized 5 ADA each — nominal liability 15 ADA against tracked active_coverage of 5 ADA.

#### Impact

- **Silent insolvency surface.** As multi-policy underwrites accumulate, the pool's reported `available = total_liquidity - active_coverage` becomes more inflated than the real liability allows. Subsequent legitimate underwriters allocate against this fake capacity.
- **At first oracle trigger,** the pool can pay one claim per under-accounted underwrite (active_coverage permits one decrement). The remaining policies cannot claim (insufficient active_coverage) — they sit on chain, the user's collateral locked, until they cancel within the 1-hour window or expire (premium goes to pool, collateral returns).
- **Cost to attacker:** `(N-1) * coverage` ADA collateral locked, `N * coverage / 50` premium savings (typical). For a 1.02× cost-to-stuck-collateral ratio, the attacker can grief LP capacity at near-cost.
- **No direct fund extraction**, but a sustained attack drives pool toward insolvency where claim payouts can't all be honored.

#### Remediation (v5-a025)

`policy_output_matches_underwrite` rewritten as a counting fold that requires EXACTLY 1 matching output:

```aiken
let matching_count =
  list.foldl(outputs, 0, fn(out, acc) {
    if matches_policy_criteria(out, ...) { acc + 1 } else { acc }
  })
matching_count == 1
```

Multi-policy creation is now ONLY supported through BatchUnderwrite, which already used a sum-based check (`batch_policies_match_totals`) that ties total_coverage / total_premium across outputs to the redeemer's totals.

**Verification on chain:**
- Pre-fix: tx `b1400c6474db...46ece02cd6f0a1` ACCEPTED on v4 with 3 policy outputs against a single redeemer-coverage.
- Post-fix (v5): R3-E replay against new pool_validator hash `c7cf3d90e885ddc54d1187edd491d68d1e1c2bd5cb7b2c986f632377` → REJECTED with PlutusFailure.
- Green-path verified: legitimate single-policy Underwrite tx `6ff0ebac89fbcb56823a9f94d38c231269389ee7a31b922f33fb918c2f3a6caa` succeeded with `valid_contract: True`.

#### Tests

`green_a_025_exactly_one_policy_output_required`, `green_a_025_zero_policy_outputs_rejected`, `green_a_025_two_policy_outputs_rejected`, `green_a_025_three_policy_outputs_rejected`. Total Aiken green-path: 186.

#### Lessons

`list.any` is a short-circuiting predicate — appropriate for "exists" semantics but DANGEROUS for accounting checks where the count matters. Audit checklist update: **for any aggregate-based pool invariant, require either exact-count or exact-sum semantics; never short-circuit predicates on aggregations.**

---

### A-014: Ratio Truncation — FIXED v4 (multiplication-form check)

**Severity:** ℹ️ **LOW**
**Status:** **FIXED in v4-a014-a015-a016 (2026-04-30)**

`is_ratio_acceptable` previously used integer division (`coverage / premium <= 50`) which permitted 1 lovelace of over-leverage at minimum-premium tier (`100_000_001 / 2_000_000 = 50` truncated). Replaced with multiplication-form: `coverage <= premium * max_coverage_ratio`. Round-3 replay R3-A: pool insolvent at the 100 ADA scale (operator pool only has ~50 ADA available) — the unit-level test `green_a_014_one_lovelace_over_now_rejected` passes; live boundary verification deferred to a more-funded preprod or mainnet rehearsal.

---

### A-015: No Upper Bound on Policy `start_time` — FIXED v4 (validity-range check)

**Severity:** ℹ️ **LOW**
**Status:** **FIXED in v4-a014-a015-a016 (2026-04-30)**
**Replay verification on v5:**
- R3-B (`start_time = 0`): REJECTED ✓
- R3-C (`start_time = year 5138`): REJECTED ✓
- R3-D (`expiry_time < start_time`): REJECTED ✓

Pool validator's Underwrite + BatchUnderwrite branches now bind `validity_range` from the Transaction destructure and require `pdat.start_time` lies within `[get_lower_bound(validity_range), get_upper_bound(validity_range)]` AND `pdat.expiry_time > pdat.start_time`. Off-chain Underwrite paths now set `validity_start = current_slot - 200` (~200 s back) and `ttl = current_slot + 600` (~10 min forward) so legitimate policies fall inside the range.

---

### A-016: Charli3 Oracle Trust Implicit — FIXED v4 (script-hash binding)

**Severity:** ℹ️ **LOW**
**Status:** **FIXED in v4-a014-a015-a016 (2026-04-30)**

`find_oracle_output` (`oracle.ak`) now requires the matching reference input to be at the canonical Charli3 oracle script hash (`221ee21e9607f766e1e1223248f67320014825169a1d98eb34c6f658`, hardcoded as `types.charli3_oracle_script_hash`). Any reference input with the right NFT but at a non-canonical script credential is silently skipped. Hardcoding (vs. a datum field) is intentional: it pins the oracle binding by validator hash so any rotation in Charli3's address requires an Aegis redeploy. Verification: `green_a_016_oracle_at_canonical_address_accepted`, `green_a_016_oracle_at_wrong_address_rejected`.

---

### A-018: Materios Bridge Outside Scope — DEFERRED (post-v1 roadmap)

**Severity:** ℹ️ **INFO**
**Status:** 🗓️ **DEFERRED to post-v1-launch roadmap (2026-04-30 decision)**

Aegis v1 ships without the Materios cross-chain attestation bridge enabled by default. Re-opens during cross-chain integration phase, gated on Materios's own audit cycle.

---

### Round-2 attack vectors confirmed properly mitigated

The following attempted attacks on v1-treasury were rejected by the validator as designed — included for audit completeness:

| Attack | Vector | Outcome |
|--------|--------|---------|
| **Donation underpay by 1 lovelace** | Submit Underwrite with `treasury_donation = required - 1` | Rejected by `donation_ok` clause (`amt >= required_donation` ⇒ False) |
| **Donation = 0** | Submit Underwrite with `treasury_donation = 0` (encoded same as None by `DonatingTxBuilder`) | Rejected: `None` branch requires `required_donation == 0`, but `required = 10000 > 0` |
| **Donation = None** | Body field 22 absent | Rejected: same as above |
| **NFT dropped from pool continuation** | Build pool output without the AEGIS_POOL_V2 NFT | Rejected by `find_canonical_pool_output` (A-008 holds) |
| **Policy output lovelace short** | Send `MIN_UTXO_LOVELACE` instead of `coverage` to policy address | Rejected by `lovelace_of(out.value) >= coverage` (A-004 holds) |
| **Output ordering with garbage script datum** | Insert a script-output with non-PolicyDatum datum first in outputs | Was rejected via tailList halt (A-022); now skipped cleanly via script-hash gate (A-022 fix) |

### Round-2 deployment artifacts

| Artifact | Pre-A-022 (v1-treasury) | Post-A-022 (v2-a022) |
|---|---|---|
| `pool_validator_hash` | `e067903b061d3337ab933f18c828403dc2232a99e1e7388356e634e5` | `4e32175419695a627d3b49f82d96f87c330da45ffb2627409354446f` |
| `pool_validator_address` | `addr_test1wrsx0ypmqcwnxdatjvl33jpggq7uyge2n8s7wwyr2mnrfegq7f828` | `addr_test1wp8ry965r9545cna8dylstvklp7rxrdytlajvf6qjd2ygmcn32tkg` |
| `pool_validator` ref UTxO | `d332e6b9...ec9b1b80#0` | `095dbba5fdd9889efd627bcf4b3690ce01fbc9bbf8ae0227e5ac99e2618aec34#0` |
| `lp_token_policy_hash` | `be86dd33...c5e3a1` | `ffa6d4ada8b7e181b22769da91872bf3174a11fbeb01adc801a0216d` |
| `lp_token_policy` ref UTxO | `aa8241ca...de5c7ec6#0` | `b75ecc19a3e6849d22297784adb500f49c41423a6b9b5905a7689dee1abbc6b5#0` |
| `policy_validator_hash` | `d492179e...49c358d7` | UNCHANGED (byte-stable across all 3 deployments) |
| `pool_nft` | `AEGIS_POOL_V2` (`c72d8554...a93b072`) | `AEGIS_POOL_V3` (`9e56198e4a882ff0bb913bc47f39a60f0f440d758d026f0f13207937`) |
| `pool_utxo_id` | `13ce9e55...95f1a56ae#0` (now empty husk) | `cf978a5adbb61b72d164acd00685030142c812c613574c6d5277145724a376db#0` |

### Updated audit posture

- **A-001 ... A-013, A-019, A-020:** closed in v0/v1
- **A-014 ... A-016 (Low):** OPEN, mainnet-blocking
- **A-017, A-018 (Info):** out of scope by design
- **A-021 (HIGH, NEW):** **CLOSED in v2-a022** — empirically verified by replaying the same attack code against the new validator
- **A-022 (LOW, NEW):** **CLOSED in v2-a022** — subsumed by A-021 fix

**Total findings to date: 22.** **Closed: 17.** **Open: 5 (A-014, A-015, A-016 Low; A-017, A-018 Info).** Mainnet still gated on A-014/A-015/A-016 closure plus an external auditor sign-off.

### Red-team scripts (re-runnable)

Located at `D:/aegis/offchain/scripts/`:

- `redteam_a021.py` — phantom policy at trash script address. Run against v2-a022 and observe REJECTED.
- `redteam_a023_donation.py` — donation underpay / zero-donation. Both REJECTED.
- `smoke_underwrite.py` — green-path Underwrite (regression baseline). Verifies the fix doesn't break legitimate flows.
- `smoke_donation.py` — body-level treasury donation smoke. Verifies the Conway field works at the ledger level.

---

*Report compiled by Flux Point Studios · Internal pre-audit · 2026-04-30*
*Priority-1 findings A-001 through A-008 closed 2026-04-30. Findings A-009 through A-013, A-019, A-020, A-021, A-022 closed in subsequent rounds. A-014 / A-015 / A-016 (Low) remain open and mainnet-blocking. Round 2 (A-021, A-022) verified empirically by submitting attack txs to live preprod and confirming the v2-a022 redeploy rejects exploits while accepting legitimate flows.*
