# Auditing Guide

This document is for the external auditor. It explains the audit's scope, where to start, what previous internal red-team rounds have already found, and how to verify the on-chain remediations empirically.

## Scope

**In scope (this audit):**
- All Aiken source under [`contracts/validators/`](../contracts/validators/) — `policy.ak`, `pool.ak`, `lp_token.ak`, `pool_nft.ak`.
- All shared libs under [`contracts/lib/aegis/`](../contracts/lib/aegis/) — `types.ak`, `pricing.ak`, `pool.ak`, `oracle.ak` (now a thin dispatcher), `oracle/{types,charli3,orcfax,aegis_self}.ak` (per-provider parsers), `validation.ak`, plus test helpers.
- The compiled blueprint [`contracts/plutus.json`](../contracts/plutus.json).
- The deploy artifacts [`deploy/deploy-state.preprod.json`](../deploy/deploy-state.preprod.json) — for cross-referencing on-chain state vs. expected hashes.
- The operator-deploy scripts in [`deploy/scripts/`](../deploy/scripts/) — these run only at deploy time and don't sign user txs, but their correctness affects the trust model (e.g., one-shot NFT minting, parameterization order).

**Out of scope (planned separate review — A-017):**
- The FastAPI backend (`api/server.py`, `api/policies.py`, etc.) — described in [`BACKEND_INTERACTION.md`](BACKEND_INTERACTION.md).
- The monitoring bot.
- The frontend / SDK.
- The publisher service that produces AegisSelf feed UTxOs (off-chain; `D:/aegis/publisher/` in the private monorepo).
- Materios cross-chain attestation bridge (A-018, deferred to post-v1 roadmap).

## Where to start

1. **Read the audit report.** [`audit/SECURITY_AUDIT_REPORT.md`](audit/SECURITY_AUDIT_REPORT.md) — 37 findings discovered by 6 rounds of internal red-team. 27 closed, 10 open (1 HIGH, the rest MED/LOW/INFO with documented deferral rationale; no CRITICAL findings open). Pay attention to:
   - The "Hash rotation history" at the top — explains the 7 deployments (v0..v6.0.2).
   - Each finding's writeup — including Round-2 / Round-3 / Round-6 sections that reference live preprod tx hashes proving the exploit worked pre-fix.
   - The lessons captured at the end of each round.

2. **Read the architecture doc.** [`ARCHITECTURE.md`](ARCHITECTURE.md) — the on-chain mental model, datum/redeemer schemas (PolicyDatum is now 11 fields with the v6 `oracle_provider` tag), the multi-oracle dispatcher topology, and cross-cutting design choices.

3. **Build and run the test suite.**
   ```bash
   cd contracts
   aiken check        # 222 tests, all green
   aiken build        # produces plutus.json — should match the committed blueprint
   ```
   If the rebuilt `plutus.json` script hashes don't match the committed values, something is wrong. Investigate.

4. **Cross-reference deploy-state.preprod.json against on-chain state via Blockfrost.**
   The committed `deploy-state.preprod.json` claims certain script hashes are live on Cardano preprod. You can verify via:
   ```bash
   curl -H "project_id: <YOUR_BLOCKFROST_KEY>" \
     https://cardano-preprod.blockfrost.io/api/v0/scripts/<script_hash>
   ```
   Or visit `https://preprod.cardanoscan.io/transaction/<tx_hash>` for the deploy txs listed in the state file.

5. **Verify Round-2 / Round-3 / Round-6 exploit txs.** Each round's finding writeups cite specific preprod tx hashes (or PoC traces) where the pre-fix attack succeeded or where the post-fix replay was rejected. Visit them on cardanoscan to confirm:
   - A-021 phantom policy: `c32d7a858bbe6d5c6ca29a502c063bcf4104072e1909dd63e20c092ccc57d973`
   - A-024 negative coverage: `01a1067cd496a31f069e0355717fe2ab1c4ebd5b2e0eb8ba1632a179cf04459a`
   - A-025 multi-policy: `b1400c6474dbecf2ad65a3ccdabac94c6a967e026d31ea128846ece02cd6f0a1`
   - v6.0.2 green-path Underwrite (post-round-6): `23889dec359280a428d8bfda160df8ffdd717735aebb419720e6dd7651255db2`

   These accepted on the corresponding pre-fix deploy. Each fix's redeploy demonstrably rejects the same attack code.

## Validator priority order

Recommended audit order, hardest to easiest:

1. **`pool.ak`** — the largest validator and the single point of fee enforcement. Most invariants live here. Pay particular attention to:
   - The `policy_output_matches_underwrite` and `batch_policies_match_totals` helpers (A-021, A-022, A-025 fixes; A-026 / Charli3-NFT-pin extension live in the round-6 build).
   - The `donation_ok` clauses on Underwrite, BatchUnderwrite, AcceptCancellation (A-021 treasury feature).
   - The `value_ok` strict equality checks across all 7 branches (A-002, A-007).
   - The `find_canonical_pool_output` / `output_has_nft` helpers.
   - The new compile-time `policy_script_hash` parameter (replaces the redeemer-supplied `policy_script` field that was dropped in v6.0.2 / L-006).
2. **`policy.ak`** — per-policy lifecycle. A-008 (canonical pool routing), A-009 (enterprise-only payout), A-010 (in-the-money cancel guard), A-012 (uniform `(oracle_provider, oracle_nft)` in batch — generalized in v6), L-003 (lower-bound `tx_lower >= observed_at` at Claim/BatchClaim/Cancel — round-6 fix).
3. **`lib/aegis/oracle.ak`** — multi-oracle dispatcher. Owns `resolve_oracle_price` and the new `canonical_oracle_nft` helper. Three-arm `when oracle_provider is { Charli3 -> ... | Orcfax -> ... | AegisSelf -> ... }` is the curated whitelist; adding a fourth provider rotates every validator hash.
4. **`lib/aegis/oracle/charli3.ak`** — Charli3 GenericData parser. A-016 (canonical script-hash binding) lives here; round-6 added `expect oracle_nft == aegis_types.charli3_ada_usd_nft_policy` parser-side pin.
5. **`lib/aegis/oracle/orcfax.ak`** — Orcfax FSP→FS pointer indirection + `FsDat<Rational>` parser. A-027 fix: `expect oracle_nft == aegis_types.orcfax_fsp_script_hash` (no caller-supplied script hash).
6. **`lib/aegis/oracle/aegis_self.ak`** — Self-publish parser. NEW in v7. A-026 fix: two-layer trust handshake (publisher NFT under canonical policy AND credential equals `aegis_self_publisher_vkh`).
7. **`lib/aegis/oracle/types.ak`** — provider-uniform `Price` record. Small, mostly documentation.
8. **`lib/aegis/pool.ak`** — `verify_underwrite_datum`, `verify_claim_datum`, `verify_add_liquidity_datum`, `verify_remove_liquidity_datum`. The datum-transition algebra. Pay attention to non-negativity guards (A-024 lessons).
9. **`lib/aegis/pricing.ak`** — `is_premium_adequate`, `calculate_protocol_fee`, `calculate_treasury_cut`. Math-level checks. A-014 (multiplication-form ratio) lives here.
10. **`lib/aegis/validation.ak`** — shared helpers (signed_by, validity-range bounds, `find_canonical_pool_output`, `sum_lovelace_to_enterprise_pkh`). A-008/A-009/A-013 helpers live here.
11. **`lib/aegis/types.ak`** — Datum/redeemer schemas; canonical-NFT constants (`charli3_ada_usd_nft_policy`, `orcfax_fsp_script_hash`, `aegis_self_nft_policy`); publisher VKH; freshness windows.
12. **`lp_token.ak`** — small. Mint policy gates LP token minting on pool consumption. Should be quick to read.
13. **`pool_nft.ak`** — one-shot mint policy. A-011 fix. Should be quick to read.

## Attack surface taxonomy

The internal red-team's threat model partitioned attacks into 12 categories. Most of these are still relevant:

1. Pool drain (full or partial)
2. Pool dilution (LP value loss without fund extraction)
3. Active-coverage griefing (locking pool capacity at cheap cost)
4. LP token mint/burn manipulation
5. Datum corruption / immutable-field violation
6. Oracle reference attacks (fake oracle, stale data, wrong feed)
7. Time / validity-range manipulation (cancel after window, claim before start)
8. Cross-policy / cross-pool attacks (binding violation, NFT confusion)
9. Operational risks (deploy hygiene, parameterization mistakes)
10. Datum-shape attacks (wrong constructor, wrong field count)
11. Deployment hygiene (one-shot mint replay, ref UTxO theft)
12. Math edge cases (truncation, overflow, negative inputs)

Round-2 added:
13. **Off-chain output ordering** — interaction between `expect` semantics and `list.any` order-sensitivity (A-022).
14. **Aggregate vs short-circuit semantics** — `list.any` is fine for "exists" predicates but dangerous for accounting that depends on count or sum (A-025).
15. **Cross-script-credential routing** — wildcards on `Script(_)` accept ANY script credential (A-021).

Round-6 added:
16. **Caller-supplied canonical handles** — A-026 / A-027 / Charli3 NFT pin: parser-side credential pins are insufficient if the validator accepts an attacker-supplied `oracle_nft` and lets them mint under their own permissive policy. Fix: validator must pin the handle via a compile-time canonical, not just trust the parser.
17. **Redeemer-supplied script hashes** — L-006: `policy_script` in `ProcessClaim` / `BatchExpireProcess` / `AcceptCancellation` let an attacker direct the pool to look up a permissive script. Fix: parameterize the validator over `policy_script_hash` and drop the redeemer field.
18. **Lower-bound oracle observation gate** — L-003: a backdated `tx_lower` could let a stale oracle reading satisfy `tx_lower <= valid_until`. Fix: also require `tx_lower >= price.observed_at`.

## How to attempt new attacks

The backend code (out of scope) constructs canonical txs. To attempt new attacks, you'll need to construct adversarial txs from scratch. Two approaches:

1. **Aiken test fixtures.** Add a green test in `contracts/lib/aegis/test_helpers/security_tests.ak` that invokes the validator branch with crafted inputs. This is the cleanest way to prove an attack works (or doesn't) at the spec level.

2. **PyCardano scripts.** The internal red-team built attack txs in Python using PyCardano (`redteam/redteam_*.py` in this repo). These scripts depend on the private backend code (`api/_treasury.py`, `api/_donation_tx_builder.py`, `api/policies.py`'s PolicyDatum class) which is NOT in this audit. The scripts are included as **reference documentation** of attack patterns — the actual exploit txs they produced are on chain and verifiable via Blockfrost.

   If you want runnable attack scripts, you can either:
   - Build them from scratch using your preferred Cardano tx-construction toolkit; OR
   - Request the private backend repo from Flux Point Studios for runtime testing (the on-chain code in this repo is the source of truth either way).

## On-chain reproduction

To attempt an attack against the live v6.0.2 deploy on preprod:

1. Set up an operator wallet with preprod ADA (~50 ADA minimum).
2. The deployed validator hashes are in `deploy/deploy-state.preprod.json`.
3. Build a tx that consumes the pool UTxO with the malicious pattern.
4. Submit via Blockfrost. Validator either accepts (finding) or rejects (good).

Since this is preprod with no real users, attempting attacks is safe and encouraged.

## Communicating findings

Please file findings using the same severity scale and format as the existing audit report:

- **Severity**: Critical / High / Medium / Low / Info
- **Location**: file:line
- **Description**: what the bug is
- **Exploitation**: how it could be exploited (sketched tx body, on-chain demonstration ideal)
- **Impact**: financial / operational consequences
- **Remediation**: recommended fix

Use the existing finding numbering — next free is **A-030** for protocol-style findings (A-026..A-029 used in round 6); the round-6 LOW / ECON families are continuation-numbered. Coordinate with the report custodian if you uncover a duplicate of a closed finding (we want to know if our remediation is incomplete).

For coordinated disclosure: see [`SECURITY.md`](../SECURITY.md). Email findings before public disclosure.

## Engagement contact

- Flux Point Studios — security@fluxpointstudios.com (PGP on request)
- Audit report custodian: same email
- Repository maintainer: same

## Estimated audit complexity

- **Aiken LOC:** ~2,800 across validators + libs (grew from v5's ~2,500 with the multi-oracle submodules).
- **Compiled validator sizes:** policy ~4.8 KB (post-v6 with provider dispatch), pool ~6.1 KB, lp_token ~0.5 KB, pool_nft ~0.5 KB.
- **Test count:** 222 (green-path).
- **Findings to date:** 37 (6 rounds of internal red-team).
- **Expected effort:** ~3–5 person-weeks for a thorough Plutus V3 audit covering the full surface.

Reach out before kickoff if you'd like a guided walkthrough of the architecture or specific findings.
