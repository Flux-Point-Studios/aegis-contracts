# Aegis Smart Contracts — On-Chain Audit Repository

**Aegis** is a parametric crypto-insurance protocol on Cardano. This repository contains the on-chain code (Aiken validators, lib helpers, fixtures), the security audit report covering 27 of 37 internal findings closed across 7 deployments (v0..v6.0.2), deploy artifacts proving the contracts are live on Cardano preprod, and red-team scripts documenting the attacks tried.

This repo is the **audit handoff package** for an external auditor. The off-chain backend (FastAPI server, monitoring bot, frontend, SDK) is intentionally NOT in this repo — those components are scheduled for a separate off-chain audit and are not in scope here.

---

## What's in the box

```
aegis-contracts/
├── README.md                       # This file
├── LICENSE                         # Apache-2.0
├── SECURITY.md                     # Responsible disclosure
├── contracts/                      # Aiken project — the audit target
│   ├── aiken.toml                  # Aiken v1.1.21 + stdlib v3.0.0
│   ├── plutus.json                 # Compiled blueprint (parameter-free build)
│   ├── validators/
│   │   ├── policy.ak               # Per-policy lifecycle (Claim / Cancel / Expire / batch variants)
│   │   ├── pool.ak                 # Liquidity pool + Underwrite + treasury donation
│   │   ├── lp_token.ak             # LP-token mint policy (parameterized over pool hash)
│   │   └── pool_nft.ak             # One-shot pool-identifier NFT (A-011 fix)
│   ├── lib/aegis/
│   │   ├── types.ak                # Datum + redeemer schemas, protocol constants, canonical-NFT pins
│   │   ├── pricing.ak              # Premium adequacy, fee + treasury cut math
│   │   ├── pool.ak                 # Datum-transition helpers, LP math
│   │   ├── oracle.ak               # Multi-oracle dispatcher (Charli3 + Orcfax + AegisSelf)
│   │   ├── oracle/                 # Per-provider parsers (v6 multi-oracle, v7 self-publish)
│   │   │   ├── types.ak            # Provider-uniform Price record
│   │   │   ├── charli3.ak          # Charli3 GenericData parser + script-hash binding (A-016)
│   │   │   ├── orcfax.ak           # Orcfax FSP→FS pointer + Rational price parser
│   │   │   └── aegis_self.ak       # AegisSelf self-publish parser (publisher VKH pin)
│   │   ├── validation.ak           # Shared signature/time/output helpers
│   │   └── test_helpers/           # Fixtures + security tests (222 tests, 0 failures)
│   └── README.md                   # Build + test instructions
├── docs/
│   ├── ARCHITECTURE.md             # On-chain protocol architecture
│   ├── BACKEND_INTERACTION.md      # How the off-chain backend calls the validators
│   ├── AUDITING_GUIDE.md           # Starting points + scope for the external auditor
│   ├── GREEN_PATH_PROOFS.md        # On-chain txs proving every user-facing branch executes correctly
│   └── audit/
│       ├── SECURITY_AUDIT_REPORT.md   # 37 findings, 27 closed (6 rounds of red-team)
│       ├── TREASURY_DONATION_SCOPE.md # Conway donation feature design
│       ├── RELAY_PRESIGNED_AUTH_SCOPE.md   # Auto-claim relay design (planned)
│       └── ORCFAX_INTEGRATION_SCOPE.md     # Multi-oracle redundancy design (shipped in v6)
├── deploy/
│   ├── README.md                   # Operator deploy runbook
│   ├── deploy-state.preprod.json   # Live v6.0.2 state (Cardano preprod, May 2026)
│   ├── archive/                    # v0..v5 historical deploy states
│   └── scripts/                    # mint_pool_nft, publish_refs, init_pool, _common
└── redteam/
    ├── README.md                   # Reproduction notes
    ├── redteam_a021.py             # Phantom policy at trash address (A-021, fixed v2)
    ├── redteam_a023_donation.py    # Donation underpay attempts (rejected)
    ├── redteam_a024_negcoverage.py # Negative-coverage Underwrite (A-024, fixed v3)
    ├── redteam_round3.py           # A-014/015/016 boundaries + A-025 multi-policy
    ├── smoke_donation.py           # Body-level Conway donation smoke
    └── smoke_underwrite.py         # Full green-path Underwrite + donation
```

---

## Audit posture (2026-05-05)

- **Total findings to date:** 37 (across 6 rounds of internal red-team)
- **Closed:** 27 — A-001..A-016 + A-019..A-027 + L-003 + L-006 + Charli3 NFT pin extension
- **Open:** 10 — 1 HIGH (L-002, batch expiry multi-policy aggregation — likely MED in practice), the rest MED/LOW/INFO with documented deferral rationale (see [`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md) Round 6 section). No CRITICAL findings open.
  - **A-017** (Info) — off-chain components (FastAPI / bot / frontend / SDK) outside this audit's scope; planned separate review.
  - **A-018** (Info) — Materios cross-chain attestation bridge — DEFERRED to post-v1 roadmap.
  - **L-001 / L-002 / L-005 / L-007 / A-028 / A-029** — round-6 deferrals with documented rationale.
  - **ECON-1..ECON-4** — round-6 economic findings (DoS-shaped, no fund extraction).
- **Aiken test count:** 222 / 0 (all green; verified by `aiken check` on tag `v6.0.2-redteam-round6`)
- **Plutus version:** V3 (Conway era)

The full finding-by-finding writeup is in [`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md). Every Round-2 / Round-3 / Round-6 finding includes the on-chain transaction hash that empirically demonstrated the exploit on Cardano preprod (or the test/PoC trace where a live demonstration was infeasible), plus the redeploy hash that demonstrably rejects the same attack code.

---

## What's deployed (live on Cardano preprod)

This is **v6.0.2-redteam-round6** — the post-round-6 build (deployed 2026-05-05 from `main` at `be6f1b1`). See [`deploy/deploy-state.preprod.json`](deploy/deploy-state.preprod.json) for the full record.

| Artifact | Hash / id |
|---|---|
| `policy_validator` | `9b58ec9f1749c87235ad81bd6c3c71e2238b6df7f00f93c386d307d8` |
| `pool_validator` (parameterized over policy hash) | `13b2150d5ca3b26bda15f24177852bdee357a5b934dab59ecf7c99da` |
| `lp_token_policy` (parameterized over pool hash) | `70bea1fe107845b0f0f0c0a465230054a682274f4ab3b417b815b6c4` |
| Pool NFT | `cfbc3f26fdbefeb3c9ac31dcab38f731780ef79d4a8bbc7232a4b3d6` (`AEGIS_POOL_V10`) |
| Pool UTxO (post green-path Underwrite) | [`23889dec359280a428d8bfda160df8ffdd717735aebb419720e6dd7651255db2#1`](https://preprod.cardanoscan.io/transaction/23889dec359280a428d8bfda160df8ffdd717735aebb419720e6dd7651255db2) |
| AegisSelf publisher VKH (compile-time pinned) | `6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152` |
| `AEGIS_PRICE_FEED_V1` NFT (preprod) | `d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f` |

**Live demo of the full invariant set executing successfully:**
[Underwrite tx `23889dec359280a428d8bfda160df8ffdd717735aebb419720e6dd7651255db2`](https://preprod.cardanoscan.io/transaction/23889dec359280a428d8bfda160df8ffdd717735aebb419720e6dd7651255db2) — 10 ADA coverage, 2 ADA premium, 10,000 lovelace Conway treasury donation (body field 22), `oracle_provider: Charli3`, `valid_contract: true`. This single tx exercises the bulk of the per-version invariant set: pool value conservation, A-022 policy-script-hash binding, A-024 positivity, A-025 single-policy-output count, A-026 oracle-NFT pin, A-027/L-006 redeemer-schema closure, treasury-donation enforcement, and the v6 multi-oracle dispatcher.

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
   aiken check        # runs 222 tests
   aiken build        # produces plutus.json
   ```
3. Read the audit report:
   - Start at [`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md)
   - Cross-reference cited validator file:line references against the source
   - For Round-2 / Round-3 / Round-6 findings, verify the on-chain **pre-fix** tx via [preprod.cardanoscan.io](https://preprod.cardanoscan.io)
   - For the **post-fix green path** (validators working as intended), see [`docs/GREEN_PATH_PROOFS.md`](docs/GREEN_PATH_PROOFS.md) — every user-facing branch with on-chain `valid_contract: true` proof
4. Audit the contracts:
   - Primary: [`contracts/validators/`](contracts/validators/)
   - Helpers: [`contracts/lib/aegis/`](contracts/lib/aegis/) (note: `oracle.ak` is now a thin dispatcher; per-provider parsers live under [`contracts/lib/aegis/oracle/`](contracts/lib/aegis/oracle/))
   - Fixtures + green tests: [`contracts/lib/aegis/test_helpers/`](contracts/lib/aegis/test_helpers/)
5. Read [`docs/AUDITING_GUIDE.md`](docs/AUDITING_GUIDE.md) for finding priorities, attack-surface taxonomy, and reproduction guidance.

---

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Security disclosure

See [`SECURITY.md`](SECURITY.md). For new findings: **do not file a public issue.** Email security@fluxpointstudios.com (PGP key on request).
