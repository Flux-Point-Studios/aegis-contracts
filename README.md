# Aegis Smart Contracts — On-Chain Audit Repository

**Aegis** is a parametric crypto-insurance protocol on Cardano. This repository contains the on-chain code (Aiken validators, lib helpers, fixtures), the security audit report covering 22 of 24 internal findings closed across 5 deployments, deploy artifacts proving the contracts are live on Cardano preprod, and red-team scripts documenting the attacks tried.

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
│   │   ├── types.ak                # Datum + redeemer schemas, protocol constants
│   │   ├── pricing.ak              # Premium adequacy, fee + treasury cut math
│   │   ├── pool.ak                 # Datum-transition helpers, LP math
│   │   ├── oracle.ak               # Charli3 oracle integration
│   │   ├── validation.ak           # Shared signature/time/output helpers
│   │   └── test_helpers/           # Fixtures + security tests (186 tests)
│   └── README.md                   # Build + test instructions
├── docs/
│   ├── ARCHITECTURE.md             # On-chain protocol architecture
│   ├── BACKEND_INTERACTION.md      # How the off-chain backend calls the validators
│   ├── AUDITING_GUIDE.md           # Starting points + scope for the external auditor
│   └── audit/
│       ├── SECURITY_AUDIT_REPORT.md   # 24 findings, 22 closed (3 rounds of red-team)
│       ├── TREASURY_DONATION_SCOPE.md # Conway donation feature design
│       └── RELAY_PRESIGNED_AUTH_SCOPE.md  # Auto-claim relay design (planned)
├── deploy/
│   ├── README.md                   # Operator deploy runbook
│   ├── deploy-state.preprod.json   # Live v5 state (Cardano preprod, May 2026)
│   ├── archive/                    # v0..v4 historical deploy states
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

## Audit posture (2026-05-01)

- **Total findings to date:** 24 (across 3 rounds of internal red-team)
- **Closed:** 22 — A-001..A-016 + A-019..A-025
- **Open:** 2 — both Info-severity:
  - **A-017** — off-chain components (FastAPI / bot / frontend / SDK) outside this audit's scope; planned separate review
  - **A-018** — Materios cross-chain attestation bridge — DEFERRED to post-v1 roadmap
- **Aiken test count:** 186 / 0 (all green)
- **Plutus version:** V3 (Conway era)

The full finding-by-finding writeup is in [`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md). Every Round-2 and Round-3 finding includes the on-chain transaction hash that empirically demonstrated the exploit on Cardano preprod, plus the redeploy hash that demonstrably rejects the same attack code.

---

## What's deployed (live on Cardano preprod)

This is **v5** — the post-A-025 build. See [`deploy/deploy-state.preprod.json`](deploy/deploy-state.preprod.json) for the full record.

| Artifact | Hash / id |
|---|---|
| `policy_validator` | `b63091c33ee34451f59f3186bd493db39cc46387b04be59d616e146b` |
| `pool_validator` (parameterized over policy hash) | `c7cf3d90e885ddc54d1187edd491d68d1e1c2bd5cb7b2c986f632377` |
| `lp_token_policy` (parameterized over pool hash) | `08ca63fe64473b547dcce9279770bbbcd0a39ff8525082dc48eefc7a` |
| Pool NFT | `4720c6e6a56c44a71f8d0da2fabcac48bc4a531357313990f2f47f93` (`AEGIS_POOL_V6`) |
| Pool UTxO | [`6d8dd3cae2a782a397a073a84294120237555caed361a696ebeae0a39282e81e#0`](https://preprod.cardanoscan.io/transaction/6d8dd3cae2a782a397a073a84294120237555caed361a696ebeae0a39282e81e) |

**Live demo of the full invariant set executing successfully:**
[Underwrite tx `6ff0ebac89fbcb56823a9f94d38c231269389ee7a31b922f33fb918c2f3a6caa`](https://preprod.cardanoscan.io/transaction/6ff0ebac89fbcb56823a9f94d38c231269389ee7a31b922f33fb918c2f3a6caa) — body field 22 (`treasury_donation`) = 10,000 lovelace, `valid_contract: True`.

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
   aiken check        # runs 186 tests
   aiken build        # produces plutus.json
   ```
3. Read the audit report:
   - Start at [`docs/audit/SECURITY_AUDIT_REPORT.md`](docs/audit/SECURITY_AUDIT_REPORT.md)
   - Cross-reference cited validator file:line references against the source
   - For Round-2 / Round-3 findings, verify the on-chain pre-fix tx via [preprod.cardanoscan.io](https://preprod.cardanoscan.io)
4. Audit the contracts:
   - Primary: [`contracts/validators/`](contracts/validators/)
   - Helpers: [`contracts/lib/aegis/`](contracts/lib/aegis/)
   - Fixtures + green tests: [`contracts/lib/aegis/test_helpers/`](contracts/lib/aegis/test_helpers/)
5. Read [`docs/AUDITING_GUIDE.md`](docs/AUDITING_GUIDE.md) for finding priorities, attack-surface taxonomy, and reproduction guidance.

---

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Security disclosure

See [`SECURITY.md`](SECURITY.md). For new findings: **do not file a public issue.** Email security@fluxpointstudios.com (PGP key on request).
