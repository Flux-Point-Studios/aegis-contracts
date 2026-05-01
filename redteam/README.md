# Red-Team Reproducibility

This directory contains the Python scripts the internal red-team used to construct attack transactions against deployed versions of the Aegis validators on Cardano preprod.

**Key context for the auditor:**

1. These scripts depend on the private off-chain backend repo (`api/_treasury.py`, `api/_donation_tx_builder.py`, `api/policies.py`'s PolicyDatum class, `api/pool.py` helpers, `api/chain.py` constants). That backend is NOT in this audit's scope (see [`docs/AUDITING_GUIDE.md`](../docs/AUDITING_GUIDE.md)).

2. The scripts are included as **documentation** of what attacks were attempted — not as ready-to-run tooling. Their value is:
   - Showing the EXACT attack patterns the internal team explored
   - Cross-referencing against the audit report's Round-2 / Round-3 findings
   - Letting an auditor extend or replicate them by porting to their own toolchain

3. The on-chain transactions these scripts produced are real and verifiable on Cardano preprod via Blockfrost. The audit report cites tx hashes for every Round-2 / Round-3 finding.

## Script catalog

| Script | Audit finding | What it does | Pre-fix outcome (on chain) |
|---|---|---|---|
| `redteam_a021.py` | A-021 (HIGH, fixed v2) | Submits an Underwrite tx where the policy output is at a non-policy script address (lp_token mint hash). Should inflate pool's `active_coverage` with an unspendable phantom policy. | ACCEPTED on v1 — tx [`c32d7a858bbe6d5c6ca29a502c063bcf4104072e1909dd63e20c092ccc57d973`](https://preprod.cardanoscan.io/transaction/c32d7a858bbe6d5c6ca29a502c063bcf4104072e1909dd63e20c092ccc57d973) |
| `redteam_a023_donation.py` | (donation enforcement test) | Tries Underwrite with `treasury_donation = required - 1`, `= 0`, `= None`. All should be REJECTED (verifies `donation_ok` clause is correct). | All rejected on v1 onwards. |
| `redteam_a024_negcoverage.py` | A-024 (MEDIUM, fixed v3) | Submits an Underwrite with `coverage = -5_000_000` (negative). Validator's `is_ratio_acceptable` accepted negative values due to flooring division; `verify_underwrite_datum` permitted shrinking pool's `active_coverage`. | ACCEPTED on v2 — tx [`01a1067cd496a31f069e0355717fe2ab1c4ebd5b2e0eb8ba1632a179cf04459a`](https://preprod.cardanoscan.io/transaction/01a1067cd496a31f069e0355717fe2ab1c4ebd5b2e0eb8ba1632a179cf04459a) |
| `redteam_round3.py` | A-014, A-015, A-025 | Battery of 5 attacks: ratio truncation boundary, start_time = 0, start_time = year 5138, expiry < start, multi-policy single-Underwrite. | A-014 boundary: rejected at premium-adequacy check. A-015: all rejected on v4+. A-025: ACCEPTED on v4 — tx [`b1400c6474dbecf2ad65a3ccdabac94c6a967e026d31ea128846ece02cd6f0a1`](https://preprod.cardanoscan.io/transaction/b1400c6474dbecf2ad65a3ccdabac94c6a967e026d31ea128846ece02cd6f0a1); rejected on v5. |
| `smoke_donation.py` | (positive smoke) | A bare self-transfer tx that sets the Conway `treasury_donation` body field to a non-zero value. Verifies the field works at the ledger level. | tx [`874a0899e149c053e9aa6ceaa2889585a031d93df3412dc135d5b1a321ae1e24`](https://preprod.cardanoscan.io/transaction/874a0899e149c053e9aa6ceaa2889585a031d93df3412dc135d5b1a321ae1e24) carries body field 22 = 1,000,000 lovelace. |
| `smoke_underwrite.py` | (positive smoke) | A legitimate Aegis Underwrite end-to-end: pool consumed, policy created, treasury donation injected, validator accepts. The full v5 invariant set executes. | tx [`6ff0ebac89fbcb56823a9f94d38c231269389ee7a31b922f33fb918c2f3a6caa`](https://preprod.cardanoscan.io/transaction/6ff0ebac89fbcb56823a9f94d38c231269389ee7a31b922f33fb918c2f3a6caa) — `valid_contract: True`, donation = 10,000 lovelace. |

## Running them (if you want)

The scripts assume PyCardano + the private backend code. To run:

1. Clone the private Aegis backend repo (request access from Flux Point Studios).
2. Set up the operator wallet with preprod ADA.
3. Set env vars per [`../deploy/README.md`](../deploy/README.md).
4. `python -m offchain.scripts.redteam_<name>`

Or — easier — port the attack patterns to your own preferred Cardano tx-construction toolkit (cardano-cli + Aiken, lucid-evolution, mesh, etc.). The scripts are short (~200 lines each) and the structure is straightforward.

## Why these are interesting beyond "the bug was fixed"

Each script encodes the EXACT shape of an attack tx that the validator must reject. Looking at them:

- `redteam_a021.py` — shows the temptation of accepting `Script(_)` payment credentials. The lesson generalizes to any Plutus protocol that creates new script-credentialed outputs in a tx.
- `redteam_a024_negcoverage.py` — shows how Aiken's flooring integer division breaks `<= K` ratio checks for negative inputs. The lesson generalizes to any ratio gate.
- `redteam_round3.py` (A-025 case) — shows how `list.any` short-circuits and is therefore unsafe for accounting checks that depend on count or sum. The lesson generalizes to any aggregation predicate.

These three lessons are now captured in the audit report's "Lessons" subsections under each finding. We expect any fresh audit to discover its own variants on these themes — the scripts here are starting points.
