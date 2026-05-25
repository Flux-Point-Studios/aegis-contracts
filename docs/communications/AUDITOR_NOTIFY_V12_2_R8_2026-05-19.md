# Auditor handoff — V12.2 Round-8

**Date**: 2026-05-19
**Repository**: `Flux-Point-Studios/aegis-contracts`
**Branch**: `feat/v12.2-r8`
**Prior round**: V12.2 + Round-7 merged to `main` (commit `f133fb7`, 2026-05-12)

---

## Scope of this round

Round-8 was an internal adversarial review across **four parallel surfaces**: on-chain drain attacks, cryptographic / schema integrity, off-chain API, and recent (2024-2026) Cardano-ecosystem exploit patterns. Reports are at `docs/audit/round-8/V12.2_ROUND_8_*.md` (6 markdown files; synthesis at `V12.2_ROUND_8_SYNTHESIS.md`).

The on-chain change in this round is **one validator-side fix** (R8-DRAIN-1) plus a **compiler-version rotation** (R8-H1). The remaining R8 findings live in the off-chain Python / TypeScript layers and the operational tooling, all out of scope for this on-chain audit. Below is the audit-relevant diff.

---

## On-chain change — R8-DRAIN-1 (MEDIUM, mainnet-blocking economic)

**File**: `contracts/validators/pool.ak`

**Finding**: The validator's team + partner output checks were two independent `list.any` calls. Nothing in V12.2 R7 forbade `partner_address == team_address`. When aliased, ONE on-chain output simultaneously satisfied BOTH checks — the team got short-changed by `partner_cut` per cycle, linear in premium, hitting Underwrite + BatchUnderwrite + AcceptCancellation symmetrically.

**Fix shape**:

```aiken
fn partner_address_not_aliased(
  partner_address: Option<Address>,
  team_address: Address,
  pool_address: Address,
  policy_script_hash: ByteArray,
) -> Bool {
  when partner_address is {
    None -> True
    Some(addr) ->
      addr != team_address && addr != pool_address && addr.payment_credential != Script(
        policy_script_hash,
      )
  }
}
```

Invoked in all three affected branches: Underwrite, BatchUnderwrite (over `batch_totals.partner_totals`), and AcceptCancellation (defense-in-depth against V11 policies on chain that pre-date this guard).

**Regression tests**: 5 new tests in `pool.ak` covering None-passes, alias-to-team-fails, alias-to-pool-fails, alias-to-policy-script-fails, and benign-unrelated-passes.

**Test count**: 712 / 712 pass (R7 baseline was 351; the increase comes from the new R8 regressions plus how Aiken now reports per-validator-scenario test variants).

---

## Compiler rotation — R8-H1

**Aiken v1.1.21 → v1.1.22** (released 2026-05-15).

V1.1.22 fixes three latent compiler bugs that affect deployed bytecode:
- Interner FreeUnique
- Negative bigint round-trip
- `-t silent` list-pattern empty-check removal

Per round-8 hypothesis: if v1.1.22 rebuild produces different blueprint hashes than v1.1.21, the deployed bytecode carries fixed-yesterday compiler bugs and MUST be redeployed for mainnet. **Hypothesis confirmed** — 3 of 4 validator hashes drifted between v1.1.21 and v1.1.22, source unchanged.

R8-H1 is **not** an on-chain logic change; the audit interest is purely that the compiled bytecode that ends up on mainnet should be the v1.1.22 build.

---

## Hash table (preprod live)

Per `contracts/plutus.json` (unparameterized) and the deploy-state file in the dev repo (parameter-applied):

| Validator | Unparameterized (plutus.json) | Parameter-applied (deployed) |
|---|---|---|
| `policy_validator` | `8dfed608955d1c548a971c753c5979dd98c5265434fa60bd08dbf513` | (no parameters) same |
| `pool_validator`   | `0977d57722a3c3bf32ba102e1ad5c4cf93f35fc56ca5b951491bdf04` | `9336069fc670e33473bec51e5d91f8817f3594983861351dc57de34b` |
| `lp_token_policy`  | `5052905c3748192210411b32425de847530a5c03320936106c22e036` | `30a541af5e813e79226d7468956c84db64723793114bce3d04191e4d` |
| `pool_nft.mint`    | `99ccaeaa5592823eaeb69754a50e8704864b071cd5cbecacdb0544ff` | (no parameters; init-utxo-bound at mint time) |

Preprod is now live on these hashes. See `D:/aegis/configs/deploy-state.preprod.json` in the dev repo for the full UTxO refs.

---

## What was verified CLEAN in Round 8 (positive coverage)

The four R8 agents found **zero new crypto findings** and the Vacuumlabs CTF proof confirmed non-applicability of "Mutual Exclusion Breaking" and "Multiple UTxO Instances" patterns (separate report at `docs/audit/round-8/V12.2_ROUND_8_VACUUMLABS_PROOF.md`). Specifically re-verified clean:

- CBOR canonical form preservation across the wallet-merge + submit byte-paths.
- PyCardano cost-model alphabetic-sort bug already neutralised in `_recompute_script_data_hash`.
- OracleProvider Constr indices align byte-for-byte between Aiken `types.ak` and Python `policies.py`.
- All 4 oracle resolvers (Charli3/Orcfax/AegisSelf/Indigo) pin canonical NFT AND script credential (or publisher VKH for AegisSelf).
- No custom signature verification anywhere in the Aiken codebase — all auth flows through Cardano's ledger vkey-witness layer.
- Pool NFT one-shot mint, LP mint direction, AegisSelf two-layer pin, Indigo three-layer handshake — all sound.
- Treasury donation (Conway era body field 22) cannot be zeroed under `premium_positive`.
- Reference-script substitution requires BLAKE2b preimage collision (not feasible).
- V11 → V12.2 datum decode fails closed via field-count mismatch.

---

## Recommended review focus

For an auditor reviewing R8 specifically, the **minimum useful read** is:

1. `docs/audit/round-8/V12.2_ROUND_8_SYNTHESIS.md` — 3-minute overview of all R8 findings + close sequence.
2. `contracts/validators/pool.ak` — the `partner_address_not_aliased` helper (~line 524) and its three invocation sites (Underwrite ~line 780; BatchUnderwrite ~line 1120; AcceptCancellation ~line 1373).
3. The 5 new regression tests inline at the bottom of `pool.ak`.
4. `docs/audit/round-8/V12.2_ROUND_8_DRAIN.md` — the original drain-adversary report; cites the exact lines and exploit construction.
5. `docs/audit/round-8/V12.2_ROUND_8_VACUUMLABS_PROOF.md` — non-applicability proof; the defense-in-depth recommendation at the end (tighten `>=` to `==` at pool.ak:302/453) is optional and not part of this commit.

The remaining R8 reports (CRYPTO, OFFCHAIN, PATTERNS) are scope-marker reads — they document what was checked and surfaced 0 on-chain findings.

---

## Mainnet gate status (post-R8)

Aegis is **gated on the auditor's R8 + accumulated sign-off**. All known internal review surfaces are now closed:

- 8 adversarial review rounds done.
- 712/712 aiken tests pass on v1.1.22.
- Preprod is live on V12.2 R8 (chain state recorded; commit `17a4e2a` in the dev repo).
- Operational monitoring (chain-tip divergence detector for the Nov 2025 partition class of attack) is now in tree at `offchain/scripts/chain_tip_divergence_monitor.py` in the dev repo.
- Off-chain hardening (rate limiters, network validation, sweep destination allowlist) is in the dev repo's `feat/mobile-capacitor-ios-scaffold` branch, ready to merge to main once you've completed R8 review.

Mainnet deploy will be a fresh mint + publish refs + init pool sequence against the v1.1.22 hashes above with `AEGIS_NETWORK=mainnet`. The team_address is compile-time-pinned and auto-selected at network flip; no source rebuild needed at the network-flip step.

---

Contact: `decimalist` on Discord / Cardano Forum, or `nathanielminton@fluxpointstudios.com`.
