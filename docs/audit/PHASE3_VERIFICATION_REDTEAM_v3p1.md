# Phase 3 Verification Red-Team v3.1 — Δ31-Δ40 Re-Attack Audit

**Auditor angle:** Black-hat verification re-attack of the v3.1 remediation. Prior round (`PHASE3_VERIFICATION_REDTEAM.md`) found 2 HIGHs (VR-001 SweepBurn `not_after` unbound, VR-002 RotateAuth post-rotation orphan) + 4 MEDs + 4 LOWs. v3.1 closes them via Δ31-Δ40. This pass tries to break the v3.1 fixes specifically; v3 closures already verified solid (Δ18-Δ30 in ClaimWithAuth) are out of scope.

**Date:** 2026-05-06.
**Build under review:** `D:/aegis-contracts/contracts` (aiken check 385/385 pass; 0 fail; 0 warning), `D:/aegis/offchain` (341 pytest pass, 21 cross-stack), `D:/aegis/frontend` (301 vitest pass, 24 cross-stack).
**Scope:** §0 / Δ31-Δ40 of `RELAY_PRESIGNED_AUTH_SCOPE_v2.md` v3.1; `validators/auth_witness.ak`, `validators/auth_witness_nft.ak`, `validators/policy.ak`, `lib/aegis/test_helpers/v8_integration_tests.ak` section 4.1, `tests/fixtures/invalid_payload_vectors.json`, `frontend/src/wallet/aegis/index.ts`, `frontend/scripts/check_aegis_privacy_boundary.cjs`, `aegis-contracts/scripts/check_deploy_constants.py`, `aegis-contracts/.github/workflows/deploy-gates.yml`.

---

## Executive Summary

**10 v3.1 deltas re-attacked across 24 candidate vectors; 8 closures hold cleanly; Δ31, Δ32, Δ33, Δ34, Δ36, Δ37, Δ39, Δ40 confirmed solid against direct re-attack, lateral pivot, and cross-cut probes. 2 deltas leak material gaps that should be closed before mainnet, both LOW severity and bounded by other layers of defense.** No new CRITICAL or HIGH-severity findings. The most severe surviving gap is **VR3.1-A (LOW): Δ38's privacy-boundary CI guard at `check_aegis_privacy_boundary.cjs` does not detect wildcard imports (`import * as ap from '../wallet/aegis/auth_payload'`) or dynamic imports (`await import('@noble/ed25519')`) outside the boundary — a malicious or misguided frontend developer could compose the lower-level CBOR/commit/sign primitives via either bypass and skip the Δ30 summary gate**. The exploit cost is bounded by the user's Aegis-wallet-seed unlock requirement (Argon2 + WebAuthn), and the call-site `confirmedSummary` check on `signAuthCommitment` still works for code that goes through the public surface — so this is defense-in-depth, not direct exploit. The next surviving gap is **VR3.1-B (LOW): Δ35's 13 new RotateAuth integration tests cover 5 of 14 field-binding violations explicitly (`domain_tag`, `network_magic`, `policy_validator`, `oracle_provider`, `payout_address`); the other 9 (insured_pkh, max_coverage, oracle_nft, oracle_freshness above 24h cap, not_before, not_after, pool_script_hash, pool_nft, policy_id) are exercised by ClaimWithAuth's symmetric tests but not by RotateAuth's tx-context integration suite — drift between the two would not be caught by the integration suite alone**. Code review confirms the validator binds all 14, but the test surface is asymmetric.

The Δ31 closure is **solid against the explicit attack class**: SweepBurn no longer carries `not_after`, the gate reads `payload.not_after` from the witness UTxO datum, and the regression test (`it_sweep_burn_rejects_redeemer_not_after_zero_for_live_payload`) exercises the exact pre-Δ31 attack shape with operator sig present + future-dated payload + tx_lower well below payload.not_after — validator rejects. Cross-cut: the `payload_canonical_ok` check from Δ22/Δ34 is NOT applied at SweepBurn (the witness is being burned, not validated for claim), but the canonical re-encode is enforced at MintWitness (Δ34) so on-chain witnesses are guaranteed canonical — non-canonical bytes can't even reach SweepBurn.

The Δ32 closure is **solid**: the rotation flow is the respend at auth_witness_validator (Option A), the new `auth_witness_validator` spend validator gates `mint_qty == 0 && continuation_count == 1` for the rotation path, the policy validator's RotateAuth branch enforces `exactly_one_new_witness`, the `count_script_inputs == 1` global guard rules out multi-policy rotations, and the integration tests exercise (a) green-path single rotation, (b) two-witness-output rejection, (c) zero-witness-output rejection, (d) asset-name-change rejection. The post-rotation ClaimWithAuth count==1 invariant holds because the chain never has more than one witness UTxO under a given asset_name.

The Δ33 closure is **solid against malicious-frontend rotation poisoning**: the new payload is decoded, canonically re-encoded, and bound across all 14 fields including `payload.policy_validator == own_script_hash`, the Ed25519 signature is verified, and `blake2b_224(new_awd.insured_vkey) == datum.insured` rules out attacker-controlled vkey substitution. Tested via 5 explicit field-violation negatives + canonical-CBOR negative + green-path post-rotation claim.

The Δ34 closure is **solid**: MintWitness's canonical re-encode check rejects non-canonical bytes at mint time, so a buggy encoder cannot create an unclaimable witness. The check is on `redeemer.payload_cbor` (which is then asserted byte-equal to the witness UTxO's payload_cbor by binding).

The Δ36 manifest expansion is **solid**: 15 vectors load correctly in both stacks; both Python (21 tests) and TS (24 tests) cross-stack tests pass. The agent's substitution of `domain_tag_zero_length` (for "signer_pkh consistency") and `max_coverage_negative` (for "64-byte signature length") is acceptable — `signer_pkh consistency` is enforced on-chain via `blake2b_224(awd.insured_vkey) == datum.insured` (lives outside AuthCoveragePayload), and 64-byte signature length is enforced in both stacks' `signAuthCommitment` / `sign_auth.py` plumbing layers. Verified: `frontend/src/wallet/aegis/sign_auth.ts:227` (`signature.length !== SIGNATURE_BYTES`) and `offchain/src/aegis/tx_builder_auth.py:488` (`if len(payload_signature) != 64`).

The Δ37 closure is **solid**: the on-chain 24h sanity cap mirrors the off-chain Python and TS encoders, applied to BOTH ClaimWithAuth (`payload_oracle_freshness_ok`, line 503-504) AND RotateAuth (`new_payload_oracle_freshness_ok`, line 806-807). Boundary tests confirm acceptance at exactly 86_400_000 ms and rejection at 86_400_001 ms. Negative oracle_freshness rejected. Aiken's `Int` is BigInt — no integer overflow concerns.

The Δ39 + Δ40 deploy-gate closures are **solid for the documented threat model**: the script catches all-zero placeholder, header drift, and missing `_mainnet` declaration. The script does NOT catch arbitrary developer placeholders (e.g., all-`a1`-bytes), and does not enforce that the `enterprise_addr_header` active-build constant matches the targeted-network — both documented limitations covered by the deploy runbook. The CI workflow `deploy-gates.yml` runs on every push, PR, and `v*` tag, with a self-test step BEFORE the actual check.

### Severity tally

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 2 |
| INFO | 5 |
| **Total** | **7** |

### Findings table

| ID | Severity | Title | Δ-against | Status |
|---|---|---|---|---|
| **VR3.1-A** | LOW | `check_aegis_privacy_boundary.cjs` does not detect wildcard imports (`import * as ap from`) or dynamic imports (`await import(...)`); a malicious or buggy frontend file outside the wallet/aegis boundary can pull `auth_payload`'s primitives + `@noble/ed25519`'s signing API and skip the Δ30 summary gate | Δ38 / VR-007 | OPEN (defense-in-depth gap; not direct exploit) |
| **VR3.1-B** | LOW | RotateAuth's 14-field binding has only 5 explicit negative integration tests; 9 fields (insured_pkh, max_coverage, oracle_nft, oracle_freshness, not_before, not_after, pool_script_hash, pool_nft, policy_id) are validator-bound but not exercised by RotateAuth's tx-context tests — drift between RotateAuth and ClaimWithAuth field bindings would not be caught by the integration suite alone | Δ35 / VR-005 | OPEN (coverage gap; not chain bug) |
| VR3.1-C | INFO | RotateAuth lacks integration test for `vkey_binds_to_insured` violation (the Δ33 step 37 check that `blake2b_224(new_awd.insured_vkey) == datum.insured`); the validator binds the field, but no test forces a tampered vkey | Δ35 | OPEN (coverage gap) |
| VR3.1-D | INFO | `it_rotate_auth_post_rotation_claim_with_auth_succeeds` exercises only the 14-field payload binding mirror, not the post-rotation count==1 witness gate; the test name overpromises full end-to-end coverage | Δ35 | OPEN (test naming gap) |
| VR3.1-E | INFO | `offchain/src/aegis/config.py:109-110` docstring lists historical post-audit-redeploy hashes (`policy_validator_hash = 532740d2...`, `pool_validator_hash = 54280b3f...`) that are stale relative to the current v3.1 plutus.json (`fd7246d2...`, `3282f461...`); this is documentation drift only — the actual config field defaults to empty string and is populated from runtime config files | Δ32 hash rotation | OPEN (docstring drift) |
| VR3.1-F | INFO | The `auth_witness_nft` MintWitness validator does NOT pin the witness output's address to the canonical `auth_witness_validator_hash` (the validator is parameterized over `policy_validator_hash` but not `auth_witness_validator_hash`); a malicious off-chain builder could mint the witness and place it at an attacker-controlled script address. Subsequent rotation would carry the witness into the same attacker script (because `witness_script_hash` is derived from the OLD witness's address). PRE-EXISTING IN v3 — not introduced by Δ31-Δ40, but worth flagging because Δ32's design depends on the witness location being trusted. Bricks the relay-auth path for the affected user; no funds at risk (manual claim fallback works) | Pre-existing | INFO (out of v3.1 scope) |
| VR3.1-G | INFO | Concurrent RotateAuth on multiple policies in the same tx is blocked by Δ6's `count_script_inputs(inputs, own_script_hash) == 1` global guard, but no integration test in the v3.1 suite exercises this rejection explicitly. Coverage relies on Δ6's existing tests in `security_tests.ak` | Δ35 | INFO (covered transitively) |

---

## Per-finding detail

### VR3.1-A — LOW — Privacy boundary CI guard misses wildcard and dynamic imports

**Threat model:** A frontend file outside `src/wallet/aegis/` composes the lower-level CBOR/commit/signing primitives without going through `signAuthCommitment` and its mandatory `confirmedSummary` gate (Δ30). The Δ38 closure adds a CI script (`check_aegis_privacy_boundary.cjs`) wired to `npm run lint:guard` that scans `src/` for forbidden symbols and module specifiers in `import { … } from '…'` clauses. The script's regex check `/\{([\s\S]*?)\}/` only matches BRACED named imports — wildcard `import * as` and dynamic `await import('…')` evade detection.

**Files:** `D:/aegis/frontend/scripts/check_aegis_privacy_boundary.cjs` lines 334-357 (extractImportStatements), 368-422 (findBreachesInImport).

**Evidence — wildcard bypass:**
```typescript
// File: src/components/MaliciousPanel.tsx
import * as ap from '../wallet/aegis/auth_payload';

export function bypass() {
  const cbor = ap.encodeAuthCoveragePayload({} as any);
  return ap.commitmentHash(cbor);
}
```

CI guard run against this file:
```
$ node scripts/check_aegis_privacy_boundary.cjs
check_aegis_privacy_boundary: OK (52 TS/TSX files scanned outside src/wallet/aegis/, 0 breaches)
```

**Evidence — dynamic-import bypass:**
```typescript
// File: src/components/MaliciousPanel.tsx
export async function bypass() {
  const ed = await import('@noble/ed25519');
  const ap = await import('../wallet/aegis/auth_payload');
  const cbor = ap.encodeAuthCoveragePayload({} as any);
  const commit = ap.commitmentHash(cbor);
  return ed.signAsync(commit, new Uint8Array(32));
}
```

CI guard run against this file: same `0 breaches`. The script's docstring (lines 326-330) explicitly says "we don't need to handle `import('…')` dynamic-import expressions, since those are runtime loads not module-level imports the boundary cares about." This is the exact attack vector that bypasses the guard.

**Why this is bounded (LOW not MED/HIGH):**
1. **The Aegis-wallet seed is gated by Argon2 + optional WebAuthn-PRF.** A malicious component outside the boundary cannot conjure a private key — it must obtain one via `unsealShares`, which requires the user's passphrase. So even with the privacy bypass, no signature can be produced without active user consent at a deeper layer.
2. **`signAuthCommitment` is still the only function that holds a `signAsync` call inside the boundary.** A bypass via wildcard imports of `auth_payload` alone produces only `payload_cbor + commit` — not a signature. To sign, the bypassing code needs `@noble/ed25519`, which requires either (a) the dynamic-import path (caught by VR3.1-A but not by the static-import guard), or (b) bringing in a NEW Ed25519 dependency (`tweetnacl`, `node-forge`, etc.). Today's `package.json` carries only `@noble/ed25519` and `@noble/hashes`; the latter is hashing-only.
3. **The on-chain validator's 14-field binding (Δ20 / Δ33) catches every payload-deception attack at the chain layer.** A bypassed-summary signature still produces a valid Ed25519 over a real payload; if the payload's fields don't bind to the on-chain policy datum, ClaimWithAuth rejects.

**Suggested fix:**
1. Extend `findBreachesInImport` to detect wildcard imports: scan for `import\s+\*\s+as\s+\w+\s+from\s+['"]([^'"]+)['"]` and reject if the right-hand-side is `..wallet/aegis/auth_payload` (or any non-`signAuthCommitment`-capable path inside the boundary).
2. Extend the comment-stripped source scan to detect dynamic imports: `import\s*\(\s*['"]([^'"]+)['"]` matching `@noble/ed25519` and `..wallet/aegis/auth_payload` with full-path resolution. The script's existing docstring acknowledges the dynamic-import gap; closing it requires a small AST step.
3. Alternative: tag `auth_payload.ts`'s lower-level primitives with a TypeScript `@internal` JSDoc and run `tsc --declaration` with `stripInternal: true` so the public types/declarations omit them — at runtime they're still callable, but the type system steers consumers away. Combined with the linter, this makes the bypass surface explicit.

**Why this is open against v3.1:** The Δ38 narrative explicitly claims "TypeScript module privacy is convention-only — the CI guard … enforces this discipline at build time." The CI guard fails to enforce on the two bypass shapes shown above. A motivated developer can reach `auth_payload`'s primitives outside the boundary today with no CI signal.

**Severity rationale:** LOW — defense-in-depth gap, no direct exploit since the chain-side 14-field binding catches all field-deception attacks and the wallet-seed unlock rate-limits any bypass attack to per-user-consent rate. The Δ30 summary gate is the explicit RT-C-06 / Δ16 closure layer; the privacy boundary is one of two layers protecting it (the other being the call-site enforcement inside `signAuthCommitment`, which still works correctly). After mainnet ship, Phase-4 hardening should close the wildcard + dynamic-import gaps in the linter.

---

### VR3.1-B — LOW — RotateAuth's 14-field binding has 5 of 14 explicit negative integration tests

**Threat model:** Drift between the RotateAuth and ClaimWithAuth field-binding chains in policy.ak. ClaimWithAuth has 14 negative tests (`it_claim_with_auth_rejects_*` for each field); RotateAuth has only 5 (`it_rotate_auth_rejects_field_binding_violation_*` for `domain_tag`, `network_magic`, `policy_validator`, `oracle_provider`, `payout_address`). The remaining 9 fields are validator-bound but the integration suite would not catch a future regression that loosened the binding on `insured_pkh`, `max_coverage`, `oracle_nft`, `oracle_freshness > 24h`, `not_before`, `not_after`, `pool_script_hash`, `pool_nft`, or `policy_id`.

**Files:** `D:/aegis-contracts/contracts/lib/aegis/test_helpers/v8_integration_tests.ak` lines 1724-1877 (the 5 RotateAuth field-binding tests).

**Evidence:** `grep -cE "test it_rotate_auth_rejects_field_binding" v8_integration_tests.ak` returns 5 (vs ClaimWithAuth's 14). The validator chain at policy.ak:840 binds all 14 fields via `&&`, but the mirror's integration negatives only cover the 5 listed.

**Why this is LOW:** ClaimWithAuth's 14 negatives + RotateAuth's `mirror_rotate_auth_full` chain mean every field IS exercised at the mirror level for at least one redeemer. If a developer accidentally drops a field from RotateAuth's binding chain, ClaimWithAuth's field bindings still hold; the failure shape would be a malicious frontend can rotate to a witness that fails ClaimWithAuth at first claim — degrading the relay-auth path but not the manual fallback. Funds remain safe.

**Suggested fix:** Add 9 more RotateAuth negative tests mirroring the ClaimWithAuth pattern:
- `it_rotate_auth_rejects_field_binding_violation_insured_pkh`
- `it_rotate_auth_rejects_field_binding_violation_max_coverage`
- `it_rotate_auth_rejects_field_binding_violation_oracle_nft`
- `it_rotate_auth_rejects_field_binding_violation_oracle_freshness_above_cap`
- `it_rotate_auth_rejects_field_binding_violation_not_before`
- `it_rotate_auth_rejects_field_binding_violation_not_after`
- `it_rotate_auth_rejects_field_binding_violation_pool_script_hash`
- `it_rotate_auth_rejects_field_binding_violation_pool_nft`
- `it_rotate_auth_rejects_field_binding_violation_policy_id`

Each is a copy-paste of the existing 5 with the field name changed. Cost: ~30 minutes Aiken.

**Severity rationale:** LOW — coverage gap, not a chain bug. The validator code is symmetric with ClaimWithAuth's tested code. After mainnet ship, this can be closed in a v8.0.1 hardening pass.

---

### VR3.1-C — INFO — RotateAuth lacks `vkey_binds_to_insured` negative integration test

**Threat model:** Drift on Δ33 step 37 (`blake2b_224(new_awd.insured_vkey) == datum.insured`) — the cryptographic gate that prevents an attacker from smuggling a controlled vkey + matching sig past the rotation.

**Files:** `D:/aegis-contracts/contracts/validators/policy.ak` line 830-831; `lib/aegis/test_helpers/v8_integration_tests.ak` (no `it_rotate_auth_rejects_wrong_vkey` test).

**Evidence:** `grep -nE "vkey|insured_vkey.*rotate" v8_integration_tests.ak` returns the helper definitions (line 80, 215, 240) and the mirror's check (line 656), but no test forces `new_awd.insured_vkey` to a value whose blake2b_224 differs from `datum.insured`.

**Suggested fix:** Add `it_rotate_auth_rejects_wrong_vkey()` that builds a rotation tx with `new_awd.insured_vkey = #"...some-other-32-byte-vkey..."` and asserts `mirror_rotate_auth_full == False`. Cost: ~5 minutes.

**Severity rationale:** INFO — the validator binds the field; this test would only catch a future regression. ClaimWithAuth's tests do NOT have a direct vkey-binding negative either (the `signature_valid` check would fail first); the gap is symmetric. Treating this as a coverage refinement, not a bug.

---

### VR3.1-D — INFO — `it_rotate_auth_post_rotation_claim_with_auth_succeeds` overpromises

**Threat model:** Test-name expectations mismatch. The test claims to close VR-002's regression failure mode end-to-end, but the body only invokes `mirror_claim_with_auth_payload_binding` against the new payload — not the count==1 witness gate.

**Files:** `D:/aegis-contracts/contracts/lib/aegis/test_helpers/v8_integration_tests.ak` lines 1879-1903.

**Evidence:**
```aiken
test it_rotate_auth_post_rotation_claim_with_auth_succeeds() {
  // ...
  // The "claim with auth" component is exercised via the existing
  // `mirror_claim_with_auth_payload_binding` helper against the NEW
  // payload (which is what would be on chain after rotation).
  let datum = sample_policy_datum()
  let new_payload = rotation_new_payload()
  let new_commit = commit(new_payload)
  let new_datum = PolicyDatum { ..datum, auth_commitment: Some(new_commit) }
  mirror_claim_with_auth_payload_binding(
    new_datum,
    encode(new_payload),
    policy_validator_hash,
  )
}
```

The test does NOT build a Transaction with the new witness as a reference input and run `collect_witnesses` to verify count==1. It only checks payload binding. The count==1 invariant is exercised by `it_full_claim_with_auth_witness_count_one_green` (line 2109), which is a separate ClaimWithAuth test, not a post-rotation test.

**Suggested fix:** Either rename the test to `..._payload_binding_succeeds` to match what it actually tests, OR extend the body to build a real Transaction with a single new-witness reference input + run the count==1 mirror.

**Severity rationale:** INFO — the test name overpromises but doesn't claim something false. The combined coverage of `mirror_claim_with_auth_payload_binding` + `it_full_claim_with_auth_witness_count_one_green` does provide the invariant; this is a refactor-for-clarity finding, not a coverage gap.

---

### VR3.1-E — INFO — `offchain/src/aegis/config.py` docstring carries stale post-audit hashes

**Threat model:** Documentation drift confuses operators. The docstring on `ScriptConfig` shows `policy_validator_hash = 532740d2...` which is the pre-v8 post-audit hash; the current v3.1 plutus.json's `policy.policy_validator.spend` is `fd7246d2cd440d078dfda4bf74a3389ca93cf6098d63f8095e78f4e2`.

**Files:** `D:/aegis/offchain/src/aegis/config.py` lines 109-110.

**Evidence:**
```python
@dataclass
class ScriptConfig:
    """Deployed contract addresses and hashes.

    The canonical script hashes after the post-audit redeploy are:
        policy_validator_hash = 532740d2b5dd5742541429b3bf09130dbed95f36144fa43a9d629c46
        pool_validator_hash   = 54280b3fc0e1d0902de3fcb3be207ff593e74e65695645f968ef90a1
        lp_token_policy_id    = 5052905c3748192210411b32425de847530a5c03320936106c22e036
    ...
    """
    policy_validator_hash: str = ""  # populated from runtime config
```

The actual runtime field defaults to `""` and gets overridden from the operator's TOML / env. So the docstring is misleading-only — no runtime impact. But an operator reading the docstring and using those hashes verbatim would deploy with WRONG hashes and discover the mismatch only at first tx submission.

**Suggested fix:** Update docstring to either (a) list the current v3.1 hashes from `plutus.json`, or (b) remove the inline hash list and point at `aegis-contracts/plutus.json` as the source of truth.

**Severity rationale:** INFO — documentation drift, not runtime bug.

---

### VR3.1-F — INFO — Pre-existing: `auth_witness_nft` MintWitness does not pin witness output to canonical auth_witness_validator address

**Threat model:** Malicious off-chain builder during Underwrite places the minted witness UTxO at an attacker-controlled script address (instead of `auth_witness_validator`). Subsequent ClaimWithAuth references the witness as a reference input — the validator's `collect_witnesses` only checks NFT presence, not the script-address. The witness datum is bound to the policy via `commit_from_cbor(payload_cbor) == commit` and the 14-field binding, so the attacker cannot directly redirect funds; they CAN destroy the witness or substitute its datum (the attacker-script accepts arbitrary spends), bricking the user's relay-auth path.

**Files:** `D:/aegis-contracts/contracts/validators/auth_witness_nft.ak` MintWitness path (lines 167-247) — no check on the witness output's address. The mint validator's parameterization is `(init_utxo_ref, network_tag, policy_validator_hash, operator_pkh)` — there's no `auth_witness_validator_hash` parameter to bind against.

**Why this is INFO not LOW or MED:**
1. **Pre-existing in v3** — not introduced by Δ31-Δ40. The original v3 MintWitness path had the same gap; Δ32's respend pattern (which derives `witness_script_hash` from the OLD witness's address) inherits the trust assumption that the witness is at the canonical script.
2. **Bricking attack only — no funds at risk.** The attacker can destroy or corrupt the user's witness, but ClaimWithAuth's commit-binding + 14-field binding ensures any corrupted witness fails Δ20 / Δ22 / payout_address binding. The user's manual claim path (Δ29 / v6.0.2) is unaffected.
3. **Mitigated at the off-chain layer.** A correctly-implemented off-chain Underwrite builder always places the witness at `auth_witness_validator` — the `aegis-contracts` Python and TS reference encoders do this. The attack requires a corrupted builder, which is the same surface as A-009/Δ9's payout_address class.

**Suggested fix:** Add `auth_witness_validator_hash` as a fifth parameter to the auth_witness_nft minting policy. In the MintWitness branch, walk outputs and assert at least one output at `auth_witness_validator_hash` carries the minted asset name with quantity 1. Cost: ~1 hour Aiken + 1 negative test. This is post-mainnet hardening — not a v3.1 ship-blocker, but should be tracked for v8.1.

**Severity rationale:** INFO — pre-existing, scope-flagged here for traceability since Δ32 builds on the witness-location trust assumption. Move to OPEN for the next hardening pass.

---

### VR3.1-G — INFO — No explicit integration test rejects multi-policy concurrent RotateAuth

**Threat model:** Coverage gap on the Δ6 single-policy-input guard's interaction with RotateAuth. Two concurrent rotations would require 2 policy_validator inputs in the same tx, which Δ6 rejects. No test in `v8_integration_tests.ak` exercises the rejection.

**Files:** `D:/aegis-contracts/contracts/lib/aegis/test_helpers/v8_integration_tests.ak`.

**Evidence:** `grep -nE "concurrent|two policies|multi.*polic|two_rotate_auth" v8_integration_tests.ak` returns no matches. Δ6's rejection is exercised by `security_tests.ak`'s existing tests (count_script_inputs invariants), but RotateAuth's redeemer specifically is not covered.

**Severity rationale:** INFO — covered transitively by Δ6's tests. Adding a RotateAuth-specific multi-input test would be ~5 minutes; treat as v8.0.1 hardening.

---

## Closures verified solid in v3.1

These v3.1 deltas were attacked along three axes (direct re-attack, lateral pivot, cross-cut) and held up:

### Δ31 — SweepBurn `not_after` is witness-bound (VR-001)

**Direct re-attack:** Pass `not_after = 0` via redeemer — IMPOSSIBLE: redeemer no longer carries `not_after`. The validator decodes the witness datum's `payload_cbor` and reads `payload.not_after`. No surface for operator-supplied `not_after`.
**Lateral pivot:** Forge witness UTxO datum with `payload.not_after = 0` — BLOCKED: Δ34's canonical re-encode at MintWitness ensures the witness's `payload_cbor` is canonical and bound to the user's signed commit. A non-canonical or forged payload cannot reach SweepBurn.
**Cross-cut:** Submit SweepBurn with the witness as a REFERENCE input (not regular) — BLOCKED: the validator's `list.find(inputs, ...)` searches REGULAR inputs only; a reference-input witness wouldn't be found and the `expect Some(witness_input)` aborts.
**Multiple input collision:** Provide an asset_name that matches multiple input UTxOs — IMPOSSIBLE: by NFT semantics + Δ34 mint policy's `exactly_one_minted` + per-policy uniqueness via blake2b_224(policy_id), only one UTxO with the asset_name can exist on chain at any time; even if it did, `list.find` returns the first, but that UTxO's payload's `not_after` is the cryptographically-bound expiry — operator cannot lie about it.
**Operator-time-frame attack:** Operator sets `tx_validity_lower_bound` to far-future to satisfy `tx_lower > payload.not_after` — TECHNICALLY POSSIBLE but **mitigated by Cardano consensus**: the validity range is enforced by every node; an operator-submitted tx with `lower_bound = 9_999_999_999_999` would be rejected by validators (the tx has not entered its validity window yet from the chain's view — no node would include it). The operator cannot accelerate chain time. Defense holds at the consensus layer.

**Tested by:** `it_sweep_burn_rejects_redeemer_not_after_zero_for_live_payload` (regression test for the exact pre-Δ31 attack shape) + the existing `it_sweep_burn_rejects_pre_expiry` + `it_sweep_burn_rejects_unsigned_by_operator` + `it_sweep_burn_rejects_invalid_network_tag`.

### Δ32 — RotateAuth respend at auth_witness_validator (VR-002)

**Direct re-attack:** Two RotateAuth in same tx — BLOCKED by Δ6 (`count_script_inputs == 1`). The two-witness-output failure shape — BLOCKED by `exactly_one_new_witness == 1` count gate AND auth_witness_validator's `continuation_count == 1` independent check.
**Lateral pivot:** RotateAuth + ClaimWithAuth in same tx — BLOCKED by Δ6 (one policy input only). Both redeemers consume the same policy UTxO; only one redeemer can fire per UTxO.
**Lateral pivot:** RotateAuth + Cancel of same policy in same tx — BLOCKED by Δ6 (one policy input). Same UTxO, mutually exclusive redeemers.
**Cross-cut:** Construct a tx where the new witness output's script credential is wrong — POTENTIAL VR3.1-F-class concern: `witness_script_hash` is derived from the OLD witness's address. If the OLD witness is at attacker's script, the new witness output is gated against attacker's script (continuation_count check). The auth_witness_validator's spend logic at the OLD attacker script address is not auth_witness_validator's logic, so the check chain may not run as designed. **This is the VR3.1-F INFO finding — pre-existing in v3, scope-flagged for v8.1 hardening, not a Δ32 regression.**
**Cross-cut:** Mint qty != 0 on RotateAuth — BLOCKED: auth_witness_validator's rotation path requires `mint_qty == 0`; a non-zero mint forces the burn-only path which requires `continuation_count == 0` (incompatible with the rotation respend's `continuation_count == 1`). Either path fails.
**Cross-cut:** RotateAuth where `insured_pkh` doesn't match `datum.insured` — BLOCKED by `payload.insured_pkh == datum.insured` (Δ33 step 27).
**Cross-cut — un-rotate via second RotateAuth back to old commit:** the user's CIP-30 sig + `actual_rotation` gate means a deliberate identical rotation is rejected (`old != new_commit` requires real change). A near-identical rotation requires finding a payload that hashes to a 1-bit-flipped commit — preimage-resistant, infeasible. The replay protection is exercised by `it_rotate_auth_old_signature_invalid_after_rotation`.

**Tested by:** 13 RotateAuth integration tests in section 4.1 covering green path + 8 explicit negatives + 2 regression-green-path (post-rotation claim works). Mirror `mirror_rotate_auth_full` covers the full validator's `&&`-chain.

### Δ33 — RotateAuth applies Δ20+Δ22 to new witness's payload (VR-003)

**Direct re-attack:** Field-by-field tampering — partially BLOCKED by 5 explicit tests (`it_rotate_auth_rejects_field_binding_violation_*` for domain_tag, network_magic, policy_validator, oracle_provider, payout_address — the prototypical attack). The remaining 9 fields are validator-bound but the integration tests do not exercise them — see VR3.1-B (LOW).
**Direct re-attack:** Canonical re-encode bypass — BLOCKED by `new_payload_canonical_ok = cbor.serialise(new_payload_data) == new_awd.payload_cbor` (line 780-781). The `it_rotate_auth_rejects_non_canonical_new_payload` test (line 1622) submits canonical bytes + a stray trailing byte — `cbor.deserialise` aborts on the trailing byte; the guarded helper captures the failure as False.
**Cross-cut:** Cross-policy binding: payload signed for policy A, used to rotate policy B — BLOCKED by `new_payload_data.policy_id == datum.policy_id` (line 789-790) AND `new_witness_policy_id_ok = new_awd.policy_id == datum.policy_id` AND `asset_name = blake2b_224(datum.policy_id)` (the asset name is policy-scoped, so a witness for policy A literally has a different asset name than policy B's lookup).
**Cross-cut — ed25519 signature replay:** the new witness's signature is verified against `new_commit`, NOT the old commit. The `verify_signature(new_awd.insured_vkey, new_commit, new_awd.signature)` call (line 832-833) ensures the signature is fresh. Old-signature replay protection is exercised by `it_rotate_auth_old_signature_invalid_after_rotation`.

### Δ34 — MintWitness applies Δ22 canonical CBOR re-encode (VR-004)

**Direct re-attack:** Submit non-canonical bytes that decode but re-encode differently — BLOCKED by `payload_canonical = cbor.serialise(payload); payload_canonical_ok = payload_canonical == payload_cbor` (lines 202-203). Exercised by `it_mint_witness_rejects_non_canonical_payload` (line 850). The check is on the WITNESS UTXO's `payload_cbor` via the redeemer (the redeemer carries `payload_cbor`, and the witness UTxO output's datum carries the same bytes — bound by the policy_id derivation chain).

### Δ35 — Full RotateAuth tx-context integration tests (VR-005)

**Coverage status:** 13 new tests cover green path + 8 explicit negatives + 2 regression-green-path (post-rotation claim succeeds, old-signature replay protection). Asymmetric coverage on field-binding negatives (5 of 14 — see VR3.1-B). Test naming overpromises on `it_rotate_auth_post_rotation_claim_with_auth_succeeds` (see VR3.1-D). No test for concurrent multi-policy RotateAuth (see VR3.1-G — covered transitively by Δ6).

**Suggested additions for v8.0.1 hardening:**
- 9 field-binding negatives (VR3.1-B fix).
- 1 vkey-mismatch negative (VR3.1-C fix).
- 1 multi-policy rotation rejection (VR3.1-G fix).
- 1 expiry-boundary RotateAuth (`payload.not_after == tx_lower` — boundary case).

### Δ36 — Cross-stack invalid-payload manifest expanded to 15 rules (VR-006)

**Substitution rationale verified:**
- `signer_pkh consistency` (off-chain): VR-006 asked for an entry asserting `awd.insured_vkey` and `payload.insured_pkh` agree. The `insured_vkey` lives in `AuthWitnessDatum`, not `AuthCoveragePayload`, so it cannot be expressed as a payload-shape vector. **On-chain enforcement: `blake2b_224(awd.insured_vkey) == datum.insured` in ClaimWithAuth (policy.ak:454) and RotateAuth (policy.ak:830).** Off-chain enforcement: the surrounding `signAuthCommitment` (TS) and `sign_auth.py` plumbing layers compute `signer_pkh = blake2b(pubkey, dkLen=28)` from the supplied private key and emit it as the `signer_pkh` field of `AuthCommitmentSigned` — drift between this and the payload's `insured_pkh` would be caught by the wrapper, but this is wrapper-level, not payload-shape.
- `64-byte signature length`: same rationale — signature lives in `AuthWitnessDatum`. **Off-chain enforcement: `signAuthCommitment` (sign_auth.ts:227) checks `signature.length !== SIGNATURE_BYTES`; `tx_builder_auth.py:488` checks `len(payload_signature) != 64`.** Both stacks reject the wrong length.

The substitution to `domain_tag_zero_length` (vector 14) and `max_coverage_negative` (vector 15) covers symmetric length-class boundary cases (the empty-bytestring length boundary for hash-width fields, and the negative-int boundary for non-negative-int fields). Acceptable.

**Tested by:** `offchain/tests/test_cross_stack_validation.py::TestCrossStackRejection` (15 vectors × 1 = 15 negatives) + `frontend/src/wallet/aegis/__tests__/cross_stack_validation.test.ts` (24 tests including 15 vector-rejection + manifest-sanity + boundary-equivalence). Both stacks pass.

### Δ37 — oracle_freshness 24h sanity cap (VR-008)

**Direct re-attack:** Submit `oracle_freshness = 999_999_999_999` ms (~285 years) — BLOCKED in BOTH redeemers: ClaimWithAuth at policy.ak:503-504 (`>= 0 && <= 86_400_000`); RotateAuth at policy.ak:806-807 (same). Tested at boundary by `it_claim_with_auth_accepts_oracle_freshness_exactly_24h` (86_400_000 accepted) + `it_claim_with_auth_rejects_oracle_freshness_above_24h_cap` (86_400_001 rejected) + `it_claim_with_auth_rejects_negative_oracle_freshness` (-1 rejected).
**Wraparound:** Aiken's `Int` is BigInt — no integer overflow. `2^63-1` would pass `<= 86_400_000`? Let me re-check: `9223372036854775807 <= 86_400_000` is `False` — rejected. **Verified.**
**Asymmetry check:** RotateAuth has the same bound (line 807); confirmed by code review and by mirror's `mirror_rotate_auth_full` line 645-646. There is no test case explicitly for RotateAuth's freshness boundary — coverage gap noted in VR3.1-B but not severity-impacting.

### Δ38 — Frontend privacy boundary (VR-007 — partial — see VR3.1-A)

**Static-import surface:** SOLID against named imports. The CI guard catches `import { encodeAuthCoveragePayload, … } from '../wallet/aegis/auth_payload'` and even `import { … as alias }` (verified: tested with red-team probe; guard reports breach + exits 1). Module specifier check catches `import { signAsync } from '@noble/ed25519'`.
**Wildcard imports:** OPEN — see VR3.1-A.
**Dynamic imports:** OPEN — see VR3.1-A. Documented limitation in the script's docstring.

### Δ39 — `auth_witness_nft_policy_id` placeholder gate (VR-009)

**Direct re-attack:** Ship build with all-zero placeholder — BLOCKED. Self-test passes 6/6: placeholder rejected, real deploy accepted, swapped headers rejected, missing _mainnet rejected, bad-length policy_id rejected, typo in active header rejected.
**Bypass via non-zero placeholder:** A developer using `#"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"` (28-byte non-zero) would pass the script's check — documented limitation. The script catches the SPECIFIC all-zero placeholder, not arbitrary repeated-byte patterns.
**Coverage:** Per the script docstring lines 167-174, the check catches "the operator forgot to update" class — sufficient for the documented threat model. Arbitrary developer placeholders are out of scope.
**CI integration:** `.github/workflows/deploy-gates.yml` runs on every `push: branches: ["**"]` + `tags: ["v*"]` + `pull_request` + manual dispatch. Self-test runs BEFORE the actual check (pre-flight integrity).

### Δ40 — `enterprise_addr_header_*` drift gate (VR-012)

**Direct re-attack:** Swap mainnet/testnet headers — BLOCKED. Self-test case "swapped headers rejected" verifies.
**Direct re-attack:** Typo in active header (`#"00"`) — BLOCKED. Self-test case "typo in active header rejected" verifies.
**Bypass via second header constant:** A developer adding `enterprise_addr_header_zigzag = #"62"` would not be detected by the script (it only checks the 4 named constants). However, the validator's `enterprise_addr_of(datum.insured)` uses only `enterprise_addr_header` — adding a new constant without rewiring the validator would have no runtime effect. **Documented limitation.**
**Network-coupling check:** the script does NOT verify that the active header matches the targeted network (would need an env var or build flag). Per docstring lines 41-46, this is the deploy runbook's responsibility. Acceptable.

---

## Top fixes by impact

| # | Finding | Impact | Effort | Mainnet block? |
|---|---|---|---|---|
| 1 | VR3.1-A — Detect wildcard + dynamic imports in privacy guard | Closes the defense-in-depth bypass on the Δ30 summary gate | ~2 hours JS + extended self-test | NO — bounded by chain-side Δ20/Δ33 + wallet-seed unlock; defense-in-depth |
| 2 | VR3.1-B — Add 9 RotateAuth field-binding negative tests | Symmetric coverage with ClaimWithAuth | ~30 minutes Aiken (copy-paste pattern) | NO — validator binds all 14, tests miss 9; would only catch future regression |
| 3 | VR3.1-C — Add `it_rotate_auth_rejects_wrong_vkey` | Locks in vkey-binding regression guard | ~5 minutes | NO — same severity as VR3.1-B |
| 4 | VR3.1-D — Rename `..._post_rotation_claim_with_auth_succeeds` to `..._payload_binding` | Test-naming clarity | ~1 minute | NO — naming concern |
| 5 | VR3.1-E — Update docstring in `offchain/src/aegis/config.py` | Operator-readability | ~5 minutes | NO — runtime field is empty default |
| 6 | VR3.1-F — Pin witness output to canonical `auth_witness_validator_hash` in MintWitness | Closes pre-existing bricking-attack class | ~1 hour Aiken + 1 negative test + redeploy | NO — pre-existing; bricking only, no funds at risk; v8.1 scope |
| 7 | VR3.1-G — Add multi-policy RotateAuth rejection test | Locks in Δ6 regression guard against RotateAuth | ~5 minutes | NO — covered transitively by Δ6 tests |

**No mainnet ship-blockers.** All findings are LOW or INFO. v3.1's Δ31-Δ40 closures are solid against the explicit attack classes and most lateral pivots.

---

## Phase 4 deploy-readiness verdict

**PROCEED — with the post-mainnet hardening list above tracked for v8.0.1.**

Rationale:
1. **v3 closures (Δ18-Δ30) verified solid in the previous round.** Out of scope for re-attack.
2. **v3.1 closures (Δ31-Δ40) verified solid against direct re-attack across 24 candidate vectors.** No exploitable findings.
3. **No CRITICAL / HIGH / MEDIUM findings.** 2 LOW + 5 INFO. The two LOW findings are:
   - VR3.1-A — Defense-in-depth gap in the frontend privacy guard. Bounded by (a) chain-side 14-field binding catching every payload-deception attack, (b) wallet-seed unlock requiring user consent at a deeper layer, (c) the call-site `confirmedSummary` gate still working for code that goes through the public surface. The bypass requires a malicious or sloppy developer to write `import * as` or `await import(...)` outside the boundary AND obtain the user's seed — a high bar for the attack.
   - VR3.1-B — Test-coverage asymmetry between RotateAuth (5 of 14 field negatives) and ClaimWithAuth (14 of 14). The validator code is symmetric; future regressions would not be caught by RotateAuth-specific tests but would still be caught by code review and by ClaimWithAuth's tests under integration-with-rotation flows.

4. **Cross-stack tests:** Aiken 385/385 pass; Python 341/341 pass; TS 301/301 pass; cross-stack 21 (Python) + 24 (TS) all pass. Spot-checked 6 named v3.1 tests by line number — all exist where reported.

5. **Deploy gates working:** the `check_deploy_constants.py` script correctly fails on the current placeholder state (intentional — must mint and pin before mainnet tag); the `check_aegis_privacy_boundary.cjs` script reports 0 breaches on the current frontend (no developer has cut through the static-import surface).

The two LOW findings should be tracked as v8.0.1 hardening but do not block the v3.1 → mainnet preprod redeploy. Pre-mainnet (final) ship gate: confirm Phase-4 deploy populates `auth_witness_nft_policy_id` with a real value and that the deploy runbook executes the `enterprise_addr_header` flip from `#"60"` → `#"61"` for the mainnet build.

---

## Methodology

1. **Reading audit:** `PHASE3_VERIFICATION_REDTEAM.md` (priors), §0 / §1.4 / §1.5 / §1.6 / §11 / §12.1 of `RELAY_PRESIGNED_AUTH_SCOPE_v2.md`, full `auth_witness.ak` (150 lines), full `auth_witness_nft.ak` (378 lines), `policy.ak` lines 60-1020 (focus on RotateAuth + ClaimWithAuth), `v8_integration_tests.ak` lines 393-1930 (mirrors + section 4.1 tests), `invalid_payload_vectors.json` (15 vectors), `frontend/src/wallet/aegis/index.ts`, `frontend/scripts/check_aegis_privacy_boundary.cjs`, `aegis-contracts/scripts/check_deploy_constants.py`, `.github/workflows/deploy-gates.yml`.

2. **Test runs:**
   - `aiken check` — 385/385 pass, 0 fail, 0 warning (verified via JSON output `grep -cE "\"status\": \"pass\""`).
   - `pytest tests/test_cross_stack_validation.py -v` — 21/21 pass.
   - `vitest run src/wallet/aegis/__tests__/cross_stack_validation.test.ts` — 24/24 pass.
   - `pytest tests/` (full offchain) — 341/341 pass.
   - `vitest run` (full frontend) — 301/301 pass.
   - `node scripts/check_aegis_privacy_boundary.cjs --self-test` — 9/9 pass.
   - `python scripts/check_deploy_constants.py --self-test` — 6/6 pass.
   - `python scripts/check_deploy_constants.py` (against current types.ak) — FAILS as expected on placeholder (intentional pre-deploy state).

3. **Per-Δ adversarial probes (24 vectors):**
   - Δ31: 5 probes (redeemer not_after=0 attempt, forge witness datum, reference-input lookup, multiple-input collision, future-time-frame consensus bypass).
   - Δ32: 7 probes (two RotateAuth same tx, RotateAuth+ClaimWithAuth same tx, RotateAuth+Cancel same tx, wrong-script new witness, mint-qty-nonzero, insured-pkh-mismatch, un-rotate via second RotateAuth).
   - Δ33: 4 probes (field-by-field tampering, canonical bypass, cross-policy binding, sig replay).
   - Δ34: 1 probe (canonical re-encode at witness UTxO output's payload_cbor).
   - Δ35: 1 probe (test-coverage walk).
   - Δ36: 1 probe (substitution justification).
   - Δ37: 4 probes (negative, exact-24h, 24h+1ms, BigInt wraparound, RotateAuth symmetry).
   - Δ38: 4 probes (wildcard imports, dynamic imports, named alias, JSDoc reference).
   - Δ39+Δ40: 4 probes (all-ones placeholder, mainnet-header drift, additional-constant typo, network-coupling).

4. **Live red-team probe:** wrote synthetic TS files to `src/_red_team_probe_tmp/` exercising the wildcard + dynamic-import bypass; ran `check_aegis_privacy_boundary.cjs`; verified the script reports 0 breaches on bypass attempts. Cleaned up the probe directory.

5. **Spot-check of named tests:** verified 6 v3.1 test names exist at the reported line numbers (`it_sweep_burn_rejects_redeemer_not_after_zero_for_live_payload`, `it_rotate_auth_green_path_no_op_a_via_respend`, `it_rotate_auth_rejects_two_witness_outputs`, `it_mint_witness_rejects_non_canonical_payload`, `it_rotate_auth_post_rotation_claim_with_auth_succeeds`, `it_claim_with_auth_rejects_oracle_freshness_above_24h_cap`).

6. **Stale-hash audit:** searched `D:/aegis-contracts/`, `D:/aegis/offchain/src/`, `D:/aegis/frontend/src/` for old hashes (`532740d2`, `54280b3f`, `c5c3a3df`, `a3b3a3a3`); found only docstring drift in `offchain/src/aegis/config.py` (line 109-110) and historical references in audit reports. No live runtime references.

The audit was sized to find any v3.1-introduced bug. Findings: 0 CRITICAL / 0 HIGH / 0 MEDIUM / 2 LOW (defense-in-depth + coverage asymmetry) / 5 INFO (documentation, naming, pre-existing pre-flag). I am confident no funds-drain, full-relay-DoS, or relay-bricking class survives Δ31-Δ40 against the explicit attack surfaces.

— Phase 3 Verification Red-Team v3.1, 2026-05-06
