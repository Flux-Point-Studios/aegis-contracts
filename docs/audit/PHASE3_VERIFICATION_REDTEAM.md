# Phase 3 Verification Red-Team — Aegis v8 Δ18-Δ30 Closure Audit

**Auditor angle:** Black-hat verification red-team. Three implementation agents closed 2 CRITICAL + 4 HIGH + ~15 MED/LOW findings via "v3 deltas" Δ18-Δ30. Mandate: try to break the closures and find the *new* bug each fix introduced.
**Date:** 2026-05-06.
**Build under review:** `D:/aegis-contracts/contracts` (aiken check green; 305+53 tests pass), `D:/aegis/offchain` (16 cross-stack tests pass), `D:/aegis/frontend` (133 vitest tests pass, including 19 cross-stack-validation).
**Scope:** §12 / Δ18-Δ30 of `RELAY_PRESIGNED_AUTH_SCOPE_v2.md`. Files: `auth_witness_nft.ak`, `policy.ak`, `pool.ak`, `types.ak`, `v8_integration_tests.ak`, `auth_payload.{py,ts}`, `sign_auth.ts`, `AuthSummaryConfirmModal.tsx`, `PoliciesPanel.tsx`.

---

## Executive Summary

**13 v3 deltas reviewed; 10 closures confirmed solid; 3 leak material gaps that are open against the v3 build.** No new CRITICAL or funds-drain vulnerabilities introduced. The most severe new gap is **VR-001 (HIGH): SweepBurn's `not_after` is a redeemer-supplied integer with no on-chain binding to the witness UTxO's actual `payload.not_after` — an honest operator with a buggy script (or a compromised operator key) can destroy live witnesses for any policy at any time, bricking the relay-presigned-auth path. The on-chain validator's `tx_lower > not_after` check is trivially satisfied with `not_after = 0`.** The next material gap is **VR-002 (HIGH): the RotateAuth flow as designed creates two on-chain UTxOs sharing the same NFT asset_name — the new mint plus the un-burned old witness — which immediately fails the Δ7 `length(witnesses) == 1` count gate in ClaimWithAuth.** The spec acknowledges the "2 UTxOs co-exist" state and proposes the sweeper closes within ~24h, but the implemented `SweepBurn` requires `tx_lower > not_after` (post-policy-expiry), not "post-rotation+24h" — so the orphan CANNOT be swept until policy expiry, which is far past the claim window. The third is **VR-003 (MED): RotateAuth lacks the Δ20 14-field binding AND the Δ22 canonical-CBOR re-encode check on the new witness's payload — a malicious frontend can cause the user's CIP-30 sig to authorize a rotation to a non-canonical witness or one with attacker-tampered fields, bricking later ClaimWithAuth.**

The Δ18 / V-001 closure (drop `init_utxo_ref` consumption per-mint) is solid — the 4-parameter compiled hash provides per-deployment uniqueness and Underwrite/RotateAuth path checks bind the mint to a legitimate policy. The Δ19 / V-002 closure (BurnViaConsume requires policy co-spend) is solid against third-party griefing — but the SweepBurn variant has the unbound `not_after` issue noted above. The Δ20 / V-007 / A-A-002 14-field binding is solid in ClaimWithAuth — every field is bound, including the redundant policy_id and insured_pkh. The Δ21 / V-003 BatchUnderwrite anchor wiring is solid — the 2-byte batch_index salt makes single vs batch preimages distinct (80 vs 82 bytes) and per-output anchors ensure unique policy_ids. The Δ22 / A-A-003 canonical-CBOR re-encode is solid in ClaimWithAuth, but missing in the auth_witness_nft.MintWitness branch and the policy.RotateAuth branch (see VR-003). The Δ23 53-test integration suite is solid in coverage of the redeemer happy paths and the listed negatives, but several adversarial paths are not exercised (see VR-005). The Δ24 / V-009 network_tag whitelist is solid. The Δ25 / V-010 actual_rotation gate is solid against literal no-op (commit-equality), though a 1-bit flip-and-burn is technically not blocked — but requires the user's own CIP-30 sig, so it's self-grief. The Δ26-Δ28 cross-stack validation parity is solid for the 10 manifest vectors, but the manifest doesn't cover all length checks (5 hash fields lack negative vectors — see VR-006). The Δ29 manual-claim button reuses the Δ9-bound v6.0.2 Claim path — chain-side defense holds even on UI-spoof attempts. The Δ30 confirmedSummary call-site enforcement is solid for callers that go through `signAuthCommitment`, but trivially bypassable by direct calls to lower-level primitives (see VR-007).

### Severity tally

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 5 |
| LOW | 4 |
| INFO | 2 |
| **Total** | **13** |

### Findings table

| ID | Severity | Title | Δ-against | Status |
|---|---|---|---|---|
| **VR-001** | **HIGH** | `SweepBurn.not_after` is a redeemer-supplied int with no on-chain binding to the witness's actual payload.not_after — operator can sweep any live witness with `not_after = 0` | Δ19 / V-008 closure leaky | OPEN |
| **VR-002** | **HIGH** | RotateAuth creates 2 UTxOs sharing the same auth_witness_nft asset_name (old + new); ClaimWithAuth's Δ7 `length(witnesses) == 1` then fails until the orphan is swept — but `SweepBurn` requires `tx_lower > not_after` (post-expiry), so the orphan cannot be swept while the policy is still claimable | Δ7 + Δ19 interaction | OPEN |
| **VR-003** | **MED** | RotateAuth's new-witness binding is weaker than ClaimWithAuth's: no canonical CBOR re-encode (Δ22), no 14-field payload binding (Δ20), no Ed25519 sig verify on the new payload — a malicious frontend can poison the new witness so future ClaimWithAuth fails | Δ20 + Δ22 not applied to RotateAuth | OPEN |
| **VR-004** | **MED** | `auth_witness_nft.MintWitness` lacks the Δ22 canonical CBOR re-encode check — non-canonical bytes pass mint-time, then fail at ClaimWithAuth (self-DoS for the user, but creates a footgun where buggy encoders silently mint un-claimable witnesses) | Δ22 not applied to MintWitness | OPEN |
| **VR-005** | **MED** | The 53 v8 integration tests don't exercise the full RotateAuth tx context (only the `actual_rotation` gate in isolation) — VR-002 and VR-003 would have been caught by 2 mid-sized integration tests | Δ23 incomplete | OPEN |
| **VR-006** | **MED** | The cross-stack invalid-payload manifest covers 10 rules, but 5 hash-field length checks (policy_id, oracle_nft, payout_address, pool_script_hash, pool_nft) lack negative vectors — drift in either stack on those fields would not be caught | Δ28 incomplete | OPEN |
| VR-007 | LOW | Δ30 `confirmedSummary` enforcement is voluntary at the call site — `encodeAuthCoveragePayload`, `commitmentHash`, and `signAsync` are exported separately and can be composed without going through `signAuthCommitment` | Δ30 trust-boundary | OPEN |
| VR-008 | LOW | `oracle_freshness >= 0` (Δ20) is a weak on-chain bound — the field accepts any non-negative BigInt; the 24h sanity cap is enforced off-chain only (in Python and TS), so a Python relay or bypassed-validation tool can sign payloads with `oracle_freshness = 999_999_999_999` ms (~285 years) and the validator accepts | Δ20 weak field-bound | OPEN |
| VR-009 | LOW | `auth_witness_nft_policy_id` constant in `types.ak` is still the all-zero placeholder `#"00…00"`. Without a CI-gate test asserting non-placeholder, an operator could ship a build whose ClaimWithAuth + RotateAuth paths silently never match any witness | A-A-006 / V-004 | OPEN |
| VR-010 | LOW | `BatchUnderwrite` policy outputs are anchored by `(underwrite_anchor, batch_index)` where batch_index is the order of policy outputs in the tx; off-chain builders MUST mirror this order exactly, and a builder bug producing differently-ordered policy outputs would silently mint unclaimable policies (the validator's `derive_policy_id_batch` mismatch would reject) | Δ21 builder-fragility | INFO |
| VR-011 | INFO | Δ25 `actual_rotation` blocks `old == new` strict equality but not 1-bit-flip griefing — however, this requires the user's CIP-30 main-wallet sig and is therefore self-inflicted (already documented as Phase 3 RT-A's wontfix class) | Δ25 not exhaustive | INFO |
| VR-012 | LOW | `enterprise_addr_header` constant in `types.ak` is hardcoded to testnet `#"60"`. Mainnet build requires manual flip to `#"61"`; absent CI-gate, a wrong constant would silently mismatch every `payload.payout_address` check on chain | Δ9 deploy-gate | OPEN |
| VR-013 | LOW | `must_be_signed_by` only checks `list.has(extra_signatories, pkh)` — verified correct; SweepBurn uses this against `operator_pkh` which is a compile-time constant (currently `aegis_self_publisher_vkh`). No ABI-shadowing or name-collision concerns observed. (Spot-check confirming `extra_signatories` is the correct list, not `inputs.has_signature`.) | — | NOT A BUG |

---

## Per-finding detail

### VR-001 — HIGH — `SweepBurn.not_after` is unbound to the witness's actual payload field

**Threat model:** Operator key compromise OR honest operator with a buggy script. Operator has unilateral authority to destroy any auth_witness UTxO at any time, even for live policies whose claim window is still open.

**Files:** `D:/aegis-contracts/contracts/validators/auth_witness_nft.ak` lines 302-328.

**Evidence:**
```aiken
SweepBurn { policy_id, not_after } -> {
  ...
  let signed_by_operator =
    must_be_signed_by(extra_signatories, operator_pkh)
  let tx_lower = get_lower_bound(validity_range)
  let auth_window_elapsed = tx_lower > not_after
  ...
  signed_by_operator && auth_window_elapsed && burn_one && only_one_under_policy && network_tag_ok
}
```

The `not_after` is a **redeemer field** the operator supplies. The validator's only check is `tx_lower > not_after`. The operator can pass `not_after = 0`, making the check trivially satisfied by any current-time tx (`tx_lower > 0` for any modern POSIX timestamp). There is **no on-chain binding** between the redeemer's `not_after` and the witness UTxO's actual payload's `not_after`.

**Repro:**
1. Alice has policy P with payload.not_after = 2030 (5 years in future). Witness UTxO W_P exists at auth_witness_validator.
2. Operator key compromise. Attacker controlling the operator key signs:
   - Inputs: [W_P, attacker_collateral]
   - Mint: `-1 of (auth_witness_nft, blake2b_224(P.policy_id))`
   - Mint redeemer: `SweepBurn { policy_id: P.policy_id, not_after: 0 }`
   - extra_signatories: [operator_pkh]
   - validity_range: lower = current_time
3. Validator: `signed_by_operator = True` (operator sig present), `auth_window_elapsed = current_time > 0 = True`, `burn_one = True`, `only_one_under_policy = True`, `network_tag_ok = True`. **Validator passes.**
4. W_P is destroyed. Alice's relay-presigned-auth path is permanently bricked for policy P. (She can still RotateAuth — but VR-002 shows that's also broken.)

**Impact:** Operator-initiated DoS on the entire relay-presigned-auth feature. Damage scales with the operator key's blast radius.

**Why this matters:** The Δ19/V-008 closure narrative says "tx_validity.lower_bound > payload.not_after so orphan cleanup cannot run before the auth window has provably elapsed." But the implementation reads the `not_after` from the *redeemer*, not from the witness's *payload*. The redeemer is operator-controlled. The defense reduces to "trust the operator," which is exactly the trust assumption the v3 spec was supposed to relax (per Δ15: "Sweeper requires operator-only authorization").

The spec text is ambiguous: §1.5's `SweepBurn` reads "tx_validity.lower_bound > not_after" (treating `not_after` as a parameter). Δ19's narrative says "the policy's expiry as bound at sig time in the auth payload" — which suggests it should be bound to the witness's payload, not the redeemer.

**Suggested fix:** SweepBurn must FETCH `not_after` from the witness UTxO's datum, not from the redeemer. The witness UTxO has the canonical `payload_cbor` containing `not_after`. The validator should:
1. Find the spent witness UTxO (it's a script input via auth_witness_validator).
2. Decode `awd.payload_cbor` → AuthCoveragePayload.
3. Bind `tx_lower > payload.not_after`.

```aiken
SweepBurn { policy_id } -> {
  // Find the witness UTxO being spent (input at auth_witness_validator with
  // matching asset name).
  expect Some(witness_input) =
    list.find(inputs, fn(i) {
      let q = assets.quantity_of(i.output.value, own_policy_id, blake2b_224(policy_id))
      q == 1
    })
  expect InlineDatum(raw_w) = witness_input.output.datum
  expect awd: AuthWitnessDatum = raw_w
  expect Some(payload_data) = cbor.deserialise(awd.payload_cbor)
  expect payload: AuthCoveragePayload = payload_data
  // Now bind to the on-chain payload field.
  let tx_lower = get_lower_bound(validity_range)
  let auth_window_elapsed = tx_lower > payload.not_after
  ...
}
```

The redeemer's `not_after` field can be dropped entirely (or kept as a redundant redeemer-attested value for builder convenience).

**Severity rationale:** HIGH — operator-key compromise is a real threat model (per memory's `aegis_operator_pkh` is the same as `aegis_self_publisher_vkh`, so a publisher-key compromise is a SweepBurn compromise too). Funds are not directly drained — but the headline v8 feature (relay-presigned-auth) is bricked. Severity is bounded by the manual-claim fallback (Δ29) which still works.

---

### VR-002 — HIGH — RotateAuth creates 2 NFT UTxOs sharing one asset_name, breaking ClaimWithAuth's Δ7 count==1 gate

**Threat model:** Honest user calls RotateAuth (legitimate use case: rotated Aegis seed, suspected key leak). Result: ClaimWithAuth is bricked for the policy's remaining lifetime.

**Files:** `D:/aegis-contracts/contracts/validators/auth_witness_nft.ak` (mint validator's MintWitness has no on-chain visibility into the OLD witness lingering at auth_witness_validator); `D:/aegis-contracts/contracts/validators/policy.ak` lines 642-644 (collect_witnesses count==1 check).

**Evidence:** RELAY_PRESIGNED_AUTH_SCOPE_v2.md §5 and §8:
> §5: mint: 1× new auth_witness_nft (same asset name = blake2b_224(policy_id))
> §8 invariants table: ON-CHAIN there can be 2 UTxOs with the same NFT after rotation — hence Δ7 (`length(witnesses) == 1`) is load-bearing here too. Sweeper closes the second witness within ~24h.

But `SweepBurn`'s on-chain check is `tx_lower > not_after`, where `not_after` is the policy's expiry — typically 30+ days out. The sweeper CANNOT sweep the orphan within 24h while the policy is still claimable.

**Repro:**
1. Alice underwrites policy P at T=0 with not_after = T+30d. Witness W_old created.
2. Alice calls RotateAuth at T=5d. New witness W_new minted (same asset_name as W_old). W_old is not burned.
3. From T=5d onward: 2 UTxOs at auth_witness_validator with asset_name = blake2b_224(P.policy_id).
4. T=10d: oracle goes below strike. Alice tries ClaimWithAuth. `collect_witnesses` finds 2 witnesses → `exactly_one_witness = (2 == 1) = False`. **Validator rejects.**
5. T=15d: Alice tries again. Same result.
6. T=30d: policy expires. Now `tx_lower > not_after` could fire SweepBurn — but ClaimWithAuth's `within_expiry = tx_upper <= datum.expiry_time` also fails. Claim window closed.

Until T=30d, Alice's only recourse is the v6.0.2 manual Claim path (Δ29 fallback) — which works because it doesn't touch witnesses. **But the relay-presigned-auth path is dead for the entire post-rotation period.**

**Impact:** RotateAuth is supposed to be the recovery mechanism for compromised keys. After legitimate RotateAuth, the user's relay-auth path is bricked for the rest of the policy's lifetime. This makes RotateAuth a destructive operation rather than a recovery one. Honest users who don't realize this will lose the relay-claim safety net silently.

The spec acknowledges the "2 UTxOs co-exist" state and asserts the sweeper resolves within 24h. The implementation does not support this — `SweepBurn` requires `tx_lower > not_after` (redeemer-supplied; per VR-001 unbound), so the operator could sweep the orphan within 24h ONLY by passing `not_after = 0`, which is the VR-001 attack class. **The honest closure of VR-002 thus depends on the existence of VR-001.** Two wrongs do not make a right — both findings need fixing together.

**Suggested fix:** ANY of these would close the gap:

(a) Atomic burn at RotateAuth: extend the RotateAuth flow to ALSO burn the old witness in the same tx. This requires:
- The old witness's BurnViaConsume redeemer in the same tx — but the auth_witness_nft mint policy can only have ONE redeemer per tx. Solution: bundle BOTH +1 mint AND -1 burn under MintWitness, with the validator updated to accept this shape.
- OR: route the RotateAuth flow through a NEW redeemer variant that does mint+burn atomically.

(b) Burn-on-RotateAuth via mint policy: extend `MintWitness` to allow `mint_qty = 0` (i.e., +1 - 1 = 0 net). Then the same redeemer mints the new and burns the old. The mint validator checks: `quantity_of(mint, ...) == 0` AND `policy is being consumed (RotateAuth path)`. Validator must also assert there's a +1 entry AND a -1 entry under the same asset_name in `mint`. Aiken's `mint` value can carry multiple entries.

(c) Allow SweepBurn on rotation orphans: bind SweepBurn's `not_after` to the witness's actual payload's not_after (per VR-001), AND add a new redeemer variant `SweepRotationOrphan { policy_id }` that requires the orphan's witness UTxO have a payload that does NOT match the current policy datum's `auth_commitment`. The orphan's `commit_from_cbor(awd.payload_cbor) != datum.auth_commitment` is the on-chain proof of "stale commit" — the new witness's payload hashes to the current commit, the old witness's hashes to the previous commit.

(d) Strict 2-tx rotation flow with cooldown: forbid RotateAuth until the previous witness is burned. Requires the user to do 2 txs (BurnOldWitness via Cancel-and-Re-Underwrite OR a dedicated kill-old-witness tx, then RotateAuth). UX-wise unattractive.

Option (c) is the minimal-deviation fix and aligns with the spec's "sweeper closes the second within 24h" narrative. The 24h is then enforced off-chain (operator runbook) but the on-chain validator can prove "this is an orphan, not a live witness" via the commit-mismatch.

**Severity rationale:** HIGH — bricks the headline v8 feature for any user who legitimately rotates. Manual fallback exists (Δ29), so funds are not at risk; but the entire relay-presigned-auth value proposition collapses post-rotation until policy expiry.

---

### VR-003 — MED — RotateAuth's new-witness binding is weaker than ClaimWithAuth's

**Threat model:** Malicious frontend (CIP-30 wallet MITM, browser extension, or compromised React build). User connects CIP-30 main wallet to authorize a RotateAuth. Frontend constructs the new witness with attacker-controlled fields. User signs the tx body via CIP-30. Validator accepts the rotation.

**Files:** `D:/aegis-contracts/contracts/validators/policy.ak` lines 579-659 (RotateAuth branch) — compare to lines 420-571 (ClaimWithAuth branch).

**Evidence:** RotateAuth's new-witness check (lines 642-652):
```aiken
let (new_witness_count, new_witness_opt) =
  collect_witnesses(reference_inputs, datum.policy_id)
let exactly_one_new_witness = new_witness_count == 1
expect Some(new_witness) = new_witness_opt
let witness_ref_attested =
  new_witness.output_reference == new_witness_ref
expect InlineDatum(raw_new_w) = new_witness.output.datum
expect new_awd: AuthWitnessDatum = raw_new_w
let new_witness_policy_id_ok = new_awd.policy_id == datum.policy_id
let new_witness_commit_ok =
  commit_from_cbor(new_awd.payload_cbor) == new_commit
```

Notice what is **NOT** checked:
- The 14-field payload binding (Δ20 only applies to ClaimWithAuth, not RotateAuth).
- The canonical CBOR re-encode-and-compare (Δ22 only applies to ClaimWithAuth).
- The Ed25519 signature on the new witness's payload — the false-positive 11 in PHASE3_REDTEAM_A_CRYPTO_CBOR.md acknowledges this and says "the next ClaimWithAuth is the binding check."

Combined: a malicious frontend can:
1. Construct a new payload with `payload.payout_address = ATTACKER_ADDRESS` (different from datum.insured's enterprise address).
2. Encode it (canonical or non-canonical).
3. Build the RotateAuth tx with the new witness containing this payload + a junk Ed25519 sig.
4. User signs the tx body via CIP-30 (no Aegis-wallet sig needed for RotateAuth).
5. Validator: `commit_from_cbor(new_awd.payload_cbor) == new_commit` — passes (since new_commit is just the BLAKE2b hash of whatever the attacker put in payload_cbor).
6. Validator: `new_witness_policy_id_ok = new_awd.policy_id == datum.policy_id` — passes.
7. Validator passes.

At later ClaimWithAuth:
- The validator decodes the new witness's payload.
- `payload.payout_address == enterprise_addr_of(datum.insured)` — **FAILS** because payload.payout_address is ATTACKER_ADDRESS.

**Result:** ClaimWithAuth fails. The relay-auth path is bricked for this policy. **No funds are stolen** because A-009 and Δ9 still bind on-chain payout to insured's PKH at claim time. But the user paid for a malicious rotation that destroyed their relay-claim path.

The user can still:
- Use the manual Claim fallback (Δ29) — works.
- Re-rotate to a clean witness — but VR-002 is then in play (multiple orphan witnesses).

**Impact:** Griefing class. A malicious frontend or extension MITM destroys the user's relay-auth path via a deceptive rotation. No theft, but a real degradation of the v8 value proposition.

**Suggested fix:** Apply Δ20 + Δ22 inside RotateAuth as well. After decoding `new_awd.payload_cbor → payload`, add:
- `payload_canonical_ok = cbor.serialise(payload) == new_awd.payload_cbor`
- The full 14-field binding chain (domain_tag, network_magic, policy_validator, policy_id, insured_pkh, payout_address, max_coverage, oracle_provider, oracle_nft, oracle_freshness, not_before, not_after, pool_script_hash, pool_nft) against datum + active-network constants.
- `verify_signature(new_awd.insured_vkey, new_commit, new_awd.signature)` — verify the new sig at rotate time too. The witness datum carries the sig; if the user's Aegis wallet signed it, this passes. If the frontend constructed a junk sig, this fails. Closes the "wallet doesn't sign new commit" gap.

The extra cost is ~1 cbor.serialise + 14 equality checks + 1 Ed25519 verify, all cheap.

**Severity rationale:** MEDIUM — requires a malicious frontend (not just an honest-but-buggy one), and the funds are not at risk (just the relay-auth path).

---

### VR-004 — MED — `auth_witness_nft.MintWitness` lacks the Δ22 canonical-CBOR re-encode check

**Threat model:** Buggy off-chain encoder (or attacker tooling) produces non-canonical CBOR. Mint succeeds. User cannot later claim.

**Files:** `D:/aegis-contracts/contracts/validators/auth_witness_nft.ak` lines 159-256.

**Evidence:** The MintWitness branch decodes `payload_cbor` via `cbor.deserialise`. It does NOT then re-serialize and compare to the input bytes. So a payload with non-canonical CBOR (e.g., non-shortest-form ints, indefinite-length bytestrings, etc.) passes the mint validator IF its decoded shape matches the underwrite_path/rotate_auth_path checks.

**Repro:**
1. Buggy Python encoder produces `payload_cbor` with `oracle_provider` encoded as `0x18 0x00` instead of `0x00` (non-shortest-form 1-byte uint header for value 0). The decoded payload has oracle_provider = 0 (Charli3); the encoded bytes are 1 byte longer than canonical.
2. User submits Underwrite with this payload. Mint validator decodes → `oracle_provider = 0`. Underwrite path checks: `pdat.policy_id == policy_id` ✓, `pdat.auth_commitment == Some(commit)` where commit = BLAKE2b(non-canonical bytes) ✓, `payload.oracle_provider == oracle_provider_to_int(pdat.oracle_provider) = 0` ✓.
3. Mint succeeds. Witness UTxO created with non-canonical `payload_cbor`.
4. Later, ClaimWithAuth: `payload_canonical_ok = cbor.serialise(payload) == awd.payload_cbor` — **FAILS** because canonical form differs from the non-canonical input.

**Impact:** Self-DoS. The user's policy is unclaimable via ClaimWithAuth. The user can still cancel/expire/manual-claim. No funds at risk.

**Why this is worth fixing:** A buggy or rushed cross-stack encoder (e.g., a 3rd-party Python tool, a CIP-30 wallet implementing its own canonical encoder) could silently produce un-claimable policies. The user would underwrite, see the witness on chain, and only at first claim attempt discover the bug. **Pre-mint validation closes the surface earlier.**

**Suggested fix:** Add the Δ22 check to MintWitness as well:
```aiken
expect Some(payload_data) = cbor.deserialise(payload_cbor)
expect payload: AuthCoveragePayload = payload_data
+ // Δ22 mirror: canonical re-encode check at mint time so a non-canonical
+ // witness cannot be created in the first place. Closes a subtle UX
+ // footgun where a 3rd-party encoder produces witnesses that pass mint
+ // but fail claim.
+ let payload_canonical = cbor.serialise(payload)
+ let payload_canonical_ok = payload_canonical == payload_cbor
let commit = commit_from_cbor(payload_cbor)
...
```

Add to both `underwrite_path_valid` and `rotate_auth_path_valid` chains, OR add to the top-level && of the redeemer.

**Severity rationale:** MEDIUM — UX footgun, not a security issue. But for the v8 mainnet ship, every layer of cross-stack defense matters.

---

### VR-005 — MED — 53-test integration suite (Δ23) lacks full RotateAuth tx context coverage

**Threat model:** Coverage gap. VR-002 and VR-003 would have been caught by 2-3 mid-sized integration tests.

**Files:** `D:/aegis-contracts/contracts/lib/aegis/test_helpers/v8_integration_tests.ak`.

**Evidence:** Section 4 (RotateAuth, lines 1036-1080) has 5 tests, but ALL of them only exercise the `actual_rotation` gate (Δ25) in isolation. There are no tests that:
- Build a full RotateAuth Transaction with a new witness as a reference input AND an old witness still on chain.
- Test the post-rotation ClaimWithAuth with 2 witnesses present (would expose VR-002).
- Test RotateAuth with a tampered new payload (would expose VR-003).
- Test SweepBurn against a live witness with `redeemer.not_after = 0` (would expose VR-001).

The mirror helper for RotateAuth (`mirror_rotate_auth_actual_rotation`, line 433) is a 5-line function that only checks the commit-equality. There's no mirror for the full RotateAuth invariant chain.

**Suggested fix:** Add the missing integration tests:

1. `test it_rotate_auth_post_rotation_two_witnesses_breaks_claim()` — build a Transaction with policy + 2 witness reference inputs (old + new, both with same asset_name), and assert collect_witnesses count == 2 → ClaimWithAuth mirror returns False. (Closes VR-002 via test.)
2. `test it_sweep_burn_rejects_redeemer_not_after_zero_for_live_payload()` — build a SweepBurn tx with redeemer.not_after=0 against a witness whose payload.not_after is in the future, assert validator rejects. (This test would fail with the current implementation per VR-001 — the test exposing the bug.)
3. `test it_rotate_auth_rejects_tampered_new_payload_payout_addr()` — build a RotateAuth tx with new_awd.payload_cbor's payout_address mutated, assert RotateAuth mirror returns False. (Currently passes — exposes VR-003.)

Without these, the v3 "53 integration tests" gate doesn't actually cover the v3 attack surface adequately.

**Severity rationale:** MEDIUM — coverage gap, not a chain bug. But it's the proximate cause of VR-001/VR-002/VR-003 reaching this audit gate.

---

### VR-006 — MED — Cross-stack invalid-payload manifest covers 10 of ~15 expected validation rules

**Threat model:** Drift in either Python or TS encoder on a length check that's not in the manifest.

**Files:** `D:/aegis-contracts/contracts/tests/fixtures/invalid_payload_vectors.json`; tests at `D:/aegis/offchain/tests/test_cross_stack_validation.py` and `D:/aegis/frontend/src/wallet/aegis/__tests__/cross_stack_validation.test.ts`.

**Evidence:** The manifest has 10 vectors covering domain_tag length, network_magic, policy_validator length, insured_pkh length, payout_body match, max_coverage floor and cap, oracle_provider, time_window, oracle_freshness cap. **It does NOT cover negative cases for:**
- `policy_id` length mismatch (28 bytes expected; nothing in the manifest tests 27 or 29)
- `oracle_nft` length mismatch
- `payout_address` length mismatch (only header byte and body bytes tested via Δ9, but not "the whole field is 28 bytes instead of 29")
- `pool_script_hash` length mismatch
- `pool_nft` length mismatch
- payout_address header byte vs network_magic mismatch (the rule is enforced in `assertPayoutHeaderForNetwork`, but not in the manifest)
- `oracle_provider` of -1 (negative; Python `_assert_constr_idx` would catch via `_VALID_ORACLE_PROVIDERS` set check, but not in the manifest)
- `oracle_freshness` negative (Python rejects via `_assert_non_neg_int`, but not in the manifest)

**Suggested fix:** Add at least 5 more vectors to the manifest covering each remaining length check. The TS and Python tests will then assert byte-for-byte parity on all enforced rules.

**Severity rationale:** MEDIUM — drift detection is the whole point of Δ28. Incomplete coverage means a silent divergence can ship.

---

### VR-007 — LOW — Δ30 `confirmedSummary` enforcement is voluntary at the call site

**Threat model:** A direct call to lower-level primitives bypasses the Δ30 summary check.

**Files:** `D:/aegis/frontend/src/wallet/aegis/sign_auth.ts` exports `signAuthCommitment`; the same file (and `auth_payload.ts`) export `encodeAuthCoveragePayload`, `commitmentHash`, and the file's `import { signAsync } from '@noble/ed25519'` is at the top of the file. A caller can replicate `signAuthCommitment`'s body without the summary check:

```typescript
import { signAsync } from '@noble/ed25519';
import { encodeAuthCoveragePayload, commitmentHash } from './auth_payload';
const cbor = encodeAuthCoveragePayload(payload);
const commit = commitmentHash(cbor);
const sig = await signAsync(commit, privateKey);
// No summary check — Δ30 bypassed.
```

**Repro:** A malicious React component or browser extension that injects code into the BuyPanel could bypass `signAuthCommitment` entirely. The user's Aegis wallet seed is the only thing protecting against this — and that's a separate concern.

**Why this is LOW:** The Δ30 enforcement is one layer of a multi-layer defense. The on-chain validator's 14-field binding (Δ20) catches every field-deception attack. The off-chain summary is a UX defense, not a cryptographic one. A bypass produces a valid signature, which the validator either accepts (if the payload is honest) or rejects (if the payload is malformed).

**Suggested fix:** Convert `signAuthCommitment` into the only export path. Make `encodeAuthCoveragePayload`, `commitmentHash`, and `signAsync` "internal" (not re-exported from the package's public surface). This is a packaging discipline, not a code change. ALTERNATIVELY: gate `signAsync` behind a wrapper that requires the same summary check. ALTERNATIVELY: add a lint rule that flags direct `signAsync` imports outside `sign_auth.ts`.

**Severity rationale:** LOW — defense-in-depth gap, no exploit if the on-chain validator catches all field-deception attacks (which Δ20 does).

---

### VR-008 — LOW — `oracle_freshness >= 0` is a weak on-chain bound

**Threat model:** Attacker tooling that produces signed payloads bypassing off-chain validation.

**Files:** `D:/aegis-contracts/contracts/validators/policy.ak` line 496 (`payload_oracle_freshness_ok = payload.oracle_freshness >= 0`).

**Evidence:** The off-chain Python and TS encoders cap `oracle_freshness` at 24 hours (86_400_000 ms) and 2^63-1. The on-chain validator only checks `>= 0`. So a Python `encode_auth_coverage_payload_canonical` (no validation) call OR a hand-crafted CBOR can produce signed payloads with `oracle_freshness = 999_999_999_999` (276 years) that the validator accepts.

**Why it doesn't directly enable an exploit:** The wallet-prompt summary (Δ30) shows `oracle_freshness` as ms in the modal. An attentive user notices a wildly large value. But A-A-007's class (UI-deception) reaches: the value shown in the modal must equal what's encoded — and Δ30 enforces this. So if the user sees `oracle_freshness: 999999999999 ms` and clicks Sign, it's their choice.

**Suggested fix:** Bind a 24h cap on chain too:
```aiken
let payload_oracle_freshness_ok =
  payload.oracle_freshness >= 0 && payload.oracle_freshness <= 86_400_000
```

Or drop `oracle_freshness` from the payload entirely (it's advisory; advisory data shouldn't be in the signed commit).

**Severity rationale:** LOW — no funds at risk, no UI deception (Δ30 closes that), just a weaker cross-stack symmetry.

---

### VR-009 — LOW — `auth_witness_nft_policy_id` placeholder is the all-zero hash

**Threat model:** Operator deploys to mainnet without updating the placeholder. ClaimWithAuth and RotateAuth silently never match any witness UTxO. Feature is dead-on-arrival.

**Files:** `D:/aegis-contracts/contracts/lib/aegis/types.ak` lines 615-617.

**Evidence:**
```aiken
pub const auth_witness_nft_policy_id: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000"
```

A 28-byte all-zero policy id requires finding a script S such that `blake2b_224(S) == #"00…00"` — a 224-bit second-preimage attack. Infeasible. So no real token can ever exist under this policy id, and `assets.quantity_of(value, #"00…00", _)` always returns 0. **`collect_witnesses` always returns count==0 for every policy.**

This was flagged as A-A-006 (LOW) in the Phase 3 Red-Team A report. It's still open in the v3 build.

**Why this matters more than A-A-006 implied:** A CI-gate test asserting `auth_witness_nft_policy_id != #"00…00"` would catch this at build time. Without it, the mainnet deploy could ship the placeholder and the bug would only surface at the first ClaimWithAuth attempt (silent fail, fail-closed).

**Suggested fix:** Add to `lib/aegis/test_helpers/v8_integration_tests.ak`:
```aiken
test deploy_gate_auth_witness_nft_policy_id_is_not_placeholder() {
  // Hard fails until the operator runs the auth_witness_nft mint deploy
  // and updates the constant in types.ak.
  auth_witness_nft_policy_id != #"00000000000000000000000000000000000000000000000000000000"
}
```

This test FAILS in the current build. Once fixed, it acts as a regression guard.

**Severity rationale:** LOW — pre-deploy hazard, fail-closed behavior at runtime.

---

### VR-010 — INFO — BatchUnderwrite anchor = `(underwrite_anchor, batch_index)` is order-fragile

**Threat model:** Off-chain builder bug that orders policy outputs differently than the validator iterates them.

**Files:** `D:/aegis-contracts/contracts/validators/pool.ak` lines 84-182.

**Evidence:** The validator's `batch_policies_match_totals` folds across `outputs` in tx-output-list order, incrementing `batch_idx` ONLY for outputs that match the policy_validator hash with valid datum. Off-chain builders MUST mirror this order exactly when computing each policy's `derive_policy_id_batch(..., batch_idx)`.

If the builder produces policy outputs in a different order than the validator iterates, the policy_ids won't match the validator's expected derivations → validator rejects → user pays a tx fee for nothing.

**Why it's INFO not LOW:** Cardano's tx body output order is preserved through the chain. An honest builder controls order. A bug in a 3rd-party builder is a bug, not a security finding. The validator's logic is correct.

**Suggested fix:** Document the ordering contract in the BatchUnderwrite redeemer doc string. Add a builder-side test that verifies a 2-policy batch produces matching policy_ids.

**Severity rationale:** INFO — builder-fragility, not a chain vulnerability.

---

### VR-011 — INFO — Δ25 `actual_rotation` doesn't block 1-bit-flip griefing

**Threat model:** Already documented in PHASE3_REDTEAM_A as a wontfix class — requires the user's CIP-30 main-wallet sig and is therefore self-grief.

**Files:** `D:/aegis-contracts/contracts/validators/policy.ak` lines 599-603.

**Evidence:**
```aiken
let actual_rotation =
  when datum.auth_commitment is {
    Some(old) -> old != new_commit
    None -> True
  }
```

A 1-bit flip in `new_commit` is technically `old != new_commit` (different value) → `actual_rotation = True` → validator passes. But the new witness must hash to the new_commit, so the attacker would need to produce a witness with payload that hashes to the 1-bit-flipped commit. This is a different payload (since BLAKE2b is preimage-resistant). So the attacker would have a different "real" rotation, not a 1-bit-flip-of-existing.

**Why this is not a real attack:** Requires the user's CIP-30 main-wallet sig. If the user signs, it's a real rotation. The validator's invariant is correct.

**Severity rationale:** INFO — not exploitable as described.

---

### VR-012 — LOW — `enterprise_addr_header` mainnet flip is a deploy-time concern

**Threat model:** Mainnet deploy ships with `#"60"` (testnet) header, all `payout_address` checks fail.

**Files:** `D:/aegis-contracts/contracts/lib/aegis/types.ak` line 656.

**Evidence:** `pub const enterprise_addr_header: ByteArray = #"60"`. Mainnet build must flip to `#"61"`. Without a CI-gate, an operator could ship the wrong constant, and every `payload.payout_address == enterprise_addr_of(datum.insured)` check on chain would fail.

**Suggested fix:** Add a deploy-gate test:
```aiken
test deploy_gate_enterprise_addr_header_matches_network_magic() {
  // Pin the relationship between active-build constants. Mainnet build
  // (network_magic = 764824073) MUST have header = 0x61; testnet builds
  // (1 / 2) MUST have 0x60.
  if network_magic == 764_824_073 {
    enterprise_addr_header == #"61"
  } else {
    enterprise_addr_header == #"60"
  }
}
```

**Severity rationale:** LOW — deploy-time hazard, fail-closed at runtime.

---

### VR-013 — NOT A BUG — `must_be_signed_by` is correct

**Investigation:** SweepBurn uses `must_be_signed_by(extra_signatories, operator_pkh)`, where `extra_signatories` is the tx's required-signers list (a Plutus-level field, not derivable from inputs). This is the correct API; the validator does NOT mistakenly check `inputs.has_pubkey_hash`. Verified via `validation.ak` line 22-27.

**Marked as NOT A BUG** for completeness — this was on the prompt's mandate to verify.

---

## Closures verified solid

These v3 deltas were attacked along multiple axes and held up:

### Δ18 (V-001 MintWitness no-longer-one-shot) — verified solid

- The `init_utxo_ref` parameter is consumed only at compile-time (parameter-baking into the validator hash). The runtime check is removed.
- Mint quantity check: `exactly_one_minted = (mint_qty == 1)` — quantity > 1 fails, quantity = 0 fails, quantity < 0 fails (negative would be a burn, which would be a different redeemer).
- Asset-name binding: `expected_asset_name = blake2b_224(redeemer.policy_id)` is computed in Aiken and used to query the mint field. Strict equality.
- `only_one_under_policy = list.length(dict.to_pairs(assets.tokens(mint, own_policy_id))) == 1` — multiple asset names under same policy in one tx fails.
- New `operator_pkh` parameter affects the compiled validator hash (per-deployment uniqueness). Cross-network reuse would produce a different policy_id, so any cross-network sig replay attempt would also need to recompute the policy_id, which is bound to the v8 spec at sign time.
- Cannot mint a witness for a policy you don't own — Underwrite path requires fresh policy output at policy_validator_hash with matching policy_id; RotateAuth path requires policy input at policy_validator_hash. Both bind the mint to a legitimate policy operation.

**Tested by:** `it_mint_witness_underwrite_green_path`, `it_mint_witness_post_init_ref_spent_still_succeeds` (the regression test for V-001), `it_mint_witness_rejects_two_tokens_minted`, `it_mint_witness_rejects_no_policy_output`, `it_mint_witness_rejects_payload_policy_id_mismatch`, `it_mint_witness_rejects_invalid_network_tag`, `it_mint_witness_rotate_path_via_input_consumed`, `it_mint_witness_rejects_provider_mismatch`.

### Δ19 (V-002 BurnWitness split into BurnViaConsume) — verified solid (BurnViaConsume only; SweepBurn has VR-001)

- BurnViaConsume requires the matching policy UTxO to be co-spent. Verified: `policy_consumed_in_tx = list.any(inputs, ...)` checks for input at `policy_validator_hash` with matching `policy_id`.
- Cross-policy attempt: attacker spends their own policy A and tries to burn victim's witness for policy B — `policy_consumed_in_tx` walks inputs looking for policy_B_id. Only finds policy_A_id. **False.** Burn fails.
- Same tx multi-redeemer attack: only one redeemer per mint policy. BurnViaConsume + SweepBurn combo is impossible.
- Mint quantity exactly -1, only one (asset_name, qty) pair. Both checked.

### Δ20 (V-007 14-field binding in ClaimWithAuth) — verified solid

- All 14 fields explicitly bound: domain_tag, network_magic, policy_validator, policy_id, insured_pkh, payout_address, max_coverage, oracle_provider, oracle_nft, oracle_freshness (≥0), not_before, not_after, pool_script_hash, pool_nft.
- `own_script_hash` retrieved correctly from `self_input.output.address.payment_credential` — matches the running validator's hash.
- Each binding is a strict equality (except oracle_freshness which is `>= 0` per spec — see VR-008 for the weakness analysis).
- The integration tests cover one mismatch per field (14 negative tests), each asserting the mirror returns False.

### Δ21 (V-003 BatchUnderwrite policy_id) — verified solid

- `derive_policy_id_batch` includes a 2-byte big-endian batch_index salt → 82-byte preimage (vs single-Underwrite's 80-byte). BLAKE2b-224 outputs are distinct (preimage-distinct + collision-resistance).
- Per-output anchor: each batch output gets `(underwrite_anchor, i)` where i is 0-based position. Validator's fold tracks `batch_idx` correctly, advancing only for policy_validator-address outputs.
- Two batches with same anchor are impossible (each batch consumes a fresh pool UTxO with distinct OutputReference).
- BatchUnderwrite + single Underwrite combined: impossible (only one pool input per tx).

### Δ22 (A-A-003 canonical CBOR re-encode) — verified solid in ClaimWithAuth

- The check `cbor.serialise(payload) == awd.payload_cbor` runs after `cbor.deserialise + AuthCoveragePayload coercion` succeed.
- Trailing-byte attack: `cbor.deserialise` rejects trailing bytes (consumed!=0 → None). `expect Some(_) = cbor.deserialise(_)` aborts.
- Non-shortest-form ints, indefinite-length bytestrings: `cbor.deserialise` accepts, but `cbor.serialise(payload)` produces canonical bytes; `canonical != non-canonical` → check fails.
- Constr index: `expect AuthCoveragePayload = data` rejects non-Constr-0 shapes (Aiken's runtime type-coercion).

NOTE: Δ22 is missing in MintWitness (VR-004) and RotateAuth (VR-003).

### Δ23 (V-005 53 integration tests) — partially solid, with VR-005 gap

The 53 tests cover the green paths and per-field negative cases for ClaimWithAuth's 14-field binding, MintWitness path validity, BurnViaConsume policy co-spend, SweepBurn operator sig + window-elapsed, and BatchUnderwrite policy_id derivation properties. They do NOT cover full RotateAuth tx context (only the actual_rotation gate in isolation) — see VR-005.

### Δ24 (V-009 network_tag whitelist) — verified solid

- Strict equality against three pinned constants: `network_tag_preprod`, `network_tag_preview`, `network_tag_mainnet` (UTF-8 bytes).
- 1-byte typo (e.g., `#"00"`): rejected (not equal to any of the 3 constants).
- Length-2 typo (e.g., `#"00\x00"`): rejected (different length than any constant).
- Applied to MintWitness, BurnViaConsume, SweepBurn — all three paths.
- Cross-deployment attack: an attacker's auth_witness_nft policy parameterized with a different network_tag would produce a different policy_id (because network_tag is in the parameter set). The canonical `auth_witness_nft_policy_id` constant would not match the attacker's, so policy.ak's `collect_witnesses` filters them out.

### Δ25 (V-010 no-op rotation rejection) — verified solid

- `actual_rotation = old != new_commit` for `Some(old)`; `True` for `None`.
- Strict commit-equality check: the user cannot submit RotateAuth with `new_commit == old_commit`.
- 1-bit flip griefing: not blocked, but requires the user's own CIP-30 sig (self-grief, see VR-011 INFO).
- Rotating to a commit without a witness: validator rejects (collect_witnesses count != 1, or commit_from_cbor != new_commit).

### Δ26-Δ28 (cross-stack validation parity) — verified solid for the 10 manifest vectors

- Both Python and TS encoders reject every entry in the manifest with a matching error pattern.
- Boundary value 2^63-1: accepted by both. 2^63: rejected by both.
- 24h freshness boundary: accepted at 24h, rejected above.
- 5 ADA coverage floor: accepted at 5 ADA, rejected at 1 lovelace.

NOTE: 5 length-check rules are missing from the manifest (VR-006).

### Δ29 (RT-C-02 manual-claim button) — verified solid

- Button visible only on non-terminal policies; disabled for non-claimable + non-connected wallet.
- The handler calls `onManualClaim(p.id)`, which routes to the parent's existing v6.0.2 Claim path. That path uses the user's CIP-30 wallet for signing — chain-side `signed_by_insured` (via `extra_signatories`) is the gate. An attacker clicking on someone else's policy in a UI-spoof scenario cannot sign as the insured.
- Race condition with relay auto-claim: Cardano UTxO model is the lock — first tx to consume the policy wins. The losing tx is rejected with `UtxoAlreadySpent`. **Defense holds.**

### Δ30 (call-site enforcement of summary) — verified solid for callers via `signAuthCommitment`

- `signAuthCommitment(payload, key, network, confirmedSummary, options?)` re-derives `humanReadableSummary` and string-compares.
- Mismatch throws → no signature produced.
- The summary includes ALL 14 fields including `oracle_freshness` (closes A-A-007).
- The `options.payoutAddressBech32` parameter must be the same value used when rendering the modal (otherwise the equality check fails).
- The `AuthSummaryConfirmModal` has explicit "I understand — sign this authorization" / Cancel buttons; cancel via Escape key or button click; the close button is disabled during `busy` state.

NOTE: bypassable via direct calls to lower-level primitives (VR-007) — defense-in-depth gap, not exploit.

---

## Top fixes by impact

| # | Finding | Impact | Effort |
|---|---|---|---|
| **1** | **VR-001** — Bind SweepBurn's `not_after` to the witness's actual payload.not_after | Closes operator-key-compromise full-relay-DoS class | ~1 day Aiken + 1 negative test |
| **2** | **VR-002** — Atomically burn old witness at RotateAuth (or add a `SweepRotationOrphan` redeemer that proves stale-commit on chain) | Closes the post-rotation ClaimWithAuth-bricked window for honest users | ~1-2 days Aiken + redeemer/spec coordination + tests |
| **3** | **VR-003** — Apply Δ20 + Δ22 to RotateAuth's new-witness binding chain | Closes the malicious-frontend rotation-poison class | ~half day Aiken + 3 negative tests |
| **4** | **VR-004** — Apply Δ22 canonical CBOR check to MintWitness | Closes the buggy-encoder unclaimable-witness footgun | ~1 hour Aiken + 1 negative test |
| **5** | **VR-009** — Add deploy-gate test asserting `auth_witness_nft_policy_id != #"00…00"` | Catches the placeholder ship-hazard at build time | ~5 minutes |
| **6** | **VR-006** — Extend invalid-payload manifest with 5 missing length rules | Closes cross-stack drift detection on those fields | ~2 hours JSON + tests |
| **7** | **VR-005** — Add the 3 missing integration tests (rotation+claim, sweep-with-not-after-zero, rotation+tampered-payload) | Captures VR-001/VR-002/VR-003 in CI for regression | ~half day Aiken |

After these seven fixes, the v3 surface is mainnet-ready. VR-007 (Δ30 enforcement boundary), VR-008 (oracle_freshness weak bound), VR-010 (BatchUnderwrite ordering doc), VR-011 (1-bit flip INFO), VR-012 (mainnet header flip CI gate) can ship as v8.0.1 hardening.

---

## Methodology summary

1. **Reading audit:** All three Phase 3 red-team reports, RELAY_PRESIGNED_AUTH_SCOPE_v2.md (v3 spec), and every implementation file listed in the prompt.
2. **Test runs:** `aiken check` (305+53 tests pass; 0 failures, 0 warnings); `pytest tests/test_cross_stack_validation.py` (16 pass); `vitest src/wallet/aegis/__tests__` (133 pass including 19 cross-stack).
3. **Per-Δ adversarial probe:** For each closed finding, constructed at least 3 attack shapes:
   - Direct: try the OLD attack against the new code.
   - Lateral: shift the attack to an adjacent code path (e.g., V-002 → SweepBurn variant via VR-001).
   - Cross-cut: combine deltas (e.g., RotateAuth + ClaimWithAuth two-witness scenario → VR-002).
4. **Test-coverage audit:** Read `v8_integration_tests.ak` line-by-line, categorized each of the 53 tests by (delta, redeemer, +/-), found the gaps in VR-005.
5. **Cross-stack vector audit:** Read the manifest schema and counted enforced rules in Python (`_assert_payload_shape`) and TS (`assertPayloadShape` + `assertNetworkConsistency` + `assertPayoutHeaderForNetwork`); compared against the 10 manifest vectors → VR-006.
6. **Spec-vs-implementation diff:** For Δ19 specifically, the spec says "tx_validity.lower_bound > payload.not_after" (witness-bound) but the implementation reads `not_after` from the redeemer → VR-001.

The audit was sized to "find ANY remaining gap"; the findings above are the union of (provably exploitable) and (theoretically exploitable but mitigated by other layers) and (defense-in-depth gap that should be closed). I am confident no CRITICAL or funds-drain class survives Δ18-Δ30. I am confident VR-001 + VR-002 are real, must-fix-before-mainnet finds.

— Phase 3 Verification Red-Team, 2026-05-06
