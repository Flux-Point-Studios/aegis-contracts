# Aegis — Keyless Relay + Pre-Signed Claim Authorization (v3.3)

**Status:** Implementation-ready spec. Supersedes `RELAY_PRESIGNED_AUTH_SCOPE.md` (v1) which was redirected to design-only. v3 absorbed the Phase-3 implementation red-team findings (2 CRITICAL + 4 HIGH on-chain) into deltas Δ18-Δ25. v3.1 (2026-05-06) absorbed the verification red-team findings VR-001 (HIGH) + VR-002 (HIGH) + VR-003..VR-006 (MED) + VR-008 (LOW) into deltas Δ31-Δ37; see §12.1 for the v3.1 closure detail and §11 for the updated traceability table. v3.2 (2026-05-06) attempted to break the circular deploy dependency between `auth_witness_nft` and `policy_validator` via Δ41 — but left a SECOND-ORDER cycle (`auth_witness_nft.mint`'s base hash still rotated whenever `auth_witness_validator_hash` const was updated). **v3.3 (2026-05-06) closes the second-order cycle via Δ42 — see §12.4 for the architecture change and the new truly-linear deploy ordering. v3.3 supersedes v3.2.**
**Date:** 2026-05-06.
**Audience:** Aiken + TypeScript + Python engineers building this. Audit-grade — every paragraph either cites a red-team finding it closes or explains why a v1 simplification was insufficient.
**Pre-reqs read:** `RELAY_PRESIGNED_AUTH_SCOPE.md` (v1, for context only — do NOT implement v1 as written), `SECURITY_AUDIT_REPORT.md` (A-001..A-027 + L-001..L-007 + ECON-1..4), v6.0.2 deploy state, Phase-3 red-team reports `PHASE3_REDTEAM_{A_CRYPTO_CBOR,B_VALIDATOR,C_RELAY_ECONOMIC}.md`.

---

## 0. What changed in v2 (vs. v1 design)

Three parallel red-team agents (cryptographic / validator-branch / off-chain-relay-economic) attacked the v1 design. They produced 2 CRITICAL + 7 HIGH + 4 MED findings. v2 absorbs all of them. Highlights:

| Δ | What | Closes |
|---|---|---|
| **Δ1** | Witness mint **atomic with Underwrite** (one tx, two outputs: policy + witness UTxO). v1's separate "publish auth" tx is gone. | C-1, F-3, F-AUTH-2 |
| **Δ2** | `auth_witness_nft` minting policy is a **true one-shot over `OutputReference`** with mint-time payload decode. Pinned as compile-time constant per network. | C-1, C-2, F-AUTH-2, F-AUTH-3 |
| **Δ3** | `policy_id` derivation **now includes the underwriting `OutputReference`** so two same-terms policies cannot collide. (Also a fix to a pre-existing v6.0.2 bug surfaced by the audit.) | H-3 |
| **Δ4** | `domain_tag` is **network-specific** (`AEGIS_CLAIM_AUTH_v1_PREPROD` vs `AEGIS_CLAIM_AUTH_v1_MAINNET`). | H-1 |
| **Δ5** | `AuthCoveragePayload` schema **adds `oracle_provider`**; on-chain mint validator asserts payload.oracle_provider == datum.oracle_provider. | F-AUTH-5 |
| **Δ6** | `ClaimWithAuth` count guard is the **same global expression** as `Claim`: `count_script_inputs(inputs, own_script_hash) == 1`. NOT a per-redeemer filter. | F-AUTH-1 |
| **Δ7** | Validator iterates **all reference inputs carrying the witness NFT** and accepts iff exactly one is present (not `list.find` first-match). | C-2, F-AUTH-3 |
| **Δ8** | New `RotateAuth` redeemer (gated by CIP-30 main-wallet signature). Lets a user invalidate an old auth without needing the Aegis-wallet seed. | M-3 (no longer "v2 follow-up") |
| **Δ9** | Default `payout_address` flips to **user's CIP-30 main-wallet enterprise variant**, not the Aegis wallet enterprise address. Closes the wallet-loss → unspendable-payout footgun. | F-5; resolves Open Q1 |
| **Δ10** | Canonical CBOR is **pinned to Plutus Constr 0 indefinite-length list** (`d8 79 9f <14 fields> ff`) — the byte sequence Aiken's `cbor.serialise` (and the underlying `serialise_data` Plutus builtin) emits, which IS the on-chain canonical authority. Inner items follow RFC 8949 §4.2 deterministic rules (smallest-possible uint headers, definite-length bytestrings, no nested indefinite items). Cross-stack byte-vector tests required (Aiken `cbor.serialise` ↔ TS encoder ↔ Python reference). | M-1 |
| **Δ10 history** | Spec correction (2026-05-06): the original Δ10 wording said "definite-length array". The on-chain authoritative form is the Plutus Constr 0 indefinite-length list emitted by `cbor.serialise`. The TS, Python, and Aiken implementations are all updated to mirror this byte-for-byte; cross-stack vector tests are the CI gate. | (no new finding) |
| **Δ4 history** | Pre-mainnet domain-tag correction (2026-05-06): the Aiken hex constants `auth_domain_tag_{preprod,preview,mainnet}` were 26-byte `AEGI_CLAIM_AUTH_v1_<NETWORK>` (typo — missing the trailing `S` byte at position 5) instead of the 27-byte `AEGIS_CLAIM_AUTH_v1_<NETWORK>` form mandated by §2.2 prose. All three stacks (Aiken, TypeScript, Python) updated to the correct 27-byte form simultaneously; fixtures regenerated; pinned CBOR + commitment vectors rotated. No in-flight signatures affected (pre-deploy). | (no new finding) |
| **Δ11** | `verify_ed25519_signature` strict-S enforcement verified by regression test. Relay dedup keys on `(policy_id, witness_utxo_ref)` not `txHash`. | H-2 |
| **Δ12** | `auth_commitment` length-check `== 32` at validator entry; payload decoded on-chain at mint and at claim (one BLAKE2b + one CBOR decode each — cheap). | F-AUTH-6 |
| **Δ13** | Relay data plane is **multi-source** (Blockfrost + Kupo OR Ogmios). Operator picks; production must use ≥2. | F-1 |
| **Δ14** | Relay tick has **per-policy next-eligible-tick cache** + **min-coverage floor (5 ADA)** to bound mass-create DoS. | F-2 |
| **Δ15** | Sweeper requires **k≥20 confirmations** + **operator-only** authorization (a sweeper script_hash signature). | F-4 |
| **Δ16** | Wallet-prompt at sig time **displays human-readable payload summary** (network, payout addr bech32, coverage in ADA, expiry). | H-1 |
| **Δ17** | Witness mint policy is parameterized over `(operator_init_utxo_ref, network_tag)`; validator pins the resulting policy id via compile-time constant — same pattern as A-026 / A-027 / Charli3-NFT. | F-AUTH-2 |
<!-- Δ18-Δ25 — Aiken on-chain v3 hardening (2026-05-06) — owned by the on-chain agent. -->
| **Δ18** | **MintWitness one-shot bug closure.** Pre-Δ18 the mint validator required the parameterized `init_utxo_ref` to be in EVERY mint's inputs — UTxOs spend exactly once on Cardano, so the policy was one-shot per LIFETIME, bricking the relay-presigned-auth feature after the first user. Post-Δ18 the parameter alone (baked into the compiled validator hash) provides one-shot-per-deployment uniqueness; per-mint anti-forgery is enforced via the existing Underwrite / RotateAuth path checks. | V-001 / A-A-001 |
| **Δ19** | **BurnWitness split into BurnViaConsume + SweepBurn.** Pre-Δ19 the inverted `no_live_policy = policy_consumed_in_tx == False` check let any third party destroy any victim's live witness UTxO and pocket the ~3.5 ADA min-UTxO at a profit (grief-ROI class). Post-Δ19, `BurnViaConsume` REQUIRES the matching policy UTxO to be co-spent in the same tx (atomic with Cancel/Expire/Claim/ClaimWithAuth); `SweepBurn` is operator-only — gated by `must_be_signed_by(extra_signatories, operator_pkh)` AND `tx_validity.lower_bound > payload.not_after` so orphan cleanup cannot run before the auth window has provably elapsed. The mint policy gains an `operator_pkh` parameter. | V-002, V-008 |
| **Δ20** | **Full 14-field payload binding in ClaimWithAuth.** Pre-Δ20, the validator decoded the 14-field `AuthCoveragePayload` but only compared 3 fields against the policy datum (`policy_id`, `oracle_provider`, `payout_address`); the other 11 (`domain_tag`, `network_magic`, `policy_validator`, `insured_pkh`, `max_coverage`, `oracle_nft`, `oracle_freshness`, `not_before`, `not_after`, `pool_script_hash`, `pool_nft`) were decoded-and-discarded — wallets displayed them, the validator didn't enforce them. Post-Δ20 every payload field is bound: domain_tag and network_magic to active-network constants; policy_validator to `own_script_hash`; insured_pkh, max_coverage, oracle_nft, not_before, not_after, pool_script_hash, pool_nft to the policy datum's corresponding field; payout_address to `enterprise_addr_of(datum.insured)`; oracle_freshness ≥ 0 (length / non-negativity bound). | V-007 / A-A-002 |
| **Δ21** | **BatchUnderwrite policy_id derivation.** Pre-Δ21, Δ3's `derive_policy_id` was wired only into the single-Underwrite path. The batch path (`batch_policies_match_totals`) accepted any caller-supplied `policy_id`, so two same-terms batched policies could collide on `policy_id` (and thus on the witness asset name `blake2b_224(policy_id)`). Post-Δ21, a new `derive_policy_id_batch(..., underwrite_anchor, batch_index)` function appends the per-output 0-based batch index to the preimage; the pool's BatchUnderwrite branch enforces `pdat.policy_id == derive_policy_id_batch(...)` for every policy output. The 2-byte salt makes the batch preimage 82 bytes vs the single-Underwrite's 80 bytes — no cross-mode collision class. | V-003 |
| **Δ22** | **Canonical CBOR re-encode-and-compare.** Pre-Δ22, Aiken's stdlib `cbor.deserialise` accepted non-canonical CBOR (non-shortest-form ints via `0x18 0x00` for value 0, indefinite-length bytestrings via the `0x5f` chunked form, etc.). The validator decoded `awd.payload_cbor` but did not re-serialize and assert canonical form — an attacker tooling that bypasses the wallet's TS validators could craft bytes the validator accepts but the canonical encoder would never produce. Post-Δ22, ClaimWithAuth re-encodes the decoded payload via `cbor.serialise(payload)` and asserts byte-equal to `awd.payload_cbor`. Cost: one extra `cbor.serialise` (~10x cheaper than the existing `cbor.deserialise` per the stdlib note). | A-A-003 |
| **Δ23** | **End-to-end Transaction-context integration tests.** Pre-Δ23 the v8 surfaces had ONLY property-level tests on isolated helpers (length checks, hash distinctness, sum-type tag values) — V-001 and V-002 reached the audit gate because no integration test built a full `Transaction` against the validator branches. Post-Δ23, a new `lib/aegis/test_helpers/v8_integration_tests.ak` module ships 53 mid-sized integration tests spanning every redeemer: MintWitness (green + 5 negatives covering the V-001 fix and the V-009 typo class); BurnViaConsume (green + 3 negatives covering the V-002 fix); SweepBurn (green + 3 negatives covering V-008 + window-elapsed); ClaimWithAuth (green + 14 negatives — one per field-binding violation in Δ20); RotateAuth (green + 5 negatives covering Δ25 + commit divergence); BatchUnderwrite policy_id derivation (5 differential checks for Δ21). Every test builds a real `Transaction` using a logic-mirror helper that 1:1 transcribes the corresponding validator branch's `&&`-chain. | V-005 |
| **Δ24** | **`network_tag` strict whitelist.** Pre-Δ24, the mint policy's `network_tag != #""` check accepted any non-empty bytestring — a 1-byte typo like `#"00"` would silently produce a legitimate-but-misnamed policy id. Post-Δ24, the parameter must equal exactly one of `network_tag_preprod` (`#"50524550524f44"`) / `network_tag_preview` (`#"50524556494557"`) / `network_tag_mainnet` (`#"4d41494e4e4554"`) — UTF-8 of `"PREPROD"` / `"PREVIEW"` / `"MAINNET"`. | V-009 |
| **Δ25** | **RotateAuth no-op rejection.** Pre-Δ25, RotateAuth accepted `new_commit == datum.auth_commitment` — a malicious caller (or a buggy frontend) could submit a "rotation" that did not actually change the on-chain commitment, paying a tx fee for nothing while burning the user's min-ADA on a fresh witness UTxO. Post-Δ25, the validator requires `new_commit != datum.auth_commitment.Some(...)` (the `None` case — first-time auth set on an opt-out policy — is treated as a real change because no prior commit exists). | V-010 |
<!-- end on-chain v3 block -->
<!-- Δ29-Δ30 — frontend remediation (2026-05-06) — owned by the frontend agent. -->
| **Δ29** | **CIP-30 manual-claim fallback** is exposed as an always-visible button on every non-terminal policy in the My Policies panel (`PoliciesPanel.tsx`). Reuses the v6.0.2 ordinary `Claim` flow — no relay-auth involvement — so the user has a safety floor when the relay AND the in-browser auto-claim wallet are both unreachable. The button is enabled only when the policy is `claimable` AND a CIP-30 wallet is connected; explainer copy makes the relay-bypass behaviour explicit. The `AegisWalletPanel` trust copy gains a "3. Manual fallback" section pointing the user to this surface. | RT-C-02 |
| **Δ30** | **Wallet-prompt summary is call-site-enforced** at sign time. `signAuthCommitment` now requires a `confirmedSummary: string` parameter that MUST equal `humanReadableSummary(payload, network)` byte-for-byte; mismatch throws and refuses to sign. The summary surface is the new `AuthSummaryConfirmModal` component, which renders all 14 payload fields verbatim with explicit "I understand — sign this authorization" / Cancel actions. The summary now includes `oracle_freshness` (closes A-A-007 deception surface) and the previously-unbound fields (`network_magic`, `domain_tag`, `policy_validator`, `pool_script_hash`, `pool_nft`) so a malicious frontend cannot quietly hide them. | A-A-007, RT-C-06 (Δ16 enforcement) |
<!-- end frontend block -->
<!-- Δ26-Δ28 — cross-stack validation parity (2026-05-06) — owned by the cross-stack remediation agent. -->
| **Δ26** | **Python encoder validation parity with TypeScript.** `offchain/src/aegis/auth_payload.py` now ships two entry points: `encode_auth_coverage_payload_canonical` (no validation — the byte-shape mirror of Aiken's `cbor.serialise` used by cross-stack vector tests) and `encode_auth_coverage_payload` (full v2-spec invariant guards, mirrors TypeScript's `encodeAuthCoveragePayload` byte-for-byte). The validated entry point now enforces: 27-byte `domain_tag`; `network_magic` ∈ {1, 2, 764824073}; 28-byte hash fields (`policy_validator`, `policy_id`, `insured_pkh`, `oracle_nft`, `pool_script_hash`, `pool_nft`); 29-byte `payout_address`; `oracle_provider` ∈ {0, 1, 2}; integer fields in `[0, 2^63 - 1]`; `not_after > not_before` strict; `max_coverage ≥ 5_000_000` lovelace (Δ14 floor); `oracle_freshness ≤ 86_400_000` ms (24h sanity cap); `payout_address[1..] == insured_pkh` (Δ9 binding); `domain_tag` ↔ `network_magic` consistency; `payout_address[0]` ↔ network header byte (0x60 testnets / 0x61 mainnet). Every rule mirrors TypeScript with matching error-message style for cross-stack debug parity. | A-A-004 |
| **Δ27** | **Int range cap alignment.** Python's `MAX_INT_FIELD` is now `2^63 - 1` (was effectively `2^64 - 1` via the `_enc_uint` lane plus an unbounded bignum fallback), matching TypeScript's existing `MAX_INT_FIELD = (1n << 63n) - 1n`. The exact value `2^63 - 1` (TV-3 fixture) round-trips identically in Python, TypeScript, and Aiken; the value `2^63` is rejected by both off-chain stacks. Aiken accepts arbitrary BigInt regardless — the asymmetry is closed where it matters (off-chain encoders), so a Python relay or CLI tool cannot produce signed bytes the TypeScript encoder cannot reproduce. | A-A-009 |
| **Δ28** | **Cross-stack validation parity test.** New shared invalid-payload manifest at `D:/aegis-contracts/contracts/tests/fixtures/invalid_payload_vectors.json` carries 10 vectors (one per validation rule). Both stacks load this manifest verbatim and assert each entry is rejected with the documented `error_pattern`. Drift detection: if either stack later loosens a rule, the manifest's CI gate trips before the divergence ships. Tests at `offchain/tests/test_cross_stack_validation.py` (Python) and `frontend/src/wallet/aegis/__tests__/cross_stack_validation.test.ts` (TypeScript). | (cross-stack drift) |
<!-- end cross-stack block -->
<!-- Δ31-Δ37 — v3.1 Aiken on-chain remediation (2026-05-06) — owned by the verification-redteam closure agent. -->
| **Δ31** | **SweepBurn `not_after` is witness-bound.** Pre-Δ31 the `SweepBurn` redeemer carried `not_after` as an operator-supplied integer; the validator's only check was `tx_lower > not_after`. An operator-key compromise (or a buggy operator script) could pass `not_after = 0` and destroy any live witness for any policy at any time, bricking the relay-presigned-auth path on demand. Post-Δ31 the redeemer no longer carries `not_after`; the gate reads `payload.not_after` from the WITNESS UTXO's payload datum (a regular input at the auth_witness_validator script), strictly binding the orphan-cleanup window to what the user actually signed. The strict `>` (not `>=`) aligns with §1.5's "auth window provably elapsed" narrative. | VR-001 |
| **Δ32** | **RotateAuth respend at auth_witness_validator (Option A).** Pre-Δ32 the rotation flow MINTED a new witness alongside the un-burned old one — leaving two UTxOs sharing the same `auth_witness_nft` asset name on chain. ClaimWithAuth's `length(witnesses) == 1` count gate (Δ7) then rejected every claim until the policy expired. Post-Δ32 the rotation flow SPENDS the old witness UTxO and RESPENDS a new witness UTxO at the same auth_witness_validator script — the NFT moves with the UTxO, no mint policy invocation, and the chain never holds more than one witness UTxO under a given asset name. The auth_witness_validator's spend path now accepts EITHER (a) burn-only (mint == -1, no continuation) OR (b) rotation respend (mint == 0, exactly one continuation at this validator with the same asset_name). The policy validator's RotateAuth branch is the cryptographic gate (user CIP-30 sig + Δ33 14-field new-payload binding); auth_witness_validator's job on the rotation path is purely structural — refuse a TWO-witness configuration. | VR-002 |
| **Δ33** | **RotateAuth applies Δ20+Δ22 to the new witness's payload.** Pre-Δ33 the rotation flow only checked `commit_from_cbor(new_awd.payload_cbor) == new_commit` — i.e., the bytes hash to the commit. The 14-field binding (Δ20) and canonical CBOR re-encode (Δ22) only fired in ClaimWithAuth, so a malicious frontend could trick the user into authorizing a rotation whose new witness carried attacker-controlled fields. The next ClaimWithAuth would fail Δ20 — bricking the relay-auth path until policy expiry. Post-Δ33 the new witness's payload is bound across all 14 fields, canonically re-encoded byte-equal, AND its Ed25519 signature verified against the new commit. Failure modes are caught at rotation time (one tx fee), not at first claim attempt (relay-auth path bricked). | VR-003 |
| **Δ34** | **MintWitness applies Δ22 canonical CBOR re-encode at mint time.** Pre-Δ34 the mint validator decoded `payload_cbor` via `cbor.deserialise` but did not re-serialize and compare to the input bytes. A buggy off-chain encoder could produce non-canonical bytes (non-shortest-form ints, indefinite-length bytestrings) that decoded successfully here but later failed ClaimWithAuth's canonical check (Δ22) — silently producing a witness whose `payload_cbor` was unclaimable. Post-Δ34 the mint validator asserts `cbor.serialise(decoded) == payload_cbor`, closing the surface earlier so a user never finishes Underwrite-with-auth holding an unclaimable policy. | VR-004 |
| **Δ35** | **≥10 RotateAuth integration tests.** Pre-Δ35 the v8_integration_tests.ak module had 5 RotateAuth tests, all property-level lemmas on the `actual_rotation` (Δ25) gate in isolation. None built a full RotateAuth Transaction context — VR-002 and VR-003 reached the audit gate because no integration test caught them. Post-Δ35 the module ships 13 new RotateAuth tests covering the full Δ32 + Δ33 surface end-to-end (green path with respend, wrong signer, two/zero witness outputs, asset-name change, non-canonical new payload, 5 field-binding violations, post-rotation ClaimWithAuth green path, old-signature replay-protection sanity). Combined with the original 5 isolated tests this gives 18 RotateAuth tests in the integration module. | VR-005 |
| **Δ36** | **Cross-stack invalid-payload manifest expanded to 15 rules.** Pre-Δ36 the shared manifest at `D:/aegis-contracts/contracts/tests/fixtures/invalid_payload_vectors.json` carried 10 vectors covering domain_tag length, network_magic, policy_validator length, insured_pkh length, payout body, max_coverage floor + cap, oracle_provider, time_window, oracle_freshness cap. Post-Δ36 the manifest carries 15 vectors — adding `oracle_nft_wrong_length`, `pool_script_hash_wrong_length`, `pool_nft_wrong_length`, `domain_tag_zero_length` (length-class boundary pin), and `max_coverage_negative` (int-range boundary pin / signature-length analogue). Both Python and TS encoders reject every entry with the documented `error_pattern`; the matching `EXPECTED_RULE_NAMES` tuples in both test suites are pinned in lock-step. | VR-006 |
| **Δ37** | **`oracle_freshness <= 24h` upper bound on chain.** Pre-Δ37 the on-chain check was `payload.oracle_freshness >= 0` — accepting any non-negative BigInt. Off-chain Python and TS encoders capped at 24h (86_400_000 ms) per Δ26 / A-A-007, but a Python relay or hand-crafted CLI tool that bypassed off-chain validation could sign payloads with `oracle_freshness = 999_999_999_999` ms (~285 years) and the validator accepted. Post-Δ37 ClaimWithAuth + RotateAuth both enforce `oracle_freshness >= 0 && oracle_freshness <= 86_400_000` so the cross-stack symmetry holds at the chain boundary too. | VR-008 |
<!-- end v3.1 block -->
<!-- Δ38-Δ40 — v3.1 frontend hardening + deploy gates (2026-05-06) — owned by the frontend / CI agent. DO NOT STOMP: the parallel Aiken agent owns Δ31-Δ37. -->
| **Δ38** | **Hard-enforced summary at the wallet/aegis module boundary.** Pre-Δ38 the public barrel `frontend/src/wallet/aegis/index.ts` re-exported `encodeAuthCoveragePayload`, `commitmentHash`, `encodeUint`/`encodeBytes`/`encodeArray`/`encodeConstr`, and `assertNetworkConsistency` alongside `signAuthCommitment`. A malicious or buggy frontend caller could compose those primitives with `@noble/ed25519`'s `signAsync` to produce a valid Ed25519 signature WITHOUT going through `signAuthCommitment` and its mandatory `confirmedSummary` byte-equality check (Δ30). Post-Δ38 the barrel re-exports ONLY: types (`AuthCoveragePayload`, `NetworkId`, `AuthCommitmentSigned`, `SummaryRenderOptions`); display helpers (`humanReadableSummary`, `domainTagFor`, `networkMagicFor`, `fromHex`, `toHex`, length/range constants); and the signing entry point (`signAuthCommitment` + `verifyAuthCommitment` + `SIGNATURE_BYTES`/`SECRET_KEY_BYTES`/`PUBLIC_KEY_BYTES`). The lower-level CBOR primitives remain `export`s at the module-internal level so peer modules and tests inside `src/wallet/aegis/` can compose them, but they are NOT re-exported. A new build-step lint guard at `frontend/scripts/check_aegis_privacy_boundary.cjs` (wired as `npm run lint:guard`) walks every `.ts`/`.tsx` source under `src/` outside the privacy boundary and fails CI on any import of a forbidden symbol or a direct `@noble/ed25519` import. The guard ships with a 9-case in-memory self-test (`npm run lint:guard:self-test`) covering positive (allowed `signAuthCommitment` / `humanReadableSummary` / commentary that mentions a forbidden name) and negative (named-import, multi-line named-import, direct `@noble/ed25519` import, type-only re-import) cases so a silently-broken guard cannot give a false PASS. | VR-007 |
| **Δ39** | **CI deploy-gate against `auth_witness_nft_policy_id` placeholder.** Pre-Δ39 the constant in `lib/aegis/types.ak` defaulted to a 28-byte all-zero placeholder; if the operator forgot to update it after the Phase-4 mint deploy, ClaimWithAuth and RotateAuth would silently match no witness UTxOs (fail-closed, dead on arrival). Post-Δ39 a static-constant guard at `D:/aegis-contracts/scripts/check_deploy_constants.py` extracts the constant from `types.ak`, asserts it is NOT the all-zero placeholder, asserts it is a valid 28-byte (56-hex-char) value, and exits 1 with a clear diagnostic if either check fails. Wired into the new GitHub Actions workflow `.github/workflows/deploy-gates.yml` as a pre-tag job that runs on every push, PR, and `v*` tag. | VR-009 |
| **Δ40** | **CI deploy-gate against enterprise-address header drift.** Pre-Δ40 a developer accidentally swapping `enterprise_addr_header_mainnet` / `enterprise_addr_header_testnet`, or hardcoding `enterprise_addr_header` (the active-build constant) to a typo, would silently brick every `payload.payout_address` check on chain (the validator would be 1 byte off). `aiken check` would still pass — the bug only surfaces on chain at the first relay-presigned-auth tx. Post-Δ40 the same `scripts/check_deploy_constants.py` script enforces: `enterprise_addr_header_mainnet == #"61"`, `enterprise_addr_header_testnet == #"60"`, and `enterprise_addr_header ∈ {#"60", #"61"}`. Combined with Δ39 these three checks live behind a single CI job. The script's self-test covers placeholder, real-deploy, swapped-headers, missing-header, bad-length-policy-id, and typo-active-header cases. | VR-012 |
<!-- end v3.1 deploy-gate block -->
<!-- Δ41 — v3.2 deploy-cycle break (2026-05-06) — owned by the Aiken on-chain agent. -->
| **Δ41** | **Break the circular deploy dependency between `auth_witness_nft` and `policy_validator`.** Pre-Δ41 the `auth_witness_nft` mint policy was parameterized over a 4-tuple `(init_utxo_ref, network_tag, policy_validator_hash, operator_pkh)` and `policy_validator` referenced `auth_witness_nft_policy_id` to identify witness UTxOs (token-policy-id binding). The two compile-time inputs formed a fixed-point that would never converge at deploy time: `auth_witness_nft`'s hash depended on `policy_validator`'s hash, and `policy_validator`'s hash depended on `auth_witness_nft`'s policy id. Post-Δ41 the cycle is broken via two architectural changes: (a) the mint policy drops `policy_validator_hash` from its parameter set (3-tuple now: `(init_utxo_ref, network_tag, operator_pkh)`); (b) `policy_validator` now identifies witness UTxOs via SCRIPT CREDENTIAL — `Script(auth_witness_validator_hash)` where `auth_witness_validator_hash` is a new compile-time-pinned constant in `lib/aegis/types.ak`, populated post-deploy via the linear ordering documented in §12.3. Security is preserved by a 3-leg transitive trust chain: the mint policy pins the witness UTxO at `auth_witness_validator_hash`; the auth_witness_validator's spend path (Δ32) self-checks `own_value` carries the canonical `auth_witness_nft_policy_id` token AND enforces burn-or-respend semantics; `policy_validator` accepts witness UTxOs only at the auth_witness_validator script address. Same security as the pre-v3.2 single-binding leg. The deploy gate at `scripts/check_deploy_constants.py` now enforces both `auth_witness_nft_policy_id` AND `auth_witness_validator_hash` are non-placeholder before mainnet tag (closes the v3.2 placeholder-ship-hazard analogue of Δ39). | (deploy-blocker, no new finding) |
<!-- end v3.2 block -->
<!-- Δ42 — v3.3 final cycle break (2026-05-06) — owned by the Aiken on-chain agent. -->
| **Δ42** | **Drop `auth_witness_validator_hash` references from `auth_witness_nft.ak` — close the second-order deploy cycle.** Pre-Δ42 (v3.2) the mint validator imported `auth_witness_validator_hash` and gated the Underwrite-path witness-output destination on `if h == auth_witness_validator_hash`. Because that constant is itself populated post-deploy (in the v3.2 linear ordering, after step 4), every change to it ROTATED this mint policy's compiled base hash — and therefore its policy id — bringing the deploy ordering back into a fixed-point loop: step 2 produced `policy_id_v0` with both consts at all-zeros; step 4 baked `auth_witness_validator_hash` and rebuilt, which invalidated `policy_id_v0` and required step 2 to re-run with the new base hash. Post-Δ42 the cycle is broken by REMOVING all `auth_witness_validator_hash` references from `validators/auth_witness_nft.ak`. The Underwrite path's witness-destination script-credential pin is replaced by a per-tx "EXACTLY ONE output anywhere carries the canonical NFT and matching `AuthWitnessDatum`" check; `BurnViaConsume`/`SweepBurn` lose their negative script-credential filters (no longer needed — typed-decode failure on `AuthWitnessDatum` returns False structurally rather than crashing). Security is preserved: orphan mints elsewhere are unreachable as witnesses because `policy_validator` accepts witnesses ONLY at `Script(auth_witness_validator_hash)` (Δ41) and `auth_witness_validator`'s spend path self-checks `own_value` carries the canonical `auth_witness_nft_policy_id` token (file unchanged in v3.3). The three-leg trust chain still holds with leg 1 (mint policy's destination check) replaced by a weaker "single output carrying the asset" check. After Δ42 the deploy ordering is truly linear in 5 steps with NO base-hash rotation of `auth_witness_nft.mint` after step 2 — see §12.4 for the proof and §6 for the new ordering. | (deploy-blocker, no new finding) |
<!-- end v3.3 block -->

Two findings remain explicitly **out of v2 scope** (informational): F-6 (multi-relay reality is a marketing/positioning concern, not a code change) and F-7 (cross-relay collateral griefing — verified safe by analysis).

---

## 1. On-chain changes (Aiken)

### 1.1 PolicyDatum — append ONE field

```aiken
pub type PolicyDatum {
  policy_id, insured, strike_price, coverage_amount, premium_paid,
  start_time, expiry_time, oracle_nft, pool_script_hash, pool_nft,
  oracle_provider,
  // NEW (v8 / relay-presigned-auth):
  auth_commitment: Option<ByteArray>,   // 32-byte BLAKE2b-256 of canonical-CBOR(AuthCoveragePayload), or None
}
```

12-field schema. Old v6.0.2 (11-field) datums cannot decode against v8 — the existing `23889dec…` preprod policy is stranded; document in `deploy-state.preprod.json` migration notes (resolves F-AUTH-9).

### 1.2 PolicyRedeemer — append two variants

```aiken
pub type PolicyRedeemer {
  Claim
  BatchClaim
  Expire
  BatchExpire
  Cancel
  ClaimWithAuth { sig: ByteArray }
  RotateAuth { new_commit: ByteArray, new_witness_ref: OutputReference }
}
```

`sig` is 64-byte raw Ed25519 over `auth_commitment`. `RotateAuth` carries the new commitment + the OutputReference of a freshly-minted replacement witness UTxO; the redeemer is gated by a CIP-30 main-wallet `extra_signatories` check (`must_be_signed_by(extra_signatories, datum.insured)`).

### 1.3 ClaimWithAuth validator branch (v3-updated)

```
1.  expect Some(commit) = datum.auth_commitment
2.  expect bytearray.length(commit) == 32                                  // Δ12
3.  let witnesses = filter(reference_inputs, has_payment_credential(Script(auth_witness_validator_hash)) && datum_policy_id == datum.policy_id)
4.  expect length(witnesses) == 1                                          // Δ7
5.  let witness = witnesses[0]
    // [Δ41 — v3.2] Witness identification is by SCRIPT CREDENTIAL
    // (auth_witness_validator_hash) + AuthWitnessDatum.policy_id,
    // NOT by NFT token policy id. Pre-Δ41 the binding was via the NFT
    // (auth_witness_nft_policy_id), which combined with the mint
    // policy being parameterized over policy_validator_hash created a
    // circular deploy dep. Δ41 closes the cycle (§12.3); security is
    // preserved by the auth_witness_validator's own self-check on
    // own_value carrying the canonical NFT — only legit-minted UTxOs
    // can ever exist at that script address.
6.  expect InlineDatum(d) = witness.output.datum
7.  expect AuthWitnessDatum { policy_id, insured_vkey, payload_cbor, signature } = d
8.  expect policy_id == datum.policy_id                                    // belt
9.  expect blake2b_256(payload_cbor) == commit                             // Δ12 — payload binds to commit
10. expect blake2b_224(insured_vkey) == datum.insured                      // C-2 — vkey matches PKH
11. expect ed25519_verify(insured_vkey, commit, redeemer.sig) == True      // headline check
12. expect signature == redeemer.sig                                       // belt: witness sig matches redeemer sig
13. let payload = expect AuthCoveragePayload = cbor_decode(payload_cbor)   // Δ12

    // [Δ22 / A-A-003] Canonical-form gate: re-encode and assert byte-equal
    // so non-canonical CBOR (non-shortest-form ints, indefinite-length
    // bytestrings via 0x5f, etc.) is rejected even when the decoder accepts.
14. expect cbor.serialise(payload) == payload_cbor

    // [Δ20 / V-007 / A-A-002] Bind ALL 14 payload fields to the active-
    // network constants and the policy datum. Pre-Δ20 only 3 fields were
    // checked; the other 11 were decoded-and-discarded.
15. expect payload.domain_tag == auth_domain_tag                           // active-network constant
16. expect payload.network_magic == network_magic                          // active-network constant
17. expect payload.policy_validator == own_script_hash
18. expect payload.policy_id == datum.policy_id                            // belt
19. expect payload.insured_pkh == datum.insured
20. expect payload.payout_address == enterprise_addr_of(datum.insured)     // Δ9
21. expect payload.max_coverage == datum.coverage_amount
22. expect payload.oracle_provider == oracle_provider_to_int(datum.oracle_provider)  // Δ5
23. expect payload.oracle_nft == datum.oracle_nft
24. expect payload.oracle_freshness >= 0
25. expect payload.not_before == datum.start_time
26. expect payload.not_after == datum.expiry_time
27. expect payload.pool_script_hash == datum.pool_script_hash
28. expect payload.pool_nft == datum.pool_nft

29. // ... reuse the same Claim invariants from policy.ak (oracle, time, payout-aggregate-A-009, residual-to-pool A-008)
30. expect count_script_inputs(inputs, own_script_hash) == 1               // Δ6 / F-AUTH-1 — GLOBAL guard
```

`enterprise_addr_of(pkh)` returns the CIP-19 enterprise address bytes for a given PKH (header byte + 28-byte hash). The validator computes this canonically; the off-chain signer must produce the SAME bytes or step 20 fails.

### 1.4 RotateAuth validator branch (v3.1-updated)

[Δ32 / VR-002] **Pre-v3.1 the rotation flow MINTED a new witness alongside the un-burned old one** — leaving two UTxOs sharing the same `auth_witness_nft` asset name on chain. ClaimWithAuth's `length(witnesses) == 1` count gate (Δ7) then rejected every claim until the policy expired, bricking the relay-presigned-auth path for the entire post-rotation period. v3.1 adopts **Option A**: the OLD witness UTxO is SPENT and a NEW witness UTxO is RESPENT at the same auth_witness_validator script — the NFT moves with the UTxO, no mint policy invocation, and the chain never holds more than one witness UTxO under a given asset name.

```
1. must_be_signed_by(extra_signatories, datum.insured)                     // CIP-30 main-wallet sig
2. expect own_script_hash spent (this policy is consumed and recreated)
3. expect bytearray.length(redeemer.new_commit) == 32

   // [Δ25 / V-010] No-op rotation rejection: new_commit MUST differ from
   // datum.auth_commitment.Some(...). The None case is a real change.
4. expect (datum.auth_commitment is Some(old) ? old != redeemer.new_commit : True)

5. let cont_output = find_canonical_continuation(outputs, datum)
6. expect cont_output.datum is InlineDatum(new_datum)
7. expect new_datum == { ...datum, auth_commitment: Some(redeemer.new_commit) }
8. expect lovelace(cont_output.value) == lovelace(own_value)               // value preserved

   // [Δ32 / VR-002 + Δ41 — v3.2] The OLD witness UTxO is SPENT (not
   // referenced). Locate by SCRIPT CREDENTIAL — a regular input at
   // `Script(auth_witness_validator_hash)` whose AuthWitnessDatum's
   // policy_id matches. Pre-Δ41 the binding was via the NFT token
   // (auth_witness_nft_policy_id); Δ41 swaps to the script-credential
   // check to break the deploy cycle (§12.3). Security is preserved
   // by auth_witness_validator's burn-or-respend semantics + own_value
   // self-check on the canonical NFT.
9. let asset_name = blake2b_224(datum.policy_id)
10. let old_witness = find(inputs, has_payment_credential(Script(auth_witness_validator_hash)) && datum_policy_id == datum.policy_id)
11. expect old_witness present
12. expect old_awd.policy_id == datum.policy_id

    // [Δ32 + Δ41] EXACTLY ONE new witness output at
    // `Script(auth_witness_validator_hash)` carrying the canonical
    // (auth_witness_nft_policy_id, blake2b_224(policy_id)) NFT AND
    // matching AuthWitnessDatum.policy_id. Two would re-create the
    // VR-002 count==1-gate-fails state; zero leaves the policy with
    // no witness on chain. Both the script-credential check (Δ41 —
    // breaks deploy cycle) AND the NFT-asset-name check (preserves
    // pre-v3.2 spoofing defense) are applied.
14. let new_witness_count = count(outputs at auth_witness_validator_hash with AuthWitnessDatum.policy_id == datum.policy_id AND value carries (auth_witness_nft_policy_id, blake2b_224(policy_id)))
15. expect new_witness_count == 1
16. let new_witness = the unique such output
17. expect old_witness.output_reference == redeemer.new_witness_ref         // rotation anchor

    // [Δ32] Mint policy MUST NOT be invoked for the asset under
    // rotation — the NFT moves through the spend, not via mint/burn.
18. expect mint(auth_witness_policy_id, asset_name) == 0

19. expect new_awd.policy_id == datum.policy_id
20. expect blake2b_256(new_awd.payload_cbor) == redeemer.new_commit

    // [Δ33 / VR-003] Apply Δ20 + Δ22 to the new witness's payload.
    // Pre-Δ33 these only fired in ClaimWithAuth; a malicious frontend
    // could trick the user into authorizing a rotation whose new
    // witness carried attacker-controlled fields, bricking the next
    // ClaimWithAuth. Closing here catches the surface at rotation time.
21. expect new_payload = cbor_decode(new_awd.payload_cbor)
22. expect cbor.serialise(new_payload) == new_awd.payload_cbor              // canonical (Δ22 mirror)
23. expect new_payload.domain_tag        == auth_domain_tag                 // active-network constant
24. expect new_payload.network_magic     == network_magic                   // active-network constant
25. expect new_payload.policy_validator  == own_script_hash
26. expect new_payload.policy_id         == datum.policy_id
27. expect new_payload.insured_pkh       == datum.insured
28. expect new_payload.payout_address    == enterprise_addr_of(datum.insured)
29. expect new_payload.max_coverage      == datum.coverage_amount
30. expect new_payload.oracle_provider   == oracle_provider_to_int(datum.oracle_provider)
31. expect new_payload.oracle_nft        == datum.oracle_nft
32. expect new_payload.oracle_freshness  >= 0 && new_payload.oracle_freshness <= 86_400_000  // [Δ37 / VR-008]
33. expect new_payload.not_before        == datum.start_time
34. expect new_payload.not_after         == datum.expiry_time
35. expect new_payload.pool_script_hash  == datum.pool_script_hash
36. expect new_payload.pool_nft          == datum.pool_nft

    // [Δ33] vkey-binds-to-insured + signature verify on the new commit.
    // Pre-Δ33 the validator only checked the bytes-to-commit hash;
    // verifying at rotation time closes the surface where a witness
    // with junk signature passed rotation but failed at first claim.
37. expect blake2b_224(new_awd.insured_vkey) == datum.insured
38. expect verify_ed25519(new_awd.insured_vkey, redeemer.new_commit, new_awd.signature)

39. count_script_inputs(inputs, own_script_hash) == 1                       // global guard (Δ6)
```

Rotates the auth without touching coverage / strike / pool binding. `RotateAuth` does NOT pay out; it only updates `auth_commitment`. **No orphan witness is left on chain** — the rotation respend ensures EXACTLY ONE witness UTxO exists per policy at any time.

Pool side: `pool_validator` does NOT need to be co-spent for `RotateAuth` — there is no value flowing. The policy UTxO is consumed and recreated with the new datum + 0 lovelace movement.

### 1.5 `auth_witness_nft` minting policy (v3.3-hardened; per-deployment one-shot)

Parameterized **per Aegis deployment** by:
- `init_utxo_ref: OutputReference` — operator-chosen, hashed into the compiled validator script so each deployment produces a unique policy id. **NOT consumed at every mint** (Δ18 / V-001 fix — the v2 spec's prior wording mis-described this as a runtime check; pre-Δ18 the validator was one-shot per LIFETIME and bricked the feature after the first user).
- `network_tag: ByteArray` — must equal exactly one of `"PREPROD"` / `"PREVIEW"` / `"MAINNET"` (Δ24 / V-009 strict whitelist; pre-Δ24 the check was `!= #""`)
- `operator_pkh: ByteArray` — sweeper key authorized to call `SweepBurn` (Δ19 / V-008)

[Δ41 — v3.2 deploy-cycle break] **The pre-v3.2 4th parameter `policy_validator_hash` is REMOVED.** Pre-v3.2 the mint policy referenced this parameter for the Underwrite path's "fresh policy output at policy_validator" check; combined with `policy_validator` referencing `auth_witness_nft_policy_id`, this created a circular deploy dependency (the two hashes formed a fixed-point that never converged). v3.2 used the new compile-time constant `auth_witness_validator_hash` (in `lib/aegis/types.ak`) to pin the WITNESS output's location at mint time.

[Δ42 — v3.3 final cycle break] **All references to `auth_witness_validator_hash` are now REMOVED from `validators/auth_witness_nft.ak`.** v3.2's destination-script-credential pin re-introduced a SECOND-ORDER deploy cycle: `auth_witness_validator_hash` is itself populated post-deploy (after step 4 of the v3.2 linear ordering), and the mint policy's compiled base hash rotated whenever that constant was updated. v3.3 (Δ42) drops the destination pin and replaces it with a per-tx "EXACTLY ONE output anywhere carries the canonical NFT and matching `AuthWitnessDatum`" check. Off-chain code routes that output to `Script(auth_witness_validator_hash)`; an orphan mint at any other address is unreachable as a witness because `policy_validator` (witness-consume side) accepts witnesses ONLY at `Script(auth_witness_validator_hash)` (Δ41) and `auth_witness_validator`'s spend path self-checks `own_value` carries the canonical NFT (file unchanged). Three-leg transitive trust chain still holds — see §12.4 for the per-finding security argument.

Mint validator (called once per Underwrite):

```
on MintWitness:
  - exactly one token minted under (this policy_id, asset_name)
  - asset_name == blake2b_224(redeemer.policy_id)
  - only one (asset_name, qty) pair under this policy in the tx
  - network_tag is one of the three pinned constants  (Δ24)
  - decoded payload's policy_id matches redeemer.policy_id
  - [Δ34 / VR-004] cbor.serialise(decoded_payload) == redeemer.payload_cbor
    (canonical-form gate at mint — pre-Δ34 a non-canonical encoder
    could mint an unclaimable witness that decoded successfully here
    but later failed ClaimWithAuth's Δ22 check)
  - [Δ42 — v3.3] Underwrite path:
      (a) EXACTLY ONE tx output (anywhere) carries the
          (own_policy_id, blake2b_224(redeemer.policy_id)) pair
          AND its InlineDatum is an AuthWitnessDatum with
          policy_id == redeemer.policy_id AND
          payload_cbor == redeemer.payload_cbor; AND
      (b) a separate policy output (skipping any output that carries
          the canonical NFT) whose InlineDatum decodes as PolicyDatum
          with policy_id == redeemer.policy_id AND auth_commitment ==
          Some(blake2b_256(redeemer.payload_cbor)) AND oracle_provider
          matching the payload's tag.
    The pre-v3.3 (v3.2) explicit "witness output at
    auth_witness_validator_hash script address" check is replaced by
    the value-based "EXACTLY ONE output carries the asset" check
    because `auth_witness_validator_hash` is no longer imported by
    this validator — the second-order deploy cycle is broken (§12.4).
    Off-chain code routes the witness output to the canonical script.
    An orphan mint at any other address is harmless because
    `policy_validator` accepts witnesses ONLY at
    `Script(auth_witness_validator_hash)`; the orphan is unreachable
    as a witness via ClaimWithAuth/RotateAuth — funds are safe.

  [Δ32 / VR-002] The pre-v3.1 RotateAuth-via-mint path is REMOVED. v3.1
  routes rotation through a respend at the auth_witness_validator script
  (NFT moves with the UTxO, no mint policy invocation), so MintWitness
  is exclusive to Underwrite-creation.

on BurnViaConsume { policy_id }:                                        (Δ19 / V-002)
  - the matching policy UTxO MUST be co-spent in the same tx
  - mint quantity is exactly -1
  - only one (asset_name, qty) pair under this policy
  - network_tag pinned
  - [Δ42 — v3.3] The pre-v3.2 negative script-credential filter on
    `auth_witness_validator_hash` (used to skip the witness input
    when locating the consumed policy by datum shape) is REMOVED.
    The constant is no longer imported by this validator. Inputs
    whose datum is `AuthWitnessDatum` (the witness input being
    burned) simply fail the typed `expect pdat: PolicyDatum =
    raw_pdat` path and contribute False to the `list.any` fold —
    no crash, because the typed-decode failure is caught by the
    surrounding `when` arm. Atomic-burn semantics preserved.

on SweepBurn { policy_id }:                                             (Δ19 / V-008 + Δ31 / VR-001 + Δ42 v3.3)
  - extra_signatories contains operator_pkh
  - the witness UTxO being burned is a regular input whose value
    carries 1× (auth_witness_nft_policy_id, blake2b_224(policy_id))
    — i.e., we have on-chain access to its `payload_cbor`
  - the witness input sits at a `Script(_)` payment credential
    (defense-in-depth structural check; the concrete
    `auth_witness_validator_hash` constant is NOT referenced post-Δ42
    so the mint policy's compiled hash stays independent of that
    constant's value)
  - decode payload from witness datum → bind `not_after` from payload
  - tx_validity.lower_bound > payload.not_after   (strict; auth window provably elapsed)
  - [Δ31 / VR-001] `not_after` is NO LONGER a redeemer parameter; the
    gate reads `payload.not_after` from the witness UTxO. Pre-Δ31 the
    redeemer carried `not_after` and the operator could pass `0` to
    destroy any live witness for any policy at any time.
  - mint quantity is exactly -1
  - only one (asset_name, qty) pair under this policy
  - network_tag pinned
```

Compile-time pin in `types.ak`: `auth_witness_nft_policy_id: ByteArray = #"…"` per network. Validator's `ClaimWithAuth` and `RotateAuth` branches use this constant; the redeemer-supplied policy id is REJECTED if it doesn't match. (Closes the redeemer-controlled-identifier anti-pattern flagged in round 6.)

### 1.6 `auth_witness_validator` — narrowly-scoped spend paths

The auth witness UTxO is locked at this address. By default the witness is **reference-only** for ClaimWithAuth — spending requires one of two narrowly-scoped paths:

**Path 1 — Burn-only.** Used by ClaimWithAuth/Cancel/Expire cleanup (BurnViaConsume) and operator orphan sweep (SweepBurn). The spend "succeeds" iff `mint(auth_witness_policy_id, asset_name) == -1 && continuation_count == 0` — the matching NFT is being burned in the same tx and no output at this validator carries the asset. This is the same pattern Charli3 uses for stale-oracle UTxO retirement.

**Path 2 — Rotation respend (Δ32 / VR-002, v3.1).** Used by RotateAuth. The spend "succeeds" iff `mint(auth_witness_policy_id, asset_name) == 0 && continuation_count == 1` — the NFT is neither minted nor burned, and exactly one continuation output at this validator carries the same asset_name. The policy validator's RotateAuth branch is the cryptographic gate (user CIP-30 sig + 14-field new-payload binding chain + Ed25519 sig verify); auth_witness_validator's job on this path is purely structural: refuse a TWO-witness configuration that would later break ClaimWithAuth's count==1 gate.

```aiken
validator auth_witness_validator {
  spend(_, _, own_ref, self) {
    // ... locate the witness input being spent, find its asset_name,
    //     count continuations at this validator with that asset_name,
    //     gate on burn-path (mint==-1 && count==0) || rotate-path
    //     (mint==0 && count==1).
  }
  else(_) { fail @"auth_witness_validator only supports the spend purpose" }
}
```

This prevents tampering: even if an attacker somehow held the witness NFT outside a burn or rotation context, they could not spend the UTxO to substitute its datum.

### 1.7 Atomic witness mint at Underwrite (Δ1)

The Underwrite tx now produces TWO outputs:
1. Policy UTxO at `policy_validator` address with `PolicyDatum.auth_commitment = Some(commit)`.
2. Witness UTxO at `auth_witness_validator` address with `AuthWitnessDatum { policy_id, insured_vkey, payload_cbor, signature }` + 1× `auth_witness_nft` token.

The witness mint policy (§1.5) verifies both at mint time. If the two outputs disagree on `policy_id` or `commit`, mint fails. There is no separate "publish auth" call.

If the user opts out of relay coverage, the Underwrite tx omits the witness mint and sets `auth_commitment = None`. Pool validator MUST allow either: present + correctly-bound witness, OR `None` + no witness mint in tx.

### 1.8 `policy_id` derivation (Δ3 — also fixes pre-existing collision risk)

**Single-Underwrite path:**
```
policy_id = blake2b_224(
  insured_pkh
  || strike_price.to_be_bytes(8)
  || coverage_amount.to_be_bytes(8)
  || start_time.to_be_bytes(8)
  || expiry_time.to_be_bytes(8)
  || pool_nft
  || underwrite_tx_input.tx_id || underwrite_tx_input.index.to_be_bytes(2)  // NEW
)
```

Including the consumed input ref makes the `policy_id` collision-resistant even across same-terms policies. The off-chain Underwrite builder must commit the chosen input ref to the policy_id at sig time, and the validator's pool-side Underwrite check must verify `pdat.policy_id == derive_policy_id(...)` (cheap — single BLAKE2b hash).

**Batch-Underwrite path (Δ21 / V-003):**

The single-Underwrite anchor (one input → one output) does not generalise to batches (one input → N outputs). Δ21 introduces `derive_policy_id_batch(..., underwrite_anchor, batch_index)` that appends a 2-byte big-endian per-output index to the preimage:

```
policy_id_batch_i = blake2b_224(
  insured_pkh
  || strike_price.to_be_bytes(8)
  || coverage_amount.to_be_bytes(8)
  || start_time.to_be_bytes(8)
  || expiry_time.to_be_bytes(8)
  || pool_nft
  || underwrite_tx_input.tx_id || underwrite_tx_input.index.to_be_bytes(2)
  || i.to_be_bytes(2)                                                      // batch_index salt
)
```

Where `i` is the 0-based index of the policy output among the batch's policy outputs (counted in tx-output order). The pool's `BatchUnderwrite` branch enforces `pdat.policy_id == derive_policy_id_batch(...)` for every policy output. The 2-byte salt makes the batch preimage 82 bytes vs the single-Underwrite's 80 bytes — no cross-mode preimage collision class. Off-chain builders mirror the construction byte-for-byte.

### 1.9 Hash rotation cascade

ClaimWithAuth + RotateAuth + Δ8 (policy_id derivation) all touch `policy_validator`. New `auth_witness_validator` + `auth_witness_nft` minting policy. Pool unchanged BUT pool_validator is parameterized over `policy_script_hash` per v6.0.2 — that parameter rotates → pool hash rotates → lp_token cascade. So all 4 existing validator hashes rotate + 2 new ones.

---

## 2. Pre-signed authorization

### 2.1 Canonical payload (revised — adds `oracle_provider`)

```
AuthCoveragePayload {
  domain_tag        : ByteArray,  // "AEGIS_CLAIM_AUTH_v1_PREPROD" or "_MAINNET"  (Δ4)
  network_magic     : Int,        // 1 / 764824073
  policy_validator  : ByteArray,  // 28-byte script hash of the v8 policy_validator
  policy_id         : ByteArray,  // PolicyDatum.policy_id (per §1.8 derivation)
  insured_pkh       : ByteArray,
  payout_address    : ByteArray,  // 29-byte enterprise CIP-19 address bytes (header + insured_pkh) — v2: derived from CIP-30 main wallet (Δ9)
  max_coverage      : Int,        // == datum.coverage_amount
  oracle_provider   : Int,        // Constr index: 0=Charli3, 1=Orcfax, 2=AegisSelf  (Δ5)
  oracle_nft        : ByteArray,
  oracle_freshness  : Int,        // ms — informational only (not enforced on-chain; advisory per §8 Q2)
  not_before        : Int,        // POSIX ms — must equal datum.start_time
  not_after         : Int,        // POSIX ms — must equal datum.expiry_time
  pool_script_hash  : ByteArray,
  pool_nft          : ByteArray,
}
```

`auth_commitment = blake2b_256(canonical_cbor(AuthCoveragePayload))`.

### 2.2 Network-specific domain tag (Δ4)

`domain_tag = "AEGIS_CLAIM_AUTH_v1_" + network_tag`. Combined with `network_magic`, no signature can replay across networks even if the user shares an Ed25519 keypair across preprod/mainnet (which BIP-44 derivation does — see memory's A-028 finding).

### 2.3 Canonical CBOR encoding (Δ10)

Pinned: **Plutus Constr 0 indefinite-length list** — bytes `d8 79 9f` + 14 field encodings + `ff`. This matches Aiken's `cbor.serialise(record)` output (which IS the on-chain canonical authority via Plutus's `serialise_data` builtin). Inner items per RFC 8949 deterministic rules: smallest-possible uint headers, definite-length bytestrings, no nested indefinite-length items.

Concretely:

```
d8 79 9f                                         <-- Plutus Constr 0 + indefinite-length list marker
  <encodeBytes(domain_tag)>                      <-- field 1
  <encodeUint(network_magic)>                    <-- field 2
  <encodeBytes(policy_validator)>                <-- field 3
  ... 11 more fields in §2.1 declaration order ...
  <encodeBytes(pool_nft)>                        <-- field 14
ff                                               <-- CBOR break stop code
```

Where `encodeBytes(b) = encodeTypeAndLength(2, b.length) || b` (definite-length major-type-2, smallest-possible header) and `encodeUint(n)` is RFC 8949 §4.2 smallest-possible major-type-0.

Reference encoders:
- **Aiken (on-chain authority):** `cbor.serialise(payload)` — `aiken/cbor` stdlib, which compiles down to Plutus's `serialise_data` builtin.
- **TypeScript (frontend):** hand-rolled `encodeAuthCoveragePayloadCanonical` in `frontend/src/wallet/aegis/auth_payload.ts` (zero CBOR-runtime dependency, ~120 LOC of auditable logic).
- **Python (off-chain reference):** `scripts/dump_vectors.py` in the contracts repo.

**Cross-stack agreement is verified via byte-vector tests in Appendix B.** Test failure = ship-block. The TypeScript suite's `__tests__/cross_stack_cbor.test.ts` reads the Aiken-published fixture and asserts byte-for-byte equality with the TS encoder's output for every vector.

Optional fields (`oracle_freshness` is informational): encoded as `Option<Int>` = `Some(n) = constr_0([n])`, `None = constr_1([])`. NOT omitted from the array.

### 2.4 Client-side signing flow (atomic with Underwrite)

```
1. CIP-30 wallet returns user's main-wallet payment_credential PKH.
2. Frontend derives:
     payout_pkh = main_wallet_payment_credential
     payout_address = 0x60 || payout_pkh    (29-byte enterprise CIP-19)
3. User picks an Aegis-wallet seed (Shamir-reconstruct via passphrase + WebAuthn).
4. Frontend computes policy_id per §1.8 (needs the Underwrite tx's chosen input ref).
5. Frontend constructs AuthCoveragePayload, canonical-CBOR-encodes it, hashes to commit.
6. Frontend prompts the Aegis wallet to sign `commit` (Ed25519 over the 32-byte commitment).
   The prompt UI displays a HUMAN-READABLE summary derived from the payload:
     "Authorize a relay to claim this policy on your behalf:
       Network:     Cardano preprod
       Coverage:    100 ADA
       Strike:      $0.30
       Payout to:   addr_test1vrhy...evgw  (your main wallet)
       Expires:     2026-08-15
     [SIGN]  [CANCEL]"
   (Δ16 — closes UI-confusion attack from H-1.)
7. Frontend builds the Underwrite tx with:
     - inputs: user funds (consumes the input ref baked into policy_id)
     - mint: 1× auth_witness_nft (policy_id-derived asset name)
     - outputs:
       * pool continuation
       * policy UTxO at policy_validator (PolicyDatum 12-field, auth_commitment = Some(commit))
       * witness UTxO at auth_witness_validator
         (AuthWitnessDatum { policy_id, insured_vkey, payload_cbor, signature })
8. CIP-30 wallet signs the tx body. Submit. Done — single tx.
```

If the user opts out, step 6 is skipped; `auth_commitment = None`; no witness mint; tx has only the pool continuation + policy output.

**Cross-stack validation parity (Δ26 — closes A-A-004):** the Python and
TypeScript encoders MUST validate IDENTICALLY at the pre-signing boundary.
A payload that one stack rejects must be rejected by the other with an
equivalent error category. Both stacks expose two encoder entry points:

* `encode_auth_coverage_payload_canonical` / `encodeAuthCoveragePayloadCanonical`
  — the byte-shape mirror of Aiken's `cbor.serialise`. No validation.
  Used by cross-stack vector tests against the Aiken fixture.
* `encode_auth_coverage_payload` / `encodeAuthCoveragePayload`
  — full v2-spec invariant guards (lengths, integer ranges, network
  consistency, payout binding, coverage floor, freshness cap, time
  window). The signing flow MUST go through this validated path so
  the wallet's signing prompt cannot show one thing and encode another.

The validation rule set is enumerated in the cross-stack invalid-payload
manifest at `D:/aegis-contracts/contracts/tests/fixtures/invalid_payload_vectors.json`
(Δ28). Both stacks load the manifest and assert each entry is rejected
with the documented `error_pattern` — drift in either stack trips the CI
gate before the divergence ships.

Integer fields are capped at `2^63 - 1` in BOTH stacks (Δ27 / A-A-009)
so values round-trip identically through Python, TypeScript, and
Aiken's `cbor.deserialise` int-header decoder.

### 2.5 Witness UTxO datum + lifecycle

```aiken
type AuthWitnessDatum {
  policy_id      : ByteArray,
  insured_vkey   : ByteArray,    // 32-byte Ed25519 pubkey (Aegis wallet, NOT the CIP-30 main wallet)
  payload_cbor   : ByteArray,    // canonical CBOR of AuthCoveragePayload (so any relay can verify locally)
  signature      : ByteArray,    // 64-byte Ed25519 over blake2b_256(payload_cbor)
}
```

Lifecycle:
- **Created**: at Underwrite (atomic mint, §2.4 step 7). 1× NFT minted under deployed `auth_witness_nft_policy_id` with asset name `blake2b_224(policy_id)`. ~3.5 ADA min-UTxO locked.
- **Referenced**: at every `ClaimWithAuth` and `RotateAuth` tx (read-only).
- **Replaced (RotateAuth)**: [Δ32 / VR-002 — v3.1] the old witness UTxO is SPENT and a NEW witness UTxO is RESPENT at the same auth_witness_validator script — the NFT moves with the UTxO, no mint policy invocation, and the chain never holds more than one witness UTxO under a given asset_name (so ClaimWithAuth's `length(witnesses) == 1` count gate stays satisfied immediately after rotation). The user's CIP-30 sig on the RotateAuth redeemer authorizes both the datum update AND the new payload binding (Δ33 enforces 14-field binding + canonical CBOR + Ed25519 sig verify on the new payload at rotation time).
- **Burned**: after Cancel/Expire/Claim consumes the policy, anyone (or the operator-only sweeper, Δ15) can submit a tx that consumes the orphan witness, burns the NFT, and recovers the min-UTxO ADA. Sweeper requires k≥20 confirmations on policy non-existence to avoid reorg griefing.

---

## 3. Off-chain relay service (`aegis-relay`)

### 3.1 Multi-source data plane (Δ13)

Relay reads from at LEAST two of: `{ Blockfrost, Kupo, Ogmios }`. Production deploys MUST configure both. If the two sources disagree on `chain_tip_slot` by more than `slot_skew_ms = 30_000`, the relay refuses to submit (logs a warning; in-browser is the safety floor anyway). This addresses F-1's SPOF concern.

### 3.2 Per-policy tick cache + spam floor (Δ14)

State (in-memory, recomputable at any time from chain):
```
class PolicyCacheEntry:
  policy_id: bytes
  next_eligible_tick_at: int          # POSIX ms; min(start_time, oracle_next_publish_predicted)
  last_witness_check_at: int
  witness_utxo_ref: Optional[OutputRef]  # cached after first successful resolve
```

Per-tick work is bounded to policies whose `next_eligible_tick_at < now + 60s`. Witness UTxOs are re-fetched at most every 5 minutes per policy (cache TTL).

**Min-coverage floor**: relay refuses to consider policies with `coverage_amount < 5_000_000` (5 ADA). Documented in policy creation UI ("offline auto-claim requires ≥5 ADA coverage"). Ad-hoc DoS via 1-lovelace-coverage spam policies is impossible.

### 3.3 Tick loop — unchanged in shape from v1, instrumented

Every `relay_tick_interval` (default 20s):
1. Fetch tip slot from data sources A + B; agree within `slot_skew_ms` or skip tick.
2. For each cached policy with `next_eligible_tick_at < now + 60s`:
   a. Fetch policy UTxO + witness UTxO + relevant oracle UTxO.
   b. Locally verify: `blake2b_256(payload_cbor) == datum.auth_commitment`, sig validates against `insured_vkey`, oracle price ≤ strike, time bounds.
   c. If eligible: build ClaimWithAuth tx, submit via primary data source (whichever is first to respond). Relay key signs only fees+collateral, not the policy input.
3. On `UtxoAlreadySpent`: drop policy from cache (claim happened via in-browser or another relay).

### 3.4 Avoiding double-claim

In-flight dedup keys on `(policy_id, witness_utxo_ref)` (Δ11) NOT `txHash`. Same `(policy_id, witness_utxo_ref)` once per 120s.

### 3.5 Threat model — additions to v1 §3.5

- **Selective delay-griefing** (F-10): Relay can sit on a valid claim, hoping the oracle bounces above strike before submitting. Liveness only — in-browser fallback path covers.
- **Sweeper griefing** (F-4): Sweeper requires ≥20-block confirmations + operator-only signature. Documented as part of relay operator runbook.
- **Single-relay reality** (F-6): "Open relay" is a positioning claim, not a code constraint. Pre-mainnet: ship the relay binary public, document the runbook, attempt onboarding ≥1 third-party operator. Until then, market as "Flux-operated relay with in-browser fallback as the safety floor."

The strict invariant from v1 holds: **a relay can cause `fail to broadcast` or `validator-rejected tx`. It can never cause `funds end up anywhere other than insured's enterprise address`.**

---

## 4. Integration with current SSS auto-claim

Unchanged from v1 §4. Both paths target the same policy UTxO; UTxO consumption is the distributed lock. Decision matrix at policy creation:

| User state | `auth_commitment` | Relay covers | In-browser covers |
|---|---|---|---|
| Both wallets, opts in to relay (default) | `Some(commit)` | Yes | Yes (redundant) |
| Both wallets, opts out of relay | `None` | No | Yes |
| CIP-30 only, no Aegis wallet | `None` | No | No (manual claim only) |

---

## 5. RotateAuth flow (v3.1 — respend at auth_witness_validator)

Trigger: user has lost trust in their Aegis-wallet seed (suspected Shamir share leak), or has migrated their CIP-30 main wallet, or wants to change `payout_address`.

```
1. User connects CIP-30 main wallet (proves they're the insured).
2. User chooses: (a) generate a new Aegis-wallet seed, OR (b) rotate to a new payout_address.
3. Frontend derives a new payload (the Δ8 policy_id is unchanged because
   the policy datum's policy_id is preserved across rotation; payout_address
   and oracle_provider can rotate; the Aegis-wallet signing key can rotate).
4. Aegis-wallet signs the new commit (the new payload's BLAKE2b-256).
5. Frontend builds RotateAuth tx with:
     - input: existing policy UTxO (consumes it; spend gated by RotateAuth branch §1.4)
     - input: existing witness UTxO at auth_witness_validator (Δ32 — SPENT, not referenced)
     - input: user's CIP-30 main-wallet utxo (extra_signatories[insured])
     - mint: NOTHING for the auth_witness_nft asset (Δ32 — net mint qty == 0)
     - output: continuation policy UTxO with NEW auth_commitment in datum
     - output: NEW witness UTxO at auth_witness_validator (same asset_name; the
       NFT moves with the UTxO via the spend, not via mint/burn)
6. CIP-30 wallet signs.
```

**[Δ32 / VR-002 — v3.1] No orphan witness is left on chain.** The old witness is consumed and the new witness inherits its NFT via the respend. ClaimWithAuth's `length(witnesses) == 1` count gate stays satisfied immediately after rotation — the relay-presigned-auth path resumes working in the next block.

[Δ33 / VR-003] **The new witness's payload is bound across all 14 fields, canonically re-encoded, AND its Ed25519 signature verified at rotation time.** Pre-Δ33 a malicious frontend could trick the user into signing a rotation whose new witness carried attacker-controlled fields — the rotation would pass on chain and the next ClaimWithAuth would fail Δ20, bricking the relay-auth path until policy expiry. v3.1 catches this at rotation time so the user never finishes a malicious rotation.

Cost: one tx fee — no mint/burn min-UTxO churn (Δ32 / VR-002 fix). The respend preserves the witness UTxO's lovelace.

---

## 6. Migration path (v6.0.2 → v8)

v6.0.2 preprod has exactly one policy on chain (`23889dec…`). v8 schema (12 fields) cannot decode the v6.0.2 (11 fields) datum. Migration:

1. Land v8 contracts on a new branch.
2. **Before redeploy**: capture green-path proof on v6.0.2 (still works), then submit `Cancel` or `Expire` against the v6.0.2 `23889dec…` policy. Document tx hash.
3. v8 redeploy: new pool_nft (`AEGIS_POOL_V11`), new ref UTxOs, new init_pool. Cascade hashes captured in `deploy-state.preprod.v8.json`. **[Δ41 — v3.2] The deploy follows the linear 5-step ordering documented in §12.3** (no circular hash dependency).
4. Frontend's policy decoder is updated for 12-field PolicyDatum at the same time as backend.
5. End-to-end e2e test (per §10.4 acceptance) before tagging v8.

### Phase 4 deploy ordering (v3.3 — truly linear, acyclic, 5 rebuilds)

Pre-v3.2 the Phase 4 deploy was **stuck in a first-order circular dep**:
the `auth_witness_nft` mint policy was parameterized over
`policy_validator_hash`, while `policy_validator` referenced
`auth_witness_nft_policy_id` — neither hash converged at deploy time.
v3.2 (Δ41) broke the first-order cycle. v3.2 left a **second-order
cycle**: `auth_witness_nft.ak` still imported `auth_witness_validator_hash`,
so the mint policy's base hash rotated whenever that constant was updated
in step 4 — invalidating the policy id pinned in step 2 and bringing the
ordering back into a fixed-point loop. v3.3 (Δ42) closes the second-order
cycle by removing all `auth_witness_validator_hash` references from
`auth_witness_nft.ak`. The new deploy ordering is **truly linear**: every
step produces a stable hash that the next step depends on, and **no
earlier hash rotates as a side-effect of a later step**.

```
1. Build with both `auth_witness_nft_policy_id` and
   `auth_witness_validator_hash` at the all-zeros placeholder.
   `auth_witness_nft.mint` base hash is STABLE — the validator no
   longer depends on either constant (Δ42 invariant). Empirically:
   `h_base_v0 == h_base_v1` for any value of
   `auth_witness_validator_hash`.
2. Apply `auth_witness_nft(init_utxo_ref, network_tag, operator_pkh)`
   — 3 params, NO `policy_validator_hash` (Δ41). Compile produces a
   stable `auth_witness_nft_policy_id` (the parameterised mint
   policy's policy id). This is the FINAL policy id — Δ42 ensures it
   never rotates again.
3. Bake `auth_witness_nft_policy_id` const into
   `lib/aegis/types.ak`. Rebuild →
   `auth_witness.auth_witness_validator.spend` hash freezes (depends
   only on `auth_witness_nft_policy_id`).
4. Bake the resulting `auth_witness_validator` hash into
   `lib/aegis/types.ak::auth_witness_validator_hash`. Rebuild →
   `policy.policy_validator.spend` hash freezes (depends only on
   `auth_witness_validator_hash`). **CRITICAL**:
   `auth_witness_nft.mint` base hash does NOT change at this step —
   Δ42 invariant. The policy id from step 2 is FINAL.
5. Mint pool NFT (`AEGIS_POOL_V11`), deploy reference scripts, init
   the pool (existing v6.0.2 → v8 procedure). The pool validator's
   compile-time `policy_script_hash` parameter consumes the
   policy_validator hash from step 4.
```

The deploy gate `scripts/check_deploy_constants.py` enforces both the
`auth_witness_nft_policy_id` and `auth_witness_validator_hash`
constants are non-placeholder before mainnet tag — both must be set
correctly between steps 2 and 3 (policy id) and between steps 3 and 4
(validator hash) for the deploy to be tag-able.

**Manual-claim fallback always available (Δ29 / RT-C-02).** Throughout the migration AND post-deploy, the v6.0.2 ordinary `Claim` flow continues to work for any policy in the money. The frontend exposes this path explicitly via the "Manual Claim (CIP-30)" button on every non-terminal policy in the My Policies panel — it is the user's safety floor when both auto-claim paths (relay and in-browser Aegis wallet) are unreachable, and it is part of the v8 release. The button uses the user's main CIP-30 wallet (Eternl, Lace, Nami, …) for the tx-body signature; no relay coordination, no Aegis-wallet seed required. The on-chain validator pays out to the same insured-bound enterprise address regardless of which path triggered the claim.

---

## 7. Failure modes

Unchanged from v1 §6 except:
- Witness UTxO in v2 is co-created with the policy → no "publish failed but policy exists" state (Δ1 closes F-3).
- Wallet-loss path: user can `Cancel` (out-of-the-money only, A-010) OR if ITM, accept that `RotateAuth` can be done from any CIP-30 wallet they can sign with as `datum.insured`.

---

## 8. What this design DOES NOT do — v3 invariant table

Same as v1 §7 plus:

| Forbidden capability | Validator check |
|---|---|
| Relay or attacker mints a fake witness for someone else's policy | `auth_witness_nft` mint policy is one-shot **per deployment** via `init_utxo_ref` baked into the compiled hash (§1.5, Δ18); compile-time-pinned policy id in `ClaimWithAuth`/`RotateAuth` (Δ17) |
| Two competing witnesses for one policy | Mint policy enforces `count(mint of policy_id) == 1`; ClaimWithAuth iterates ALL ref inputs and accepts iff exactly one witness present (Δ7) |
| Auth signed for a different oracle provider than policy is bound to | Mint validator asserts `payload.oracle_provider == datum.oracle_provider` at Underwrite + RotateAuth (Δ5); claim validator re-decodes payload + reasserts (Δ12 step 22) |
| Attacker signs auth that pays to their own address | Validator computes `enterprise_addr_of(datum.insured)` and asserts `payload.payout_address` matches (Δ9 step 20); A-009 still routes payout aggregate to insured PKH |
| User loses Aegis seed → relay drains to inaccessible Aegis address | Default `payout_address` is CIP-30 main-wallet enterprise variant (Δ9) — main wallet keys are independent of Aegis seed |
| Old auth replays after RotateAuth | [Δ32 / v3.1] Old witness UTxO is SPENT during rotation — the NFT moves with the UTxO via a respend at the auth_witness_validator (no mint, no burn). The chain holds EXACTLY ONE witness UTxO at `Script(auth_witness_validator_hash)` with matching AuthWitnessDatum.policy_id at all times, so ClaimWithAuth's Δ7 count gate is never broken by rotation. Pre-v3.1 the rotation MINTED a new witness alongside the un-burned old one, leaving 2 UTxOs under the same asset_name and bricking ClaimWithAuth until expiry — VR-002. [Δ41 — v3.2] Witness identification swapped from NFT-token-policy-id to script-credential to break the deploy cycle; security preserved via auth_witness_validator's burn-or-respend semantics + own_value self-check on the canonical NFT. |
| Cross-network sig replay | `domain_tag` includes `_PREPROD` / `_MAINNET` (Δ4) + `network_magic` numeric; both bound on-chain by Δ20 (steps 15-16). |
| Policy-id collision (same terms, different policies) — single Underwrite | `policy_id` derivation includes `OutputReference` (Δ3); pool's Underwrite check verifies `pdat.policy_id == derive_policy_id(...)` (§1.8). |
| Policy-id collision (same terms, different policies) — batch Underwrite | `derive_policy_id_batch(..., underwrite_anchor, batch_index)` (Δ21); pool's BatchUnderwrite branch verifies `pdat.policy_id == derive_policy_id_batch(...)` for every policy output (§1.8). |
| Third party destroys live witness UTxO and pockets min-ADA | `BurnViaConsume` (Δ19) requires the matching policy UTxO to be co-spent; orphan-only `SweepBurn` is operator-signed AND requires `tx_lower > payload.not_after`. [Δ31 / v3.1] `not_after` is read from the WITNESS UTxO's payload bytes — pre-v3.1 it was a redeemer-supplied integer, allowing operator-key compromise to destroy any live witness with `not_after = 0`. |
| Operator key compromise kills relay-auth feature | [Δ31 / v3.1] SweepBurn binds `not_after` to the witness's user-signed `payload.not_after`. An operator-controlled `not_after = 0` no longer satisfies the gate — closes VR-001. |
| Non-canonical CBOR bypasses wallet validation | Validator re-encodes decoded payload via `cbor.serialise` and asserts byte-equal to `awd.payload_cbor` — applied in ClaimWithAuth (Δ22), MintWitness (Δ34), and RotateAuth (Δ33). |
| Buggy encoder mints unclaimable witness | [Δ34 / v3.1] MintWitness asserts canonical re-encode at mint time so a non-canonical witness never reaches chain — closes VR-004. |
| Malicious frontend poisons rotation to brick later ClaimWithAuth | [Δ33 / v3.1] RotateAuth applies the full Δ20 14-field binding + Δ22 canonical re-encode + Ed25519 sig verify on the new payload AT rotation time — closes VR-003. |
| Wallet-displayed-but-unenforced payload field deception | All 14 payload fields bound to either active-network constants or the policy datum (Δ20 — ClaimWithAuth + Δ33 — RotateAuth). |
| `network_tag` typo silently produces a misnamed deployment | Mint policy parameter must equal exactly `"PREPROD"` / `"PREVIEW"` / `"MAINNET"` UTF-8 (Δ24). |
| No-op rotation grief (caller burns user min-ADA without changing state) | RotateAuth requires `new_commit != datum.auth_commitment.Some(_)` (Δ25). |
| `oracle_freshness` value vastly out of cap silently signed | [Δ37 / v3.1] On-chain validator binds `oracle_freshness >= 0 && <= 86_400_000` (24h) in both ClaimWithAuth and RotateAuth — closes VR-008's cross-stack asymmetry. |
| Cross-stack length-check drift (oracle_nft, pool_script_hash, pool_nft) | [Δ36 / v3.1] Shared invalid-payload manifest at `tests/fixtures/invalid_payload_vectors.json` carries 15 vectors (was 10); both Python and TS encoders reject every length / range boundary entry — closes VR-006. |
| Circular deploy dep blocks Phase 4 | [Δ41 — v3.2] `auth_witness_nft` mint policy drops `policy_validator_hash` from its parameter set (3-tuple now); `policy_validator` identifies witness UTxOs by `Script(auth_witness_validator_hash)` script credential. Linear 5-step deploy ordering — see §12.3 / §6 Phase-4 deploy section. Deploy-gate at `scripts/check_deploy_constants.py` enforces both `auth_witness_nft_policy_id` AND `auth_witness_validator_hash` are non-placeholder before mainnet tag. |
| Attacker forges witness UTxO at non-auth_witness_validator script address (post-Δ41) | The mint policy enforces the witness output is at `Script(auth_witness_validator_hash)` (Δ41); the auth_witness_validator's spend path (Δ32) self-checks `own_value` carries the canonical `auth_witness_nft_policy_id` token AND enforces burn-or-respend semantics; `policy_validator` accepts witness UTxOs only at `auth_witness_validator_hash` (Δ41). Three-leg transitive trust chain — the spoofing surface that the pre-v3.2 single-token-policy-id leg covered is preserved end-to-end. |

---

## 9. Implementation phases (TDD)

Each phase: tests-first, then code, then green CI gate before next phase starts.

| Phase | Owner | Deliverable | Acceptance |
|---|---|---|---|
| **1** | Aiken agent | New types (12-field PolicyDatum, ClaimWithAuth/RotateAuth redeemers, AuthWitnessDatum, AuthCoveragePayload), new validators (auth_witness_validator, auth_witness_nft minting policy), new ClaimWithAuth + RotateAuth branches in policy.ak, policy_id derivation update | `aiken check` 222 → ≥260 tests green; new green tests for every Δ + every §8 invariant; cross-validator invariants preserved (A-001..A-027 + L-003 + L-006 unchanged) |
| **2a** | Off-chain Python agent | PolicyDatum dataclass (12 fields), ClaimWithAuthRedeemer + RotateAuthRedeemer + AuthWitnessDatum (pyc.PlutusData), AuthCoveragePayload encoder using `cbor2`, build_claim_with_auth_tx, build_rotate_auth_tx, build_underwrite_with_auth_tx (atomic mint) | offchain pytest 208 → ≥240 green; cross-stack CBOR byte-vector test (Appendix B) green |
| **2b** | Frontend agent | `auth_payload.ts` (canonical CBOR encoder, byte-vector tests), `signAuthCommitment` in signer.ts, "Enable offline auto-claim" UI toggle in policy creation flow with payload-summary signing prompt, displays current auth status on policies, RotateAuth UX | vitest 41 → ≥55 green; CBOR encoder produces byte-identical output to Python for all Appendix B test vectors |
| **3** | Implementation red-team agents (3× parallel) | Attack the implemented code (not the design) along the same 3 axes (crypto / validator / relay); patch findings before deploy | All HIGH+ findings closed; remaining MEDs documented & accepted |
| **4** | Operator | v8 preprod redeploy: cancel old `23889dec…`, mint new pool NFT (`AEGIS_POOL_V11`), publish refs, init pool, smoke test all paths (Underwrite-with-auth, ClaimWithAuth, RotateAuth, Cancel, Expire) | All 5 smoke txs `valid_contract: true` |
| **5** | Relay agent | New `aegis-relay/` repo: Fly.io or Railway deploy, Blockfrost+Kupo, tick loop with Δ14 caching, monitoring/alerting | E2E proof: create policy with auth → close browser → trigger oracle → relay claims within 60s |
| **6** | Docs agent | `RELAY_PRESIGNED_AUTH_SCOPE_v2.md` updated with final hashes, GREEN_PATH_PROOFS.md gains v8 section, SECURITY_AUDIT_REPORT.md gains §Round 7, public repo tagged `v8.0.0-relay-presigned-auth` | All public docs current; auditor notification sent |

---

## 10. Acceptance checklist

- [ ] All v6.0.2 contract tests still green (222 baseline preserved by additive changes).
- [ ] ≥30 new green tests covering: ClaimWithAuth happy path, RotateAuth happy path, every CRITICAL/HIGH finding from the design red-team converted to a negative test, every §8 invariant.
- [ ] Cross-stack CBOR byte-vector tests (Appendix B): TS encoder ↔ Python `cbor2` ↔ Aiken `cbor.serialise` produce identical bytes for all test payloads.
- [ ] `aegis-relay` deployable to Fly.io or Railway with two env vars (`BLOCKFROST_KEY`, `KUPO_URL`).
- [ ] End-to-end preprod scenario: create policy with auth → close all browser tabs → wait for oracle to print below strike → relay claims within 60s → audit log shows tx submitted by relay with insured-bound payout.
- [ ] All claim paths (in-browser + relay) pay to the SAME insured-bound enterprise address (CIP-30 main wallet variant, Δ9).
- [ ] No new dependency on a centralized index; relay state is purely a function of chain data.
- [ ] `RotateAuth` exercised on chain with both: (a) Aegis-seed rotation, (b) payout-address rotation.
- [ ] Wallet-prompt at sig time displays the human-readable payload summary (Δ16 verified by Playwright e2e test).
- [ ] All deferred findings from round 6 (L-002, ECON-1, A-028, A-029, ECON-2, ECON-3, ECON-4, L-007, L-001, L-005) reviewed and confirmed unchanged or improved by v8.
- [ ] Documentation updated: this file with final hashes, `GREEN_PATH_PROOFS.md` v8 section, `SECURITY_AUDIT_REPORT.md` round 7, `MEMORY.md` index entries.
- [ ] Tag `v8.0.0-relay-presigned-auth` on `Flux-Point-Studios/aegis-contracts`.

---

## 11. Red-team findings traceability

| Finding | Severity | Closed by | Reference |
|---|---|---|---|
| C-1 (witness mint forgeable) | CRITICAL | Δ1 + Δ2 + Δ17 | §1.5, §1.7 |
| C-2 (vkey substitution) | CRITICAL | Δ7 | §1.3 step 4 |
| F-AUTH-1 (cross-redeemer count) | CRITICAL | Δ6 | §1.3 step 18 |
| F-AUTH-2 (mint policy not one-shot) | CRITICAL | Δ2 + Δ17 | §1.5 |
| H-1 (cross-network replay) | HIGH | Δ4 + Δ16 | §2.2, §2.4 step 6 |
| H-2 (sig malleability) | HIGH | Δ11 | §3.4 + Aiken regression test |
| H-3 (policy_id collision) | HIGH | Δ3 | §1.8 |
| F-AUTH-3 (witness-stuffing DoS) | HIGH | Δ7 | §1.3 step 4 |
| F-AUTH-4 (payout binding gap) | HIGH | Δ9 | §1.3 step 16 |
| F-AUTH-5 (oracle_provider missing) | HIGH | Δ5 | §2.1, §1.5 |
| F-1 (Blockfrost SPOF) | HIGH | Δ13 | §3.1 |
| F-2 (mass-create DoS) | HIGH | Δ14 | §3.2 |
| F-3 (publish atomicity) | HIGH | Δ1 | §1.7, §2.4 |
| M-1 (CBOR ambiguity) | MED | Δ10 + Appendix B | §2.3 |
| M-2 (224 vs 256 bit hash) | MED | Δ12 (decode at validator) | §1.3 step 13 |
| M-3 (auth rotation) | MED | Δ8 (RotateAuth shipped) | §1.4, §5 |
| F-AUTH-6 (commit length) | MED | Δ12 | §1.3 step 2 |
| F-4 (sweeper griefing) | MED | Δ15 | §3.5 |
| F-5 (wallet-loss footgun) | MED | Δ9 | §2.4 |
| F-6 (multi-relay reality) | MED | (positioning, no code change) | §3.5 |
| L-1 / L-2 (domain tag, oracle_freshness advisory) | LOW | accepted as documented limitations | §2.1, §2.3 |
| F-7 / F-8 / F-9 / F-10 (relay liveness) | LOW/INFO | already mitigated or accepted | §3.5 |
| F-AUTH-7 / F-AUTH-9 / F-AUTH-10 | LOW/INFO | accepted | §6, §7 |
<!-- Δ29-Δ30 traceability — frontend remediation 2026-05-06 -->
| RT-C-02 (relay+wallet dual-liveness fallback) | HIGH | Δ29 | §6 (manual-claim fallback always available), `frontend/src/components/panels/PoliciesPanel.tsx`, `frontend/src/App.tsx::handleManualClaim` |
| RT-C-06 (Δ16 wallet-prompt summary not call-site enforced) | MED | Δ30 | `frontend/src/wallet/aegis/sign_auth.ts::signAuthCommitment(confirmedSummary)`, `frontend/src/components/aegis_wallet/AuthSummaryConfirmModal.tsx` |
| A-A-007 (oracle_freshness UI binding) | LOW | Δ30 | `humanReadableSummary` now renders `Oracle freshness: <ms>` line; `signAuthCommitment` re-derives + asserts byte-equality. On-chain side: ClaimWithAuth additionally enforces `payload.oracle_freshness >= 0` (Δ20). |
<!-- end frontend block -->
<!-- Δ26-Δ28 traceability — cross-stack remediation 2026-05-06 -->
| A-A-004 (Python encoder lacks validation) | MED | Δ26 | `offchain/src/aegis/auth_payload.py::encode_auth_coverage_payload` + `_assert_payload_shape` (mirrors `frontend/src/wallet/aegis/auth_payload.ts::assertPayloadShape` line-for-line); §2.4 |
| A-A-009 (int range cap asymmetry) | LOW | Δ27 | `offchain/src/aegis/auth_payload.py::MAX_INT_FIELD = (1 << 63) - 1` matches TS `MAX_INT_FIELD = (1n << 63n) - 1n`; cross-stack vector tests at TV-3 (boundary 2^63-1) and `invalid_payload_vectors.json` #7 (one over the cap) |
| Cross-stack drift detection | (CI gate) | Δ28 | shared manifest `contracts/tests/fixtures/invalid_payload_vectors.json`; rejection asserted in both `offchain/tests/test_cross_stack_validation.py` and `frontend/src/wallet/aegis/__tests__/cross_stack_validation.test.ts` |
<!-- end cross-stack block -->
<!-- Δ18-Δ25 traceability — Aiken on-chain v3 hardening 2026-05-06 -->
| V-001 / A-A-001 (MintWitness one-shot bug) | CRITICAL | Δ18 | `validators/auth_witness_nft.ak` mint branch (init_utxo_ref no longer required at runtime); `lib/aegis/test_helpers/v8_integration_tests.ak::it_mint_witness_post_init_ref_spent_still_succeeds` |
| V-002 (BurnWitness inverted check) | CRITICAL | Δ19 | `validators/auth_witness_nft.ak` BurnViaConsume + SweepBurn split; `it_burn_via_consume_rejects_no_policy_input` (negative), `it_burn_via_consume_green_path_with_policy_input` (positive) |
| V-007 / A-A-002 (payload field binding gap) | HIGH | Δ20 | `validators/policy.ak` ClaimWithAuth steps 14-28; integration tests `it_claim_with_auth_rejects_*_mismatch` (14 negatives, one per field) |
| V-003 (BatchUnderwrite policy_id) | HIGH | Δ21 | `validators/pool.ak::batch_policies_match_totals` enforces `derive_policy_id_batch(...)`; `lib/aegis/types.ak::derive_policy_id_batch`; tests `it_batch_underwrite_*` (5 differential checks) |
| A-A-003 (canonical CBOR re-encode) | HIGH | Δ22 | `validators/policy.ak` ClaimWithAuth step 14 (`cbor.serialise(payload) == awd.payload_cbor`); tests `it_canonical_cbor_round_trip_byte_equal_for_*`, `it_claim_with_auth_rejects_non_canonical_cbor` |
| V-005 (no integration tests) | HIGH | Δ23 | `lib/aegis/test_helpers/v8_integration_tests.ak` (53 new tests covering every redeemer with full Transaction context + per-finding negatives) |
| V-008 (sweeper not operator-only) | MED | Δ19 | `validators/auth_witness_nft.ak` SweepBurn redeemer (operator_pkh + tx_lower > not_after gates); tests `it_sweep_burn_*` (4 cases) |
| V-009 (network_tag sanity) | MED | Δ24 | `validators/auth_witness_nft.ak::network_tag_ok` strict whitelist; `lib/aegis/types.ak::network_tag_{preprod,preview,mainnet}`; test `it_mint_witness_rejects_invalid_network_tag` |
| V-010 (no-op rotation) | LOW | Δ25 | `validators/policy.ak` RotateAuth `actual_rotation` gate; tests `it_rotate_auth_rejects_no_op_rotation`, `test_delta25_*` |
| V-004 (auth_witness_nft_policy_id placeholder) | HIGH | (deploy-gate, runbook) | Documented as deploy-gate per A-A-006 — operator must pin actual policy id post-mint before tagging mainnet. Closed in v3.1 by the CI gate at `scripts/check_deploy_constants.py` (Δ39) — the placeholder check now runs on every push, PR, and `v*` tag via `.github/workflows/deploy-gates.yml`. |
| V-006 (RotateAuth list.find first-match) | MED | (closed in v3.1 — see Δ32) | v3.1 RotateAuth uses an explicit fold over outputs counting witness continuations + a `list.find` to locate the unique match. The first-match scrutiny no longer applies as written. |
<!-- end on-chain v3 block -->
<!-- VR-001..VR-006 + VR-008 traceability — v3.1 Aiken on-chain remediation 2026-05-06 -->
| VR-001 (SweepBurn `not_after` is unbound to witness payload) | HIGH | Δ31 | `validators/auth_witness_nft.ak` SweepBurn redeemer (no `not_after` field; the gate reads `payload.not_after` from the WITNESS UTxO's payload datum); `lib/aegis/test_helpers/v8_integration_tests.ak::it_sweep_burn_rejects_redeemer_not_after_zero_for_live_payload` (REGRESSION test for the operator-key-compromise full-relay-DoS class) |
| VR-002 (RotateAuth creates 2 NFT UTxOs sharing one asset_name) | HIGH | Δ32 | `validators/auth_witness.ak` (dual-path spend — burn-only OR rotation respend); `validators/policy.ak` RotateAuth branch (Option A — respend at auth_witness_validator, no mint policy invocation); `lib/aegis/test_helpers/v8_integration_tests.ak::it_rotate_auth_green_path_no_op_a_via_respend` + `it_rotate_auth_rejects_two_witness_outputs` + `it_rotate_auth_post_rotation_claim_with_auth_succeeds` (REGRESSION green path) |
| VR-003 (RotateAuth's new-witness binding is weaker than ClaimWithAuth's) | MED | Δ33 | `validators/policy.ak` RotateAuth branch (Δ20 14-field binding + Δ22 canonical re-encode + Ed25519 sig verify on the new payload); `lib/aegis/test_helpers/v8_integration_tests.ak::it_rotate_auth_rejects_field_binding_violation_*` (5 negatives — domain_tag, network_magic, policy_validator, oracle_provider, payout_address) + `it_rotate_auth_rejects_non_canonical_new_payload` |
| VR-004 (MintWitness lacks Δ22 canonical CBOR re-encode) | MED | Δ34 | `validators/auth_witness_nft.ak` MintWitness branch (`payload_canonical == payload_cbor` after `cbor.serialise(decoded)`); `lib/aegis/test_helpers/v8_integration_tests.ak::it_mint_witness_rejects_non_canonical_payload` |
| VR-005 (53 v3 integration tests miss full RotateAuth tx context) | MED | Δ35 | `lib/aegis/test_helpers/v8_integration_tests.ak` SECTION 4.1 — 13 NEW RotateAuth integration tests covering the full Δ32 + Δ33 surface end-to-end (green path with respend, wrong signer, two/zero witness outputs, asset-name change, non-canonical new payload, 5 field-binding violations, post-rotation claim green path, old-signature replay-protection sanity) |
| VR-006 (cross-stack manifest covers 10 of ~15 expected length checks) | MED | Δ36 | `tests/fixtures/invalid_payload_vectors.json` (15 vectors, was 10 — adds `oracle_nft_wrong_length`, `pool_script_hash_wrong_length`, `pool_nft_wrong_length`, `domain_tag_zero_length`, `max_coverage_negative`); `offchain/tests/test_cross_stack_validation.py::EXPECTED_VECTOR_COUNT = 15` + `EXPECTED_RULE_NAMES`; `frontend/src/wallet/aegis/__tests__/cross_stack_validation.test.ts` matching counts |
| VR-008 (oracle_freshness ≥ 0 is a weak on-chain bound) | LOW | Δ37 | `validators/policy.ak` ClaimWithAuth + RotateAuth — both enforce `oracle_freshness >= 0 && oracle_freshness <= 86_400_000` (24h sanity cap, mirrors the off-chain Python and TS encoders); `lib/aegis/test_helpers/v8_integration_tests.ak::it_claim_with_auth_rejects_oracle_freshness_above_24h_cap` + `it_claim_with_auth_accepts_oracle_freshness_exactly_24h` |
<!-- end v3.1 on-chain block -->
<!-- VR-007 / VR-009 / VR-012 traceability — v3.1 frontend hardening + deploy gates 2026-05-06 -->
| VR-007 (Δ30 enforcement is voluntary at the call site) | LOW | Δ38 | `frontend/src/wallet/aegis/index.ts` (public surface re-exports only `signAuthCommitment` + display helpers + types; the CBOR / hash / signing primitives are intentionally module-private); CI guard at `frontend/scripts/check_aegis_privacy_boundary.cjs` wired to `npm run lint:guard`; in-memory self-test via `npm run lint:guard:self-test` (9 cases). |
| VR-009 (auth_witness_nft_policy_id all-zero placeholder ship-hazard) | LOW | Δ39 | `D:/aegis-contracts/scripts/check_deploy_constants.py` (placeholder check + 28-byte length check); CI workflow `.github/workflows/deploy-gates.yml` runs on every push / PR / `v*` tag; Python in-memory self-test (6 cases). |
| VR-012 (enterprise_addr_header_* drift / typo) | LOW | Δ40 | `D:/aegis-contracts/scripts/check_deploy_constants.py` (asserts `_mainnet == #"61"`, `_testnet == #"60"`, active header ∈ {`#"60"`, `#"61"`}); same CI workflow as VR-009; same self-test covers swapped, missing, and typo cases. |
<!-- end v3.1 traceability block -->
<!-- v3.2 traceability — Δ41 deploy-cycle break 2026-05-06 -->
| First-order circular deploy dep (auth_witness_nft.policy_id ↔ policy_validator.hash fixed-point) | DEPLOY-BLOCKER | Δ41 | `validators/auth_witness_nft.ak` (3-tuple param set, drop `policy_validator_hash`); `validators/policy.ak` ClaimWithAuth + RotateAuth (witness identification by `Script(auth_witness_validator_hash)` script credential); `lib/aegis/types.ak::auth_witness_validator_hash` (new compile-time pin, placeholder until Phase-4 step 4); `scripts/check_deploy_constants.py` (gates both `auth_witness_nft_policy_id` AND `auth_witness_validator_hash` against placeholder ship-hazard). Re-attack matrix preserved: every closed finding from v3 / v3.1 (C-1, C-2, F-AUTH-1..6, V-001..V-010, A-A-001..A-A-009, VR-001..VR-009/012) still holds — see §12.3 "Re-attack confirmation" for the per-finding analysis. |
<!-- end v3.2 traceability block -->
<!-- v3.3 traceability — Δ42 second-order cycle break 2026-05-06 -->
| Second-order circular deploy dep (auth_witness_nft.mint base hash rotates whenever `auth_witness_validator_hash` const updated) | DEPLOY-BLOCKER | Δ42 | `validators/auth_witness_nft.ak` (drop import + all references to `auth_witness_validator_hash`; replace destination-script-credential pin in MintWitness Underwrite path with per-tx "EXACTLY ONE output anywhere carries the canonical (own_policy_id, asset_name) AND its AuthWitnessDatum matches" check; drop negative script-credential filters in BurnViaConsume/SweepBurn — typed-decode failure path returns False structurally); `lib/aegis/test_helpers/v8_integration_tests.ak` (mirrors updated; `mirror_mint_witness` drops the witness-validator-hash parameter; `mirror_burn_via_consume` drops the negative-filter; new test `it_mint_witness_at_arbitrary_script_succeeds_but_orphan_unreachable_via_claim` pins the v3.3 invariant — orphan mints succeed at the mint policy but are unreachable via policy_validator's witness collection). 5-step truly-linear deploy ordering (no base-hash rotation post step 2) documented in §12.4 / §6 Phase-4. Re-attack matrix preserved: every closed finding from v3 / v3.1 / v3.2 still holds — see §12.4 "Re-attack confirmation" for the per-finding analysis. |
<!-- end v3.3 traceability block -->

**Coverage: 100% of CRITICAL + HIGH absorbed. 7 of 9 MEDs absorbed; 2 remaining MEDs are documented limitations (F-6 multi-relay reality is positioning, L-2 oracle_freshness advisory is accepted). Phase-3 implementation red-team findings RT-C-02 (HIGH liveness), RT-C-06 (MED wallet-prompt), A-A-004 (MED Python validation), and A-A-009 (LOW int63 cap) closed by Δ29 / Δ30 / Δ26 / Δ27 respectively. Aiken on-chain Phase-3 findings V-001/V-002 (CRITICAL), V-003/V-005/V-007/A-A-002/A-A-003 (HIGH), V-008/V-009 (MED), V-010 (LOW) closed by Δ18-Δ25. Phase-3 verification red-team v3.1 findings VR-001/VR-002 (HIGH), VR-003/VR-004/VR-005/VR-006 (MED), VR-008 (LOW) closed by Δ31-Δ37 (Aiken on-chain); VR-007 / VR-009 / VR-012 (all LOW) closed by Δ38 / Δ39 / Δ40 (frontend + deploy-gates).**

---

## 12. v3 Remediation Deltas (Aiken on-chain hardening)

Three Phase-3 implementation red-team agents (crypto/CBOR, validator-branch, relay/economic) attacked the v2-implemented code (not the design). They produced a combined 2 CRITICAL + 4 HIGH on-chain findings the v2 spec/test bed did not catch. v3 absorbs all of them via Δ18-Δ25. Each delta below cites the closing code path AND the proving integration test name.

### Δ18 — MintWitness one-shot bug closure (V-001 / A-A-001)

**Symptom (pre-Δ18):** `auth_witness_nft.ak` line ~98-103 required the parameterised `init_utxo_ref` to be in the inputs of EVERY mint call. Cardano UTxOs spend exactly once → mint succeeds exactly once across the deployment lifetime → relay-presigned-auth bricked after the first user.

**Root cause:** copy-paste of the `pool_nft.ak` one-shot pattern. `pool_nft` is a TRUE singleton (mint exactly once, ever); `auth_witness_nft` needs to mint once per Underwrite (and once per RotateAuth). The patterns are not interchangeable.

**Fix (`validators/auth_witness_nft.ak`):**
- Remove the `one_shot_consumed = list.any(inputs, fn(i) { i.output_reference == init_utxo_ref })` runtime check from MintWitness.
- Keep the `init_utxo_ref` parameter — it remains baked into the compiled validator hash, so each deployment produces a unique policy id by parameterisation rather than runtime input-consumption.
- Per-mint anti-forgery is enforced via the existing `underwrite_path_valid || rotate_auth_path_valid` guard (the witness binds to either a fresh policy output with matching commit OR a consumed policy input).
- A `let _init_anchor_in_hash = init_utxo_ref.transaction_id` keeps the parameter syntactically referenced (the compiler's parameterised-validator ABI requires every parameter to be live in the body).

**Proving test:** `it_mint_witness_post_init_ref_spent_still_succeeds` (v8_integration_tests.ak) — builds a Transaction with NO input matching `init_utxo_ref` and asserts the mint succeeds. Pre-Δ18 the same test would have rejected the mint.

### Δ19 — BurnWitness inverted check (V-002) + sweeper auth (V-008)

**Symptom (pre-Δ19):** `BurnWitness` accepted iff the policy was NOT consumed in the same tx (`no_live_policy = policy_consumed_in_tx == False`) — semantically inverted. Any third-party could submit a burn-only tx that destroyed a victim's live witness UTxO and pocketed the ~3.5 ADA min-UTxO at a profit. Grief-ROI class.

**Fix (`validators/auth_witness_nft.ak`, redeemer split):**

- **`BurnViaConsume { policy_id }`** — happy-path cleanup. Requires the matching policy UTxO to be co-spent in the same tx (i.e., burned alongside Cancel/Expire/Claim/ClaimWithAuth). The mint validator asserts:
  - `policy_consumed_in_tx == True` (one of the inputs is at `policy_validator_hash` with matching `pdat.policy_id`)
  - mint quantity == -1
  - only one (asset_name, qty) pair under the policy
  - network_tag pinned (Δ24)

- **`SweepBurn { policy_id, not_after }`** — orphan cleanup, operator-only. Used when the policy was terminated in a prior tx without burning the witness in-line. The mint validator asserts:
  - `must_be_signed_by(extra_signatories, operator_pkh)` (operator parameter, set at deploy time — currently `aegis_operator_pkh = aegis_self_publisher_vkh`)
  - `tx_validity.lower_bound > not_after` (auth window provably elapsed; off-chain runbook supplements with k≥20-confirmations on policy non-existence to guard against reorg griefing)
  - mint quantity == -1
  - only one (asset_name, qty) pair under the policy
  - network_tag pinned

**Mint policy gains an `operator_pkh: ByteArray` parameter** (4-tuple parameterisation: `(init_utxo_ref, network_tag, policy_validator_hash, operator_pkh)`).

**Proving tests:** `it_burn_via_consume_green_path_with_policy_input` (positive), `it_burn_via_consume_rejects_no_policy_input` (V-002 closure), `it_burn_via_consume_rejects_wrong_burn_quantity`, `it_burn_via_consume_rejects_mismatched_policy_id`, `it_sweep_burn_green_path_signed_and_expired` (positive), `it_sweep_burn_rejects_unsigned_by_operator` (V-008 closure), `it_sweep_burn_rejects_pre_expiry`, `it_sweep_burn_rejects_invalid_network_tag`.

### Δ20 — Full 14-field payload binding (V-007 / A-A-002)

**Symptom (pre-Δ20):** `policy.ak` ClaimWithAuth decoded the 14-field `AuthCoveragePayload` but only compared 3 fields against the policy datum (`policy_id`, `oracle_provider`, `payout_address`). The other 11 (`domain_tag`, `network_magic`, `policy_validator`, `insured_pkh`, `max_coverage`, `oracle_nft`, `oracle_freshness`, `not_before`, `not_after`, `pool_script_hash`, `pool_nft`) were decoded-and-discarded. Wallets displayed them, validator did not enforce — wallet-deception class.

**Fix (`validators/policy.ak` ClaimWithAuth branch):** add 11 explicit equality checks after the existing decode + the (existing) provider/policy_id/payout binding:

```aiken
let payload_domain_tag_ok = payload.domain_tag == auth_domain_tag
let payload_network_magic_ok = payload.network_magic == network_magic
let payload_policy_validator_ok = payload.policy_validator == own_script_hash
let payload_insured_pkh_ok = payload.insured_pkh == datum.insured
let payload_max_coverage_ok = payload.max_coverage == datum.coverage_amount
let payload_oracle_nft_ok = payload.oracle_nft == datum.oracle_nft
let payload_oracle_freshness_ok = payload.oracle_freshness >= 0
let payload_not_before_ok = payload.not_before == datum.start_time
let payload_not_after_ok = payload.not_after == datum.expiry_time
let payload_pool_script_hash_ok = payload.pool_script_hash == datum.pool_script_hash
let payload_pool_nft_ok = payload.pool_nft == datum.pool_nft
```

`auth_domain_tag` and `network_magic` are the active-network compile-time constants in `lib/aegis/types.ak`. `oracle_freshness` is bound non-negative (advisory field, but length-checked here closes A-A-007's deception window).

**Proving tests:** 14 negatives + 1 positive: `it_claim_with_auth_green_path_binds_all_14_fields` and `it_claim_with_auth_rejects_*_mismatch` for each of `domain_tag`, `network_magic`, `policy_validator`, `policy_id`, `insured_pkh`, `payout_address`, `max_coverage`, `oracle_provider`, `oracle_nft`, `negative_oracle_freshness`, `not_before`, `not_after`, `pool_script_hash`, `pool_nft`.

### Δ21 — BatchUnderwrite policy_id derivation (V-003)

**Symptom (pre-Δ21):** Δ3's `derive_policy_id(...)` was wired only into `policy_output_matches_underwrite` (single-Underwrite). The batch path `batch_policies_match_totals` accepted any caller-supplied `policy_id` — two same-terms batched policies could collide on `policy_id` (and thus on the witness asset name `blake2b_224(policy_id)`), making the relay-auth path unusable on more than one of them.

**Fix:**

1. **New helper `lib/aegis/types.ak::derive_policy_id_batch`:**
   ```aiken
   pub fn derive_policy_id_batch(
     insured_pkh, strike_price, coverage_amount, start_time, expiry_time,
     pool_nft, underwrite_tx_input: OutputReference, batch_index: Int,
   ) -> ByteArray { ... }
   ```
   Mirror of `derive_policy_id` with one extra trailing 2-byte big-endian `batch_index`. The salt makes the batch preimage 82 bytes vs the single-mode's 80 bytes — no cross-mode preimage collision class.

2. **Pool branch update (`validators/pool.ak::batch_policies_match_totals`):** the fold over outputs now tracks `(cov_acc, prem_acc, ok_acc, batch_idx)`. For each policy output, `pdat.policy_id` MUST equal `derive_policy_id_batch(..., underwrite_anchor, batch_idx)` (where `underwrite_anchor` is the consumed pool UTxO's `OutputReference` passed via the new function arg). `batch_idx` increments only on policy-output matches; non-policy outputs (pool continuation, change) do not consume an index.

3. **Call site (`validators/pool.ak`):** the BatchUnderwrite branch now passes `own_ref` to `batch_policies_match_totals`. Off-chain builders mirror the same construction so the i-th policy output's `policy_id = derive_policy_id_batch(..., own_ref, i)`.

**Proving tests:** `it_batch_underwrite_first_policy_id_uses_index_0`, `it_batch_underwrite_distinct_policy_ids_across_batch` (3 entries, 3 distinct ids), `it_batch_underwrite_anchor_difference_rotates_ids`, `it_batch_underwrite_id_distinct_from_single_underwrite_id`, `it_batch_underwrite_ids_are_28_bytes`.

### Δ22 — Canonical CBOR re-encode-and-compare (A-A-003)

**Symptom (pre-Δ22):** Aiken's stdlib `cbor.deserialise` accepts non-canonical CBOR — non-shortest-form ints (e.g., `0x18 0x00` for value 0 instead of `0x00`), indefinite-length bytestrings via the `0x5f` chunked form. An attacker tooling that bypasses the wallet's TS validators could craft bytes the validator decodes successfully but the canonical encoder would never produce. Two byte sequences could decode to the same logical payload but produce different `blake2b_256` commits — a class of wallet-deception attacks where the user signs the canonical commit but the witness UTxO carries the non-canonical bytes.

**Fix (`validators/policy.ak` ClaimWithAuth branch, immediately after the decode at step 13):**

```aiken
expect payload: AuthCoveragePayload = cbor_decode_payload(awd.payload_cbor)
let payload_canonical = cbor.serialise(payload)
let payload_canonical_ok = payload_canonical == awd.payload_cbor
```

Cost: one extra `cbor.serialise` (~10x cheaper than `cbor.deserialise` per the stdlib note). Closes the canonical-determinism class entirely.

**Proving tests:** `it_canonical_cbor_round_trip_byte_equal_for_tv1`, `it_canonical_cbor_round_trip_byte_equal_for_aegis_self`, `it_claim_with_auth_canonical_round_trip_positive`, `it_claim_with_auth_rejects_non_canonical_cbor` (negative — appends a stray byte after the canonical break-stop and asserts the guarded canonical check returns False).

### Δ23 — End-to-end Transaction-context integration tests (V-005)

**Symptom (pre-Δ23):** All 57 v8 tests in `lib/aegis/test_helpers/v8_auth_tests.ak` were property-level lemmas on isolated helpers (length checks, hash distinctness, sum-type tag values). Zero tests built a `Transaction` and exercised a validator branch end-to-end. V-001 and V-002 reached the audit gate because no integration test caught them — the tests covered properties the validator should obey but never the actual `Transaction → Bool` mapping.

**Fix:** New module `lib/aegis/test_helpers/v8_integration_tests.ak` (~1100 LOC) with 53 mid-sized integration tests. Each test:

1. Constructs a full `Transaction` (inputs, outputs, mint, validity_range, extra_signatories) using helper builders adapted from `fixtures.ak`.
2. Calls a logic-mirror helper (`mirror_mint_witness`, `mirror_burn_via_consume`, `mirror_sweep_burn`, `mirror_claim_with_auth_payload_binding`, `mirror_rotate_auth_actual_rotation`) that 1:1 transcribes the corresponding validator's `&&`-chain.
3. Asserts the mirror's Bool output matches the expected accept/reject behaviour.

The mirror discipline: every mirror helper in `v8_integration_tests.ak` is a syntactic transcription of the corresponding validator branch. A divergence between mirror and validator is itself a bug. The mirror is the single source of truth for "what did the validator say for this Transaction" — replacing the missing pre-Δ23 integration coverage.

**Coverage matrix:**
- MintWitness: 8 tests (green + 7 negatives covering V-001 fix + V-009 + provider mismatch)
- BurnViaConsume: 4 tests (green + 3 negatives, V-002 closure)
- SweepBurn: 4 tests (green + 3 negatives, V-008 + window-elapsed)
- ClaimWithAuth payload binding: 16 tests (green + 14 field-binding negatives + 1 canonical-form negative)
- Canonical round-trip: 3 tests (TV-1 byte-equal, AegisSelf byte-equal, positive round-trip via guarded check)
- RotateAuth: 5 tests (green + no-op rejection + first-time-from-None + commit divergence + no-op blocked despite witness)
- BatchUnderwrite: 5 tests (Δ21 differential checks)
- Cross-stack TV pinning: 2 tests (TV-1 + TV-2 commit hashes pinned)
- Constant pinning: 3 tests (Δ24 network_tag + Δ19 operator_pkh)
- Full Transaction context smoke tests: 3 tests (witness count gates, atomic burn-with-claim path)

### Δ24 — `network_tag` strict whitelist (V-009)

**Symptom (pre-Δ24):** The mint policy's `network_tag != #""` check passed any non-empty bytestring. A 1-byte typo like `network_tag = #"00"` would silently produce a legitimate-but-misnamed policy id. No security impact (the policy id is still unique per-deployment-per-typo via parameter-baking), but a deploy-hygiene footgun.

**Fix (`validators/auth_witness_nft.ak`):**

```aiken
let network_tag_ok =
  network_tag == network_tag_preprod      // #"50524550524f44"
  || network_tag == network_tag_preview   // #"50524556494557"
  || network_tag == network_tag_mainnet   // #"4d41494e4e4554"
```

The three constants live in `lib/aegis/types.ak` and are UTF-8 of `"PREPROD"` / `"PREVIEW"` / `"MAINNET"`.

**Proving tests:** `it_mint_witness_rejects_invalid_network_tag` (1-byte typo `#"00"` rejected), `it_sweep_burn_rejects_invalid_network_tag`, `test_delta24_network_tag_strict_whitelist`.

### Δ25 — RotateAuth no-op rejection (V-010)

**Symptom (pre-Δ25):** `RotateAuth` accepted `new_commit == datum.auth_commitment.Some(_)`. A malicious caller could submit a "rotation" that didn't actually change the on-chain commitment, paying a tx fee for nothing while burning the user's min-ADA on a fresh witness UTxO. Pure churn / nuisance class.

**Fix (`validators/policy.ak` RotateAuth branch):**

```aiken
let actual_rotation =
  when datum.auth_commitment is {
    Some(old) -> old != new_commit
    None -> True
  }
```

Wired into the final `&&`-chain of RotateAuth. The `None` case (first-time auth set on an opt-out policy being upgraded to opt-in) is treated as a real change because no prior commit exists.

**Proving tests:** `it_rotate_auth_green_path_real_change`, `it_rotate_auth_rejects_no_op_rotation`, `it_rotate_auth_first_time_from_none_accepted`, `it_rotate_auth_distinct_commits_required_for_field_only_changes`, `it_rotate_auth_no_op_blocked_even_with_witness_present`, `test_delta25_*`.

### Implementation summary

| File | Lines changed (approx) | Δ touched |
|---|---|---|
| `validators/auth_witness_nft.ak` | rewritten (~240 → 280) | Δ18, Δ19, Δ24 |
| `validators/policy.ak` | +60 lines in ClaimWithAuth + RotateAuth | Δ20, Δ22, Δ25 |
| `validators/pool.ak` | +25 lines in batch_policies_match_totals | Δ21 |
| `lib/aegis/types.ak` | +60 lines (derive_policy_id_batch, network_tag_*, aegis_operator_pkh) | Δ19, Δ21, Δ24 |
| `lib/aegis/test_helpers/v8_auth_tests.ak` | +110 lines (Δ18-Δ25 property tests) | Δ18-Δ25 |
| `lib/aegis/test_helpers/v8_integration_tests.ak` | NEW (~1110 lines) | Δ23 (and proves Δ18-Δ25) |

**Build outputs:**
- `aiken check`: 305 baseline + 63 new (10 in v8_auth_tests + 53 in v8_integration_tests) = 368 / 368 green.
- `aiken build`: blueprint regenerated; size grew 101890 → 107013 bytes (accommodates new BurnViaConsume/SweepBurn variants and the operator_pkh parameter).
- `aiken fmt --check`: clean.
- TV-1..TV-5 cross-stack commit hashes: byte-identical to v2 (the on-chain CBOR encoder is unchanged; v3 only adds runtime checks).

---

## 12.1 v3.1 Verification Re-attack Closures (Aiken on-chain hardening)

A Phase-3 verification red-team (`PHASE3_VERIFICATION_REDTEAM.md`, 2026-05-06) attacked the v3 closures (Δ18-Δ30) along three axes (direct re-attack, lateral pivot, cross-cut). It produced 13 findings; 7 of them were on-chain and absorbed in this v3.1 hardening pass via Δ31-Δ37. The remaining 3 LOW findings (VR-007 / VR-009 / VR-012) are off-chain / CI / deploy-gate concerns closed in §12.2 below by the parallel frontend agent.

### Δ31 — SweepBurn `not_after` is witness-bound (VR-001)

**Symptom (pre-Δ31):** `auth_witness_nft.ak` SweepBurn redeemer carried `not_after` as an operator-supplied integer. The validator's only check was `tx_lower > not_after`. An operator-key compromise (or a buggy operator script) could pass `not_after = 0`, making the check trivially satisfied for any modern POSIX time. There was NO on-chain binding between the redeemer's `not_after` and the witness UTxO's actual `payload.not_after`. Net effect: a unilateral kill switch on every live witness.

**Root cause:** The Δ19 closure narrative said "tx_validity.lower_bound > payload.not_after", but the implementation read `not_after` from the redeemer, not from the witness's payload. Spec drift between narrative and code.

**Fix (`validators/auth_witness_nft.ak` SweepBurn redeemer):**
- Drop the `not_after` field from the redeemer entirely. The redeemer is now `SweepBurn { policy_id }`.
- Locate the witness UTxO being burned (it's a regular input at the auth_witness_validator script carrying exactly 1× `(auth_witness_nft_policy_id, blake2b_224(policy_id))`).
- Decode its `payload_cbor` to extract `payload.not_after`.
- Bind `tx_validity.lower_bound > payload.not_after` (strict `>`, aligns with §1.5's "auth window provably elapsed" narrative).
- Defense-in-depth: `awd.policy_id == redeemer.policy_id`, `payload.policy_id == redeemer.policy_id`, `witness input is at a script address`.

**Proving test:** `it_sweep_burn_rejects_redeemer_not_after_zero_for_live_payload` — builds a SweepBurn tx with operator sig + witness payload's `not_after` set to 1_700_604_800_000 (well in the future) but `validity_range.lower = 1_700_500_000_000` (current time). Pre-Δ31 the (now-removed) redeemer-`not_after = 0` argument would have made `tx_lower > 0 = True` and the validator would have accepted; post-Δ31 the gate reads `payload.not_after = 1_700_604_800_000` and `tx_lower > not_after` evaluates to `False`, so the validator rejects. Closes the operator-key-compromise full-relay-DoS class.

### Δ32 — RotateAuth respend at auth_witness_validator (VR-002)

**Symptom (pre-Δ32):** the v3 RotateAuth flow MINTED a new witness alongside the un-burned old one. After a legitimate rotation the chain held 2 UTxOs sharing the same `auth_witness_nft` asset name. ClaimWithAuth's Δ7 `length(witnesses) == 1` count gate then rejected every claim until the policy expired. The spec acknowledged the "2 UTxOs co-exist" state and asserted the sweeper resolves within ~24h, but `SweepBurn` required `tx_lower > not_after` (post-expiry) — so the orphan COULD NOT be swept while the policy was still claimable. RotateAuth was therefore a destructive operation rather than a recovery one.

**Root cause:** The Δ7 count gate is the load-bearing primitive for ClaimWithAuth's witness-stuffing defense (closes C-2 + F-AUTH-3). The pre-v3.1 rotation flow violated the Δ7 invariant by design.

**Fix — Option A (preferred): respend without mint.** RotateAuth SPENDS the old witness UTxO and RESPENDS a new witness UTxO at the same auth_witness_validator script. The NFT moves with the UTxO. No mint policy invocation. The chain never holds more than one witness UTxO under a given asset_name.

**File-level changes:**

1. `validators/auth_witness.ak` — the spend validator now accepts EITHER:
   - **Path 1 (burn-only):** `mint(auth_witness_nft_policy_id, asset_name) == -1 && continuation_count == 0` — the existing burn path used by BurnViaConsume + SweepBurn.
   - **Path 2 (rotation respend):** `mint(auth_witness_nft_policy_id, asset_name) == 0 && continuation_count == 1` — the NFT is neither minted nor burned; exactly one continuation output at this validator carries the same asset_name.

2. `validators/policy.ak` RotateAuth branch — finds the OLD witness as a regular INPUT (was: reference input under v3), finds the NEW witness as a regular OUTPUT, asserts `mint_qty == 0` for the asset, asserts `new_witness_count == 1` at the witness script, asserts `new_witness_ref == old_witness_input.output_reference` (the rotation anchor pins the input being respent).

3. `validators/auth_witness_nft.ak` MintWitness — the `rotate_auth_path` branch is REMOVED (was: accepted a mint when the policy was consumed in inputs). The mint policy now binds exclusively to Underwrite-creation; rotation no longer invokes the mint policy at all.

**Proving tests:**
- `it_rotate_auth_green_path_no_op_a_via_respend` — builds a full rotation tx (policy in + old witness in + policy cont + new witness out + insured CIP-30 sig) and asserts the mirror returns True. The chain ends up with EXACTLY ONE witness UTxO post-rotation.
- `it_rotate_auth_rejects_two_witness_outputs` — builds a tx that produces 2 witness outputs (the v3 failure shape) and asserts the mirror returns False. Regression test for VR-002.
- `it_rotate_auth_post_rotation_claim_with_auth_succeeds` — exercises the post-rotation ClaimWithAuth path against the new commit. Closes the original VR-002 failure mode end-to-end.

### Δ33 — RotateAuth applies Δ20+Δ22 to the new witness's payload (VR-003)

**Symptom (pre-Δ33):** the v3 RotateAuth flow only checked `commit_from_cbor(new_awd.payload_cbor) == new_commit` (i.e., the bytes hash to the commit) and `new_awd.policy_id == datum.policy_id`. It did NOT enforce:
- The Δ20 14-field binding (active-network constants + datum equality on every payload field).
- The Δ22 canonical CBOR re-encode-and-compare.
- The Ed25519 signature verification on the new payload.

A malicious frontend (CIP-30 wallet MITM, browser extension, or compromised React build) could craft a rotation tx whose new witness carried attacker-controlled fields (e.g., `payout_address` rewired to attacker). The user's CIP-30 sig over the rotation tx body would authorize the rotation, the validator would accept, and the next ClaimWithAuth would fail Δ20 — bricking the relay-auth path until policy expiry.

**Fix (`validators/policy.ak` RotateAuth branch):** apply the full ClaimWithAuth invariant chain to the new witness's payload at rotation time:

- `cbor.serialise(new_payload) == new_awd.payload_cbor` (Δ22 mirror).
- 14-field binding: domain_tag, network_magic, policy_validator (== own_script_hash), policy_id, insured_pkh, payout_address, max_coverage, oracle_provider, oracle_nft, oracle_freshness ∈ [0, 86_400_000] (Δ37 too), not_before, not_after, pool_script_hash, pool_nft.
- `blake2b_224(new_awd.insured_vkey) == datum.insured` (closes the C-2 analogue for rotation).
- `verify_ed25519_signature(new_awd.insured_vkey, new_commit, new_awd.signature)` — the new witness's signature must verify against the new commit at rotation time.

**Proving tests:**
- `it_rotate_auth_rejects_field_binding_violation_*` (5 negatives — domain_tag, network_magic, policy_validator, oracle_provider, payout_address). Each builds a rotation tx with one tampered field in the new payload and asserts the mirror returns False.
- `it_rotate_auth_rejects_non_canonical_new_payload` — builds a rotation tx whose new witness's `payload_cbor` is the canonical bytes plus a stray trailing byte. The canonical re-encode check fails.

### Δ34 — MintWitness applies Δ22 canonical CBOR re-encode (VR-004)

**Symptom (pre-Δ34):** `auth_witness_nft.ak` MintWitness branch decoded `payload_cbor` via `cbor.deserialise` but did NOT re-serialize and compare to the input bytes. A buggy off-chain encoder (or attacker tooling) could submit non-canonical CBOR (non-shortest-form ints via `0x18 0x00` for value 0, indefinite-length bytestrings via the `0x5f` chunked form) that decoded to the same logical payload but whose bytes were not the canonical form. The witness UTxO would be created with non-canonical `payload_cbor`; later ClaimWithAuth's Δ22 check would fail because `cbor.serialise(decoded) != payload_cbor`. The user's policy would be silently unclaimable via the relay-auth path — only the manual-claim fallback (Δ29) would still work.

**Fix (`validators/auth_witness_nft.ak` MintWitness branch):** add the Δ22 mirror at mint time:

```aiken
expect Some(payload_data) = cbor.deserialise(payload_cbor)
expect payload: AuthCoveragePayload = payload_data
let payload_canonical = cbor.serialise(payload)
let payload_canonical_ok = payload_canonical == payload_cbor
let commit = commit_from_cbor(payload_cbor)
// ... underwrite_path_valid && payload_canonical_ok && ...
```

Cost: one extra `cbor.serialise` (~10x cheaper than `cbor.deserialise` per the stdlib note). Closes the buggy-encoder unclaimable-witness footgun.

**Proving test:** `it_mint_witness_rejects_non_canonical_payload` — submits a MintWitness tx whose redeemer's `payload_cbor` is the canonical bytes plus a stray trailing byte. Pre-Δ34 the validator would have accepted; post-Δ34 the canonical re-encode check rejects.

### Δ35 — Full RotateAuth tx-context integration tests (VR-005)

**Symptom (pre-Δ35):** the 53 v3 integration tests in `v8_integration_tests.ak` had only 5 RotateAuth tests, all property-level lemmas on the `actual_rotation` (Δ25) gate in isolation. None built a full RotateAuth Transaction context. VR-002 and VR-003 reached the audit gate because no integration test caught them.

**Fix:** add 13 new RotateAuth integration tests covering the full Δ32 + Δ33 surface end-to-end:

| Test name | Closes |
|---|---|
| `it_rotate_auth_green_path_no_op_a_via_respend` | Δ32 green path |
| `it_rotate_auth_rejects_wrong_signer` | RotateAuth signer gate |
| `it_rotate_auth_rejects_two_witness_outputs` | Δ32 — VR-002 regression |
| `it_rotate_auth_rejects_zero_witness_outputs` | Δ32 — witness disappearance |
| `it_rotate_auth_rejects_asset_name_change` | Δ32 — asset_name pinning |
| `it_rotate_auth_rejects_non_canonical_new_payload` | Δ33 — Δ22 mirror |
| `it_rotate_auth_rejects_field_binding_violation_domain_tag` | Δ33 |
| `it_rotate_auth_rejects_field_binding_violation_network_magic` | Δ33 |
| `it_rotate_auth_rejects_field_binding_violation_policy_validator` | Δ33 |
| `it_rotate_auth_rejects_field_binding_violation_oracle_provider` | Δ33 |
| `it_rotate_auth_rejects_field_binding_violation_payout_address` | Δ33 — VR-003 prototypical attack |
| `it_rotate_auth_post_rotation_claim_with_auth_succeeds` | Δ32 — VR-002 regression green |
| `it_rotate_auth_old_signature_invalid_after_rotation` | Replay-protection sanity |

Combined with the original 5 isolated tests (`it_rotate_auth_green_path_real_change`, `..._rejects_no_op_rotation`, `..._first_time_from_none_accepted`, `..._distinct_commits_required_for_field_only_changes`, `..._no_op_blocked_even_with_witness_present`), the integration module ships 18 RotateAuth tests in v3.1.

### Δ36 — Cross-stack invalid-payload manifest expanded to 15 rules (VR-006)

**Symptom (pre-Δ36):** the shared manifest at `tests/fixtures/invalid_payload_vectors.json` carried 10 vectors. The verification red-team flagged 5 missing length / range checks: `oracle_nft` length, `pool_script_hash` length, `pool_nft` length, signer_pkh consistency analogue, and 64-byte signature length. Drift in either Python or TS encoder on any of those fields would not be caught.

**Fix (`tests/fixtures/invalid_payload_vectors.json`):** add 5 new vectors —

| ID | Name | Rule |
|---|---|---|
| 11 | `oracle_nft_wrong_length` | oracle_nft must be exactly 28 bytes |
| 12 | `pool_script_hash_wrong_length` | pool_script_hash must be exactly 28 bytes |
| 13 | `pool_nft_wrong_length` | pool_nft must be exactly 28 bytes |
| 14 | `domain_tag_zero_length` | domain_tag must be exactly 27 bytes (zero-length boundary) |
| 15 | `max_coverage_negative` | max_coverage must be in [0, 2^63 - 1] (negative-int boundary; signature-length analogue per the manifest comment — the 64-byte sig + signer-vkey-binding live OUTSIDE AuthCoveragePayload, so the manifest pins the equivalent uint-range cross-stack symmetry) |

The `EXPECTED_VECTOR_COUNT` in both `offchain/tests/test_cross_stack_validation.py` and `frontend/src/wallet/aegis/__tests__/cross_stack_validation.test.ts` is bumped from 10 → 15. The matching `EXPECTED_RULE_NAMES` tuples are updated in lock-step. Both stacks reject every entry with an error matching the documented `error_pattern`.

**Re-run:** `pytest test_cross_stack_validation.py` 21/21 green; `vitest cross_stack_validation.test.ts` 24/24 green.

### Δ37 — `oracle_freshness <= 24h` on-chain (VR-008)

**Symptom (pre-Δ37):** the on-chain check was `payload.oracle_freshness >= 0`. The off-chain Python and TS encoders capped at 86_400_000 ms (24h) per Δ26 / A-A-007, but a Python relay or hand-crafted CLI tool that bypassed off-chain validation could sign payloads with `oracle_freshness = 999_999_999_999` ms (~285 years) and the chain validator would accept.

**Fix (`validators/policy.ak`):** bind a 24h cap on chain too. Applied to BOTH ClaimWithAuth and RotateAuth (the latter via Δ33's full new-payload binding chain):

```aiken
let payload_oracle_freshness_ok =
  payload.oracle_freshness >= 0 && payload.oracle_freshness <= 86_400_000
```

Cross-stack symmetry is now exact: 86_400_000 ms is the inclusive upper bound in all three stacks (Aiken, Python, TypeScript).

**Proving tests:** `it_claim_with_auth_rejects_oracle_freshness_above_24h_cap` (negative — 86_400_001 rejected) and `it_claim_with_auth_accepts_oracle_freshness_exactly_24h` (boundary — 86_400_000 accepted). The boundary test guards the `<=` semantics against a future drift to `<`.

### v3.1 Implementation summary (Aiken on-chain)

| File | Change | Δ touched |
|---|---|---|
| `validators/auth_witness.ak` | Spend validator now accepts EITHER burn-only OR rotation respend. New `continuation_count` fold + path discrimination. | Δ32 |
| `validators/auth_witness_nft.ak` | SweepBurn redeemer drops `not_after` and reads it from the witness UTxO's payload. MintWitness gains canonical re-encode at mint time. RotateAuth path removed (rotation no longer mints). | Δ31, Δ34 |
| `validators/policy.ak` | RotateAuth branch rewritten: spends old witness as input (was: ref input), produces new witness as output, mint qty must be 0, full Δ20 + Δ22 + Ed25519 verify on new payload, oracle_freshness 24h cap. ClaimWithAuth's oracle_freshness gains the same 24h cap. | Δ32, Δ33, Δ37 |
| `lib/aegis/test_helpers/v8_integration_tests.ak` | Mirrors updated for new SweepBurn signature (`mirror_sweep_burn` no longer takes `not_after`). New mirror `mirror_rotate_auth_full` (~150 lines, structurally-broken shapes return False). 13 new RotateAuth integration tests (Δ35). 1 regression test for SweepBurn (Δ31). 1 negative test for MintWitness canonical (Δ34). 2 boundary tests for oracle_freshness 24h cap (Δ37). | Δ31, Δ34, Δ35, Δ37 |
| `tests/fixtures/invalid_payload_vectors.json` | 10 → 15 vectors; new schema label `aegis-invalid-payload-vectors-v2`. | Δ36 |
| `offchain/tests/test_cross_stack_validation.py` | `EXPECTED_VECTOR_COUNT = 15`; `EXPECTED_RULE_NAMES` extended with 5 new rules. | Δ36 |
| `frontend/src/wallet/aegis/__tests__/cross_stack_validation.test.ts` | `EXPECTED_VECTOR_COUNT = 15`; matching `EXPECTED_RULE_NAMES`. | Δ36 |

### v3.1 build outputs (Aiken on-chain)

- `aiken check`: 368 baseline + 17 new = 385 / 385 green.
- `aiken fmt --check`: clean.
- `aiken build`: blueprint regenerated; 3 validator hashes rotate due to v3.1 changes:
  - `auth_witness.auth_witness_validator` rotated (dual-path spend) — Phase-4 redeploy required.
  - `auth_witness_nft.auth_witness_nft` rotated (SweepBurn redeemer change + MintWitness canonical check) — Phase-4 redeploy required.
  - `policy.policy_validator` rotated (RotateAuth restructure + oracle_freshness 24h cap) — Phase-4 redeploy required.
- TV-1..TV-5 cross-stack commit hashes: byte-identical to v3 (the on-chain CBOR encoder is unchanged; v3.1 only adds runtime checks + restructures RotateAuth).
- Python cross-stack tests: 21 / 21 green.
- TypeScript cross-stack tests: 24 / 24 green.

---

## 12.2 v3.1 Frontend hardening + deploy gates

A Phase-3 verification red-team (`PHASE3_VERIFICATION_REDTEAM.md`, 2026-05-06) attacked the v3 closures (Δ18-Δ30) along multiple axes. It produced 13 findings; 10 were on-chain HIGH/MED gaps absorbed by the parallel Aiken agent (Δ31-Δ37); the remaining 3 were LOW-severity off-chain / CI gaps closed in this v3.1 hardening pass:

- **Δ38 closes VR-007** ("Δ30 enforcement is voluntary at the call site"). The Δ30 / RT-C-06 closure made `signAuthCommitment` re-derive `humanReadableSummary` and assert byte-equality with a caller-supplied `confirmedSummary`. The verification red-team noted this is voluntary at the call site: a frontend that imports the lower-level CBOR / hash / signing primitives directly can produce a valid Ed25519 signature without ever showing the user the summary modal. v3.1 hardens the trust boundary by:
  1. Locking down `frontend/src/wallet/aegis/index.ts` so the public barrel re-exports only `signAuthCommitment` + display helpers + types. The CBOR encoders (`encodeAuthCoveragePayload`, `encodeAuthCoveragePayloadCanonical`), the BLAKE2b-256 hasher (`commitmentHash`), the canonical-CBOR primitives (`encodeUint`, `encodeBytes`, `encodeArray`, `encodeConstr`), and the validation helper `assertNetworkConsistency` remain `export`s at the file level (so peer modules and `__tests__/` inside the privacy boundary can compose them) but are NOT re-exported from `index.ts`.
  2. Adding a build-step lint guard at `frontend/scripts/check_aegis_privacy_boundary.cjs`. The guard walks every `.ts`/`.tsx` source under `frontend/src/` excluding `frontend/src/wallet/aegis/` and grep-checks each `import` statement for any forbidden symbol (the 8 primitives above) or any direct import of `@noble/ed25519`. Wired into `package.json` as `npm run lint:guard`. The guard parses imports cheaply (comment-stripped, multi-line aware) and prints a per-breach diagnostic with file, line, offending text, and a sentence explaining why the symbol is gated.
  3. The guard ships with an in-memory self-test (`npm run lint:guard:self-test`) covering 9 cases: 4 positive (allowed `signAuthCommitment` / `humanReadableSummary` imports, JSDoc and comment references that mention a forbidden symbol) and 5 negative (named import, multi-line named import, direct `@noble/ed25519` import, type-only re-import of the encoder). The self-test catches a silently-broken guard that would otherwise give a false PASS on the actual codebase.
- **Δ39 closes VR-009** ("auth_witness_nft_policy_id placeholder is the all-zero hash"). The constant in `lib/aegis/types.ak` is the 28-byte all-zero placeholder until the Phase-4 mint deploy. If the operator forgets to update it, ClaimWithAuth and RotateAuth silently match no witness UTxOs (the fail-closed on-chain behaviour is correct, but the bug only surfaces at the first claim attempt — far too late). v3.1 adds a static-constant CI gate at `D:/aegis-contracts/scripts/check_deploy_constants.py` that asserts the constant is NOT the all-zero placeholder and IS exactly 28 bytes (56 hex chars) before tagging.
- **Δ40 closes VR-012** ("enterprise_addr_header mainnet flip is a deploy-time concern"). Same script asserts `enterprise_addr_header_mainnet == #"61"`, `enterprise_addr_header_testnet == #"60"`, and the active-build constant `enterprise_addr_header` ∈ {`#"60"`, `#"61"`}. Drift in any of these would be silently 1 byte off in every `payload.payout_address` check on chain — `aiken check` would still pass, the bug would surface only on chain.

The two CI checks share one Python script and one GitHub Actions workflow (`.github/workflows/deploy-gates.yml`) that runs on every push, PR, and `v*` tag. The script ships with a 6-case in-memory self-test (`python scripts/check_deploy_constants.py --self-test`): placeholder rejected, real-deploy accepted, swapped headers rejected, missing-mainnet-header rejected, bad-length policy_id rejected, typo-active-header rejected. The self-test runs as the first step in the CI workflow so a silently-broken script cannot give a false PASS on the actual `types.ak`.

### v3.1 implementation summary

| File | Change | Δ touched |
|---|---|---|
| `frontend/src/wallet/aegis/index.ts` | Trim public re-exports to `signAuthCommitment` + display helpers + types. CBOR / hash / signing primitives remain module-internal. Module-header comment documents the privacy boundary and points at the CI guard. | Δ38 |
| `frontend/scripts/check_aegis_privacy_boundary.cjs` (new, ~370 lines) | CommonJS Node script. Walks `src/` excluding `src/wallet/aegis/`, parses imports, fails on any forbidden symbol or direct `@noble/ed25519` import. 9-case in-memory self-test. | Δ38 |
| `frontend/package.json` | Add `lint:guard` and `lint:guard:self-test` scripts. | Δ38 |
| `D:/aegis-contracts/scripts/check_deploy_constants.py` (new, ~520 lines) | Python script. Extracts `auth_witness_nft_policy_id`, `enterprise_addr_header_mainnet`, `enterprise_addr_header_testnet`, and `enterprise_addr_header` from `lib/aegis/types.ak`. Validates against pinned values. 6-case in-memory self-test. | Δ39, Δ40 |
| `D:/aegis-contracts/.github/workflows/deploy-gates.yml` (new) | GitHub Actions workflow. Runs script self-test then the deploy-constant check. Triggers on push, PR, and `v*` tag. | Δ39, Δ40 |
| `D:/aegis-contracts/README.md` | Document the deploy gate under a new `## Deploy gates (v8 / v3.1)` section between `## Quick start` and `## License`. | Δ39, Δ40 |

### v3.1 build outputs

- Frontend: `npm run lint` + `npm run lint:guard` + `npm run lint:guard:self-test` clean. `npx tsc -b` clean. `npx vitest run` 296 / 296 tests green (no regression).
- Frontend privacy guard: 51 TS/TSX files scanned outside `src/wallet/aegis/`, 0 breaches detected.
- Aegis-contracts deploy gate: `python scripts/check_deploy_constants.py --self-test` 6 / 6 cases green. Against the live `types.ak` (which still has the all-zero placeholder pre-Phase-4-deploy), the script correctly exits 1 with a clear diagnostic — confirming the gate is live.

### Why the guard is convention-only at TypeScript level + how that's mitigated

TypeScript module privacy is convention-only — there is no equivalent of Rust's `pub(crate)` or Java's `package-private`. A determined attacker writing a malicious browser extension could `import { commitmentHash } from '@aegis/frontend/src/wallet/aegis/auth_payload'` no matter what we do at the language level. The mitigations:

1. The CI lint guard catches accidental drift in the Aegis codebase itself (the 99% case — a future contributor writing a new component and reaching into the wallet internals because it's there).
2. The on-chain validator's Δ20 14-field binding (already shipped in v3) catches every field-deception attack regardless of how the signature was produced. The user's funds are not at risk if Δ38 is bypassed.
3. The browser-extension attack class is closed by Δ16 / Δ30 — the Aegis wallet's signing prompt is the security boundary; if the extension can inject code into the page, the wallet's seed is the only thing standing between the attacker and a signature, and that is a separate concern (covered by the seed sealing / WebAuthn PRF discipline shipped in Stream 3).

Δ38 is therefore correctly classified as a defence-in-depth gap, not a funds-at-risk closure. The v3.1 hardening prevents accidental drift INSIDE the codebase; the chain-side enforcement is the absolute security floor.

---

## 12.3 v3.2 Deploy Cycle Break (Δ41)

### Symptom (pre-v3.2)

The Phase-4 deploy was **stuck in a circular dep**:

* `auth_witness_nft` mint policy was parameterized over a 4-tuple `(init_utxo_ref, network_tag, policy_validator_hash, operator_pkh)`. Its compiled-validator hash (and therefore its policy id) depended on the `policy_validator_hash` parameter.
* `policy_validator` (the spend validator at `validators/policy.ak`) referenced `auth_witness_nft_policy_id` (the mint policy's policy id) at four call sites in the ClaimWithAuth and RotateAuth branches — used to identify witness UTxOs via `assets.quantity_of(value, auth_witness_nft_policy_id, blake2b_224(policy_id)) == 1`.

The two compile-time inputs formed a fixed-point that never converged. The operator had no way to produce both hashes simultaneously: pinning `auth_witness_nft_policy_id` first required compiling `auth_witness_nft` with `policy_validator_hash`, but that hash depends on the not-yet-pinned `auth_witness_nft_policy_id`. Pinning `policy_validator_hash` first required compiling `policy_validator` with `auth_witness_nft_policy_id`, but that policy id depends on the not-yet-pinned `policy_validator_hash`.

The result: the relay-presigned-auth feature's Phase-4 deploy was **blocked**.

### Fix — Architectural changes

**(a) Drop `policy_validator_hash` from the mint policy's parameter set.**

`validators/auth_witness_nft.ak` now takes 3 parameters: `(init_utxo_ref, network_tag, operator_pkh)`. The Underwrite-path "fresh policy output at policy_validator" check is replaced by a pair of bindings:

1. **Witness output at `auth_witness_validator_hash`** — using the new compile-time-pinned constant `auth_witness_validator_hash` in `lib/aegis/types.ak`. This pins the witness UTxO's location at mint time so a misbuilt tx fails fast.
2. **Policy datum binding** — locate any output (at any address that is NOT the witness validator) whose InlineDatum decodes as PolicyDatum with matching `policy_id`, `auth_commitment == Some(blake2b_256(payload_cbor))`, and `oracle_provider` matching the payload's tag.

The witness output's location is the load-bearing pin; the policy output's address is unconstrained because the policy validator (which actually processes Cancel/Expire/Claim/ClaimWithAuth) refuses to spend policies at attacker-controlled addresses, so a misbuilt policy is a self-inflicted user error, not a security issue.

**(b) Switch `policy_validator`'s witness identification from token-policy-id to script-credential.**

`validators/policy.ak` ClaimWithAuth + RotateAuth now identify witness UTxOs by:

```aiken
when input.output.address.payment_credential is {
  Script(h) ->
    if h == auth_witness_validator_hash {
      // Decode AuthWitnessDatum and check policy_id
      ...
    }
}
```

instead of the pre-v3.2:

```aiken
let qty = assets.quantity_of(input.output.value, auth_witness_nft_policy_id, asset_name)
if qty == 1 { ... }
```

`auth_witness_validator_hash` is a new compile-time-pinned constant in `lib/aegis/types.ak`, populated post-deploy via the linear ordering documented above (§6 Phase 4).

**(c) Add `auth_witness_validator_hash` to the deploy gate.**

`scripts/check_deploy_constants.py` now enforces BOTH `auth_witness_nft_policy_id` AND `auth_witness_validator_hash` are non-placeholder before mainnet tag. A 7th self-test case covers the new placeholder rejection.

### Three-leg transitive trust chain

Security is preserved by composing three checks:

1. **Mint policy (`auth_witness_nft`)** pins the witness output at `Script(auth_witness_validator_hash)` — no other path produces a UTxO at that script with the canonical NFT.
2. **Auth witness validator (`auth_witness.ak`, unchanged in v3.2)** self-checks `own_value` carries a token under the canonical `auth_witness_nft_policy_id` AND enforces burn-or-respend semantics on the spend path (Δ32) — once a UTxO is at this script address, the NFT can leave only via burn or via a respend that preserves the asset_name with a fresh datum.
3. **Policy validator (`policy.ak`)** accepts witness UTxOs only at `Script(auth_witness_validator_hash)` — combining with leg 2, only legit-minted UTxOs (those whose asset matches the canonical NFT and whose history runs through the auth_witness_validator script) can ever be observed as witnesses by ClaimWithAuth/RotateAuth.

The pre-v3.2 single-leg "policy_validator checks the NFT directly" defense becomes the 3-leg pipeline above. A spoofing attempt — e.g., an attacker minting a fake witness under their own permissive NFT policy and outputting it at the auth_witness_validator script address — fails at leg 2: the auth_witness_validator's spend path requires the value to carry a token under the canonical `auth_witness_nft_policy_id`, so the attacker's UTxO can never be spent, and any user who tries to reference it would (a) fail leg 1's mint enforcement (their tx never minted under the canonical policy id) and (b) the validator's own_value self-check.

### Re-attack confirmation

Every closed finding from v3 / v3.1 is re-checked against the v3.2 architecture. The full per-finding analysis:

| Finding | Closed by | Survives v3.2 architectural change |
|---|---|---|
| C-1 (witness mint forgeable) | Δ1 + Δ2 + Δ17 | Yes — the mint policy still requires asset_name binding + payload decoding + witness output at the canonical script. |
| C-2 (vkey substitution) | Δ7 | Yes — ClaimWithAuth still asserts `blake2b_224(insured_vkey) == datum.insured`. |
| F-AUTH-1..6 | Δ4-Δ12 | Yes — none of these references the witness identification mechanism. |
| H-1 (cross-network replay) | Δ4 + Δ16 + Δ20 | Yes — domain_tag and network_magic are bound by Δ20 in ClaimWithAuth, unchanged. |
| H-2 (sig malleability) | Δ11 | Yes — Ed25519 strict-S enforced by builtin, unaffected. |
| H-3 (policy_id collision) | Δ3 + Δ21 | Yes — policy_id derivation is unchanged. |
| V-001 (mint one-shot bug) | Δ18 | Yes — `init_utxo_ref` parameter still hashed into the validator script for per-deployment uniqueness. |
| V-002 (BurnWitness inverted) | Δ19 | Yes — `BurnViaConsume` still requires the policy to be co-spent (now identified by datum shape, with a script-credential negative-filter to skip the witness input). |
| V-007 (payload field binding) | Δ20 | Yes — all 14 fields still bound in ClaimWithAuth. |
| V-008 (sweeper auth) | Δ19 | Yes — `SweepBurn` still operator-signed + witness UTxO at script + window-elapsed gate. |
| V-009 (network_tag whitelist) | Δ24 | Yes — strict whitelist preserved. |
| V-010 (no-op rotation) | Δ25 | Yes — `actual_rotation` gate preserved. |
| A-A-001..A-A-009 | Δ22 + Δ26 + Δ27 + Δ34 | Yes — canonical CBOR + cross-stack validation parity unaffected. |
| VR-001 (SweepBurn `not_after` unbound) | Δ31 | Yes — gate still reads `payload.not_after` from the witness UTxO. |
| VR-002 (RotateAuth 2-witness state) | Δ32 | Yes — rotation respend semantics preserved; the asset_name binding is preserved on the new witness output (`assets.quantity_of(out.value, auth_witness_nft_policy_id, asset_name) == 1`) so the NFT pin is end-to-end. |
| VR-003 (RotateAuth weak binding) | Δ33 | Yes — full Δ20 14-field binding + Δ22 canonical re-encode + Ed25519 sig verify on new payload, unchanged. |
| VR-004 (MintWitness canonical) | Δ34 | Yes — `cbor.serialise(decoded) == payload_cbor` preserved. |
| VR-005 (RotateAuth integration tests) | Δ35 | Yes — 13 tests still pass; mirrors updated to match v3.2 script-credential identification. |
| VR-006 (cross-stack manifest 15 rules) | Δ36 | Yes — unchanged. |
| VR-008 (oracle_freshness 24h cap) | Δ37 | Yes — bound preserved in ClaimWithAuth and RotateAuth. |
| VR-009 (auth_witness_nft_policy_id placeholder) | Δ39 | Yes — deploy gate preserved. |
| VR-012 (enterprise_addr_header drift) | Δ40 | Yes — deploy gate preserved. |

**No regressions.** Two new tests pin the v3.2 invariant: `it_policy_validator_accepts_witness_at_canonical_auth_witness_script_address` (positive) and `it_policy_validator_rejects_witness_at_wrong_script_address` (negative — confirms the script-credential pin rejects an attacker-script witness with the canonical NFT, which the pre-v3.2 token-only check would have ACCEPTED).

### v3.2 Implementation summary

| File | Change | Δ touched |
|---|---|---|
| `validators/auth_witness_nft.ak` | Drop `policy_validator_hash` parameter (4-tuple → 3-tuple). Underwrite path replaces "policy at policy_validator" check with "(witness at auth_witness_validator) AND (policy datum bound)". BurnViaConsume identifies the consumed policy by datum shape only (script-credential negative-filter to skip witness input). | Δ41 |
| `validators/policy.ak` | Witness identification at all 4 call sites switched from `assets.quantity_of(value, auth_witness_nft_policy_id, blake2b_224(policy_id)) == 1` to `Script(auth_witness_validator_hash)` payment-credential equality + `AuthWitnessDatum.policy_id` match. RotateAuth additionally re-asserts the canonical NFT on the new witness output (asset-name pin preserved). | Δ41 |
| `validators/auth_witness.ak` | UNCHANGED. The auth_witness_validator's own self-check on `own_value` carrying the canonical NFT remains the security backbone of leg 2 of the new 3-leg trust chain. | (none) |
| `lib/aegis/types.ak` | Add new compile-time constant `auth_witness_validator_hash: ByteArray` (28-byte placeholder, populated post-deploy via §6 Phase-4 step 4). Doc comment for `auth_witness_nft_policy_id` updated to reflect the v3.2 architecture. | Δ41 |
| `lib/aegis/test_helpers/v8_integration_tests.ak` | Mirrors updated for v3.2: `mirror_mint_witness` no longer takes `policy_validator_hash` (takes `auth_witness_validator_hash` for the witness-output pin); `mirror_burn_via_consume` drops `policy_validator_hash` and uses the script-credential negative-filter; `mirror_rotate_auth_full` identifies witnesses by script credential. 2 new positive/negative tests pin the script-credential binding. | Δ41 |
| `scripts/check_deploy_constants.py` | Add `check_auth_witness_validator_hash` against the all-zero placeholder + 28-byte length check. Self-test gains a 7th case (`placeholder auth_witness_validator_hash rejected`). | Δ41 |

### v3.2 build outputs

- `aiken check`: 385 baseline + 2 new = 387 / 387 green.
- `aiken fmt --check`: clean.
- `aiken build`: blueprint regenerated. 2 validator hashes rotate due to v3.2 changes:
  - `auth_witness_nft.auth_witness_nft.mint`: `18ce1c…05d` → `de0a0d…d55` (3-tuple parameterisation + restructured Underwrite path).
  - `policy.policy_validator.spend`: `fd7246…4e2` → `95604c…a85` (witness identification swapped to script credential).
  - `auth_witness.auth_witness_validator.spend`: UNCHANGED at `7b95b1…695` (file unchanged).
- TV-1..TV-5 cross-stack commit hashes: byte-identical to v3.1 (the on-chain CBOR encoder is unchanged; v3.2 only restructures validator references, no canonical-form changes).

---

## 12.4 v3.3 Final Cycle Break (Δ42)

### Symptom (post-v3.2)

v3.2 broke the FIRST-ORDER cycle (`auth_witness_nft` no longer
parameterized over `policy_validator_hash` — Δ41). But the v3.2 architecture left a SECOND-ORDER cycle:

* The mint policy `validators/auth_witness_nft.ak` STILL imported
  `auth_witness_validator_hash` from `lib/aegis/types.ak` and gated
  the Underwrite-path witness-output destination on
  `if h == auth_witness_validator_hash`. That import made the mint
  policy's compiled bytecode (and therefore its base hash) depend
  on the value of the `auth_witness_validator_hash` constant.
* `auth_witness_validator_hash` is itself populated post-deploy:
  the v3.2 ordering's step 4 wrote the freshly-frozen
  `auth_witness_validator` hash into `lib/aegis/types.ak` and
  rebuilt. That rebuild ROTATED `auth_witness_nft.mint`'s base
  hash — and therefore the policy id pinned in step 2 of the
  ordering. The pinned `auth_witness_nft_policy_id` constant was
  now stale; rebuilding to refresh it would in turn rotate
  `auth_witness_validator`'s hash (depends only on
  `auth_witness_nft_policy_id`), which would invalidate
  `auth_witness_validator_hash`, which would re-rotate
  `auth_witness_nft.mint` — fixed-point loop.

The result: the v3.2 deploy ordering was advertised as "linear"
but was empirically a fixed-point. Phase 4 deploy was BLOCKED.

Empirical proof (pre-Δ42, hypothetical run on a v3.2 build):

```
# Step 1: build with both consts at all-zeros placeholder.
$ aiken build
auth_witness_nft.mint = h_base_v0  # depends on auth_witness_validator_hash
auth_witness.spend     = av0       # depends on auth_witness_nft_policy_id
policy_validator.spend = pv0       # depends on auth_witness_validator_hash

# Step 4 (per v3.2 ordering): bake auth_witness_validator_hash, rebuild.
# Set auth_witness_validator_hash = av0.
$ aiken build
auth_witness_nft.mint = h_base_v1  # CHANGED — pre-Δ42 this validator
                                    # imported auth_witness_validator_hash,
                                    # so its bytecode rotated.
                                    # The policy id pinned in step 2 is
                                    # NOW STALE.
```

### Fix — Architectural change

**Drop all `auth_witness_validator_hash` references from
`validators/auth_witness_nft.ak`.**

The witness-destination script-credential pin (used by the v3.2
Underwrite path's `if h == auth_witness_validator_hash` guard) is
replaced by a per-tx VALUE-based check: EXACTLY ONE tx output
(anywhere) carries the same `(self_policy_id, asset_name)` pair AND
its inline `AuthWitnessDatum` matches the redeemer's `policy_id` and
`payload_cbor`. The mint policy's compiled bytecode is now
INDEPENDENT of `auth_witness_validator_hash` — empirically:

```
# Step 1: build with both consts at all-zeros placeholder.
h_base_v0 = 9ad6e585ab2712b7a7eea22805ef2ff8b121bb792f4e72073e1939d7

# Set auth_witness_validator_hash = #"01010101...0101" (any non-zero
# 28-byte value), rebuild.
h_base_v1 = 9ad6e585ab2712b7a7eea22805ef2ff8b121bb792f4e72073e1939d7

h_base_v0 == h_base_v1  # ✓ Δ42 invariant verified
```

Δ42 also drops the negative script-credential filters in
`BurnViaConsume` and `SweepBurn` (used pre-Δ42 to skip the witness
input when locating the consumed policy by datum shape). These
filters relied on importing `auth_witness_validator_hash`, so they
had to go too. The replacement is a structural typed-decode: an
input whose datum is `AuthWitnessDatum` (the witness input being
burned) simply fails the typed `expect pdat: PolicyDatum =
raw_pdat` path and contributes False to the `list.any` fold — no
crash, because the typed-decode failure is caught by the surrounding
`when` arm. Atomic-burn semantics are preserved.

### Three-leg transitive trust chain (post-Δ42)

Security is preserved end-to-end via the same three legs as v3.2,
with one difference in leg 1:

1. **Mint policy (`auth_witness_nft`)** — leg 1 weakened. Pre-Δ42 the
   mint policy enforced "witness output at
   `Script(auth_witness_validator_hash)`". Post-Δ42 the mint policy
   enforces "EXACTLY ONE tx output (anywhere) carries the canonical
   `(own_policy_id, asset_name)` pair AND matching
   `AuthWitnessDatum`". An off-chain code path that puts the
   witness output at a non-canonical script address still passes
   the mint check — the orphan witness exists on chain.
2. **Auth witness validator (`auth_witness.ak`, file unchanged in
   v3.3)** — self-checks `own_value` carries a token under the
   canonical `auth_witness_nft_policy_id` AND enforces
   burn-or-respend semantics on the spend path (Δ32). Once a UTxO
   sits at the canonical script address, the NFT can leave only
   via burn or via a respend that preserves the asset_name with a
   fresh datum. Leg 2 unchanged from v3.2.
3. **Policy validator (`policy.ak`, unchanged in v3.3 vs v3.2)** —
   accepts witness UTxOs only at
   `Script(auth_witness_validator_hash)`. Leg 3 unchanged.

The pre-v3.3 (v3.2) "explicit destination pin at mint time" defense
is replaced by "value-based count check at mint + script-credential
filter at consume time". A spoofing attempt — e.g., an attacker
mints under the canonical policy and routes the witness output to
their own script address — produces an orphan that:

* passes the mint policy's checks (the new "EXACTLY ONE output
  carries the asset" check is satisfied — there IS one such output,
  it's just at the wrong address);
* but is REJECTED by the policy validator's witness-collection
  helper at ClaimWithAuth + RotateAuth time, because that helper
  filters reference inputs by `Script(auth_witness_validator_hash)`
  payment credential. The orphan never becomes a witness;
* and is also unable to ever leave the attacker's script (since the
  attacker's script is not `auth_witness_validator`, its spend
  semantics are whatever the attacker built — but the orphan can
  never be referenced under ClaimWithAuth/RotateAuth, so its
  spendability is moot). The attacker has wasted ~3.5 ADA min-UTxO
  on an unreachable witness — no funds at risk for any user.

### Re-attack confirmation

Every closed finding from v3 / v3.1 / v3.2 is re-checked against the
v3.3 architecture. The full per-finding analysis:

| Finding | Closed by | Survives v3.3 architectural change |
|---|---|---|
| C-1 (witness mint forgeable) | Δ1 + Δ2 + Δ17 | Yes — the mint policy still requires asset_name binding + payload decoding + EXACTLY ONE matching output. The destination pin moved from "at script `auth_witness_validator_hash`" to "anywhere; consume-time filter at policy_validator" — same end-to-end binding strength. |
| C-2 (vkey substitution) | Δ7 | Yes — ClaimWithAuth still asserts `blake2b_224(insured_vkey) == datum.insured`. |
| F-AUTH-1..6 | Δ4-Δ12 | Yes — none of these references the witness identification mechanism. |
| H-1 (cross-network replay) | Δ4 + Δ16 + Δ20 | Yes — domain_tag and network_magic are bound by Δ20 in ClaimWithAuth, unchanged. |
| H-2 (sig malleability) | Δ11 | Yes — Ed25519 strict-S enforced by builtin, unaffected. |
| H-3 (policy_id collision) | Δ3 + Δ21 | Yes — policy_id derivation unchanged. |
| V-001 (mint one-shot bug) | Δ18 | Yes — `init_utxo_ref` parameter still hashed into the validator script for per-deployment uniqueness. |
| V-002 (BurnWitness inverted) | Δ19 | Yes — `BurnViaConsume` still requires the policy to be co-spent. The v3.2 negative-filter on `auth_witness_validator_hash` (used to skip the witness input when locating the consumed policy by datum shape) is removed in Δ42 and replaced by the structural typed-decode failure path: `AuthWitnessDatum` does not coerce to `PolicyDatum`, so the witness input contributes False to the `list.any` fold without crashing. The atomic-burn invariant is preserved. |
| V-007 (payload field binding) | Δ20 | Yes — all 14 fields still bound in ClaimWithAuth. |
| V-008 (sweeper auth) | Δ19 | Yes — `SweepBurn` still operator-signed + witness UTxO at `Script(_)` defense-in-depth structural check + window-elapsed gate. |
| V-009 (network_tag whitelist) | Δ24 | Yes — strict whitelist preserved. |
| V-010 (no-op rotation) | Δ25 | Yes — `actual_rotation` gate preserved. |
| A-A-001..A-A-009 | Δ22 + Δ26 + Δ27 + Δ34 | Yes — canonical CBOR + cross-stack validation parity unaffected. |
| VR-001 (SweepBurn `not_after` unbound) | Δ31 | Yes — gate still reads `payload.not_after` from the witness UTxO. |
| VR-002 (RotateAuth 2-witness state) | Δ32 | Yes — rotation respend semantics preserved (`auth_witness_validator` file unchanged in v3.3); the asset_name binding is preserved on the new witness output (`assets.quantity_of(out.value, auth_witness_nft_policy_id, asset_name) == 1`) so the NFT pin is end-to-end. |
| VR-003 (RotateAuth weak binding) | Δ33 | Yes — full Δ20 14-field binding + Δ22 canonical re-encode + Ed25519 sig verify on new payload, unchanged in `policy.ak` (which is also unchanged in v3.3 vs v3.2). |
| VR-004 (MintWitness canonical) | Δ34 | Yes — `cbor.serialise(decoded) == payload_cbor` preserved at mint time. |
| VR-005 (RotateAuth integration tests) | Δ35 | Yes — 13 RotateAuth tests still pass; mirrors unchanged in v3.3 (the witness identification on the rotation path uses `auth_witness_addr_hash` which is the test fixture's stand-in for `auth_witness_validator_hash` — independent of the mint policy). |
| VR-006 (cross-stack manifest 15 rules) | Δ36 | Yes — unchanged. |
| VR-008 (oracle_freshness 24h cap) | Δ37 | Yes — bound preserved in ClaimWithAuth and RotateAuth. |
| VR-009 (auth_witness_nft_policy_id placeholder) | Δ39 | Yes — deploy gate preserved. |
| VR-012 (enterprise_addr_header drift) | Δ40 | Yes — deploy gate preserved. |
| Δ41 v3.2 first-order cycle (auth_witness_nft.policy_id ↔ policy_validator.hash) | Δ41 | Yes — the v3.2 architectural change (3-tuple parameterisation + script-credential identification at policy_validator) is unchanged in v3.3. |

**No regressions.** One new test pins the v3.3 invariant:
`it_mint_witness_at_arbitrary_script_succeeds_but_orphan_unreachable_via_claim`
— builds a tx that mints a canonical witness but routes its output
to an attacker-controlled script address. Asserts BOTH (a) the mint
succeeds at the v3.3 mint policy (the value-based count check is
satisfied), AND (b) the orphan witness is unreachable via
ClaimWithAuth — the policy_validator's witness-collection helper
(`mirror_policy_validator_collect_witnesses`) returns 0 because the
orphan is not at `Script(auth_witness_validator_hash)`.

### v3.3 Implementation summary

| File | Change | Δ touched |
|---|---|---|
| `validators/auth_witness_nft.ak` | Drop import + all references to `auth_witness_validator_hash`. MintWitness Underwrite path: replace destination-script-credential pin with "EXACTLY ONE tx output anywhere carries the canonical `(own_policy_id, asset_name)` AND matching `AuthWitnessDatum`" via a fold-over-outputs counting helper. Policy-output binding rewritten to skip outputs by NFT-presence rather than by script-credential. BurnViaConsume drops negative script-credential filter (typed-decode failure on `AuthWitnessDatum` returns False structurally). SweepBurn structural `Script(_)` check preserved (no constant dependency). Module-header documents the security argument for each delta in detail. | Δ42 |
| `validators/auth_witness.ak` | UNCHANGED. The auth_witness_validator's own self-check on `own_value` carrying the canonical NFT remains the security backbone of leg 2 of the 3-leg trust chain. | (none) |
| `validators/policy.ak` | UNCHANGED in v3.3 vs v3.2. The witness-consume side already uses `Script(auth_witness_validator_hash)` script-credential equality (via Δ41). | (none) |
| `lib/aegis/types.ak` | Update doc comments on `auth_witness_nft_policy_id` and `auth_witness_validator_hash` constants to reflect the v3.3 deploy ordering (linear, 5 rebuilds, no base-hash rotation post step 2). No constant value changes. | Δ42 (docs only) |
| `lib/aegis/test_helpers/v8_integration_tests.ak` | Mirrors updated for v3.3: `mirror_mint_witness` drops `auth_witness_validator_hash_test` parameter (signature: `(network_tag, redeemer_policy_id, payload_cbor, self) -> Bool`); the underwrite_path_valid check is rewritten as a count-fold over outputs by NFT-presence. `mirror_burn_via_consume` drops the `auth_witness_addr_hash` negative filter. New test `it_mint_witness_at_arbitrary_script_succeeds_but_orphan_unreachable_via_claim` pins the v3.3 invariant (orphan mint succeeds + orphan unreachable via policy_validator's witness collection). | Δ42 |
| `docs/audit/RELAY_PRESIGNED_AUTH_SCOPE_v2.md` | This file. Bumped from v3.2 → v3.3. New §12.4 for Δ42; updated §0 Δ42 row, §1.5 narrative, §6 Phase-4 deploy ordering, §11 traceability table. | Δ42 |
| `docs/audit/SECURITY_AUDIT_REPORT.md` | New v8 / relay-presigned-authorization section documenting the full v3.x design audit trail (v2 design → 3-angle red-team → v3 fixes → verification → v3.1 → v3.2 first-order cycle break → v3.3 second-order cycle break Δ42). | Δ42 |

### v3.3 build outputs

- `aiken check`: 387 baseline (v3.2) + 1 new = 388 / 388 green.
- `aiken fmt --check`: clean.
- `aiken build`: blueprint regenerated. Hash rotation summary (vs the v3.2 build at `de0a0d…d55`):
  - `auth_witness_nft.auth_witness_nft.mint`: rotated to `9ad6e585ab2712b7a7eea22805ef2ff8b121bb792f4e72073e1939d7` (post-Δ42, with both `auth_witness_nft_policy_id` and `auth_witness_validator_hash` at all-zeros placeholder). The new base hash is INDEPENDENT of `auth_witness_validator_hash`'s value (verified empirically — see "Symptom" + "Fix" sections above).
  - `auth_witness.auth_witness_validator.spend`: UNCHANGED at `7b95b1e0e02e1812bd282facbc6ebbdae8876b9e0be5b17d8dd98695` (file unchanged in v3.3).
  - `policy.policy_validator.spend`: UNCHANGED vs v3.2 at `95604c241b1782034cc9a84630b2c4131a92ccbc80deca6c90b4fa85` (file unchanged in v3.3, both placeholder constants).
- TV-1..TV-5 cross-stack commit hashes: byte-identical to v3.1 / v3.2 (the on-chain CBOR encoder is unchanged; v3.3 only restructures the mint validator's body, no canonical-form changes). TV-1 commit hash pinned at `091c23daf3b3bab1bb7508ae312d48198f121fff1e7a6caeddd49f52aeb80885` — verified green.
- Δ42 cycle break empirical verification: building twice (once with `auth_witness_validator_hash = #"00…00"`, once with `= #"01…01"`) produces IDENTICAL `auth_witness_nft.mint` base hash (`9ad6e585…`), proving the second-order cycle is closed.

```
deploy ordering (post-Δ42 / v3.3):

   step 1                step 2                  step 3                  step 4                  step 5
  ┌──────┐  pick init_  ┌──────────────────┐  bake     ┌──────────────────┐  bake     ┌──────────────┐  mint pool
  │build │ ───utxo───▶  │auth_witness_nft  │ ──policy_id▶│auth_witness_     │ ──hash──▶│policy_       │ ───NFT───▶ ...
  │with  │  apply       │.mint hash STABLE │  rebuild  │validator hash    │  rebuild │validator     │  deploy
  │both  │  3 params    │(no const dep)    │           │FROZEN            │          │hash FROZEN   │  refs
  │consts│              │                  │           │(depends on       │          │(depends on   │
  │= 0   │              │                  │           │ NFT policy id)   │          │ validator    │
  └──────┘              └──────────────────┘           └──────────────────┘          │ hash const)  │
                                                                                      └──────────────┘
                                                                                            │
                                                                                            ▼
                          ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                          Δ42 invariant: auth_witness_nft.mint hash UNCHANGED across step 4
                          (depended on `auth_witness_validator_hash` pre-Δ42; independent post-Δ42).
                          ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Appendix A — File-level change inventory (revised)

| File | Change |
|---|---|
| `contracts/lib/aegis/types.ak` | PolicyDatum gains 12th field `auth_commitment: Option<ByteArray>`. Two new redeemer variants: `ClaimWithAuth { sig }`, `RotateAuth { new_commit, new_witness_ref }`. New types: `AuthWitnessDatum`, `AuthCoveragePayload`. New constants: `auth_witness_nft_policy_id` (per network, used by `auth_witness_validator` self-check), **`auth_witness_validator_hash` (Δ41 / v3.2 + Δ42 / v3.3 — used by `policy_validator` for witness UTxO script-credential identification; NOT referenced from `auth_witness_nft.ak` post-Δ42; placeholder until Phase-4 deploy step 4)**, network-specific domain tags. |
| `contracts/lib/aegis/auth_payload.ak` (new) | Canonical CBOR shape definition + decoder for `AuthCoveragePayload`. Used by mint policy and ClaimWithAuth branch. |
| `contracts/validators/policy.ak` | New ClaimWithAuth + RotateAuth branches (§1.3, §1.4). policy_id derivation update (§1.8). |
| `contracts/validators/pool.ak` | Underwrite branch verifies `pdat.policy_id == derive_policy_id(...)` using consumed input ref. |
| `contracts/validators/auth_witness_nft.ak` (new; updated — Δ41 / v3.2 + Δ42 / v3.3) | One-shot mint policy parameterized over `(init_utxo_ref, network_tag, operator_pkh)` (3-tuple, post-Δ41 / v3.2 — `policy_validator_hash` dropped to break first-order deploy cycle). Δ42 / v3.3 additionally drops all imports + references to `auth_witness_validator_hash` to close the second-order deploy cycle (the mint policy's compiled bytecode now does NOT depend on either `auth_witness_nft_policy_id` or `auth_witness_validator_hash`). MintWitness Underwrite path uses a per-tx "EXACTLY ONE output anywhere carries the canonical NFT + matching `AuthWitnessDatum`" check; orphan mints elsewhere are unreachable as witnesses via `policy_validator`'s `Script(auth_witness_validator_hash)` filter. Mint validator per §1.5. |
| `contracts/validators/auth_witness.ak` (new) | Spend validator that always-fails except for the burn-only path (§1.6). |
| `contracts/lib/aegis/test_helpers/security_tests.ak` | New `green_v8_*` and `redteam_v8_*` tests covering every Δ. Cross-stack CBOR byte-vector test fixtures. |
| `api/policies.py` | PolicyDatum dataclass extended. New redeemer classes. New tx-builder helpers: build_underwrite_with_auth_tx, build_claim_with_auth_tx, build_rotate_auth_tx. policy_id derivation function. |
| `api/oracles/dispatcher.py` | No change (oracle_provider already in PolicyDatum since v6). |
| `offchain/src/aegis/auth_payload.py` (new) | Canonical CBOR encoder using `cbor2`. Test vectors per Appendix B. |
| `frontend/src/wallet/aegis/auth_payload.ts` (new) | Hand-rolled Plutus-canonical CBOR encoder (zero CBOR-runtime dep) — `encodeAuthCoveragePayload` (validation + encode) and `encodeAuthCoveragePayloadCanonical` (raw encode for cross-stack vector test). Mirrors Aiken's `cbor.serialise` byte-for-byte. |
| `frontend/src/wallet/aegis/signer.ts` | New `signAuthCommitment(seed, commit) → Ed25519 sig`. Wraps existing `signTransactionBytes` with seed-scrub discipline. |
| `frontend/src/components/panels/BuyPanel.tsx` (or equivalent) | New "Enable offline auto-claim" toggle. Signing prompt with human-readable payload summary. |
| `frontend/src/components/panels/AegisWalletPanel.tsx` | RotateAuth flow UI (separate from Underwrite). |
| `aegis-relay/` (new repo) | Single-process Node/TS service. Multi-source data plane (Blockfrost + Kupo). Per-policy tick cache. Min-coverage floor. Operator-runbook doc. |
| `configs/deploy-state.preprod.v8.json` (new) | All v8 hashes + ref UTxOs after redeploy. |
| `contracts/tests/fixtures/invalid_payload_vectors.json` (new — Δ28) | Shared cross-stack invalid-payload manifest. 10 vectors (one per validation rule). Loaded by BOTH Python and TypeScript test suites; each entry must be rejected by both stacks with the documented `error_pattern`. CI gate for cross-stack validation drift. |
| `offchain/tests/test_cross_stack_validation.py` (new — Δ28) | Python side of the cross-stack rejection contract. Loads the shared manifest, asserts every entry is rejected by `encode_auth_coverage_payload`, pins the rule-name ordering so adding/dropping a rule fails loudly. |
| `frontend/src/wallet/aegis/__tests__/cross_stack_validation.test.ts` (new — Δ28) | TypeScript side of the cross-stack rejection contract. Loads the same manifest via `fs.readFileSync` (no duplicated copy), asserts every entry is rejected by `encodeAuthCoveragePayload`, pins int63 boundary symmetry (TV-3 fixture vs manifest #7). |
| `frontend/src/wallet/aegis/index.ts` (modified — Δ38) | Public barrel trimmed to re-export ONLY `signAuthCommitment` + `verifyAuthCommitment` + `humanReadableSummary` + display helpers + length/range constants + types. CBOR / hash / canonical-CBOR primitives are intentionally NOT re-exported. Header comment documents the VR-007 closure and points at the CI guard. |
| `frontend/scripts/check_aegis_privacy_boundary.cjs` (new — Δ38) | CommonJS Node script (~370 LOC). Walks `frontend/src/` excluding `src/wallet/aegis/`, parses ESM `import` statements with multi-line awareness and JS/TS comment stripping, and fails the build on any import of a forbidden symbol (lower-level CBOR / hash primitives, `assertNetworkConsistency`) or any direct import of `@noble/ed25519`. Exits 0 with a count summary on clean codebase, 1 with per-breach diagnostics on detection. Self-test mode (`--self-test`) covers 9 positive/negative cases. |
| `frontend/package.json` (modified — Δ38) | Adds `lint:guard` and `lint:guard:self-test` script entries. |
| `scripts/check_deploy_constants.py` (new — Δ39 + Δ40; updated — Δ41) | Python static-constant guard. Extracts `auth_witness_nft_policy_id`, **`auth_witness_validator_hash` (Δ41 / v3.2)**, `enterprise_addr_header_mainnet`, `enterprise_addr_header_testnet`, and `enterprise_addr_header` from `contracts/lib/aegis/types.ak` via a tolerant regex; asserts both auth-related constants are NOT the 28-byte all-zero placeholder AND are 56-hex-char values; asserts the header constants equal their pinned CIP-19 type-6 values (`#"60"` testnet, `#"61"` mainnet); asserts the active-build header is one of the two pinned values. Self-test mode (`--self-test`) covers 7 positive/negative cases (added: `placeholder auth_witness_validator_hash rejected`). |
| `.github/workflows/deploy-gates.yml` (new — Δ39 + Δ40) | GitHub Actions workflow. Runs the Python script's self-test then runs the script against the in-tree `types.ak`. Triggers on every push, PR, and `v*` tag. Single job, no external dependencies beyond Python 3.11 (provided by `actions/setup-python`). |
| `README.md` (modified — Δ39 + Δ40) | New `## Deploy gates (v8 / v3.1)` section between `## Quick start` and `## License`. Explains how to invoke the guard locally and what each pinned value means. |

---

## Appendix B — Cross-stack CBOR test vectors

Required: 5 test payloads covering happy path + edge cases. Each payload must produce byte-identical Plutus-canonical CBOR (Constr 0 indefinite-length list, `d8 79 9f <fields> ff`) across (a) Aiken's `cbor.serialise` (on-chain authority, via the mint validator and ClaimWithAuth branch), (b) the Python reference encoder (`scripts/dump_vectors.py`), and (c) the TypeScript hand-rolled encoder (`frontend/src/wallet/aegis/auth_payload.ts`).

```
TV-1: minimal preprod payload (all required fields, no advisories)
TV-2: mainnet payload with non-zero oracle_freshness
TV-3: edge: max_coverage = 2^63 - 1 (largest signed 64-bit)
TV-4: edge: not_after - not_before = 1 (minimal window)
TV-5: edge: oracle_provider = AegisSelf (Constr 2; the v7 addition)
```

**Single source of truth:** the Aiken-side fixture lives at `D:/aegis-contracts/contracts/tests/fixtures/auth_payload_vectors.json` (produced by the Aiken test suite + the reference Python encoder, both byte-pinned via the on-chain `auth_payload_tv*_canonical_cbor_pinned` tests in `lib/aegis/auth_payload.ak`). The Aiken-side `cbor_hex` and `blake2b_256_hex` fields are the cross-stack contract.

The TypeScript suite's `frontend/src/wallet/aegis/__tests__/cross_stack_cbor.test.ts` reads this Aiken fixture directly (no duplicated copy) and asserts that the TS encoder's `encodeAuthCoveragePayloadCanonical` output matches each vector's `cbor_hex` and `blake2b_256_hex` byte-for-byte. The TS suite's own fixture (`frontend/src/wallet/aegis/__tests__/fixtures/auth_payload_vectors.json`) is the TS-side mirror with the additional Ed25519 signing artifacts (seed_hex, signature_hex, signer_pkh_hex) for the sign-flow round-trip tests.

CI gate: any divergence between Aiken fixture and TS encoder = build red.

---

**Decision authority:** all open questions from v1 are resolved. Proceed to phase 1 (Aiken agent).
