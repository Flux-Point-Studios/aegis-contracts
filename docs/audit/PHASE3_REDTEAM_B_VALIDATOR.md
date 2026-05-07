# Phase 3 Red-Team B — Aiken Validator Layer (v8 Relay-Presigned-Auth)

**Auditor angle:** Aiken validator logic, witness UTxOs, mint policy, redeemer flows.
**Date:** 2026-05-06.
**Build under review:** D:/aegis-contracts/contracts (aiken v1.1.21+42babe5, 305/305 tests green).
**Spec under review:** RELAY_PRESIGNED_AUTH_SCOPE_v2.md (the v8 spec).
**Mandate:** Adversarial review of the on-chain layer prior to mainnet. Find the holes.

---

## Executive Summary

The v8 on-chain implementation has **two CRITICAL bugs that turn the relay-presigned-auth feature from "audit-grade" to "broken-on-mainnet"**, plus several **defense-in-depth gaps** that should be closed before tagging `v8.0.0`. The existing 305-test suite is largely composed of *property* tests on isolated helpers (`derive_policy_id`, `is_valid_commit_length`, `oracle_provider_to_int`) and **does not exercise either of the CRITICAL bugs in an end-to-end Transaction context**. That gap is itself a finding (V-005 below).

| # | Severity | Finding | Status |
|---|---|---|---|
| **V-001** | **CRITICAL** | `auth_witness_nft.MintWitness` requires `init_utxo_ref` consumption on **every** mint — feature is one-mint-only across the deployment lifetime. | **OPEN, ship-block** |
| **V-002** | **CRITICAL** | `auth_witness_nft.BurnWitness` allows anyone to burn any live witness without consuming the policy. DoS on the entire relay-auth path. | **OPEN, ship-block** |
| **V-003** | HIGH | `BatchUnderwrite` does NOT verify `derive_policy_id` (Δ3 not wired through) — same-terms `policy_id` collision still possible via the batch path. | **OPEN** |
| **V-004** | HIGH | `auth_witness_nft_policy_id` constant is the all-zeros placeholder (`#"0000…"`), not a real hash. Without the post-deploy update, `collect_witnesses` returns `count == 0` for every reference input — `ClaimWithAuth`/`RotateAuth` are unreachable. | **OPEN** |
| **V-005** | HIGH | No end-to-end Aiken `test`-context coverage of `auth_witness_nft` mint/burn validator. V-001 + V-002 would have been caught by 1 green-path + 2 negative tests. | **OPEN** |
| **V-006** | MED | `RotateAuth` `cont_output_opt` uses `list.find` — first-match. An attacker-controlled "decoy" policy_validator output can be placed first; subsequent outputs at the same address are unconstrained. | **OPEN** |
| **V-007** | MED | `ClaimWithAuth` does NOT bind 11 of the 14 `AuthCoveragePayload` fields (`domain_tag`, `network_magic`, `policy_validator`, `insured_pkh`, `max_coverage`, `oracle_nft`, `oracle_freshness`, `not_before`, `not_after`, `pool_script_hash`, `pool_nft`) to the policy datum / network constants. Defense-in-depth gap; closed off-chain by the wallet UI but the on-chain belt+suspenders is missing. | **OPEN** |
| **V-008** | MED | `auth_witness_nft.BurnWitness` does not verify the burn txn was authored by the operator-only sweeper key (Δ15). Spec §3.5 says k≥20 confs + sweeper sig; on-chain there is no signature gate. | **OPEN** |
| **V-009** | LOW | `auth_witness_nft` `network_tag` parameter is checked only for non-empty (`!= #""`); a 1-byte tag would silently pass. Sanity gate is too weak. | **OPEN** |
| **V-010** | LOW | `RotateAuth`'s "new witness must be unique" check (`exactly_one_new_witness`) tolerates a no-op rotation — re-using the *existing* witness (no mint) passes if `new_commit == old_commit`. Spec §2.5 implies a fresh mint is required; not enforced. | **OPEN** |
| **V-011** | LOW | `auth_witness_validator.spend` accepts a burn even if the witness UTxO carries multiple asset names under `auth_witness_nft_policy_id` (one of which is being burned, others stranded). The `expect [Pair(asset_name, qty)] = …` would fail; defense by datum-shape rejection. Treat as documented. | **NOT A BUG** |
| **V-012** | INFO | `oracle_freshness` payload field is documented as advisory; on-chain it is not used at all. Spec is correct. | **NOT A BUG** |

**Severity tally:** 2 CRITICAL · 3 HIGH · 3 MED · 2 LOW · 2 informational/false-positive.

**Top-3 fixes by impact:**
1. V-001 — change `MintWitness` to drop the `init_utxo_ref`-consumption requirement (only the policy-id parameterisation buys the per-deployment uniqueness; the per-mint guard belongs to the Underwrite/RotateAuth path-validity check, which is already there).
2. V-002 — change `BurnWitness` to require the policy UTxO to be consumed in the **same tx** with `Cancel`/`Expire`/`Claim`/`ClaimWithAuth`, not absent from inputs.
3. V-003 — wire `derive_policy_id` through `batch_policies_match_totals`, identical to the `policy_output_matches_underwrite` check.

---

## §11 Traceability Audit — does any "closed" finding still have a gap?

| Finding | Spec claims closed by | Actual implementation status |
|---|---|---|
| C-1 (witness mint forgeable) | Δ1 + Δ2 + Δ17 | **NOT CLOSED** — V-001 makes minting impossible after the first deploy-time mint. The Δ2 "true one-shot over OutputReference" wording was implemented as one-shot **per mint** instead of one-shot **per deployment**. Closes the original C-1 by accident (mint impossible ⇒ also unforgeable ⇒ feature broken). |
| F-AUTH-2 (mint policy not one-shot) | Δ2 + Δ17 | **NOT CLOSED in the way the spec intends** — see V-001. |
| F-AUTH-3 (witness-stuffing DoS) | Δ7 (`length(witnesses) == 1`) | **CLOSED** — `collect_witnesses` returns the count. |
| F-AUTH-4 (payout binding gap) | Δ9 | **CLOSED** — step 16 of ClaimWithAuth checks `payload.payout_address == enterprise_addr_of(datum.insured)`. |
| F-AUTH-5 (oracle_provider missing) | Δ5 | **CLOSED** — step 14 of ClaimWithAuth checks the int tag. |
| F-AUTH-6 (commit length not validated) | Δ12 | **CLOSED** — step 2 of ClaimWithAuth + RotateAuth. |
| H-1 (cross-network sig replay) | Δ4 + Δ16 | **PARTIALLY CLOSED** — see V-007. The on-chain validator does NOT check `payload.domain_tag` / `payload.network_magic` against compile-time constants. Defense relies entirely on the off-chain wallet UI + per-network validator-hash rotation. |
| H-2 (sig malleability) | Δ11 | **CLOSED** — `verify_ed25519_signature` builtin enforces strict-S. |
| H-3 (policy_id collision) | Δ3 | **PARTIALLY CLOSED** — `policy_output_matches_underwrite` enforces. `batch_policies_match_totals` does **not** (V-003). |
| F-1 / F-2 / F-4 / F-5 / F-6 | (off-chain) | Out of scope for this red team. |

**Coverage gap: 4 of the 12 spec-listed CRITICAL+HIGH closures are weaker on-chain than the §11 traceability table claims.** The spec is correct about *intent*; the implementation has gaps.

---

## V-001 — CRITICAL — `auth_witness_nft.MintWitness` is one-shot for the entire deployment lifetime

### Threat & invariant broken
Per spec §2.5, "Created [witness UTxO]: at Underwrite (atomic mint…). 1× NFT minted under deployed `auth_witness_nft_policy_id` with asset name `blake2b_224(policy_id)`." The protocol design requires **one mint per policy** (and one additional mint per RotateAuth).

The implementation in `auth_witness_nft.ak` enforces a stricter invariant: every `MintWitness` call must consume the parameterized `init_utxo_ref`. Since a UTxO can only be spent once on Cardano, this means **only ONE successful `MintWitness` ever** across the deployment.

### Evidence
`D:/aegis-contracts/contracts/validators/auth_witness_nft.ak`, lines 98-103:

```aiken
// 4. The init_utxo_ref must be consumed in this tx (one-shot).
// This is the ONLY guarantee that prevents replay-mints; without
// it an attacker could mint a second witness for any policy at
// any later time. (Closes F-AUTH-2 / C-1.)
let one_shot_consumed =
  list.any(inputs, fn(i) { i.output_reference == init_utxo_ref })
```

The comment is the developer's mental model — they thought of the init UTxO as a per-mint anti-replay token. The actual semantic is per-deployment. The validator's final return expression `exactly_one_minted && only_one_under_policy && one_shot_consumed && payload_policy_id_ok && (underwrite_path_valid || rotate_auth_path_valid) && network_tag_ok` ANDs `one_shot_consumed` in.

This is the same mistake the `pool_nft` policy makes intentionally — `pool_nft` is a TRUE singleton, mintable exactly once. `pool_nft.ak` line 53-54: `let init_utxo_consumed = list.any(inputs, fn(input) { input.output_reference == utxo_ref })`. The pattern was copied without re-deriving the security argument.

### Repro
1. Operator deploys auth_witness_nft policy parameterized over `init_utxo_ref = U1`.
2. User A creates Policy 1 with auth via Underwrite. Tx consumes U1 + mints witness for Policy 1. Tx accepted.
3. User B creates Policy 2 with auth via Underwrite. Tx attempts to consume U1 — **fails**: U1 was spent in step 2. No alternative input satisfies the `list.any` guard. Mint validator rejects.
4. From now on, no policy can ever have `auth_commitment != None`. The relay-presigned-auth feature is bricked.

### Why no test catches this
The Phase-1 test file `v8_auth_tests.ak` covers the validator's logical primitives (asset-name binding, policy-id derivation, commit length, oracle-provider tags) but never instantiates a `Transaction` and runs `auth_witness_nft.mint` against it. The closest test, `test_fauth2_mint_policy_one_shot_per_init_ref`, only asserts `init_a != init_b` — i.e., that *two distinct OutputReferences are distinct*, not that the validator behaves correctly when called twice.

### Severity: CRITICAL
The relay-presigned-auth feature is the headline v8 deliverable. After the first user, every subsequent user cannot opt in. On preprod this is "feature-disabled"; on mainnet it is "all coverage policies after the first lose the auto-claim safety net" — a value-loss class because the very policies the user expected to auto-trigger will silently revert to in-browser-only.

### Proposed fix
Drop the `one_shot_consumed` AND from the return expression. The `init_utxo_ref` parameter remains — its job is to make the policy id one-shot-per-deployment (the parameter is hashed into the script, so two deployments with different init_refs produce different policy ids). The per-mint security comes from `(underwrite_path_valid || rotate_auth_path_valid)`, which already binds the mint to either a fresh PolicyDatum output (Underwrite) or a consumed PolicyDatum input (RotateAuth). Both of those are the actual anti-forgery checks; `one_shot_consumed` is redundant *and* breaks the protocol.

```aiken
// 4. (REMOVED) init_utxo_ref consumption was incorrectly required per-mint.
//    The parameter is a compile-time hash input — it makes the policy id
//    one-shot-per-deployment (different deployments produce different policy
//    ids), but it is NOT consumed at runtime. Per-mint anti-forgery is
//    enforced by underwrite_path_valid || rotate_auth_path_valid below.

exactly_one_minted && only_one_under_policy && payload_policy_id_ok
  && (underwrite_path_valid || rotate_auth_path_valid)
  && network_tag_ok
```

Add a green-path test: `Transaction { inputs: [...], outputs: [policy_output, witness_output], mint: +1 witness, ... }` with redeemer `MintWitness { policy_id, payload_cbor }` and assert the validator returns True.

Add a negative test: same Transaction but the policy_output has `auth_commitment = None` → assert validator returns False.

---

## V-002 — CRITICAL — `auth_witness_nft.BurnWitness` allows any third-party to destroy any live witness UTxO (DoS on relay-auth)

### Threat & invariant broken
Per spec §2.5, "Burned: after Cancel/Expire/Claim consumes the policy, anyone (or the operator-only sweeper, Δ15) can submit a tx that consumes the orphan witness, burns the NFT, and recovers the min-UTxO ADA. Sweeper requires k≥20 confirmations on policy non-existence to avoid reorg griefing."

The on-chain check in `auth_witness_nft.ak` at the burn path is:

```aiken
let policy_consumed_in_tx =
  list.any(inputs, fn(i) {
    when i.output.address.payment_credential is {
      Script(h) ->
        if h == policy_validator_hash {
          when i.output.datum is {
            InlineDatum(raw_pdat) -> {
              expect pdat: PolicyDatum = raw_pdat
              pdat.policy_id == policy_id
            }
            _ -> False
          }
        } else { False }
      _ -> False
    }
  })
let no_live_policy = policy_consumed_in_tx == False
```

The intent (per the in-code comment, line 188-193) is: "Burn allowed iff the policy with this policy_id has been Cancel/Expire/Claim'd in a PRIOR tx, so its UTxO no longer exists." But the actual check is `policy NOT in current tx inputs` — which is trivially satisfied by **any** burn-only tx that does not co-spend the policy.

Plutus has no way to assert "the policy UTxO does not exist on chain anywhere"; the only achievable on-chain check is "the policy is being consumed *with* a terminating redeemer in the same tx". The implementation chose the former (impossible) and degraded to the latter without realizing — the variable name `no_live_policy` is misleading.

### Evidence
`D:/aegis-contracts/contracts/validators/auth_witness_nft.ak`, lines 187-223 (full BurnWitness branch).

The `auth_witness_validator.spend` (separate validator at the witness UTxO's address) only checks that the matching NFT is being burned in the same tx (`assets.quantity_of(mint, auth_witness_nft_policy_id, asset_name) == -1`). It does NOT cross-check the BurnWitness redeemer's policy gate. So as long as `BurnWitness { policy_id }` is called with a non-consumed policy_id, the spend succeeds AND the burn succeeds.

### Repro
1. Victim has an active Policy P with witness UTxO W at auth_witness_validator. Policy is not yet claimed.
2. Attacker observes W on chain (public knowledge — every tx mints a labelled NFT).
3. Attacker submits a burn-only tx:
   - **inputs:** [W, attacker_collateral_utxo]
   - **redeemer (auth_witness_validator):** any (the validator ignores it)
   - **redeemer (auth_witness_nft, policy id):** `BurnWitness { policy_id: P.policy_id }`
   - **mint:** `-1` of `(auth_witness_nft_policy_id, blake2b_224(P.policy_id))`
   - **outputs:** [attacker_change with W's recovered min-UTxO ada]
4. `auth_witness_validator.spend` checks: NFT being burned (yes) ⇒ pass.
5. `auth_witness_nft.BurnWitness` checks: P NOT in inputs (true) ⇒ pass. Burn succeeds.
6. W is destroyed. Policy P's `auth_commitment` is still `Some(commit)` on chain, but no witness UTxO exists.
7. Relay's `ClaimWithAuth` for P fails (`exactly_one_witness == False`, count=0).
8. User's `RotateAuth` for P fails (same reason).
9. User's only remaining options: `Cancel` (within 1h window only), `Expire` (after policy expiry), or in-browser `Claim` (requires Aegis-wallet signing UX, still works because it doesn't read the witness).

### Cost-to-damage
Attacker pays: ~0.2 ADA tx fee. Attacker gains: ~3.5 ADA min-UTxO ada from W (positive ROI). Damage to victim: relay-auth path is bricked for that policy's lifetime. Multiplied across the entire user base, the relay business case collapses.

### Severity: CRITICAL
The relay-presigned-auth feature can be denied to any user at any time, by any third party, at a profit. A grief-ROI attack is in the worst class — the attacker is *paid* to deny service.

### Proposed fix
The burn must require the policy UTxO to be co-spent in the same tx (i.e., be claimed/expired/cancelled in the SAME tx). Replace the inverted check with the direct check:

```aiken
BurnWitness { policy_id } -> {
  // Burn allowed iff the policy with this policy_id is ALSO being
  // consumed (Cancel/Expire/Claim/ClaimWithAuth) in this same tx.
  // Plutus cannot prove "policy no longer exists on chain"; we instead
  // prove "policy is being terminated right now", which is strictly
  // safer (the burn cannot precede the termination).
  let policy_terminated_now =
    list.any(inputs, fn(i) {
      when i.output.address.payment_credential is {
        Script(h) ->
          if h == policy_validator_hash {
            when i.output.datum is {
              InlineDatum(raw_pdat) -> {
                expect pdat: PolicyDatum = raw_pdat
                pdat.policy_id == policy_id
              }
              _ -> False
            }
          } else { False }
        _ -> False
      }
    })

  let expected_asset_name = blake2b_224(policy_id)
  let burn_qty =
    assets.quantity_of(mint, own_policy_id, expected_asset_name)
  let burn_one = burn_qty == -1

  policy_terminated_now && burn_one
}
```

This forces every burn into a 2-script-input tx (policy + witness), which is governed by:
- The policy validator's chosen redeemer (Cancel/Expire/Claim/ClaimWithAuth), each of which has its own bindings.
- The `auth_witness_validator.spend`'s NFT-burn check.

The resulting attack surface is "any user-initiated termination tx can also burn the witness in-line" — which is the correct semantic (saves the user the orphan-cleanup tx fee).

For the orphan-cleanup case (policy already terminated in prior tx, witness lingers), spec §3.5 calls for an operator-only sweeper. Implement that as a separate `SweepBurn` redeemer variant that requires the operator's signature in `extra_signatories` instead of policy co-spend. Out-of-scope for the immediate fix; document as a follow-up.

### Test to add
- **Green:** Tx with [policy_input (Cancel), witness_input, mint -1 witness] → BurnWitness passes.
- **Red (attack repro):** Tx with [witness_input, mint -1 witness] (no policy input) → BurnWitness fails.

---

## V-003 — HIGH — `BatchUnderwrite` does not enforce `derive_policy_id` (Δ3 not wired through batch path)

### Threat & invariant broken
Per spec §1.8, "the off-chain Underwrite builder must commit the chosen input ref to the policy_id at sig time, and the validator's pool-side Underwrite check must verify `pdat.policy_id == derive_policy_id(...)`". This closes H-3 (policy_id collision via same-terms policies).

`policy_output_matches_underwrite` (the single-Underwrite path) enforces this (`pool.ak` line 219-228). `batch_policies_match_totals` (the BatchUnderwrite path) does NOT.

### Evidence
`D:/aegis-contracts/contracts/validators/pool.ak`, lines 84-151 — the entire `batch_policies_match_totals` body. The check that should be there:

```aiken
// MISSING in BatchUnderwrite — present in single Underwrite at line 219-228:
let policy_id_ok =
  pdat.policy_id == derive_policy_id(
    pdat.insured, pdat.strike_price, pdat.coverage_amount,
    pdat.start_time, pdat.expiry_time, pdat.pool_nft,
    /* anchor: ??? */ )
```

The reason for the gap: BatchUnderwrite consumes ONE pool input and emits N policy outputs; there's only one `OutputReference` for the consumed pool, but each policy needs to commit to a *different* anchor to keep `policy_id`s distinct. The single-Underwrite case uses `own_ref` as the anchor (line 386: `own_ref`); the batch case has no obvious choice without redesigning the redeemer.

### Repro
1. Attacker (or honest user) submits BatchUnderwrite for 2 policies with identical `(insured, strike, coverage, start, expiry, pool_nft)`. Each policy datum includes a `policy_id` field — caller-controlled, no on-chain check.
2. Both policies have **identical caller-supplied `policy_id`**. The witness asset name `blake2b_224(policy_id)` is identical for both.
3. At ClaimWithAuth time, BOTH policies require the same witness UTxO. The `collect_witnesses` count is at most 1 (one mint per asset name), so only one of the two can be claimed. The other is permanently locked into the auth path.

This is a smaller blast radius than the original H-3 (no value drain), but it does enable a class of liveness attacks on batched same-terms policies. Honest users batching multiple identical-coverage policies (e.g., "2 × 100 ADA × $0.30 strike") would silently end up unable to use the relay-auth path on more than one of them.

### Severity: HIGH
H-3 is rated HIGH in §11. The closure is incomplete — a user-facing footgun for legitimate batch underwriting. Pre-mainnet this MUST be wired through.

### Proposed fix
Pick a deterministic anchor that distinguishes each policy in the batch. Two options:

1. **Per-output anchor:** redefine `derive_policy_id` for the batch case to include the policy's own `OutputReference` (computable on-chain since each output has an index in `outputs`). But OutputReference of an output is `Hash(tx_id, index)` — the tx_id isn't known at validation time (it's the hash of the tx body, which the validator is *part of*). Forget this.

2. **Anchor = (own_ref, output_index_in_batch):** the redeemer carries `BatchUnderwrite { total_coverage, total_premium, anchors: List<OutputReference> }` where anchors[i] is the i-th policy's anchor. The validator iterates outputs, and for the i-th policy output, the anchor is `anchors[i]`. Each anchor is a unique `(own_ref, i)` pair derived as something like `OutputReference { transaction_id: own_ref.transaction_id, output_index: i }`. The off-chain builder mirrors the construction.

3. **Anchor = (own_ref, hash of policy fields):** even simpler — the anchor for the i-th policy is `own_ref` and we add the policy_id derivation a *salt* parameter that is unique per output. This requires extending `derive_policy_id` with a salt parameter; the off-chain builder picks `salt = i`.

Option 2 is the cleanest. Implement; add 2 negative tests (two policies with same anchor → reject; two policies with same caller-supplied policy_id but the validator's `derive_policy_id` produces a different one → reject).

---

## V-004 — HIGH — `auth_witness_nft_policy_id` is the all-zeros placeholder

### Threat & invariant broken
The `ClaimWithAuth` and `RotateAuth` branches use `auth_witness_nft_policy_id` (a compile-time constant in `types.ak`) to filter reference inputs for the witness NFT. Per Δ17, this constant is pinned at validator-hash level — a wrong value is a fail-closed regression.

### Evidence
`D:/aegis-contracts/contracts/lib/aegis/types.ak`, lines 615-616:

```aiken
pub const auth_witness_nft_policy_id: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000"
```

The comment at lines 608-614 acknowledges the value is a placeholder pending first preprod deploy. **The current implementation will not match any real witness UTxO at validation time** — `assets.quantity_of(input.output.value, #"0000…0000", asset_name)` returns 0 for every reference input (no real NFT will ever be minted under the all-zeros policy id).

### Severity: HIGH
This is a "ship-block" detail rather than a security bug — the placeholder value WILL be detected at first integration test. But:
1. There is no compile-time validation that the constant is a real 28-byte hash (i.e., the all-zeros value compiles fine — the Aiken type system doesn't reject it).
2. If shipped to mainnet with the placeholder, the entire ClaimWithAuth + RotateAuth surface is dead code. Defense-in-depth: the validator hash would still rotate (different from the v6 hash), so it's not catastrophic — but the v8 redeploy would silently lack the headline feature.
3. The deploy-state JSON (per Phase 4 of the spec) is supposed to be rebuilt with the actual hashes; if that step is forgotten, the placeholder ships.

### Proposed fix
Two options:
1. **Build-time gate:** add an `aiken check` test that asserts `auth_witness_nft_policy_id != #"0000…0000"` AND `bytearray.length(auth_witness_nft_policy_id) == 28`. Before tagging v8, this test must be green. (Requires the operator to deploy auth_witness_nft once, capture its policy id, replace the constant, rebuild.)
2. **Make it a parameter:** parameterize `policy_validator` over `auth_witness_nft_policy_id` (same way `pool_validator` is parameterized over `policy_script_hash`). The off-chain `aiken blueprint apply` step inserts the actual hash at deploy time. Cleaner, eliminates the typo class.

Option 2 is recommended — it generalizes to any future "compile-time pin to another validator's hash" need.

---

## V-005 — HIGH — No end-to-end Aiken `Transaction`-context test for `auth_witness_nft` mint or burn

### Threat & invariant broken
The Phase-1 acceptance gate requires "≥30 new green tests covering: ClaimWithAuth happy path, RotateAuth happy path, every CRITICAL/HIGH finding from the design red-team converted to a negative test, every §8 invariant" (spec §10).

Examining `D:/aegis-contracts/contracts/lib/aegis/test_helpers/v8_auth_tests.ak` — 57 tests are present, all of them assert *property* lemmas on isolated helpers (length checks, hash distinctness, sum-type tag values). **Zero tests construct a `Transaction` and invoke `auth_witness_nft.mint(redeemer, policy_id, self)` against it.** Same for `auth_witness_validator.spend` and the `policy.ClaimWithAuth` / `policy.RotateAuth` branches — they have property-level tests but no end-to-end Transaction tests.

The pre-existing `security_tests.ak` (from v6) DOES have full Transaction-context tests for the v6 surfaces (Underwrite, Claim, etc.). The v8 additions stopped short of that bar.

### Evidence
- `v8_auth_tests.ak` test names beginning with `test_*` (57 of them) — none invoke a validator. Skim of every body confirms.
- `security_tests.ak` test names like `test_a009_*`, `test_a013_*` — DO build full Transactions. Pattern not replicated for v8.

### Why this matters
V-001 and V-002 — both CRITICAL, both shippable with the current 305-test green baseline — would have been caught by 4 mid-sized integration tests:
1. Green `MintWitness` after the init UTxO is already spent (catches V-001).
2. Green `BurnWitness` with no policy in inputs (catches V-002 — the test SHOULD fail, but currently passes because the validator accepts).
3. Green `BurnWitness` with the policy being Cancel'd in same tx (the intended-correct path).
4. Negative `MintWitness` with attacker-substituted PolicyDatum.

### Severity: HIGH
The test gap is a process bug, not a chain bug. Severity is HIGH because it is the proximate cause of V-001 and V-002 reaching the audit-grade gate. Mainnet pre-flight checklist must include "Aiken Transaction-context tests for every v8 validator branch".

### Proposed fix
Add a new test module `lib/aegis/test_helpers/v8_validator_integration.ak` with full Transaction fixtures for:
- `auth_witness_nft.MintWitness` (green + 4 negatives)
- `auth_witness_nft.BurnWitness` (green + V-002 attack repro)
- `auth_witness_validator.spend` (green burn-with-mint + 2 negatives: spend without burn, spend with continuation)
- `policy.ClaimWithAuth` (green + per-step negative)
- `policy.RotateAuth` (green + V-006 attack repro)

Target: 30+ new tests. Phase 1 acceptance gate is then ACTUALLY met.

---

## V-006 — MED — `RotateAuth` `cont_output_opt` first-match invariant gap

### Threat & invariant broken
In `policy.ak` `RotateAuth` branch, the continuation policy UTxO is found via `list.find(outputs, …)` — first-match by `payment_credential == Script(own_script_hash)`. Subsequent outputs at the same address are unconstrained.

### Evidence
`policy.ak` line 560-569:

```aiken
let cont_output_opt =
  list.find(
    outputs,
    fn(out) {
      when out.address.payment_credential is {
        Script(h) -> h == own_script_hash
        _ -> False
      }
    },
  )
expect Some(cont_output) = cont_output_opt
```

If the attacker constructs a tx with two outputs at the policy_validator address — first one satisfying all the field-equality checks (`datum_unchanged_except_commit`, `value_preserved`, etc.), second one with attacker-chosen datum — only the FIRST is checked.

### Repro and impact
The attacker would need a way to fund the second output. The pool is not co-spent in RotateAuth, so the attacker pays the lovelace from their own wallet. The second output is then a "free-standing" PolicyDatum at the policy_validator address that wasn't created via Underwrite — it has no entry in `pool.active_coverage`, no premium was paid.

To weaponize, the attacker would have to claim against this rogue policy. But `policy.Claim` requires `pool_receives_remainder`, which requires the canonical pool output. Without consuming and recreating the pool, no canonical pool output exists. Result: the rogue policy can be CREATED but never CLAIMED.

So immediate value-extraction is blocked. But:
- The rogue policy is on-chain forever (unspendable, since no redeemer can satisfy `pool_receives_remainder`).
- An attacker could spam-create rogue policies to bloat the index and confuse off-chain bookkeeping.
- Future protocol upgrades that loosen the pool-co-spend requirement could turn this latent bug into a value attack.

### Severity: MED
No clear value-drain at v8. Cleanup hygiene + future-proofing.

### Proposed fix
Replace `list.find` with a fold-counting approach (same pattern as `policy_output_matches_underwrite`'s A-025 fix):

```aiken
let cont_count =
  list.foldl(outputs, 0, fn(out, acc) {
    when out.address.payment_credential is {
      Script(h) -> if h == own_script_hash { acc + 1 } else { acc }
      _ -> acc
    }
  })
let exactly_one_continuation = cont_count == 1
```

Then `expect Some(cont_output) = cont_output_opt` still works (find is fine *if* there's only one). Add `exactly_one_continuation` to the return AND.

---

## V-007 — MED — `ClaimWithAuth` does not bind 11/14 payload fields to datum/network

### Threat
Per §8 invariant table: "Cross-network sig replay → `domain_tag` includes `_PREPROD` / `_MAINNET` (Δ4) + `network_magic` numeric." This is intended as a two-leg defense. The on-chain validator only relies on the validator-hash being different per network; it does NOT actually check `payload.domain_tag` or `payload.network_magic`.

Likewise: `payload.policy_validator`, `payload.insured_pkh`, `payload.max_coverage`, `payload.oracle_nft`, `payload.oracle_freshness`, `payload.not_before`, `payload.not_after`, `payload.pool_script_hash`, `payload.pool_nft` — none are checked against the policy datum or compile-time constants. Only `policy_id`, `payout_address`, `oracle_provider` are checked.

### Why it doesn't immediately break
The user signs the canonical CBOR, which IS what gets hashed into the commit. So the bytes the user signs are exactly the bytes the validator reads. If the user signs a payload with bogus `max_coverage = 1`, the validator accepts (because it doesn't check), but the validator uses `datum.coverage_amount` as the actual on-chain enforcement value, so the bogus payload field has no value-flow effect.

### When it COULD break
1. **Off-chain UI bug:** if the wallet's human-readable summary skips a field, the user signs an attacker-substituted payload (e.g., wrong `pool_script_hash`) without noticing. The on-chain validator doesn't catch the substitution because it doesn't check.
2. **Cross-network confusion:** if dev keys are reused across preprod/mainnet (per memory's A-028 BIP-44 finding), and someone accidentally deploys with the same `policy_validator` hash on both networks, a preprod-signed payload would be accepted at mainnet because `domain_tag` and `network_magic` aren't checked.
3. **Future schema evolution:** if v9 adds a 13-th PolicyDatum field, and the payload structure isn't simultaneously rotated, a v8-witness-with-old-payload could still hash to the v9 commit and get past the validator.

### Severity: MED
Defense-in-depth is the design intent of the §8 table. The on-chain belt-and-suspenders is missing.

### Proposed fix
Add to the `ClaimWithAuth` AND chain:

```aiken
// V-007: belt — verify the signed payload's network/binding fields
// match the active-network compile-time constants.
let domain_ok = payload.domain_tag == auth_domain_tag
let network_ok = payload.network_magic == network_magic
let validator_ok = payload.policy_validator == own_script_hash
let insured_ok = payload.insured_pkh == datum.insured
let oracle_nft_ok = payload.oracle_nft == datum.oracle_nft
let coverage_ok = payload.max_coverage == datum.coverage_amount
let not_before_ok = payload.not_before == datum.start_time
let not_after_ok = payload.not_after == datum.expiry_time
let pool_hash_ok = payload.pool_script_hash == datum.pool_script_hash
let pool_nft_ok = payload.pool_nft == datum.pool_nft
```

These are 10 cheap byte comparisons. Same for the auth_witness_nft mint validator (Underwrite path) — currently only `policy_id`, `commit`, `oracle_provider` are bound; the other 11 fields are not checked at mint time either.

---

## V-008 — MED — `BurnWitness` lacks operator-only signature gate (Δ15)

### Threat
Spec §3.5 / Δ15 requires the sweeper to be operator-only with k≥20 confirmations on policy non-existence. On-chain, the burn path has no signature check at all — once V-002 is fixed (require policy co-spend), any user can burn on their own policy termination, but the *orphan-cleanup* sweeper has no on-chain gate.

The orphan case arises when policy was Cancel/Expire/Claim'd in a PRIOR tx without burning the witness in the same tx. Then the witness UTxO lingers. Per spec, only the operator's sweeper bot should clean these up (after k≥20 confs to avoid reorg griefing).

### Why it's MED, not HIGH
After V-002 is fixed, the only remaining issue is the orphan-cleanup attack: an attacker grabs the ~3.5 ADA min-UTxO from any orphan witness. The economic loss per orphan is ~3.5 ADA — small. But:
1. The k≥20 confirmation requirement is a reorg defense; on-chain it's unenforced (Plutus has no slot-window concept beyond `validity_range`).
2. Sweeping into an attacker's pocket is still funding loss for the protocol.

### Proposed fix
Add a `SweepBurn` redeemer variant that requires `must_be_signed_by(extra_signatories, sweeper_vkh)` where `sweeper_vkh` is a compile-time constant. After the policy is terminated in a prior tx, only the sweeper (operator) can burn the orphan witness. Document the k≥20 confirmation as an operator-runbook requirement (not enforceable on-chain).

```aiken
SweepBurn { policy_id } -> {
  let signed_by_sweeper = must_be_signed_by(extra_signatories, aegis_sweeper_vkh)
  // ... same burn checks but without policy co-spend requirement
  signed_by_sweeper && burn_one
}
```

---

## V-009 — LOW — `network_tag` parameter sanity check is too weak

### Evidence
`auth_witness_nft.ak` line 180: `let network_tag_ok = network_tag != #""`.

A 1-byte `network_tag` (e.g., `#"00"`) passes. The spec intent is one of `"PREPROD"` / `"PREVIEW"` / `"MAINNET"` (UTF-8 bytes). The parameter is part of the validator-hash derivation, so a typo'd value still produces a legitimate (but misnamed) policy id. No security impact since the policy id is still unique per-deployment-per-typo. Pure operator-hygiene concern.

### Proposed fix
Tighter check, e.g.:

```aiken
let network_tag_ok =
  network_tag == "PREPROD"  // bytes #"50524550524f44"
  || network_tag == "PREVIEW"  // bytes #"50524556494557"
  || network_tag == "MAINNET"  // bytes #"4d41494e4e4554"
```

Or accept it as documentation-only and remove the runtime check (the parameter affects the policy id; off-chain build correctness is the right place for typo detection).

---

## V-010 — LOW — `RotateAuth` allows no-op rotation

### Evidence
The validator requires `commit_from_cbor(new_awd.payload_cbor) == new_commit` (line 602-603). If the attacker submits RotateAuth with `new_commit == old_commit` AND references the EXISTING witness as the "new" witness (no mint), the check passes:
- `commit_from_cbor(old_witness.payload_cbor) == old_commit == new_commit` ✓
- `exactly_one_new_witness` = 1 (the one already on-chain) ✓
- `new_witness_policy_id_ok` ✓ (same policy_id)
- `new_datum.auth_commitment == Some(new_commit)` = `Some(old_commit)` — no actual change

Result: the policy is consumed and recreated with the SAME datum. Nothing actually rotated. The user's CIP-30 sig is consumed, no new witness was minted, the on-chain state is identical.

### Severity: LOW
No value loss; the user pays a tx fee for a no-op. Nuisance class.

### Proposed fix
Require `new_commit != old_commit`:

```aiken
let actual_rotation =
  when datum.auth_commitment is {
    Some(old) -> old != new_commit
    None -> True  // first-time auth set after opt-out
  }
```

Or: require the new witness UTxO to be a freshly-minted one (i.e., the witness's OutputReference is a tx output of the current tx, not an existing input). This is harder to express on-chain — the validator can't directly compute "the OutputReference is fresh" without the tx_id (which is the tx body hash). Use the `actual_rotation` check instead.

---

## V-011 — NOT A BUG — multiple asset names under `auth_witness_nft_policy_id` on a witness UTxO

### Investigation
`auth_witness_validator.spend` line 52: `expect [Pair(asset_name, qty)] = assets_for_policy`. This pattern-match REQUIRES exactly one (asset_name, qty) pair under `auth_witness_nft_policy_id`. Multi-pair → match fails → spend fails (datum-shape rejection).

Since the mint policy enforces `only_one_under_policy = list.length(...) == 1`, no UTxO can have >1 token under the policy by construction. But what if a UTxO has 0? The `expect` fails — rejected. What about 2 from a misconfigured mint? The `only_one_under_policy` check prevents that at mint time.

Defense holds. Marked NOT A BUG.

---

## V-012 — INFO — `oracle_freshness` is advisory

### Investigation
Spec §2.1 docstring on the `oracle_freshness` field: "Advisory milliseconds — informational (not enforced on-chain). Encoded explicitly as `Int` (NOT `Option<Int>`) so the field is always present with a numeric value."

The validator does not read `payload.oracle_freshness` anywhere. Confirmed by grep. **Working as designed.** Off-chain consumers (wallet UI summary, audit logs) are responsible.

---

## False Positives — Attacks Tried That Fail Thanks to Existing Checks

### FP-1 — Witness asset name forgery via prefix-match
**Hypothesis:** spec says asset_name == policy_id (28 bytes). What if asset_name = policy_id || extra? Does the validator strict-equal?

**Test:** `assets.quantity_of(value, policy, asset_name)` returns the qty for the EXACT (policy, asset_name) pair. Plutus assets are strict-keyed; no prefix-match. Mint validator's `asset_name == blake2b_224(policy_id)` is a strict equality. Defense holds.

### FP-2 — Cross-policy witness reuse
**Hypothesis:** can a witness for Policy A be referenced when claiming Policy B?

**Test:** `collect_witnesses(reference_inputs, datum.policy_id)` filters by `assets.quantity_of(value, auth_witness_nft_policy_id, blake2b_224(datum.policy_id))`. Only witnesses with the exact asset name for Policy B's policy_id pass. Policy A's witness has a different asset_name (Hash distinctness). Defense holds.

### FP-3 — `count_script_inputs` bypass via reference inputs
**Hypothesis:** can multiple POLICY UTxOs be claimed in same tx by stuffing them as reference inputs (don't count as inputs)?

**Test:** Reference inputs are read-only. They cannot be "claimed" — claiming requires spending the policy UTxO, which puts it in `inputs`. `count_script_inputs(inputs, own_script_hash)` is the right scope. Defense holds.

### FP-4 — `count_script_inputs` bypass via non-script inputs
**Hypothesis:** can extra non-script (pubkey) inputs distort the count?

**Test:** `count_script_inputs` filters by `Script(h) -> h == script_hash`. Pubkey inputs are skipped. Defense holds.

### FP-5 — Underwrite same `init_utxo_ref` in two parallel mempool txs
**Hypothesis:** mempool race — two txs both consuming the operator's init_utxo_ref. Different OutputReferences for the resulting policy UTxOs → potentially different `policy_id`s → potentially different witness asset names.

**Test:** Once one tx is included on-chain, the init UTxO is spent; the other tx fails with `UtxoNotFound`. Cardano's UTxO model rejects double-spends. Defense holds.

(Note: this is moot for V-001 because no second mint can succeed anyway.)

### FP-6 — Cancel→Re-Underwrite same terms collision
**Hypothesis:** Cancel a policy, then Re-Underwrite with same terms. Same `policy_id`?

**Test:** `derive_policy_id` includes the consumed `OutputReference` (line 681 of types.ak). Each Underwrite consumes a different pool UTxO (the prior Underwrite/Claim/Cancel emitted a fresh pool continuation with a fresh OutputReference). So `policy_id`s differ. Defense holds **for single-Underwrite**; see V-003 for the BatchUnderwrite gap.

### FP-7 — Strict-S Ed25519 enforcement
**Hypothesis:** `verify_ed25519_signature` builtin enforces strict-S?

**Test:** The Plutus builtin (per Aiken's `aiken/crypto.verify_ed25519_signature`) wraps Cardano's underlying CIP-49 implementation, which DOES enforce strict-S since the Vasil hard fork. Defense holds.

### FP-8 — `auth_commitment` mutation mid-life via Cancel/Expire
**Hypothesis:** can the Cancel/Expire branches recreate the policy with mutated `auth_commitment`?

**Test:** Cancel and Expire route value to insured + pool; they DO NOT recreate the policy UTxO. The policy is consumed and not recreated (Cancel's fix to A-020 has the pool produce its own continuation). No surface for datum mutation through Cancel/Expire. Defense holds.

### FP-9 — `enterprise_addr_of` length / header attack
**Hypothesis:** what if attacker substitutes a different header byte (e.g., 0x70 base address)?

**Test:** `enterprise_addr_of(insured)` is `bytearray.concat(enterprise_addr_header, insured)` where `enterprise_addr_header` is the compile-time constant `#"60"` (preprod) or `#"61"` (mainnet). The validator computes this canonically; the attacker cannot inject a different header without breaking the equality check at step 16. Defense holds.

### FP-10 — Sum type Eq for OracleProvider
**Hypothesis:** Aiken sum types don't auto-derive `==`. Does the validator have a hidden bug?

**Test:** `policy.ak` defines `oracle_provider_eq` as a manual pattern-match (line 125-132). Used in RotateAuth at line 578-580. Direct `==` on the `OracleProvider` sum type is NOT used. Defense holds (the developer was aware of this Aiken pitfall).

### FP-11 — `Option<ByteArray>` Eq for `auth_commitment`
**Hypothesis:** does `==` on `Option<ByteArray>` work in Aiken?

**Test:** Plutus `Data`-encodable types use structural equality via `serialise_data`. `Option` is `Some -> Constr 0 [bytes]`, `None -> Constr 1 []`. CBOR-level equality is correct. Defense holds.

### FP-12 — Auth payload reused across policies
**Hypothesis:** can a sig over a payload for Policy A be replayed at Policy B?

**Test:** `payload.policy_id == datum.policy_id` (step 15) — directly checked. Different policies, different policy_ids, different commits, different sigs required. Defense holds.

### FP-13 — Reference scripts re-uploaded
**Hypothesis:** can the deployed validator reference scripts be re-uploaded with malicious bytecode?

**Test:** Reference scripts are immutable on-chain — once published at a UTxO, the script bytes are fixed. The UTxO itself can be spent (by whoever controls the address it's at), but the script-hash that validators reference is a hash of the bytes; re-publishing produces a DIFFERENT hash. The validator's compile-time pin (`policy_validator_hash` parameter) protects against substitution. Defense holds.

### FP-14 — `BurnWitness` redeemer with attacker-substituted policy_id (post-V-002 fix)
**Hypothesis:** with V-002 fixed (require policy co-spend), can the attacker still burn by spoofing `policy_id` in the redeemer?

**Test:** the fix asserts `policy_id_in_redeemer == pdat.policy_id` of the consumed policy input. The asset name in the burn `mint` field must equal `blake2b_224(policy_id)` (this comes from `expected_asset_name = blake2b_224(policy_id)`). Both are bound; cannot be desynced. Defense holds.

---

## Aiken-on-Windows Sanity Check

Per memory's `feedback_aiken_on_windows.md` — silent compile errors on Windows are a real failure mode.

- `aiken check` returns 305/305 passed, 0 failed. Build artifacts in `plutus.json` line up with source (validator hashes computed from the current bytes; `auth_witness.auth_witness_validator.spend` hash `6326353d81af16d4…`, `auth_witness_nft.auth_witness_nft.mint` hash `4d2c5c440d08862e…`, etc.). No silent-compile evidence.
- Sum-type Eq — V-FP-10 confirms the developer manually wrote `oracle_provider_eq`. Sum-type pattern match is exhaustive (no `_` wildcard in dispatch logic). 
- Opaque-type init — `VerificationKeyHash`, `ScriptHash` are opaque; the file uses `ByteArray` literal initialization and lets the type system promote at use site. Same pattern as v6.

No Aiken-on-Windows pitfalls observed in this round.

---

## Top-3 Fixes by Impact

1. **V-001** — Drop `one_shot_consumed` from `auth_witness_nft.MintWitness` return AND. The check is a copy-paste from `pool_nft.ak` that doesn't apply here. Without this fix, the relay-presigned-auth feature is one-policy-only on mainnet.

2. **V-002** — Replace the inverted `no_live_policy = policy_consumed_in_tx == False` check in `BurnWitness` with `policy_terminated_now = policy_consumed_in_tx`. Forces every burn to co-spend a being-terminated policy. Add a separate `SweepBurn` variant gated by operator signature for orphan cleanup (V-008).

3. **V-003** — Wire `derive_policy_id` through `batch_policies_match_totals` with a per-output anchor (option 2 in V-003's fix section: extend the `BatchUnderwrite` redeemer with a `List<OutputReference>` of anchors). Add 2 negative tests.

After these three fixes, the next wave of polish (V-004 placeholder hash, V-005 integration tests, V-007 belt-and-suspenders) should land before tagging `v8.0.0` for mainnet.

---

## Conclusion

The v2 spec is correct in design. The implementation has **two CRITICAL bugs that brick the headline feature** (V-001, V-002), one **HIGH severity gap** in the BatchUnderwrite path that re-opens H-3 (V-003), and a **process gap** (V-005) that explains why the gates in §11 aren't actually enforcing what the spec claims.

**Pre-mainnet recommendation:** **DO NOT TAG v8.0.0** without fixing V-001, V-002, V-003 at minimum. Add 30+ Aiken Transaction-context tests covering the v8 surfaces (V-005). Update the §11 traceability table with a "verified by test xyz" column so future reviewers can audit closure.

The Aiken layer is the last line of defense. The current build does not yet hold that line on the v8 surfaces.
