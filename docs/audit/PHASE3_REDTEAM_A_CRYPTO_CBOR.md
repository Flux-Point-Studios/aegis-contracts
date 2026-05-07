# Phase 3 Red-Team A — Crypto/CBOR Attacks

**Scope:** Aegis v8 relay-presigned-authorization. Cryptographic primitives, CBOR canonicalization, cross-stack divergence between Aiken / TypeScript / Python encoders, and the Ed25519/BLAKE2b chain that secures the pre-signed-claim path.
**Methodology:** Source review of all three encoders + the on-chain validators (`policy.ak`, `auth_witness_nft.ak`, `auth_witness.ak`, `pool.ak`), empirical probes of `@noble/ed25519` v3.1.0 strict-S behavior, hand-crafted non-canonical CBOR, and analysis of the Aiken stdlib `cbor.deserialise` source.
**Date:** 2026-05-06.
**Prerequisites read:** `RELAY_PRESIGNED_AUTH_SCOPE_v2.md` (incl. Δ history through 2026-05-06 corrections), `auth_payload.{ak,ts,py}`, `auth_witness_nft.ak`, `auth_witness.ak`, `policy.ak`, `pool.ak`, fixtures at `tests/fixtures/auth_payload_vectors.json`, `frontend/src/wallet/aegis/__tests__/fixtures/auth_payload_vectors.json`.

---

## Executive summary

**13 findings. 1 CRITICAL functional, 1 HIGH design, 2 MEDIUM, 5 LOW, 4 INFO.** The cryptographic primitives are well-implemented — strict-S is empirically verified across S=0, S=L, S=L±1, and high-S forgeries; cross-network domain-tag binding is enforced at sign-time; commitment hash is correctly bound to canonical CBOR; the witness-stuffing DoS is closed; payout binding (Δ9) is enforced; oracle-provider cross-claim binding (Δ5) is enforced.

The **critical** finding is functional, not cryptographic: the `auth_witness_nft` mint validator's `one_shot_consumed` check requires the parameterized `init_utxo_ref` to be in the inputs of EVERY mint call. Because UTxOs are spent at most once, this means the mint policy can only succeed exactly once on chain — bricking ALL Underwrite-with-auth and RotateAuth flows after the first one. This is a textbook "one-shot semantics misapplied as per-mint check" mistake; it MUST be fixed before any v8 deploy.

The **high** finding is a binding gap: the on-chain `ClaimWithAuth` validator decodes the signed `AuthCoveragePayload` but only compares 3 of 14 fields against the policy datum (`policy_id`, `oracle_provider`, `payout_address`). The other 11 fields (`max_coverage`, `not_before`, `not_after`, `pool_script_hash`, `pool_nft`, `oracle_nft`, `policy_validator`, `insured_pkh`, `oracle_freshness`, `domain_tag`, `network_magic`) are read-and-discarded. The wallet UI shows these fields to the user; a malicious frontend could show "100 ADA coverage" while the actual on-chain coverage is 100,000 ADA — the user signs a payload whose `max_coverage` field is 100 ADA, but the validator never checks that field against `datum.coverage_amount`. The defence-of-last-resort is `payload.policy_id == datum.policy_id`, which transitively binds via §1.8's hash, but only fields baked into `derive_policy_id` are protected (`insured_pkh`, `strike_price`, `coverage_amount`, `start_time`, `expiry_time`, `pool_nft`). Fields NOT in the derivation (`oracle_nft`, `policy_validator`, `oracle_freshness`, `domain_tag`, `network_magic`, `pool_script_hash`) are not bound at all from the validator's perspective.

The **mediums** are: (a) the Aiken `cbor.deserialise` accepts non-canonical CBOR (non-shortest int headers, indefinite-length bytestrings via the `0x5f` chunked form, indefinite-length lists in inner positions) — exposing canonical determinism violations even though the commit-binding mostly absorbs them; (b) the cross-stack encoder behaviors diverge — TS rejects negatives, values > 2^63-1, and out-of-range Constr indices; Python accepts all of those; Aiken accepts all major-type-0 (uint header 0..27) and major-type-1 (negative) values. A Python relay or attacker tool can produce CBOR that the TS encoder cannot, and the on-chain validator will accept.

The **lows** cover: the `derive_policy_id` preimage's variable-length `pool_nft` (canonicalization weakness — theoretical second-preimage parity); the `auth_witness_nft_policy_id` constant being the all-zero placeholder `#"00…00"` in the current build (deploy-gate hazard); the `oracle_freshness` field being neither length-bounded nor numeric-bounded (not exploitable but UI-confusion surface); the noble v3 `S=0` edge case (returns identity, not strictly rejected, but verification equation still fails).

The **infos** document attacks tried that don't work, with reasoning — e.g., the BLAKE2b second-preimage attack at 2^256, trailing bytes attack (Aiken's deserialise rejects them at line 76), pubkey malleability (noble emits canonical y-coordinate), domain-tag pinning across networks (TV-1 vs TV-2 verified to produce distinct hashes).

### Severity tally

| Severity | Count |
|---|---|
| CRITICAL | 1 |
| HIGH | 1 |
| MEDIUM | 2 |
| LOW | 5 |
| INFO | 4 |
| **Total** | **13** |

### Findings table

| ID | Severity | Title | Status |
|---|---|---|---|
| A-A-001 | **CRITICAL** | `auth_witness_nft` `one_shot_consumed` check applies to EVERY mint, not just the deployment-establishing one — bricks Underwrite-with-auth after the first call | open |
| A-A-002 | **HIGH** | `ClaimWithAuth` validator decodes 14-field payload but only binds 3 fields to `datum`; 11 fields are wallet-displayed-but-unenforced | open |
| A-A-003 | MED | Aiken `cbor.deserialise` accepts non-canonical CBOR (non-shortest int headers, indefinite-length bytestrings) — canonical-determinism violation | open |
| A-A-004 | MED | Python encoder has no shape validation; accepts negatives, values > 2^63-1, oracle_provider out-of-range — TS/Python encoder asymmetry | open |
| A-A-005 | LOW | `derive_policy_id` preimage uses variable-length `pool_nft` without a length prefix — canonicalization weakness | open |
| A-A-006 | LOW | `auth_witness_nft_policy_id` is the all-zero placeholder `#"00…00"` in committed code; ALL ClaimWithAuth tx fail until deployment-time pin is applied | open |
| A-A-007 | LOW | `oracle_freshness` field has no length/range bound off-chain; relay/wallet UI may render an attacker-controlled value | open |
| A-A-008 | LOW | `@noble/ed25519` v3 `S=0` returns identity in `multiply(s, false)` rather than throwing — verification still fails but the surface is wider than expected | open |
| A-A-009 | LOW | TS `MAX_INT_FIELD = 2^63-1` is asymmetric with the on-chain Plutus integer (unbounded) and Python's `2^64-1` cap — frontend rejects values an offline tool can sign | open |
| A-A-010 | INFO | BLAKE2b second-preimage at 2^256 is infeasible; commit binding is sound | wontfix |
| A-A-011 | INFO | Trailing-bytes attack: Aiken's `deserialise` rejects (line 76 `consumed != 0 → None`); cross-checked against canonical fixture | wontfix |
| A-A-012 | INFO | Pubkey malleability: noble emits canonical y-coordinate via `numTo32bLE(y)`; cofactor-cleared and small-order pubkeys rejected by `zip215:false` | wontfix |
| A-A-013 | INFO | Cross-network sig replay (TV-1 preprod vs TV-2 mainnet): empirically verified — distinct hashes, distinct sigs, mutual rejection | wontfix |

---

## Per-finding detail

### A-A-001 — `auth_witness_nft` one-shot check is per-mint instead of per-deployment

**Severity:** CRITICAL
**Status:** OPEN
**Files:** `contracts/validators/auth_witness_nft.ak` lines 98-103
**Threat model:** Any user attempting Underwrite-with-auth after the first one ever submitted on chain.

**Code excerpt (auth_witness_nft.ak):**
```aiken
// 4. The init_utxo_ref must be consumed in this tx (one-shot).
// This is the ONLY guarantee that prevents replay-mints; without
// it an attacker could mint a second witness for any policy at
// any later time. (Closes F-AUTH-2 / C-1.)
let one_shot_consumed =
  list.any(inputs, fn(i) { i.output_reference == init_utxo_ref })
```

**Repro:**
1. Operator deploys the auth_witness_nft mint policy, parameterized over `(init_utxo_ref = OUR-CHOSEN-UTXO, network_tag, policy_validator_hash)`. The deploy tx consumes `init_utxo_ref` and pins the resulting policy_id in `types.auth_witness_nft_policy_id`.
2. Alice submits Underwrite-with-auth. Her tx tries to mint a witness. The mint validator checks `one_shot_consumed = list.any(inputs, fn(i) { i.output_reference == init_utxo_ref })`. **`init_utxo_ref` was consumed in step 1 — it does not exist anymore.** Alice's tx fails: `one_shot_consumed = False`.
3. Every subsequent Underwrite-with-auth fails the same way. The mint policy is permanently disabled.

Wait — actually the deploy tx itself doesn't necessarily mint. The mint policy's parameter is `init_utxo_ref`; the validator checks at MINT time that `init_utxo_ref` is in the inputs. The first Underwrite-with-auth tx would consume `init_utxo_ref`, mint a witness, and succeed. ALL SUBSEQUENT Underwrite-with-auth and RotateAuth txes would fail because `init_utxo_ref` is gone.

**This means the design supports exactly ONE policy with auth-coverage per network deployment.** That is plainly not the intent (the spec §1.5 says "called once per Underwrite or RotateAuth" — the PARAMETERIZATION is one-shot, not the validator's per-call check).

**Evidence — read this together with the parameterization comment in the validator (line 67-71):**
> `init_utxo_ref` is consumed at the operator's first publish, making the resulting policy id one-shot

The intent is that the *policy id* is one-shot — i.e., each network deployment has a unique policy id derived from a unique `init_utxo_ref`. This is a parameter-baking pattern: the validator's compiled hash includes the `init_utxo_ref`, so a different operator (or a different network deploy) gets a different policy_id. **The `init_utxo_ref` does NOT need to be consumed at every mint — it just needs to be consumed at COMPILE-TIME-PARAMETERIZATION (which it isn't actually consumed there; consumption happens whenever the operator builds a tx that spends it).**

The bug: the validator's `one_shot_consumed` check enforces consumption at every mint call. But `init_utxo_ref` is a UTxO, and Cardano UTxOs are spent at most once. So `one_shot_consumed = True` happens exactly once across the entire chain history — and then the mint policy is bricked.

**Compare to Charli3 / pool_nft pattern (used elsewhere in Aegis):**
```aiken
// pool_nft.ak (validator referenced by `aegis_self_nft_policy`, AEGIS_POOL_V8 etc.)
// — minting permitted only at the FIRST tx (the deploy tx) when init_utxo_ref
// is consumed; thereafter the parameter is "spent" and mint always fails.
// This enforces ONE token of this policy, ever.
```

The pool_nft pattern is a TRUE one-shot — exactly one token of this policy can ever be minted. The auth_witness_nft, however, NEEDS to mint more than once (one mint per Underwrite). So the patterns are incompatible. The auth_witness_nft validator copy-pasted the one-shot pattern instead of designing a different uniqueness mechanism.

**Suggested fix:**
- The `init_utxo_ref` parameter is sufficient by itself for policy-id uniqueness via parameterization (different `init_utxo_ref` → different compiled policy id). The validator does NOT need to additionally check `init_utxo_ref` consumption.
- Replace `one_shot_consumed` with the existing checks: `exactly_one_minted && only_one_under_policy && payload_policy_id_ok && (underwrite_path_valid || rotate_auth_path_valid) && network_tag_ok`. The Underwrite path's "fresh policy output at policy_validator address with PolicyDatum where policy_id matches AND auth_commitment = blake2b_256(payload_cbor)" already binds the witness to a legitimate policy; together with `exactly_one_minted` per (policy_id, asset_name) and the policy_validator's `derive_policy_id` enforcement at the pool, the witness is bound to a unique policy per Underwrite.
- Alternative if the original intent was "init_utxo_ref must be consumed at FIRST mint, not subsequent": this is not implementable in Plutus statelessly. Drop the check.

**Diff hint:**
```aiken
-        let one_shot_consumed =
-          list.any(inputs, fn(i) { i.output_reference == init_utxo_ref })
-
-        ... && one_shot_consumed && ...
+        // The `init_utxo_ref` parameter alone makes the compiled policy id
+        // unique per deployment; we do NOT check consumption at mint time
+        // because that would brick mints after the init UTxO is spent.
+        // Witness binding is enforced via Underwrite/RotateAuth paths below.

         exactly_one_minted && only_one_under_policy && payload_policy_id_ok && (
           underwrite_path_valid || rotate_auth_path_valid
         ) && network_tag_ok
```

---

### A-A-002 — `ClaimWithAuth` validator binds only 3 of 14 payload fields to `datum`

**Severity:** HIGH
**Status:** OPEN
**Files:** `contracts/validators/policy.ak` lines 419-536 (ClaimWithAuth branch); `contracts/lib/aegis/types.ak` lines 230-277 (AuthCoveragePayload type)
**Threat model:** Malicious frontend (or a CIP-30 wallet showing a misleading prompt) presenting a wallet UI that displays `max_coverage = 1 ADA` while building an Underwrite tx that locks 100 ADA of pool capacity. User's signature authorizes the relay-driven claim of 100 ADA (datum.coverage_amount, NOT payload.max_coverage). Wallet UI was deceptive.

**Threat model #2:** Future schema evolution — if `policy_id` derivation drops a field (e.g., `pool_nft` becomes a parameter rather than a datum field), the unbound payload fields silently lose their indirect binding.

**Audit grep — what the validator actually reads from `payload`:**

```
$ grep -n 'payload\.' contracts/validators/policy.ak contracts/validators/auth_witness_nft.ak
contracts/validators/policy.ak:474:          payload.oracle_provider == oracle_provider_to_int(...)
contracts/validators/policy.ak:481:        let payload_policy_id_ok = payload.policy_id == datum.policy_id
contracts/validators/policy.ak:491:          payload.payout_address == enterprise_addr_of(datum.insured)
contracts/validators/auth_witness_nft.ak:112:        let payload_policy_id_ok = payload.policy_id == policy_id
contracts/validators/auth_witness_nft.ak:136:          payload.oracle_provider == oracle_provider_to_int(...)
```

Three fields used in `policy.ak` ClaimWithAuth: `policy_id`, `oracle_provider`, `payout_address`. The other 11 fields (`domain_tag`, `network_magic`, `policy_validator`, `insured_pkh`, `max_coverage`, `oracle_nft`, `oracle_freshness`, `not_before`, `not_after`, `pool_script_hash`, `pool_nft`) are decoded via `expect payload: AuthCoveragePayload = cbor_decode_payload(awd.payload_cbor)` and then **never read**.

**Indirect binding via `policy_id`:** §1.8's `derive_policy_id(insured_pkh, strike_price, coverage_amount, start_time, expiry_time, pool_nft, underwrite_tx_input)` hash-commits 6 fields. If `payload.policy_id == datum.policy_id`, those 6 fields ARE indirectly bound. Specifically:
- `insured_pkh` → bound (datum.insured)
- `coverage_amount` → bound (datum.coverage_amount, transitively via the policy_id hash)
- `start_time` → bound (datum.start_time)
- `expiry_time` → bound (datum.expiry_time)
- `pool_nft` → bound (datum.pool_nft)

**NOT indirectly bound (read by validator, not in `policy_id` preimage, not compared to datum):**
- `domain_tag` — bytes claiming PREPROD/MAINNET/PREVIEW. Not checked against current network.
- `network_magic` — int claiming 1/2/764824073. Not checked.
- `policy_validator` — claimed v8 policy_validator hash. Never compared to the actual `own_script_hash`.
- `oracle_nft` — already in datum (not in derive_policy_id). Validator does NOT check `payload.oracle_nft == datum.oracle_nft`.
- `oracle_freshness` — advisory. Not checked.
- `pool_script_hash` — already in datum. Validator does NOT check `payload.pool_script_hash == datum.pool_script_hash`.
- `max_coverage` — separately bound transitively via policy_id (since coverage_amount is in the preimage).

So `domain_tag`, `network_magic`, `policy_validator`, `oracle_nft`, `oracle_freshness`, `pool_script_hash` are wallet-displayed but on-chain-unenforced.

**Concrete repro (wallet-UX deception):**
1. Alice opens a malicious frontend on preprod. Frontend's CIP-30 connector reports preprod (network magic 1) correctly.
2. Frontend constructs an `AuthCoveragePayload` with:
   - `domain_tag = AEGIS_CLAIM_AUTH_v1_PREPROD` (matches network)
   - `oracle_nft = ATTACKER-CONTROLLED-NFT-POLICY` (different from the one the policy datum uses)
   - All other fields are correct for the underlying policy.
3. Wallet UI shows the human-readable summary derived from the payload, including the claimed oracle. The user might verify "Oracle: ATTACKER ORACLE" — but the field doesn't help them: the on-chain validator dispatches to `datum.oracle_provider` (correctly), not to `payload.oracle_nft`.
4. User signs. Relay claims later — using `datum.oracle_nft` (the canonical Charli3 NFT from the policy datum). Payout proceeds normally.

In this specific case the user is not financially harmed — the policy's actual oracle is the correct one. But the wallet PROMPT was misleading: it claimed "Oracle: ATTACKER ORACLE" when the actual oracle is canonical. **The principle: any payload field NOT compared to datum is a deception surface.**

**Concrete repro #2 — coverage display deception:**
1. Alice connects her CIP-30 wallet. Frontend builds an Underwrite tx that locks 100 ADA from her wallet (signed by her tx-body-sig).
2. The Underwrite tx's policy datum has `coverage_amount = 100_000_000_000` lovelace (100 ADA).
3. Frontend constructs the auth payload with `max_coverage = 1_000_000` lovelace (1 ADA). The wallet UI shows: "Authorize a relay to claim this policy on your behalf: Coverage: 1 ADA, Strike: $0.30, Payout to: <Alice's address>, Expires: 2026-08-15 [SIGN]".
4. Alice clicks SIGN, having reviewed and approved 1 ADA of authorization.
5. The on-chain `policy_id = derive_policy_id(insured_pkh, strike_price, 100_000_000_000, ...)`. The auth payload's `policy_id` field MUST equal that on-chain value, otherwise the witness mint fails (auth_witness_nft.ak line 112). So the off-chain frontend sets `payload.policy_id` to the correct value (computed from the 100 ADA coverage). **`payload.max_coverage = 1_000_000` is INCONSISTENT with `payload.policy_id` (which embeds 100 ADA), but the on-chain validator never cross-checks them.**
6. The relay later claims, drawing 100 ADA from the pool to Alice's payout address. Alice authorized "1 ADA" via the wallet prompt; the actual ledger movement is 100 ADA.

In this case Alice still receives the 100 ADA — so she's not directly harmed financially. But:
- (a) Alice may have intended to authorize a 1-ADA quick claim and is now committed to a 100-ADA position she didn't expect to have automatic claims for.
- (b) The pool has 100 ADA of liability against Alice's 1 ADA of premium (if the frontend also lied about the premium during the original Underwrite — though premium is part of `policy_id` derivation transitively via `coverage_amount`, so this specific deception is bounded).

**The deception's severity is bounded** by the policy_id transitive binding: any field IN the `derive_policy_id` preimage cannot be deceptively displayed without the on-chain Underwrite failing. Fields OUTSIDE the preimage (oracle_nft, policy_validator, oracle_freshness, pool_script_hash) can be displayed deceptively with no consequence beyond user confusion.

**Fix:** In the ClaimWithAuth validator, after decoding `payload`, add a series of additional `expect`/`let`s:
```aiken
// Bind every payload field that ISN'T transitively constrained by policy_id.
let payload_oracle_nft_ok = payload.oracle_nft == datum.oracle_nft
let payload_pool_script_hash_ok = payload.pool_script_hash == datum.pool_script_hash
// Compile-time-pin domain_tag and network_magic so the validator rejects
// any payload signed for a different network. The current spec relies on
// the wallet's sign-time check; defense-in-depth makes it on-chain too.
let payload_domain_tag_ok = payload.domain_tag == auth_domain_tag
let payload_network_magic_ok = payload.network_magic == network_magic
// Bind insured_pkh redundantly (already implied by datum.insured, but cheap):
let payload_insured_pkh_ok = payload.insured_pkh == datum.insured
// Bind policy_validator hash redundantly:
expect Script(own_script_hash) = self_input.output.address.payment_credential
let payload_policy_validator_ok = payload.policy_validator == own_script_hash
// max_coverage redundantly (already via policy_id):
let payload_max_coverage_ok = payload.max_coverage == datum.coverage_amount
// not_before, not_after redundantly:
let payload_not_before_ok = payload.not_before == datum.start_time
let payload_not_after_ok = payload.not_after == datum.expiry_time
```

Add to the final `&&`-chain. Cost: ~9 extra equality checks; cheap. Closes the deception surface end-to-end.

---

### A-A-003 — Aiken `cbor.deserialise` accepts non-canonical CBOR

**Severity:** MEDIUM
**Status:** OPEN
**Files:** `contracts/build/packages/aiken-lang-stdlib/lib/aiken/cbor.ak` (stdlib, not modifiable directly); `contracts/validators/policy.ak` line 143; `contracts/validators/auth_witness_nft.ak` line 106.
**Threat model:** A future stack (Python relay, alternate frontend, CLI signer) producing non-canonical CBOR that the Aiken validator accepts, but which is byte-distinct from the canonical TS encoder's output for the same logical payload.

**Evidence (Aiken stdlib `cbor.deserialise`):**
```aiken
// from build/packages/aiken-lang-stdlib/lib/aiken/cbor.ak
fn decode_uint(peek, take, header, and_then) {
  if header < 24 {
    and_then(header)              // Shortest form
  } else if header == 24 {
    let payload <- peek(1)        // Accepts 1-byte (header 24) for ANY value 0..255
    and_then(payload)
  } else if header < 28 {
    // Accepts 2/4/8-byte forms regardless of actual value
    let width = bytearray.at(#[2, 4, 8], header - 25)
    ...
  }
  ...
}
```
**No shortest-form enforcement.** `0x18 0x00` (1-byte form for value 0) decodes to 0, same as `0x00`. `0x1b 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00` (8-byte form for value 0) ALSO decodes to 0.

```aiken
// Indefinite-length bytestring chunks
if next == token_begin_bytes {  // 0x5f
  let b <- decode_chunks(peek, take)  // glues chunks via append_bytearray
  return(builtin.b_data(b))
}
```
Aiken accepts the `0x5f`-prefixed chunked form for bytestrings. So a 28-byte hash could be encoded as `0x58 0x1c <28 bytes>` (canonical) OR as `0x5f 0x4e <14 bytes> 0x4e <14 bytes> 0xff` (chunked). Both decode to the same logical bytestring; their byte sequences differ; their BLAKE2b hashes differ.

**Repro (Python — produces non-canonical CBOR that Aiken decodes successfully):**
```python
# Encode the canonical TV-1, then mutate field 7 (oracle_provider, value 0)
# to use the 1-byte length form (0x18 0x00) instead of the 0-byte form (0x00).
import sys, hashlib
sys.path.insert(0, 'D:/aegis-contracts/contracts/scripts')
from dump_vectors import enc_uint, enc_bytes, enc_constr0, TV1
field_order = ['domain_tag','network_magic','policy_validator','policy_id',
               'insured_pkh','payout_address','max_coverage','oracle_provider',
               'oracle_nft','oracle_freshness','not_before','not_after',
               'pool_script_hash','pool_nft']
fields_canonical = [enc_uint(TV1[k]) if isinstance(TV1[k], int) else enc_bytes(TV1[k])
                    for k in field_order]
canonical = enc_constr0(fields_canonical)
fields_noncanon = list(fields_canonical)
fields_noncanon[7] = bytes([0x18, 0x00])  # oracle_provider = 0 in 2-byte form
noncanon = enc_constr0(fields_noncanon)
print('canon hash:    ', hashlib.blake2b(canonical, digest_size=32).hexdigest())
print('non-canon hash:', hashlib.blake2b(noncanon, digest_size=32).hexdigest())
# canon: 091c23daf3b3bab1bb7508ae312d48198f121fff1e7a6caeddd49f52aeb80885
# non-canon: dbd31483453e2ca3d58e1f556e14e7c15af298f579f7945f527a56cd47ada47f
```

The TS encoder cannot produce `noncanon` (its `encodeUint` always emits shortest form). But:
- A Python tool CAN produce it (Python's cbor2 by default emits canonical, but a hand-rolled mutator can produce non-canonical).
- Aiken's `cbor.deserialise(noncanon)` succeeds and decodes both `canonical` and `noncanon` to the same logical AuthCoveragePayload.
- The blake2b commit differs.

**Why this matters:** In the relay-presigned-auth flow the user signs the canonical commit (via TS). The witness UTxO is created at Underwrite with the user-signed bytes. Validator decodes those bytes and binds. **No exploit on the vanilla flow.**

But:
1. **Non-canonical commit collisions:** an attacker tooling could construct two different byte sequences that decode to the same logical payload and present them to a user across two flows. Each produces a distinct commit; the user signs one, the on-chain witness has the other. Hash mismatch fails the validator. Liveness, not safety.
2. **Future cross-chain bridge / stand-alone verifier:** if Aegis ever exports `payload_cbor + sig` outside the Cardano context (e.g., to a Solana bridge for cross-chain claim attestation), and the external verifier RE-ENCODES the parsed payload to canonical form before re-hashing, the resulting hash will differ from the one that was signed. Attestation fails.
3. **Audit attack surface:** "the on-chain decoder accepts non-canonical CBOR" is a yellow flag for any auditor. It does not directly enable an exploit but is a recurring class of bugs in the wider crypto literature (e.g., Bitcoin's BIP-66 strict-DER, Ethereum's malleable-RLP, Cardano's own CIP-117 motivation).

**Fix options:**
- (a) **Canonical-form re-encode-and-compare in the validator.** After decoding `payload: AuthCoveragePayload`, re-encode via `cbor.serialise(payload)` and assert equality with `awd.payload_cbor`. Cost: 1 extra `cbor.serialise` (~10x cheaper than deserialise per the stdlib note). Closes the canonical-form gap entirely.
- (b) **Documented constraint:** declare via spec that all encoders MUST produce shortest-form, definite-length bytestrings, definite-length lists for inner fields. Cross-stack tests already cover this for happy paths; add negative tests that reject non-canonical inputs.
- (c) **Drop `cbor.deserialise` entirely.** Have the redeemer carry the parsed fields (oracle_provider, policy_id, payout_address) and have the validator hash the canonical re-encoded bytes. This avoids the deserialise cost at the price of redeemer bloat.

Option (a) is the cleanest fix and aligns with the existing pattern (the validator already does `commit_from_cbor(awd.payload_cbor) == commit`).

**Diff hint (option a):**
```aiken
expect payload: AuthCoveragePayload = cbor_decode_payload(awd.payload_cbor)
+ // Defense-in-depth: re-encode and assert canonical form. Closes the
+ // surface where Aiken's cbor.deserialise accepts non-shortest-form ints,
+ // indefinite-length bytestrings, and other non-canonical encodings.
+ let payload_canonical = cbor.serialise(payload)
+ let payload_canonical_ok = payload_canonical == awd.payload_cbor
...
commit_len_ok && exactly_one_witness && ... && payload_canonical_ok && ...
```

---

### A-A-004 — Python encoder has no shape validation; cross-stack asymmetry with TS

**Severity:** MEDIUM
**Status:** OPEN
**Files:** `offchain/src/aegis/auth_payload.py` (no shape validation); `frontend/src/wallet/aegis/auth_payload.ts` (rich shape validation)
**Threat model:** A Python relay or developer tool signing a payload that the TS encoder would reject. The Aiken validator accepts the payload bytes (decode succeeds) and the only enforcement is the 3 fields ClaimWithAuth checks (A-A-002). If those 3 fields are correct, the malformed values for the other 11 are accepted.

**Evidence:**
- TS `assertNonNegInt`: rejects negative values, rejects > 2^63-1.
- TS `assertConstrIdx`: rejects oracle_provider not in {0,1,2}.
- TS `assertBytesLength`: 28 bytes for hash fields, 29 for payout_address, 27 for domain_tag.
- TS `assertNetworkConsistency`: rejects domain_tag/network_magic mismatch.
- **Python:** `_encode_field(value)` only checks `isinstance(value, int) | bytes`. NO length check, NO range check, NO Constr-index check, NO network-consistency check.

**Repro (Python):**
```python
from offchain.src.aegis.auth_payload import (
    AuthCoveragePayload, encode_auth_coverage_payload, commitment_hash
)
# Construct a payload that TS rejects but Python encodes:
p = AuthCoveragePayload(
    domain_tag=b"AEGIS_CLAIM_AUTH_v99_FORGED",  # 27 bytes but wrong network
    network_magic=12345,                          # not 1/2/764824073
    policy_validator=b"\x00" * 28,
    policy_id=b"\x00" * 28,
    insured_pkh=b"\x00" * 28,
    payout_address=b"\x60" + b"\x00" * 28,        # OK
    max_coverage=2**70,                           # > 2^64-1 (would encode as bignum)
    oracle_provider=99,                           # not 0/1/2
    oracle_nft=b"\x00" * 28,
    oracle_freshness=-1,                          # negative
    not_before=2**63,                             # > 2^63-1, < 2^64
    not_after=0,                                  # not_after < not_before
    pool_script_hash=b"\x00" * 28,
    pool_nft=b"",                                 # zero-length bytestring
)
cbor = encode_auth_coverage_payload(p)
print('encoded len:', len(cbor))
print('commit:', commitment_hash(cbor).hex())
# Encoded successfully. TS would have rejected at assertPayloadShape.
```

**Why this matters off-chain:**
- The relay-service code is in TypeScript per the spec, but a defensive operator may write a Python re-implementation for cross-checking. If the Python tool is deployed as a primary submitter, malformed payloads can flow.
- A user-facing wallet built on `pycardano` (popular in the Cardano-Python ecosystem) would have the same shape blind spot.
- An attacker writing a custom signer (e.g., for cross-stack attack research) can produce values the TS encoder cannot.

**On-chain effect:**
- Aiken's `cbor.deserialise` accepts: `oracle_provider = 99` decodes as `i_data(99)`, fits the `Int`-typed payload field. Validator's `payload.oracle_provider == oracle_provider_to_int(datum.oracle_provider)` REJECTS this — `oracle_provider_to_int` returns 0/1/2.
- `max_coverage = 2^70` encodes as bignum (tag 2). **Aiken's `decode_data` does NOT handle tag 2** (it only handles tag 102 + tags 121..127 + 1280+); the decode would fail. So a Python-encoded payload with values >= 2^64 is REJECTED on chain (but only via decode failure, not a clean error message).
- `oracle_freshness = -1` encodes as major-type-1. Aiken decodes as `i_data(-1)`. Validator never reads this field. Accepted.
- `not_before` > 2^63 fits in 8-byte uint encoding. Aiken accepts. Validator never reads this field. Accepted.
- `not_after < not_before` — the Python encoder accepts; Aiken accepts; on-chain validator does not check this. Accepted.
- `pool_nft = b""` (empty) — Aiken accepts an empty bytestring. Validator does not read `payload.pool_nft`. Accepted.
- `domain_tag = b"AEGIS_CLAIM_AUTH_v99_FORGED"` — Aiken accepts. Validator does not check (per A-A-002). Accepted.

So the cross-stack asymmetry primarily manifests as a **deception surface** when combined with A-A-002. Neither finding alone is critical; together they expand the wallet-UX deception window.

**Fix:** Bring the Python encoder up to parity with TS. Specifically:
- Add `assert isinstance(payload.network_magic, int) and payload.network_magic in {1, 2, 764824073}`
- Add length checks: `assert len(payload.domain_tag) == 27`, etc.
- Add `assert payload.oracle_provider in (0, 1, 2)`
- Add `assert 0 <= payload.max_coverage < 2**63`
- Add `assert payload.not_after >= payload.not_before`
- Add `assertNetworkConsistency` check.

Cross-stack TODO: a CI gate that the Python and TS encoders REJECT the same set of inputs (a "negative" cross-stack contract).

**Diff hint (offchain/src/aegis/auth_payload.py):**
```python
def encode_auth_coverage_payload(payload: AuthCoveragePayload) -> bytes:
+    # Shape validation — must mirror the TS assertPayloadShape so any
+    # invalid payload that the wallet UI couldn't sign is also impossible
+    # for the off-chain Python tools to sign. (Closes cross-stack asymmetry.)
+    _assert_payload_shape(payload)
     field_bytes = [_encode_field(getattr(payload, name)) for name in _FIELD_ORDER]
     return _enc_constr0_indef(field_bytes)
```

with `_assert_payload_shape` doing length/range/network checks.

---

### A-A-005 — `derive_policy_id` preimage uses variable-length `pool_nft` without length prefix

**Severity:** LOW
**Status:** OPEN
**Files:** `contracts/lib/aegis/types.ak` lines 674-695; `offchain/src/aegis/auth_payload.py` lines 421-431
**Threat model:** Theoretical second-preimage parity collision. An attacker controlling pool_nft choice (one-shot per pool deploy, so practically constrained to operator) finds a same-policy-id collision via choosing pool_nft length ± shifting bytes into tx_id.

**Evidence (types.ak):**
```aiken
let preimage =
  insured_pkh                                                  // 28 bytes (fixed)
    |> bytearray.concat(bytearray.from_int_big_endian(strike_price, 8))   // 8
    |> bytearray.concat(bytearray.from_int_big_endian(coverage_amount, 8)) // 8
    |> bytearray.concat(bytearray.from_int_big_endian(start_time, 8))     // 8
    |> bytearray.concat(bytearray.from_int_big_endian(expiry_time, 8))    // 8
    |> bytearray.concat(pool_nft)                              // VARIABLE-LENGTH
    |> bytearray.concat(underwrite_tx_input.transaction_id)    // 32 bytes (fixed)
    |> bytearray.concat(
        bytearray.from_int_big_endian(underwrite_tx_input.output_index, 2),
      )                                                        // 2 bytes (fixed)
blake2b_224(preimage)
```

`pool_nft` is variable-length. From `types.ak` line 152 the canonical `pool_nft` is "the canonical pool NFT policy id". Cardano policy ids are 28-byte (BLAKE2b-224 of a script). But Aiken's type is `ByteArray` with no length constraint — and in practice `pool_nft` is typically 28 bytes BUT could in principle be 27 or 29.

**Concrete collision recipe (theoretical):**
- preimage_A = `insured_pkh || ... || pool_nft_A (28 bytes ending in 0xab) || tx_id_A starting with 0xcd ...`
- preimage_B = `insured_pkh || ... || pool_nft_B (29 bytes = pool_nft_A || 0xcd) || tx_id_B starting with the second byte of tx_id_A ...`

If the bytes line up, the BLAKE2b-224 hash is identical. Probability: 2^-224 for random preimages; negligible.

**Why even theoretical:** the canonicalization principle. RFC 8949 §4.2 mandates length-prefixed encoding for variable-length payload elements precisely to prevent this. The Aegis `derive_policy_id` mixes a variable-length item (`pool_nft`) into a hash without a length tag.

**Practical exploitability:** essentially nil. `pool_nft` is one-shot-minted by the operator's pool_nft.ak validator (which ALWAYS produces 28-byte hashes via blake2b_224). So in practice `pool_nft` length is fixed at 28 bytes per deployment. Cross-deployment collisions are even less concerning since each deployment has its own validator hash.

**Fix:** add a 1-byte length prefix to `pool_nft` in the preimage:
```aiken
+ |> bytearray.concat(bytearray.from_int_big_endian(bytearray.length(pool_nft), 1))
  |> bytearray.concat(pool_nft)
```

Off-chain Python and (when added) TS must mirror.

**Severity LOW because:** practical exploitability requires (a) attacker controls pool_nft choice (one-shot, operator-only), (b) attacker can compute non-trivial collisions on-the-fly during pool minting, (c) the resulting collision must yield a profitable arbitrage. None of those conditions are reachable without operator key compromise, in which case the collision is the least of the protocol's problems.

---

### A-A-006 — `auth_witness_nft_policy_id` is the all-zero placeholder; ClaimWithAuth fails until deploy-time pin is applied

**Severity:** LOW
**Status:** OPEN (deploy-gate)
**Files:** `contracts/lib/aegis/types.ak` lines 615-616
**Threat model:** Operator deploys v8 to mainnet without updating the placeholder constant. All ClaimWithAuth and RotateAuth flows fail.

**Evidence:**
```aiken
pub const auth_witness_nft_policy_id: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000"
```

The placeholder value is 28-byte all-zeros. This is the policy id used by:
- `policy.ak` line 176 — `assets.quantity_of(input.output.value, auth_witness_nft_policy_id, asset_name)` in `collect_witnesses`
- `auth_witness.ak` line 48 — `assets.tokens(own_value, auth_witness_nft_policy_id)`
- `auth_witness.ak` line 58 — `assets.quantity_of(mint, auth_witness_nft_policy_id, asset_name)`

A 28-byte all-zero policy id requires finding a script S such that `blake2b_224(S) == #"00…00"` — a 224-bit second-preimage attack. Infeasible (~2^224).

So no actual token can ever exist under the placeholder policy id. `assets.quantity_of(value, #"00…00", _)` always returns 0. `assets.tokens(value, #"00…00")` always returns an empty dict. **`collect_witnesses` always returns `(0, None)` → `exactly_one_witness == False` → ALL ClaimWithAuth tx fail.**

**Fix:** the deploy-gate is acknowledged in the spec ("Placeholder until first preprod deploy"). Make this a CI/test gate:
```aiken
test auth_witness_nft_policy_id_is_not_placeholder() {
  // Deploy-gate test: the placeholder must be updated to the actual
  // minted policy id before any on-chain test can pass.
  auth_witness_nft_policy_id != #"00000000000000000000000000000000000000000000000000000000"
}
```
This test will fail until the operator runs the auth_witness_nft mint deploy and updates the constant. Currently absent from `lib/aegis/test_helpers/v8_auth_tests.ak`.

Add to deploy runbook: "Step N: mint auth_witness_nft via init_utxo_ref tx, capture resulting policy id, paste into types.ak `auth_witness_nft_policy_id`, re-run `aiken check`."

Severity LOW because pre-deploy rather than post-deploy hazard.

---

### A-A-007 — `oracle_freshness` is unbound and unenforced; UI deception surface

**Severity:** LOW
**Status:** OPEN
**Files:** `contracts/lib/aegis/types.ak` lines 263-268; `frontend/src/wallet/aegis/auth_payload.ts` (lines 180-181)
**Threat model:** Wallet UI displays `oracle_freshness` as part of the "human-readable signing prompt" (Δ16) — see `humanReadableSummary` line 240-251 of sign_auth.ts (it currently doesn't display it, but it COULD be added per the spec's wording — and a custom wallet implementer MAY add it).

**Evidence:** `oracle_freshness` is an arbitrary 64-bit uint (TS bounds it to 2^63-1). It's documented as "advisory" — never enforced on-chain. But it's INSIDE the canonical CBOR, hashed into the commit, and signed by the user.

The `payload.oracle_freshness` field is **never read** by the validator (per A-A-002 grep). So a malicious frontend could:
- Show "Oracle freshness: 5 minutes" in the wallet UI
- Encode `oracle_freshness = 5_000_000_000` (5,000 seconds in ms = ~83 minutes) in the actual CBOR

User signs based on UI; on-chain accepts. No financial harm because the field is advisory.

**Fix options:**
- (a) Remove `oracle_freshness` from `AuthCoveragePayload` entirely. It's advisory; advisory data shouldn't be in the signed commit.
- (b) Bind it to a ceiling: `payload.oracle_freshness <= MAX_ORACLE_FRESHNESS_MS` (e.g., 1 hour). Documented as a hard cap.
- (c) Documented surface: spec the "oracle_freshness display in wallet UI" verbatim and require the wallet implementer to consume the bigint as ms (bound the rendering). Less robust but cheapest.

Severity LOW because no financial harm is achievable.

---

### A-A-008 — `@noble/ed25519` v3 `S=0` returns identity instead of throwing; verification still fails but the surface is wider than expected

**Severity:** LOW
**Status:** OPEN
**Files:** `D:/aegis/frontend/node_modules/@noble/ed25519/index.ts` line 521 (`multiply`)
**Threat model:** Documentation-vs-reality drift. The Aegis sign_auth.ts comments claim noble v3 enforces strict-S in `Point.multiply`. Empirically:

```
canonical sig OK: true
S=0 sig accepted? false
S=L sig accepted? false
S=L-1 sig accepted? false
S=L+1 sig accepted? false
S+L (high-S forgery) accepted? false
```

S=0 is rejected in practice — but NOT by `assertRange`. Reading noble's `multiply` (lines 520-538):
```typescript
multiply(n: bigint, safe = true): Point {
  if (!safe && n === 0n) return I;     // <-- S=0 returns identity, no throw
  assertRange(n, 1n, N);
  ...
}
```

In the verification path `_verify` calls `G.multiply(s, false)` (unsafe mode). With `s=0` the function returns `I` (identity), no exception. The verification equation then asks `RkA.subtract(SB).clearCofactor().is0()` where `SB = I`. So `RkA.clearCofactor().is0()` must hold — i.e., `R + kA` must equal identity. For an arbitrary signed message, `kA` is random; identity equality is improbable (~2^-252). So in practice S=0 always fails verification — but via the equation, NOT via a strict-S guard.

**Why this is LOW:** the equation rejects S=0 with overwhelming probability. But the IMPLICIT correctness depends on the Cardano Plutus `verify_ed25519_signature` builtin's behavior matching noble's. If Plutus accepts S=0 (e.g., a libsodium quirk), there's a divergence: a relay's pre-submit verify (using noble) might reject a signature that the on-chain validator (using Plutus) accepts. Liveness, not safety.

**Fix:** Aegis can't change noble. But the spec should document:
- "noble v3 multiply(s, false) treats S=0 as identity, not as out-of-range. Verification equation rejects with overwhelming probability."
- "If the on-chain Plutus verify_ed25519_signature behaves differently for S=0, a divergence exists. This has not been observed in practice but is a consensus-critical edge case to monitor."

Add a regression test that S=0 is rejected on chain (Aiken test using `verify_ed25519_signature` with crafted signature).

---

### A-A-009 — TS `MAX_INT_FIELD = 2^63-1` rejects values that Python and Aiken accept

**Severity:** LOW
**Status:** OPEN
**Files:** `frontend/src/wallet/aegis/auth_payload.ts` lines 135 + 577
**Threat model:** Cross-stack asymmetry. The Aegis TS encoder rejects values in `[2^63, 2^64-1]`. Python encodes them. Aiken's deserialise decodes them.

**Evidence:**
- TS `MAX_INT_FIELD = (1n << 63n) - 1n` and `assertNonNegInt` rejects values > MAX_INT_FIELD.
- TS `encodeUint` accepts values up to 2^64-1 (refuses only > 2^64-1).
- Python `_enc_uint` accepts values up to 2^64-1 (encodes as bignum beyond that).
- Aiken's `decode_uint` accepts header up to 27 (8-byte payload), which is exactly 2^64-1.

If a Python-tool-signed payload has `max_coverage = 2^63 + 5_000_000`, it encodes successfully. The TS encoder cannot reproduce these bytes. The on-chain validator accepts (and never reads max_coverage anyway per A-A-002).

**Why MED-pedigree-but-LOW-now:** combined with A-A-002, an off-chain Python tool can produce signed payloads that:
- The TS-driven cross-stack test would never produce.
- The on-chain validator accepts.
- The wallet UX (if Python-driven) would render the value without comment.

In isolation, no exploit. As a class of bugs, it's a yellow flag for cross-stack determinism.

**Fix:** make Python's MAX_INT_FIELD = 2^63-1 to match TS. Then the cross-stack test set is symmetric.

---

### A-A-010 — INFO — BLAKE2b second-preimage at 2^256 is infeasible

**Severity:** INFO
**Status:** WONTFIX
**Threat model:** Attacker forges `payload_cbor'` such that `blake2b_256(payload_cbor') == blake2b_256(canonical_payload_cbor)`.

BLAKE2b-256 has 256-bit output. Second-preimage cost: 2^256 (no known weakness). Birthday: 2^128 (still infeasible). The commit binding (`commit_from_cbor(awd.payload_cbor) == commit`) is sound under standard cryptographic assumptions.

**Verified:** Aegis validator computes `blake2b_256` directly via the Plutus builtin; no truncation, no double-hash, no length-extension surface.

---

### A-A-011 — INFO — Trailing-bytes attack rejected by Aiken's deserialise

**Severity:** INFO
**Status:** WONTFIX
**Threat model:** Attacker submits `awd.payload_cbor = canonical_cbor || trailing_junk`. Aiken decodes the canonical prefix and accepts; commit_from_cbor over the full bytes produces a different hash than the canonical, so binds to a forged commit; user signs the forged commit.

**Why it doesn't work:** Aiken's `cbor.deserialise` (stdlib `cbor.ak` lines 72-82):
```aiken
if length == 0 {
  None
} else {
  let Pair(result, consumed) = decode_data(peek, take)(length)
  if consumed != 0 {
    None       // <-- trailing bytes detected: reject
  } else {
    Some(result)
  }
}
```

The `consumed` cursor returns nonzero if any byte is left after decoding. **Trailing bytes are rejected.** Verified by reading the stdlib source.

(Caveat — A-A-003 covers the orthogonal case where the bytes ARE all consumed but in a non-canonical form.)

---

### A-A-012 — INFO — Pubkey malleability mitigated; no compressed/decompressed dual encoding

**Severity:** INFO
**Status:** WONTFIX
**Threat model:** Attacker presents two different pubkey encodings for the same EC point; verification differs.

**Why it doesn't work:**
- noble's `point.toBytes()` (lines 555-560) emits a 32-byte canonical form: `numTo32bLE(y) | (x_sign << 7)`. ALWAYS canonical.
- noble's `Point.fromBytes(b, zip215)` validates `0 <= y < P` (when zip215=false). This rejects non-canonical y > P encodings.
- Plutus's `verify_ed25519_signature` builtin pins the pubkey shape to 32 bytes (libsodium-compatible).

`getPublicKeyAsync` always returns canonical bytes. The Aegis validator passes them through `verify_ed25519_signature` which accepts only the canonical 32-byte form.

Cofactor-cleared / small-order pubkeys: noble v3's `_verify` with zip215=false rejects via `if (!zip215 && A.isSmallOrder()) return false;` (line 845 of index.ts). Aegis uses zip215=false. Good.

---

### A-A-013 — INFO — Cross-network sig replay rejected by domain_tag + network_magic binding

**Severity:** INFO
**Status:** WONTFIX
**Threat model:** Attacker submits a mainnet-signed witness on preprod (or vice versa).

**Verified empirically (sign_auth.test.ts):**
```
TV-1 (preprod) commit: 091c23daf3b3bab1bb7508ae312d48198f121fff1e7a6caeddd49f52aeb80885
TV-2 (mainnet) commit: 64b01e537a005e32a53cc37494755cea1f3413fc2b25accefb9e7080c3023bec
```
Distinct commits → distinct sigs (over different messages). The `cross-network replay rejected` test in sign_auth.test.ts already exercises this. Δ4 closes the H-1 surface.

**Edge case:** if a relay accepts BOTH `payload_cbor` (containing `domain_tag = MAINNET_TAG`) and `sig` over `commit(payload_cbor)`, but submits the `sig` claim on preprod where the policy datum's `auth_commitment` was set with the PREPROD-tagged commit — the on-chain check `blake2b_256(awd.payload_cbor) == commit` rejects. Good.

---

## False positives — attacks tried that didn't work

For audit completeness, the following attacks were attempted and confirmed not viable:

### F-1. Indefinite-length nested fields inside the Constr 0 envelope
**Idea:** the outer Constr 0 is `0xd8 0x79 0x9f ... 0xff` (indefinite). Could an inner field ALSO be indefinite (e.g. encoded as `0x9f ... 0xff` as a CBOR list)?
**Why it fails:** the AuthCoveragePayload schema has no list-typed inner fields; all 14 fields are bytestrings or uints. The Aiken stdlib `decode_data` for major-type-0/1/2 doesn't have an indefinite branch (only major-type-4 lists and major-type-5 maps do). Bytestrings have the orthogonal indefinite-form via `0x5f` (covered by A-A-003). No cross-field indefinite-list smuggling.

### F-2. CBOR bignum (tag 2 / tag 3) for max_coverage
**Idea:** Python encoder produces bignum for `max_coverage = 2^65`; Aiken's decoder accepts.
**Why it fails:** Aiken's `decode_data` major-type-6 branch routes tag != 102 and tag < 1280 to `tag - 121` for Constr index. Tag 2 → Constr index -119. Then it tries to decode fields per the Constr branch, which expects either an indefinite-list `0x9f` marker or a definite-length array header. The bignum's payload (a major-type-2 bytestring) is NEITHER, so decode fails. Result: the witness mint validator's `expect Some(payload_data) = cbor.deserialise(payload_cbor)` returns None and the mint tx is rejected.

### F-3. Empty bytestring fields (`payout_address = b""`)
**Idea:** A 0-byte payout_address bypasses the on-chain `enterprise_addr_of` equality check.
**Why it fails:** `enterprise_addr_of(datum.insured)` always produces a 29-byte result (1-byte header + 28-byte VKH). `b"" != 29_byte_address`. Mint validator's `payload_policy_id_ok` and `payout_addr_binds` (in ClaimWithAuth) reject. Off-chain TS `assertBytesLength('payout_address', _, 29)` also rejects.

### F-4. Indefinite-length bytestring chunks for hash fields
**Idea:** Encode `policy_id` as `0x5f 0x40 0x5e <14 bytes> 0x4e <14 bytes> 0xff` (indefinite chunks).
**Why partially-works-not-exploit:** Aiken's `decode_chunks` accepts and re-glues chunks via `append_bytearray`. The decoded `policy_id` is the concatenated bytestring. The validator's `payload.policy_id == datum.policy_id` would still hold IFF the concatenation matches. **However the BLAKE2b commit over the chunked CBOR differs from the commit over canonical CBOR.** So a user's signature over the canonical commit doesn't verify against the chunked-CBOR-derived commit. Not exploitable end-to-end.

### F-5. Constr index collision (Constr 0 → 1 via byte mutation)
**Idea:** Change `0xd8 0x79 0x9f` to `0xd8 0x7a 0x9f` (Constr 1 with 14 fields). Decoder accepts as Constr 1.
**Why it fails:** Aiken's `expect AuthCoveragePayload = data` where `AuthCoveragePayload` is defined as a Constr 0 type. Constr 1 fails the runtime type-coercion; `expect ... = ...` aborts the validator. (Confirmed by the spec note "Constr index collision: `Constr 0` is hardcoded.") If a future Aiken type adds a sum variant before AuthCoveragePayload, the index could shift — but that's a refactor-time concern, not an exploit.

### F-6. Length-extension on BLAKE2b-256
**Idea:** Standard SHA-2 has length-extension; could BLAKE2b?
**Why it fails:** BLAKE2 is not vulnerable to length-extension (it uses a length-padded domain separator). Aegis uses `blake2b_256` directly; no construction looks like `H(K || M)` where K is secret-ish.

### F-7. The 27-byte `domain_tag` is short enough for length-extension prefix collision
**Idea:** Aegis uses `AEGIS_CLAIM_AUTH_v1_PREPROD` (27 bytes). Could an attacker craft a different 27-byte tag with the same partial state?
**Why it fails:** the tag is only the FIRST FIELD of the canonical CBOR; the BLAKE2b operates over the full CBOR, not a prefix. Plus BLAKE2b doesn't have length-extension. Plus Aegis pins the tag bytes verbatim against `auth_domain_tag` constants. Multiple layers.

### F-8. `signer_pkh = blake2b_224(insured_vkey)` collision attack
**Idea:** Could an attacker provide a vkey that hashes to a pkh already in some valid policy datum?
**Why it fails:** 2^224 second-preimage. Plus the validator checks `blake2b_224(awd.insured_vkey) == datum.insured` AND `verify_ed25519_signature(awd.insured_vkey, commit, sig) == True` — the attacker would need to forge BOTH the pkh-hash collision AND a valid Ed25519 signature for the colliding-pkh's vkey. The latter requires the corresponding private key, which the attacker doesn't have (the pkh-collision attack would just produce a public key whose private key is unknown).

### F-9. 0xff byte as a field value triggering false break-stop-code interpretation
**Idea:** The outer envelope ends with `0xff` (CBOR break). What if a bytestring field contains `0xff` bytes inside?
**Why it fails:** definite-length bytestring encoding has a length prefix (`0x58 0x1c <28 bytes>`); the decoder reads exactly 28 bytes regardless of their values. The break-stop-code is only consulted in indefinite-length contexts, not inside a definite-length bytestring's payload. (Indefinite bytestrings via `0x5f` ARE break-terminated, but again the chunks have their own length prefixes.)

### F-10. Witness-stuffing DoS via duplicate ref-input asset names
**Idea:** Submit ClaimWithAuth with TWO reference inputs both carrying tokens with the same asset name under auth_witness_nft_policy_id.
**Why it fails:** Δ7 / `collect_witnesses` in policy.ak iterates ALL reference inputs and counts; `exactly_one_witness = (witness_count == 1)`. Two witnesses → reject. (Verified in the v8_auth_tests `test_fauth3_witness_stuffing_two_witnesses_rejected`.)

### F-11. RotateAuth without re-signing the new commit
**Idea:** Submit RotateAuth without an Ed25519 sig over the new commit; rely on CIP-30 main-wallet sig only.
**Why it works as designed:** by spec, RotateAuth is gated solely by the CIP-30 main-wallet `extra_signatories` check on `datum.insured`. The new witness's `payload_cbor` is bound via `commit_from_cbor(new_awd.payload_cbor) == new_commit`, but the new witness's `signature` field is NEITHER read nor verified by the policy.ak RotateAuth branch. So the new witness can carry a junk `signature` — the next ClaimWithAuth would reject it (signature_valid would fail). This is the intended design: RotateAuth doesn't pay out, so no signature verification is needed; the next ClaimWithAuth is the binding check. **No exploit, but the spec's defensive design is worth re-reading carefully.**

---

## Recommendations — top 3 fixes by impact

### 1. Fix A-A-001 (CRITICAL): remove `one_shot_consumed` from auth_witness_nft mint validator
Pre-deploy gate. Without this fix, v8 is functionally bricked after the first Underwrite-with-auth on chain. Trivial diff, high regression-test value.

### 2. Fix A-A-002 (HIGH): bind ALL 14 payload fields in ClaimWithAuth validator
Add 9 explicit equality checks for the currently-unbound fields. Cost: ~9 cheap equality checks. Closes the wallet-UX deception class entirely. Combined with A-A-001 fix, this is the principal pre-mainnet mitigation.

### 3. Fix A-A-003 (MEDIUM): re-encode-and-compare the canonical CBOR at validator entry
Adds a single `cbor.serialise(payload) == awd.payload_cbor` check. Closes the canonical-determinism gap for any future encoder that produces non-canonical bytes. Cost: 1 extra `cbor.serialise` call (~10x cheaper than the existing `cbor.deserialise`).

Shipping these three closes the entire "wallet-displayed-but-unenforced" deception class and the entire "non-canonical CBOR accepted on chain" canonicalization class. The remaining LOWs (A-A-004 through A-A-009) are good housekeeping but not pre-mainnet blockers.

---

**End of report.**

— Phase 3 Red-Team A (crypto/CBOR), 2026-05-06.
