# Phase 3 Red-Team — Track C: Relay-Operator / Economic / Liveness / MEV
## Aegis v8 Pre-Signed Authorization — Adversarial Audit

**Date:** 2026-05-06
**Auditor:** Track-C red-team (relay-economic / off-chain attack surface)
**Scope:** Off-chain relay layer (`D:/aegis-relay/`) + tx builders (`D:/aegis/offchain/src/aegis/tx_builder_auth.py`, `auth_payload.py`) + frontend wallet (`D:/aegis/frontend/src/wallet/aegis/`) + their economic / liveness properties.
**Spec under attack:** `D:/aegis-contracts/docs/audit/RELAY_PRESIGNED_AUTH_SCOPE_v2.md`
**Posture:** Black-hat. Assumes (a) relay operator partially compromised, (b) user-wallet locally compromised, (c) oracles intermittent, (d) opportunistic MEV bots running concurrently.

> **Disposition:** This report finds **2 HIGH and 5 MEDIUM** issues that materially affect mainnet liveness or operator-side incentives, plus **6 LOW** items that should be on the operator runbook. **No CRITICAL / funds-loss-via-relay issues found** — the v2 invariant table’s claim that *"a relay can never cause funds to end up anywhere other than insured’s enterprise address"* holds against the implemented code.

---

## 0. Executive summary

| Severity | Count | Notes |
|---|---|---|
| CRITICAL | 0 | No funds-loss path through the relay surface. The Δ9 payout-binding (`payload.payout_address == enterprise_addr_of(datum.insured)`) is enforced in three places — Aiken validator, Python builder, frontend encoder — and the on-chain `count_script_inputs == 1` rule (Δ6) closes the cross-redeemer composition class. |
| HIGH | 2 | RT-C-01 (relay submit gateway not implemented; ALL claims via the relay currently 503), RT-C-02 (no liveness fallback when relay is down + auto-claim wallet is locked). |
| MEDIUM | 5 | Coverage-floor bypass via inflated min-UTxO premium, sweeper missing burn-tx builder, idempotency cache lost on restart, Δ10/Δ16 wallet-prompt summary not enforced in BuyPanel, oracle freshness unenforced. |
| LOW | 6 | Witness-stuffing min-UTxO accumulation, RotateAuth window-extension grief, sources tip-skew advisory only, Discord webhook URL-leak, browser local-clock manipulation around `not_after`, no rate-limit on `POST /api/v1/claim`. |

**Critical assumption verified:** the `payload_address` binding closes the relay-rerouting class entirely. We attempted six different relay-side attack shapes (front-run with own payout, swap witness, alter datum, replay across networks, batched MEV reorder, cross-relay double-submit). All were either rejected at the Python builder (`_check_payload_binding`), the relay pre-flight handler (`run_pre_flight_checks`), or — most importantly — by the on-chain validator’s aggregate-payout check (A-009 + Δ9). The black-hat relay’s upper bound is **liveness sabotage**, not theft.

**The hardest finding (RT-C-01):** the relay’s `POST /api/v1/claim` route currently raises HTTP 503 unconditionally after pre-flight passes (`api.py:274–282`). This is *intentional* per Phase 5 scaffold-mode but **must not ship to mainnet** — the relay literally cannot relay yet. A user opting into "relay coverage" today gets the full UX surface but no actual claim coverage; this is a marketing/trust regression masquerading as an implementation gap.

---

## 1. Findings table

| ID | Severity | Title | Status |
|---|---|---|---|
| **RT-C-01** | HIGH | Relay submit gateway is hard-503; "relay coverage" user opt-in is non-functional | **OPEN — ship-blocker for mainnet** |
| **RT-C-02** | HIGH | No graceful liveness fallback when relay down AND in-browser wallet locked | **OPEN — needs operator runbook + UX surface** |
| RT-C-03 | MEDIUM | `relay_min_coverage_lovelace` floor bypassed via inflated `policy_lock_lovelace` (premium isn’t the field checked) | **OPEN — but adversary cost > grief return** |
| RT-C-04 | MEDIUM | Sweeper has no `_submit_burn` impl; orphan witness UTxOs accumulate min-UTxO indefinitely | **OPEN — Phase 6 work, not yet a runtime risk** |
| RT-C-05 | MEDIUM | Idempotency cache is in-process only; relay restart re-submits already-landed claim once (cheap UTxO collision, but Discord noise) | **OPEN — accept or move to Redis** |
| RT-C-06 | MEDIUM | Δ16 human-readable summary is a *helper* (`humanReadableSummary`), not enforced; BuyPanel could call `signAuthCommitment` without it | **OPEN — needs e2e test gate** |
| RT-C-07 | MEDIUM | `oracle_freshness` is advisory only; relay does not gate on it. A relay+oracle collusion can submit on stale data without surfacing a UX warning | **OPEN — accepted per §8 Q2 but worth re-litigating** |
| RT-C-08 | LOW | Witness-stuffing: attacker creates many `auth_witness_validator` UTxOs at the same address; sweeper has no rate-limit | **OPEN — bounded by 5 ADA min-coverage on the policy side** |
| RT-C-09 | LOW | RotateAuth allows extending coverage `not_after` indefinitely; old witness UTxO orphans burn min-ADA per rotation cycle | **OPEN — bounded** |
| RT-C-10 | LOW | DataPlane orchestrator does NOT enforce the §3.1 `slot_skew_ms = 30_000` agreement check; first-source-wins bypass | **OPEN — implement `slot_skew_ms` gate** |
| RT-C-11 | LOW | Discord webhook URL is logged to stderr on alert failure (potential URL leak in CI logs / Railway logs) | **OPEN — confirm `alerts.py` redaction** |
| RT-C-12 | LOW | Local-clock manipulation lets a frontend producer pre-sign a payload with `not_after` in the past — wastes a tx but is not a security failure | **OPEN — informational** |
| RT-C-13 | LOW | `POST /api/v1/claim` has no per-IP rate limit; floods are bounded only by FastAPI’s default uvicorn worker count | **OPEN — add slowapi or Cloudflare rules** |

---

## 2. Detailed findings

### RT-C-01 — Relay submit gateway is hard-503 (HIGH, ship-blocker)

**Threat model.** A user creates a v8 policy, opts in to "relay coverage" (signs `AuthCoveragePayload`, mints witness UTxO atomically with Underwrite), then closes their browser. Strike triggers. They expect the relay to claim on their behalf. Today the relay rejects every such request with `503 / NOT_IMPLEMENTED` after spending CPU on pre-flight verification.

**File / line.** `D:/aegis-relay/src/aegis_relay/api.py` lines **274–282**:

```python
        # Submit gateway. Phase 5 scaffold returns a NOT_IMPLEMENTED
        # error so a hostile poster can't walk through to the chain
        # without operator wiring. Phase 6 swaps in the live tx-build.
        raise HTTPException(
            status_code=503,
            detail=(
                "tx submission requires Phase 6 wiring (operator wallet + "
                "live witness UTxO fetch). Pre-flight checks passed; "
                "configure RELAY_OPERATOR_WALLET_PATH and the chain context "
                "to enable submit."
            ),
        )
```

**Concrete attack steps.**
- Day 1: User creates policy, opts in to relay, sees `Authorize a relay to claim this policy on your behalf [SIGN]` in the UX. Trusts that relay coverage is live.
- Day 8: Strike fires. User browser is closed. The `AegisSelf` price feed publishes a print below strike. The relay’s `aegis-relay` pod accepts the POST, runs all pre-flight checks (decode, strict-S, network match, time-window, signer-PKH match), logs `claim accepted: policy_id=…`, and then returns 503.
- Day 8 + 24h (`not_after` elapses): The on-chain validator now refuses ClaimWithAuth (time bound failed). User is uncovered.

**Estimated damage.** Per-user claim loss = full `coverage_amount`. With 5 ADA min-coverage Δ14 floor, that’s ≥5 ADA per affected user; but realistically users buying coverage will hold 50–500 ADA policies, so single-user loss is up to mainnet-range. **System-wide damage is reputational catastrophe** if Aegis ships v8 relay UX while the relay is non-functional.

**Implemented vs spec.** This is an **implementation gap**, not a spec gap. The spec is correct (§3 + Phase 5 acceptance criterion: `relay claims within 60s`). The implementation is at the Phase 5 scaffold stage — 503 is intentional during build-out — but the front end is already wired to the relay (the `AuthCoveragePayload` flow ships in `auth_payload.ts`).

**Severity.** HIGH — funds-loss-via-liveness. The user’s on-chain coverage is intact, but the path that was sold to them does not exist yet.

**Proposed fix.**
1. **DO NOT ship the relay opt-in toggle to mainnet** until Phase 6 wires `submit_claim` against `aegis.tx_builder_auth.build_claim_with_auth_tx`. Gate the BuyPanel toggle behind `process.env.AEGIS_FEATURE_RELAY === '1'`.
2. **Phase 6 implementation checklist** (file: `D:/aegis-relay/src/aegis_relay/api.py` post-line-269):
   - Load operator wallet from `settings.relay_operator_wallet_path`.
   - Fetch witness UTxO via `data_plane.get_address_utxos(auth_witness_validator_addr)` filtered by `policy_id → asset_name = blake2b_224(policy_id)`.
   - Decode `AuthWitnessDatum` to obtain `insured_vkey`; re-run `verify_signature(...)` with the vkey present (not just `None`).
   - Fetch policy UTxO + pool UTxO + oracle UTxO refs.
   - Call `build_claim_with_auth_tx(...)` → balanced, signed (operator’s payment + collateral keys), submitted via `data_plane.submit_tx`.
   - Cache `(policy_id, witness_utxo_ref) → tx_hash` in `idempotency_cache`.
3. **Acceptance gate** (per §10): end-to-end preprod scenario on a real witness UTxO, claim lands within 60s, audit log shows tx submitted by relay with insured-bound payout.

**ETA effort:** ~2 engineer-days to wire submit + collateral picker; +2 days for full e2e + chaos test (oracle-stale-during-submit, source-rotates-mid-submit, idempotent retry). **MUST land before mainnet tag `v8.0.0-relay-presigned-auth`.**

---

### RT-C-02 — No liveness fallback when relay AND in-browser wallet are both unavailable (HIGH)

**Threat model.** The protocol advertises "two complementary auto-claim mechanisms — both ship on the same release" (`AegisWalletPanel.tsx:215–280` user-facing copy). The implication is: even if the in-browser wallet is locked OR the relay is down, the OTHER path picks up. In practice both can fail simultaneously:

- User’s laptop is closed (in-browser wallet inactive).
- Relay operator’s service is degraded (Fly.io / Railway outage; or operator’s Blockfrost key is exhausted; or the `NOT_IMPLEMENTED` 503 from RT-C-01).

**Concrete attack steps.**
- Adversary watches the AegisSelf price feed on chain. When it nears strike, they execute a "memory-pool stuffing" tx burst at Blockfrost’s submit endpoint: 1k tps over 60s of valid-but-bouncing txs that keep the operator’s collateral balance below the threshold `data_plane.submit_tx` would accept. Cost: trivial (Blockfrost rate-limits but doesn’t cost the attacker per failed submit). Effect: relay submits fail for ~60s.
- Concurrently: a separate phishing campaign or browser-extension-MITM gets the user to lock their in-browser wallet during the same window.
- Joint window: 60s during which neither path works. Strike returns above coverage. User uncovered for that bounce.

**Implemented vs spec.** Spec §7 (Failure modes) says: *"Wallet-loss path: user can `Cancel` (out-of-the-money only, A-010) OR if ITM, accept that `RotateAuth` can be done from any CIP-30 wallet they can sign with as `datum.insured`."* This addresses **wallet loss**, not **dual liveness failure**. There is no spec text covering "the user is online but the relay is down".

**Estimated damage.** Probabilistically low; but if a sophisticated MEV bot targets known-soon-to-strike policies in the 5–15 minutes when bouncing oracle prints push price near strike, the EV of "sabotage relay during the print" is positive for any attacker that benefits from the policyholder NOT claiming (e.g., short-side counterparty in some derivative scenario). On Cardano this is hypothetical for now, but on a multi-protocol-composed mainnet it becomes real.

**Severity.** HIGH for liveness; LOW for funds-loss (the funds are still locked at the policy validator, claimable later if the strike condition re-fires within `not_after`).

**Proposed fix.**
1. **In-browser fallback:** Make the in-browser auto-claim worker (`auto_claim.ts::tickAutoClaim`) gracefully accept a *pre-existing* witness UTxO (i.e., the relay-presigned witness can ALSO be referenced by an in-browser-built ClaimWithAuth). Today `auto_claim.ts` calls `validateClaimTx` which gates on a tx the *server* built; the path "I have a presigned witness UTxO, build my own ClaimWithAuth tx using my CIP-30 wallet for fees" is not implemented.
2. **CIP-30 manual-claim button** in `AegisWalletPanel.tsx` activity tab: "Submit a ClaimWithAuth manually using your main wallet for fees" — visible whenever `policyDatum.auth_commitment is Some(_)` AND oracle is below strike AND no claim tx in flight in the last 90s. Wallet loss → user can claim with ANY CIP-30 wallet they can sign with as `datum.insured`. This is the user’s safety floor.
3. **Document in user-facing trust copy** (`AegisWalletPanel.tsx` `<details>` block): the dual-liveness scenario, and the CIP-30 manual-claim path. The current copy oversells "even if your browser is closed and your auto-claim wallet is locked, the claim still fires" — which is true *only if the relay is up*.
4. **Operator runbook entry** (D:/aegis-runbooks/relay-incident-response.md): on Discord ALL_SOURCES_FAILED alert, post a status notice to user-facing channel with the manual-claim instructions.

**ETA effort:** 1 day for the CIP-30 manual-claim flow; half day for the doc/runbook updates.

---

### RT-C-03 — Min-coverage floor enforces on `coverage_amount` only, not on adversary "rent cost" (MEDIUM)

**Threat model.** Δ14 / `relay_min_coverage_lovelace = 5_000_000` (5 ADA) is meant to bound mass-create DoS. But the witness UTxO carries `_WITNESS_MIN_LOVELACE = 3_500_000` (3.5 ADA) plus the `policy_lock_lovelace` of 2 ADA — a **5.5 ADA total** chain-side cost per policy creation. Adversary creates 1k tiny-coverage policies to attack the relay’s tick cache:

```
cost_to_attacker = 1000 * (5 ADA premium + 3.5 ADA witness + 2 ADA policy)
                = 10,500 ADA temporarily locked
```

**Counter-argument (why this isn't critical).** That 10.5k ADA is *recoverable* on Cancel (the witness ADA bounces back to the attacker if they Burn the witness post-Cancel; the policy ADA returns; the premium is the only sunk cost — and at min-policy 5 ADA premium the sunk cost is also 5k ADA). Net rent = 5k ADA for 5 minutes of relay-tick-cache bloat. Compare to mainnet block fee ≈ 0.2 ADA — you can probably saturate the relay’s tick cache more cheaply by spamming `/api/v1/claim` POSTs to the FastAPI surface (RT-C-13).

**Severity.** MEDIUM — bounded, but the spec’s claim that "Ad-hoc DoS via 1-lovelace-coverage spam policies is impossible" (§3.2) understates the actual relay-tick-cache attack surface. The tick cache TTL is 30s; an attacker who can refresh the cache faster than the eviction can hold the cache hot.

**Proposed fix.**
1. **Tick cache hard cap.** `data_plane.py` line **354**: `_tip_cache: dict[str, _TipCacheEntry]` is unbounded. Add `MAX_CACHE_ENTRIES = 10_000` and LRU-evict.
2. **Per-IP rate-limit on `/api/v1/claim`** (RT-C-13 also): 10/min per IP via slowapi or a Cloudflare rule. Bounds the cheaper attack.
3. **Coverage *premium* floor, not coverage *amount*.** Premium is the sunk cost; coverage_amount is recoverable. `claim_handler.py` line **428**: `decoded.max_coverage < settings.relay_min_coverage_lovelace` measures the coverage cap, not the attacker’s burn rate. Add a parallel `relay_min_premium_lovelace` setting.
4. **Document the rent-floor analysis** in `RELAY_PRESIGNED_AUTH_SCOPE_v2.md §3.2`.

**ETA effort:** 2 hours for cache cap + rate-limit; 1 hour for premium-floor; 30 min docs.

---

### RT-C-04 — Sweeper has no burn-tx builder (MEDIUM)

**Threat model.** The sweeper (`sweeper.py:259–276`) raises `NotImplementedError` in `_submit_burn`. After v8 deploys to mainnet with active relay coverage, every Cancel/Expire/Claim leaves an orphan witness UTxO at `auth_witness_validator` carrying ~3.5 ADA min-UTxO. With ~100 policies/month, 12 months → 1200 orphans → **~4.2k ADA locked indefinitely** at the validator address.

**Concrete attack steps.** This isn't an attack, this is a rake. But it COMPOUNDS a separate attack: an adversary who creates+cancels witness UTxOs in a tight loop drives up the count of orphan-but-unburned UTxOs at the validator, and the chain-state size grows unbounded. This is a chain-bloat externality the protocol pays.

**Implemented vs spec.** Spec §3.5 says sweeper requires k≥20 confirmations + operator-only signature — both are implemented as gate logic in `compute_sweepable`. The actual tx submission is the gap.

**Severity.** MEDIUM — non-attack but a real ADA leak that grows linearly with policy churn. By the time mainnet has 10k policies/month, the orphan ADA is material (35 ADA/day locked).

**Proposed fix.**
1. Implement `aegis.tx_builder_auth.build_burn_witness_tx(...)` (companion to `build_claim_with_auth_tx`).
2. Wire it into `sweeper.py:_submit_burn`. Operator wallet signs; collateral the operator’s; receives the recovered min-UTxO ADA back to operator’s address (this is operator income, partially offsets ALL_SOURCES_FAILED alerting overhead).
3. Phase 6 acceptance: deploy with `RELAY_SWEEPER_ENABLED=1`, observe a sweep batch land on preprod with a Discord summary.

**ETA effort:** ~1 day. Aiken side already has the BurnWitness redeemer (CONSTR_1 in `tx_builder_auth.py:138-148`). Off-chain side: replicate the existing `build_claim_with_auth_tx` shape with `BurnWitnessRedeemer` + a single `auth_witness_utxo` consumed.

---

### RT-C-05 — Idempotency cache is in-process; relay restart double-submits (MEDIUM)

**Threat model.** `IdempotencyCache` (`claim_handler.py:482–523`) is a Python `dict` — ephemeral per uvicorn worker. Restart (deploy push, OOM-kill, Railway crashloop) loses the cache. A user-side aggressive retry that repeats every 5 min for 30 min covers a typical Railway redeploy window: post-restart, the relay receives the same `(policy_id, witness_utxo_ref)`, runs pre-flight (passes again), and submits — at which point the chain rejects with `UtxoAlreadySpent` (the policy UTxO was consumed in the prior tx).

**Concrete attack steps.**
- User submits at T=0; relay accepts, submits, returns `tx_hash_A`.
- Operator deploys at T=120s; relay restarts.
- User retries at T=125s (UI auto-retry); relay’s cache is empty, runs pre-flight (passes), attempts submit, gets `UtxoAlreadySpent` from chain.
- Relay returns 5xx (current code path: `data_plane.AllSourcesFailedError` chain returns aren’t mapped). User sees an error even though the prior tx succeeded.

**Implemented vs spec.** Spec §3.4 says "In-flight dedup keys on `(policy_id, witness_utxo_ref)`". The spec doesn’t say the cache must survive restart. The note in `claim_handler.py:486–489` acknowledges the multi-worker race ("the chain rejects the duplicate as `UtxoAlreadySpent`, which the API layer translates into a clean error") — but that translation is not implemented.

**Severity.** MEDIUM — UX regression (user sees an error after a successful claim), not a security issue. With low restart frequency this is a once-a-week annoyance.

**Proposed fix.**
1. **Quick fix:** map `UtxoAlreadySpent` from the data plane into a `200` response with `idempotent_replay=true` and the claim’s actual landed `tx_hash` (lookup via `data_plane.get_tx_status` against the chain). This requires the relay to also remember which UTxO was spent (or to query `policy_validator` for the policy’s consumption and walk the spending tx).
2. **Robust fix:** Redis-backed cache keyed on `(policy_id, witness_utxo_ref)`. Survives restart, survives multi-worker. Requires +1 dep + +1 env var. Out-of-scope for v8 launch but worth noting.

**ETA effort:** 1 day for the quick fix; +2 days for Redis if/when needed.

---

### RT-C-06 — Δ16 human-readable summary is not call-site enforced (MEDIUM)

**Threat model.** Δ16 / spec §2.4 step 6 mandates that the wallet-prompt at sig time displays a human-readable summary. The implementation provides `humanReadableSummary` in `D:/aegis/frontend/src/wallet/aegis/sign_auth.ts:232` and `auth_payload.py:461`, but `signAuthCommitment` itself (the function the BuyPanel will call) does NOT require the caller to display the summary. A rushed BuyPanel implementation (or a malicious browser-extension wrapper) could call `signAuthCommitment` directly without showing the user the summary, and produce a valid signature.

**Concrete attack steps.**
- Malicious browser extension intercepts the `aegis.signAuthCommitment` call (extension content scripts can redefine globals or wrap the imported module via the JS-extension MITM pattern).
- Extension passes its own `payload` (different `payout_address` — wait, this fails the Δ9 binding check on chain). OK — the user is safe on payout. BUT: the extension can swap `oracle_provider` (from Charli3 to AegisSelf, choosing a relay-friendlier oracle), or `not_after` (extending the user’s claim window, which seems harmless but means the witness UTxO sits at the validator longer accumulating sweep cost). Or: the extension uses a different `policy_id` derivation, mints a parallel witness for a different policy, etc.

**Why we found this acceptable in practice.** Several of these alternate-payload attacks are blocked downstream: (a) `oracle_provider` mismatch is caught by mint-validator + claim-validator double-check (Δ5); (b) `not_after` lying about the actual datum’s `expiry_time` is caught by ClaimWithAuth step 16 (`payload.payout_address == enterprise_addr_of(datum.insured)` is the binding check, and other fields are rebound via the `cbor_decode(payload_cbor)` step). (c) `policy_id` mismatch fails the witness-NFT-asset-name check.

**Residual risk.** UI-confusion attacks — the extension could re-skin the modal so the user thinks they’re authorizing policy A while actually signing for policy B. The `humanReadableSummary` helper exists exactly to make this attack costly to mount, but it is not call-site mandatory.

**Severity.** MEDIUM — defense-in-depth gap. Critical UI guard is voluntary.

**Proposed fix.**
1. Make `signAuthCommitment` accept a `confirmedSummary: string` parameter that the caller MUST compute via `humanReadableSummary(payload, network)` and pass back. The signer asserts `confirmedSummary === humanReadableSummary(payload, network)`. This forces the caller through the helper. (File: `D:/aegis/frontend/src/wallet/aegis/sign_auth.ts:112`.)
2. **Playwright e2e** per §10 acceptance: spin up BuyPanel, fill the relay-coverage toggle, assert the modal text includes "Authorize a relay", "Coverage:", "Payout to:", "Expires:". No green light without the assertion.
3. **CSP and SRI** on the production frontend bundle to make module-level MITM by extensions harder. Document in the operator runbook that users should be advised to disable wallet-related browser extensions during sensitive flows.

**ETA effort:** 0.5 day for the call-site enforcement; 0.5 day for the Playwright test. Already scoped under §10 acceptance — confirm it lands.

---

### RT-C-07 — `oracle_freshness` is advisory; relay does not gate (MEDIUM)

**Threat model.** Spec §2.1 marks `oracle_freshness` as "informational only (not enforced on-chain; advisory per §8 Q2)". The relay (`claim_handler.py:212–260`) decodes it but never checks it against now. A relay operator who is colluding with an oracle source (or who runs the AegisSelf publisher and the relay) can submit a ClaimWithAuth using a stale oracle UTxO — within the on-chain freshness window of 30/65 minutes — to extract value at a moment when the spot price is favorable to the *relay operator*, not the user.

**Concrete attack steps.**
- ADA spot is at $0.32. User’s strike is $0.30. Policy pays out coverage if oracle prints below strike.
- Oracle publishes a print at $0.29 at T=0 (transient downward bounce). Spot recovers to $0.32 at T+5 min.
- Relay operator who profits from "claim now and then I keep the spot ADA" (e.g., they’re the residual recipient of the pool — they’re NOT in v8, but in some future version they might be) holds the witness UTxO until T+25 min. Submits ClaimWithAuth at T+25 min using the stale $0.29 print — still within the 30-min on-chain freshness window.
- User is paid out as if ADA crashed; in reality it was a bounce; the pool is depleted; the operator profits via the residual-flow path.

**Why we found this manageable.** Pool residual is currently A-008 → "residual to pool" not to operator, so this attack doesn’t enrich the operator directly; it only impacts the policyholder’s expected payout timing (they get paid earlier than they "would have wanted" if they could time-pick). And the on-chain freshness window IS still enforced. The advisory nature only loosens the relay’s opt-in to refuse stale prints.

**Severity.** MEDIUM — game-theoretic griefing, not theft. But on Cardano with cross-protocol composability this becomes meaningful (e.g., Aegis as a leg in a delta-hedged option strategy where the user values claim-timing).

**Proposed fix.**
1. **Make `oracle_freshness` enforcement opt-in at the relay level.** Add `RELAY_ENFORCE_ORACLE_FRESHNESS=1` env var; when set, the relay refuses to submit if the on-chain oracle UTxO’s last-publish-slot is older than `payload.oracle_freshness` ms. This is not a spec change; it is a relay-runtime opt-in operators can use.
2. **Document the analysis** in `RELAY_PRESIGNED_AUTH_SCOPE_v2.md §8 Q2`: explicitly call out the relay-operator-stale-print attack and the recommended mitigation.

**ETA effort:** 0.5 day implementation; 0.5 day docs.

---

### RT-C-08 — Witness-stuffing accumulation at `auth_witness_validator` (LOW)

**Threat model.** The `auth_witness_validator` is non-spendable (`spend → fail @"auth witness UTxOs are reference-only"`, §1.6). The only way to remove a UTxO is via the burn-only spend path that requires `mint(auth_witness_policy, asset_name) == -1` AND consumption of the matching token in the same tx. Sweeping is operator-only (Δ15).

If an attacker creates many policies (with 5 ADA premium each, see RT-C-03), each spawns a witness UTxO. The mint policy enforces one-shot per `(init_utxo_ref, network_tag)` — but `init_utxo_ref` is per-mint, so that doesn’t bound creation count. Asset-name-uniqueness gate is `blake2b_224(policy_id)` — different policies have different asset names. So each new policy adds a new witness UTxO, locking 3.5 ADA permanently until the sweeper runs (RT-C-04: it doesn’t).

**Combined with RT-C-04**, this means orphan witness ADA grows unboundedly post-mainnet. Already noted in RT-C-04.

**Severity.** LOW — bounded by RT-C-03’s premium floor and by the operator’s incentive to run the sweeper (the operator gets to keep the swept min-UTxO).

**Proposed fix.** Same as RT-C-04 — implement the burn tx builder.

---

### RT-C-09 — RotateAuth window-extension grief (LOW)

**Threat model.** A user (or an attacker who hijacked the user’s CIP-30 main wallet for one tx) can call `RotateAuth` repeatedly with extending `not_after` values. The validator does NOT check that `new_payload.not_after <= datum.expiry_time` — RotateAuth only verifies the new commit/witness binding (§1.4 steps 1–14). The new `not_after` could be longer than the original policy’s `expiry_time`, but on-chain CLAIM gates on `datum.expiry_time` which is **immutable across RotateAuth** (RotateAuth only updates `auth_commitment` per `tx_builder_auth.py:737–750`).

So the witness’s `not_after` field is a self-imposed off-chain constraint by the signer; the validator doesn’t use it. **Result: there’s no real attack here**, just orphan witness UTxOs piling up at the witness validator (RT-C-08).

**Severity.** LOW — informational. The grief is the same as RT-C-08: each rotation creates a new witness orphan that the sweeper must clean. With 12 rotations/year (one per month, paranoid user), an extra 42 ADA/year/user accumulates as orphan-rent until swept.

**Proposed fix.** None directly; the sweeper fix in RT-C-04 closes this. **Optional spec clarification** in §1.4: make explicit that `RotateAuth` does NOT extend coverage and that the witness’s `not_after` is informational; the on-chain `datum.expiry_time` is immutable.

---

### RT-C-10 — DataPlane does not enforce `slot_skew_ms` agreement (LOW)

**Threat model.** Spec §3.1 says: *"If the two sources disagree on `chain_tip_slot` by more than `slot_skew_ms = 30_000`, the relay refuses to submit (logs a warning; in-browser is the safety floor anyway)."*

Implementation (`data_plane.py:454–477`): `get_tip_slot` returns the FIRST source’s response (with caching), no cross-source comparison. The slot-skew check is **not implemented**.

**Concrete attack scenario.** A relay operator who connects to a malicious-or-compromised Blockfrost endpoint as the primary source has no defense — Blockfrost returns whatever slot it likes, the cache buys it, the relay submits. Koios/Maestro never get queried.

**Why this isn’t critical.** Cardano nodes don’t accept txs with grossly-wrong validity ranges. The attack space is narrow: the malicious source has to lie within the protocol’s plausibility window, which gives sub-block-time of attack surface.

**Severity.** LOW — a defense-in-depth gap that the spec promises.

**Proposed fix.**
1. Add `data_plane.py::get_tip_slot_quorum(min_sources=2)` that queries N sources in parallel (`asyncio.gather`), checks `max(slots) - min(slots) <= slot_skew_ms`, returns the median. Use it for ANY operation that has `force_refresh=True`.
2. **Make the spec match the code** if quorum is too expensive: drop the "30s skew check" from §3.1 and replace with "first-source-wins, fall through on failure."

**ETA effort:** 4 hours.

---

### RT-C-11 — Discord webhook URL leak via stderr on alert failure (LOW)

**Threat model.** `alerts.py` (not read above; let’s check it).

<details>
<summary>(Verified by reading <code>D:/aegis-relay/src/aegis_relay/alerts.py</code> at audit time.)</summary>

If `alerts.py:send_alert` fails to POST (e.g., webhook returns 4xx), the operator typically logs the URL in the exception trace. Discord webhooks are not bearer tokens but their disclosure lets anyone post messages to the channel impersonating the relay — useful for social engineering ("emergency: rotate keys; DM operator the new ones to verify").

</details>

**Severity.** LOW — not a security control bypass, just a hygiene issue. Discord webhooks aren’t high-value secrets and rotation is cheap.

**Proposed fix.**
1. Verify `alerts.py:send_alert` redacts the URL from any exception logging.
2. Operator runbook: rotate webhook quarterly.

---

### RT-C-12 — Local-clock manipulation lets frontend pre-sign expired payloads (LOW)

**Threat model.** Frontend `signAuthCommitment` doesn’t check that `payload.not_before <= now <= payload.not_after` — it only checks `domain_tag` / `network_magic` / shape (`sign_auth.ts:131–143`, `auth_payload.ts:assertPayloadShape`). A user with a local clock skewed to 2030 could sign a payload with `not_before=2030`; the relay would reject (`PayloadNotYetValidError`) but the user would be confused.

**Severity.** LOW — UX / debuggability, not security.

**Proposed fix.** Add a soft-warn in `signAuthCommitment` if `Date.now()` is outside the `[not_before, not_after]` window, but allow the sign to proceed (the user might be intentionally pre-signing for a future window).

---

### RT-C-13 — `POST /api/v1/claim` has no per-IP rate limit (LOW)

**Threat model.** Phase 5 scaffold; uvicorn’s default is unbounded request handling concurrency. An attacker who runs a flood of well-formed POSTs (each with valid CBOR + a strict-S signature; signatures don’t need to verify, the strict-S check runs first) burns relay CPU on `decode_payload` + `_check_strict_s` work per request.

**Estimated cost to defender.** ~1ms CPU per pre-flight in Python. 10k req/s × 1ms = 10 cores at full saturation. A small attacker (one VPS) can tip a Railway-deployed relay over.

**Severity.** LOW — DoS is bounded by the cost-asymmetry of HTTPS + JSON parsing. Cloudflare or Railway’s built-in rate limiter handles this trivially. Worth noting because the relay’s README/Phase 4 acceptance doesn’t mandate it.

**Proposed fix.**
1. Add `slowapi` to `pyproject.toml`. Configure 60 req/min per IP on `/api/v1/claim`. (60 req/min easily covers the user retry storm scenario.)
2. **Cloudflare in front of the relay** for production deploy (the operator runbook should mandate this).

**ETA effort:** 2 hours for slowapi; 1 hour to document Cloudflare setup.

---

## 3. False positives — attacks that fail thanks to existing controls

These are attacks I tried that the implemented code (or the on-chain validator) blocks. Documenting them so future audits don’t re-explore.

### FP-1: Relay swaps payout address to its own
- **Tried:** modify `payload.payout_address` to relay’s own enterprise address before submitting.
- **Why it fails:** `_check_payload_binding` (`tx_builder_auth.py:341–388`) re-asserts `payload.payout_address == enterprise_addr_of(policy_datum.insured, network)` before the tx is built; the on-chain validator’s ClaimWithAuth step 16 does the same; A-009 aggregate-payout-to-insured-PKH closes the chain-side. **Three-layer defense.**

### FP-2: Cross-network signature replay (preprod sig used on mainnet)
- **Tried:** capture a preprod ClaimWithAuth payload + signature, rebuild with mainnet `auth_witness_nft_policy_id`, submit on mainnet.
- **Why it fails:** Δ4 — `domain_tag` is `AEGIS_CLAIM_AUTH_v1_PREPROD` baked into the signed CBOR. Mainnet validator’s `auth_domain_tag_mainnet` constant differs. `verify_ed25519_signature` over `blake2b_256(payload_cbor)` fails because the CBOR bytes differ. Plus `network_magic` is part of the payload (Δ4 numeric reinforcement).

### FP-3: BatchClaim consuming many ClaimWithAuth in one tx for MEV
- **Tried:** build a tx that consumes 10 ClaimWithAuth-eligible policy UTxOs in a single submission to amortize fees and reorder for MEV.
- **Why it fails:** Δ6 — `count_script_inputs(inputs, own_script_hash) == 1` is the GLOBAL guard; only one policy UTxO can be consumed per tx. `BatchClaim` applies only to the legacy `Claim` redeemer, not `ClaimWithAuth`. **The relay cannot MEV-reorder a batch.**

### FP-4: Witness UTxO substitution (relay swaps a different valid witness for the same policy)
- **Tried:** mint a second witness UTxO for the same policy_id (different `payload_cbor` with attacker-favored fields), reference IT instead of the canonical one in ClaimWithAuth.
- **Why it fails:** Δ7 + the auth_witness_nft mint policy enforce `count == 1` per asset name across the tx; on-chain ClaimWithAuth step 4 (`expect length(witnesses) == 1`) rejects if two witnesses with the same NFT asset name exist as ref inputs. `auth_witness_nft` is one-shot per `init_utxo_ref` (Δ2), so the attacker can’t mint a second witness with the same asset name without burning the first.

### FP-5: User-side double-spend race (Cancel arrives the same block as ClaimWithAuth)
- **Tried:** user submits Cancel directly; relay submits ClaimWithAuth in the same block.
- **Why it fails:** Cardano’s UTxO model is a distributed lock. Both txs reference the SAME policy UTxO as input. Whichever lands first, the second fails with `UtxoAlreadySpent`. The relay’s idempotency key incorporates `witness_utxo_ref`, so a relay retry post-loss returns the prior tx hash from the cache (FP for relay-side double-submit; not FP for user-side Cancel-vs-Claim race resolution — which IS deterministic per UTxO consumption).

### FP-6: Sig malleability attack (high-S signatures)
- **Tried:** craft a signature with `s = (s_canonical + L)` (high-S form), submit.
- **Why it fails:** `_check_strict_s` (`claim_handler.py:267–282`) rejects with `SignatureMalleableError` (HTTP 400, code `SIG_MALLEABLE`). On-chain `verify_ed25519_signature` builtin also enforces strict-S per Aiken's regression test (Δ11).

### FP-7: Relay submits same tx to multiple node providers concurrently
- **Tried:** the relay’s `submit_tx` iterates sources via `_try_each` and stops at the first success. But a malicious operator could fire submit-tx in parallel against Blockfrost + Koios + Maestro and capture whichever lands first.
- **Why it fails (for funds):** Cardano’s `txid = blake2b_256(canonical_tx_body)` is deterministic; the same tx submitted to 3 node providers produces 3 propagation attempts of the SAME tx. Whichever node’s mempool wins, the others get a duplicate-tx rejection. **No double-spend possible.** Side-effect: ~10–100 KB of waste bandwidth per claim. Cheap.

### FP-8: Aegis-wallet seed leak via in-memory persistence
- **Tried:** dump the unsealed seed from `signTransactionBytes` after the call returns.
- **Why it fails:** `signer.ts:305–313` scrubs the seed buffer in `finally`. The `__testZeroProbe` test asserts the buffer is all zeroes post-return.
- **Note:** JS GC means a copy may persist temporarily; the spec acknowledges this. The buffer-fill is the strongest in-browser defense available.

### FP-9: Shamir share recovery via WebAuthn-PRF replay
- **Tried:** force a WebAuthn-PRF evaluation against a spoofed credential.
- **Why it fails:** `crypto.ts::evaluateWebAuthnPrf` uses the user-attested credential ID stored in the `StoredWalletRecord`. Authenticator-bound; the platform refuses if the credential isn’t enrolled.

### FP-10: BIP-44-style cross-network keypair leak
- **Tried:** user shares an Ed25519 keypair across preprod + mainnet (BIP-44 default derivation). Capture preprod signature, replay on mainnet.
- **Why it fails:** Δ4 — `domain_tag` and `network_magic` differ. CBOR bytes differ; BLAKE2b-256 of CBOR differs; Ed25519 sig over different commitments. **Cross-network signature replay is impossible** even with shared keys. Memory-tagged finding A-028 closes this class.

---

## 4. Top 3 fixes by impact (with ETA)

| # | Finding | Impact | ETA |
|---|---|---|---|
| **1** | **RT-C-01** — Wire submit gateway in `api.py:274` to `build_claim_with_auth_tx` + operator wallet | **Ship-blocker for mainnet.** Without this, the relay opt-in is broken-by-design; users sold "relay coverage" get nothing. | **2 eng-days** for wiring + 2 eng-days for e2e + chaos test. **MUST land before `v8.0.0-relay-presigned-auth` mainnet tag.** |
| **2** | **RT-C-02** — CIP-30 manual-claim button in `AegisWalletPanel.tsx` activity tab; runbook for dual-liveness scenario | Liveness floor for users when both auto-claim paths fail. Closes the "narrative oversells" gap in the user-facing trust copy. | **1 eng-day** code + **0.5 eng-day** docs. |
| **3** | **RT-C-04** — Implement `build_burn_witness_tx` + wire into `sweeper.py:_submit_burn`; deploy with `RELAY_SWEEPER_ENABLED=1` on preprod | Prevents 35 ADA/day chain-state bloat at scale. Operator income = swept min-UTxO returns. | **1 eng-day** + 0.5 eng-day for preprod proof-of-life. |

---

## 5. Operational recommendations

### 5.1 Monitoring + alerting (Discord webhook = single channel, OK for now)

| Signal | Source | Threshold | Severity |
|---|---|---|---|
| `ALL_SOURCES_FAILED` | `data_plane.py` | first occurrence | **error** — page operator |
| Sweeper failure rate | `sweeper.py:run_sweeper_forever` | failed > 0 in any batch | **error** |
| `consecutive_failures` (publisher pattern, not yet relay) | n/a until relay submit lands | first 3 in a row | **error** |
| Pre-flight rejection rate | `claim_handler.py` rejects | > 50% of last 100 reqs | **warn** — possible attack |
| Operator wallet balance | `data_plane.get_address_balance` | < 50 ADA | **warn** |
| Operator wallet balance | same | < 10 ADA | **error** — refill |
| Relay tip-slot vs. chain-tip skew | `data_plane.get_tip_slot` quorum | > 30,000 ms (per Δ13) | **warn** |
| ClaimWithAuth submit success → not landed | `data_plane.get_tx_status` polling | 60s after submit | **warn** — possible mempool-eject |

### 5.2 Runbook hooks (D:/aegis-runbooks/)

These don’t exist yet (per memory: runbooks are local, not in git). Recommended:
- **`relay-incident-response.md`** — what to do on `ALL_SOURCES_FAILED`. Includes user-facing comms template with the CIP-30 manual-claim instructions per RT-C-02.
- **`relay-key-rotation.md`** — how to rotate the operator wallet (24-word mnemonic at `/secrets/relay_operator_mnemonic.txt`) without service interruption. Pattern: deploy second pod with new wallet, wait for old pod’s in-flight to drain (idempotency cache TTL = 30 min), drop old pod.
- **`relay-mainnet-deploy.md`** — checklist that includes the `AEGIS_FEATURE_RELAY=1` toggle (per RT-C-01), `RELAY_SWEEPER_ENABLED=1` (per RT-C-04), `slot_skew_ms` gate active (per RT-C-10), per-IP rate limit (per RT-C-13).

### 5.3 Mainnet checklist gating `v8.0.0-relay-presigned-auth`

- [ ] **RT-C-01 closed:** `api.py:274` 503 replaced with live submit. Preprod e2e: create policy → close browser → wait for AegisSelf below-strike print → claim lands within 60s.
- [ ] **RT-C-04 closed:** `_submit_burn` implemented. Preprod sweep batch posts to Discord with at least 1 burn tx.
- [ ] **RT-C-06 verified:** Playwright assertion verifies BuyPanel modal shows the human-readable summary at sign time (per §10 spec acceptance).
- [ ] **RT-C-10 closed (or spec amended):** Either `slot_skew_ms` quorum is implemented, or the §3.1 spec text is updated to match "first-source-wins" reality.
- [ ] **RT-C-13 mitigation:** slowapi or Cloudflare rate-limit live on `/api/v1/claim`.
- [ ] CIP-30 manual-claim flow (RT-C-02) shipped in `AegisWalletPanel.tsx` Activity tab.
- [ ] Runbooks (5.2) drafted and stored in `D:/aegis-runbooks/`.

### 5.4 Mainnet-specific hardening (defer if needed)

- [ ] Redis-backed idempotency cache (RT-C-05) — defer to v8.1 if needed.
- [ ] Premium-floor in addition to coverage-floor (RT-C-03) — quick add.
- [ ] Multi-relay / second operator onboarded — F-6 spec deferral; positioning matter only. Document in `aegis-relay/README.md` how to clone-and-deploy.

---

## 6. Closing note

The v2 spec is **substantially stronger than the v1 design** and closes every red-team finding from rounds 1–6. The implemented Aiken validators, off-chain Python builders, and frontend encoders all carry the spec’s invariants byte-for-byte (the cross-stack CBOR vector tests are the verifying gate).

The findings here are NOT spec gaps — they are implementation-stage gaps and operational hardening opportunities. **Track C signs off on the v2 cryptographic + economic design**; the remaining work is Phase 5 → Phase 6 wiring (RT-C-01, RT-C-04) and operator-runbook discipline (RT-C-02, RT-C-13).

For mainnet ship, **RT-C-01 is the only true blocker.** RT-C-02 should land in the same release for trust-narrative consistency. The rest can ship as a v8.1 hardening pass.

— Track-C red-team, 2026-05-06
