# Auditor notification — Aegis V12 multi-pair oracle allowlist + protocol-fee mechanism (preprod, 2026-05-11)

## Subject line

> Aegis V12: AegisSelf single-NFT pin generalised to a 5-NFT allowlist + protocol-fee extraction mechanism — same trust anchor, multi-pair coverage, team+partner fees pinned at compile time (preprod only, mainnet gated on your sign-off)

---

## Body (paste into email/Slack to auditor)

> Hi [auditor name],
>
> Status update on the Aegis engagement. We are preparing the V12 validator deploy, which now ships **TWO coordinated trust-anchor rotations** under a single audit pass:
>
> **(a) AegisSelf NFT allowlist widening** — generalises the round-6 single-NFT pin (A-026 / A-027) to a closed five-element allowlist, one NFT per supported pair (ADA/USD, BTC/USD, ETH/USD, USDC/USD, USDT/USD). This is the original V12 scope; preserves the round-6 trust anchor unchanged (5-element set is set-theoretically equivalent to the 1-element pin under round-6's invariants).
>
> **(b) Protocol-fee extraction mechanism** — V11 contracts have NO path to collect the 2% `protocol_fee_bps` to the team (the 2% currently sits as phantom lovelace in the pool, unreachable by team OR LPs). V12 adds a compile-time-pinned team address (per-network constant in `types.ak`) plus an optional caller-supplied partner address (capped at 20% of fee), enforced by Underwrite + AcceptCancellation + BatchUnderwrite validator outputs. The Conway-era 0.5% treasury donation is unchanged.
>
> Both changes rotate the trust anchors simultaneously. Operator elected to fix them together under a single deploy radius because the validator hashes rotate for both regardless. We'd appreciate your read on both before we mainnet-rotate.
>
> **Operator-locked decisions since the original V12 design doc (please review the diff in §3.5, §3.8, §3.9, §3.10):**
>
> * **D7 — Min-utxo floor with submitter-paid pad.** Each fee output (team and partner, on BOTH Underwrite and AcceptCancellation, AND on BatchUnderwrite per-policy) must satisfy `output_lovelace >= max(min_utxo_lovelace = 2 ADA, calculated_cut)`. The submitter's wallet pays the floor pad (Conway `treasury_donation`-style submitter-source pattern). Pool accounting decoupled from floor pads (pool grows by `net_premium`, percentage-calculated, NOT minus floored amounts).
> * **D8 — AcceptCancellation B2 confirmed.** Cancel-time team cut applied to the 10% cancellation_fee retention, NOT to the original premium. Cumulative per-policy team take = 2 ADA (Underwrite) + 0.2 ADA (Cancel) = 2.2 ADA for a 100-ADA policy. Canceller pays the cancel-time floor pad.
> * **D9 — Full base-address pin confirmed.** `team_address` Aiken constant is the **full 56-byte base address** (payment_vkh + stake_vkh) via smart-constructor form. Rotation requires new validator deploy. Operator chose this over payment-credential-only equality to close the "same-payment-but-different-stake" exfil surface.
> * **D10 — BatchUnderwrite IN SCOPE for V12.** V12 ships the on-chain validator branch AND the off-chain `build_batch_underwrite_tx` correct. UI deferred to V12.1, but no validator redeploy when the UI lands. **This is your primary focus** — the most complex V12 branch.
>
> **TL;DR for scope:**
>
> - Aiken file diffs touch FIVE files (was 2 in pre-revision-2): `types.ak`, `oracle/aegis_self.ak`, `oracle.ak`, `pricing.ak`, `validators/pool.ak`. Roughly 250 lines changed across the five (vs ~18 in the NFT-only diff).
> - All four validator hashes rotate (policy + pool + lp_token + pool_nft) — same rotation pattern as round 6.
> - **Preprod only at this stage.** Mainnet deploy is gated on your sign-off.
> - **NFT allowlist** scope: no new redeemers, no new datum fields, no new sum-type variants. `expect oracle_nft == constant` → `expect list.has(constant_list, oracle_nft)`.
> - **Protocol-fee** scope: TWO new fields on `PolicyDatum` (`partner_address: Option<Address>`, `partner_share_bps: Int`); TWO new compile-time constants in `types.ak` (`team_address` per-network, `partner_share_cap_bps`); ONE new helper in `pricing.ak` (`calculate_protocol_fee_split`); Underwrite/AcceptCancellation/BatchUnderwrite branches in `pool.ak` add team/partner output checks and change the pool-continuation invariant from `+ premium` to `+ net_premium`.
> - V11's 4 preprod test policies (~97 ADA combined premium) stay claimable via raw CLI against the V11 validator hash. Hard-cut from the dApp UI; operator-controlled wallets only.
> - V11 → V12 user-visible fee goes from 0.5% (Cardano treasury only — the 2% protocol fee was phantom-stuck in V11) to 2.5% (2% team + 0.5% Cardano). This is the first version where the team actually collects revenue. Deliberate, operator-blessed change.
>
> **Files changed in V12 (5 files in Wave 2 PR):**
>
> ```
> contracts/lib/aegis/types.ak                       (NFT allowlist: 1 constant replaced; 5 hex literals added.
>                                                     Protocol fee: 2 new constants — team_address[_preprod/_mainnet] + partner_share_cap_bps;
>                                                     PolicyDatum gains 2 new fields — partner_address: Option<Address>, partner_share_bps: Int)
> contracts/lib/aegis/oracle/aegis_self.ak           (1 line: expect oracle_nft == ... -> expect list.has(..., oracle_nft); 1 comment block updated)
> contracts/lib/aegis/oracle.ak                      (canonical_oracle_nft AegisSelf branch returns List for the new list-based check)
> contracts/lib/aegis/pricing.ak                     (new helper calculate_protocol_fee_split returning (team_cut, partner_cut))
> contracts/validators/pool.ak                       (Underwrite: pool value invariant flips from `+ premium` to `+ net_premium`;
>                                                     adds team + optional partner output checks with 2-ADA min-utxo floor (D7);
>                                                     partner_share_bps cap + consistency checks.
>                                                     AcceptCancellation: adds team + optional partner cuts from the 10% cancellation fee retention (B2 / D8);
>                                                     same min-utxo floor mechanic; canceller wallet pays the pad.
>                                                     BatchUnderwrite: per-policy floor before aggregation, single team output for entire batch,
>                                                     consolidated per-unique-partner outputs. Helper `batch_policies_match_totals_v12` returns
>                                                     `(cov_sum, prem_sum, funded_ok, team_total, partner_totals, shares_ok)`.
>                                                     Full V12-on-chain-complete + V12-off-chain-complete + V12.1-UI-wired per D10.)
> ```
>
> Plus Aiken test additions: ~39 new tests total (8 NFT-allowlist + 31 protocol-fee-mechanism). The full breakdown is in §10.1 + §10.4 of the design doc.
>
> **What we'd most like your eyes on:**
>
> **NFT allowlist scope:**
>
> 1. **The threat-model argument that 5-NFT allowlist == 1-NFT pin (set-theoretically equivalent under round-6's invariants).** Each of the 5 NFTs is (a) `quantity: 1` permanent, (b) minted under a one-shot mint policy whose authority UTxO has been consumed, (c) lands at the same canonical publisher VKH (`6096332c3f9c18805fdb1d189b74d54497049ffb254659cd45622152`). The on-chain `find_feed_output` still requires the UTxO's payment credential to equal `aegis_self_publisher_vkh`, so the second trust leg gates all 5 NFTs equally. The only set-theoretic change is the canonical set's cardinality (5 vs 1). We believe this preserves the A-026 trust anchor exactly; please confirm.
> 2. **`PolicyDatum.oracle_nft` immutability.** A given policy's `oracle_nft` is frozen at Underwrite time. So a BTC-bound policy can only ever claim against the BTC feed, an ADA-bound policy can only ever claim against the ADA feed. There is no cross-pair contamination. This is the same immutability argument as v6's `oracle_provider`, extended to `oracle_nft`. Please confirm the per-policy binding semantics hold.
> 3. **Validator hash rotation pattern.** Because `types.ak` is imported by both validators, both hashes rotate (and `lp_token_policy` + `pool_nft_policy` chain off the new pool hash). This is identical to the round-6 rotation pattern; new values are TBD until Aiken build (rotation table below).
>
> **Protocol-fee mechanism scope:**
>
> 4. **`team_address` compile-time pin (`types.ak`).** The team_address Aiken constants are full `Address` records (payment_credential + stake_credential), pinned per-network. Operator-confirmed bech32 values:
>    * Preprod: `addr_test1qrph8epfa8dg6wjwmls873g0xllyjnlt3hh08nv9kcrw9ln40ur83k9c87dpxuar3jucqrg0sc54zvzmf53pu6due2eqa5m8d2` — payment VKH `c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe`, stake VKH `757f0678d8b83f9a1373a38cb9800d0f862951305b4d221e69bccab2`
>    * Mainnet: `addr1q9s6m9d8yedfcf53yhq5j5zsg0s58wpzamwexrxpfelgz2wgk0s9l9fqc93tyc8zu4z7hp9dlska2kew9trdg8nscjcq3sk5s3` — payment VKH `61ad95a7265a9c269125c149505043e143b822eedd930cc14e7e8129`, stake VKH `c8b3e05f9520c162b260e2e545eb84adfc2dd55b2e2ac6d41e70c4b0`
>    Decoded via `docs/architecture/_decode_addresses.py` (manual bech32 decode + CIP-19 base-address split; the script is in the repo so you can re-run to confirm the bytes). Please confirm the decoded VKHs match what you'd compute independently.
>
> 5. **`partner_share_cap_bps = 2000` enforcement.** Compile-time constant. The Underwrite, AcceptCancellation, and BatchUnderwrite branches each reject `PolicyDatum.partner_share_bps > 2000` AND `partner_share_bps < 0` AND `partner_share_bps > 0 with partner_address == None`. Please verify the cap is enforced in ALL three branches, not just Underwrite.
>
> 6. **Per-100-ADA-premium math (solo policy).** 98 ADA → pool (was 100 in V11), 2 ADA → team_address output (was phantom in V11), 0.5 ADA → Cardano treasury via Conway donation (unchanged). Please trace the math against the validator logic — specifically verify the Underwrite pool-value invariant flipped from `cont_pool == old_pool + premium` (V11) to `+ net_premium` (V12) and the team output is a required output, not optional.
>
> 7. **Per-100-ADA-premium math (partner @ 20% cap).** 98 ADA → pool, 1.6 ADA → team, 0.4 ADA → partner_address, 0.5 ADA → Cardano treasury. Same submitter cost, same user-visible 2.5% fee.
>
> 8. **AcceptCancellation cancel-fee split (B2 choice, operator-CONFIRMED).** V12 applies the same 2%/0.5% split to the 10% cancellation_fee retention, NOT to the original premium. So per 100-ADA cancelled policy: refund 90 ADA → insured, team_cut from cancel = `0.02 * 0.1 * 100 = 0.2 ADA`, treasury_cut from cancel = `0.005 * 0.1 * 100 = 0.05 ADA`, pool retains `9.8 ADA` of the cancellation fee after team takes 0.2 (solo case). The per-policy team take is `2 ADA (Underwrite) + 0.2 ADA (cancel) = 2.2 ADA` cumulative. **Operator confirmed B2 in the V12 second-pass handoff (decision D8).** The §3.9 design doc has the full comparison and rationale.
>
> 8a. **Min-utxo floor mechanic (D7, operator-CONFIRMED).** Each fee output (team and partner, on BOTH Underwrite and AcceptCancellation) must satisfy `output_lovelace >= max(min_utxo_lovelace, calculated_cut)`. When the percentage-calculated cut is below the 2-ADA floor, the **submitter's wallet pays the floor-pad subsidy** — exactly the same submitter-source pattern V11 already uses for the Conway `treasury_donation` field (sourced from submitter inputs, not the pool, not the premium). The pool's `total_liquidity` and physical lovelace both still grow by exactly `net_premium = premium - calculated_team_cut - calculated_partner_cut` (NOT minus the floored amounts).
>
> Math walkthroughs:
>
> | Scenario | calculated team cut | floor pad | calculated partner cut | floor pad | Cardano donation | **Submitter pays** |
> |---|---|---|---|---|---|---|
> | 100-ADA premium, 20% partner | 1.6 ADA | +0.4 ADA | 0.4 ADA | +1.6 ADA | 0.5 ADA | **102.5 ADA** |
> | 200-ADA premium, no partner | 4 ADA | 0 (no pad) | n/a | n/a | 1 ADA | **201 ADA** |
> | 50-ADA premium, no partner | 1 ADA | +1 ADA | n/a | n/a | 0.25 ADA | **51.25 ADA** |
> | 100-ADA premium, no partner | 2 ADA | 0 (exactly at floor) | n/a | n/a | 0.5 ADA | **100.5 ADA** |
>
> For AcceptCancellation on a 100-ADA cancelled policy (no partner): cancel-time team_cut = 0.2 ADA, floor pad = 1.8 ADA, canceller wallet pays the 1.8 ADA pad. Pool decreases by exactly `90 + 0.2 = 90.2 ADA` (unfloored math). LP keeps 9.8 ADA of the 10% retention.
>
> Please confirm: (a) the floor-pad math produces clean tx-builder behavior with no edge cases where the submitter is double-charged, (b) the submitter-source pad pattern is sound (no surface for the canceller to under-pay the pad), and (c) the pool's value invariant (`net_premium` percentage-calculated, not floor-padded) is correctly decoupled from the per-output floor checks.
>
> 8b. **Full base-address pin (D9, operator-CONFIRMED).** The Aiken `team_address_preprod` / `team_address_mainnet` constants pin the **full 56-byte base address** (28-byte payment_vkh + 28-byte stake_vkh) at compile time using the smart-constructor form (`from_verification_key |> with_delegation_key`). Rotation = new validator hash = new deploy. The operator explicitly chose full-address pinning over payment-credential-only equality to close the "same-payment-but-different-stake" exfiltration shape. Operational consequence: an operator who delegates the team wallet to a new stake pool MUST rebuild and redeploy. Decoded VKH bytes (verbatim from `docs/architecture/_decode_addresses.py`, pinned in §3.5 of the design doc):
>
> * Preprod: payment `c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe`, stake `757f0678d8b83f9a1373a38cb9800d0f862951305b4d221e69bccab2`
> * Mainnet: payment `61ad95a7265a9c269125c149505043e143b822eedd930cc14e7e8129`, stake `c8b3e05f9520c162b260e2e545eb84adfc2dd55b2e2ac6d41e70c4b0`
>
> 8c. **BatchUnderwrite is in scope for V12 (D10, operator-NEW).** The original V12 brief tagged BatchUnderwrite as fee-bypass-prevention only (validator must be self-consistent, off-chain wiring deferrable). Per operator decision D10, BatchUnderwrite ships V12-on-chain-complete + V12-off-chain-complete (UI deferred to V12.1, no validator redeploy required when UI lands). **This is the auditor's primary focus** — BatchUnderwrite is the most complex V12 branch because it aggregates per-policy fee data across N policies. Critical design decisions resolved in §3.10 of the design doc:
>
> * **Per-policy floor** applied individually before summing. A 5-policy batch with `team_cut_i = 1.6 ADA` each requires team output `>= 5 × 2 = 10 ADA`, NOT `>= max(min_utxo, 8) = 8 ADA`. Sum-then-floor accounting is a fee-bypass attack surface.
> * **Single aggregated team output** for the entire batch (sum of per-policy floored team cuts).
> * **Consolidated per-unique-partner outputs** — if 5 policies share `partner_address = X`, the tx emits ONE consolidated partner_X output `>= sum of 5 floored partner cuts`. If they differ, N partner outputs (one per unique address).
> * **Mixed partner / no-partner batches** — per-policy enforcement: each policy independently passes the standard `partner_address ↔ partner_share_bps` consistency check.
>
> Worked 5-policy example with mixed partners (3 solo + 1 partner_X @ 20% + 1 partner_Y @ 20%, all 100-ADA premium):
>
> | Policy | premium | partner | team_cut floored | partner_cut floored |
> |---|---|---|---|---|
> | 1 | 100 | None | 2 ADA | n/a |
> | 2 | 100 | None | 2 ADA | n/a |
> | 3 | 100 | None | 2 ADA | n/a |
> | 4 | 100 | Some(X) | 2 ADA | 2 ADA |
> | 5 | 100 | Some(Y) | 2 ADA | 2 ADA |
>
> Required outputs: 10 ADA → team_address, 2 ADA → partner_X, 2 ADA → partner_Y. Pool grows by `total_premium − Σ team_cut_i (unfloored) − Σ partner_cut_i (unfloored) = 500 − 9.2 − 0.8 = 490 ADA`. Submitter pays `500 + (10 − 9.2) + (2 − 0.4) + (2 − 0.4) + 2.5 (treasury donation) = 506.5 ADA`.
>
> Please trace this 5-policy batch through the V12 validator manually (using the §3.10 spec) and confirm: (a) the aggregated-output semantics match the per-policy invariants, (b) the per-policy floor convention closes the sum-then-floor fee-bypass surface, (c) the pool's value invariant uses the unfloored cut sums, (d) the floor pads are sourced exclusively from the submitter's inputs.
>
> 9. **V11 vs V12 backwards-incompatibility (intentional).** V11's `PolicyDatum` has 11 positional fields (v5's 10 fields + v6's `oracle_provider` append). V12 appends 2 more (`partner_address`, `partner_share_bps`) for 13 total. V11 policy UTxOs cannot decode under the V12 schema; they're stranded at the V11 validator hash and recovered via raw-CLI claim/expire/cancel against the V11 reference scripts (which stay on chain). This is the hard-cut cutover described in §9 of the design doc. Please confirm the cutover semantics are sound.
>
> 10. **Caller-supplied `partner_address` trust model.** `PolicyDatum.partner_address` is set by the policy creator at Underwrite time. Anyone can set any address. A caller setting an attacker-controlled address is **self-pwning** (diverting their own fees away from the team into a wallet they don't control); the protocol incurs no risk. Please sign off on this trust model — specifically, that the validator does NOT need to verify the partner_address belongs to a registered partner.
>
> **Threat-model bullets (canonical 5-NFT set properties):**
>
> - Each of the 5 NFTs is a one-shot mint with `quantity: 1` permanent. Re-minting under any of the 5 policy ids is mathematically impossible because each policy's authorising init UTxO has been spent. Burns leave quantity zero but a fresh mint cannot occur.
> - All 5 NFTs were minted by the canonical publisher's signing key. Mint authority for each NFT is the consumed init UTxO of `pool_nft.ak`, not the signing key per se. So a future publisher-key compromise does NOT permit re-minting under any of the 5 policy ids.
> - An attacker forging a fake NFT under a non-allowlisted policy still fails the V12 parser's `expect list.has(aegis_self_canonical_nfts, oracle_nft)` check. Sixth-policy NFTs are rejected before the payment-credential check even runs (same fail-fast order as round 6).
> - An attacker compromising the publisher VKH is bounded by what the publisher could already do today: sign stale prices. V12 does not widen this attack surface — the publisher service still gates publish authority on the same key, and the validator's freshness gate (`tx_lower <= valid_until`) still requires the datum's per-publish `expiry` field to be unexpired.
> - The set is closed at compile time. Adding a sixth NFT requires a `types.ak` constant rotation + validator rebuild + redeploy + visible hash rotation. There is no runtime path (validator parameter, redeemer field, governance datum) that can extend the allowlist.
> - The Aiken `list.has` function is already used in `aegis_self.ak:54` (against `assets.policies(input.output.value)`) and is the same primitive used by `validation.ak::output_has_nft` at line 210. We are not introducing a new stdlib dependency.
>
> **Validator hash rotation table** (TBD until Aiken build; populated in Wave 2):
>
> | Hash | V11 (preprod) | V12 (preprod) |
> |---|---|---|
> | `policy_validator` | `8fe45e44339417ad27ca6cd1662d771a0c224fc0052189647321a3f5` | TBD |
> | `pool_validator` | `41cc5c53a899a9b69d62f2a946c17285203b32f9a373b0eeaf09650f` | TBD |
> | `lp_token_policy` | `cd8048bf0d926c65a8b9422106aab8ff48c2c1eb24b27c04044ec004` | TBD |
> | `pool_nft_policy` | (operator-set per init UTxO) | TBD (Wave 4) |
>
> Rotation is unapplied on preprod pending your initial read. Mainnet rotation is gated on your explicit sign-off.
>
> **Reference materials:**
>
> - Design doc (full architectural spec, revision 2): [`docs/v12_validator_upgrade.md`](../v12_validator_upgrade.md) — NFT allowlist scope at Sections 2-3.4 + 5.1-5.7 + 6.1-6.4; protocol-fee mechanism scope at Sections 3.5-3.10 + 5.8-5.9 + 6.5 + 10.4-10.6 + 13.1 + 14. Section 4 (hash rotation), Section 10 (test plan), Section 11 (rollout) span both scopes.
> - Address-decode script (kept in repo for reproducibility): [`docs/architecture/_decode_addresses.py`](../architecture/_decode_addresses.py) — bech32 → (payment_vkh, stake_vkh) for the operator's preprod and mainnet addresses; auditor can re-run to confirm the §3.5 hex bytes.
> - Branch: `feat/v12-multi-pair-oracle` (parent commit `c57a568` on staging).
> - Public repo (push pending before this email goes out — see send checklist): https://github.com/Flux-Point-Studios/aegis-contracts
> - Round-6 audit notes that V12 generalises: [`docs/audit/SECURITY_AUDIT_REPORT.md`](../audit/SECURITY_AUDIT_REPORT.md) round 6 section.
> - Round-6 auditor email (for context on the original A-026 / A-027 fixes): [`docs/communications/AUDITOR_NOTIFY_REDTEAM6_2026-05-04.md`](AUDITOR_NOTIFY_REDTEAM6_2026-05-04.md).
>
> Happy to walk through both scopes on a call if useful — the NFT allowlist diff is small but the "5 == 1, just bigger" claim deserves narration end-to-end, and the protocol-fee mechanism is a coordinated diff across 4 Aiken files. Otherwise let us know if V12 changes your timeline; preprod deploy is locked behind your initial read.
>
> Thanks,
> — deci / Flux Point Studios

---

## What we'd like reviewed

### NFT allowlist scope

- [ ] **Diff in `contracts/lib/aegis/types.ak` (NFT scope)** — replaces `aegis_self_nft_policy: ByteArray` (1 hex literal) with `aegis_self_canonical_nfts: List<ByteArray>` (5 hex literals). 5 hex strings are quoted in Section 3.1 of the design doc; confirm each is 28 bytes and corresponds to a one-shot mint at the canonical publisher VKH.
- [ ] **Diff in `contracts/lib/aegis/oracle/aegis_self.ak`** — single line at line 83 flips `expect oracle_nft == aegis_types.aegis_self_nft_policy` to `expect list.has(aegis_types.aegis_self_canonical_nfts, oracle_nft)`. Updated comment block immediately above explains the generalisation in-line.
- [ ] **Diff in `contracts/lib/aegis/oracle.ak`** — `canonical_oracle_nft` for the `AegisSelf` provider becomes a list-returning dispatch, and the call sites in `validators/pool.ak` (lines 124-125, 205-206) flip from `==` equality to `list.has`.
- [ ] **Per-policy binding immutability** — confirm `PolicyDatum.oracle_nft` is frozen at Underwrite time and remains the trust handshake the insured agreed to at premium-payment time.
- [ ] **Validator hash rotation** — once Wave 2 produces fresh hashes, confirm the new policy + pool + lp_token + pool_nft hashes are consistent across `plutus.json`.

### Protocol-fee mechanism scope

- [ ] **`team_address` compile-time pin in `types.ak`** — confirm the bech32 addresses decode to the operator-confirmed payment+stake VKH pair below (re-decode via `docs/architecture/_decode_addresses.py` to verify):
  - Preprod: `addr_test1qrph8epfa8dg6wjwmls873g0xllyjnlt3hh08nv9kcrw9ln40ur83k9c87dpxuar3jucqrg0sc54zvzmf53pu6due2eqa5m8d2` → payment VKH `c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe`, stake VKH `757f0678d8b83f9a1373a38cb9800d0f862951305b4d221e69bccab2`
  - Mainnet: `addr1q9s6m9d8yedfcf53yhq5j5zsg0s58wpzamwexrxpfelgz2wgk0s9l9fqc93tyc8zu4z7hp9dlska2kew9trdg8nscjcq3sk5s3` → payment VKH `61ad95a7265a9c269125c149505043e143b822eedd930cc14e7e8129`, stake VKH `c8b3e05f9520c162b260e2e545eb84adfc2dd55b2e2ac6d41e70c4b0`
- [ ] **Verify `partner_share_cap_bps = 2000` enforcement** in:
  - [ ] Underwrite branch (`pool.ak`)
  - [ ] AcceptCancellation branch (`pool.ak`)
  - [ ] BatchUnderwrite branch (`pool.ak`)
- [ ] **`partner_share_bps` consistency checks** (in all three fee-bearing branches): reject `partner_share_bps < 0`, reject `partner_share_bps > 2000`, reject `partner_share_bps > 0 with partner_address == None`.
- [ ] **Trace the per-100-ADA-premium math** (solo policy): 98 ADA → pool, 2 ADA → team_address output, 0.5 ADA → Cardano treasury via Conway. Confirm the new Underwrite invariant is `cont_pool == old_pool + net_premium` (not `+ premium`) and that the team output is a HARD required output (`list.any(...)` check, not optional).
- [ ] **Trace the per-100-ADA-premium math** (partner @ 20%): 98 ADA → pool, 1.6 ADA → team, 0.4 ADA → partner_address output, 0.5 ADA → Cardano treasury. Confirm the partner output is conditionally required (only when `partner_address == Some(_)` and `partner_share_bps > 0`).
- [ ] **AcceptCancellation cancel-fee split (B2 choice, operator-CONFIRMED via D8)** — confirm the 2%/0.5% split is applied to `cancellation_fee = 0.1 * premium`, NOT to the original premium. So team_cut on cancel = `0.02 * cancellation_fee = 0.002 * premium`. Pool continuation invariant flips to `cont_pool == old_pool - refund - team_cut - partner_cut` (V11 was `- refund` only). Same per-output 2-ADA floor applies as Underwrite — canceller wallet pays the floor pad.
- [ ] **Min-utxo floor mechanic (D7)** — confirm the floor-pad math produces clean tx-builder behavior with no edge cases where the submitter is double-charged. Specific scenarios to trace:
  - [ ] 50-ADA solo policy (team_cut = 1 ADA, pad = 1 ADA, submitter pays 51.25 ADA total)
  - [ ] 100-ADA partner @ 20% (team pad 0.4, partner pad 1.6, submitter pays 102.5 ADA total)
  - [ ] 200-ADA solo policy (team_cut = 4 ADA above floor, no pad, submitter pays 201 ADA total)
  - [ ] 100-ADA cancel (cancel-time team_cut = 0.2 ADA, pad = 1.8 ADA from canceller; pool decreases by exactly 90.2 ADA)
  - [ ] Confirm pool's `value_ok` invariant uses percentage-calculated cuts (NOT floored amounts) — pool accounting is decoupled from floor pads.
  - [ ] Confirm no edge case where a malformed builder routes floor pad through the pool's inputs (would silently drain pool by the pad amount).
- [ ] **Full base-address pin (D9, operator-CONFIRMED)** — confirm the team_address constant is the **full 56-byte base address** (payment_vkh + stake_vkh) via the smart-constructor form (`from_verification_key |> with_delegation_key`). Validate that the validator's `out.address == team_address` check uses full structural Address equality, not just payment_credential equality. An attacker routing fees to `(payment=team_payment, stake=attacker_stake)` would otherwise exfiltrate the staking yield while satisfying a payment-only check.
- [ ] **BatchUnderwrite scope (D10, NEW V12 surface — primary auditor focus)** — confirm:
  - [ ] **Per-policy floor** before aggregation: a 5-policy batch with `team_cut_i = 1.6 ADA` each requires team output `>= 10 ADA` (5 × 2 ADA floored), NOT `>= 8 ADA` (sum-then-floor).
  - [ ] **Single aggregated team output** for entire batch (operator-blessed canonical builder shape).
  - [ ] **Consolidated per-unique-partner aggregated outputs** (one output per distinct partner_address ≥ sum of that partner's floored cuts).
  - [ ] **Per-policy partner_share_bps invariants** (cap, consistency, non-negativity) folded into the walker's `shares_ok` field — any policy violating fails the whole batch.
  - [ ] **Pool's value invariant** uses unfloored cut sums (`total_net = total_premium − Σ team_cut_i − Σ partner_cut_i`, percentage-calculated).
  - [ ] **Floor pads sourced exclusively from submitter inputs** (no path for the pool to subsidize pads).
  - [ ] Trace the 5-policy batch in §8c manually — confirm each of the 7 required outputs (1 team + 2 partners + pool continuation + treasury donation + change + submitter wallet bal) lands at the correct address with the correct lovelace.
  - [ ] Confirm `batch_policies_match_totals_v12` (§3.10.3) cannot be exploited via the partner_totals accumulator (e.g., colliding partner addresses, off-by-one in the `list.find` lookup).
  - [ ] Confirm BatchUnderwrite UI deferral (§11.1) does NOT create a validator/backend mismatch — backend `add_batch_protocol_fee_outputs` (§3.10.8) is V12-correct and pytest-covered.
- [ ] **Confirm V11 vs V12 backwards-incompatibility is intentional** — V11 13-field `PolicyDatum` cannot decode under V12 schema (with the new `partner_address: Option<Address>` and `partner_share_bps: Int` fields). Hard-cut cutover described in §9 of the design doc. V11 policies stranded at V11 validator hash with raw-CLI escape hatch.
- [ ] **Sign off on the caller-supplied `partner_address` trust model** — anyone can set any address; setting an attacker-controlled address is self-pwning (diverting the caller's own fees away from the team into an attacker's wallet) but is NOT a protocol risk. The validator does NOT verify the partner_address belongs to a registered partner.
- [ ] **V11 phantom-fee dilution surface** (informational) — V11's `pool.ak:343` enforces `cont_pool == old_pool + premium` while `verify_underwrite_datum` only credits `+ net_premium`. The 2% delta sat as "phantom" lovelace in the pool — uncounted in `total_liquidity`, unreachable by team OR LPs. V12 fixes this by changing the invariant to `+ net_premium` and routing the 2% to the team output. No active mitigation needed (V12 closes the surface); we flag this for your sign-off as a silent finding in V11 that V12 happens to close.

### Test plan coverage

- [ ] **NFT allowlist tests (Section 10.1):** 5 per-pair acceptance + 1 negative + 1 cardinality + 1 fixture-based spend-path = 8 tests.
- [ ] **Protocol-fee mechanism Aiken tests (Section 10.4):** 6 `pricing.ak` split tests + 3 `types.ak` constant tests + ~11 Underwrite tests + ~7 AcceptCancellation tests + 4 BatchUnderwrite tests = ~31 tests.
- [ ] **Backend tests (Section 10.5):** ~6 fee-split helper tests + ~7 build-endpoint tests + ~3 team-address resolver tests + ~3 cancel-policy fee tests = ~19 tests.
- [ ] **Frontend tests (Section 10.6):** ~2 v0 negative-coverage tests (assert no partner UI in BuyPanel).
- [ ] **E2E tx-hash smoke tests (Section 10.7):** 5 per-asset tx hashes + 1 fee-presence verification (assert team output present at `AEGIS_TEAM_ADDRESS_PREPROD` in a real preprod tx).

---

## Threat-model bullets (paste-ready for your write-up)

### NFT allowlist scope

1. **`quantity: 1` permanent per NFT.** All 5 NFTs are one-shot mints; their authorising init UTxOs have been consumed. Re-minting under any of the 5 policy ids is impossible — even with a publisher-key compromise — because the policy validator's mint branch requires the exact (already-spent) init UTxO ref in the consumed inputs.
2. **Mint keys discarded post-mint.** Mint authority for each NFT is the consumed init UTxO, not the signing key. The publisher signing key only authorises publishes (spend-and-roll the canonical UTxO forward), not mints.
3. **Closed compile-time set.** The 5 NFT policy ids are encoded as a `List<ByteArray>` constant in `lib/aegis/types.ak`. Adding a sixth NFT requires a validator-hash rotation; there is no runtime path (validator parameter, redeemer field, governance UTxO) to extend the allowlist.
4. **Forged-NFT attacker still rejected.** An attacker minting under their own permissive policy and outputting at the publisher VKH fails the `expect list.has(aegis_self_canonical_nfts, oracle_nft)` check — the attacker's policy id is not a list member. Same fail-fast order as round 6 (rejection before the payment-credential check runs).
5. **Publisher-key compromise bounded.** An attacker compromising the publisher signing key gains the same powers the publisher already has: spend-and-roll the 5 canonical UTxOs forward with adversarial price datums. V12 does not widen this surface. The validator's freshness gate (`tx_lower <= valid_until` against the datum's per-publish `expiry`) still constrains how stale a published price can be at claim time.
6. **Per-policy `oracle_nft` immutability.** `PolicyDatum.oracle_nft` is set at Underwrite time and frozen for the policy's lifetime. A BTC-bound policy reads BTC prices only; an ADA-bound policy reads ADA prices only. No cross-pair contamination; same immutability argument as v6's `oracle_provider` field.

### Protocol-fee mechanism scope

7. **Compile-time-pinned team address.** `team_address` is a full `Address` record (payment + stake credentials) pinned per-network in `types.ak`. An operator who could mutate the team address via datum could silently redirect fees mid-flight; pinning at compile time forces a visible redeploy + audit step on any rotation. Same security pattern as `treasury_share_bps` (also compile-time-pinned, line 283 of `types.ak`).
8. **Hard-required team output.** The Underwrite, AcceptCancellation, and BatchUnderwrite branches each enforce a `list.any(outputs, fn(out) { out.address == team_address && lovelace_of(out.value) >= team_cut })` check. The check uses FULL Address equality (payment + stake), not just payment_credential — so an attacker cannot exfiltrate fees by routing to a same-payment-but-different-stake address.
9. **Compile-time `partner_share_cap_bps = 2000`.** Maximum partner share is 20% of the protocol fee = 0.4% of premium. The validator rejects `PolicyDatum.partner_share_bps > 2000` AND `partner_share_bps < 0` AND `partner_share_bps > 0 with partner_address == None`. Floor on team revenue is 80% of fee = 1.6% of premium.
10. **Caller-supplied `partner_address` is self-pwn-only.** Anyone can set any address as partner. Setting an attacker-controlled address diverts the caller's OWN fees to an attacker's wallet — not a protocol risk. The validator does NOT verify the partner_address belongs to a registered partner. Trust model: integrators who care about partner integrity verify off-chain before signing.
11. **Per-policy `partner_address` and `partner_share_bps` immutability.** Both fields are part of `PolicyDatum` and frozen at Underwrite time. The cancel-time team/partner cut math uses the same values the user agreed to at premium-payment time. Same immutability argument as v6's `oracle_provider`.
12. **V11 phantom-fee surface, closed by V12.** V11's Underwrite enforces `cont_pool == old_pool + premium` while crediting only `+ net_premium` to `total_liquidity`. The 2% delta is unreachable by team OR LPs OR users — silently accumulating in the pool. V12 fixes this with `+ net_premium` and a required team output. No active V11 exploit (the phantom is just stuck lovelace), but V12 closes the visibility surface.
13. **Cancel-time fee scope (B2 design).** V12 applies the 2%/0.5% split to the 10% cancellation_fee retention, NOT the original premium. Per-policy team take is capped at 2% (Underwrite) + 0.2% (cancel) = 2.2% of premium maximum. LP cancel-yield curve matches V11 expectations minus a tiny per-event fee. ProcessClaim / Expire / BatchExpireProcess apply NO new fees (claim is the user's insurance payout; expire returns funds to the pool unchanged).

---

## Reference materials (full list)

- **Design doc:** `D:/aegis/docs/v12_validator_upgrade.md` (revision 2 — adds §3.5–§3.10, §5.8–§5.9, §6.5, §10.4–§10.6, §13.1, §14 for the protocol-fee mechanism)
- **Branch:** `feat/v12-multi-pair-oracle` (parent commit `c57a568`)
- **Aiken file 1 (current, V11):** `contracts/lib/aegis/types.ak` line 429-453 (`aegis_self_nft_policy` constant), line 93-135 (`PolicyDatum` schema)
- **Aiken file 2 (current, V11):** `contracts/lib/aegis/oracle/aegis_self.ak` line 75-83 (the `expect` pin)
- **Aiken file 3 (current, V11):** `contracts/lib/aegis/oracle.ak` line 96-102 (`canonical_oracle_nft` dispatch)
- **Aiken file 4 (current, V11):** `contracts/lib/aegis/pricing.ak` line 76-82 (`calculate_treasury_cut`, the model for the new fee split helper)
- **Aiken file 5 (current, V11):** `contracts/validators/pool.ak` line 295-384 (Underwrite branch), line 746-824 (AcceptCancellation branch), line 570-656 (BatchUnderwrite branch), line 172-231 (`policy_output_matches_underwrite`)
- **Bech32 decode tool:** `docs/architecture/_decode_addresses.py` — Python script that decodes the operator's preprod and mainnet bech32 addresses to (payment_vkh, stake_vkh). Auditor can re-run to confirm the bytes in §3.5 of the design doc.
- **Round-6 audit pass:** `docs/audit/SECURITY_AUDIT_REPORT.md` (round 6, 2026-05-04)
- **Round-6 auditor email:** `docs/communications/AUDITOR_NOTIFY_REDTEAM6_2026-05-04.md`
- **Public repo URL:** https://github.com/Flux-Point-Studios/aegis-contracts (push pending before send — see checklist)
- **Diff link (after push):** https://github.com/Flux-Point-Studios/aegis-contracts/compare/staging...feat/v12-multi-pair-oracle

---

## Send checklist

Run before pasting the body above into email:

- [ ] **Confirm auditor's preferred channel.** Email (`hever@...`) or Slack? Round 6 went via email; default to the same unless the auditor's last message asked for a channel change.
- [ ] **Push `feat/v12-multi-pair-oracle` to the public repo BEFORE sending** so the diff link resolves on the auditor's first click. Push command from `D:/aegis`:
  ```
  git push origin feat/v12-multi-pair-oracle
  ```
- [ ] **Verify the design doc path resolves on the public repo** (some auditors load the link in a sandbox that follows GitHub paths).
- [ ] **Sanitise 28-byte hex literals.** Double-check the 5 hex strings in the design doc Section 3.1 against the live preprod publisher base address `addr_test1qpsfvvev87wp3qzlmvw33xm564zfwpyllvj5vkwdg43zz5kr0wnh0wdqfaz5ydkgljysaj5lr9kzlqf4l7a2fpqalxjqn8s06k` UTxOs — a typo in any of the 5 strings silently turns into "no UTxO matches" at claim time and is the highest-risk surface in this design. Spot-check at least one (BTC/USD `ae304e27...d7bd`) against Blockfrost before sending.
- [ ] **Re-verify the team_address VKH decode** by running `python docs/architecture/_decode_addresses.py` from `D:/aegis`. Confirm output matches Section 3.5 of the design doc:
  - Preprod payment VKH: `c373e429e9da8d3a4edfe07f450f37fe494feb8deef3cd85b606e2fe`
  - Preprod stake VKH: `757f0678d8b83f9a1373a38cb9800d0f862951305b4d221e69bccab2`
  - Mainnet payment VKH: `61ad95a7265a9c269125c149505043e143b822eedd930cc14e7e8129`
  - Mainnet stake VKH: `c8b3e05f9520c162b260e2e545eb84adfc2dd55b2e2ac6d41e70c4b0`
  A typo in the team_address hex literals silently routes the team's fees to an attacker-controlled address on every Underwrite tx — same risk class as the NFT typo above. Highest-risk surface in the protocol-fee mechanism.
- [ ] **Insert auditor name** in the body (`Hi [auditor name],`).
- [ ] **CC** legal (per existing audit-engagement comms) and ops.
- [ ] **Subject line** — use the suggestion at the top of this doc; trim if the auditor's mail client truncates over 80 chars.
- [ ] **Send via** the same thread as round 6 if continuing a thread (rotation context preserved); new thread otherwise (so the auditor can prioritise V12 independently).
- [ ] **Post a Slack heads-up** to the operator channel (Flux Point ops) immediately after sending so the team is aware the auditor clock is now ticking.
