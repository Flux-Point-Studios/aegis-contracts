# Backend ↔ On-Chain Interaction

The off-chain backend (FastAPI server, monitoring bot, frontend, SDK) is **not in this audit's scope**. This document describes how that backend interacts with the validators in this repo, so the on-chain auditor can understand the trust boundary, what data flows in, what assumptions the contracts make about the off-chain side, and where validator invariants must hold even if the backend misbehaves.

## High-level flow

```
        ┌──────────────┐         build              ┌──────────────┐
        │ User browser │ ─────────────────────────▶ │   FastAPI    │
        │   (CIP-30)   │ ◀───── unsigned tx ──────  │  /build/...  │
        └──────┬───────┘         (CBOR)             └──────┬───────┘
               │ sign with CIP-30                          │
               │                                           │ (read-only)
               ▼                                           ▼
        ┌──────────────┐         submit           ┌──────────────┐
        │   Cardano    │ ◀─────────────────────── │  Blockfrost  │
        │   preprod    │ ◀───── /tx/submit ────── │   indexer    │
        └──────────────┘                          └──────────────┘
```

The backend is **stateless and key-less for user transactions**. It builds unsigned txs and returns CBOR; the user's CIP-30 wallet (or the in-browser non-custodial Aegis-wallet) signs; the signed CBOR is submitted via `POST /api/tx/submit` (a thin pass-through to Blockfrost or a node).

Operator-only paths (deploy, NFT mint, ref-script publish, init-pool) DO sign server-side, but those run only in `AEGIS_OPERATOR_MODE=1` against the operator's enterprise wallet — they are out of the user-facing surface and gated by an explicit env var.

## What the backend reads

- **Pool UTxO**: `query_utxos_at_address(POOL_SCRIPT_ADDRESS)`. Filtered by canonical pool NFT presence to identify the singleton.
- **Policy UTxOs**: `query_utxos_at_address(POLICY_SCRIPT_ADDRESS)`. Each parsed for its inline `PolicyDatum`.
- **Multi-oracle reference UTxO**: per the policy's `oracle_provider` (Charli3 / Orcfax / AegisSelf), the backend resolves the canonical reference-input UTxO and includes it in claim/cancel txs. For Charli3: `query_utxos_at_address(CHARLI3_ORACLE_ADDRESS)` filtered by `charli3_ada_usd_nft_policy`. For Orcfax: query the FSP UTxO at the per-network `orcfax_fsp_script_hash`, follow its pointer to the FS UTxO. For AegisSelf: query the publisher wallet's address, filter by `AEGIS_PRICE_FEED_V1` token, pick the freshest UTxO. The validator dispatcher (`aegis/oracle.resolve_oracle_price`) re-validates the trust handshake on chain regardless of how the backend selected the input.
- **User wallet UTxOs**: standard Cardano wallet queries via Blockfrost.

## What the backend writes (validator-mediated)

For every fee-bearing or stateful operation, the backend constructs a multi-validator tx that:

1. Consumes the **pool UTxO** as a script input with the appropriate pool redeemer (Underwrite / ProcessClaim / AddLiquidity / etc.).
2. For underwrite: appends a **policy output** at the policy_validator address with a hand-built `PolicyDatum`.
3. For claim/cancel/expire: also consumes the **policy UTxO** as a script input with the appropriate policy redeemer.
4. References the deployed validator scripts via CIP-33 `reference_inputs` (the validators are NOT inlined per-tx).
5. References the **provider-specific oracle UTxO(s)** via `reference_inputs` (read-only). Charli3 = single oracle UTxO; Orcfax = FSP + FS UTxO pair (FSP carries the pointer, FS carries the price datum); AegisSelf = single publisher UTxO. The validator dispatches on the policy's bound `oracle_provider`.
6. Sets `tx.treasury_donation` (CDDL key 22) to the calculated cut for fee-bearing flows.
7. Sets validity-range bounds (`validity_start = current_slot - 200`, `ttl = current_slot + 600`) so on-chain time invariants like A-015 hold.

The validator code in this repo is what makes ANY of these operations safe — the backend is a convenience layer, not a trust anchor.

## Specific backend modules and their on-chain effect

| Backend file | Calls into validators | Notes |
|---|---|---|
| `api/policies.py::create_policy` | pool.Underwrite | Builds a single-policy underwrite. Sets treasury_donation. |
| `api/policies.py::batch_underwrite` | pool.BatchUnderwrite | Multi-policy single-tx underwrite. Validator's `batch_policies_match_totals` enforces sum invariants. |
| `api/policies.py::claim_policy` | policy.Claim + pool.ProcessClaim | Co-spends one policy and the pool. Includes provider-specific oracle ref input(s). **[v6.0.2 / L-006]** `pool.ProcessClaim` redeemer no longer carries `policy_script` — backend constructor updated. |
| `api/policies.py::cancel_policy` | policy.Cancel + pool.AcceptCancellation | Same co-spend; oracle ref input used by policy.Cancel for the in-the-money guard. **[v6.0.2 / L-006]** `pool.AcceptCancellation` redeemer no longer carries `policy_script`. |
| `api/policies.py::batch_claim_chained` | policy.BatchClaim + pool.ProcessClaim | Aggregates multiple claims; validator A-012 enforces uniform `(oracle_provider, oracle_nft)` (generalized in v6 to span all providers, including AegisSelf). |
| `api/pool.py::add_liquidity` | pool.AddLiquidity + lp_token.MintLP | Mints aLP tokens proportional to deposit. |
| `api/pool.py::remove_liquidity` | pool.RemoveLiquidity + lp_token.BurnLP | Burns aLP, withdraws ADA. |
| `api/pool.py::init_pool` | (no script consumption) | Creates the bootstrap pool UTxO at the script address with the NFT. Operator-only. |
| `api/_donation_tx_builder.py::DonatingTxBuilder` | n/a — PyCardano wrapper | Subclass that injects `treasury_donation` into the body and overrides `_calc_change` so the donation is treated as an outflow. Required because PyCardano 0.19.2 doesn't account for donation in change calc. |

## Trust assumptions baked into the validators

The validators do NOT trust the backend. Specifically:

| Assumption | Enforced by |
|---|---|
| Pool's `active_coverage` only grows by the EXACT redeemer-coverage on Underwrite | `verify_underwrite_datum` (`lib/aegis/pool.ak`) |
| Pool's `total_liquidity` only grows by the EXACT net premium | same |
| Pool's lovelace only changes by the exact branch-specific delta | `value_ok` clauses in each branch (A-007) |
| Pool NFT must be carried in every continuation output | `find_canonical_pool_output` (A-008) |
| Policy datum is bound to the canonical pool | `pdat.pool_script_hash` + `pdat.pool_nft` checks |
| Policy output must be at the policy_validator script hash | A-021 / A-022 fix — pool validator parameterized over policy_script_hash |
| Exactly one policy output per Underwrite | A-025 fix — count-of-1 fold |
| Coverage + premium are positive | A-024 fix — explicit `> 0` guards |
| Coverage / premium ratio doesn't slip past 50× | A-014 fix — multiplication form |
| Policy `start_time` lies in tx validity range | A-015 fix — `start_time_in_tx_range` helper |
| Oracle reference input passes the per-provider trust handshake (canonical NFT pin AND credential pin) | A-016 (Charli3 script-hash binding) + Round-6 NFT-pin extension; A-026 (AegisSelf two-layer); A-027 (Orcfax FSP script hash); enforced by `oracle/{charli3,orcfax,aegis_self}.ak` parsers + Underwrite-time `pdat.oracle_nft == canonical_oracle_nft(pdat.oracle_provider)` |
| Treasury donation matches the protocol-fee-derived cut | A-021 (donation feature) — `donation_ok` clauses on three pool branches |
| Payouts go to enterprise addresses (no stake credential) | A-009 — `sum_lovelace_to_enterprise_pkh` |
| Single canonical pool exists | A-011 — one-shot NFT mint policy |

If the backend ever builds a tx that violates ANY of these, the validator rejects it. The whole audit philosophy is: **the validators are the single source of truth; off-chain code is a convenience layer that the validators distrust by default.**

## What the backend assumes about the validator (for failure modes)

The backend does pre-flight checks (e.g., "is the pool solvent?", "is the oracle fresh?") to give users meaningful errors before submission. These pre-flights mirror the validator's checks. If a pre-flight passes but the validator rejects, that's either:
- A backend bug (the pre-flight is laxer than the validator) — backend should be tightened.
- A race condition (state changed between pre-flight and submit) — backend retries.
- An adversarial tx — should not happen via the API since the API only builds canonical txs.

## Operator-mode entry points

The `offchain/scripts/` (mirrored in this repo at `deploy/scripts/`) contains operator-only scripts gated by `AEGIS_OPERATOR_MODE=1`:

- `mint_pool_nft.py` — one-shot mint of the canonical pool NFT.
- `publish_refs.py` — publishes the three reference-script UTxOs at the operator's enterprise address.
- `init_pool.py` — creates the bootstrap pool UTxO at the pool script address.

These run with the operator's signing key (loaded from a path set via the `AEGIS_OPERATOR_WALLET_PATH` env var, pointing at a BIP-39 mnemonic file kept outside the repository). They cannot be triggered by users; the operator runs them once per deployment.

## What's NOT enforced on-chain (auditor watch list)

- **Premium pricing model**: the actuarial calculation (base rate × duration multiplier × utilization factor) lives in `api/policies.py`. The validator only enforces `is_premium_adequate` (premium >= min, ratio acceptable). A backend bug could quote a too-low premium that the validator still accepts. Risk surface: backend.
- **Oracle price reading from datum**: the per-provider parsers under `oracle/` extract the price from each provider's datum format. We trust each provider's datum schema for the policies that bind to them. If a provider changes their schema, our parser breaks for THAT provider only — policies bound to the other two providers continue working. Mitigation: pin every provider's canonical handle by validator hash (A-016 + Round-6 NFT pin for Charli3; A-027 for Orcfax FSP script hash; A-026 for the AegisSelf publisher VKH and NFT policy id) so a provider-side redeploy forces an Aegis redeploy and surfaces the change in the chain log.
- **CIP-30 wallet correctness**: the user trusts their wallet to display the tx body honestly. Out of scope for on-chain audit.
- **Time accuracy**: the validator uses `validity_range` POSIX bounds, which derive from slot numbers via the ledger's slot→time mapping. Off-chain code converts between slots and POSIX manually. A miscalibration there would create policies whose start_time doesn't match wall-clock. Risk surface: backend.

The off-chain audit (A-017, planned separately) will cover these surfaces.
