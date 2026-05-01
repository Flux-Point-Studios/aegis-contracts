# Operator Deploy Runbook

These scripts run **once per deployment version** to publish the validators on Cardano preprod (or mainnet, with the appropriate config). They consume the operator's wallet and produce the deploy state under [`deploy-state.preprod.json`](deploy-state.preprod.json).

For the auditor: these scripts are NOT in the live transaction path for end users. They run only when the operator does a fresh deploy. Their correctness affects the trust model (e.g., one-shot pool NFT replay, parameterization order) but they do NOT sign user-facing txs.

## Pre-requisites

- Python 3.11+
- `pycardano==0.19.2` or compatible
- `cbor2`
- `aiken` CLI (for blueprint parameterization)
- A Cardano preprod wallet with at least 50 ADA (covers ref-script publish + min-UTxO bootstrap + fees).
- Blockfrost preprod project key.

## Environment

The scripts read these env vars (none committed; see private operator config):

```bash
AEGIS_OPERATOR_MODE=1                           # gates against accidental runs
AEGIS_OPERATOR_WALLET_PATH=/path/to/mnemonic    # 24-word mnemonic file (NEVER commit)
BLOCKFROST_KEY=preprod...                       # Blockfrost project id
BLOCKFROST_BASE_URL=https://cardano-preprod.blockfrost.io/api
```

## Run order

1. **`mint_pool_nft.py`** — one-shot mint of the canonical pool NFT, parameterized over an operator-chosen init UTxO and a token name (e.g., `AEGIS_POOL_VN`). Once the init UTxO is consumed, no second NFT can ever be minted under that policy id (A-011).

   ```bash
   AEGIS_OPERATOR_MODE=1 python -m offchain.scripts.mint_pool_nft \
     --token-name AEGIS_POOL_V6 --submit
   ```

2. **`publish_refs.py`** — publishes the three validator scripts as CIP-33 reference UTxOs at the operator's enterprise address. Applies the parameterization cascade:
   - `pool_validator` ← `policy_script_hash`
   - `lp_token_policy` ← (post-application) `pool_script_hash`

   ```bash
   AEGIS_OPERATOR_MODE=1 python -m offchain.scripts.publish_refs \
     --submit --wait-between-txs 90
   ```

3. **`init_pool.py`** — creates the bootstrap pool UTxO at the (now parameterized) pool script address, locks the pool NFT into it with an inline `PoolDatum` (total_liquidity=0, active_coverage=0, lp_supply=0).

   ```bash
   AEGIS_OPERATOR_MODE=1 python -m offchain.scripts.init_pool --submit
   ```

After all three succeed, [`deploy-state.preprod.json`](deploy-state.preprod.json) is fully populated. The pool is ready for end users to AddLiquidity, Underwrite policies, etc.

## What's in deploy-state.preprod.json

The file records the live deploy artifacts:

```json
{
  "network": "preprod",
  "version": "v5-a025",
  "previous_version": "configs/deploy-state.preprod.v4.json",
  "steps": {
    "mint_pool_nft": {
      "policy_id": "...",       // canonical pool NFT policy id
      "asset_name_ascii": "AEGIS_POOL_V6",
      "tx_hash": "...",
      "init_utxo": "...#N"
    },
    "publish_refs": {
      "results": [
        { "label": "policy_validator", "ref_utxo_id": "...", "script_hash": "..." },
        { "label": "pool_validator",   "ref_utxo_id": "...", "script_hash": "..." },
        { "label": "lp_token_policy",  "ref_utxo_id": "...", "script_hash": "..." }
      ]
    },
    "init_pool": {
      "tx_hash": "...",
      "pool_address": "...",
      "pool_validator_hash": "...",
      "lp_token_policy_hash": "...",
      "pool_nft_policy_id": "...",
      "pool_utxo_id": "...#0"
    }
  }
}
```

Auditors: cross-reference the `tx_hash` fields against [preprod.cardanoscan.io](https://preprod.cardanoscan.io) to verify the chain state matches the committed values.

## Archive directory

[`archive/`](archive/) contains historical `deploy-state.preprod.vN.json` files for v0 through v4. Each represents a different version of the validators that was on chain before being superseded by the current v5. The pre-fix attack txs cited in the audit report (e.g., `c32d7a85...` against v1) were submitted against the corresponding archived version. The pool addresses in those archives are stranded — no real users were on preprod, so no migration was required.

## Trust model

The operator wallet has no on-chain authority over the deployed validators after `init_pool`. The pool's `protocol_fee_bps`, `lp_token_policy`, `pool_nft`, and `lp_supply` are immutable per the validator's `immutable_ok` checks. The operator can:

- Mint the canonical pool NFT (one-shot — only at deploy time).
- Publish ref scripts (anyone can; the operator just paid the ADA).
- Init the pool (sets initial datum; only one init UTxO can be created per pool NFT).

The operator CANNOT:

- Change the pool's protocol fee post-init.
- Mint additional pool NFTs.
- Drain the pool (validator's `value_ok` strict equality checks).
- Bypass treasury donation enforcement (compile-time constant).
- Change the canonical Charli3 oracle binding (compile-time constant).

Any of these would require redeploying with new validators (new hashes), which is observable to the chain. This is the trust handshake.

## What the operator MUST safeguard

- Their wallet's mnemonic — controls the operator wallet. If compromised, attacker can spend the ref-script UTxOs (they sit at the operator's address) and re-deploy under their own control. Mitigation: ref-script UTxO theft only affects the operator's own ADA; it doesn't drain the pool.
- The Blockfrost API key — if compromised, attacker can spam tx submission rate-limits but cannot forge txs.
