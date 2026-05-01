"""Create the canonical Aegis pool UTxO on Cardano preprod.

Pre-requisites:
  - mint_pool_nft has produced the canonical NFT at the operator wallet
  - publish_refs has published the three reference scripts

This script consumes the pool-NFT UTxO at the operator address and creates
ONE script UTxO at the pool validator's address carrying:
  * the pool NFT (locks the NFT in the canonical pool, where the validator's
    `find_canonical_pool_output` looks for it)
  * an inline PoolDatum with total_liquidity=0, active_coverage=0, lp_supply=0
    (the first AddLiquidity caller will bootstrap supply via the
    `lp_supply == 0` branch of `calculate_lp_mint`)
  * min-UTxO ADA computed from the actual output bytes

Usage (PowerShell):

    cd D:/aegis
    $env:AEGIS_OPERATOR_MODE = '1'
    python -m offchain.scripts.init_pool                # dry-run
    python -m offchain.scripts.init_pool --submit       # broadcast
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pycardano as pyc

from offchain.scripts._common import (
    OperatorWallet,
    assert_operator_mode,
    banner,
    load_operator_wallet,
    make_preprod_context,
    print_tx_summary,
    read_deploy_state,
    record_step,
    utxo_summary,
)

# ---------------------------------------------------------------------------
# PoolDatum (must match contracts/lib/aegis/types.ak EXACTLY)
# ---------------------------------------------------------------------------


@dataclass
class PoolDatum(pyc.PlutusData):
    """Inline datum locked at the pool script address.

    Fields, in declaration order (this is what gets CBOR-encoded as
    Constr 0 [...]) — must match aegis/types.ak::PoolDatum:
      total_liquidity:  Int (lovelace deposited by LPs)
      active_coverage:  Int (lovelace reserved for active policies)
      lp_token_policy:  ByteArray (28-byte LP token policy hash)
      protocol_fee_bps: Int
      pool_nft:         ByteArray (28-byte canonical NFT policy id)
      lp_supply:        Int (outstanding aLP, fix A-003)
    """

    CONSTR_ID = 0
    total_liquidity: int
    active_coverage: int
    lp_token_policy: bytes
    protocol_fee_bps: int
    pool_nft: bytes
    lp_supply: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def find_pool_nft_utxo(
    utxos: list[pyc.UTxO],
    pool_nft_policy_id_hex: str,
    asset_name: bytes,
) -> pyc.UTxO:
    target_policy = pyc.ScriptHash(bytes.fromhex(pool_nft_policy_id_hex))
    target_name = pyc.AssetName(asset_name)
    for u in utxos:
        ma = u.output.amount.multi_asset
        if ma is None:
            continue
        for policy_id, assets in ma.items():
            if bytes(policy_id) == bytes(target_policy):
                for an, qty in assets.items():
                    if bytes(an) == bytes(target_name) and int(qty) >= 1:
                        return u
    raise RuntimeError(
        f"Pool NFT {pool_nft_policy_id_hex}.{asset_name.hex()} not found at operator wallet. "
        "Did mint_pool_nft succeed?"
    )


def pick_helper_utxo(utxos: list[pyc.UTxO], exclude: pyc.UTxO,
                     min_lovelace: int = 5_000_000) -> pyc.UTxO | None:
    pure = [
        u for u in utxos
        if u.input != exclude.input
        and (not u.output.amount.multi_asset or len(u.output.amount.multi_asset) == 0)
        and u.output.amount.coin >= min_lovelace
    ]
    if not pure:
        return None
    return min(pure, key=lambda u: u.output.amount.coin)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--submit", action="store_true",
                        help="Actually broadcast the tx (default: dry-run only)")
    parser.add_argument("--protocol-fee-bps", type=int, default=200,
                        help="Initial protocol fee in basis points (default: 200 = 2%%)")
    args = parser.parse_args()

    assert_operator_mode()
    banner("Initialize canonical Aegis pool UTxO")

    # ---- 1. Load deploy state ------------------------------------------------
    state = read_deploy_state()
    steps = state.get("steps", {})
    mint_step = steps.get("mint_pool_nft")
    refs_step = steps.get("publish_refs")
    if not mint_step:
        sys.stderr.write("ERROR: mint_pool_nft step missing from deploy-state. Run mint_pool_nft first.\n")
        return 2
    if not refs_step or not refs_step.get("results"):
        sys.stderr.write("ERROR: publish_refs step missing. Run publish_refs first.\n")
        return 2

    pool_nft_policy_id = mint_step["policy_id"]
    asset_name = bytes.fromhex(mint_step["asset_name_hex"])
    print(f"      pool NFT policy id: {pool_nft_policy_id}")
    print(f"      pool NFT asset:     {asset_name.decode('ascii', errors='replace')}")

    # Pull script hashes from publish_refs results (single source of truth).
    by_label = {r["label"]: r for r in refs_step["results"]}
    pool_validator_hash_hex = by_label["pool_validator"]["script_hash"]
    lp_token_policy_hash_hex = by_label["lp_token_policy"]["script_hash"]
    print(f"      pool_validator hash: {pool_validator_hash_hex}")
    print(f"      lp_token policy hash: {lp_token_policy_hash_hex}")

    # ---- 2. Connect, load wallet --------------------------------------------
    print(f"\n[1/4] Connecting to real Cardano preprod via Blockfrost...")
    ctx = make_preprod_context()
    print(f"      tip slot = {ctx.last_block_slot}")

    print(f"[2/4] Loading operator wallet...")
    wallet = load_operator_wallet()
    print(f"      base addr: {wallet.address}")

    utxos = ctx.utxos(str(wallet.address))
    print(f"      balance: {sum(u.output.amount.coin for u in utxos)/1_000_000:.2f} ADA across {len(utxos)} UTxOs")

    # ---- 3. Build init tx ---------------------------------------------------
    print(f"\n[3/4] Locating pool NFT UTxO...")
    nft_utxo = find_pool_nft_utxo(utxos, pool_nft_policy_id, asset_name)
    print(f"      nft utxo: {utxo_summary(nft_utxo)}")

    helper = pick_helper_utxo(utxos, exclude=nft_utxo, min_lovelace=5_000_000)
    if helper:
        print(f"      helper:   {utxo_summary(helper)}")

    # Pool script address (script-only, no stake credential)
    pool_script_hash = pyc.ScriptHash(bytes.fromhex(pool_validator_hash_hex))
    pool_address = pyc.Address(payment_part=pool_script_hash, network=pyc.Network.TESTNET)
    print(f"      pool addr: {pool_address}")

    # Construct the pool datum
    datum = PoolDatum(
        total_liquidity=0,
        active_coverage=0,
        lp_token_policy=bytes.fromhex(lp_token_policy_hash_hex),
        protocol_fee_bps=args.protocol_fee_bps,
        pool_nft=bytes.fromhex(pool_nft_policy_id),
        lp_supply=0,
    )

    # Output value: NFT (1 unit) + bootstrap min-UTxO ada.
    # Min-UTxO with an inline datum + 1 token ≈ 1.6 ADA; allocate 2 ADA.
    bootstrap_lovelace = 2_000_000
    nft_policy = pyc.ScriptHash(bytes.fromhex(pool_nft_policy_id))
    nft_value = pyc.Value(
        coin=bootstrap_lovelace,
        multi_asset=pyc.MultiAsset(
            {nft_policy: pyc.Asset({pyc.AssetName(asset_name): 1})}
        ),
    )

    builder = pyc.TransactionBuilder(ctx)
    builder.add_input(nft_utxo)
    if helper:
        builder.add_input(helper)
    builder.add_output(
        pyc.TransactionOutput(
            address=pool_address,
            amount=nft_value,
            datum=datum,
        )
    )

    if args.submit:
        signed_tx = builder.build_and_sign(
            signing_keys=[wallet.skey],
            change_address=wallet.address,
            merge_change=False,
        )
        tx_body = signed_tx.transaction_body
    else:
        tx_body = builder.build(change_address=wallet.address, merge_change=False)
    fee = int(tx_body.fee)

    summary = {
        "pool_address": str(pool_address),
        "pool_validator_hash": pool_validator_hash_hex,
        "pool_nft_policy_id": pool_nft_policy_id,
        "pool_nft_asset_hex": asset_name.hex(),
        "lp_token_policy_hash": lp_token_policy_hash_hex,
        "datum": {
            "total_liquidity": 0,
            "active_coverage": 0,
            "protocol_fee_bps": args.protocol_fee_bps,
            "lp_supply": 0,
        },
        "bootstrap_lovelace": bootstrap_lovelace,
        "fee_lovelace": fee,
        "fee_ada": f"{fee/1_000_000:.4f}",
        "inputs": len(tx_body.inputs),
        "outputs": len(tx_body.outputs),
    }
    print_tx_summary("INIT_POOL", summary)

    if not args.submit:
        print("\n[dry-run] No tx submitted. Re-run with --submit to broadcast.")
        return 0

    # ---- 4. Submit + record -------------------------------------------------
    print(f"\n[4/4] Submitting init pool tx...")
    tx_hash = ctx.submit_tx(signed_tx.to_cbor())
    tx_hash_str = str(tx_hash)
    print(f"  tx_hash: {tx_hash_str}")
    print(f"  cexplorer: https://preprod.cexplorer.io/tx/{tx_hash_str}")

    record_step("init_pool", {
        "tx_hash": tx_hash_str,
        "pool_utxo_id": f"{tx_hash_str}#0",
        "pool_address": str(pool_address),
        "pool_validator_hash": pool_validator_hash_hex,
        "pool_nft_policy_id": pool_nft_policy_id,
        "pool_nft_asset_hex": asset_name.hex(),
        "lp_token_policy_hash": lp_token_policy_hash_hex,
        "bootstrap_lovelace": bootstrap_lovelace,
        "protocol_fee_bps": args.protocol_fee_bps,
        "submitted_at": int(time.time()),
    })
    print("  state recorded -> configs/deploy-state.preprod.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
