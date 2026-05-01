"""Mint the canonical Aegis pool NFT (one-shot, parameterized).

Steps:
  1. Pick the smallest pure-ADA UTxO (≥ 5 ADA) at the operator wallet — this
     is the "init UTxO" that gets baked into the parameterized minting policy.
     Once consumed, no further mint of this exact policy can ever succeed.
  2. Re-apply the `pool_nft.pool_nft` blueprint twice (utxo_ref, token_name) via
     ``aiken blueprint apply`` to produce the parameterized minting policy.
  3. Compute its policy ID.
  4. Build a tx that consumes the init UTxO and mints exactly 1 unit of
     ``(policy_id, "AEGIS_POOL")`` to the operator address.
  5. Dry-run by default; pass ``--submit`` to actually broadcast.

Usage (PowerShell):

    cd D:/aegis
    $env:AEGIS_OPERATOR_MODE = '1'
    python -m offchain.scripts.mint_pool_nft               # dry-run
    python -m offchain.scripts.mint_pool_nft --submit      # broadcast

After a successful submit, the resulting policy_id + tx_hash are written to
``configs/deploy-state.preprod.json`` so downstream scripts can pick them up.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import cbor2
import pycardano as pyc

from offchain.scripts._common import (
    CONTRACTS_DIR,
    PLUTUS_JSON,
    OperatorWallet,
    assert_operator_mode,
    banner,
    load_operator_wallet,
    make_preprod_context,
    pick_init_utxo,
    print_tx_summary,
    record_step,
    utxo_summary,
)

DEFAULT_TOKEN_NAME = b"AEGIS_POOL"
MIN_UTXO_NFT_LOVELACE = 2_000_000


def encode_output_reference(tx_hash_hex: str, output_index: int) -> bytes:
    """Encode an Aiken `OutputReference` as PlutusData CBOR.

    Aiken: ``OutputReference { transaction_id: Hash<Blake2b_256, Transaction>, output_index: Int }``
    Plutus Data: ``Constr 0 [B(tx_hash_32), I(output_index)]``
    CBOR: ``D8 79 82 5820 <32-bytes> <int>`` (tag 121 = Constr 0).
    """
    tx_hash_bytes = bytes.fromhex(tx_hash_hex)
    if len(tx_hash_bytes) != 32:
        raise ValueError(f"tx_hash must be 32 bytes hex, got {len(tx_hash_bytes)}")
    return cbor2.dumps(cbor2.CBORTag(121, [tx_hash_bytes, output_index]))


def encode_bytearray(b: bytes) -> bytes:
    """Encode an Aiken `ByteArray` as PlutusData CBOR (just the bytes)."""
    return cbor2.dumps(b)


def apply_blueprint_param(input_blueprint: Path, output_blueprint: Path,
                          module_name: str, validator_name: str,
                          param_cbor_hex: str) -> None:
    """Run `aiken blueprint apply` once.

    Aiken's CLI on Windows swallows error output to stderr, so we capture
    stdout (the applied blueprint) and only write it to disk if non-empty.
    Module + validator must both be specified to disambiguate when several
    validators exist in the project.
    """
    cmd = [
        "aiken", "blueprint", "apply",
        "-i", input_blueprint.name,
        "-m", module_name,
        "-v", validator_name,
        param_cbor_hex,
    ]
    proc = subprocess.run(cmd, cwd=input_blueprint.parent, capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.strip():
        sys.stderr.write(
            "aiken blueprint apply failed.\n"
            f"  cwd:   {input_blueprint.parent}\n"
            f"  cmd:   {' '.join(cmd)}\n"
            f"  rc:    {proc.returncode}\n"
            f"  stdout (first 400 chars): {proc.stdout[:400]}\n"
            f"  stderr (first 400 chars): {proc.stderr[:400]}\n"
        )
        raise RuntimeError("aiken blueprint apply failed")
    output_blueprint.write_text(proc.stdout, encoding="utf-8")


def parameterize_pool_nft(
    init_utxo: pyc.UTxO,
    token_name: bytes,
    workdir: Path,
) -> tuple[pyc.PlutusV3Script, pyc.ScriptHash]:
    """Apply both parameters and return the compiled script + its policy id."""
    step1 = workdir / "pool_nft.step1.json"
    step2 = workdir / "pool_nft.step2.json"

    utxo_ref_cbor = encode_output_reference(
        str(init_utxo.input.transaction_id), int(init_utxo.input.index)
    ).hex()
    token_name_cbor = encode_bytearray(token_name).hex()

    # The applied blueprint must live next to the source plutus.json so
    # aiken can resolve module references during the second apply.
    work_step1 = PLUTUS_JSON.parent / "_pool_nft_step1.json"
    work_step2 = PLUTUS_JSON.parent / "_pool_nft_step2.json"
    try:
        apply_blueprint_param(PLUTUS_JSON, work_step1, "pool_nft", "pool_nft", utxo_ref_cbor)
        apply_blueprint_param(work_step1, work_step2, "pool_nft", "pool_nft", token_name_cbor)
        # Copy the final result to the requested workdir destination
        step2.write_text(work_step2.read_text(encoding="utf-8"), encoding="utf-8")
    finally:
        # Clean up the in-place work files so we don't pollute the contracts dir
        for f in (work_step1, work_step2):
            try:
                f.unlink()
            except FileNotFoundError:
                pass

    blueprint = json.loads(step2.read_text(encoding="utf-8"))
    validators = blueprint.get("validators", [])
    # Look for the SPECIFIC pool_nft.pool_nft.mint entry, not just any
    # *.mint — multiple minting policies exist (lp_token, pool_nft).
    spend_entry = next(
        (v for v in validators if v.get("title") == "pool_nft.pool_nft.mint"), None
    )
    if spend_entry is None:
        raise RuntimeError(
            "Could not find pool_nft.pool_nft.mint entry in applied blueprint. "
            f"Validators present: {[v.get('title') for v in validators]}"
        )
    # Verify both parameters were applied (the entry should have no
    # `parameters` field, or an empty list)
    remaining_params = spend_entry.get("parameters") or []
    if remaining_params:
        raise RuntimeError(
            f"Pool NFT validator still has unapplied parameters: "
            f"{[p.get('title') for p in remaining_params]}"
        )

    compiled_hex = spend_entry["compiledCode"]
    script_hash_hex = spend_entry["hash"]
    script_bytes = bytes.fromhex(compiled_hex)
    plutus_script = pyc.PlutusV3Script(script_bytes)
    script_hash = pyc.ScriptHash(bytes.fromhex(script_hash_hex))
    return plutus_script, script_hash


def build_mint_tx(
    ctx: pyc.ChainContext,
    wallet: OperatorWallet,
    init_utxo: pyc.UTxO,
    plutus_script: pyc.PlutusV3Script,
    policy_id: pyc.ScriptHash,
    token_name: bytes,
) -> pyc.TransactionBuilder:
    """Build (but don't sign) the mint tx."""
    builder = pyc.TransactionBuilder(ctx)

    # Consume the init UTxO explicitly (it's the parameterized binding).
    builder.add_input(init_utxo)
    # Add an additional pure-ADA UTxO from the operator wallet so we have
    # plenty of room for fees + change. add_input_address alone sometimes
    # under-selects for the merge-change calculation.
    other_utxos = [u for u in ctx.utxos(str(wallet.address))
                   if u.input != init_utxo.input
                   and (not u.output.amount.multi_asset or len(u.output.amount.multi_asset) == 0)]
    if other_utxos:
        # Pick the SMALLEST ADA-only UTxO ≥ 5 ADA so we don't waste a big one
        candidates = [u for u in other_utxos if u.output.amount.coin >= 5_000_000]
        helper_utxo = min(candidates or other_utxos, key=lambda u: u.output.amount.coin)
        builder.add_input(helper_utxo)

    asset_name = pyc.AssetName(token_name)
    mint = pyc.MultiAsset({policy_id: pyc.Asset({asset_name: 1})})

    # Set the mint
    builder.mint = mint

    # Add the minting script with a unit redeemer
    redeemer = pyc.Redeemer(0)  # _redeemer: Data — any value accepted
    builder.add_minting_script(plutus_script, redeemer)

    # Output the NFT back to the operator wallet at min-UTxO ada
    nft_value = pyc.Value(
        coin=MIN_UTXO_NFT_LOVELACE,
        multi_asset=pyc.MultiAsset({policy_id: pyc.Asset({asset_name: 1})}),
    )
    builder.add_output(pyc.TransactionOutput(wallet.address, nft_value))

    return builder


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--submit", action="store_true",
                        help="Actually broadcast the tx (default: dry-run only)")
    parser.add_argument("--token-name", default="AEGIS_POOL",
                        help="ASCII token name (default: AEGIS_POOL)")
    parser.add_argument("--init-utxo", default=None,
                        help="Override init UTxO selection (format: tx_hash#index)")
    parser.add_argument("--min-init-ada", type=float, default=5.0,
                        help="Minimum ADA in the init UTxO (default: 5)")
    args = parser.parse_args()

    assert_operator_mode()

    token_name = args.token_name.encode("ascii")
    if len(token_name) > 32:
        sys.stderr.write("ERROR: token_name must be ≤ 32 bytes\n")
        return 2

    banner("Mint Aegis canonical pool NFT (one-shot)")

    print(f"[1/5] Connecting to real Cardano preprod via Blockfrost…")
    ctx = make_preprod_context()
    tip = ctx.last_block_slot
    print(f"      tip slot = {tip}")

    print(f"[2/5] Loading operator wallet…")
    wallet = load_operator_wallet()
    print(f"      address: {wallet.address}")
    print(f"      vkh:     {wallet.vkh_hex}")

    utxos = ctx.utxos(str(wallet.address))
    total = sum(u.output.amount.coin for u in utxos)
    print(f"      balance: {total/1_000_000:.2f} ADA across {len(utxos)} UTxOs")

    if args.init_utxo:
        want_hash, _, want_idx = args.init_utxo.partition("#")
        want_idx = int(want_idx)
        match = [u for u in utxos
                 if str(u.input.transaction_id) == want_hash and u.input.index == want_idx]
        if not match:
            sys.stderr.write(f"ERROR: --init-utxo {args.init_utxo} not found at operator address\n")
            return 2
        init_utxo = match[0]
    else:
        init_utxo = pick_init_utxo(utxos, min_lovelace=int(args.min_init_ada * 1_000_000))

    print(f"[3/5] Init UTxO selected: {utxo_summary(init_utxo)}")

    print(f"[4/5] Re-applying pool_nft blueprint with utxo_ref + token_name…")
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        plutus_script, policy_id = parameterize_pool_nft(init_utxo, token_name, workdir)

    print(f"      parameterized policy id: {bytes(policy_id).hex()}")
    print(f"      script size: {len(plutus_script)} bytes")

    print(f"[5/5] Building mint tx…")
    builder = build_mint_tx(ctx, wallet, init_utxo, plutus_script, policy_id, token_name)

    # Build (and sign on submit) in a SINGLE pass — calling builder.build()
    # twice mutates internal state and trips PyCardano's change-calculator.
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
        "init_utxo": f"{init_utxo.input.transaction_id}#{init_utxo.input.index}",
        "init_utxo_lovelace": init_utxo.output.amount.coin,
        "policy_id": bytes(policy_id).hex(),
        "asset_name (hex)": token_name.hex(),
        "asset_name (ascii)": token_name.decode("ascii"),
        "mint_qty": 1,
        "operator_address": str(wallet.address),
        "fee_lovelace": fee,
        "fee_ada": f"{fee/1_000_000:.4f}",
        "outputs": len(tx_body.outputs),
        "inputs": len(tx_body.inputs),
    }
    print_tx_summary("MINT_POOL_NFT", summary)

    if not args.submit:
        print("\n[dry-run] No tx submitted. Re-run with --submit to broadcast.")
        return 0

    banner("Submitting…")
    tx_hash = ctx.submit_tx(signed_tx.to_cbor())
    tx_hash_str = str(tx_hash)
    print(f"  tx_hash: {tx_hash_str}")
    print(f"  cexplorer: https://preprod.cexplorer.io/tx/{tx_hash_str}")

    record_step("mint_pool_nft", {
        "tx_hash": tx_hash_str,
        "policy_id": bytes(policy_id).hex(),
        "asset_name_hex": token_name.hex(),
        "asset_name_ascii": token_name.decode("ascii"),
        "init_utxo": f"{init_utxo.input.transaction_id}#{init_utxo.input.index}",
        "operator_address": str(wallet.address),
        "submitted_at": int(time.time()),
        "compiled_script_hex": plutus_script.hex() if hasattr(plutus_script, "hex") else bytes(plutus_script).hex(),
    })
    print(f"\n  state recorded -> configs/deploy-state.preprod.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
