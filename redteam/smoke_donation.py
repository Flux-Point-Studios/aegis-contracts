"""Smoke-test the Conway treasury_donation field end-to-end on preprod.

Submits a tiny self-transfer tx that includes ``donation = 1_000_000``
(1 ADA) on the body. This is NOT an Aegis policy creation — just the
minimum tx that proves:

  1. PyCardano serializes ``donation`` (CDDL key 22) correctly
  2. Blockfrost preprod accepts the field
  3. The cardanoscan / cexplorer explorer renders the donation row

The captured tx hash + URL is the demo asset for the Draper Dragon
pitch ("here is a real Aegis-paid treasury donation, on chain, today").

Usage::

    cd D:/aegis
    $env:AEGIS_OPERATOR_MODE = '1'
    python -m offchain.scripts.smoke_donation --submit
"""
from __future__ import annotations

import argparse
import sys
import time

import pycardano as pyc

# Add project root to path so we can import api.
import os, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "api"))

from _donation_tx_builder import DonatingTxBuilder
from _treasury import calculate_treasury_cut

from offchain.scripts._common import (
    assert_operator_mode,
    banner,
    load_operator_wallet,
    make_preprod_context,
    print_tx_summary,
    utxo_summary,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--submit", action="store_true",
                        help="Actually broadcast (default: dry-run)")
    parser.add_argument("--donation-ada", type=float, default=1.0,
                        help="Treasury donation in ADA (default: 1.0)")
    args = parser.parse_args()

    assert_operator_mode()
    banner("Smoke-test Conway treasury_donation on preprod")

    print("[1/3] Connecting to preprod via Blockfrost...")
    ctx = make_preprod_context()
    print(f"      tip slot = {ctx.last_block_slot}")

    print("[2/3] Loading operator wallet...")
    wallet = load_operator_wallet()
    print(f"      address: {wallet.address}")

    donation_lovelace = int(args.donation_ada * 1_000_000)
    print(f"      donation: {args.donation_ada} ADA ({donation_lovelace} lovelace)")

    # Math demonstrator: at default fee 200 bps and share 2500 bps, this
    # is what a 100 ADA Aegis premium would owe. Print it for the pitch.
    aegis_100ada_cut = calculate_treasury_cut(100_000_000, 200, 2_500)
    print(f"      [demo math] a 100 ADA Aegis premium would owe "
          f"{aegis_100ada_cut} lovelace = {aegis_100ada_cut/1_000_000:.3f} ADA")

    print("[3/3] Building self-transfer + donation tx...")
    utxos = ctx.utxos(str(wallet.address))
    pure_ada = [
        u for u in utxos
        if not u.output.amount.multi_asset or len(u.output.amount.multi_asset) == 0
    ]
    if not pure_ada:
        sys.stderr.write("ERROR: no pure-ADA UTxO available.\n")
        return 2
    funder = max(pure_ada, key=lambda u: u.output.amount.coin)
    print(f"      input: {utxo_summary(funder)}")

    builder = DonatingTxBuilder(ctx, treasury_donation=donation_lovelace)
    builder.add_input(funder)
    # Send a small output to ourselves; the rest comes back as change.
    builder.add_output(pyc.TransactionOutput(wallet.address, 2_000_000))

    if args.submit:
        signed = builder.build_and_sign(
            signing_keys=[wallet.skey],
            change_address=wallet.address,
            merge_change=False,
        )
        tx_body = signed.transaction_body
    else:
        tx_body = builder.build(change_address=wallet.address, merge_change=False)

    print_tx_summary("DONATION_SMOKE", {
        "donation_lovelace": int(tx_body.donation) if tx_body.donation else 0,
        "donation_ada": f"{(tx_body.donation or 0)/1_000_000:.3f}",
        "fee_lovelace": int(tx_body.fee),
        "fee_ada": f"{int(tx_body.fee)/1_000_000:.4f}",
        "inputs": len(tx_body.inputs),
        "outputs": len(tx_body.outputs),
    })

    if not args.submit:
        print("\n[dry-run] No tx submitted. Re-run with --submit to broadcast.")
        return 0

    tx_hash = ctx.submit_tx(signed.to_cbor())
    tx_hash_str = str(tx_hash)
    print(f"  tx_hash: {tx_hash_str}")
    print(f"  cexplorer: https://preprod.cexplorer.io/tx/{tx_hash_str}")
    print(f"  cardanoscan: https://preprod.cardanoscan.io/transaction/{tx_hash_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
