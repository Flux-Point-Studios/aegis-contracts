"""End-to-end pitch demo: real Aegis Underwrite tx with treasury donation.

Sequence:
  1. add_liquidity(50 ADA) so the pool can underwrite anything.
  2. wait for the new pool UTxO to confirm.
  3. create_policy(coverage=10 ADA, premium~=0.2 ADA, 1 day duration).
  4. decode the Underwrite tx body, assert body[22] (donation) equals
     calculate_treasury_cut(premium, 200 bps, 2500 bps).
  5. print cardanoscan URLs.

This is the high-fidelity proof that the v1-treasury validator's donation_ok
clause executes correctly under a real Plutus V3 spend — not just a body-
level smoke (smoke_donation.py was that).

Usage::

    cd D:/aegis
    $env:AEGIS_OPERATOR_MODE = '1'
    python -m offchain.scripts.smoke_underwrite --add-ada 50 --coverage 10
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys
import time

import cbor2
import pycardano as pyc

# api/ is the importable module for create_policy / add_liquidity
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "api"))

from offchain.scripts._common import (
    assert_operator_mode,
    banner,
    load_operator_wallet,
    make_preprod_context,
)


def wait_for_tx(ctx: pyc.BlockFrostChainContext, tx_hash: str,
                timeout_s: int = 240) -> None:
    """Poll until the tx is indexed by Blockfrost."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            ctx.api.transaction(tx_hash)
            return
        except Exception:
            time.sleep(6)
    raise TimeoutError(f"tx {tx_hash} not confirmed within {timeout_s}s")


def decode_donation_field(tx_hash: str, ctx: pyc.BlockFrostChainContext) -> int | None:
    """Fetch tx CBOR from Blockfrost and return body field 22 (donation)."""
    raw = ctx.api.transaction_cbor(tx_hash)
    cbor_hex = getattr(raw, "cbor", None) or raw["cbor"] if isinstance(raw, dict) else None
    if cbor_hex is None and hasattr(raw, "to_dict"):
        cbor_hex = raw.to_dict()["cbor"]
    if cbor_hex is None:
        raise RuntimeError(f"could not extract cbor from blockfrost response: {raw!r}")
    body = cbor2.loads(bytes.fromhex(cbor_hex))[0]
    return body.get(22)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--add-ada", type=float, default=50.0,
                        help="Liquidity to add to the pool (ADA, default 50)")
    parser.add_argument("--coverage", type=float, default=10.0,
                        help="Policy coverage in ADA (default 10)")
    parser.add_argument("--strike", type=float, default=0.35,
                        help="Strike price in USD (default 0.35)")
    parser.add_argument("--duration", type=float, default=1.0,
                        help="Policy duration in days (default 1)")
    parser.add_argument("--skip-add-liquidity", action="store_true",
                        help="Skip add_liquidity step (use if pool already funded)")
    args = parser.parse_args()

    assert_operator_mode()
    banner("Aegis Underwrite + Treasury Donation — preprod end-to-end")

    print("[setup] Connecting + loading wallet...")
    ctx = make_preprod_context()
    wallet = load_operator_wallet()
    print(f"        operator: {wallet.address}")
    utxos = ctx.utxos(str(wallet.address))
    print(f"        balance:  {sum(u.output.amount.coin for u in utxos)/1_000_000:.2f} ADA")

    add_liquidity_tx_hash: str | None = None

    if not args.skip_add_liquidity:
        print(f"\n[1/3] add_liquidity({args.add_ada} ADA)...")
        # Lazy-import: api/policies.py side-effect-imports chain.py which
        # reads env at import time, so we must import after env is loaded
        # by _common.
        from pool import add_liquidity

        result = add_liquidity(ctx, wallet.skey, wallet.address, args.add_ada)
        add_liquidity_tx_hash = result["tx_hash"]
        print(f"      tx_hash: {add_liquidity_tx_hash}")
        print(f"      cardanoscan: https://preprod.cardanoscan.io/transaction/{add_liquidity_tx_hash}")
        print("      waiting for confirmation...")
        wait_for_tx(ctx, add_liquidity_tx_hash)
        print("      confirmed.")
        # Refresh ctx so subsequent UTxO queries see the new pool state.
        ctx = make_preprod_context()
    else:
        print("\n[1/3] skipping add_liquidity (--skip-add-liquidity)")

    print(f"\n[2/3] create_policy(coverage={args.coverage} ADA, "
          f"strike=${args.strike}, duration={args.duration}d)...")
    from policies import create_policy

    policy_result = create_policy(
        ctx, wallet.skey, wallet.address,
        strike_price_usd=args.strike,
        coverage_ada=args.coverage,
        duration_days=args.duration,
    )
    underwrite_tx_hash = policy_result["tx_hash"]
    print(f"      tx_hash: {underwrite_tx_hash}")
    print(f"      cardanoscan: https://preprod.cardanoscan.io/transaction/{underwrite_tx_hash}")
    print(f"      premium_paid: {policy_result.get('premium_paid_ada', '?')} ADA")

    print("      waiting for confirmation...")
    wait_for_tx(ctx, underwrite_tx_hash)
    print("      confirmed.")

    print("\n[3/3] Decoding tx body — checking field 22 (donation)...")
    donation_lovelace = decode_donation_field(underwrite_tx_hash, ctx)
    if donation_lovelace is None:
        print("      ERROR: tx body has NO donation field. The validator")
        print("             *should* have rejected this. Investigate immediately.")
        return 1

    # Compute the expected cut from the premium reported in the result.
    from _treasury import calculate_treasury_cut, TREASURY_SHARE_BPS
    premium_lovelace = int(policy_result.get("premium_paid_lovelace", 0)) or int(
        float(policy_result.get("premium_paid_ada", 0)) * 1_000_000
    )
    if premium_lovelace == 0:
        print(f"      WARN: could not extract premium from result: {policy_result!r}")
        expected = None
    else:
        expected = calculate_treasury_cut(premium_lovelace, 200, TREASURY_SHARE_BPS)

    print(f"      donation on chain: {donation_lovelace} lovelace ({donation_lovelace/1_000_000:.4f} ADA)")
    if expected is not None:
        print(f"      expected (math):   {expected} lovelace ({expected/1_000_000:.4f} ADA)")
        if donation_lovelace == expected:
            print(f"      MATCH — donation_ok branch executed correctly.")
        else:
            print(f"      MISMATCH — investigate. Off-chain disagrees with on-chain.")
            return 1

    banner("PITCH DEMO ASSETS")
    if add_liquidity_tx_hash:
        print(f"  Add liquidity:  https://preprod.cardanoscan.io/transaction/{add_liquidity_tx_hash}")
    print(f"  Underwrite:     https://preprod.cardanoscan.io/transaction/{underwrite_tx_hash}")
    print(f"  Donation:       {donation_lovelace} lovelace via Conway field 22")
    return 0


if __name__ == "__main__":
    sys.exit(main())
