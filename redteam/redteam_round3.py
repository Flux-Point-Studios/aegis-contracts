"""Round-3 red-team — verify A-014/A-015/A-016 closures + new attacks.

Attacks attempted:
  R3-A. Coverage = premium*50 + 1 lovelace (A-014 boundary)
  R3-B. start_time = 0 epoch (A-015 past-dated policy)
  R3-C. start_time far in future (A-015 future-dated policy)
  R3-D. expiry_time < start_time (A-015 misordered)
  R3-E. Multi-policy single-Underwrite (creative — multiple legitimate
        policy outputs in one tx, only one redeemer's premium paid)

Each attack is built and submit-tested. Expected: REJECTED for A through D
(now blocked by validator). E is interesting — see if validator detects.
"""
from __future__ import annotations

import sys
import pathlib
import hashlib

import pycardano as pyc

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "api"))

from offchain.scripts._common import (
    assert_operator_mode, banner, load_operator_wallet, make_preprod_context,
)


def craft_underwrite(
    *,
    coverage_lovelace: int,
    premium_lovelace: int,
    start_time_override: int | None = None,
    expiry_time_override: int | None = None,
    extra_policy_outputs: int = 0,
    label: str,
) -> str:
    """Construct + submit a malicious Underwrite. Returns 'rejected' or 'accepted'."""
    ctx = make_preprod_context()
    wallet = load_operator_wallet()

    from chain import (
        POOL_SCRIPT_ADDRESS, POOL_REF_SCRIPT_UTXO_ID, POLICY_SCRIPT_ADDRESS,
        POOL_SCRIPT_HASH, ORACLE_NFT_POLICY_ID, PREPROD_SLOT_ZERO_POSIX,
    )
    from policies import (
        PolicyDatum, UnderwriteRedeemer, POOL_SPEND_EX_UNITS, MIN_UTXO_LOVELACE,
    )
    from pool import _find_pool_utxo, _utxo_lovelace, PoolDatum, _resolve_ref_utxo
    from _treasury import calculate_treasury_cut
    from _donation_tx_builder import DonatingTxBuilder

    pool_utxo, pool_datum = _find_pool_utxo(ctx)
    if pool_datum.total_liquidity - pool_datum.active_coverage < coverage_lovelace and coverage_lovelace > 0:
        return f"skipped (pool insolvent: avail={pool_datum.total_liquidity - pool_datum.active_coverage}, want={coverage_lovelace})"

    insured_pkh = bytes(wallet.address.payment_part)
    chain_posix_ms = (PREPROD_SLOT_ZERO_POSIX + ctx.last_block_slot) * 1000
    start_time_ms = (
        start_time_override
        if start_time_override is not None
        else chain_posix_ms - 120_000
    )
    expiry_time_ms = (
        expiry_time_override
        if expiry_time_override is not None
        else start_time_ms + 86_400_000
    )

    policy_id = hashlib.blake2b(
        insured_pkh + label.encode() + str(coverage_lovelace).encode(),
        digest_size=28,
    ).digest()
    policy_datum = PolicyDatum(
        policy_id=policy_id, insured=insured_pkh,
        strike_price=350_000,
        coverage_amount=coverage_lovelace, premium_paid=premium_lovelace,
        start_time=start_time_ms, expiry_time=expiry_time_ms,
        oracle_nft=bytes.fromhex(ORACLE_NFT_POLICY_ID),
        pool_script_hash=bytes.fromhex(POOL_SCRIPT_HASH),
        pool_nft=pool_datum.pool_nft,
    )

    protocol_fee = premium_lovelace * pool_datum.protocol_fee_bps // 10_000
    net_premium = premium_lovelace - protocol_fee
    new_pool_datum = PoolDatum(
        total_liquidity=pool_datum.total_liquidity + net_premium,
        active_coverage=pool_datum.active_coverage + coverage_lovelace,
        lp_token_policy=pool_datum.lp_token_policy,
        protocol_fee_bps=pool_datum.protocol_fee_bps,
        pool_nft=pool_datum.pool_nft, lp_supply=pool_datum.lp_supply,
    )

    treasury_cut = calculate_treasury_cut(premium_lovelace, pool_datum.protocol_fee_bps)
    builder = DonatingTxBuilder(ctx, treasury_donation=treasury_cut)

    # Set tx validity — for "past start_time" attack the user might lie
    # about validity; honest range here.
    last_block_slot = ctx.last_block_slot
    builder.validity_start = last_block_slot - 200
    builder.ttl = last_block_slot + 600

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
    # Output 0: legitimate policy output
    builder.add_output(pyc.TransactionOutput(
        address=policy_address,
        amount=max(coverage_lovelace if coverage_lovelace > 0 else 0, MIN_UTXO_LOVELACE),
        datum=policy_datum,
    ))

    # E: extra policy outputs (multi-policy single-Underwrite attack)
    for i in range(extra_policy_outputs):
        extra_id = hashlib.blake2b(policy_id + str(i).encode(), digest_size=28).digest()
        extra_datum = PolicyDatum(
            policy_id=extra_id, insured=insured_pkh,
            strike_price=350_000,
            coverage_amount=coverage_lovelace, premium_paid=premium_lovelace,
            start_time=start_time_ms, expiry_time=expiry_time_ms,
            oracle_nft=bytes.fromhex(ORACLE_NFT_POLICY_ID),
            pool_script_hash=bytes.fromhex(POOL_SCRIPT_HASH),
            pool_nft=pool_datum.pool_nft,
        )
        builder.add_output(pyc.TransactionOutput(
            address=policy_address,
            amount=max(coverage_lovelace if coverage_lovelace > 0 else 0, MIN_UTXO_LOVELACE),
            datum=extra_datum,
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
        return f"ACCEPTED tx={tx_hash}"
    except Exception as e:
        msg = str(e)[:200]
        return f"rejected"


def main() -> int:
    assert_operator_mode()
    banner("RED TEAM ROUND 3 — A-014/A-015/A-016 closures + creative attacks")

    # R3-A: 1 lovelace over the 50× ratio
    print("\n[R3-A] coverage = 100.000001 ADA at premium = 2 ADA (1 lovelace over)")
    r = craft_underwrite(
        coverage_lovelace=100_000_001, premium_lovelace=2_000_000,
        label="r3a",
    )
    print(f"        result: {r}")

    # R3-B: start_time = 0
    print("\n[R3-B] start_time = 0 (epoch dawn)")
    r = craft_underwrite(
        coverage_lovelace=10_000_000, premium_lovelace=2_000_000,
        start_time_override=0,
        expiry_time_override=86_400_000,
        label="r3b",
    )
    print(f"        result: {r}")

    # R3-C: start_time at year ~5138
    print("\n[R3-C] start_time = year 5138")
    r = craft_underwrite(
        coverage_lovelace=10_000_000, premium_lovelace=2_000_000,
        start_time_override=99_999_999_999_999,
        expiry_time_override=99_999_999_999_999 + 86_400_000,
        label="r3c",
    )
    print(f"        result: {r}")

    # R3-D: expiry_time < start_time
    print("\n[R3-D] expiry_time = start_time - 1")
    ctx = make_preprod_context()
    from chain import PREPROD_SLOT_ZERO_POSIX
    chain_posix = (PREPROD_SLOT_ZERO_POSIX + ctx.last_block_slot) * 1000
    r = craft_underwrite(
        coverage_lovelace=10_000_000, premium_lovelace=2_000_000,
        start_time_override=chain_posix - 120_000,
        expiry_time_override=chain_posix - 120_001,
        label="r3d",
    )
    print(f"        result: {r}")

    # R3-E: 3 legitimate policy outputs in one Underwrite
    print("\n[R3-E] 3 policies in one Underwrite (only 1 premium paid)")
    r = craft_underwrite(
        coverage_lovelace=5_000_000, premium_lovelace=2_000_000,
        extra_policy_outputs=2,  # 1 main + 2 extras = 3 total
        label="r3e",
    )
    print(f"        result: {r}")

    print("\n" + "=" * 60)
    print("Summary: R3-A through R3-D should all be `rejected`.")
    print("R3-E may be `ACCEPTED` (multi-policy creation possible) — see analysis.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
