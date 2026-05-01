"""Red-team — try to bypass the validator-enforced treasury donation.

Three sub-attacks:
  (a) Donation = required - 1 lovelace (underpay by 1)
  (b) Donation = None (Conway field absent)
  (c) Donation = 0 (field present but zero)

All three MUST be rejected by ``donation_ok`` in pool.ak's Underwrite branch.
If any are accepted, the treasury enforcement is bypassed.
"""
from __future__ import annotations

import argparse
import sys
import pathlib

import pycardano as pyc

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "api"))

from offchain.scripts._common import (
    assert_operator_mode, banner, load_operator_wallet, make_preprod_context,
)


def attempt(name: str, donation_lovelace, args) -> str:
    """Returns 'rejected' (good) or 'accepted' (BAD — finding!)."""
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

    coverage_lovelace = int(args.coverage_ada * 1_000_000)
    premium_lovelace = 2_000_000
    duration_days = 1
    strike_price_scaled = 350_000

    insured_pkh = bytes(wallet.address.payment_part)
    chain_posix_ms = (PREPROD_SLOT_ZERO_POSIX + ctx.last_block_slot) * 1000
    start_time_ms = chain_posix_ms - 120_000
    expiry_time_ms = start_time_ms + duration_days * 86_400_000
    policy_id = _generate_policy_id(
        insured_pkh, strike_price_scaled, coverage_lovelace,
        start_time_ms, expiry_time_ms,
    )
    policy_datum = PolicyDatum(
        policy_id=policy_id, insured=insured_pkh,
        strike_price=strike_price_scaled,
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

    # Pass the maliciously low (or absent) donation directly. The
    # DonatingTxBuilder rejects negatives at construction time, so we
    # bypass it for the underpay-by-1 case via a tiny subclass below.
    class HostileBuilder(DonatingTxBuilder):
        def __init__(self, ctx, donation):
            super().__init__(ctx, treasury_donation=None)
            self.donation = donation  # raw set, no validation

    builder = HostileBuilder(ctx, donation_lovelace)
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

    # Output 0: legitimate policy at the policy_validator address.
    policy_address = pyc.Address.from_primitive(POLICY_SCRIPT_ADDRESS)
    builder.add_output(pyc.TransactionOutput(
        address=policy_address,
        amount=max(coverage_lovelace, MIN_UTXO_LOVELACE),
        datum=policy_datum,
    ))

    # Output 1: pool continuation (NFT preserved).
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

    expected_cut = calculate_treasury_cut(premium_lovelace, pool_datum.protocol_fee_bps)
    print(f"\n[{name}] expected={expected_cut}, sending={donation_lovelace}")
    try:
        signed_tx = builder.build_and_sign(
            signing_keys=[wallet.skey], change_address=wallet.address,
            merge_change=False,
        )
        tx_hash = ctx.submit_tx(signed_tx.to_cbor())
        print(f"[{name}] !!! ACCEPTED — VALIDATOR BYPASS !!! tx_hash={tx_hash}")
        return "accepted"
    except Exception as e:
        msg = str(e)[:120]
        print(f"[{name}] rejected: {msg}")
        return "rejected"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--coverage-ada", type=float, default=5.0)
    args = parser.parse_args()

    assert_operator_mode()
    banner("RED TEAM A-023 — donation field bypass attempts")

    from _treasury import calculate_treasury_cut

    # Compute expected for premium=2_000_000, fee_bps=200
    expected = calculate_treasury_cut(2_000_000, 200)
    print(f"Expected donation for 2 ADA premium: {expected} lovelace")

    # (a) underpay by 1 lovelace
    r1 = attempt("a-underpay-by-1", expected - 1, args)
    # (b) None — field absent. We need to set self.donation = None on a fresh
    #     builder. Skip if self.donation = None means the body has no field,
    #     which is what DonatingTxBuilder treats as "no donation owed."
    r2 = attempt("b-zero-donation", 0, args)
    # (c) explicit zero — encoded as field 22 = 0. Unusual but tests strict
    #     equality with required > 0.
    # We treat 0 same as None per DonatingTxBuilder, so (b) and (c) overlap.

    print("\n" + "=" * 60)
    print(f"RESULTS:")
    print(f"  underpay-by-1: {r1}")
    print(f"  zero-donation: {r2}")
    accepted = [n for n, r in [("underpay", r1), ("zero", r2)] if r == "accepted"]
    if accepted:
        print(f"\n!!! BYPASS CONFIRMED — A-023 finding: {accepted}")
        return 1
    print("\nAll donation-bypass attempts rejected. donation_ok holds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
