"""Helpers for pinning a per-branch symbolic context to a JSON fixture.

Each function takes a fresh symbolic ctx + the corresponding JSON dict
and returns a list of Z3 equality constraints binding every symbolic
field to the fixture's concrete value. The differential test then
adds these to the solver alongside the encoder's guards.
"""

from __future__ import annotations


def _pin_pool_datum(d, payload: dict) -> list:
    return [
        d.total_liquidity == payload["total_liquidity"],
        d.active_coverage == payload["active_coverage"],
        d.lp_token_policy == payload["lp_token_policy"],
        d.protocol_fee_bps == payload["protocol_fee_bps"],
        d.pool_nft == payload["pool_nft"],
        d.lp_supply == payload["lp_supply"],
    ]


def _pin_policy_datum(pd, payload: dict) -> list:
    return [
        pd.policy_id == payload["policy_id"],
        pd.insured == payload["insured"],
        pd.strike_price == payload["strike_price"],
        pd.coverage_amount == payload["coverage_amount"],
        pd.premium_paid == payload["premium_paid"],
        pd.start_time == payload["start_time"],
        pd.expiry_time == payload["expiry_time"],
        pd.oracle_nft == payload["oracle_nft"],
        pd.pool_script_hash == payload["pool_script_hash"],
        pd.pool_nft == payload["pool_nft"],
        pd.oracle_provider == payload["oracle_provider"],
        pd.partner_address_is_some == payload["partner_address_is_some"],
        pd.partner_address_id == payload["partner_address_id"],
        pd.partner_share_bps == payload["partner_share_bps"],
    ]


def _pin_consts(c, payload: dict) -> list:
    return [
        c.team_address_id == payload["team_address_id"],
        c.pool_address_id == payload["pool_address_id"],
        c.policy_script_hash == payload["policy_script_hash"],
        c.min_utxo_lovelace == payload["min_utxo_lovelace"],
        c.min_premium == payload["min_premium"],
        c.partner_share_cap_bps == payload["partner_share_cap_bps"],
        c.treasury_share_bps == payload["treasury_share_bps"],
        c.protocol_fee_bps == payload["protocol_fee_bps"],
    ]


def _pin_treasury_donation(td, payload: dict) -> list:
    return [
        td.is_some == payload["is_some"],
        td.amount == payload["amount"],
    ]


def pin_process_claim_ctx(ctx, fx: dict) -> list:
    return (
        _pin_pool_datum(ctx.old_pool_datum, fx["old_pool_datum"])
        + _pin_pool_datum(ctx.new_pool_datum, fx["new_pool_datum"])
        + _pin_policy_datum(
            ctx.consumed_policy_datum, fx["consumed_policy_datum"]
        )
        + [
            ctx.redeemer.payout == fx["redeemer"]["payout"],
            ctx.own_input_lovelace == fx["own_input_lovelace"],
            ctx.cont_output_lovelace == fx["cont_output_lovelace"],
            ctx.own_pool_script_hash == fx["own_pool_script_hash"],
        ]
        + _pin_consts(ctx.consts, fx["consts"])
    )


def pin_add_liquidity_ctx(ctx, fx: dict) -> list:
    return (
        _pin_pool_datum(ctx.old_pool_datum, fx["old_pool_datum"])
        + _pin_pool_datum(ctx.new_pool_datum, fx["new_pool_datum"])
        + [
            ctx.redeemer.amount == fx["redeemer"]["amount"],
            ctx.own_input_lovelace == fx["own_input_lovelace"],
            ctx.cont_output_lovelace == fx["cont_output_lovelace"],
            ctx.mint_lp_qty == fx["mint_lp_qty"],
        ]
        + _pin_consts(ctx.consts, fx["consts"])
    )


def pin_remove_liquidity_ctx(ctx, fx: dict) -> list:
    return (
        _pin_pool_datum(ctx.old_pool_datum, fx["old_pool_datum"])
        + _pin_pool_datum(ctx.new_pool_datum, fx["new_pool_datum"])
        + [
            ctx.redeemer.amount == fx["redeemer"]["amount"],
            ctx.own_input_lovelace == fx["own_input_lovelace"],
            ctx.cont_output_lovelace == fx["cont_output_lovelace"],
            ctx.mint_lp_qty == fx["mint_lp_qty"],
        ]
        + _pin_consts(ctx.consts, fx["consts"])
    )


def pin_accept_cancellation_ctx(ctx, fx: dict) -> list:
    return (
        _pin_pool_datum(ctx.old_pool_datum, fx["old_pool_datum"])
        + _pin_pool_datum(ctx.new_pool_datum, fx["new_pool_datum"])
        + _pin_policy_datum(
            ctx.consumed_policy_datum, fx["consumed_policy_datum"]
        )
        + [
            ctx.own_input_lovelace == fx["own_input_lovelace"],
            ctx.cont_output_lovelace == fx["cont_output_lovelace"],
            ctx.team_output_lovelace == fx["team_output_lovelace"],
            ctx.partner_output_lovelace == fx["partner_output_lovelace"],
            ctx.own_pool_script_hash == fx["own_pool_script_hash"],
        ]
        + _pin_treasury_donation(ctx.treasury_donation, fx["treasury_donation"])
        + _pin_consts(ctx.consts, fx["consts"])
    )


def pin_batch_underwrite_ctx(ctx, fx: dict) -> list:
    b = ctx.batch_totals
    bx = fx["batch_totals"]
    return (
        _pin_pool_datum(ctx.old_pool_datum, fx["old_pool_datum"])
        + _pin_pool_datum(ctx.new_pool_datum, fx["new_pool_datum"])
        + [
            ctx.redeemer.total_coverage == fx["redeemer"]["total_coverage"],
            ctx.redeemer.total_premium == fx["redeemer"]["total_premium"],
            ctx.own_input_lovelace == fx["own_input_lovelace"],
            ctx.cont_output_lovelace == fx["cont_output_lovelace"],
            ctx.team_output_lovelace == fx["team_output_lovelace"],
            ctx.own_pool_script_hash == fx["own_pool_script_hash"],
            b.cov_sum == bx["cov_sum"],
            b.prem_sum == bx["prem_sum"],
            b.fee_total_sum == bx["fee_total_sum"],
            b.team_total == bx["team_total"],
            b.partner_totals_sum == bx["partner_totals_sum"],
            b.funded_ok == bx["funded_ok"],
            b.shares_ok == bx["shares_ok"],
            b.partner_outputs_all_funded == bx["partner_outputs_all_funded"],
            b.aliased_partner_present == bx["aliased_partner_present"],
        ]
        + _pin_treasury_donation(ctx.treasury_donation, fx["treasury_donation"])
        + _pin_consts(ctx.consts, fx["consts"])
    )
