"""Concrete fixture generation from Z3 models.

Given a symbolic context + Z3 model, walk the context's dataclass
fields and emit a nested Python dict matching the on-chain CBOR shape
(specifically: the same shape as the hand-built JSON fixtures in
`tests/fixtures/*_positive.json`).

The dict is what `tests/_pinning.py::pin_*_ctx` expects and is what
`aiken_runner` serialises into Aiken-readable test source.
"""

from __future__ import annotations

import dataclasses
import random
from typing import Any, Callable, Iterable

from z3 import (
    ArithRef,
    BoolRef,
    IntNumRef,
    ModelRef,
    Solver,
    sat,
    unsat,
)

from ..context import (
    MIN_PREMIUM_PREPROD,
    MIN_UTXO_LOVELACE,
    PARTNER_SHARE_CAP_BPS,
    PROTOCOL_FEE_BPS_DEFAULT,
    TREASURY_SHARE_BPS,
    SymbolicAcceptCancellationContext,
    SymbolicAddLiquidityContext,
    SymbolicBatchUnderwriteContext,
    SymbolicPolicyDatum,
    SymbolicPoolDatum,
    SymbolicProcessClaimContext,
    SymbolicRemoveLiquidityContext,
    SymbolicScriptContext,
    SymbolicTreasuryDonation,
    fresh_accept_cancellation_context,
    fresh_add_liquidity_context,
    fresh_batch_underwrite_context,
    fresh_process_claim_context,
    fresh_remove_liquidity_context,
    fresh_underwrite_context,
    pin_protocol_constants,
)
from ..encoders import (
    AcceptCancellationEncoder,
    AddLiquidityEncoder,
    BaseEncoder,
    BatchUnderwriteEncoder,
    ProcessClaimEncoder,
    RemoveLiquidityEncoder,
    UnderwriteEncoder,
)


# ---------------------------------------------------------------------------
# Z3 -> Python int extraction
# ---------------------------------------------------------------------------


def _eval_int(model: ModelRef, var: ArithRef, default: int = 0) -> int:
    """Evaluate a Z3 Int variable in the model, returning a Python int.

    If the variable is unconstrained, Z3 may not have a concrete
    assignment for it; fall back to `default`.
    """
    raw = model.eval(var, model_completion=True)
    if isinstance(raw, IntNumRef):
        return raw.as_long()
    # Fallback path: try `.as_long()` directly (Z3 may already complete).
    try:
        return raw.as_long()
    except Exception:
        return default


def _pool_datum_dict(model: ModelRef, d: SymbolicPoolDatum) -> dict:
    return {
        "total_liquidity": _eval_int(model, d.total_liquidity),
        "active_coverage": _eval_int(model, d.active_coverage),
        "lp_token_policy": _eval_int(model, d.lp_token_policy),
        "protocol_fee_bps": _eval_int(model, d.protocol_fee_bps),
        "pool_nft": _eval_int(model, d.pool_nft),
        "lp_supply": _eval_int(model, d.lp_supply),
    }


def _policy_datum_dict(model: ModelRef, p: SymbolicPolicyDatum) -> dict:
    return {
        "policy_id": _eval_int(model, p.policy_id),
        "insured": _eval_int(model, p.insured),
        "strike_price": _eval_int(model, p.strike_price),
        "coverage_amount": _eval_int(model, p.coverage_amount),
        "premium_paid": _eval_int(model, p.premium_paid),
        "start_time": _eval_int(model, p.start_time),
        "expiry_time": _eval_int(model, p.expiry_time),
        "oracle_nft": _eval_int(model, p.oracle_nft),
        "pool_script_hash": _eval_int(model, p.pool_script_hash),
        "pool_nft": _eval_int(model, p.pool_nft),
        "oracle_provider": _eval_int(model, p.oracle_provider),
        "partner_address_is_some": _eval_int(
            model, p.partner_address_is_some
        ),
        "partner_address_id": _eval_int(model, p.partner_address_id),
        "partner_share_bps": _eval_int(model, p.partner_share_bps),
    }


def _consts_dict(model: ModelRef, c) -> dict:
    return {
        "team_address_id": _eval_int(model, c.team_address_id),
        "pool_address_id": _eval_int(model, c.pool_address_id),
        "policy_script_hash": _eval_int(model, c.policy_script_hash),
        "min_utxo_lovelace": _eval_int(model, c.min_utxo_lovelace),
        "min_premium": _eval_int(model, c.min_premium),
        "partner_share_cap_bps": _eval_int(model, c.partner_share_cap_bps),
        "treasury_share_bps": _eval_int(model, c.treasury_share_bps),
        "protocol_fee_bps": _eval_int(model, c.protocol_fee_bps),
    }


def _treasury_donation_dict(
    model: ModelRef, td: SymbolicTreasuryDonation
) -> dict:
    return {
        "is_some": _eval_int(model, td.is_some),
        "amount": _eval_int(model, td.amount),
    }


# ---------------------------------------------------------------------------
# Per-branch model -> fixture-dict
# ---------------------------------------------------------------------------


def _underwrite_dict(model: ModelRef, ctx: SymbolicScriptContext) -> dict:
    return {
        "old_pool_datum": _pool_datum_dict(model, ctx.old_pool_datum),
        "new_pool_datum": _pool_datum_dict(model, ctx.new_pool_datum),
        "new_policy_datum": _policy_datum_dict(model, ctx.new_policy_datum),
        "redeemer": {
            "coverage": _eval_int(model, ctx.redeemer.coverage),
            "premium": _eval_int(model, ctx.redeemer.premium),
        },
        "own_input_lovelace": _eval_int(model, ctx.own_input_lovelace),
        "cont_output_lovelace": _eval_int(model, ctx.cont_output_lovelace),
        "team_output_lovelace": _eval_int(model, ctx.team_output_lovelace),
        "partner_output_lovelace": _eval_int(
            model, ctx.partner_output_lovelace
        ),
        "own_pool_script_hash": _eval_int(model, ctx.own_pool_script_hash),
        "validity_range": {
            "lb": _eval_int(model, ctx.validity_range.lb),
            "ub": _eval_int(model, ctx.validity_range.ub),
        },
        "treasury_donation": _treasury_donation_dict(
            model, ctx.treasury_donation
        ),
        "consts": _consts_dict(model, ctx.consts),
    }


def _process_claim_dict(
    model: ModelRef, ctx: SymbolicProcessClaimContext
) -> dict:
    return {
        "old_pool_datum": _pool_datum_dict(model, ctx.old_pool_datum),
        "new_pool_datum": _pool_datum_dict(model, ctx.new_pool_datum),
        "consumed_policy_datum": _policy_datum_dict(
            model, ctx.consumed_policy_datum
        ),
        "redeemer": {"payout": _eval_int(model, ctx.redeemer.payout)},
        "own_input_lovelace": _eval_int(model, ctx.own_input_lovelace),
        "cont_output_lovelace": _eval_int(model, ctx.cont_output_lovelace),
        "own_pool_script_hash": _eval_int(model, ctx.own_pool_script_hash),
        "consts": _consts_dict(model, ctx.consts),
    }


def _add_liquidity_dict(
    model: ModelRef, ctx: SymbolicAddLiquidityContext
) -> dict:
    return {
        "old_pool_datum": _pool_datum_dict(model, ctx.old_pool_datum),
        "new_pool_datum": _pool_datum_dict(model, ctx.new_pool_datum),
        "redeemer": {"amount": _eval_int(model, ctx.redeemer.amount)},
        "own_input_lovelace": _eval_int(model, ctx.own_input_lovelace),
        "cont_output_lovelace": _eval_int(model, ctx.cont_output_lovelace),
        "mint_lp_qty": _eval_int(model, ctx.mint_lp_qty),
        "consts": _consts_dict(model, ctx.consts),
    }


def _remove_liquidity_dict(
    model: ModelRef, ctx: SymbolicRemoveLiquidityContext
) -> dict:
    return {
        "old_pool_datum": _pool_datum_dict(model, ctx.old_pool_datum),
        "new_pool_datum": _pool_datum_dict(model, ctx.new_pool_datum),
        "redeemer": {"amount": _eval_int(model, ctx.redeemer.amount)},
        "own_input_lovelace": _eval_int(model, ctx.own_input_lovelace),
        "cont_output_lovelace": _eval_int(model, ctx.cont_output_lovelace),
        "mint_lp_qty": _eval_int(model, ctx.mint_lp_qty),
        "consts": _consts_dict(model, ctx.consts),
    }


def _accept_cancellation_dict(
    model: ModelRef, ctx: SymbolicAcceptCancellationContext
) -> dict:
    return {
        "old_pool_datum": _pool_datum_dict(model, ctx.old_pool_datum),
        "new_pool_datum": _pool_datum_dict(model, ctx.new_pool_datum),
        "consumed_policy_datum": _policy_datum_dict(
            model, ctx.consumed_policy_datum
        ),
        "own_input_lovelace": _eval_int(model, ctx.own_input_lovelace),
        "cont_output_lovelace": _eval_int(model, ctx.cont_output_lovelace),
        "team_output_lovelace": _eval_int(model, ctx.team_output_lovelace),
        "partner_output_lovelace": _eval_int(
            model, ctx.partner_output_lovelace
        ),
        "own_pool_script_hash": _eval_int(model, ctx.own_pool_script_hash),
        "treasury_donation": _treasury_donation_dict(
            model, ctx.treasury_donation
        ),
        "consts": _consts_dict(model, ctx.consts),
    }


def _batch_underwrite_dict(
    model: ModelRef, ctx: SymbolicBatchUnderwriteContext
) -> dict:
    b = ctx.batch_totals
    return {
        "old_pool_datum": _pool_datum_dict(model, ctx.old_pool_datum),
        "new_pool_datum": _pool_datum_dict(model, ctx.new_pool_datum),
        "redeemer": {
            "total_coverage": _eval_int(model, ctx.redeemer.total_coverage),
            "total_premium": _eval_int(model, ctx.redeemer.total_premium),
        },
        "own_input_lovelace": _eval_int(model, ctx.own_input_lovelace),
        "cont_output_lovelace": _eval_int(model, ctx.cont_output_lovelace),
        "team_output_lovelace": _eval_int(model, ctx.team_output_lovelace),
        "own_pool_script_hash": _eval_int(model, ctx.own_pool_script_hash),
        "batch_totals": {
            "cov_sum": _eval_int(model, b.cov_sum),
            "prem_sum": _eval_int(model, b.prem_sum),
            "fee_total_sum": _eval_int(model, b.fee_total_sum),
            "team_total": _eval_int(model, b.team_total),
            "partner_totals_sum": _eval_int(model, b.partner_totals_sum),
            "funded_ok": _eval_int(model, b.funded_ok),
            "shares_ok": _eval_int(model, b.shares_ok),
            "partner_outputs_all_funded": _eval_int(
                model, b.partner_outputs_all_funded
            ),
            "aliased_partner_present": _eval_int(
                model, b.aliased_partner_present
            ),
        },
        "treasury_donation": _treasury_donation_dict(
            model, ctx.treasury_donation
        ),
        "consts": _consts_dict(model, ctx.consts),
    }


# Branch -> (encoder cls, ctx factory, dict-extractor)
BRANCH_GENERATORS: dict[
    str,
    tuple[type[BaseEncoder], Callable[[], Any], Callable[[ModelRef, Any], dict]],
] = {
    "Underwrite": (
        UnderwriteEncoder,
        fresh_underwrite_context,
        _underwrite_dict,
    ),
    "ProcessClaim": (
        ProcessClaimEncoder,
        fresh_process_claim_context,
        _process_claim_dict,
    ),
    "AddLiquidity": (
        AddLiquidityEncoder,
        fresh_add_liquidity_context,
        _add_liquidity_dict,
    ),
    "RemoveLiquidity": (
        RemoveLiquidityEncoder,
        fresh_remove_liquidity_context,
        _remove_liquidity_dict,
    ),
    "AcceptCancellation": (
        AcceptCancellationEncoder,
        fresh_accept_cancellation_context,
        _accept_cancellation_dict,
    ),
    "BatchUnderwrite": (
        BatchUnderwriteEncoder,
        fresh_batch_underwrite_context,
        _batch_underwrite_dict,
    ),
}


def model_to_fixture(branch: str, model: ModelRef, ctx) -> dict:
    """Extract a concrete fixture dict from a Z3 model.

    Returns a dict matching `tests/fixtures/<branch>_positive.json`
    shape so the existing `_pinning.py` helpers can rebind it.
    """
    if branch not in BRANCH_GENERATORS:
        raise ValueError(
            f"Unknown branch '{branch}'. Available: {sorted(BRANCH_GENERATORS)}"
        )
    _, _, extractor = BRANCH_GENERATORS[branch]
    return extractor(model, ctx)


# ---------------------------------------------------------------------------
# Sampling: turn the encoder's constraint space into N concrete inputs
# ---------------------------------------------------------------------------


def _diversity_constraints(
    branch: str, ctx, seed: int
) -> list[BoolRef]:
    """Add random-but-bounded pins to make the model interesting.

    Z3 will return the same "simplest" model on every call. To get
    differentiated random inputs, we pin a handful of free fields to
    small random values drawn from a deterministic seed. The encoder's
    guards then constrain the rest.

    These pins are CONSERVATIVE — we never pin a variable in a way that
    contradicts the encoder. The encoder + protocol pins always win.
    """
    rng = random.Random(seed)
    pins: list[BoolRef] = []

    # Pool / policy identities (pure symbolic Ints — no semantic
    # constraint other than equality elsewhere).
    pool_nft = rng.randint(1, 10**9)
    lp_policy = rng.randint(1, 10**9)
    insured = rng.randint(1, 10**9)
    policy_id = rng.randint(1, 10**9)
    strike = rng.randint(1, 10**9)
    oracle_nft = rng.randint(1, 10**9)
    # Validity range: start_time must lie in [lb, ub] (policy_match guard).
    lb = rng.randint(1_700_000_000_000, 1_700_000_050_000)
    ub = lb + rng.randint(100_000, 600_000)
    start_time = rng.randint(lb, ub)
    expiry = ub + rng.randint(60_000_000, 100_000_000_000)

    # Pool starting liquidity / active. Keep bounded to avoid silly
    # 10**18 numbers that slow Z3.
    starting_total = rng.randint(10_000_000_000, 1_000_000_000_000)
    starting_active = rng.randint(0, starting_total // 2)
    lp_supply = rng.randint(1_000_000_000, 10**12)

    # Address ids — small distinct values for differential clarity.
    team_id = rng.randint(1, 1000)
    pool_id = team_id + rng.randint(1, 1000)
    policy_hash = pool_id + rng.randint(1, 1000)

    op = ctx.old_pool_datum
    pins.extend(
        [
            op.pool_nft == pool_nft,
            op.lp_token_policy == lp_policy,
            op.total_liquidity == starting_total,
            op.active_coverage == starting_active,
            op.lp_supply == lp_supply,
            op.protocol_fee_bps == PROTOCOL_FEE_BPS_DEFAULT,
        ]
    )

    # Branch-specific diversity pins.
    if branch in ("Underwrite",):
        # Coverage and premium — drive these from the seed so each
        # sample explores a different point in the (coverage, premium)
        # surface. Use a bias toward the "non-degenerate" regime so
        # the encoder routinely finds a satisfying assignment.
        premium = rng.randint(MIN_PREMIUM_PREPROD, 100_000_000_000)
        # coverage <= premium * 50, leave headroom
        coverage_cap = max(1, premium * 49)
        coverage = rng.randint(1, min(coverage_cap, 100_000_000_000))
        # Ensure can_underwrite holds: liquidity available >= coverage.
        # We can't pin if it conflicts; just SUGGEST via pool_id pins:
        pins.extend(
            [
                ctx.redeemer.premium == premium,
                ctx.redeemer.coverage == coverage,
                ctx.consts.team_address_id == team_id,
                ctx.consts.pool_address_id == pool_id,
                ctx.consts.policy_script_hash == policy_hash,
                ctx.new_policy_datum.policy_id == policy_id,
                ctx.new_policy_datum.insured == insured,
                ctx.new_policy_datum.strike_price == strike,
                ctx.new_policy_datum.oracle_nft == oracle_nft,
                ctx.new_policy_datum.expiry_time == expiry,
                ctx.new_policy_datum.start_time == start_time,
                ctx.validity_range.lb == lb,
                ctx.validity_range.ub == ub,
            ]
        )

    elif branch == "ProcessClaim":
        # Payout drives everything; coverage_amount must equal payout
        # (policy_consumed guard).
        coverage = rng.randint(MIN_UTXO_LOVELACE, max(MIN_UTXO_LOVELACE + 1, starting_active))
        pins.extend(
            [
                ctx.redeemer.payout == coverage,
                ctx.consumed_policy_datum.policy_id == policy_id,
                ctx.consumed_policy_datum.insured == insured,
                ctx.consumed_policy_datum.strike_price == strike,
                ctx.consumed_policy_datum.oracle_nft == oracle_nft,
                ctx.consumed_policy_datum.expiry_time == expiry,
                ctx.consumed_policy_datum.start_time == start_time,
                ctx.consts.team_address_id == team_id,
                ctx.consts.pool_address_id == pool_id,
                ctx.consts.policy_script_hash == policy_hash,
            ]
        )

    elif branch == "AddLiquidity":
        # Pin lp_supply == total so calculate_lp_mint mints amount 1:1
        # (avoids integer-division residue UNSAT).
        pins = []
        pins.extend(
            [
                op.pool_nft == pool_nft,
                op.lp_token_policy == lp_policy,
                op.total_liquidity == starting_total,
                op.active_coverage == starting_active,
                op.lp_supply == starting_total,
                op.protocol_fee_bps == PROTOCOL_FEE_BPS_DEFAULT,
            ]
        )
        amount = rng.randint(MIN_UTXO_LOVELACE, 100_000_000_000)
        pins.extend(
            [
                ctx.redeemer.amount == amount,
                ctx.consts.team_address_id == team_id,
                ctx.consts.pool_address_id == pool_id,
                ctx.consts.policy_script_hash == policy_hash,
            ]
        )

    elif branch == "RemoveLiquidity":
        # withdrawal_safe: total - amount >= active.
        # The encoder also requires `lp_burned * total / lp_supply ==
        # amount`. To keep integer divisibility tractable we pin
        # lp_supply = total (1:1 ratio), so lp_burned = amount.
        pins = [p for p in pins if p is not (op.lp_supply == lp_supply)]
        # Remove the prior lp_supply pin and re-add as 1:1.
        # (Defensive: simpler to overwrite by appending equality —
        # Z3 will reject as UNSAT if both pins conflict, so we
        # rebuild without the original.)
        # Rebuild from scratch for this branch:
        pins = []
        pins.extend(
            [
                op.pool_nft == pool_nft,
                op.lp_token_policy == lp_policy,
                op.total_liquidity == starting_total,
                op.active_coverage == starting_active,
                op.lp_supply == starting_total,  # 1:1
                op.protocol_fee_bps == PROTOCOL_FEE_BPS_DEFAULT,
            ]
        )
        headroom = max(1, starting_total - starting_active - 1)
        amount = rng.randint(MIN_UTXO_LOVELACE, max(MIN_UTXO_LOVELACE + 1, headroom))
        pins.extend(
            [
                ctx.redeemer.amount == amount,
                ctx.consts.team_address_id == team_id,
                ctx.consts.pool_address_id == pool_id,
                ctx.consts.policy_script_hash == policy_hash,
            ]
        )

    elif branch == "AcceptCancellation":
        coverage = rng.randint(MIN_UTXO_LOVELACE, max(MIN_UTXO_LOVELACE + 1, starting_active))
        premium = rng.randint(MIN_PREMIUM_PREPROD, max(MIN_PREMIUM_PREPROD + 1, coverage))
        pins.extend(
            [
                ctx.consumed_policy_datum.coverage_amount == coverage,
                ctx.consumed_policy_datum.premium_paid == premium,
                ctx.consumed_policy_datum.policy_id == policy_id,
                ctx.consumed_policy_datum.insured == insured,
                ctx.consumed_policy_datum.strike_price == strike,
                ctx.consumed_policy_datum.oracle_nft == oracle_nft,
                ctx.consumed_policy_datum.expiry_time == expiry,
                ctx.consumed_policy_datum.start_time == start_time,
                ctx.consts.team_address_id == team_id,
                ctx.consts.pool_address_id == pool_id,
                ctx.consts.policy_script_hash == policy_hash,
            ]
        )

    elif branch == "BatchUnderwrite":
        # Pick a sensible aggregate that lives in the "shares_ok &&
        # funded_ok" regime; the encoder will then pin the value-flow.
        total_premium = rng.randint(MIN_PREMIUM_PREPROD * 2, 10_000_000_000)
        total_coverage = rng.randint(1, total_premium * 50)
        pins.extend(
            [
                ctx.redeemer.total_premium == total_premium,
                ctx.redeemer.total_coverage == total_coverage,
                ctx.consts.team_address_id == team_id,
                ctx.consts.pool_address_id == pool_id,
                ctx.consts.policy_script_hash == policy_hash,
            ]
        )

    return pins


def sample_satisfying_assignment(
    branch: str,
    seed: int,
    extra_constraints: Iterable[BoolRef] = (),
    address_distinctness: bool = False,
) -> tuple[ModelRef | None, Any]:
    """Sample ONE satisfying assignment from the encoder's constraint
    space, randomised by `seed`.

    Returns (model, ctx). If the diversity pins make the encoder UNSAT
    (no satisfying assignment exists under those random pins), returns
    (None, ctx). Callers should retry with a fresh seed.

    `extra_constraints` lets the caller add a property (or its
    negation) before sampling so the model also satisfies that
    constraint.
    """
    if branch not in BRANCH_GENERATORS:
        raise ValueError(f"Unknown branch '{branch}'")

    encoder_cls, ctx_factory, _ = BRANCH_GENERATORS[branch]
    ctx = ctx_factory()
    encoder = encoder_cls()

    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    if address_distinctness:
        c_consts = ctx.consts
        solver.add(c_consts.team_address_id != c_consts.pool_address_id)
        solver.add(c_consts.team_address_id != c_consts.policy_script_hash)
        solver.add(c_consts.pool_address_id != c_consts.policy_script_hash)
    for c in _diversity_constraints(branch, ctx, seed):
        solver.add(c)
    for c in extra_constraints:
        solver.add(c)

    result = solver.check()
    if result != sat:
        return None, ctx
    return solver.model(), ctx


def generate_concrete_fixture(
    branch: str,
    seed: int,
    address_distinctness: bool = False,
) -> dict | None:
    """One-shot: build a fully concrete fixture dict for `branch`.

    Returns None if the diversity pins conflict with the encoder
    (caller should retry with a fresh seed).
    """
    model, ctx = sample_satisfying_assignment(
        branch, seed, address_distinctness=address_distinctness
    )
    if model is None:
        return None
    return model_to_fixture(branch, model, ctx)
