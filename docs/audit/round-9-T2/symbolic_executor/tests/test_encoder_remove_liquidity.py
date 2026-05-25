"""RemoveLiquidityEncoder unit tests + differential against JSON fixtures."""

from __future__ import annotations

import pytest
from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_remove_liquidity_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import RemoveLiquidityEncoder

from ._pinning import pin_remove_liquidity_ctx


def test_encoder_lists_all_expected_guards():
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder()
    guards = encoder.all_guard_names(ctx)
    assert set(guards) == set(RemoveLiquidityEncoder.GUARD_NAMES)
    assert tuple(guards) == RemoveLiquidityEncoder.GUARD_NAMES


def test_encoder_disable_unknown_guard_raises():
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder(disable_guards={"nope"})
    with pytest.raises(ValueError):
        encoder.encode(ctx)


def test_encoder_accepts_positive_fixture(remove_liquidity_positive):
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_remove_liquidity_ctx(ctx, remove_liquidity_positive):
        solver.add(c)
    assert solver.check() == sat


def test_encoder_rejects_each_negative_fixture(remove_liquidity_negatives):
    assert remove_liquidity_negatives, "expected at least one negative fixture"
    for fx in remove_liquidity_negatives:
        ctx = fresh_remove_liquidity_context()
        encoder = RemoveLiquidityEncoder()
        solver = Solver()
        for c in encoder.encode(ctx):
            solver.add(c)
        for c in pin_remove_liquidity_ctx(ctx, fx):
            solver.add(c)
        result = solver.check()
        assert result == unsat, (
            f"Negative fixture (_violates={fx['_violates']!r}) should be "
            f"REJECTED, but got {result}."
        )


def test_disabling_violated_guard_recovers_acceptance(remove_liquidity_negatives):
    for fx in remove_liquidity_negatives:
        violated = fx["_violates"]
        ctx = fresh_remove_liquidity_context()
        encoder = RemoveLiquidityEncoder(disable_guards={violated})
        solver = Solver()
        for c in encoder.encode(ctx):
            solver.add(c)
        for c in pin_remove_liquidity_ctx(ctx, fx):
            solver.add(c)
        result = solver.check()
        assert result == sat, (
            f"With guard {violated!r} disabled, the negative fixture "
            f"should be accepted - but got {result}."
        )


def test_intermediates_pin_lp_burned_on_positive_fixture(
    remove_liquidity_positive,
):
    """On the positive fixture, lp_burned == -mint_lp_qty == 500_000_000."""
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_remove_liquidity_ctx(ctx, remove_liquidity_positive):
        solver.add(c)
    assert solver.check() == sat
    model = solver.model()
    inter = encoder._intermediates_for(ctx)
    assert model.eval(inter.lp_burned).as_long() == 500_000_000
    assert model.eval(inter.expected_withdrawal).as_long() == 500_000_000
    assert model.eval(inter.pool_delta).as_long() == -500_000_000
