"""AddLiquidityEncoder unit tests + differential against JSON fixtures."""

from __future__ import annotations

import pytest
from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_add_liquidity_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import AddLiquidityEncoder

from ._pinning import pin_add_liquidity_ctx


def test_encoder_lists_all_expected_guards():
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder()
    guards = encoder.all_guard_names(ctx)
    assert set(guards) == set(AddLiquidityEncoder.GUARD_NAMES)
    assert tuple(guards) == AddLiquidityEncoder.GUARD_NAMES


def test_encoder_disable_unknown_guard_raises():
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder(disable_guards={"nope"})
    with pytest.raises(ValueError):
        encoder.encode(ctx)


def test_encoder_accepts_positive_fixture(add_liquidity_positive):
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_add_liquidity_ctx(ctx, add_liquidity_positive):
        solver.add(c)
    assert solver.check() == sat


def test_encoder_rejects_each_negative_fixture(add_liquidity_negatives):
    assert add_liquidity_negatives, "expected at least one negative fixture"
    for fx in add_liquidity_negatives:
        ctx = fresh_add_liquidity_context()
        encoder = AddLiquidityEncoder()
        solver = Solver()
        for c in encoder.encode(ctx):
            solver.add(c)
        for c in pin_add_liquidity_ctx(ctx, fx):
            solver.add(c)
        result = solver.check()
        assert result == unsat, (
            f"Negative fixture (_violates={fx['_violates']!r}) should be "
            f"REJECTED, but got {result}."
        )


def test_disabling_violated_guard_recovers_acceptance(add_liquidity_negatives):
    for fx in add_liquidity_negatives:
        violated = fx["_violates"]
        ctx = fresh_add_liquidity_context()
        encoder = AddLiquidityEncoder(disable_guards={violated})
        solver = Solver()
        for c in encoder.encode(ctx):
            solver.add(c)
        for c in pin_add_liquidity_ctx(ctx, fx):
            solver.add(c)
        result = solver.check()
        assert result == sat, (
            f"With guard {violated!r} disabled, the negative fixture "
            f"should be accepted - but got {result}."
        )


def test_intermediates_pin_lp_minted_on_positive_fixture(add_liquidity_positive):
    """On the positive fixture, lp_minted should equal `amount` (1:1 pool)."""
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_add_liquidity_ctx(ctx, add_liquidity_positive):
        solver.add(c)
    assert solver.check() == sat
    model = solver.model()
    inter = encoder._intermediates_for(ctx)
    # 500_000_000 amount, 100B/100B pool (1:1) -> lp_minted = 500_000_000.
    assert model.eval(inter.lp_minted).as_long() == 500_000_000
    assert model.eval(inter.pool_delta).as_long() == 500_000_000
