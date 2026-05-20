"""Property tests for the RemoveLiquidity branch."""

from __future__ import annotations

from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_remove_liquidity_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import RemoveLiquidityEncoder
from symbolic_executor.properties import (
    ImmutablePoolDatumProperty,
    NoNegativePoolStateProperty,
    PoolConservationProperty,
    WithdrawalSafeProperty,
)


def _solver_with(encoder, ctx):
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    return solver


# ---------------------------------------------------------------------------
# pool_conservation
# ---------------------------------------------------------------------------


def test_pool_conservation_proven_on_remove_liquidity():
    """new_total - old_total == -amount."""
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder()
    solver = _solver_with(encoder, ctx)
    prop = PoolConservationProperty("RemoveLiquidity")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_pool_conservation_finds_counterexample_when_datum_ok_disabled():
    """Drop `datum_ok` -> new_total no longer pinned."""
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder(disable_guards={"datum_ok"})
    solver = _solver_with(encoder, ctx)
    prop = PoolConservationProperty("RemoveLiquidity")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# no_negative_pool_state
# ---------------------------------------------------------------------------


def test_no_negative_pool_state_proven_on_remove_liquidity():
    """Inductive: a solvent pre-state stays non-negative after RemoveLiquidity.

    Load-bearing guards: `amount_positive` (so amount > 0 bounds the
    withdrawal) and `withdrawal_safe` (so new_total >= old_active >= 0).
    """
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder()
    solver = _solver_with(encoder, ctx)
    prop = NoNegativePoolStateProperty("RemoveLiquidity")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_no_negative_pool_state_finds_counterexample_when_withdrawal_safe_disabled():
    """Drop `withdrawal_safe` -> Z3 can pick amount > old_total, driving
    new_total < 0."""
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder(disable_guards={"withdrawal_safe"})
    solver = _solver_with(encoder, ctx)
    prop = NoNegativePoolStateProperty("RemoveLiquidity")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# immutable_pool_datum (lp_supply ALLOWED to change here)
# ---------------------------------------------------------------------------


def test_immutable_pool_datum_proven_on_remove_liquidity():
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder()
    solver = _solver_with(encoder, ctx)
    prop = ImmutablePoolDatumProperty("RemoveLiquidity")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_immutable_pool_datum_finds_counterexample_when_immutable_ok_disabled():
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder(disable_guards={"immutable_ok"})
    solver = _solver_with(encoder, ctx)
    prop = ImmutablePoolDatumProperty("RemoveLiquidity")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# withdrawal_safe  (branch-specific)
# ---------------------------------------------------------------------------


def test_withdrawal_safe_proven_on_remove_liquidity():
    """new_total >= new_active under a solvent pre-state."""
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder()
    solver = _solver_with(encoder, ctx)
    prop = WithdrawalSafeProperty()
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_withdrawal_safe_finds_counterexample_when_withdrawal_safe_disabled():
    """Drop `withdrawal_safe` -> Z3 can pick amount > old_total - old_active."""
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder(disable_guards={"withdrawal_safe"})
    solver = _solver_with(encoder, ctx)
    prop = WithdrawalSafeProperty()
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat
