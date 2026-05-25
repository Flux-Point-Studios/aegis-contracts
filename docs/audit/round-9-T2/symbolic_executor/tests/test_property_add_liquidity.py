"""Property tests for the AddLiquidity branch."""

from __future__ import annotations

from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_add_liquidity_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import AddLiquidityEncoder
from symbolic_executor.properties import (
    ImmutablePoolDatumProperty,
    LpMintMatchesFormulaProperty,
    NoNegativePoolStateProperty,
    PoolConservationProperty,
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


def test_pool_conservation_proven_on_add_liquidity():
    """new_total - old_total == amount under the encoder."""
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder()
    solver = _solver_with(encoder, ctx)
    prop = PoolConservationProperty("AddLiquidity")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_pool_conservation_finds_counterexample_when_datum_ok_disabled():
    """Drop `datum_ok` -> new_total no longer pinned to old_total + amount."""
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder(disable_guards={"datum_ok"})
    solver = _solver_with(encoder, ctx)
    prop = PoolConservationProperty("AddLiquidity")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# no_negative_pool_state
# ---------------------------------------------------------------------------


def test_no_negative_pool_state_proven_on_add_liquidity():
    """AddLiquidity only INCREASES pool; pre-solvent stays non-negative."""
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder()
    solver = _solver_with(encoder, ctx)
    prop = NoNegativePoolStateProperty("AddLiquidity")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_no_negative_pool_state_finds_counterexample_when_amount_positive_disabled():
    """Drop `amount_positive` -> Z3 can pick amount < -old_total, breaking
    the post-state non-negativity. Also need to drop datum_ok so new_total
    isn't pinned to old_total + amount."""
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder(
        disable_guards={"amount_positive", "datum_ok"}
    )
    solver = _solver_with(encoder, ctx)
    prop = NoNegativePoolStateProperty("AddLiquidity")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# immutable_pool_datum (lp_supply ALLOWED to change here)
# ---------------------------------------------------------------------------


def test_immutable_pool_datum_proven_on_add_liquidity():
    """lp_token_policy / protocol_fee_bps / pool_nft preserved (NOT lp_supply)."""
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder()
    solver = _solver_with(encoder, ctx)
    prop = ImmutablePoolDatumProperty("AddLiquidity")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_immutable_pool_datum_finds_counterexample_when_immutable_ok_disabled():
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder(disable_guards={"immutable_ok"})
    solver = _solver_with(encoder, ctx)
    prop = ImmutablePoolDatumProperty("AddLiquidity")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# lp_mint_matches_formula  (branch-specific)
# ---------------------------------------------------------------------------


def test_lp_mint_matches_formula_proven_on_add_liquidity():
    """mint_qty == calculate_lp_mint(amount, old_total, old_lp_supply)."""
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder()
    solver = _solver_with(encoder, ctx)
    prop = LpMintMatchesFormulaProperty()
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_lp_mint_matches_formula_finds_counterexample_when_datum_ok_disabled():
    """Drop datum_ok -> new_lp_supply no longer tied to lp_minted formula;
    Z3 can pick a mint_qty that does NOT match calculate_lp_mint."""
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder(disable_guards={"datum_ok"})
    solver = _solver_with(encoder, ctx)
    prop = LpMintMatchesFormulaProperty()
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat
