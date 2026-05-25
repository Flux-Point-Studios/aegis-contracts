"""No-negative-active-coverage property tests.

Safety claim: 0 <= new_active_coverage <= new_total_liquidity.

Load-bearing guards: `coverage_positive` (negative coverage drives
active_coverage negative through verify_underwrite_datum) and
`can_cover` (without it, new_active can exceed new_total).
"""

from __future__ import annotations

from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_underwrite_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import UnderwriteEncoder
from symbolic_executor.properties import NoNegativeActiveCoverageProperty


def _solver_with(encoder, ctx):
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    return solver


def test_no_negative_active_coverage_proven_on_underwrite():
    ctx = fresh_underwrite_context()
    encoder = UnderwriteEncoder()
    solver = _solver_with(encoder, ctx)
    prop = NoNegativeActiveCoverageProperty()
    solver.add(prop.check(encoder, ctx))
    result = solver.check()
    assert result == unsat, (
        f"Active-coverage range must be PROVEN UNSAT, got {result}. "
        f"Model (if SAT): {solver.model() if result == sat else 'n/a'}"
    )


def test_no_negative_active_coverage_finds_counterexample_when_coverage_positive_disabled():
    """Drop `coverage_positive` — Z3 should find a model with negative
    coverage, driving new_active_coverage below zero.

    Note: simply dropping `coverage_positive` is not enough on its own
    because `premium_ok` (= `is_premium_adequate`) ALSO bounds
    `coverage <= premium * 50` from above but NOT from below. Negative
    coverage satisfies `coverage <= premium * 50`. So the counter-
    example requires only this single drop.
    """
    ctx = fresh_underwrite_context()
    encoder = UnderwriteEncoder(disable_guards={"coverage_positive"})
    solver = _solver_with(encoder, ctx)
    prop = NoNegativeActiveCoverageProperty()
    solver.add(prop.check(encoder, ctx))
    result = solver.check()
    assert result == sat, (
        "Dropping `coverage_positive` should expose the A-024 exploit "
        f"(negative coverage → negative new_active). Got {result}."
    )
    model = solver.model()
    coverage = model.eval(ctx.redeemer.coverage).as_long()
    new_active = model.eval(ctx.new_pool_datum.active_coverage).as_long()
    # The counterexample must EITHER have coverage < 0 (driving active
    # negative) or new_active > new_total. Both are valid violations.
    assert (
        coverage < 0
        or new_active < 0
        or new_active
        > model.eval(ctx.new_pool_datum.total_liquidity).as_long()
    ), (
        f"Counterexample shape unexpected: coverage={coverage}, "
        f"new_active={new_active}"
    )


def test_no_negative_active_coverage_finds_counterexample_when_can_cover_disabled():
    """Drop `can_cover` — Z3 should find a model where new_active >
    new_total (insolvency)."""
    ctx = fresh_underwrite_context()
    encoder = UnderwriteEncoder(disable_guards={"can_cover"})
    solver = _solver_with(encoder, ctx)
    prop = NoNegativeActiveCoverageProperty()
    solver.add(prop.check(encoder, ctx))
    result = solver.check()
    assert result == sat, (
        "Dropping `can_cover` should expose insolvency: a coverage "
        f"large enough to push new_active > new_total. Got {result}."
    )
