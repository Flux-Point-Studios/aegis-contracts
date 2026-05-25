"""Immutable PoolDatum property tests (R8-DRAIN-1 family)."""

from __future__ import annotations

from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_underwrite_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import UnderwriteEncoder
from symbolic_executor.properties import ImmutablePoolDatumProperty


def _solver_with(encoder, ctx):
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    return solver


def test_immutable_pool_datum_proven_on_underwrite():
    ctx = fresh_underwrite_context()
    encoder = UnderwriteEncoder()
    solver = _solver_with(encoder, ctx)
    prop = ImmutablePoolDatumProperty()
    solver.add(prop.check(encoder, ctx))
    result = solver.check()
    assert result == unsat, (
        f"Immutable-PoolDatum must be PROVEN UNSAT, got {result}. "
        f"Model (if SAT): {solver.model() if result == sat else 'n/a'}"
    )


def test_immutable_pool_datum_finds_counterexample_when_immutable_ok_disabled():
    """Drop `immutable_ok` — Z3 should find a model where at least one
    of the four immutable fields changes."""
    ctx = fresh_underwrite_context()
    encoder = UnderwriteEncoder(disable_guards={"immutable_ok"})
    solver = _solver_with(encoder, ctx)
    prop = ImmutablePoolDatumProperty()
    solver.add(prop.check(encoder, ctx))
    result = solver.check()
    assert result == sat, (
        "Dropping `immutable_ok` should expose datum mutation. "
        f"Got {result}."
    )
    model = solver.model()
    d = ctx.old_pool_datum
    nd = ctx.new_pool_datum
    diffs = sum(
        1
        for (a, b) in [
            (d.lp_token_policy, nd.lp_token_policy),
            (d.protocol_fee_bps, nd.protocol_fee_bps),
            (d.pool_nft, nd.pool_nft),
            (d.lp_supply, nd.lp_supply),
        ]
        if model.eval(a).as_long() != model.eval(b).as_long()
    )
    assert diffs >= 1, "Counterexample should mutate at least one immutable field"
