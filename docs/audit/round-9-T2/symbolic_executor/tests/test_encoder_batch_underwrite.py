"""BatchUnderwriteEncoder unit tests + differential against JSON fixtures.

SCOPE: this encoder lifts the per-policy list-walker to aggregate
scalars (see `encoders/batch_underwrite.py` module docstring). The
fixtures provide aggregate values for `batch_totals` directly — they
do NOT encode individual policies. The R8-DRAIN-1 alias test uses
the `aliased_partner_present` aggregate flag.
"""

from __future__ import annotations

import pytest
from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_batch_underwrite_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import BatchUnderwriteEncoder

from ._pinning import pin_batch_underwrite_ctx


def test_encoder_lists_all_expected_guards():
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder()
    guards = encoder.all_guard_names(ctx)
    assert set(guards) == set(BatchUnderwriteEncoder.GUARD_NAMES)
    assert tuple(guards) == BatchUnderwriteEncoder.GUARD_NAMES


def test_encoder_disable_unknown_guard_raises():
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder(disable_guards={"nope"})
    with pytest.raises(ValueError):
        encoder.encode(ctx)


def test_encoder_accepts_positive_fixture(batch_underwrite_positive):
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_batch_underwrite_ctx(ctx, batch_underwrite_positive):
        solver.add(c)
    assert solver.check() == sat


def test_encoder_rejects_each_negative_fixture(batch_underwrite_negatives):
    assert batch_underwrite_negatives, "expected at least one negative fixture"
    for fx in batch_underwrite_negatives:
        ctx = fresh_batch_underwrite_context()
        encoder = BatchUnderwriteEncoder()
        solver = Solver()
        for c in encoder.encode(ctx):
            solver.add(c)
        for c in pin_batch_underwrite_ctx(ctx, fx):
            solver.add(c)
        result = solver.check()
        assert result == unsat, (
            f"Negative fixture (_violates={fx['_violates']!r}) should be "
            f"REJECTED, but got {result}."
        )


def test_disabling_violated_guard_recovers_acceptance(batch_underwrite_negatives):
    for fx in batch_underwrite_negatives:
        violated = fx["_violates"]
        ctx = fresh_batch_underwrite_context()
        encoder = BatchUnderwriteEncoder(disable_guards={violated})
        solver = Solver()
        for c in encoder.encode(ctx):
            solver.add(c)
        for c in pin_batch_underwrite_ctx(ctx, fx):
            solver.add(c)
        result = solver.check()
        assert result == sat, (
            f"With guard {violated!r} disabled, the negative fixture "
            f"should be accepted - but got {result}."
        )


def test_intermediates_pin_net_pool_growth_on_positive_fixture(
    batch_underwrite_positive,
):
    """On the positive fixture, net_pool_growth == 2450 ADA."""
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_batch_underwrite_ctx(ctx, batch_underwrite_positive):
        solver.add(c)
    assert solver.check() == sat
    model = solver.model()
    inter = encoder._intermediates_for(ctx)
    # total_premium = 2500M, fee_total_sum = 50M -> net = 2450M.
    assert model.eval(inter.net_pool_growth).as_long() == 2_450_000_000
    assert model.eval(inter.pool_delta).as_long() == 2_450_000_000
    # required_donation = 2500M * 200/10000 * 2500/10000 = 50M * 2500 / 10000 = 12.5M.
    assert model.eval(inter.required_donation).as_long() == 12_500_000
