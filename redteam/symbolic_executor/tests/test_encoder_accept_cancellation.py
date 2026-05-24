"""AcceptCancellationEncoder unit tests + differential against JSON fixtures."""

from __future__ import annotations

import pytest
from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_accept_cancellation_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import AcceptCancellationEncoder

from ._pinning import pin_accept_cancellation_ctx


def test_encoder_lists_all_expected_guards():
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder()
    guards = encoder.all_guard_names(ctx)
    assert set(guards) == set(AcceptCancellationEncoder.GUARD_NAMES)
    assert tuple(guards) == AcceptCancellationEncoder.GUARD_NAMES


def test_encoder_disable_unknown_guard_raises():
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder(disable_guards={"nope"})
    with pytest.raises(ValueError):
        encoder.encode(ctx)


def test_encoder_accepts_positive_fixture(accept_cancellation_positive):
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_accept_cancellation_ctx(ctx, accept_cancellation_positive):
        solver.add(c)
    assert solver.check() == sat, (
        "Positive AcceptCancellation fixture must be accepted. "
        "If this fails, either the fixture has drifted from the Aiken "
        "branch or the encoder is over-constraining."
    )


def test_encoder_rejects_each_negative_fixture(accept_cancellation_negatives):
    assert accept_cancellation_negatives, "expected at least one negative fixture"
    for fx in accept_cancellation_negatives:
        ctx = fresh_accept_cancellation_context()
        encoder = AcceptCancellationEncoder()
        solver = Solver()
        for c in encoder.encode(ctx):
            solver.add(c)
        for c in pin_accept_cancellation_ctx(ctx, fx):
            solver.add(c)
        result = solver.check()
        assert result == unsat, (
            f"Negative fixture (_violates={fx['_violates']!r}) should be "
            f"REJECTED, but got {result}."
        )


def test_disabling_violated_guard_recovers_acceptance(
    accept_cancellation_negatives,
):
    for fx in accept_cancellation_negatives:
        violated = fx["_violates"]
        ctx = fresh_accept_cancellation_context()
        encoder = AcceptCancellationEncoder(disable_guards={violated})
        solver = Solver()
        for c in encoder.encode(ctx):
            solver.add(c)
        for c in pin_accept_cancellation_ctx(ctx, fx):
            solver.add(c)
        result = solver.check()
        assert result == sat, (
            f"With guard {violated!r} disabled, the negative fixture "
            f"should be accepted - but got {result}."
        )


def test_intermediates_pin_refund_and_fee_on_positive_fixture(
    accept_cancellation_positive,
):
    """On the positive fixture, hand-computed refund/fee/team-cut hold."""
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_accept_cancellation_ctx(ctx, accept_cancellation_positive):
        solver.add(c)
    assert solver.check() == sat
    model = solver.model()
    inter = encoder._intermediates_for(ctx)
    # premium_paid=500M → cancellation_fee=50M, refund=450M.
    assert model.eval(inter.cancellation_fee).as_long() == 50_000_000
    assert model.eval(inter.refund_amount).as_long() == 450_000_000
    # raw_fee_cancel = 50M * 200 / 10000 = 1M → fee_total_cancel = max(2M, 1M) = 2M.
    assert model.eval(inter.raw_fee_cancel).as_long() == 1_000_000
    assert model.eval(inter.fee_total_cancel).as_long() == 2_000_000
    # No partner → team_cut == fee_total_cancel.
    assert model.eval(inter.partner_cut).as_long() == 0
    assert model.eval(inter.team_cut).as_long() == 2_000_000
    # required_donation = 50M * 200/10000 * 2500/10000 = 1M * 2500 / 10000 = 250K.
    assert model.eval(inter.required_donation).as_long() == 250_000
    # pool_delta = refund + fee_total_cancel = 452M.
    assert model.eval(inter.pool_delta).as_long() == 452_000_000
