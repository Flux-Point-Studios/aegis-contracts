"""ProcessClaimEncoder unit tests + differential against JSON fixtures.

Methodology mirrors `test_encoder_underwrite.py` for the Underwrite
branch — see that file's docstring for the rubric.

Differential layer: each negative fixture violates EXACTLY ONE guard
and names it in `_violates`. The test pair asserts:

  1. With the full encoder: UNSAT (= encoder REJECTS).
  2. With ONLY that guard disabled: SAT (= encoder would ACCEPT if
     not for that guard). This is the load-bearing PROOF at the
     fixture layer.
"""

from __future__ import annotations

import pytest
from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_process_claim_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import ProcessClaimEncoder

from ._pinning import pin_process_claim_ctx


def test_encoder_lists_all_expected_guards():
    """The encoder MUST expose all 6 guards from `GUARD_NAMES`."""
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder()
    guards = encoder.all_guard_names(ctx)
    assert set(guards) == set(ProcessClaimEncoder.GUARD_NAMES)
    assert tuple(guards) == ProcessClaimEncoder.GUARD_NAMES


def test_encoder_disable_unknown_guard_raises():
    """Typos in `disable_guards` are surfaced loudly."""
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder(disable_guards={"this_guard_does_not_exist"})
    with pytest.raises(ValueError):
        encoder.encode(ctx)


def test_encoder_accepts_positive_fixture(process_claim_positive):
    """The known-good positive ProcessClaim fixture MUST satisfy ALL guards."""
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_process_claim_ctx(ctx, process_claim_positive):
        solver.add(c)
    assert solver.check() == sat


def test_encoder_rejects_each_negative_fixture(process_claim_negatives):
    """Each negative fixture MUST be rejected by the encoder."""
    assert process_claim_negatives, "expected at least one negative fixture"
    for fx in process_claim_negatives:
        ctx = fresh_process_claim_context()
        encoder = ProcessClaimEncoder()
        solver = Solver()
        for c in encoder.encode(ctx):
            solver.add(c)
        for c in pin_process_claim_ctx(ctx, fx):
            solver.add(c)
        result = solver.check()
        assert result == unsat, (
            f"Negative fixture (_violates={fx['_violates']!r}) should be "
            f"REJECTED by the encoder, but got {result}."
        )


def test_disabling_violated_guard_recovers_acceptance(process_claim_negatives):
    """For each negative fixture, disabling ONLY the violated guard
    should turn UNSAT -> SAT (load-bearing proof at fixture layer)."""
    for fx in process_claim_negatives:
        violated = fx["_violates"]
        ctx = fresh_process_claim_context()
        encoder = ProcessClaimEncoder(disable_guards={violated})
        solver = Solver()
        for c in encoder.encode(ctx):
            solver.add(c)
        for c in pin_process_claim_ctx(ctx, fx):
            solver.add(c)
        result = solver.check()
        assert result == sat, (
            f"With guard {violated!r} disabled, the negative fixture "
            f"should be accepted - but got {result}."
        )


def test_intermediates_pin_pool_delta_on_positive_fixture(process_claim_positive):
    """On the positive fixture, pool_delta should equal payout (= 5000 ADA)."""
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_process_claim_ctx(ctx, process_claim_positive):
        solver.add(c)
    assert solver.check() == sat
    model = solver.model()
    inter = encoder._intermediates_for(ctx)
    assert model.eval(inter.pool_delta).as_long() == 5_000_000_000
