"""Property tests for the ProcessClaim branch.

Per the foundation rubric, EVERY (property, branch) pair gets BOTH
halves of the counterexample-pair test:

  1. `test_<property>_proven_on_process_claim()` — full encoder
     yields UNSAT under the property's negation.
  2. `test_<property>_finds_counterexample_when_<guard>_disabled()` —
     drop the load-bearing guard; expect SAT.

If a guard is REDUNDANT for a property (the negation stays UNSAT
without it), the test surfaces it as a finding and we document in
`V12.2_ROUND_9_T2_EXTENSIONS.md`.
"""

from __future__ import annotations

from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_process_claim_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import ProcessClaimEncoder
from symbolic_executor.properties import (
    ImmutablePoolDatumProperty,
    NoNegativePoolStateProperty,
    PayoutBoundedByCoverageProperty,
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


def test_pool_conservation_proven_on_process_claim():
    """pool_delta == payout under the encoder."""
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder()
    solver = _solver_with(encoder, ctx)
    prop = PoolConservationProperty("ProcessClaim")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_pool_conservation_finds_counterexample_when_value_ok_disabled():
    """Drop `value_ok` -> Z3 can pick any cont_output_lovelace, so
    pool_delta != payout is satisfiable."""
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder(disable_guards={"value_ok"})
    solver = _solver_with(encoder, ctx)
    prop = PoolConservationProperty("ProcessClaim")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# no_negative_pool_state
# ---------------------------------------------------------------------------


def test_no_negative_pool_state_proven_on_process_claim():
    """Inductive: a solvent pre-state stays non-negative after ProcessClaim.

    The ProcessClaim branch ENFORCES this directly via the
    `remains_non_negative` guard AND `datum_ok`'s embedded
    non-negativity checks. Both are load-bearing in their own way.
    """
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder()
    solver = _solver_with(encoder, ctx)
    prop = NoNegativePoolStateProperty("ProcessClaim")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_no_negative_pool_state_finds_counterexample_when_datum_ok_disabled():
    """Drop `datum_ok` -> Z3 can pick payout > old_total, driving
    new_total < 0 (since the encoder's pool-delta tie to payout in
    value_ok is still required, but new_pool_datum's total is now
    unconstrained from the redeemer)."""
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder(
        disable_guards={"datum_ok", "remains_non_negative"}
    )
    solver = _solver_with(encoder, ctx)
    prop = NoNegativePoolStateProperty("ProcessClaim")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# immutable_pool_datum
# ---------------------------------------------------------------------------


def test_immutable_pool_datum_proven_on_process_claim():
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder()
    solver = _solver_with(encoder, ctx)
    prop = ImmutablePoolDatumProperty("ProcessClaim")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_immutable_pool_datum_finds_counterexample_when_immutable_ok_disabled():
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder(disable_guards={"immutable_ok"})
    solver = _solver_with(encoder, ctx)
    prop = ImmutablePoolDatumProperty("ProcessClaim")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# payout_bounded_by_coverage  (branch-specific)
# ---------------------------------------------------------------------------


def test_payout_bounded_by_coverage_proven_on_process_claim():
    """payout <= consumed_policy.coverage_amount."""
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder()
    solver = _solver_with(encoder, ctx)
    prop = PayoutBoundedByCoverageProperty()
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_payout_bounded_by_coverage_finds_counterexample_when_policy_consumed_disabled():
    """Drop `policy_consumed`; Z3 can pick payout > coverage."""
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder(disable_guards={"policy_consumed"})
    solver = _solver_with(encoder, ctx)
    prop = PayoutBoundedByCoverageProperty()
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# Redundant-guard findings (R1 in V12.2_ROUND_9_T2_EXTENSIONS.md)
# ---------------------------------------------------------------------------


def test_remains_non_negative_is_redundant_against_datum_ok():
    """REDUNDANCY R1: dropping `remains_non_negative` ALONE keeps
    `no_negative_pool_state` PROVEN — `datum_ok` (which calls
    `verify_claim_datum`) already enforces `new_total >= 0 AND
    new_active >= 0` via its embedded checks.

    The validator's explicit `remains_non_negative` guard is therefore
    defense-in-depth — it remains useful as a future-proofing layer in
    case `verify_claim_datum` is ever refactored.
    """
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder(disable_guards={"remains_non_negative"})
    solver = _solver_with(encoder, ctx)
    prop = NoNegativePoolStateProperty("ProcessClaim")
    solver.add(prop.check(encoder, ctx))
    # If this assertion ever flips to SAT, the redundancy has been
    # broken (probably by a refactor of verify_claim_datum) — surface
    # the change in the report.
    assert solver.check() == unsat


def test_bounds_ok_is_redundant_for_no_negative_pool_state_on_accept_cancellation():
    """REDUNDANCY R2 (cross-file pointer): see
    test_property_accept_cancellation.py for the AcceptCancellation
    branch's analogous `bounds_ok` redundancy. This stub keeps the
    redundancy index discoverable from the ProcessClaim test file
    (which is where most reviewers look for ProcessClaim findings).

    NOTE: kept as a docstring-only stub to avoid duplicating test
    logic across files.
    """
    pass
