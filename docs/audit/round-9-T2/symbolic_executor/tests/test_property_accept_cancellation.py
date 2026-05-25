"""Property tests for the AcceptCancellation branch."""

from __future__ import annotations

from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_accept_cancellation_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import AcceptCancellationEncoder
from symbolic_executor.properties import (
    ImmutablePoolDatumProperty,
    NoNegativePoolStateProperty,
    PartnerNotAliasedProperty,
    PoolConservationProperty,
    RefundBoundedByPremiumProperty,
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


def test_pool_conservation_proven_on_accept_cancellation():
    """pool_delta == refund + fee_total_cancel."""
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder()
    solver = _solver_with(encoder, ctx)
    prop = PoolConservationProperty("AcceptCancellation")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_pool_conservation_finds_counterexample_when_value_ok_disabled():
    """Drop `value_ok` -> cont_output_lovelace no longer pinned."""
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder(disable_guards={"value_ok"})
    solver = _solver_with(encoder, ctx)
    prop = PoolConservationProperty("AcceptCancellation")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# no_negative_pool_state
# ---------------------------------------------------------------------------


def test_no_negative_pool_state_proven_on_accept_cancellation():
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder()
    solver = _solver_with(encoder, ctx)
    prop = NoNegativePoolStateProperty("AcceptCancellation")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_no_negative_pool_state_finds_counterexample_when_remains_non_negative_disabled():
    """Drop `remains_non_negative` AND `bounds_ok` -> Z3 can pick a
    refund + coverage that drives new_total or new_active negative."""
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder(
        disable_guards={"remains_non_negative", "bounds_ok"}
    )
    solver = _solver_with(encoder, ctx)
    prop = NoNegativePoolStateProperty("AcceptCancellation")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# immutable_pool_datum (lp_supply UNCHANGED on cancel)
# ---------------------------------------------------------------------------


def test_immutable_pool_datum_proven_on_accept_cancellation():
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder()
    solver = _solver_with(encoder, ctx)
    prop = ImmutablePoolDatumProperty("AcceptCancellation")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_immutable_pool_datum_finds_counterexample_when_immutable_ok_disabled():
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder(disable_guards={"immutable_ok"})
    solver = _solver_with(encoder, ctx)
    prop = ImmutablePoolDatumProperty("AcceptCancellation")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# partner_not_aliased (R8-DRAIN-1 on the AC branch)
# ---------------------------------------------------------------------------


def test_partner_not_aliased_proven_on_accept_cancellation():
    """R8-DRAIN-1 hedge for V11 policies cancelled under V12.2+ pool."""
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder()
    solver = _solver_with(encoder, ctx)
    # Distinct privileged-address IDs so the model has freedom to alias.
    solver.add(ctx.consts.team_address_id != ctx.consts.pool_address_id)
    solver.add(ctx.consts.team_address_id != ctx.consts.policy_script_hash)
    solver.add(ctx.consts.pool_address_id != ctx.consts.policy_script_hash)
    prop = PartnerNotAliasedProperty("AcceptCancellation")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_partner_not_aliased_finds_counterexample_when_guard_disabled():
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder(disable_guards={"partner_not_aliased"})
    solver = _solver_with(encoder, ctx)
    solver.add(ctx.consts.team_address_id != ctx.consts.pool_address_id)
    solver.add(ctx.consts.team_address_id != ctx.consts.policy_script_hash)
    solver.add(ctx.consts.pool_address_id != ctx.consts.policy_script_hash)
    prop = PartnerNotAliasedProperty("AcceptCancellation")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# refund_bounded_by_premium  (branch-specific)
# ---------------------------------------------------------------------------


def test_refund_bounded_by_premium_proven_on_accept_cancellation():
    """refund <= premium_paid (under premium_paid >= 0 precondition)."""
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder()
    solver = _solver_with(encoder, ctx)
    prop = RefundBoundedByPremiumProperty()
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_bounds_ok_is_redundant_for_no_negative_pool_state():
    """REDUNDANCY R2: dropping `bounds_ok` ALONE keeps
    `no_negative_pool_state` PROVEN. The `remains_non_negative`
    guard already enforces `new_total >= 0 AND new_active >= 0`
    independently of `bounds_ok`.

    `bounds_ok` is load-bearing for OTHER properties — it bounds
    `refund_amount <= old_total` and
    `coverage_amount <= old_active` explicitly, which matters for
    any "pool doesn't underflow on a single tx" property. But for
    the specific `no_negative_pool_state` post-condition, the
    inductive pre-state + `datum_ok` + `remains_non_negative`
    chain suffices.

    See `V12.2_ROUND_9_T2_EXTENSIONS.md` §4 for the full
    redundant-guard discussion.
    """
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder(disable_guards={"bounds_ok"})
    solver = _solver_with(encoder, ctx)
    prop = NoNegativePoolStateProperty("AcceptCancellation")
    solver.add(prop.check(encoder, ctx))
    # If this assertion ever flips to SAT, the redundancy has been
    # broken (probably by a refactor of remains_non_negative).
    assert solver.check() == unsat


def test_refund_bounded_by_premium_redundant_finding():
    """REDUNDANT-GUARD finding: the refund_bounded_by_premium property
    is enforced purely by the encoder's intermediate definitions
    (calculate_refund formula), not by any single guard. The math
    guarantees `refund_amount = premium - premium*1000/10000 =
    premium*9000/10000` which is structurally <= premium for any
    non-negative premium.

    Dropping `bounds_ok` (the only guard that explicitly bounds
    refund_amount) still leaves the property PROVEN. We surface this
    here as a documented redundancy — the safety claim is a property
    of the FORMULA, not of an enforced guard.

    NOTE: this is the moral analogue of the foundation's
    `pool_conservation` situation, where the property is a property of
    the intermediate definitions rather than a guard. See
    `V12.2_ROUND_9_T2_EXTENSIONS.md` for the table of redundant-guard
    findings.
    """
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder(disable_guards={"bounds_ok"})
    solver = _solver_with(encoder, ctx)
    prop = RefundBoundedByPremiumProperty()
    solver.add(prop.check(encoder, ctx))
    # Confirmed: math-only property; dropping bounds_ok still proves.
    assert solver.check() == unsat
