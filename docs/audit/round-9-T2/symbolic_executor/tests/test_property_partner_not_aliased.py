"""Partner-not-aliased property tests (R8-DRAIN-1)."""

from __future__ import annotations

from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_underwrite_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import UnderwriteEncoder
from symbolic_executor.properties import PartnerNotAliasedProperty


def _solver_with(encoder, ctx):
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    return solver


def test_partner_not_aliased_proven_on_underwrite():
    """The full encoder rejects every aliased-partner Underwrite."""
    ctx = fresh_underwrite_context()
    encoder = UnderwriteEncoder()
    solver = _solver_with(encoder, ctx)
    # Distinct privileged-address IDs so the model has freedom to alias.
    # (The pin_protocol_constants helper does NOT pin these — they're
    # caller-supplied addresses. For this property we need them to be
    # distinct values so that an "alias" is a meaningful counter-
    # example shape.)
    solver.add(ctx.consts.team_address_id != ctx.consts.pool_address_id)
    solver.add(ctx.consts.team_address_id != ctx.consts.policy_script_hash)
    solver.add(ctx.consts.pool_address_id != ctx.consts.policy_script_hash)
    prop = PartnerNotAliasedProperty()
    solver.add(prop.check(encoder, ctx))
    result = solver.check()
    assert result == unsat, (
        f"Partner-not-aliased must be PROVEN UNSAT, got {result}. "
        f"Model (if SAT): {solver.model() if result == sat else 'n/a'}"
    )


def test_partner_not_aliased_finds_counterexample_when_guard_disabled():
    """Drop `partner_not_aliased`. Z3 should find a model where the
    partner address equals one of team_address / pool_address /
    policy_script_hash."""
    ctx = fresh_underwrite_context()
    encoder = UnderwriteEncoder(disable_guards={"partner_not_aliased"})
    solver = _solver_with(encoder, ctx)
    solver.add(ctx.consts.team_address_id != ctx.consts.pool_address_id)
    solver.add(ctx.consts.team_address_id != ctx.consts.policy_script_hash)
    solver.add(ctx.consts.pool_address_id != ctx.consts.policy_script_hash)
    prop = PartnerNotAliasedProperty()
    solver.add(prop.check(encoder, ctx))
    result = solver.check()
    assert result == sat, (
        "Dropping `partner_not_aliased` should expose R8-DRAIN-1. "
        f"Got {result}."
    )
    model = solver.model()
    addr = model.eval(ctx.new_policy_datum.partner_address_id).as_long()
    privileged = {
        model.eval(ctx.consts.team_address_id).as_long(),
        model.eval(ctx.consts.pool_address_id).as_long(),
        model.eval(ctx.consts.policy_script_hash).as_long(),
    }
    assert addr in privileged, (
        f"Counterexample partner_address_id ({addr}) should alias one of "
        f"the privileged addresses ({privileged})."
    )
