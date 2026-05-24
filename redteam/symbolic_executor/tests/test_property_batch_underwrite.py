"""Property tests for the BatchUnderwrite branch.

SCOPE: list-walks are lifted to scalar aggregates (see encoder
docstring). Per-element properties are encoded via the walker's
aggregate flags (`aliased_partner_present`, `shares_ok`,
`partner_outputs_all_funded`, `funded_ok`).
"""

from __future__ import annotations

from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    fresh_batch_underwrite_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import BatchUnderwriteEncoder
from symbolic_executor.properties import (
    CanCoverHoldsProperty,
    ImmutablePoolDatumProperty,
    NoNegativePoolStateProperty,
    PartnerNotAliasedProperty,
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


def test_pool_conservation_proven_on_batch_underwrite():
    """total_premium == net_pool_growth + fee_total_sum."""
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder()
    solver = _solver_with(encoder, ctx)
    prop = PoolConservationProperty("BatchUnderwrite")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_pool_conservation_finds_counterexample_when_definition_dropped():
    """Without the intermediate definition (net_pool_growth = total_premium
    - fee_total_sum), Z3 picks a different net_pool_growth and breaks the
    identity. This mirrors the foundation's pool_conservation test shape."""
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder()
    solver = Solver()
    for c in encoder.encode(ctx, include_definitions=False):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    prop = PoolConservationProperty("BatchUnderwrite")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# no_negative_pool_state
# ---------------------------------------------------------------------------


def test_no_negative_pool_state_proven_on_batch_underwrite():
    """Inductive with LP-cushion pre-condition (V12.2 §10.1 LP absorbs floor).

    See `properties/no_negative_pool_state.py` for the per-branch
    pre-condition rationale. Pre: `old_total + total_premium >=
    fee_total_sum` (cushion absorbs aggregate floor cost).
    """
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder()
    solver = _solver_with(encoder, ctx)
    prop = NoNegativePoolStateProperty("BatchUnderwrite")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_no_negative_pool_state_finds_counterexample_when_can_cover_disabled():
    """Drop `can_cover` -> Z3 can pick total_coverage > available, driving
    new_active > new_total (insolvency); but new_active >= 0 still requires
    care. Easier: also drop datum_ok so new_active is free."""
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder(
        disable_guards={"can_cover", "datum_ok"}
    )
    solver = _solver_with(encoder, ctx)
    prop = NoNegativePoolStateProperty("BatchUnderwrite")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# immutable_pool_datum (4-way: lp_supply UNCHANGED on Batch)
# ---------------------------------------------------------------------------


def test_immutable_pool_datum_proven_on_batch_underwrite():
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder()
    solver = _solver_with(encoder, ctx)
    prop = ImmutablePoolDatumProperty("BatchUnderwrite")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_immutable_pool_datum_finds_counterexample_when_immutable_ok_disabled():
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder(disable_guards={"immutable_ok"})
    solver = _solver_with(encoder, ctx)
    prop = ImmutablePoolDatumProperty("BatchUnderwrite")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# partner_not_aliased (R8-DRAIN-1 batch arm — aggregate flag)
# ---------------------------------------------------------------------------


def test_partner_not_aliased_proven_on_batch_underwrite():
    """The aggregate `aliased_partner_present` flag is 0 iff NO entry
    in partner_totals aliases a privileged address."""
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder()
    solver = _solver_with(encoder, ctx)
    prop = PartnerNotAliasedProperty("BatchUnderwrite")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_partner_not_aliased_finds_counterexample_when_guard_disabled():
    """Drop `partner_addresses_not_aliased` -> Z3 can pick
    aliased_partner_present = 1, exposing the R8-DRAIN-1 batch arm."""
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder(
        disable_guards={"partner_addresses_not_aliased"}
    )
    solver = _solver_with(encoder, ctx)
    prop = PartnerNotAliasedProperty("BatchUnderwrite")
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat


# ---------------------------------------------------------------------------
# can_cover_holds  (branch-specific)
# ---------------------------------------------------------------------------


def test_can_cover_holds_proven_on_batch_underwrite():
    """total_coverage <= old_total - old_active."""
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder()
    solver = _solver_with(encoder, ctx)
    prop = CanCoverHoldsProperty()
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == unsat


def test_can_cover_holds_finds_counterexample_when_can_cover_disabled():
    """Drop `can_cover` -> Z3 picks total_coverage > available."""
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder(disable_guards={"can_cover"})
    solver = _solver_with(encoder, ctx)
    prop = CanCoverHoldsProperty()
    solver.add(prop.check(encoder, ctx))
    assert solver.check() == sat
