"""Payout-bounded-by-coverage property (ProcessClaim only).

Safety claim: the requested `payout` on ProcessClaim is bounded by
the consumed policy's declared `coverage_amount`. Without this, a
hostile builder could request `payout > coverage_amount` (the A-001
pool-drain attack — fixed by the `payout_matches_coverage` predicate
inside the `policy_consumed` guard).

The Aiken validator's binding is the STRONGER `payout ==
policy_datum.coverage_amount` (equality), which implies the upper
bound. We assert the upper bound as the safety property so the
specific guard that load-bears it is the entire `policy_consumed`
predicate.

Reference: A-001 fix at pool.ak line 837-843.
"""

from __future__ import annotations

from z3 import BoolRef

from ..encoders.base import BaseEncoder
from .base import BaseProperty


class PayoutBoundedByCoverageProperty(BaseProperty):
    name = "payout_bounded_by_coverage"
    description = (
        "ProcessClaim: requested payout <= consumed policy's coverage_amount."
    )

    def check(self, encoder: BaseEncoder, ctx) -> BoolRef:
        r = ctx.redeemer
        pdat = ctx.consumed_policy_datum
        # Negated property: payout > coverage_amount.
        return r.payout > pdat.coverage_amount
