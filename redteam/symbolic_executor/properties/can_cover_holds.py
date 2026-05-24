"""Can-cover-holds property (BatchUnderwrite — aggregate `can_underwrite`).

Safety claim: post-BatchUnderwrite, the validator preserves the
aggregate solvency invariant — i.e. it never accepts a batch whose
`total_coverage` exceeds the pool's available liquidity.

Formal:
  total_coverage <= old_total - old_active   (i.e. can_cover holds)

Load-bearing guard: `can_cover` (line 1014 of pool.ak).

This is the BATCH analogue of Underwrite's `can_cover`. The
foundation's `no_negative_active_coverage` proved that Underwrite
preserves inductive solvency at the per-policy level; this property
proves the same at the aggregate batch level.
"""

from __future__ import annotations

from z3 import And, BoolRef

from ..encoders.base import BaseEncoder
from .base import BaseProperty


class CanCoverHoldsProperty(BaseProperty):
    name = "can_cover_holds"
    description = (
        "BatchUnderwrite: total_coverage <= old_total - old_active "
        "(can_underwrite aggregate)."
    )

    def check(self, encoder: BaseEncoder, ctx) -> BoolRef:
        r = ctx.redeemer
        d = ctx.old_pool_datum
        # Negated: total_coverage > available_liquidity.
        return r.total_coverage > (d.total_liquidity - d.active_coverage)
