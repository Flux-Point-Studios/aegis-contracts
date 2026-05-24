"""Pool conservation property — branch-parameterized.

Safety claim: every lovelace movement at the pool layer matches the
expected formula for the branch:

  Underwrite:         pool_delta == +net_pool_growth          (pool grows)
                      = premium - fee_total
  ProcessClaim:       pool_delta == -payout                    (pool shrinks)
  AddLiquidity:       pool_delta == +amount                   (pool grows)
  RemoveLiquidity:    pool_delta == -amount                    (pool shrinks)
  AcceptCancellation: pool_delta == -(refund + fee_total_cancel) (pool shrinks)
  BatchUnderwrite:    pool_delta == +net_pool_growth           (pool grows)
                      = total_premium - fee_total_sum

This is the BRANCH-level analogue of the I1 conservation invariant in
`z3_conservation_proof.py`. The fee-math proof shows conservation
holds on the arithmetic in isolation; this branch-level property
shows the VALIDATOR reads the inputs from the same source the math
assumes.

The load-bearing guard is `value_ok` (or `datum_ok` for the
AddLiquidity / RemoveLiquidity branches where the value-flow guard
and the datum-update guard duplicate the same `± amount` claim).

# Foundation-pass shape preserved

The Underwrite branch's pool_conservation property is the original
one — `premium == net_pool_growth + fee_total`. We KEEP that exact
expression here (the foundation's counterexample-pair test in
`tests/test_property_pool_conservation.py` relies on it). For the
five extended branches we add the corresponding pool-delta identity.
"""

from __future__ import annotations

from z3 import BoolRef, Or

from ..encoders.base import BaseEncoder
from .base import BaseProperty


class PoolConservationProperty(BaseProperty):
    """Pool conservation as branch-parameterized invariant.

    Default branch is "Underwrite" to preserve the foundation tests'
    behaviour exactly. Other branches pass `branch=<name>` at
    construction; the encoder + context must match.
    """

    name = "pool_conservation"
    description = (
        "Pool lovelace delta matches the expected formula per branch "
        "(no lovelace disappears at the validator's arithmetic layer)."
    )

    def __init__(self, branch: str = "Underwrite") -> None:
        self.branch = branch

    def check(self, encoder: BaseEncoder, ctx) -> BoolRef:
        if self.branch == "Underwrite":
            # Foundation's identity: premium == net_pool_growth + fee_total.
            inter = encoder._intermediates_for(ctx)  # noqa: SLF001
            r = ctx.redeemer
            return r.premium != inter.net_pool_growth + inter.fee_total

        if self.branch == "ProcessClaim":
            # pool_delta = own - cont = payout. Negated.
            inter = encoder._intermediates_for(ctx)  # noqa: SLF001
            r = ctx.redeemer
            return inter.pool_delta != r.payout

        if self.branch == "AddLiquidity":
            # new_total - old_total = amount. Negated.
            inter = encoder._intermediates_for(ctx)  # noqa: SLF001
            r = ctx.redeemer
            return inter.pool_delta != r.amount

        if self.branch == "RemoveLiquidity":
            # new_total - old_total = -amount. Negated.
            inter = encoder._intermediates_for(ctx)  # noqa: SLF001
            r = ctx.redeemer
            return inter.pool_delta != -r.amount

        if self.branch == "AcceptCancellation":
            # pool_delta = own - cont = refund + fee_total_cancel. Negated.
            inter = encoder._intermediates_for(ctx)  # noqa: SLF001
            return inter.pool_delta != (
                inter.refund_amount + inter.fee_total_cancel
            )

        if self.branch == "BatchUnderwrite":
            # total_premium == net_pool_growth + fee_total_sum. Negated.
            inter = encoder._intermediates_for(ctx)  # noqa: SLF001
            r = ctx.redeemer
            b = ctx.batch_totals
            return r.total_premium != inter.net_pool_growth + b.fee_total_sum

        raise ValueError(f"Unknown branch for pool_conservation: {self.branch}")
