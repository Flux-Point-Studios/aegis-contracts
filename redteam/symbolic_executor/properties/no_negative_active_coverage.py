"""Active-coverage range property (INDUCTIVE).

Safety claim (inductive): IF the pre-state satisfies the solvency
invariant (0 <= old_active <= old_total), THEN Underwrite produces a
post-state that ALSO satisfies it (0 <= new_active <= new_total).

This is an INDUCTIVE invariant: the validator does not (and cannot)
re-check the chain history — it only enforces that ITS transition
preserves the property. The off-chain bootstrap of the pool (the
init-pool tx) is responsible for the base case (0 <= 0 <= 100 ADA).

Formal (negated for Z3):
    Pre:  0 <= old_active <= old_total
    NOT (0 <= new_active <= new_total)

The load-bearing guards (each turns the post-condition false under
some pre-state):
  * `coverage_positive` (without it, redeemer.coverage < 0 is accepted
     and the new active_coverage can go negative — this was live
     exploit A-024 in the security audit)
  * `can_cover`         (without it, new_active can exceed new_total —
     the pool becomes insolvent)
  * `datum_ok`          (without it, the new_active is unconstrained
     even when redeemer values are bounded)

Note for non-inductive analysis: if you want to prove the property
holds UNCONDITIONALLY, you need to additionally verify that the
init-pool path establishes the base case AND that NO OTHER branch
(ProcessClaim, BatchUnderwrite, AddLiquidity, RemoveLiquidity,
AcceptCancellation, BatchExpireProcess) can violate it. That cross-
branch composition proof is FUTURE WORK — it's the natural next step
once all six branch encoders ship.
"""

from __future__ import annotations

from z3 import And, BoolRef, Implies, Not, Or

from ..context import SymbolicScriptContext
from ..encoders.base import BaseEncoder
from .base import BaseProperty


class NoNegativeActiveCoverageProperty(BaseProperty):
    name = "no_negative_active_coverage"
    description = (
        "Inductive: pre-solvent pool stays post-solvent after Underwrite "
        "(0 <= new_active <= new_total whenever 0 <= old_active <= old_total)."
    )

    def check(
        self, encoder: BaseEncoder, ctx: SymbolicScriptContext
    ) -> BoolRef:
        d = ctx.old_pool_datum
        nd = ctx.new_pool_datum
        c = ctx.consts
        # Inductive pre-condition:
        #   (a) the OLD state is solvent (0 <= old_active <= old_total), AND
        #   (b) the OLD state uses the canonical protocol_fee_bps (= 200).
        # Condition (b) is necessary because the validator reads fee_bps
        # from the datum — without pinning it, a degenerate fee_bps > 100%
        # makes net_pool_growth < 0 and the pool can lose lovelace on a
        # single Underwrite. The off-chain init-pool tx is the source of
        # truth for the canonical fee_bps; `immutable_ok` then propagates
        # it forward. The chain bootstrap establishes (b) for the
        # singleton pool; here we add it explicitly so the inductive
        # claim is the right shape.
        pre = And(
            d.active_coverage >= 0,
            d.active_coverage <= d.total_liquidity,
            d.protocol_fee_bps == c.protocol_fee_bps,
        )
        # Negated property: the post-state is NOT solvent, despite the pre.
        post_violated = Or(
            nd.active_coverage < 0,
            nd.active_coverage > nd.total_liquidity,
        )
        return And(pre, post_violated)
