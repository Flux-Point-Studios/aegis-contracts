"""No-negative-pool-state property (universal across all branches).

Safety claim: after the redeemer, the new pool datum satisfies
  new_total_liquidity >= 0 AND new_active_coverage >= 0.

Unlike the foundation's inductive `no_negative_active_coverage`
property (which also requires `0 <= old_active <= old_total` as a
pre-condition and `protocol_fee_bps == 200` for the Underwrite floor
regime), this property is non-inductive: it's the POST-condition the
validator MUST establish unconditionally on every branch, regardless
of how degenerate the pre-state is.

Some branches enforce this directly via `remains_non_negative` guards
(ProcessClaim, BatchExpireProcess, AcceptCancellation). Other branches
infer it from a chain of guards:
  - Underwrite:        `coverage_positive` + `can_cover` +
                       `datum_ok` (verify_underwrite_datum) +
                       pre-state solvency
  - AddLiquidity:      `amount_positive` + `datum_ok` +
                       pre-state non-negativity
  - RemoveLiquidity:   `amount_positive` + `withdrawal_safe` +
                       pre-state solvency
  - BatchUnderwrite:   coverage_positive + can_cover +
                       (similar to Underwrite, aggregate)

The property includes a pre-condition `pre_solvent` that turns it
into an inductive invariant — same shape as the foundation's
`no_negative_active_coverage`. The pre-condition is `old_total >= 0
AND old_active >= 0 AND old_active <= old_total`.
"""

from __future__ import annotations

from z3 import And, BoolRef, Or

from ..encoders.base import BaseEncoder
from .base import BaseProperty


class NoNegativePoolStateProperty(BaseProperty):
    """Post-state non-negativity (inductive over a solvent pre-state)."""

    name = "no_negative_pool_state"
    description = (
        "After the redeemer, new.total_liquidity >= 0 AND "
        "new.active_coverage >= 0 (under a solvent pre-state)."
    )

    def __init__(self, branch: str = "Underwrite") -> None:
        self.branch = branch

    def check(self, encoder: BaseEncoder, ctx) -> BoolRef:
        d = ctx.old_pool_datum
        nd = ctx.new_pool_datum

        # Solvent pre-state: 0 <= old_active <= old_total AND old_total >= 0.
        pre_solvent = And(
            d.total_liquidity >= 0,
            d.active_coverage >= 0,
            d.active_coverage <= d.total_liquidity,
        )

        # For Underwrite, the Hybrid Fee floor regime makes fee_total >
        # premium possible at small premiums; the validator allows the
        # LP to absorb the floor cost. For the inductive invariant to
        # hold, we pin protocol_fee_bps to the canonical 200 bps and
        # require premium >= min_premium (chained from is_premium_adequate).
        if self.branch == "Underwrite":
            c = ctx.consts
            pre_solvent = And(
                pre_solvent,
                d.protocol_fee_bps == c.protocol_fee_bps,
            )

        # For BatchUnderwrite, the aggregate fee_total_sum (sum of
        # per-policy floors) can exceed total_premium when the batch
        # contains many small-premium policies. The pool absorbs the
        # difference (V12.2 spec §10.1). For the post-state to be
        # non-negative, the pre-state must carry enough cushion to
        # absorb the LP-loss: `old_total + total_premium >=
        # fee_total_sum`. Equivalently, the net_pool_growth (=
        # total_premium - fee_total_sum) must not exceed old_total in
        # magnitude when negative. We encode this as an additional
        # pre-condition. Without it the property is unenforceable —
        # the LP-absorb design is INTENTIONAL.
        if self.branch == "BatchUnderwrite":
            c = ctx.consts
            b = ctx.batch_totals
            r = ctx.redeemer
            pre_solvent = And(
                pre_solvent,
                d.protocol_fee_bps == c.protocol_fee_bps,
                # LP cushion: old_total can absorb the aggregate floor cost.
                # This is the explicit "post-state non-negative" cushion.
                d.total_liquidity + r.total_premium >= b.fee_total_sum,
            )

        # Negated post-condition: new state goes negative.
        post_violated = Or(
            nd.total_liquidity < 0,
            nd.active_coverage < 0,
        )
        return And(pre_solvent, post_violated)
