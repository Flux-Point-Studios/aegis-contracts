"""Refund-bounded-by-premium property (AcceptCancellation only).

Safety claim: the cancel-path refund `refund_amount` is bounded
above by the consumed policy's `premium_paid` (it CANNOT pay out
more than was paid in). The validator's `calculate_refund` helper
computes `refund = premium - 10% cancellation_fee = premium *
9_000 / 10_000`, which is structurally below `premium_paid`.

Load-bearing: the encoder's intermediate definitions (which mirror
`calculate_refund` exactly). Without the definitions, Z3 could
choose any `refund_amount` and trip the upper bound.

A secondary load-bearing guard is `bounds_ok` (line 1309), which
asserts `refund_amount >= 0 AND refund_amount <= datum.total_liquidity`
explicitly. The upper bound by `premium_paid` is unconditional in the
math.

Reference: V12.2 spec §3.6 cancellation fee / refund split.
"""

from __future__ import annotations

from z3 import And, BoolRef

from ..encoders.base import BaseEncoder
from .base import BaseProperty


class RefundBoundedByPremiumProperty(BaseProperty):
    """The refund_amount is at most `premium_paid` for any non-negative premium.

    Pre-condition: `premium_paid >= 0`. Without this pre-condition the
    Z3 model can pick `premium_paid = -1`, at which integer division
    on the cancellation_fee `-1 * 1_000 / 10_000` floors to -1
    (Euclidean), making `refund = premium - fee = -1 - (-1) = 0`. The
    raw arithmetic comparison `0 > -1` then triggers a vacuous
    counterexample — but the "refund of 0 against a negative premium"
    is not an actual overpayment; no lovelace leaves the pool for the
    insured (the validator's `bounds_ok` enforces `refund >= 0`
    independently). The pre-condition rules out the vacuous case so
    the property targets the genuine economic invariant.

    Aegis policies are only created via Underwrite, which enforces
    `premium > 0` via the `premium_positive` guard, so on-chain
    policies always satisfy this pre-condition. The Z3-level
    pre-condition is necessary because the AcceptCancellation
    encoder operates on an arbitrary symbolic policy datum (which
    could carry any value if synthesized outside Underwrite).
    """

    name = "refund_bounded_by_premium"
    description = (
        "AcceptCancellation: refund_amount <= consumed policy's premium_paid "
        "(under premium_paid >= 0 pre-condition)."
    )

    def check(self, encoder: BaseEncoder, ctx) -> BoolRef:
        inter = encoder._intermediates_for(ctx)  # noqa: SLF001
        pdat = ctx.consumed_policy_datum
        # Pre: premium_paid >= 0.
        pre = pdat.premium_paid >= 0
        # Negated property: refund > premium_paid (overpayment).
        post_violated = inter.refund_amount > pdat.premium_paid
        return And(pre, post_violated)
