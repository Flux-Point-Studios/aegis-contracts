"""Withdrawal-safe property (RemoveLiquidity only).

Safety claim: post-RemoveLiquidity, the pool stays SOLVENT
(`new_total >= new_active`). Equivalently, the validator's
`can_withdraw` predicate evaluates True against the old state and the
withdrawal amount.

Pre-condition: the OLD state must be solvent (`old_total >=
old_active`). Without it, no withdrawal preserves solvency.

The load-bearing guard is `withdrawal_safe` (line 936 of pool.ak):
`can_withdraw(old_total, old_active, amount) := old_total - amount
>= old_active`. Note this is logically `new_total >= old_active`
under `datum_ok` (which binds `new_total == old_total - amount`).
Active coverage is preserved on RemoveLiquidity (the validator's
`verify_remove_liquidity_datum` requires `new_active == old_active`),
so the post-condition `new_total >= new_active` is exactly the same.

Reference: A-002 / can_withdraw at lib/aegis/pool.ak:78.
"""

from __future__ import annotations

from z3 import And, BoolRef

from ..encoders.base import BaseEncoder
from .base import BaseProperty


class WithdrawalSafeProperty(BaseProperty):
    name = "withdrawal_safe"
    description = (
        "RemoveLiquidity: pool remains solvent — new_total >= new_active "
        "under a solvent pre-state."
    )

    def check(self, encoder: BaseEncoder, ctx) -> BoolRef:
        d = ctx.old_pool_datum
        nd = ctx.new_pool_datum
        # Pre: 0 <= old_active <= old_total.
        pre_solvent = And(
            d.active_coverage >= 0,
            d.active_coverage <= d.total_liquidity,
        )
        # Negated post: new_total < new_active.
        post_violated = nd.total_liquidity < nd.active_coverage
        return And(pre_solvent, post_violated)
