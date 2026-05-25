"""Immutable PoolDatum property — branch-parameterized (R8-DRAIN-1 family).

Safety claim: the validator MUST preserve the four pool-datum "spine"
fields across the transition:
  - lp_token_policy
  - protocol_fee_bps
  - pool_nft
  - lp_supply     [WITH BRANCH EXCEPTION]

Branch exception: `lp_supply` is the only mutable spine field. It
MOVES during AddLiquidity / RemoveLiquidity (the validator's
`verify_add_liquidity_datum` / `verify_remove_liquidity_datum`
binds the delta to `calculate_lp_mint` / `calculate_withdrawal`).
For every OTHER branch — Underwrite, ProcessClaim,
AcceptCancellation, BatchUnderwrite, BatchExpireProcess —
`lp_supply` is part of the immutable conjunction.

Load-bearing guard: `immutable_ok` on every branch.

Reference: V12.2 spec §3.1 immutable spine; R8-DRAIN-1 family.
"""

from __future__ import annotations

from z3 import BoolRef, Or

from ..encoders.base import BaseEncoder
from .base import BaseProperty


_LP_SUPPLY_MUTABLE_BRANCHES = frozenset({"AddLiquidity", "RemoveLiquidity"})


class ImmutablePoolDatumProperty(BaseProperty):
    """Branch-parameterized immutable spine.

    Default branch is "Underwrite" (foundation behaviour). For the
    five extended branches pass `branch=<name>`.
    """

    name = "immutable_pool_datum"
    description = (
        "lp_token_policy / protocol_fee_bps / pool_nft preserved across "
        "the transition (plus lp_supply except on Add/Remove Liquidity)."
    )

    def __init__(self, branch: str = "Underwrite") -> None:
        self.branch = branch

    def check(self, encoder: BaseEncoder, ctx) -> BoolRef:
        d = ctx.old_pool_datum
        nd = ctx.new_pool_datum
        disjuncts = [
            nd.lp_token_policy != d.lp_token_policy,
            nd.protocol_fee_bps != d.protocol_fee_bps,
            nd.pool_nft != d.pool_nft,
        ]
        if self.branch not in _LP_SUPPLY_MUTABLE_BRANCHES:
            disjuncts.append(nd.lp_supply != d.lp_supply)
        return Or(*disjuncts)
