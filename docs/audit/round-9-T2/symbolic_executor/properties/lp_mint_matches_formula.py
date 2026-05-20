"""LP-mint-matches-formula property (AddLiquidity only).

Safety claim: the LP token quantity minted on AddLiquidity equals
`calculate_lp_mint(amount, old_total, old_lp_supply)`. Two cases:
  - Bootstrap (old_total == 0): lp_minted == amount
  - Proportional:               lp_minted == amount * old_lp_supply / old_total

Load-bearing guards:
  - `datum_ok` — binds `new_lp_supply == old_lp_supply + lp_minted`
    via `verify_add_liquidity_datum` (which computes lp_minted via
    the formula).
  - `lp_minted` — binds `mint_qty == new_lp_supply - old_lp_supply`
    AND `mint_qty > 0`.

Together they pin: `mint_qty == calculate_lp_mint(amount, old_total,
old_lp_supply)`. Disabling EITHER one disconnects the mint quantity
from the formula and admits a counterexample.

Reference: A-003 fix at lib/aegis/pool.ak:133.
"""

from __future__ import annotations

from z3 import BoolRef

from ..encoders.base import BaseEncoder
from .base import BaseProperty


class LpMintMatchesFormulaProperty(BaseProperty):
    name = "lp_mint_matches_formula"
    description = (
        "AddLiquidity: minted LP quantity equals calculate_lp_mint(amount, "
        "old_total, old_lp_supply) — bootstrap or proportional."
    )

    def check(self, encoder: BaseEncoder, ctx) -> BoolRef:
        inter = encoder._intermediates_for(ctx)  # noqa: SLF001
        # Negated property: mint_qty != expected lp_minted.
        return ctx.mint_lp_qty != inter.lp_minted
