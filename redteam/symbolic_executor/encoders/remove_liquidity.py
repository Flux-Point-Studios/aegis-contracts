"""RemoveLiquidityEncoder — symbolic execution of `pool.ak` RemoveLiquidity branch.

Mapping from `D:/aegis/contracts/validators/pool.ak` lines 925-972 (the
`RemoveLiquidity { amount } -> { ... }` arm) to a list of named Z3 guards.

Guards (mirrors the Aiken `&&` chain at line 971):
  - amount_positive   : amount > 0
  - withdrawal_safe   : can_withdraw(old_total, old_active, amount) :=
                        old_total - amount >= old_active
                        (post-withdrawal solvency)
  - datum_ok          : verify_remove_liquidity_datum (decomposed)
                          new_total == old_total - amount
                          AND new_active == old_active
                          AND new_lp_supply == old_lp_supply - lp_burned
                          AND lp_burned >= 0
                          AND calculate_withdrawal(lp_burned,
                              old_total, old_lp_supply) == amount
  - immutable_ok      : new_datum.{lp_token_policy, protocol_fee_bps,
                        pool_nft} == datum.{...}
                        (lp_supply ALLOWED to change.)
  - value_ok          : cont_output.lovelace ==
                        own_input.lovelace - amount
  - direction_ok      : mint_qty < 0  (it's a BURN, not a mint)

LP burn formula (lib/aegis/pool.ak:40 `calculate_withdrawal`):
  if old_lp_supply == 0:
      fail @"Cannot withdraw: LP supply is zero"
  else:
      lp_burned * old_total / old_lp_supply

The validator computes `lp_burned_qty = -mint_qty`, so under the
encoder: `lp_burned = -ctx.mint_lp_qty`.

NOT modelled:
  - The `fail @"Cannot withdraw: LP supply is zero"` branch. Z3
    division by zero is undefined; we side-step by encoding the
    formula only when `lp_supply > 0`. The Aiken `fail` ALSO makes the
    branch unreachable for `lp_supply == 0`, so the encoder's
    behaviour matches the validator's (both reject).

Reference: V12.2 spec §3.3 (Remove Liquidity), A-002 / A-003 fixes
inline in the source comments.
"""

from __future__ import annotations

import dataclasses
from typing import Iterable

from z3 import And, BoolRef, Int

from .base import BaseEncoder, GuardedConstraints


@dataclasses.dataclass(frozen=True)
class RemoveLiquidityIntermediates:
    """Encoder-internal derived quantities for RemoveLiquidity.

    `lp_burned` mirrors `-mint_qty`. `expected_withdrawal` mirrors
    `calculate_withdrawal(lp_burned, old_total, old_lp_supply)`.
    `pool_delta` is exposed for the conservation property.
    """

    lp_burned: object
    expected_withdrawal: object
    pool_delta: object


class RemoveLiquidityEncoder(BaseEncoder):
    """Encodes the RemoveLiquidity branch of `validators/pool.ak`.

    See module docstring for the mapping to pool.ak lines 925-972.
    """

    GUARD_NAMES: tuple[str, ...] = (
        "amount_positive",
        "withdrawal_safe",
        "datum_ok",
        "immutable_ok",
        "value_ok",
        "direction_ok",
    )

    def __init__(self, disable_guards: Iterable[str] | None = None) -> None:
        super().__init__(disable_guards=disable_guards)
        self._intermediates_cache: dict[int, RemoveLiquidityIntermediates] = {}

    # ------------------------------------------------------------------
    # Intermediate-variable factory
    # ------------------------------------------------------------------

    def _intermediates_for(self, ctx) -> RemoveLiquidityIntermediates:
        key = id(ctx)
        cached = self._intermediates_cache.get(key)
        if cached is not None:
            return cached
        prefix = f"rl_{key:x}"
        inter = RemoveLiquidityIntermediates(
            lp_burned=Int(f"{prefix}.lp_burned"),
            expected_withdrawal=Int(f"{prefix}.expected_withdrawal"),
            pool_delta=Int(f"{prefix}.pool_delta"),
        )
        self._intermediates_cache[key] = inter
        return inter

    # ------------------------------------------------------------------
    # Intermediate variable definitions
    # ------------------------------------------------------------------

    def _intermediate_definitions(self, ctx) -> list[BoolRef]:
        inter = self._intermediates_for(ctx)
        d = ctx.old_pool_datum

        # lp_burned = -mint_qty (Aiken: `lp_burned_qty = -mint_qty`)
        lp_burned_def = inter.lp_burned == -ctx.mint_lp_qty

        # expected_withdrawal = lp_burned * old_total / old_lp_supply
        # Z3 division-by-zero is undefined; we don't constrain when
        # lp_supply == 0 (the validator's `fail` makes that unreachable).
        # The datum_ok guard then drives Z3 to find lp_supply > 0
        # configurations only.
        expected_withdrawal_def = (
            inter.expected_withdrawal
            == (inter.lp_burned * d.total_liquidity) / d.lp_supply
        )

        # pool_delta = new_total - old_total = -amount under value_ok
        pool_delta_def = inter.pool_delta == (
            ctx.new_pool_datum.total_liquidity - d.total_liquidity
        )

        return [lp_burned_def, expected_withdrawal_def, pool_delta_def]

    # ------------------------------------------------------------------
    # Named guards (the `&&` chain at pool.ak line 971)
    # ------------------------------------------------------------------

    def _guard_constraints(self, ctx) -> list[GuardedConstraints]:
        inter = self._intermediates_for(ctx)
        d = ctx.old_pool_datum
        nd = ctx.new_pool_datum
        r = ctx.redeemer

        # 2. amount > 0 (line 933)
        amount_positive = r.amount > 0

        # 3. withdrawal_safe = can_withdraw(old_total, old_active, amount)
        #    := old_total - amount >= old_active     (line 937)
        withdrawal_safe = (d.total_liquidity - r.amount) >= d.active_coverage

        # 5. verify_remove_liquidity_datum (decomposed, lib/aegis/pool.ak:149):
        #    expected_withdrawal == amount
        #    AND new_total == old_total - amount
        #    AND new_active == old_active
        #    AND new_lp_supply == old_lp_supply - lp_burned
        #    AND lp_burned >= 0
        datum_ok = And(
            inter.expected_withdrawal == r.amount,
            nd.total_liquidity == d.total_liquidity - r.amount,
            nd.active_coverage == d.active_coverage,
            nd.lp_supply == d.lp_supply - inter.lp_burned,
            inter.lp_burned >= 0,
        )

        # 6. immutable_ok (line 961): THREE-way (lp_supply changes here).
        immutable = And(
            nd.lp_token_policy == d.lp_token_policy,
            nd.protocol_fee_bps == d.protocol_fee_bps,
            nd.pool_nft == d.pool_nft,
        )

        # 7. value_ok (line 965): cont == own - amount.
        value_flow = (
            ctx.cont_output_lovelace
            == ctx.own_input_lovelace - r.amount
        )

        # 8. direction_ok (line 969): mint_qty < 0 (BURN).
        direction_ok = ctx.mint_lp_qty < 0

        return [
            GuardedConstraints("amount_positive", [amount_positive]),
            GuardedConstraints("withdrawal_safe", [withdrawal_safe]),
            GuardedConstraints("datum_ok", [datum_ok]),
            GuardedConstraints("immutable_ok", [immutable]),
            GuardedConstraints("value_ok", [value_flow]),
            GuardedConstraints("direction_ok", [direction_ok]),
        ]
