"""AddLiquidityEncoder — symbolic execution of `pool.ak` AddLiquidity branch.

Mapping from `D:/aegis/contracts/validators/pool.ak` lines 879-920 (the
`AddLiquidity { amount } -> { ... }` arm) to a list of named Z3 guards.

Guards (mirrors the Aiken `&&` chain at line 919):
  - amount_positive  : amount > 0
  - datum_ok         : verify_add_liquidity_datum(...) (decomposed)
                       new_total == old_total + amount
                       AND new_active == old_active
                       AND new_lp_supply == old_lp_supply + lp_minted
                       where lp_minted = calculate_lp_mint(amount,
                                                          old_total,
                                                          old_lp_supply)
  - immutable_ok     : new_datum.{lp_token_policy, protocol_fee_bps,
                       pool_nft} == datum.{...}
                       NOTE: lp_supply IS allowed to change here
                       (verify_add_liquidity_datum binds the delta).
  - value_ok         : cont_output.lovelace == own_input.lovelace + amount
  - lp_minted        : mint_qty == lp_supply_delta AND mint_qty > 0
                       (validator binds the LP mint direction +
                       magnitude in a single guard, line 917)

LP minting formula (lib/aegis/pool.ak:21 `calculate_lp_mint`):
  if old_total == 0:
      lp_to_mint = amount        # bootstrap case (1:1)
  else:
      lp_to_mint = amount * old_lp_supply / old_total

NOT modelled:
  - Liquidity-bootstrap edge case where `old_lp_supply > 0` but
    `old_total == 0`. The bootstrap path zeroes out the proportional
    formula's denominator; the Aiken code's `if total_liquidity == 0`
    branch covers this with a 1:1 mint. Z3's If(...) encoding mirrors
    that exactly.
  - mint asset name + policy id. The validator reads
    `assets.quantity_of(mint, datum.lp_token_policy, "aLP")`. We
    encode just the resulting quantity as `ctx.mint_lp_qty`; the
    asset-name / policy-id constraints are enforced off-validator
    (when `lp_token_policy` is verified by the LP token validator).

Reference: V12.2 spec §3.2 (Add Liquidity), A-003 fix inline.
"""

from __future__ import annotations

import dataclasses
from typing import Iterable

from z3 import And, BoolRef, If, Int, IntVal

from .base import BaseEncoder, GuardedConstraints


@dataclasses.dataclass(frozen=True)
class AddLiquidityIntermediates:
    """Encoder-internal derived quantities for AddLiquidity.

    `lp_minted` mirrors `calculate_lp_mint(amount, old_total,
    old_lp_supply)`. The validator uses this implicitly via
    `verify_add_liquidity_datum`; we expose it as a named intermediate
    so the `lp_minted` guard can compare against it.

    `pool_delta` = new_total - old_total = amount under the encoder
    (used by the pool_conservation property).
    """

    lp_minted: object
    pool_delta: object


class AddLiquidityEncoder(BaseEncoder):
    """Encodes the AddLiquidity branch of `validators/pool.ak`.

    See module docstring for the mapping to pool.ak lines 879-920.
    """

    GUARD_NAMES: tuple[str, ...] = (
        "amount_positive",
        "datum_ok",
        "immutable_ok",
        "value_ok",
        "lp_minted",
    )

    def __init__(self, disable_guards: Iterable[str] | None = None) -> None:
        super().__init__(disable_guards=disable_guards)
        self._intermediates_cache: dict[int, AddLiquidityIntermediates] = {}

    # ------------------------------------------------------------------
    # Intermediate-variable factory
    # ------------------------------------------------------------------

    def _intermediates_for(self, ctx) -> AddLiquidityIntermediates:
        key = id(ctx)
        cached = self._intermediates_cache.get(key)
        if cached is not None:
            return cached
        prefix = f"al_{key:x}"
        inter = AddLiquidityIntermediates(
            lp_minted=Int(f"{prefix}.lp_minted"),
            pool_delta=Int(f"{prefix}.pool_delta"),
        )
        self._intermediates_cache[key] = inter
        return inter

    # ------------------------------------------------------------------
    # Intermediate variable definitions (calculate_lp_mint)
    # ------------------------------------------------------------------

    def _intermediate_definitions(self, ctx) -> list[BoolRef]:
        inter = self._intermediates_for(ctx)
        d = ctx.old_pool_datum
        r = ctx.redeemer

        # lp_minted = if old_total == 0 then amount
        #             else amount * old_lp_supply / old_total
        lp_minted_def = inter.lp_minted == If(
            d.total_liquidity == 0,
            r.amount,
            (r.amount * d.lp_supply) / d.total_liquidity,
        )

        # pool_delta = new_total - old_total (= amount under value_ok)
        pool_delta_def = inter.pool_delta == (
            ctx.new_pool_datum.total_liquidity - d.total_liquidity
        )

        return [lp_minted_def, pool_delta_def]

    # ------------------------------------------------------------------
    # Named guards (the `&&` chain at pool.ak line 919)
    # ------------------------------------------------------------------

    def _guard_constraints(self, ctx) -> list[GuardedConstraints]:
        inter = self._intermediates_for(ctx)
        d = ctx.old_pool_datum
        nd = ctx.new_pool_datum
        r = ctx.redeemer

        # 2. amount > 0 (line 887)
        amount_positive = r.amount > 0

        # 3. verify_add_liquidity_datum (lib/aegis/pool.ak:133, decomposed)
        #    new_total == old_total + amount
        #    AND new_active == old_active
        #    AND new_lp_supply == old_lp_supply + calculate_lp_mint(...)
        datum_ok = And(
            nd.total_liquidity == d.total_liquidity + r.amount,
            nd.active_coverage == d.active_coverage,
            nd.lp_supply == d.lp_supply + inter.lp_minted,
        )

        # 4. immutable_ok (line 903): THREE-way (lp_supply ALLOWED to
        # move; verify_add_liquidity_datum binds its delta).
        immutable = And(
            nd.lp_token_policy == d.lp_token_policy,
            nd.protocol_fee_bps == d.protocol_fee_bps,
            nd.pool_nft == d.pool_nft,
        )

        # 5. value_ok (line 907): cont == own + amount.
        value_flow = (
            ctx.cont_output_lovelace
            == ctx.own_input_lovelace + r.amount
        )

        # 6. lp_minted (line 917): mint_qty == lp_supply_delta AND
        # mint_qty > 0. lp_supply_delta = new_lp_supply - old_lp_supply.
        lp_minted_guard = And(
            ctx.mint_lp_qty == nd.lp_supply - d.lp_supply,
            ctx.mint_lp_qty > 0,
        )

        return [
            GuardedConstraints("amount_positive", [amount_positive]),
            GuardedConstraints("datum_ok", [datum_ok]),
            GuardedConstraints("immutable_ok", [immutable]),
            GuardedConstraints("value_ok", [value_flow]),
            GuardedConstraints("lp_minted", [lp_minted_guard]),
        ]
