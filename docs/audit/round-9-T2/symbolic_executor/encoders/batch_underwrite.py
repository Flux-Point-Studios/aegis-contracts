"""BatchUnderwriteEncoder — symbolic execution of `pool.ak` BatchUnderwrite branch.

Mapping from `D:/aegis/contracts/validators/pool.ak` lines 997-1137 (the
`BatchUnderwrite { total_coverage, total_premium } -> { ... }` arm) to a
list of named Z3 guards.

# SCOPE STATEMENT (load-bearing)

This encoder LIFTS the per-policy list-walker (`batch_policies_match_totals_v12`)
to its SCALAR aggregate results — see the
`SymbolicBatchFeeTotals` record in `context.py`. We do NOT model
individual list elements. Per-element invariants (e.g. "EVERY policy's
partner_share is in [0, cap]", "EVERY policy is a valid policy
output bound to THIS pool") are encoded as the walker's boolean
outputs (`shares_ok`, `funded_ok`, `aliased_partner_present`).

The trade-off: we cannot directly express properties like "if any
policy in the batch aliases the team_address then the validator
rejects" at the per-element level. Instead, we encode the
`aliased_partner_present` flag (= True iff ANY entry in
partner_totals aliases a privileged address) and prove a
counterexample-pair test on it. The aliasing-presence flag is the
moral equivalent — it captures the property the validator's
`list.all` would reject.

# Guards (mirrors the Aiken `&&` chain at line 1136):

  - coverage_positive            : total_coverage > 0
  - premium_positive             : total_premium > 0
  - premium_ok                   : is_premium_adequate(total_premium,
                                   total_coverage)
  - can_cover                    : can_underwrite(old_total, old_active,
                                   total_coverage)
  - datum_ok                     : verify_underwrite_datum on aggregate
                                   net_pool_growth + total_coverage
  - immutable_ok                 : lp_token_policy / protocol_fee_bps /
                                   pool_nft / lp_supply unchanged
  - value_ok                     : cont == own + net_pool_growth
  - batch_policies_funded        : batch_totals.funded_ok == 1
  - shares_ok                    : batch_totals.shares_ok == 1
  - partner_addresses_not_aliased: batch_totals.aliased_partner_present
                                   == 0 (R8-DRAIN-1 batch arm,
                                   list.all encoded as aggregate flag)
  - team_output_funded           : team_output_lovelace >=
                                   batch_totals.team_total
  - partner_outputs_funded       : batch_totals.partner_outputs_all_funded
                                   == 1 (lifted list.all)
  - donation_ok                  : treasury_donation matches required cut

# Coupling constraints encoded as intermediate definitions:

  - batch_totals.cov_sum == redeemer.total_coverage when
    batch_policies_funded == 1 (the walker's funded_ok already
    enforces this; we mirror as a definition for property reasoning)
  - batch_totals.prem_sum == redeemer.total_premium similarly
  - team_total + partner_totals_sum == fee_total_sum (split helper
    contract)
  - net_pool_growth = total_premium - fee_total_sum

# Reference: V12.2 spec §3.7 (Batch Underwrite), R8-DRAIN-1 batch arm
hedge for old V11 batches.
"""

from __future__ import annotations

import dataclasses
from typing import Iterable

from z3 import And, BoolRef, If, Implies, Int, IntVal, Or

from .base import BaseEncoder, GuardedConstraints


@dataclasses.dataclass(frozen=True)
class BatchUnderwriteIntermediates:
    """Encoder-internal derived quantities for BatchUnderwrite."""

    net_pool_growth: object
    required_donation: object
    pool_delta: object


class BatchUnderwriteEncoder(BaseEncoder):
    """Encodes the BatchUnderwrite branch of `validators/pool.ak`.

    See module docstring for the mapping to pool.ak lines 997-1137 and
    the explicit list-topology scope statement.
    """

    GUARD_NAMES: tuple[str, ...] = (
        "coverage_positive",
        "premium_positive",
        "premium_ok",
        "can_cover",
        "datum_ok",
        "immutable_ok",
        "value_ok",
        "batch_policies_funded",
        "shares_ok",
        "partner_addresses_not_aliased",
        "team_output_funded",
        "partner_outputs_funded",
        "donation_ok",
    )

    def __init__(self, disable_guards: Iterable[str] | None = None) -> None:
        super().__init__(disable_guards=disable_guards)
        self._intermediates_cache: dict[
            int, BatchUnderwriteIntermediates
        ] = {}

    # ------------------------------------------------------------------
    # Intermediate-variable factory
    # ------------------------------------------------------------------

    def _intermediates_for(self, ctx) -> BatchUnderwriteIntermediates:
        key = id(ctx)
        cached = self._intermediates_cache.get(key)
        if cached is not None:
            return cached
        prefix = f"bu_{key:x}"
        inter = BatchUnderwriteIntermediates(
            net_pool_growth=Int(f"{prefix}.net_pool_growth"),
            required_donation=Int(f"{prefix}.required_donation"),
            pool_delta=Int(f"{prefix}.pool_delta"),
        )
        self._intermediates_cache[key] = inter
        return inter

    # ------------------------------------------------------------------
    # Intermediate variable definitions
    # ------------------------------------------------------------------

    def _intermediate_definitions(self, ctx) -> list[BoolRef]:
        BPS = 10_000
        inter = self._intermediates_for(ctx)
        r = ctx.redeemer
        d = ctx.old_pool_datum
        c = ctx.consts
        b = ctx.batch_totals

        defs: list[BoolRef] = []

        # net_pool_growth = total_premium - fee_total_sum (line 1051)
        defs.append(inter.net_pool_growth == r.total_premium - b.fee_total_sum)

        # team_total + partner_totals_sum == fee_total_sum
        # (split helper contract from calculate_protocol_fee_split — sum
        # invariant; not a redundant guard, this is mathematically
        # forced by the walker.)
        defs.append(b.team_total + b.partner_totals_sum == b.fee_total_sum)

        # required_donation = total_premium * fee_bps / 10_000
        #                                   * treasury_share_bps / 10_000
        defs.append(
            inter.required_donation
            == (
                (r.total_premium * d.protocol_fee_bps) / BPS
                * c.treasury_share_bps
            )
            / BPS
        )

        # pool_delta = new_total - old_total (= net_pool_growth under value_ok)
        defs.append(
            inter.pool_delta
            == ctx.new_pool_datum.total_liquidity - d.total_liquidity
        )

        # batch_totals.funded_ok / shares_ok / partner_outputs_all_funded /
        # aliased_partner_present are 0/1 indicators.
        defs.append(Or(b.funded_ok == 0, b.funded_ok == 1))
        defs.append(Or(b.shares_ok == 0, b.shares_ok == 1))
        defs.append(
            Or(b.partner_outputs_all_funded == 0, b.partner_outputs_all_funded == 1)
        )
        defs.append(
            Or(b.aliased_partner_present == 0, b.aliased_partner_present == 1)
        )

        # When funded_ok == 1, the walker's sum-pinning invariants hold:
        #   cov_sum == total_coverage, prem_sum == total_premium.
        # We encode this as an implication so we can REASON about the
        # pinned identity downstream.
        defs.append(
            Implies(b.funded_ok == 1, b.cov_sum == r.total_coverage)
        )
        defs.append(
            Implies(b.funded_ok == 1, b.prem_sum == r.total_premium)
        )

        # All aggregate sums are non-negative (the walker can never
        # produce negative aggregate quantities — each per-policy
        # contribution is bounded below by 0).
        defs.append(b.fee_total_sum >= 0)
        defs.append(b.team_total >= 0)
        defs.append(b.partner_totals_sum >= 0)

        return defs

    # ------------------------------------------------------------------
    # Named guards (the `&&` chain at pool.ak line 1136)
    # ------------------------------------------------------------------

    def _guard_constraints(self, ctx) -> list[GuardedConstraints]:
        inter = self._intermediates_for(ctx)
        r = ctx.redeemer
        d = ctx.old_pool_datum
        nd = ctx.new_pool_datum
        c = ctx.consts
        b = ctx.batch_totals
        td = ctx.treasury_donation

        # 1. coverage_positive (line 1007): total_coverage > 0.
        coverage_positive = r.total_coverage > 0

        # 2. premium_positive (line 1008): total_premium > 0.
        premium_positive = r.total_premium > 0

        # 3. premium_ok (line 1011): is_premium_adequate.
        #    total_premium >= min_premium AND total_premium > 0 AND
        #    total_coverage <= total_premium * 50.
        premium_adequate = And(
            r.total_premium >= c.min_premium,
            r.total_premium > 0,
            r.total_coverage <= r.total_premium * 50,
        )

        # 4. can_cover (line 1014): old_total - old_active >= total_coverage.
        can_cover = d.total_liquidity - d.active_coverage >= r.total_coverage

        # 7. datum_ok (line 1054): verify_underwrite_datum aggregate.
        #   new_total == old_total + net_pool_growth
        #   AND new_active == old_active + total_coverage.
        datum_ok = And(
            nd.total_liquidity == d.total_liquidity + inter.net_pool_growth,
            nd.active_coverage == d.active_coverage + r.total_coverage,
        )

        # 5. immutable_ok (line 1024): 4-way (lp_supply UNCHANGED on Batch).
        immutable = And(
            nd.lp_token_policy == d.lp_token_policy,
            nd.protocol_fee_bps == d.protocol_fee_bps,
            nd.pool_nft == d.pool_nft,
            nd.lp_supply == d.lp_supply,
        )

        # 8. value_ok (line 1068): cont == own + net_pool_growth.
        value_flow = (
            ctx.cont_output_lovelace
            == ctx.own_input_lovelace + inter.net_pool_growth
        )

        # 9. batch_policies_funded (line 1074): batch_totals.funded_ok.
        batch_policies_funded = b.funded_ok == 1

        # 10. shares_ok (line 1078): batch_totals.shares_ok.
        shares_ok = b.shares_ok == 1

        # 11. partner_addresses_not_aliased (line 1109): list.all on
        #     partner_totals — encoded as the aggregate flag.
        partner_addresses_not_aliased = b.aliased_partner_present == 0

        # 12. team_output_funded (line 1084): team_output >= team_total.
        team_funded = ctx.team_output_lovelace >= b.team_total

        # 13. partner_outputs_funded (line 1096): list.all on
        #     partner_totals — encoded as the aggregate flag.
        partner_outputs_funded = b.partner_outputs_all_funded == 1

        # 14. donation_ok (line 1130).
        donation = If(
            td.is_some == 1,
            td.amount >= inter.required_donation,
            inter.required_donation == 0,
        )

        return [
            GuardedConstraints("coverage_positive", [coverage_positive]),
            GuardedConstraints("premium_positive", [premium_positive]),
            GuardedConstraints("premium_ok", [premium_adequate]),
            GuardedConstraints("can_cover", [can_cover]),
            GuardedConstraints("datum_ok", [datum_ok]),
            GuardedConstraints("immutable_ok", [immutable]),
            GuardedConstraints("value_ok", [value_flow]),
            GuardedConstraints(
                "batch_policies_funded", [batch_policies_funded]
            ),
            GuardedConstraints("shares_ok", [shares_ok]),
            GuardedConstraints(
                "partner_addresses_not_aliased",
                [partner_addresses_not_aliased],
            ),
            GuardedConstraints("team_output_funded", [team_funded]),
            GuardedConstraints(
                "partner_outputs_funded", [partner_outputs_funded]
            ),
            GuardedConstraints("donation_ok", [donation]),
        ]
