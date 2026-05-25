"""AcceptCancellationEncoder — symbolic execution of `pool.ak` AcceptCancellation branch.

Mapping from `D:/aegis/contracts/validators/pool.ak` lines 1227-1388 (the
`AcceptCancellation -> { ... }` arm) to a list of named Z3 guards. This
is the LARGEST branch by guard count (12 guards in the `&&` chain on
line 1387).

Guards (mirrors the Aiken `&&` chain at line 1387):
  - policy_targets_this_pool : policy_datum.pool_script_hash ==
                               own_pool_hash AND
                               policy_datum.pool_nft == datum.pool_nft
  - bounds_ok                : refund_amount >= 0
                               AND refund_amount <= datum.total_liquidity
                               AND policy_datum.coverage_amount
                                   <= datum.active_coverage
  - value_ok                 : cont_output.lovelace ==
                               own_input.lovelace - refund_amount -
                               fee_total_cancel
  - datum_ok                 : new_total ==
                               old_total - refund_amount - fee_total_cancel
                               AND new_active ==
                               old_active - policy_datum.coverage_amount
  - immutable_ok             : new_datum.{lp_token_policy,
                               protocol_fee_bps, pool_nft, lp_supply}
                               == datum.{...} (4 equalities — lp_supply
                               UNCHANGED on cancel)
  - remains_non_negative     : new.total_liquidity >= 0 AND
                               new.active_coverage >= 0
  - donation_ok              : treasury_donation matches required cut
                               (Some(amt) -> amt >= required;
                                None -> required == 0)
  - partner_share_in_bounds  : 0 <= policy_datum.partner_share_bps <= cap
  - partner_consistency      : Some(_) -> True;
                               None -> partner_share_bps == 0
  - partner_not_aliased      : R8-DRAIN-1 family (Underwrite-style)
  - team_output_funded       : team_output_lovelace >= team_cut
  - partner_output_funded    : Some(addr) -> if partner_cut > 0 then
                                 partner_output_lovelace >= partner_cut
                                 else True (silent absorb)
                               None -> True

Intermediate definitions (mirrors lib/aegis/pricing.ak):
  - refund_amount = calculate_refund(premium_paid)
                  = premium_paid - (premium_paid * 1_000 / 10_000)
                  = premium_paid * 9_000 / 10_000
  - cancellation_fee = premium_paid - refund_amount
  - fee_total_cancel = max(min_utxo, cancellation_fee * fee_bps / 10_000)
  - partner_cut_raw = fee_total_cancel * partner_share_bps / 10_000
  - partner_cut = if partner_cut_raw >= min_utxo then partner_cut_raw else 0
  - team_cut = fee_total_cancel - partner_cut
  - required_donation = cancellation_fee * fee_bps / 10_000
                        * treasury_share_bps / 10_000

NOT modelled:
  - The `list.find(inputs, ...)` walk for the policy input. We lift
    the walker's RESULT into `consumed_policy_datum`.
  - The `extra_signatories` / submitter wallet for the donation
    source. The validator does not read these — donation amount lands
    in the Conway donation body field.

Reference: V12.2 spec §3.6 (Accept Cancellation), R8-DRAIN-1 fix on
this branch is explicitly an "old V11 policies on chain may carry
hostile partner_addresses" hedge.
"""

from __future__ import annotations

import dataclasses
from typing import Iterable

from z3 import And, BoolRef, If, Implies, Int, IntVal, Or

from .base import BaseEncoder, GuardedConstraints


@dataclasses.dataclass(frozen=True)
class AcceptCancellationIntermediates:
    """Encoder-internal derived quantities for AcceptCancellation."""

    refund_amount: object
    cancellation_fee: object
    raw_fee_cancel: object
    fee_total_cancel: object
    partner_cut_raw: object
    partner_cut: object
    team_cut: object
    required_donation: object
    pool_delta: object


class AcceptCancellationEncoder(BaseEncoder):
    """Encodes the AcceptCancellation branch of `validators/pool.ak`.

    See module docstring for the mapping to pool.ak lines 1227-1388.
    """

    GUARD_NAMES: tuple[str, ...] = (
        "policy_targets_this_pool",
        "bounds_ok",
        "value_ok",
        "datum_ok",
        "immutable_ok",
        "remains_non_negative",
        "donation_ok",
        "partner_share_in_bounds",
        "partner_consistency",
        "partner_not_aliased",
        "team_output_funded",
        "partner_output_funded",
    )

    def __init__(self, disable_guards: Iterable[str] | None = None) -> None:
        super().__init__(disable_guards=disable_guards)
        self._intermediates_cache: dict[
            int, AcceptCancellationIntermediates
        ] = {}

    # ------------------------------------------------------------------
    # Intermediate-variable factory
    # ------------------------------------------------------------------

    def _intermediates_for(self, ctx) -> AcceptCancellationIntermediates:
        key = id(ctx)
        cached = self._intermediates_cache.get(key)
        if cached is not None:
            return cached
        prefix = f"ac_{key:x}"
        inter = AcceptCancellationIntermediates(
            refund_amount=Int(f"{prefix}.refund_amount"),
            cancellation_fee=Int(f"{prefix}.cancellation_fee"),
            raw_fee_cancel=Int(f"{prefix}.raw_fee_cancel"),
            fee_total_cancel=Int(f"{prefix}.fee_total_cancel"),
            partner_cut_raw=Int(f"{prefix}.partner_cut_raw"),
            partner_cut=Int(f"{prefix}.partner_cut"),
            team_cut=Int(f"{prefix}.team_cut"),
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
        CANCEL_BPS = 1_000  # 10% cancellation fee
        inter = self._intermediates_for(ctx)
        c = ctx.consts
        d = ctx.old_pool_datum
        pdat = ctx.consumed_policy_datum

        defs: list[BoolRef] = []

        # cancellation_fee = premium_paid * 1_000 / 10_000
        # refund_amount = premium_paid - cancellation_fee
        defs.append(
            inter.cancellation_fee
            == (pdat.premium_paid * CANCEL_BPS) / BPS
        )
        defs.append(
            inter.refund_amount == pdat.premium_paid - inter.cancellation_fee
        )

        # raw_fee_cancel = cancellation_fee * datum.protocol_fee_bps / 10_000
        defs.append(
            inter.raw_fee_cancel
            == (inter.cancellation_fee * d.protocol_fee_bps) / BPS
        )

        # fee_total_cancel = max(min_utxo, raw_fee_cancel)
        defs.append(
            inter.fee_total_cancel
            == If(
                inter.raw_fee_cancel >= c.min_utxo_lovelace,
                inter.raw_fee_cancel,
                c.min_utxo_lovelace,
            )
        )

        # partner_cut_raw = fee_total_cancel * partner_share_bps / 10_000
        # (only when Some(addr) AND share > 0; else 0)
        defs.append(
            inter.partner_cut_raw
            == If(
                And(
                    pdat.partner_address_is_some == 1,
                    pdat.partner_share_bps > 0,
                ),
                (inter.fee_total_cancel * pdat.partner_share_bps) / BPS,
                IntVal(0),
            )
        )

        # partner_cut = if partner_cut_raw >= min_utxo then ... else 0
        defs.append(
            inter.partner_cut
            == If(
                inter.partner_cut_raw >= c.min_utxo_lovelace,
                inter.partner_cut_raw,
                IntVal(0),
            )
        )

        # team_cut = fee_total_cancel - partner_cut
        defs.append(
            inter.team_cut == inter.fee_total_cancel - inter.partner_cut
        )

        # required_donation =
        #   cancellation_fee * protocol_fee_bps / 10_000
        #                    * treasury_share_bps / 10_000
        defs.append(
            inter.required_donation
            == (
                (inter.cancellation_fee * d.protocol_fee_bps) / BPS
                * c.treasury_share_bps
            )
            / BPS
        )

        # pool_delta = own_input - cont_output
        # (For AcceptCancellation, pool DECREASES by refund + fee_total_cancel)
        defs.append(
            inter.pool_delta
            == ctx.own_input_lovelace - ctx.cont_output_lovelace
        )

        return defs

    # ------------------------------------------------------------------
    # Named guards (the `&&` chain at pool.ak line 1387)
    # ------------------------------------------------------------------

    def _guard_constraints(self, ctx) -> list[GuardedConstraints]:
        inter = self._intermediates_for(ctx)
        d = ctx.old_pool_datum
        nd = ctx.new_pool_datum
        pdat = ctx.consumed_policy_datum
        c = ctx.consts
        td = ctx.treasury_donation

        # 3. policy_targets_this_pool (line 1259)
        policy_targets = And(
            pdat.pool_script_hash == ctx.own_pool_script_hash,
            pdat.pool_nft == d.pool_nft,
        )

        # 9. bounds_ok (line 1309): refund >= 0 AND refund <= old_total
        #    AND policy.coverage_amount <= old.active_coverage.
        bounds_ok = And(
            inter.refund_amount >= 0,
            inter.refund_amount <= d.total_liquidity,
            pdat.coverage_amount <= d.active_coverage,
        )

        # 10. value_ok (line 1316): cont == own - refund - fee_total_cancel.
        value_flow = (
            ctx.cont_output_lovelace
            == ctx.own_input_lovelace
            - inter.refund_amount
            - inter.fee_total_cancel
        )

        # 11. datum_ok (line 1323):
        #   new_total == old_total - refund - fee_total_cancel
        #   AND new_active == old_active - policy.coverage_amount
        datum_ok = And(
            nd.total_liquidity
            == d.total_liquidity - inter.refund_amount - inter.fee_total_cancel,
            nd.active_coverage == d.active_coverage - pdat.coverage_amount,
        )

        # 12. immutable_ok (line 1328): 4-way (lp_supply UNCHANGED on cancel).
        immutable = And(
            nd.lp_token_policy == d.lp_token_policy,
            nd.protocol_fee_bps == d.protocol_fee_bps,
            nd.pool_nft == d.pool_nft,
            nd.lp_supply == d.lp_supply,
        )

        # 13. remains_non_negative (line 1332):
        #   new.total_liquidity >= 0 AND new.active_coverage >= 0.
        remains_non_negative = And(
            nd.total_liquidity >= 0,
            nd.active_coverage >= 0,
        )

        # 16. donation_ok (line 1367):
        #   Some(amt) -> amt >= required_donation;
        #   None      -> required_donation == 0.
        donation = If(
            td.is_some == 1,
            td.amount >= inter.required_donation,
            inter.required_donation == 0,
        )

        # 6. partner_share_in_bounds (line 1280): 0 <= share_bps <= cap.
        partner_share_in_bounds = And(
            pdat.partner_share_bps >= 0,
            pdat.partner_share_bps <= c.partner_share_cap_bps,
        )

        # 7. partner_consistency (line 1285): None -> share == 0;
        #    Some -> True (no further constraint).
        partner_consistency = Implies(
            pdat.partner_address_is_some == 0,
            pdat.partner_share_bps == 0,
        )

        # 17. partner_not_aliased (line 1379): R8-DRAIN-1.
        # None -> True; Some(addr) -> addr != team && addr != pool
        #                             && addr.cred != Script(policy_hash).
        partner_not_aliased = Or(
            pdat.partner_address_is_some == 0,
            And(
                pdat.partner_address_id != c.team_address_id,
                pdat.partner_address_id != c.pool_address_id,
                pdat.partner_address_id != c.policy_script_hash,
            ),
        )

        # 14. team_output_funded (line 1338): team_output >= team_cut.
        team_funded = ctx.team_output_lovelace >= inter.team_cut

        # 15. partner_output_funded (line 1346):
        #   Some(addr) -> if partner_cut > 0 then partner_out >= partner_cut
        #                 else True;
        #   None       -> True.
        partner_funded = If(
            pdat.partner_address_is_some == 1,
            If(
                inter.partner_cut > 0,
                ctx.partner_output_lovelace >= inter.partner_cut,
                True,
            ),
            True,
        )

        return [
            GuardedConstraints("policy_targets_this_pool", [policy_targets]),
            GuardedConstraints("bounds_ok", [bounds_ok]),
            GuardedConstraints("value_ok", [value_flow]),
            GuardedConstraints("datum_ok", [datum_ok]),
            GuardedConstraints("immutable_ok", [immutable]),
            GuardedConstraints("remains_non_negative", [remains_non_negative]),
            GuardedConstraints("donation_ok", [donation]),
            GuardedConstraints(
                "partner_share_in_bounds", [partner_share_in_bounds]
            ),
            GuardedConstraints("partner_consistency", [partner_consistency]),
            GuardedConstraints("partner_not_aliased", [partner_not_aliased]),
            GuardedConstraints("team_output_funded", [team_funded]),
            GuardedConstraints("partner_output_funded", [partner_funded]),
        ]
