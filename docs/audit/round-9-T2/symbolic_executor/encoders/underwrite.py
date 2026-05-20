"""UnderwriteEncoder — symbolic execution of `pool.ak` Underwrite branch.

This file is the WORKED EXAMPLE for the symbolic-executor framework.
The mapping is from `D:/aegis/contracts/validators/pool.ak` lines
~630-792 (Underwrite arm of the spend `when redeemer is` switch) to a
list of named Z3 guards.

Each `let foo_ok = ...` in the Aiken source becomes one
`GuardedConstraints(name="foo_ok", constraints=[...])` here. The final
line of the Aiken branch — the big `&&` conjunction — is the implicit
"all guards hold" condition that `encode(ctx)` returns.

Intermediate variables (fee_total, net_pool_growth, partner_cut,
team_cut, treasury_cut, required_donation, partner_cut_raw) are
declared as Z3 variables on the `ctx` extension and tied down by
`_intermediate_definitions`. We keep them as bespoke Z3 Ints rather
than reusing context fields because they're encoder-internal, not part
of the on-chain ScriptContext.

Reference: V12.2 spec §3.5 (Hybrid Fee, silent-absorb).
"""

from __future__ import annotations

import dataclasses
from typing import Iterable

from z3 import And, BoolRef, If, Implies, Int, IntVal, Or

from ..context import (
    PARTNER_SHARE_CAP_BPS,
    PROTOCOL_FEE_BPS_DEFAULT,
    SymbolicScriptContext,
)
from .base import BaseEncoder, GuardedConstraints


@dataclasses.dataclass(frozen=True)
class UnderwriteIntermediates:
    """Encoder-internal derived quantities.

    Defined exactly once per encoder instance + per context (cached on
    the encoder instance via `_intermediates_for`).
    """

    raw_fee: object
    fee_total: object
    net_pool_growth: object
    partner_cut_raw: object
    partner_cut: object
    team_cut: object
    treasury_cut: object


class UnderwriteEncoder(BaseEncoder):
    """Encodes the Underwrite branch of `validators/pool.ak`.

    Guards (mirrors the Aiken `&&` chain at line ~791):
      - coverage_positive      : coverage > 0
      - premium_positive       : premium > 0
      - premium_ok             : is_premium_adequate(premium, coverage)
      - can_cover              : can_underwrite(...)
      - datum_ok               : verify_underwrite_datum(...)
      - immutable_ok           : pool datum invariants preserved
      - value_ok               : cont lovelace == own + net_pool_growth
      - donation_ok            : treasury_donation >= required_donation
      - partner_share_in_bounds: 0 <= share_bps <= cap
      - partner_consistency    : None => share_bps == 0
      - partner_not_aliased    : R8-DRAIN-1 invariant
      - team_output_funded     : output at team_address >= team_cut
      - partner_output_funded  : output at partner_address >= partner_cut

    Plus three implicit "structural" pins enforced by the validator's
    `expect` patterns that we lift into guards for completeness:
      - policy_output_matches_underwrite: a single policy output exists
        at policy_script_hash carrying the new policy datum. Encoded as
        EQUALITY constraints between the new policy datum's
        coverage_amount/premium_paid and the redeemer's coverage/premium
        plus pool-binding fields. See `policy_output_matches_underwrite`
        in pool.ak lines 416-507.
    """

    GUARD_NAMES: tuple[str, ...] = (
        "coverage_positive",
        "premium_positive",
        "premium_ok",
        "can_cover",
        "datum_ok",
        "immutable_ok",
        "value_ok",
        "donation_ok",
        "partner_share_in_bounds",
        "partner_consistency",
        "partner_not_aliased",
        "team_output_funded",
        "partner_output_funded",
        "policy_output_matches_underwrite",
    )

    def __init__(self, disable_guards: Iterable[str] | None = None) -> None:
        super().__init__(disable_guards=disable_guards)
        # Lazily-built per-context intermediates cache (we let
        # `_intermediates_for` re-create on demand; the cache is keyed
        # by `id(ctx)` since the dataclass is frozen but Z3 vars are
        # not hashable for our purposes).
        self._intermediates_cache: dict[int, UnderwriteIntermediates] = {}

    # ------------------------------------------------------------------
    # Intermediate-variable factory
    # ------------------------------------------------------------------

    def _intermediates_for(
        self, ctx: SymbolicScriptContext
    ) -> UnderwriteIntermediates:
        key = id(ctx)
        cached = self._intermediates_cache.get(key)
        if cached is not None:
            return cached
        prefix = f"uw_{key:x}"
        inter = UnderwriteIntermediates(
            raw_fee=Int(f"{prefix}.raw_fee"),
            fee_total=Int(f"{prefix}.fee_total"),
            net_pool_growth=Int(f"{prefix}.net_pool_growth"),
            partner_cut_raw=Int(f"{prefix}.partner_cut_raw"),
            partner_cut=Int(f"{prefix}.partner_cut"),
            team_cut=Int(f"{prefix}.team_cut"),
            treasury_cut=Int(f"{prefix}.treasury_cut"),
        )
        self._intermediates_cache[key] = inter
        return inter

    # ------------------------------------------------------------------
    # Intermediate variable definitions (Hybrid Fee math)
    # ------------------------------------------------------------------

    def _intermediate_definitions(
        self, ctx: SymbolicScriptContext
    ) -> list[BoolRef]:
        BPS = 10_000
        inter = self._intermediates_for(ctx)
        c = ctx.consts
        d = ctx.old_pool_datum
        r = ctx.redeemer
        pd = ctx.new_policy_datum

        defs: list[BoolRef] = []

        # raw_fee = premium * protocol_fee_bps / 10_000  (truncating div)
        # The validator reads `datum.protocol_fee_bps`, so we tie it to
        # the OLD pool datum's bps (which equals the pinned const via
        # the `immutable_ok` guard — but we ALSO want this expression
        # to be coherent when `immutable_ok` is DISABLED, which is why
        # we read from the datum here rather than from `consts`).
        defs.append(inter.raw_fee == (r.premium * d.protocol_fee_bps) / BPS)

        # fee_total = max(min_utxo, raw_fee)
        defs.append(
            inter.fee_total
            == If(
                inter.raw_fee >= c.min_utxo_lovelace,
                inter.raw_fee,
                c.min_utxo_lovelace,
            )
        )

        # net_pool_growth = premium - fee_total
        defs.append(inter.net_pool_growth == r.premium - inter.fee_total)

        # partner_cut_raw and partner_cut (silent absorb)
        # When partner_address is None OR share_bps == 0:
        #   partner_cut_raw == 0
        # Else:
        #   partner_cut_raw == fee_total * partner_share_bps / 10_000
        defs.append(
            inter.partner_cut_raw
            == If(
                And(pd.partner_address_is_some == 1, pd.partner_share_bps > 0),
                (inter.fee_total * pd.partner_share_bps) / BPS,
                IntVal(0),
            )
        )

        # Silent absorb: below floor → 0
        defs.append(
            inter.partner_cut
            == If(
                inter.partner_cut_raw >= c.min_utxo_lovelace,
                inter.partner_cut_raw,
                IntVal(0),
            )
        )

        # team_cut = fee_total - partner_cut
        defs.append(inter.team_cut == inter.fee_total - inter.partner_cut)

        # treasury_cut = premium * protocol_fee_bps / 10_000 * treasury_share_bps / 10_000
        defs.append(
            inter.treasury_cut
            == (
                (r.premium * d.protocol_fee_bps) / BPS * c.treasury_share_bps
            )
            / BPS
        )

        return defs

    # ------------------------------------------------------------------
    # Named guards (the `&&` chain at pool.ak line 791)
    # ------------------------------------------------------------------

    def _guard_constraints(
        self, ctx: SymbolicScriptContext
    ) -> list[GuardedConstraints]:
        inter = self._intermediates_for(ctx)
        d = ctx.old_pool_datum
        nd = ctx.new_pool_datum
        pd = ctx.new_policy_datum
        r = ctx.redeemer
        c = ctx.consts
        vr = ctx.validity_range
        td = ctx.treasury_donation

        # `is_premium_adequate(premium, coverage)`:
        #   premium >= min_premium && premium > 0 && coverage <= premium * 50
        premium_adequate = And(
            r.premium >= c.min_premium,
            r.premium > 0,
            r.coverage <= r.premium * 50,
        )

        # `can_underwrite(total_liquidity, active_coverage, coverage)`:
        #   total_liquidity - active_coverage >= coverage
        can_underwrite = d.total_liquidity - d.active_coverage >= r.coverage

        # `verify_underwrite_datum(...)`:
        #   new_total == old_total + net_pool_growth
        #   AND new_active == old_active + coverage
        verify_datum = And(
            nd.total_liquidity == d.total_liquidity + inter.net_pool_growth,
            nd.active_coverage == d.active_coverage + r.coverage,
        )

        # Immutable PoolDatum fields preserved
        immutable = And(
            nd.lp_token_policy == d.lp_token_policy,
            nd.protocol_fee_bps == d.protocol_fee_bps,
            nd.pool_nft == d.pool_nft,
            nd.lp_supply == d.lp_supply,
        )

        # Value-flow: cont_output.lovelace == own_input.lovelace + net_pool_growth
        value_flow = (
            ctx.cont_output_lovelace
            == ctx.own_input_lovelace + inter.net_pool_growth
        )

        # Treasury donation check:
        # `when treasury_donation is { Some(amt) -> amt >= req; None -> req == 0 }`
        donation = If(
            td.is_some == 1,
            td.amount >= inter.treasury_cut,
            inter.treasury_cut == 0,
        )

        # Partner share in [0, cap]
        partner_share_in_bounds = And(
            pd.partner_share_bps >= 0,
            pd.partner_share_bps <= c.partner_share_cap_bps,
        )

        # Partner consistency: None => share_bps == 0
        # `partner_address.is_some == 0 => share_bps == 0`
        partner_consistency = Implies(
            pd.partner_address_is_some == 0,
            pd.partner_share_bps == 0,
        )

        # Partner not aliased (R8-DRAIN-1).
        #
        # Aiken source:
        #   None      -> True
        #   Some(addr) -> addr != team && addr != pool && addr.cred != Script(policy_hash)
        #
        # We model `addr != Script(policy_hash)` as an inequality on the
        # symbolic Int that identifies the partner's payment_credential.
        # The fixture pins `policy_script_hash` to a distinct value from
        # any non-aliased `partner_address_id`. For a fully-symbolic
        # context, the guard requires the inequality.
        partner_not_aliased = Or(
            pd.partner_address_is_some == 0,
            And(
                pd.partner_address_id != c.team_address_id,
                pd.partner_address_id != c.pool_address_id,
                # The Aiken check is on `addr.payment_credential != Script(h)`.
                # Our partner_address_id models the FULL Address. We
                # encode the aliasing-check as a single non-equality
                # against `policy_script_hash`. This is conservative:
                # in the byte-string world, two different stake
                # credentials with the SAME payment credential would
                # collide in the validator but not in our model. A
                # future tightening would separate payment from stake
                # in `SymbolicPolicyDatum.partner_address_id` (TODO).
                pd.partner_address_id != c.policy_script_hash,
            ),
        )

        # Team output funded.
        # `output_to_address_at_least(outputs, team_address, team_cut)`:
        # The encoder lifts this to "team_output_lovelace >= team_cut",
        # where `team_output_lovelace` is the max lovelace among outputs
        # at team_address (or 0 if no such output exists). Note V12.2
        # spec §8.1.4 guarantees team_cut >= min_utxo, so this implies
        # the chosen output is spendable.
        team_funded = ctx.team_output_lovelace >= inter.team_cut

        # Partner output funded.
        # `when partner_address is { Some(addr) -> partner_cut > 0 ?
        #                            output_to_address_at_least(...) : True
        #                          ; None -> True }`
        partner_funded = If(
            pd.partner_address_is_some == 1,
            If(
                inter.partner_cut > 0,
                ctx.partner_output_lovelace >= inter.partner_cut,
                True,  # silent absorb path
            ),
            True,  # solo policy
        )

        # `expect Some(...) = policy_output_matches_underwrite(...)`.
        #
        # This `expect` is the canonical-datum pin on the new policy
        # output. It binds:
        #   - new_policy.pool_script_hash == own_pool_script_hash
        #   - new_policy.pool_nft         == old_pool.pool_nft
        #   - new_policy.coverage_amount  == redeemer.coverage
        #   - new_policy.premium_paid     == redeemer.premium
        # (+ start_time inside validity_range — but that's an off-chain
        #  contract not enforced by Aiken in this branch, so we omit it
        #  from the safety-property check. The Aiken code IS strict
        #  about start_time being in the validity range; we encode that
        #  too, since later properties may want it.)
        policy_match = And(
            pd.pool_script_hash == ctx.own_pool_script_hash,
            pd.pool_nft == d.pool_nft,
            pd.coverage_amount == r.coverage,
            pd.premium_paid == r.premium,
            pd.start_time >= vr.lb,
            pd.start_time <= vr.ub,
        )

        return [
            GuardedConstraints("coverage_positive", [r.coverage > 0]),
            GuardedConstraints("premium_positive", [r.premium > 0]),
            GuardedConstraints("premium_ok", [premium_adequate]),
            GuardedConstraints("can_cover", [can_underwrite]),
            GuardedConstraints("datum_ok", [verify_datum]),
            GuardedConstraints("immutable_ok", [immutable]),
            GuardedConstraints("value_ok", [value_flow]),
            GuardedConstraints("donation_ok", [donation]),
            GuardedConstraints(
                "partner_share_in_bounds", [partner_share_in_bounds]
            ),
            GuardedConstraints("partner_consistency", [partner_consistency]),
            GuardedConstraints("partner_not_aliased", [partner_not_aliased]),
            GuardedConstraints("team_output_funded", [team_funded]),
            GuardedConstraints("partner_output_funded", [partner_funded]),
            GuardedConstraints(
                "policy_output_matches_underwrite", [policy_match]
            ),
        ]
