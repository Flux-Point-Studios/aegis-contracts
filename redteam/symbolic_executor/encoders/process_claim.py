"""ProcessClaimEncoder — symbolic execution of `pool.ak` ProcessClaim branch.

Mapping from `D:/aegis/contracts/validators/pool.ak` lines 797-874 (the
`ProcessClaim { payout } -> { ... }` arm of the `when redeemer is`
switch) to a list of named Z3 guards.

Each `let foo_ok = ...` in the Aiken source becomes one
`GuardedConstraints(name="foo_ok", constraints=[...])` here. The final
line of the Aiken branch — `payout_positive && policy_consumed &&
datum_ok && immutable_ok && value_ok && remains_non_negative` — is the
implicit "all guards hold" condition that `encode(ctx)` returns.

Guards mirror the Aiken `&&` chain at pool.ak line 873:
  - payout_positive          : payout > 0
  - policy_consumed          : policy_targets_this_pool AND
                               payout_matches_coverage
  - datum_ok                 : verify_claim_datum(...) (decomposed:
                               payout >= 0, payout <= old_active,
                               new_total == old_total - payout,
                               new_active == old_active - payout,
                               new_total >= 0, new_active >= 0)
  - immutable_ok             : new_datum.{lp_token_policy,
                               protocol_fee_bps, pool_nft, lp_supply}
                               == datum.{...} (4 equalities)
  - value_ok                 : cont_output.lovelace ==
                               own_input.lovelace - payout
  - remains_non_negative     : new_datum.total_liquidity >= 0 AND
                               new_datum.active_coverage >= 0

NOT modelled (load-bearing OMISSIONS — see foundation report §5.2):
  - The `list.find(inputs, fn(i) { ... policy_script_hash ... })` walk
    that produces the consumed `policy_input`. We lift the walker's
    RESULT into `consumed_policy_datum` directly. The walker's
    side-condition that the consumed input is at the canonical policy
    script credential is encoded as `consumed_policy_datum.pool_script_hash
    == own_pool_script_hash` (since the validator binds the policy datum
    to its own consumed Address via the find filter).
  - Oracle freshness / strike validation. The ProcessClaim branch in
    pool.ak does NOT read the oracle — the policy validator does, on
    the Claim path. Pool's role is to release funds against an
    already-validated policy. The cross-validator binding lives in
    `policy.Claim`'s output check (out of scope here).

Reference: V12.2 spec §3.6 (Process Claim), A-001 / F-007 / A-005 /
L-006 fixes inline in the source comments.
"""

from __future__ import annotations

import dataclasses
from typing import Iterable

from z3 import And, BoolRef, Int

from .base import BaseEncoder, GuardedConstraints


@dataclasses.dataclass(frozen=True)
class ProcessClaimIntermediates:
    """Encoder-internal derived quantities for ProcessClaim.

    The ProcessClaim branch is simpler than Underwrite — no fee math,
    no partner split, no donation — so the only intermediate is the
    `pool_delta = own_input_lovelace - cont_output_lovelace`, which
    properties may reference (e.g. `pool_conservation` asserts this
    equals `payout`).
    """

    pool_delta: object


class ProcessClaimEncoder(BaseEncoder):
    """Encodes the ProcessClaim branch of `validators/pool.ak`.

    See module docstring for the mapping to pool.ak lines 797-874.
    """

    GUARD_NAMES: tuple[str, ...] = (
        "payout_positive",
        "policy_consumed",
        "datum_ok",
        "immutable_ok",
        "value_ok",
        "remains_non_negative",
    )

    def __init__(self, disable_guards: Iterable[str] | None = None) -> None:
        super().__init__(disable_guards=disable_guards)
        self._intermediates_cache: dict[int, ProcessClaimIntermediates] = {}

    # ------------------------------------------------------------------
    # Intermediate-variable factory
    # ------------------------------------------------------------------

    def _intermediates_for(self, ctx) -> ProcessClaimIntermediates:
        key = id(ctx)
        cached = self._intermediates_cache.get(key)
        if cached is not None:
            return cached
        prefix = f"pc_{key:x}"
        inter = ProcessClaimIntermediates(
            pool_delta=Int(f"{prefix}.pool_delta"),
        )
        self._intermediates_cache[key] = inter
        return inter

    # ------------------------------------------------------------------
    # Intermediate variable definitions
    # ------------------------------------------------------------------

    def _intermediate_definitions(self, ctx) -> list[BoolRef]:
        inter = self._intermediates_for(ctx)
        # pool_delta = own_input.lovelace - cont_output.lovelace
        # (For ProcessClaim, the pool DECREASES by `payout`, so pool_delta
        # should equal `payout` under the encoder.)
        return [
            inter.pool_delta
            == ctx.own_input_lovelace - ctx.cont_output_lovelace,
        ]

    # ------------------------------------------------------------------
    # Named guards (the `&&` chain at pool.ak line 873)
    # ------------------------------------------------------------------

    def _guard_constraints(self, ctx) -> list[GuardedConstraints]:
        d = ctx.old_pool_datum
        nd = ctx.new_pool_datum
        pdat = ctx.consumed_policy_datum
        r = ctx.redeemer

        # 2. payout > 0 (line 805)
        payout_positive = r.payout > 0

        # `policy_consumed = policy_targets_this_pool && payout_matches_coverage`
        # (lines 839-843).
        #   policy_targets_this_pool: policy_datum.pool_script_hash == own_pool_hash
        #                             AND policy_datum.pool_nft == datum.pool_nft
        #   payout_matches_coverage : payout == policy_datum.coverage_amount
        policy_consumed = And(
            pdat.pool_script_hash == ctx.own_pool_script_hash,
            pdat.pool_nft == d.pool_nft,
            r.payout == pdat.coverage_amount,
        )

        # 3. verify_claim_datum (decomposed, lib/aegis/pool.ak:120).
        #   payout >= 0
        #   AND payout <= old_active
        #   AND new_total == old_total - payout
        #   AND new_active == old_active - payout
        #   AND new_total >= 0
        #   AND new_active >= 0
        datum_ok = And(
            r.payout >= 0,
            r.payout <= d.active_coverage,
            nd.total_liquidity == d.total_liquidity - r.payout,
            nd.active_coverage == d.active_coverage - r.payout,
            nd.total_liquidity >= 0,
            nd.active_coverage >= 0,
        )

        # 4. immutable_ok (line 856): 4-way equality.
        immutable = And(
            nd.lp_token_policy == d.lp_token_policy,
            nd.protocol_fee_bps == d.protocol_fee_bps,
            nd.pool_nft == d.pool_nft,
            nd.lp_supply == d.lp_supply,
        )

        # 5. value_ok (line 863): cont == own - payout.
        value_flow = (
            ctx.cont_output_lovelace
            == ctx.own_input_lovelace - r.payout
        )

        # 6. remains_non_negative (line 870):
        #    new.total_liquidity >= 0 AND new.active_coverage >= 0.
        # NOTE: this overlaps with datum_ok's last two clauses. The
        # validator carries both explicit checks; we mirror that. Z3
        # collapses the duplicate constraints losslessly.
        remains_non_negative = And(
            nd.total_liquidity >= 0,
            nd.active_coverage >= 0,
        )

        return [
            GuardedConstraints("payout_positive", [payout_positive]),
            GuardedConstraints("policy_consumed", [policy_consumed]),
            GuardedConstraints("datum_ok", [datum_ok]),
            GuardedConstraints("immutable_ok", [immutable]),
            GuardedConstraints("value_ok", [value_flow]),
            GuardedConstraints("remains_non_negative", [remains_non_negative]),
        ]
