"""Differential pipeline: Z3 prediction vs concrete re-evaluation.

For each (branch, property) pair:

  1. Sample N concrete inputs from the encoder's constraint space.
  2. For each input:
     a. Pin the symbolic ctx to the concrete values.
     b. Add the encoder's guards and the protocol pins.
     c. Add the NEGATED property.
     d. Re-run Z3. UNSAT here means the property holds on this input.
        SAT means the property is VIOLATED by this concrete input.
  3. Cross-check: the property checker says PROVEN globally (UNSAT
     over the full symbolic domain), so EVERY concrete sample MUST
     also be UNSAT. Any SAT result is a disagreement -> finding.
  4. For predicates that map 1-to-1 to public Aiken helper functions
     (`can_underwrite`, `can_withdraw`, `is_premium_adequate`), emit
     an Aiken test fixture and report it to the runner for subprocess
     verification.

The differential runner DOES NOT modify the existing 112 tests; it
ADDS new pytest cases under `fuzz/test_fuzz.py`.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
from typing import Any, Iterable

from z3 import And, BoolRef, Not, Solver, sat, unsat

from ..cli import BRANCH_PROPERTIES, address_distinctness_pins
from ..context import (
    pin_protocol_constants,
)
from ..encoders import BaseEncoder
from ..tests._pinning import (
    pin_accept_cancellation_ctx,
    pin_add_liquidity_ctx,
    pin_batch_underwrite_ctx,
    pin_process_claim_ctx,
    pin_remove_liquidity_ctx,
)
from .concrete_generator import (
    BRANCH_GENERATORS,
    model_to_fixture,
    sample_satisfying_assignment,
)


# ---------------------------------------------------------------------------
# Branch -> pinning helper. Underwrite uses an in-test helper; we mirror
# the same shape inline to avoid changing test_encoder_underwrite.py.
# ---------------------------------------------------------------------------


def _pin_underwrite(ctx, fx: dict) -> list:
    op = fx["old_pool_datum"]
    np_ = fx["new_pool_datum"]
    pd = fx["new_policy_datum"]
    r = fx["redeemer"]
    vr = fx["validity_range"]
    td = fx["treasury_donation"]
    co = fx["consts"]
    return [
        ctx.old_pool_datum.total_liquidity == op["total_liquidity"],
        ctx.old_pool_datum.active_coverage == op["active_coverage"],
        ctx.old_pool_datum.lp_token_policy == op["lp_token_policy"],
        ctx.old_pool_datum.protocol_fee_bps == op["protocol_fee_bps"],
        ctx.old_pool_datum.pool_nft == op["pool_nft"],
        ctx.old_pool_datum.lp_supply == op["lp_supply"],
        ctx.new_pool_datum.total_liquidity == np_["total_liquidity"],
        ctx.new_pool_datum.active_coverage == np_["active_coverage"],
        ctx.new_pool_datum.lp_token_policy == np_["lp_token_policy"],
        ctx.new_pool_datum.protocol_fee_bps == np_["protocol_fee_bps"],
        ctx.new_pool_datum.pool_nft == np_["pool_nft"],
        ctx.new_pool_datum.lp_supply == np_["lp_supply"],
        ctx.new_policy_datum.policy_id == pd["policy_id"],
        ctx.new_policy_datum.insured == pd["insured"],
        ctx.new_policy_datum.strike_price == pd["strike_price"],
        ctx.new_policy_datum.coverage_amount == pd["coverage_amount"],
        ctx.new_policy_datum.premium_paid == pd["premium_paid"],
        ctx.new_policy_datum.start_time == pd["start_time"],
        ctx.new_policy_datum.expiry_time == pd["expiry_time"],
        ctx.new_policy_datum.oracle_nft == pd["oracle_nft"],
        ctx.new_policy_datum.pool_script_hash == pd["pool_script_hash"],
        ctx.new_policy_datum.pool_nft == pd["pool_nft"],
        ctx.new_policy_datum.oracle_provider == pd["oracle_provider"],
        ctx.new_policy_datum.partner_address_is_some
        == pd["partner_address_is_some"],
        ctx.new_policy_datum.partner_address_id == pd["partner_address_id"],
        ctx.new_policy_datum.partner_share_bps == pd["partner_share_bps"],
        ctx.redeemer.coverage == r["coverage"],
        ctx.redeemer.premium == r["premium"],
        ctx.own_input_lovelace == fx["own_input_lovelace"],
        ctx.cont_output_lovelace == fx["cont_output_lovelace"],
        ctx.team_output_lovelace == fx["team_output_lovelace"],
        ctx.partner_output_lovelace == fx["partner_output_lovelace"],
        ctx.own_pool_script_hash == fx["own_pool_script_hash"],
        ctx.validity_range.lb == vr["lb"],
        ctx.validity_range.ub == vr["ub"],
        ctx.treasury_donation.is_some == td["is_some"],
        ctx.treasury_donation.amount == td["amount"],
        ctx.consts.team_address_id == co["team_address_id"],
        ctx.consts.pool_address_id == co["pool_address_id"],
        ctx.consts.policy_script_hash == co["policy_script_hash"],
        ctx.consts.min_utxo_lovelace == co["min_utxo_lovelace"],
        ctx.consts.min_premium == co["min_premium"],
        ctx.consts.partner_share_cap_bps == co["partner_share_cap_bps"],
        ctx.consts.treasury_share_bps == co["treasury_share_bps"],
        ctx.consts.protocol_fee_bps == co["protocol_fee_bps"],
    ]


BRANCH_PINNERS = {
    "Underwrite": _pin_underwrite,
    "ProcessClaim": pin_process_claim_ctx,
    "AddLiquidity": pin_add_liquidity_ctx,
    "RemoveLiquidity": pin_remove_liquidity_ctx,
    "AcceptCancellation": pin_accept_cancellation_ctx,
    "BatchUnderwrite": pin_batch_underwrite_ctx,
}


# ---------------------------------------------------------------------------
# (branch, property) pair enumeration
# ---------------------------------------------------------------------------


def _enumerate_pairs() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for branch, props in BRANCH_PROPERTIES.items():
        for prop_name in sorted(props.keys()):
            out.append((branch, prop_name))
    return out


BRANCH_PROPERTY_PAIRS: list[tuple[str, str]] = _enumerate_pairs()


# ---------------------------------------------------------------------------
# Aiken-mappable predicates (Tier 2)
# ---------------------------------------------------------------------------


# Aiken's public helpers we can call directly with concrete inputs.
# Each entry maps a (branch, property) pair to a callable that, given
# a fixture dict, returns ((aiken_function_name, args_tuple), bool_prediction)
# OR None if the pair has no direct Aiken mapping.
def _aiken_pair_can_underwrite(fx: dict) -> tuple[str, tuple[int, int, int], bool]:
    """Map the Underwrite branch's can_underwrite implication."""
    total = fx["old_pool_datum"]["total_liquidity"]
    active = fx["old_pool_datum"]["active_coverage"]
    coverage = fx["redeemer"]["coverage"]
    return (
        "can_underwrite",
        (total, active, coverage),
        (total - active) >= coverage,
    )


def _aiken_pair_can_underwrite_batch(
    fx: dict,
) -> tuple[str, tuple[int, int, int], bool]:
    """Map the BatchUnderwrite branch's aggregate can_underwrite check."""
    total = fx["old_pool_datum"]["total_liquidity"]
    active = fx["old_pool_datum"]["active_coverage"]
    coverage = fx["redeemer"]["total_coverage"]
    return (
        "can_underwrite",
        (total, active, coverage),
        (total - active) >= coverage,
    )


def _aiken_pair_can_withdraw(fx: dict) -> tuple[str, tuple[int, int, int], bool]:
    total = fx["old_pool_datum"]["total_liquidity"]
    active = fx["old_pool_datum"]["active_coverage"]
    amount = fx["redeemer"]["amount"]
    return (
        "can_withdraw",
        (total, active, amount),
        (total - amount) >= active,
    )


def _aiken_pair_is_premium_adequate(
    fx: dict,
) -> tuple[str, tuple[int, int], bool]:
    premium = fx["redeemer"]["premium"]
    coverage = fx["redeemer"]["coverage"]
    return (
        "is_premium_adequate",
        (premium, coverage),
        premium >= 2_000_000 and premium > 0 and coverage <= premium * 50,
    )


AIKEN_MAPPED_PAIRS: dict[tuple[str, str], Any] = {
    # The Underwrite branch's `can_cover` guard maps directly to
    # `can_underwrite/3`. We hook off `no_negative_active_coverage`
    # because that property is the one that semantically depends on
    # available_liquidity >= coverage.
    ("Underwrite", "no_negative_active_coverage"): _aiken_pair_can_underwrite,
    ("BatchUnderwrite", "can_cover_holds"): _aiken_pair_can_underwrite_batch,
    ("RemoveLiquidity", "withdrawal_safe"): _aiken_pair_can_withdraw,
    # is_premium_adequate is one of the guards on the Underwrite
    # `pool_conservation` predicate's input space; differentially
    # test that boolean.
    ("Underwrite", "pool_conservation"): _aiken_pair_is_premium_adequate,
}


# ---------------------------------------------------------------------------
# Differential result
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class DifferentialResult:
    """Per-sample result of running a (branch, property) check.

    `concrete_holds = True` if the property holds on the concrete input
    (Z3 returns UNSAT on the negation under the pinned ctx). False
    means the input is a COUNTEREXAMPLE; the differential pipeline
    expects every sample to have `concrete_holds = True` because all
    27 pairs are proven globally UNSAT.

    `aiken_input` (if set) is the (function_name, args, expected) tuple
    that maps the input to an Aiken helper for Tier-2 subprocess
    verification.
    """

    branch: str
    property: str
    seed: int
    sampled: bool
    concrete_holds: bool | None
    fixture: dict | None
    aiken_input: tuple[str, tuple, bool] | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Core run
# ---------------------------------------------------------------------------


def _build_concrete_solver(branch: str, fixture: dict):
    """Build a fresh Solver loaded with the encoder + the pinned
    fixture + the protocol-const pins.

    Returns (ctx, encoder, solver). The caller then adds the property
    (negated) and asks check().
    """
    encoder_cls, ctx_factory, _ = BRANCH_GENERATORS[branch]
    ctx = ctx_factory()
    encoder = encoder_cls()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    pinner = BRANCH_PINNERS[branch]
    for c in pinner(ctx, fixture):
        solver.add(c)
    return ctx, encoder, solver


def run_pair(
    branch: str,
    property_name: str,
    seed: int,
) -> DifferentialResult:
    """Sample ONE concrete input for (branch, property), evaluate."""
    if branch not in BRANCH_GENERATORS:
        raise ValueError(f"Unknown branch '{branch}'")
    if property_name not in BRANCH_PROPERTIES.get(branch, {}):
        raise ValueError(
            f"Property '{property_name}' not registered for branch '{branch}'"
        )

    needs_address_distinctness = property_name == "partner_not_aliased"

    model, ctx_for_sampling = sample_satisfying_assignment(
        branch,
        seed,
        address_distinctness=needs_address_distinctness,
    )
    if model is None:
        return DifferentialResult(
            branch=branch,
            property=property_name,
            seed=seed,
            sampled=False,
            concrete_holds=None,
            fixture=None,
            error="diversity pins yielded UNSAT (retry with another seed)",
        )

    fixture = model_to_fixture(branch, model, ctx_for_sampling)

    # Now re-run with the CONCRETE pinning, asking the negated property.
    # This is the differential step: the abstract proof says UNSAT for
    # ANY input in the constraint space, so the concrete pinning should
    # also be UNSAT.
    ctx, encoder, solver = _build_concrete_solver(branch, fixture)
    if needs_address_distinctness:
        for c in address_distinctness_pins(ctx):
            solver.add(c)
    prop = BRANCH_PROPERTIES[branch][property_name]()
    solver.add(prop.check(encoder, ctx))
    res = solver.check()

    concrete_holds = res == unsat

    aiken_input = None
    pair_key = (branch, property_name)
    if pair_key in AIKEN_MAPPED_PAIRS and AIKEN_MAPPED_PAIRS[pair_key] is not None:
        try:
            aiken_input = AIKEN_MAPPED_PAIRS[pair_key](fixture)
        except (KeyError, TypeError):
            aiken_input = None

    return DifferentialResult(
        branch=branch,
        property=property_name,
        seed=seed,
        sampled=True,
        concrete_holds=concrete_holds,
        fixture=fixture,
        aiken_input=aiken_input,
    )


def write_fixture(out_dir: Path, result: DifferentialResult) -> Path | None:
    """Write a generated fixture to disk for Aiken consumption.

    The Aiken side reads these fixtures by indexing on the
    (branch, property, seed) triple.
    """
    if result.fixture is None:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    name = (
        f"fuzz_{result.branch}_{result.property}_{result.seed:08d}.json"
    )
    path = out_dir / name
    path.write_text(json.dumps(result.fixture, indent=2), encoding="utf-8")
    return path
