"""Command-line entry point for the symbolic executor.

Usage:
    python -m redteam.symbolic_executor verify \\
        --branch Underwrite --property no_negative_active_coverage

Exits 0 on PROVEN, 1 on COUNTEREXAMPLE / UNKNOWN.

The CLI is intentionally thin — it wraps the encoder + property
pair, runs Z3, and prints a one-line result. For multi-property
batches use `verify-all`.

# Branch-to-property dispatch

Each branch has its own:
  - encoder class                  (see BRANCH_ENCODERS)
  - fresh-context factory          (see BRANCH_CONTEXT_FACTORIES)
  - list of applicable properties  (see BRANCH_PROPERTIES)

A property may apply to ONLY one branch (e.g.
`payout_bounded_by_coverage` is ProcessClaim-only) or to many (e.g.
`pool_conservation` applies to every branch). The CLI uses
`BRANCH_PROPERTIES` to gate which (branch, property) pairs are
verifiable.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Iterable

from z3 import Solver, sat, unsat

from .context import (
    fresh_accept_cancellation_context,
    fresh_add_liquidity_context,
    fresh_batch_underwrite_context,
    fresh_process_claim_context,
    fresh_remove_liquidity_context,
    fresh_underwrite_context,
    pin_protocol_constants,
)
from .encoders import (
    AcceptCancellationEncoder,
    AddLiquidityEncoder,
    BatchUnderwriteEncoder,
    ProcessClaimEncoder,
    RemoveLiquidityEncoder,
    UnderwriteEncoder,
)
from .properties import (
    BaseProperty,
    CanCoverHoldsProperty,
    ImmutablePoolDatumProperty,
    LpMintMatchesFormulaProperty,
    NoNegativeActiveCoverageProperty,
    NoNegativePoolStateProperty,
    PartnerNotAliasedProperty,
    PayoutBoundedByCoverageProperty,
    PoolConservationProperty,
    RefundBoundedByPremiumProperty,
    WithdrawalSafeProperty,
)


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------

BRANCH_ENCODERS = {
    "Underwrite": UnderwriteEncoder,
    "ProcessClaim": ProcessClaimEncoder,
    "AddLiquidity": AddLiquidityEncoder,
    "RemoveLiquidity": RemoveLiquidityEncoder,
    "AcceptCancellation": AcceptCancellationEncoder,
    "BatchUnderwrite": BatchUnderwriteEncoder,
}

BRANCH_CONTEXT_FACTORIES = {
    "Underwrite": fresh_underwrite_context,
    "ProcessClaim": fresh_process_claim_context,
    "AddLiquidity": fresh_add_liquidity_context,
    "RemoveLiquidity": fresh_remove_liquidity_context,
    "AcceptCancellation": fresh_accept_cancellation_context,
    "BatchUnderwrite": fresh_batch_underwrite_context,
}

# Mapping: branch -> { property_name -> property factory (no args) }.
# Factories produce a `BaseProperty` instance ready to call `.check()`.
def _branch_properties() -> dict[str, dict[str, "callable"]]:
    return {
        "Underwrite": {
            "pool_conservation": lambda: PoolConservationProperty("Underwrite"),
            "no_negative_active_coverage": lambda: NoNegativeActiveCoverageProperty(),
            "no_negative_pool_state": lambda: NoNegativePoolStateProperty("Underwrite"),
            "immutable_pool_datum": lambda: ImmutablePoolDatumProperty("Underwrite"),
            "partner_not_aliased": lambda: PartnerNotAliasedProperty("Underwrite"),
        },
        "ProcessClaim": {
            "pool_conservation": lambda: PoolConservationProperty("ProcessClaim"),
            "no_negative_pool_state": lambda: NoNegativePoolStateProperty("ProcessClaim"),
            "immutable_pool_datum": lambda: ImmutablePoolDatumProperty("ProcessClaim"),
            "payout_bounded_by_coverage": lambda: PayoutBoundedByCoverageProperty(),
        },
        "AddLiquidity": {
            "pool_conservation": lambda: PoolConservationProperty("AddLiquidity"),
            "no_negative_pool_state": lambda: NoNegativePoolStateProperty("AddLiquidity"),
            "immutable_pool_datum": lambda: ImmutablePoolDatumProperty("AddLiquidity"),
            "lp_mint_matches_formula": lambda: LpMintMatchesFormulaProperty(),
        },
        "RemoveLiquidity": {
            "pool_conservation": lambda: PoolConservationProperty("RemoveLiquidity"),
            "no_negative_pool_state": lambda: NoNegativePoolStateProperty("RemoveLiquidity"),
            "immutable_pool_datum": lambda: ImmutablePoolDatumProperty("RemoveLiquidity"),
            "withdrawal_safe": lambda: WithdrawalSafeProperty(),
        },
        "AcceptCancellation": {
            "pool_conservation": lambda: PoolConservationProperty("AcceptCancellation"),
            "no_negative_pool_state": lambda: NoNegativePoolStateProperty("AcceptCancellation"),
            "immutable_pool_datum": lambda: ImmutablePoolDatumProperty("AcceptCancellation"),
            "partner_not_aliased": lambda: PartnerNotAliasedProperty("AcceptCancellation"),
            "refund_bounded_by_premium": lambda: RefundBoundedByPremiumProperty(),
        },
        "BatchUnderwrite": {
            "pool_conservation": lambda: PoolConservationProperty("BatchUnderwrite"),
            "no_negative_pool_state": lambda: NoNegativePoolStateProperty("BatchUnderwrite"),
            "immutable_pool_datum": lambda: ImmutablePoolDatumProperty("BatchUnderwrite"),
            "partner_not_aliased": lambda: PartnerNotAliasedProperty("BatchUnderwrite"),
            "can_cover_holds": lambda: CanCoverHoldsProperty(),
        },
    }


BRANCH_PROPERTIES = _branch_properties()

# Foundation-compat alias: the original `PROPERTIES` map for the
# Underwrite branch (used by the foundation's `verify-all` test).
PROPERTIES = {
    name: factory for name, factory in BRANCH_PROPERTIES["Underwrite"].items()
}

# Foundation-compat alias: the original `BRANCHES` map.
BRANCHES = BRANCH_ENCODERS

# Auxiliary: address-distinctness pins. The partner_not_aliased
# property requires team / pool / policy_script_hash to be DISTINCT
# in the symbolic ctx so the model has freedom to ALIAS (otherwise
# Z3 collapses them). We supply this as a helper rather than as
# `pin_protocol_constants` because it's caller-state, not chain-pin.
def address_distinctness_pins(ctx) -> list:
    """Return constraints making the three privileged-address Ints distinct."""
    c = ctx.consts
    return [
        c.team_address_id != c.pool_address_id,
        c.team_address_id != c.policy_script_hash,
        c.pool_address_id != c.policy_script_hash,
    ]


def _build_context_and_solver(branch: str, disable_guards: Iterable[str]):
    if branch not in BRANCH_ENCODERS:
        raise SystemExit(
            f"Branch '{branch}' is not implemented. Available: "
            f"{sorted(BRANCH_ENCODERS.keys())}"
        )
    ctx = BRANCH_CONTEXT_FACTORIES[branch]()
    encoder = BRANCH_ENCODERS[branch](disable_guards=disable_guards)
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    return ctx, encoder, solver


def cmd_verify(args: argparse.Namespace) -> int:
    branch: str = args.branch
    prop_name: str = args.property
    branch_props = BRANCH_PROPERTIES.get(branch, {})
    if prop_name not in branch_props:
        print(
            f"Property '{prop_name}' is not registered for branch "
            f"'{branch}'. Available for this branch: "
            f"{sorted(branch_props.keys())}",
            file=sys.stderr,
        )
        return 2

    ctx, encoder, solver = _build_context_and_solver(
        branch, disable_guards=args.disable_guard or []
    )

    prop = branch_props[prop_name]()
    # If the property is partner_not_aliased, also pin address
    # distinctness so the model has freedom to alias (otherwise the
    # privileged address Ints can collapse to a single value).
    if prop_name == "partner_not_aliased":
        for c in address_distinctness_pins(ctx):
            solver.add(c)

    solver.add(prop.check(encoder, ctx))

    start = time.time()
    result = solver.check()
    elapsed = time.time() - start

    if result == unsat:
        print(
            f"PROVEN  branch={branch} property={prop_name} "
            f"elapsed={elapsed:.3f}s disabled={sorted(args.disable_guard or [])}"
        )
        return 0
    elif result == sat:
        print(
            f"COUNTEREXAMPLE  branch={branch} property={prop_name} "
            f"elapsed={elapsed:.3f}s disabled={sorted(args.disable_guard or [])}"
        )
        if args.show_model:
            print()
            print(solver.model())
        return 1
    else:
        print(
            f"UNKNOWN  branch={branch} property={prop_name} "
            f"elapsed={elapsed:.3f}s"
        )
        return 1


def cmd_list_guards(args: argparse.Namespace) -> int:
    branch: str = args.branch
    ctx, encoder, _ = _build_context_and_solver(branch, disable_guards=[])
    print(f"Guards for branch '{branch}':")
    for name in encoder.all_guard_names(ctx):
        print(f"  - {name}")
    return 0


def cmd_verify_all(args: argparse.Namespace) -> int:
    branch: str = args.branch
    if branch == "ALL":
        # Iterate over every (branch, property) pair.
        branches = list(BRANCH_ENCODERS.keys())
    else:
        branches = [branch]

    failures = 0
    for br in branches:
        branch_props = BRANCH_PROPERTIES.get(br, {})
        for prop_name in sorted(branch_props.keys()):
            ctx, encoder, solver = _build_context_and_solver(
                br, disable_guards=[]
            )
            prop = branch_props[prop_name]()
            if prop_name == "partner_not_aliased":
                for c in address_distinctness_pins(ctx):
                    solver.add(c)
            solver.add(prop.check(encoder, ctx))
            start = time.time()
            result = solver.check()
            elapsed = time.time() - start
            status = (
                "PROVEN" if result == unsat
                else ("COUNTEREXAMPLE" if result == sat else "UNKNOWN")
            )
            tag = f"[{br}]"
            print(f"  {status:15s}  {tag:22s}  {prop_name:35s}  ({elapsed:.3f}s)")
            if result != unsat:
                failures += 1
    return 0 if failures == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="symbolic_executor",
        description="Aegis-specific symbolic executor (Z3-backed FV).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Aggregate "every property registered against any branch" choice list.
    all_property_names = sorted(
        {p for props in BRANCH_PROPERTIES.values() for p in props}
    )

    p_verify = sub.add_parser("verify", help="Verify ONE property on a branch.")
    p_verify.add_argument(
        "--branch", default="Underwrite", choices=list(BRANCH_ENCODERS.keys())
    )
    p_verify.add_argument(
        "--property", required=True, choices=all_property_names
    )
    p_verify.add_argument(
        "--disable-guard",
        action="append",
        default=[],
        help="Disable a named guard (repeatable). Use to confirm the guard is load-bearing.",
    )
    p_verify.add_argument(
        "--show-model",
        action="store_true",
        help="On COUNTEREXAMPLE, print the Z3 model.",
    )
    p_verify.set_defaults(func=cmd_verify)

    p_all = sub.add_parser(
        "verify-all",
        help="Run every property registered for a branch. "
             "Pass --branch ALL to run across every branch.",
    )
    p_all.add_argument(
        "--branch", default="Underwrite",
        choices=list(BRANCH_ENCODERS.keys()) + ["ALL"],
    )
    p_all.set_defaults(func=cmd_verify_all)

    p_list = sub.add_parser(
        "list-guards", help="List the named guards for a branch encoder."
    )
    p_list.add_argument(
        "--branch", default="Underwrite", choices=list(BRANCH_ENCODERS.keys())
    )
    p_list.set_defaults(func=cmd_list_guards)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
