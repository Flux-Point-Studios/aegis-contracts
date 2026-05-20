"""Branch encoders.

Each encoder takes a `SymbolicScriptContext` and produces a list of Z3
boolean constraints representing the conjunction of guards that the
corresponding validator branch enforces. A "branch" here is one arm of
the `when redeemer is { ... }` switch in `validators/pool.ak`.

To add a new branch encoder, follow `underwrite.py` as a template:
  1. Subclass `BaseEncoder`.
  2. Override `encode(ctx)` to return the guard list.
  3. Map each Aiken `let foo_ok = ...` line to a named entry in
     `_guard_constraints()` (so `disable_guards={"foo_ok"}` can drop it
     for the counterexample-pair test).
"""

from __future__ import annotations

from .base import BaseEncoder, GuardedConstraints
from .underwrite import UnderwriteEncoder
from .process_claim import ProcessClaimEncoder
from .add_liquidity import AddLiquidityEncoder
from .remove_liquidity import RemoveLiquidityEncoder
from .accept_cancellation import AcceptCancellationEncoder
from .batch_underwrite import BatchUnderwriteEncoder

__all__ = [
    "BaseEncoder",
    "GuardedConstraints",
    "UnderwriteEncoder",
    "ProcessClaimEncoder",
    "AddLiquidityEncoder",
    "RemoveLiquidityEncoder",
    "AcceptCancellationEncoder",
    "BatchUnderwriteEncoder",
]
