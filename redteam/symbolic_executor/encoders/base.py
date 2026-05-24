"""BaseEncoder ABC.

The encoder layer converts an Aiken validator branch into a Z3
constraint list. Each `let <name>_ok = <expr>` in the validator becomes
a NAMED guard so the counterexample-pair test can drop a specific guard
and prove it is load-bearing.

Convention: a guard is the `(name, [Z3 expressions])` pair returned by
`_guard_constraints`. The encoder's `encode(ctx)` method then either:
  * Adds ALL guards (the default, "branch is fully enforced" mode), OR
  * Drops the guards named in `disable_guards`, modelling "what would
    the validator accept if we deleted this `&&`?"

The fact that EVERY guard must be in `disable_guards` to be droppable
is a deliberate ergonomic — typos are caught loudly because dropping a
nonexistent guard raises.
"""

from __future__ import annotations

import abc
import dataclasses
from typing import FrozenSet, Iterable, Sequence

from z3 import BoolRef

# NOTE: `ctx` is typed as `object` at the base layer because the five
# extended branches (ProcessClaim, AddLiquidity, RemoveLiquidity,
# AcceptCancellation, BatchUnderwrite) each have their own per-branch
# context dataclass (see `context.py`). Subclasses ascribe the precise
# type in their signatures. We deliberately avoid `Union[...]` here to
# keep the framework extensible without touching the base each time a
# new branch is added.


@dataclasses.dataclass(frozen=True)
class GuardedConstraints:
    """A single named guard in a branch encoder."""

    name: str
    constraints: Sequence[BoolRef]


class BaseEncoder(abc.ABC):
    """Abstract base for branch encoders.

    Subclasses MUST override `_guard_constraints(ctx)` to return the
    full list of named guards. They may also override `encode(ctx)` if
    they need to add cross-guard constraints (e.g. lateral pinning of
    derived intermediate variables).
    """

    def __init__(
        self,
        disable_guards: Iterable[str] | None = None,
    ) -> None:
        self.disable_guards: FrozenSet[str] = frozenset(disable_guards or [])

    @abc.abstractmethod
    def _guard_constraints(
        self, ctx
    ) -> list[GuardedConstraints]:
        """Return the full ordered list of named guards.

        Each entry corresponds to one `let foo_ok = ...` line in the
        Aiken branch and produces ZERO OR MORE Z3 boolean constraints
        whose CONJUNCTION encodes that guard.

        Guards with multiple constraints (e.g. "datum_ok" expands to
        two equalities) keep them as a list so a future agent can drop
        them as a single guard or split them out.
        """
        raise NotImplementedError

    def encode(
        self,
        ctx,
        include_definitions: bool = True,
    ) -> list[BoolRef]:
        """Produce the Z3 constraint list for this branch.

        `include_definitions=True` also adds the encoder's intermediate
        variable definitions (fee_total, net_pool_growth, team_cut,
        partner_cut). Properties that talk about these intermediates
        need them; properties that only talk about top-level fields can
        skip them, but the default is to include them.

        Drops any guard whose `name` is in `self.disable_guards`.
        """
        unknown = self.disable_guards - {g.name for g in self._guard_constraints(ctx)}
        if unknown:
            raise ValueError(
                f"disable_guards references unknown guards: {sorted(unknown)}"
            )

        out: list[BoolRef] = []
        if include_definitions:
            out.extend(self._intermediate_definitions(ctx))

        for guard in self._guard_constraints(ctx):
            if guard.name in self.disable_guards:
                continue
            out.extend(guard.constraints)
        return out

    def _intermediate_definitions(
        self, ctx
    ) -> list[BoolRef]:
        """Override to declare intermediate-variable defining constraints.

        Default: nothing. The Underwrite encoder uses this to pin
        `fee_total == max(min_utxo, raw_fee)`, etc.
        """
        return []

    def all_guard_names(self, ctx) -> list[str]:
        """Convenience: enumerate the guard names for this encoder.

        Used by tests + the CLI's `--list-guards` introspection path.
        """
        return [g.name for g in self._guard_constraints(ctx)]
