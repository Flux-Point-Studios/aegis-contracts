"""BaseProperty ABC.

A property's `check(encoder, ctx)` returns the *negation* of the
safety claim — a Z3 expression that is SAT iff the property is
VIOLATED. This convention is load-bearing: the test rubric (see
README + V12.2_ROUND_9_T2_FOUNDATION.md) adds the encoder's guards
plus the negated property and asks the solver. UNSAT = PROVEN.
"""

from __future__ import annotations

import abc

from z3 import BoolRef

from ..context import SymbolicScriptContext
from ..encoders.base import BaseEncoder


class BaseProperty(abc.ABC):
    """Abstract base for safety properties."""

    #: Human-readable property name (shown in CLI output + reports)
    name: str = "<unnamed property>"

    #: Plain-English description of the safety claim
    description: str = ""

    @abc.abstractmethod
    def check(
        self, encoder: BaseEncoder, ctx: SymbolicScriptContext
    ) -> BoolRef:
        """Return a Z3 expression that is SAT iff the property is VIOLATED.

        The standard call-site pattern is:

            solver = Solver()
            for c in encoder.encode(ctx):
                solver.add(c)
            solver.add(prop.check(encoder, ctx))
            result = solver.check()  # unsat == PROVEN

        Encoders may declare property-relevant intermediate variables
        (e.g. `fee_total`); properties access them via
        `encoder._intermediates_for(ctx)`. This is a deliberate
        encoder-property coupling — the property author is expected to
        be aware of the encoder's intermediates.
        """
        raise NotImplementedError
