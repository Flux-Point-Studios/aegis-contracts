"""Safety properties.

A property captures a safety claim about a validator branch. Each
property is a class whose `check(encoder, ctx)` method returns a Z3
expression representing the NEGATION of the property — Z3 finding a
counterexample (SAT) means the property is VIOLATED, while UNSAT means
the property holds across the encoder's full input domain.

Convention reminder: properties return the NEGATION. This matches the
counterexample-driven workflow (find a model that violates the safety
claim) and avoids needing two methods per property.

To add a new property:
  1. Subclass `BaseProperty`.
  2. Implement `check(encoder, ctx)` returning a Z3 BoolRef that is
     SAT iff the property is violated.
  3. Add a test file `tests/test_property_<name>.py` with the
     proven-pair AND counterexample-pair tests (see rubric in
     `V12.2_ROUND_9_T2_FOUNDATION.md`).
"""

from __future__ import annotations

from .base import BaseProperty
from .pool_conservation import PoolConservationProperty
from .no_negative_active_coverage import NoNegativeActiveCoverageProperty
from .no_negative_pool_state import NoNegativePoolStateProperty
from .immutable_pool_datum import ImmutablePoolDatumProperty
from .partner_not_aliased import PartnerNotAliasedProperty
from .payout_bounded_by_coverage import PayoutBoundedByCoverageProperty
from .lp_mint_matches_formula import LpMintMatchesFormulaProperty
from .withdrawal_safe import WithdrawalSafeProperty
from .refund_bounded_by_premium import RefundBoundedByPremiumProperty
from .can_cover_holds import CanCoverHoldsProperty

__all__ = [
    "BaseProperty",
    "PoolConservationProperty",
    "NoNegativeActiveCoverageProperty",
    "NoNegativePoolStateProperty",
    "ImmutablePoolDatumProperty",
    "PartnerNotAliasedProperty",
    "PayoutBoundedByCoverageProperty",
    "LpMintMatchesFormulaProperty",
    "WithdrawalSafeProperty",
    "RefundBoundedByPremiumProperty",
    "CanCoverHoldsProperty",
]
