"""Partner-not-aliased property — branch-parameterized (R8-DRAIN-1 family).

Safety claim: when `partner_address.is_some()`, the partner Address
does NOT equal:
  - team_address, OR
  - pool_address (own_input.address), OR
  - any Address whose payment_credential == Script(policy_script_hash).

Branches:
  - Underwrite          — applies to `new_policy_datum.partner_*` fields
                          (the new policy being CREATED).
  - AcceptCancellation  — applies to `consumed_policy_datum.partner_*`
                          fields (the old policy being CANCELLED).
                          Hedge against V11 policies on chain that
                          weren't validated against R8-DRAIN-1 at
                          creation time.
  - BatchUnderwrite     — applies to the AGGREGATE walker output
                          `batch_totals.aliased_partner_present`.
                          Per-element aliasing inside the batch is
                          REJECTED iff this flag is 0. Counter-
                          example shape: a batch whose walker
                          flagged some entry as aliased; the
                          aggregate flag is 1; without the
                          `partner_addresses_not_aliased` guard the
                          tx would still be accepted.

Load-bearing guards (each turns the property false when dropped):
  - Underwrite          : `partner_not_aliased`
  - AcceptCancellation  : `partner_not_aliased`
  - BatchUnderwrite     : `partner_addresses_not_aliased`

References:
  - `partner_address_not_aliased` helper at pool.ak line 534
  - V12.2_ROUND_8_DRAIN.md
"""

from __future__ import annotations

from z3 import And, BoolRef, Or

from ..encoders.base import BaseEncoder
from .base import BaseProperty


class PartnerNotAliasedProperty(BaseProperty):
    name = "partner_not_aliased"
    description = (
        "When partner_address.is_some, the partner address does not alias "
        "with team_address, pool_address, or the policy_script_hash credential."
    )

    def __init__(self, branch: str = "Underwrite") -> None:
        self.branch = branch

    def check(self, encoder: BaseEncoder, ctx) -> BoolRef:
        c = ctx.consts

        if self.branch == "Underwrite":
            pd = ctx.new_policy_datum
        elif self.branch == "AcceptCancellation":
            pd = ctx.consumed_policy_datum
        elif self.branch == "BatchUnderwrite":
            # Aggregate flag: the walker emits 1 iff ANY policy in the
            # batch aliased a privileged address. Property violated iff
            # the flag is 1 (the validator would have to reject).
            return ctx.batch_totals.aliased_partner_present == 1
        else:
            raise ValueError(
                f"partner_not_aliased: branch {self.branch!r} does not have "
                f"partner fields. Supported: Underwrite, AcceptCancellation, "
                f"BatchUnderwrite."
            )

        # Negated property:
        #   partner is Some(addr) AND addr aliases with a privileged address.
        return And(
            pd.partner_address_is_some == 1,
            Or(
                pd.partner_address_id == c.team_address_id,
                pd.partner_address_id == c.pool_address_id,
                pd.partner_address_id == c.policy_script_hash,
            ),
        )
