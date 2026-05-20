# Aegis Symbolic Executor

Z3-backed symbolic execution for Aegis's Plutus V3 validator branches.

## What this IS

A small, Aegis-specific framework that:

1. Encodes a chosen validator branch (e.g. `Underwrite`) as a list of Z3 integer
   constraints — one per `let foo_ok = ...` line in the Aiken source.
2. Lets you ASSERT a safety property as the NEGATED claim and ask Z3 for a
   counterexample. UNSAT = property proven across the encoder's symbolic
   input domain.
3. Lets you DROP individual guards (`disable_guards={"value_ok"}`) and watch
   the same property turn into a counterexample — which proves the guard
   is load-bearing for that property.

The worked example is the `Underwrite` arm of `validators/pool.ak` (V12.2 R7).
Four safety properties ship as foundational examples:

- `pool_conservation`           — premium == net_pool_growth + fee_total
- `no_negative_active_coverage` — 0 <= new_active <= new_total
- `immutable_pool_datum`        — lp_token_policy / protocol_fee_bps / pool_nft / lp_supply
- `partner_not_aliased`         — R8-DRAIN-1 invariant

## What this IS NOT

- A general Plutus FV framework. We don't model UPLC semantics, CBOR, or
  arbitrary Aiken programs.
- A full ScriptContext model. We encode only the fields each branch actually
  reads. `context.py` documents the explicit omissions.

## Hard rules

- Properties return the NEGATION of the safety claim. Z3 SAT = violated.
- Every property ships with a PAIRED test: prove it UNSAT under the full
  encoder; then ASSERT it produces a counterexample (SAT) when the
  load-bearing guard is dropped. The counterexample-pair test is the
  load-bearing-guard PROOF. If the property still holds without a guard,
  surface that as "guard is redundant" — interesting finding.
- "Pristine and flawless." If a property cannot be proven, surface it
  as a TODO/finding — do NOT silently drop. If a field the validator
  reads is not modelled, surface it as a TODO in the encoder.

## Adding a new branch encoder

Template (see `encoders/underwrite.py` for the worked version):

```python
from .base import BaseEncoder, GuardedConstraints

class ProcessClaimEncoder(BaseEncoder):
    GUARD_NAMES = ("payout_positive", "datum_ok", "value_ok", ...)

    def _intermediate_definitions(self, ctx):
        # Define any derived quantities your guards reference.
        return []

    def _guard_constraints(self, ctx):
        return [
            GuardedConstraints("payout_positive", [ctx.redeemer.payout > 0]),
            # ... one entry per `let foo_ok = ...` in the Aiken branch
        ]
```

Then register the encoder + the branch's safety properties in
`cli.py::BRANCHES`/`PROPERTIES` and add tests under `tests/`.

## Adding a new property

Template:

```python
from .base import BaseProperty
from z3 import And, BoolRef

class MyProperty(BaseProperty):
    name = "my_property"
    description = "..."

    def check(self, encoder, ctx) -> BoolRef:
        # Return the NEGATION of the safety claim — SAT iff violated.
        return ...
```

## Quick start

```bash
# Verify ONE property on the Underwrite branch:
python -m redteam.symbolic_executor verify \
    --branch Underwrite --property no_negative_active_coverage

# Verify ALL properties:
python -m redteam.symbolic_executor verify-all --branch Underwrite

# List the named guards for a branch (useful when adding a new property):
python -m redteam.symbolic_executor list-guards --branch Underwrite

# Confirm a guard is load-bearing for a property — should print
# COUNTEREXAMPLE instead of PROVEN:
python -m redteam.symbolic_executor verify \
    --branch Underwrite --property immutable_pool_datum \
    --disable-guard immutable_ok --show-model

# Run the test suite:
pytest D:/aegis/redteam/symbolic_executor/tests
```

## See also

- `V12.2_ROUND_9_T2_FOUNDATION.md` — full design write-up (in the parent dir).
- `z3_conservation_proof.py` — fee-math invariants (the predecessor work).
- `D:/aegis/contracts/validators/pool.ak` lines 630-792 — the Underwrite branch.
