"""Differential fuzzer for the Aegis symbolic executor.

Given Z3 has proven all 27 (branch, property) pairs UNSAT, this module
extends the proof with concrete-input differential testing:

  1. Sample N satisfying assignments from the encoder's constraint space.
  2. Materialize each into a concrete ScriptContext dict matching the
     existing JSON fixture shape (see `tests/fixtures/*_positive.json`).
  3. Re-evaluate the encoder + property predictions concretely.
  4. Where possible, run the input through the actual Aiken validator
     via `aiken check` subprocess and assert the verdicts agree.

If Z3's prediction disagrees with the concrete re-evaluation, that's a
model-bug finding. If Z3 agrees with concrete re-evaluation but Aiken
disagrees, that's a validator-bug finding. Both are surfaced as test
failures with file:line citations.
"""

from __future__ import annotations

from .concrete_generator import (
    BRANCH_GENERATORS,
    generate_concrete_fixture,
    model_to_fixture,
    sample_satisfying_assignment,
)
from .differential import (
    BRANCH_PROPERTY_PAIRS,
    DifferentialResult,
    run_pair,
)
from .fuzz_runner import (
    FuzzReport,
    fuzz_pair,
    fuzz_pair_with_aiken,
)

__all__ = [
    "BRANCH_GENERATORS",
    "BRANCH_PROPERTY_PAIRS",
    "DifferentialResult",
    "FuzzReport",
    "fuzz_pair",
    "fuzz_pair_with_aiken",
    "generate_concrete_fixture",
    "model_to_fixture",
    "run_pair",
    "sample_satisfying_assignment",
]
