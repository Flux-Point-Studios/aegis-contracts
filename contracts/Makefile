# =============================================================================
# Aegis contracts Makefile
# Location: D:/aegis/contracts/Makefile
#
# Convenience targets for the property-fuzz layer (Round 10) and the existing
# Aiken test suite. The fuzz layer complements the Z3 SMT proofs
# (`D:/aegis/redteam/z3_conservation_proof.py`, 49 invariants) and the
# Aegis-specific symbolic executor (`D:/aegis/redteam/symbolic_executor/`,
# 27 branch x property pairs PROVEN UNSAT) with randomized adversarial
# sampling.
#
# Two layers run independently:
#   - fuzz-aiken : aiken check (includes Team A's Aiken-native property tests
#                  under contracts/lib/aegis/test_helpers/).
#   - fuzz-python: pytest against the differential fuzzer under
#                  D:/aegis/redteam/symbolic_executor/fuzz/.
#
# Windows note: aiken's stdout is dropped when piped through Git Bash on
# Windows (see memory bank `reference_aiken_windows_stdout_workaround`).
# All aiken invocations route through `cmd //c "... 2>&1"` to capture the
# stream reliably across both Linux CI and Windows local runs.
# =============================================================================

.PHONY: check fuzz-aiken fuzz-python fuzz-python-deep fuzz-all help

# Default: a plain Aiken type-check + the full test suite.
check:
	cmd //c "aiken check 2>&1"

# Aiken layer: property tests live alongside the existing 356 unit tests in
# contracts/lib/aegis/**/*.ak; `aiken check` runs every `test` declaration.
fuzz-aiken:
	cmd //c "aiken check 2>&1"

# Python differential fuzz layer. The runner lives under
# D:/aegis/redteam/symbolic_executor/fuzz/. Default iteration count comes from
# the runner's conftest (N=1000 per (branch x property) pair).
fuzz-python:
	cd ../redteam/symbolic_executor && pytest fuzz/ -v

# Deep variant. Cranks the iteration count to N=100000 per pair. Intended for
# the nightly CI job; takes ~10-15 minutes on a 2024 laptop. Local dev should
# prefer `fuzz-python` for the inner loop.
fuzz-python-deep:
	cd ../redteam/symbolic_executor && pytest fuzz/ -v --slow

# Composite: run both layers in sequence. CI uses this target.
fuzz-all: fuzz-aiken fuzz-python

help:
	@echo "Aegis contracts Makefile targets:"
	@echo "  check             - aiken check (type-check + 356 existing tests)"
	@echo "  fuzz-aiken        - aiken check (includes Team A property tests)"
	@echo "  fuzz-python       - pytest D:/aegis/redteam/symbolic_executor/fuzz/"
	@echo "  fuzz-python-deep  - pytest --slow (N=100000 per pair, ~15 min)"
	@echo "  fuzz-all          - fuzz-aiken then fuzz-python"
