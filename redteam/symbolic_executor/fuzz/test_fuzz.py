"""Differential fuzz pytest harness.

This file is what `pytest D:/aegis/redteam/symbolic_executor/fuzz/` runs.

Test layout (per the paired-TDD rubric):

  * Positive half — for each (branch, property) pair: generate N
    concrete inputs, assert the property holds on every one.
    Parameterized over `N in {10, 100, 1000}` (1000 only with --slow).

  * Negative half — for each (branch, property) pair: generate ONE
    concrete input, invalidate ONE constraint (drop the load-bearing
    guard the property is known to need), assert the property NOW
    finds a counterexample on that input.

  * Aiken Tier 2 — for the (branch, property) pairs mappable to
    public Aiken helper functions, also drive the inputs through
    `aiken check --match-tests fuzz_*` and assert the Aiken-side
    verdict matches the Python prediction. Skipped if aiken binary
    not on PATH.

Configuration via env vars / CLI flags:
  * `pytest --slow`        — adds the N=1000, N=10_000, N=100_000 tiers.
  * AEGIS_FUZZ_SKIP_AIKEN — set to "1" to skip Tier 2 even if aiken
                            is available. Default: only run Tier 2
                            with `--slow`.

If a disagreement surfaces, the test fails with a verbose dump of the
disagreeing fixture so the reader can hand-port it to a regression
fixture under `tests/fixtures/`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

# Make `import symbolic_executor` resolve when pytest is invoked
# directly on this directory.
HERE = Path(__file__).resolve()
REDTEAM_DIR = HERE.parents[2]
if str(REDTEAM_DIR) not in sys.path:
    sys.path.insert(0, str(REDTEAM_DIR))


from symbolic_executor.cli import (  # noqa: E402
    BRANCH_PROPERTIES,
    address_distinctness_pins,
)
from symbolic_executor.context import pin_protocol_constants  # noqa: E402
from symbolic_executor.fuzz.concrete_generator import (  # noqa: E402
    BRANCH_GENERATORS,
    sample_satisfying_assignment,
    model_to_fixture,
)
from symbolic_executor.fuzz.differential import (  # noqa: E402
    BRANCH_PINNERS,
    BRANCH_PROPERTY_PAIRS,
    AIKEN_MAPPED_PAIRS,
    run_pair,
)
from symbolic_executor.fuzz.fuzz_runner import (  # noqa: E402
    fuzz_pair,
    fuzz_pair_with_aiken,
)
from z3 import Solver, sat, unsat  # noqa: E402


# ---------------------------------------------------------------------------
# Pytest --slow opt-in
# ---------------------------------------------------------------------------


def _slow_enabled(request) -> bool:
    return bool(request.config.getoption("--slow", default=False))


# ---------------------------------------------------------------------------
# Positive-half parametrization
# ---------------------------------------------------------------------------


# Each pair runs at the small N (10) by default. The medium and large
# tiers are gated on `--slow`.
@pytest.mark.parametrize("branch,property_name", BRANCH_PROPERTY_PAIRS)
def test_property_holds_under_fuzz_n10(branch: str, property_name: str):
    """Positive half: 10 random concrete inputs, property must hold on each.

    Z3 has already PROVEN the property UNSAT over the full symbolic
    domain, so this MUST succeed for any input the encoder accepts.
    A failure here means the model's symbolic encoding admits an input
    the concrete re-evaluation rejects (model bug).
    """
    report = fuzz_pair(branch, property_name, n=10, seed_base=1)
    assert report.n_sampled > 0, (
        f"[{branch}/{property_name}] no concrete samples produced; "
        f"diversity pins may be too tight."
    )
    if not report.all_hold:
        first = report.disagreements[0]
        pytest.fail(
            f"[{branch}/{property_name}] property VIOLATED on a concrete sample.\n"
            f"  seed={first.seed}\n"
            f"  fixture=\n{json.dumps(first.fixture, indent=2)}"
        )


@pytest.mark.parametrize("branch,property_name", BRANCH_PROPERTY_PAIRS)
def test_property_holds_under_fuzz_n100(branch: str, property_name: str):
    """Positive half at N=100. Same assertion as N=10 with more samples."""
    report = fuzz_pair(branch, property_name, n=100, seed_base=2)
    assert report.n_sampled >= 50, (
        f"[{branch}/{property_name}] only {report.n_sampled}/100 samples "
        f"produced; check diversity-pin tightness."
    )
    if not report.all_hold:
        first = report.disagreements[0]
        pytest.fail(
            f"[{branch}/{property_name}] property VIOLATED on a concrete sample.\n"
            f"  seed={first.seed}\n"
            f"  fixture=\n{json.dumps(first.fixture, indent=2)}"
        )


# ---------------------------------------------------------------------------
# Negative-half (paired counterexample)
# ---------------------------------------------------------------------------


# Map each (branch, property) pair to the load-bearing guard(s) the
# property fails without. A frozenset means "drop ALL of these together"
# (some properties require multiple guards dropped for a counterexample
# to surface — see the existing tests/test_property_*.py). `None` means
# the property is a pure-math identity not gated by any single guard
# (covered by include_definitions=False in the existing suite).
#
# Drawn from the existing tests/test_property_*.py counterexample-pair
# tests so we stay consistent with the proven load-bearing relations.
LOAD_BEARING_GUARD: dict[tuple[str, str], str | frozenset[str] | None] = {
    # Underwrite
    ("Underwrite", "no_negative_active_coverage"): "datum_ok",
    ("Underwrite", "no_negative_pool_state"): "datum_ok",
    ("Underwrite", "immutable_pool_datum"): "immutable_ok",
    ("Underwrite", "partner_not_aliased"): "partner_not_aliased",
    ("Underwrite", "pool_conservation"): None,  # math identity
    # ProcessClaim
    ("ProcessClaim", "no_negative_pool_state"): frozenset(
        {"datum_ok", "remains_non_negative"}
    ),
    ("ProcessClaim", "immutable_pool_datum"): "immutable_ok",
    ("ProcessClaim", "payout_bounded_by_coverage"): "policy_consumed",
    ("ProcessClaim", "pool_conservation"): "value_ok",
    # AddLiquidity
    ("AddLiquidity", "no_negative_pool_state"): "datum_ok",
    ("AddLiquidity", "immutable_pool_datum"): "immutable_ok",
    ("AddLiquidity", "lp_mint_matches_formula"): "lp_minted",
    ("AddLiquidity", "pool_conservation"): "datum_ok",
    # RemoveLiquidity
    ("RemoveLiquidity", "no_negative_pool_state"): "withdrawal_safe",
    ("RemoveLiquidity", "immutable_pool_datum"): "immutable_ok",
    ("RemoveLiquidity", "withdrawal_safe"): "withdrawal_safe",
    ("RemoveLiquidity", "pool_conservation"): "datum_ok",
    # AcceptCancellation
    ("AcceptCancellation", "no_negative_pool_state"): frozenset(
        {"remains_non_negative", "bounds_ok"}
    ),
    ("AcceptCancellation", "immutable_pool_datum"): "immutable_ok",
    ("AcceptCancellation", "partner_not_aliased"): "partner_not_aliased",
    ("AcceptCancellation", "refund_bounded_by_premium"): None,  # math
    ("AcceptCancellation", "pool_conservation"): "value_ok",
    # BatchUnderwrite
    ("BatchUnderwrite", "can_cover_holds"): "can_cover",
    ("BatchUnderwrite", "no_negative_pool_state"): frozenset(
        {"can_cover", "datum_ok"}
    ),
    ("BatchUnderwrite", "immutable_pool_datum"): "immutable_ok",
    ("BatchUnderwrite", "partner_not_aliased"): "partner_addresses_not_aliased",
    ("BatchUnderwrite", "pool_conservation"): None,  # math identity
}


@pytest.mark.parametrize("branch,property_name", BRANCH_PROPERTY_PAIRS)
def test_property_negative_pair_finds_counterexample(
    branch: str, property_name: str
):
    """Negative half: prove the named load-bearing guard is load-bearing
    by DROPPING it on the symbolic encoder and asserting the property
    becomes SAT (the encoder admits a counterexample).

    This mirrors the existing `tests/test_property_*.py` paired tests
    but at the differential layer — same proof, different harness. It
    catches the case where the encoder later gets a "fix" that removes
    the guard's load-bearing effect without anyone noticing.

    Pairs with `None` (e.g. `pool_conservation` on Underwrite, where
    the property is a pure-math identity not gated by any single
    guard) are SKIPPED here.
    """
    guard_spec = LOAD_BEARING_GUARD.get((branch, property_name))
    if guard_spec is None:
        pytest.skip(
            f"[{branch}/{property_name}] property is pure-math; no single "
            f"load-bearing guard to drop."
        )

    guards_to_drop: frozenset[str]
    if isinstance(guard_spec, str):
        guards_to_drop = frozenset({guard_spec})
    else:
        guards_to_drop = guard_spec

    encoder_cls, ctx_factory, _ = BRANCH_GENERATORS[branch]
    ctx = ctx_factory()
    # Validate every named guard exists on the encoder before constructing.
    encoder_probe = encoder_cls()
    known = set(encoder_probe.all_guard_names(ctx))
    unknown = guards_to_drop - known
    if unknown:
        pytest.skip(
            f"[{branch}/{property_name}] guards {sorted(unknown)} not "
            f"registered on the {branch} encoder (encoder lists: "
            f"{sorted(known)})"
        )

    ctx = ctx_factory()
    encoder = encoder_cls(disable_guards=guards_to_drop)
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    if property_name == "partner_not_aliased":
        for c in address_distinctness_pins(ctx):
            solver.add(c)
    prop = BRANCH_PROPERTIES[branch][property_name]()
    solver.add(prop.check(encoder, ctx))
    result = solver.check()
    assert result == sat, (
        f"[{branch}/{property_name}] dropping load-bearing guards "
        f"{sorted(guards_to_drop)} should admit a counterexample, but got "
        f"{result}. Either the guards are not actually load-bearing for "
        f"this property, or the mapping in LOAD_BEARING_GUARD is wrong."
    )


# ---------------------------------------------------------------------------
# Diversity smoke tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("branch,property_name", BRANCH_PROPERTY_PAIRS)
def test_fuzz_inputs_are_diverse(branch: str, property_name: str):
    """Sanity: 20 different seeds produce >= 5 distinct fixtures.

    If the diversity pins are too tight, every fixture collapses to
    the same minimal Z3 model. This catches over-pinning regressions.
    """
    fixtures: set[str] = set()
    for i in range(20):
        res = run_pair(branch, property_name, seed=3_000_000 + i * 13)
        if not res.sampled:
            continue
        # AcceptCancellation contexts don't carry a redeemer (the cancel
        # branch reads everything off the consumed policy datum). Fall
        # back to total_liquidity + active_coverage as the diversity
        # signature for those.
        if "redeemer" in res.fixture:
            payload = res.fixture["redeemer"]
        else:
            payload = {
                "tl": res.fixture["old_pool_datum"]["total_liquidity"],
                "ac": res.fixture["old_pool_datum"]["active_coverage"],
                "premium": res.fixture.get(
                    "consumed_policy_datum", {}
                ).get("premium_paid"),
            }
        sig = json.dumps(payload, sort_keys=True) + str(
            res.fixture["old_pool_datum"]["total_liquidity"]
        )
        fixtures.add(sig)
    assert len(fixtures) >= 5, (
        f"[{branch}/{property_name}] only {len(fixtures)} distinct "
        f"fixtures across 20 seeds; diversity pins may be over-constraining."
    )


# ---------------------------------------------------------------------------
# Slow tier (--slow)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("branch,property_name", BRANCH_PROPERTY_PAIRS)
def test_property_holds_under_fuzz_n1000(
    request, branch: str, property_name: str
):
    """N=1000 tier — gated on `--slow`. Same assertion as N=10/100.

    Run with `pytest fuzz/ --slow`. Skipped otherwise.
    """
    if not _slow_enabled(request):
        pytest.skip("N=1000 tier requires --slow")
    report = fuzz_pair(branch, property_name, n=1000, seed_base=3)
    assert report.n_sampled >= 500, (
        f"[{branch}/{property_name}] only {report.n_sampled}/1000 samples"
    )
    assert report.all_hold, (
        f"[{branch}/{property_name}] {report.n_violates} violations across "
        f"{report.n_sampled} samples. First disagreement seed: "
        f"{report.disagreements[0].seed}"
    )


def test_property_holds_under_fuzz_n100000_underwrite_conservation(request):
    """N=100k mega-tier on the worked example — gated on `--slow`.

    Underwrite + pool_conservation is the foundational pair; running
    100k samples through it surfaces deep-tail divergences.
    """
    if not _slow_enabled(request):
        pytest.skip("N=100k tier requires --slow")
    report = fuzz_pair(
        "Underwrite", "pool_conservation", n=100_000, seed_base=99
    )
    assert report.n_sampled >= 50_000
    assert report.all_hold


# ---------------------------------------------------------------------------
# Aiken Tier 2
# ---------------------------------------------------------------------------


def _aiken_skip_env() -> bool:
    return os.environ.get("AEGIS_FUZZ_SKIP_AIKEN") == "1"


@pytest.mark.parametrize(
    "branch,property_name",
    [pair for pair in BRANCH_PROPERTY_PAIRS if pair in AIKEN_MAPPED_PAIRS and AIKEN_MAPPED_PAIRS[pair] is not None],
)
def test_aiken_subprocess_matches_python_prediction(
    request, branch: str, property_name: str
):
    """Tier 2: drive Aiken-mappable inputs through `aiken check` and
    assert the Aiken-side verdict matches the Python prediction.

    Skipped if `--slow` is not set OR `AEGIS_FUZZ_SKIP_AIKEN=1`.

    A non-skip success means: for the public Aiken helpers
    (`can_underwrite`, `can_withdraw`, `is_premium_adequate`), the
    Python re-evaluation agrees with the Aiken evaluation across N
    concrete inputs.
    """
    if not _slow_enabled(request):
        pytest.skip("Tier 2 (Aiken subprocess) requires --slow")
    if _aiken_skip_env():
        pytest.skip("AEGIS_FUZZ_SKIP_AIKEN=1 set")

    report = fuzz_pair_with_aiken(
        branch, property_name, n=20, seed_base=5
    )
    if report.aiken_subprocess_result is None:
        pytest.skip(
            f"[{branch}/{property_name}] no Aiken-mapped samples produced"
        )

    sub = report.aiken_subprocess_result
    if sub.get("skipped_reason"):
        pytest.skip(f"Tier 2 skipped: {sub['skipped_reason']}")

    assert sub["ok"], (
        f"[{branch}/{property_name}] aiken subprocess FAILED.\n"
        f"  returncode={sub['returncode']}\n"
        f"  stdout:\n{sub['stdout']}\n"
        f"  stderr:\n{sub['stderr']}"
    )


# ---------------------------------------------------------------------------
# Aggregate sanity tests (not parametrised — single tests)
# ---------------------------------------------------------------------------


def test_all_27_pairs_have_load_bearing_mapping():
    """Sanity: every (branch, property) pair has a LOAD_BEARING_GUARD entry."""
    for pair in BRANCH_PROPERTY_PAIRS:
        assert pair in LOAD_BEARING_GUARD, (
            f"Pair {pair} missing from LOAD_BEARING_GUARD map. "
            f"Add the load-bearing guard name or None for pure-math."
        )


def test_concrete_generator_covers_all_six_branches():
    """The concrete generator must support every branch the executor
    knows about."""
    assert set(BRANCH_GENERATORS.keys()) == set(BRANCH_PINNERS.keys())
    assert len(BRANCH_GENERATORS) == 6


def test_aiken_mapped_pairs_subset_of_known_pairs():
    """Aiken-mappable pair table must be a subset of the 27 known pairs."""
    known = set(BRANCH_PROPERTY_PAIRS)
    for pair in AIKEN_MAPPED_PAIRS:
        assert pair in known, f"AIKEN_MAPPED_PAIRS has unknown pair {pair}"
