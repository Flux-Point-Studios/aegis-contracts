"""Shared pytest fixtures for the symbolic executor test suite.

Two scopes of fixtures:

  * `underwrite_ctx`  — a fresh symbolic ScriptContext + a Solver with
                       the encoder's constraints + the protocol-const
                       pins already added. Use this when your test
                       only needs to ADD the negated property and ask.
  * `underwrite_encoder` — a default UnderwriteEncoder (all guards on).
  * Fixture files under `fixtures/*.json` — known-good ScriptContexts
    for the differential layer (see test_encoder_underwrite.py).

The extension suite adds per-branch contexts + JSON fixtures for:
  ProcessClaim, AddLiquidity, RemoveLiquidity, AcceptCancellation,
  BatchUnderwrite. See `V12.2_ROUND_9_T2_EXTENSIONS.md` for the
  full coverage matrix.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from z3 import Solver

# Make the package importable when pytest is invoked as
# `pytest D:/aegis/redteam/symbolic_executor/tests` (without a
# pyproject install). We add the redteam/ folder to sys.path so
# `import symbolic_executor` resolves.
HERE = Path(__file__).resolve()
REDTEAM_DIR = HERE.parents[2]
if str(REDTEAM_DIR) not in sys.path:
    sys.path.insert(0, str(REDTEAM_DIR))


from symbolic_executor.context import (  # noqa: E402
    fresh_accept_cancellation_context,
    fresh_add_liquidity_context,
    fresh_batch_underwrite_context,
    fresh_process_claim_context,
    fresh_remove_liquidity_context,
    fresh_underwrite_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import (  # noqa: E402
    AcceptCancellationEncoder,
    AddLiquidityEncoder,
    BatchUnderwriteEncoder,
    ProcessClaimEncoder,
    RemoveLiquidityEncoder,
    UnderwriteEncoder,
)


FIXTURES_DIR = HERE.parent / "fixtures"


# ---------------------------------------------------------------------------
# Foundation fixtures (preserved exactly)
# ---------------------------------------------------------------------------


@pytest.fixture
def underwrite_ctx_pair():
    """Return (ctx, encoder, solver_with_encoder_and_pins).

    Each test gets a fresh ctx + solver so previous adds don't leak.
    """
    ctx = fresh_underwrite_context()
    encoder = UnderwriteEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    return ctx, encoder, solver


@pytest.fixture
def underwrite_ctx():
    return fresh_underwrite_context()


@pytest.fixture
def underwrite_encoder():
    return UnderwriteEncoder()


@pytest.fixture
def positive_fixture() -> dict:
    """Load the known-good positive-path Underwrite fixture."""
    path = FIXTURES_DIR / "underwrite_positive.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def negative_fixtures() -> list[dict]:
    """Load every known-bad fixture for differential testing."""
    out: list[dict] = []
    for p in sorted(FIXTURES_DIR.glob("underwrite_negative_*.json")):
        out.append(json.loads(p.read_text(encoding="utf-8")))
    return out


# ---------------------------------------------------------------------------
# Extension fixtures: ProcessClaim
# ---------------------------------------------------------------------------


@pytest.fixture
def process_claim_ctx_pair():
    ctx = fresh_process_claim_context()
    encoder = ProcessClaimEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    return ctx, encoder, solver


@pytest.fixture
def process_claim_positive() -> dict:
    return json.loads(
        (FIXTURES_DIR / "process_claim_positive.json").read_text(
            encoding="utf-8"
        )
    )


@pytest.fixture
def process_claim_negatives() -> list[dict]:
    out: list[dict] = []
    for p in sorted(FIXTURES_DIR.glob("process_claim_negative_*.json")):
        out.append(json.loads(p.read_text(encoding="utf-8")))
    return out


# ---------------------------------------------------------------------------
# Extension fixtures: AddLiquidity
# ---------------------------------------------------------------------------


@pytest.fixture
def add_liquidity_ctx_pair():
    ctx = fresh_add_liquidity_context()
    encoder = AddLiquidityEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    return ctx, encoder, solver


@pytest.fixture
def add_liquidity_positive() -> dict:
    return json.loads(
        (FIXTURES_DIR / "add_liquidity_positive.json").read_text(
            encoding="utf-8"
        )
    )


@pytest.fixture
def add_liquidity_negatives() -> list[dict]:
    out: list[dict] = []
    for p in sorted(FIXTURES_DIR.glob("add_liquidity_negative_*.json")):
        out.append(json.loads(p.read_text(encoding="utf-8")))
    return out


# ---------------------------------------------------------------------------
# Extension fixtures: RemoveLiquidity
# ---------------------------------------------------------------------------


@pytest.fixture
def remove_liquidity_ctx_pair():
    ctx = fresh_remove_liquidity_context()
    encoder = RemoveLiquidityEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    return ctx, encoder, solver


@pytest.fixture
def remove_liquidity_positive() -> dict:
    return json.loads(
        (FIXTURES_DIR / "remove_liquidity_positive.json").read_text(
            encoding="utf-8"
        )
    )


@pytest.fixture
def remove_liquidity_negatives() -> list[dict]:
    out: list[dict] = []
    for p in sorted(FIXTURES_DIR.glob("remove_liquidity_negative_*.json")):
        out.append(json.loads(p.read_text(encoding="utf-8")))
    return out


# ---------------------------------------------------------------------------
# Extension fixtures: AcceptCancellation
# ---------------------------------------------------------------------------


@pytest.fixture
def accept_cancellation_ctx_pair():
    ctx = fresh_accept_cancellation_context()
    encoder = AcceptCancellationEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    return ctx, encoder, solver


@pytest.fixture
def accept_cancellation_positive() -> dict:
    return json.loads(
        (FIXTURES_DIR / "accept_cancellation_positive.json").read_text(
            encoding="utf-8"
        )
    )


@pytest.fixture
def accept_cancellation_negatives() -> list[dict]:
    out: list[dict] = []
    for p in sorted(FIXTURES_DIR.glob("accept_cancellation_negative_*.json")):
        out.append(json.loads(p.read_text(encoding="utf-8")))
    return out


# ---------------------------------------------------------------------------
# Extension fixtures: BatchUnderwrite
# ---------------------------------------------------------------------------


@pytest.fixture
def batch_underwrite_ctx_pair():
    ctx = fresh_batch_underwrite_context()
    encoder = BatchUnderwriteEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    return ctx, encoder, solver


@pytest.fixture
def batch_underwrite_positive() -> dict:
    return json.loads(
        (FIXTURES_DIR / "batch_underwrite_positive.json").read_text(
            encoding="utf-8"
        )
    )


@pytest.fixture
def batch_underwrite_negatives() -> list[dict]:
    out: list[dict] = []
    for p in sorted(FIXTURES_DIR.glob("batch_underwrite_negative_*.json")):
        out.append(json.loads(p.read_text(encoding="utf-8")))
    return out
