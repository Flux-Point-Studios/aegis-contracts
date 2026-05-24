"""Unit tests for the symbolic ScriptContext encoder layer."""

from __future__ import annotations

from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    MIN_UTXO_LOVELACE,
    PARTNER_SHARE_CAP_BPS,
    PROTOCOL_FEE_BPS_DEFAULT,
    TREASURY_SHARE_BPS,
    fresh_underwrite_context,
    pin_protocol_constants,
)


def test_fresh_context_returns_independent_z3_vars():
    """Two fresh contexts must use distinct Z3 variables.

    If they shared variables a multi-test session would leak
    constraints across tests.
    """
    a = fresh_underwrite_context("a")
    b = fresh_underwrite_context("b")
    # Z3 BoolRef equality is structural; two `Int("a.x")` are equal,
    # two `Int("a.x")` and `Int("b.x")` are not.
    assert str(a.old_pool_datum.total_liquidity) != str(
        b.old_pool_datum.total_liquidity
    )


def test_pin_protocol_constants_is_satisfiable_alone():
    """The protocol-const pins MUST be a satisfiable conjunction by themselves.

    A test that fails here would mean we accidentally added a
    contradiction across the pins (e.g. two pins disagree on
    `protocol_fee_bps`).
    """
    ctx = fresh_underwrite_context()
    solver = Solver()
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    assert solver.check() == sat


def test_pinned_values_match_aiken_constants():
    """Sanity-check the Python mirrors match the on-chain Aiken constants.

    Drift between these would mean the Z3 model proves things about a
    pool the chain doesn't deploy. Cross-reference:
    `contracts/lib/aegis/types.ak`.
    """
    assert MIN_UTXO_LOVELACE == 2_000_000
    assert PARTNER_SHARE_CAP_BPS == 2_000
    assert TREASURY_SHARE_BPS == 2_500
    assert PROTOCOL_FEE_BPS_DEFAULT == 200


def test_pin_protocol_constants_drives_consts_to_expected_values():
    """When we add the pins to a solver, evaluating the consts should
    return the documented preprod values."""
    ctx = fresh_underwrite_context()
    solver = Solver()
    for c in pin_protocol_constants(ctx):
        solver.add(c)
    assert solver.check() == sat
    model = solver.model()
    assert model.eval(ctx.consts.min_utxo_lovelace).as_long() == 2_000_000
    assert model.eval(ctx.consts.partner_share_cap_bps).as_long() == 2_000
    assert model.eval(ctx.consts.treasury_share_bps).as_long() == 2_500
    assert model.eval(ctx.consts.protocol_fee_bps).as_long() == 200
