"""UnderwriteEncoder unit tests + differential against JSON fixtures.

The differential layer is the trust handshake between the Python
encoder and the on-chain Aiken validator. We do NOT execute the Aiken
code here — we provide hand-built ScriptContext fixtures whose
positive/negative status was hand-verified against
`D:/aegis/contracts/validators/pool.ak`. For each fixture we:

  * Build a fresh symbolic ctx.
  * Pin every Z3 variable to the fixture's concrete value (so the
    context is fully concrete).
  * Add the encoder's constraints + the protocol-const pins.
  * Check whether the solver is SAT (encoder accepts) or UNSAT
    (encoder rejects).

The positive fixture MUST be accepted; each negative fixture MUST be
rejected — and the test asserts the specific guard named in
`_violates` is responsible, by re-running with ONLY that guard
disabled and confirming it goes from UNSAT → SAT.

Methodology: the fixtures encode known-good and known-bad scenarios
hand-verified against the Aiken source. A future agent who upgrades
the encoder must re-verify the fixtures still match the chain — a
simple sanity check on `aiken check`'s positive-path Underwrite test
will do.
"""

from __future__ import annotations

import pytest
from z3 import Solver, sat, unsat

from symbolic_executor.context import (
    SymbolicScriptContext,
    fresh_underwrite_context,
    pin_protocol_constants,
)
from symbolic_executor.encoders import UnderwriteEncoder


def _pin_ctx_from_fixture(
    ctx: SymbolicScriptContext, fx: dict
) -> list:
    """Return Z3 constraints that pin every ctx variable to the
    corresponding value in the fixture dict."""

    op = fx["old_pool_datum"]
    np_ = fx["new_pool_datum"]
    pd = fx["new_policy_datum"]
    r = fx["redeemer"]
    vr = fx["validity_range"]
    td = fx["treasury_donation"]
    co = fx["consts"]

    return [
        # Old pool datum
        ctx.old_pool_datum.total_liquidity == op["total_liquidity"],
        ctx.old_pool_datum.active_coverage == op["active_coverage"],
        ctx.old_pool_datum.lp_token_policy == op["lp_token_policy"],
        ctx.old_pool_datum.protocol_fee_bps == op["protocol_fee_bps"],
        ctx.old_pool_datum.pool_nft == op["pool_nft"],
        ctx.old_pool_datum.lp_supply == op["lp_supply"],
        # New pool datum
        ctx.new_pool_datum.total_liquidity == np_["total_liquidity"],
        ctx.new_pool_datum.active_coverage == np_["active_coverage"],
        ctx.new_pool_datum.lp_token_policy == np_["lp_token_policy"],
        ctx.new_pool_datum.protocol_fee_bps == np_["protocol_fee_bps"],
        ctx.new_pool_datum.pool_nft == np_["pool_nft"],
        ctx.new_pool_datum.lp_supply == np_["lp_supply"],
        # New policy datum
        ctx.new_policy_datum.policy_id == pd["policy_id"],
        ctx.new_policy_datum.insured == pd["insured"],
        ctx.new_policy_datum.strike_price == pd["strike_price"],
        ctx.new_policy_datum.coverage_amount == pd["coverage_amount"],
        ctx.new_policy_datum.premium_paid == pd["premium_paid"],
        ctx.new_policy_datum.start_time == pd["start_time"],
        ctx.new_policy_datum.expiry_time == pd["expiry_time"],
        ctx.new_policy_datum.oracle_nft == pd["oracle_nft"],
        ctx.new_policy_datum.pool_script_hash == pd["pool_script_hash"],
        ctx.new_policy_datum.pool_nft == pd["pool_nft"],
        ctx.new_policy_datum.oracle_provider == pd["oracle_provider"],
        ctx.new_policy_datum.partner_address_is_some
        == pd["partner_address_is_some"],
        ctx.new_policy_datum.partner_address_id == pd["partner_address_id"],
        ctx.new_policy_datum.partner_share_bps == pd["partner_share_bps"],
        # Redeemer
        ctx.redeemer.coverage == r["coverage"],
        ctx.redeemer.premium == r["premium"],
        # Off-pool ctx vars
        ctx.own_input_lovelace == fx["own_input_lovelace"],
        ctx.cont_output_lovelace == fx["cont_output_lovelace"],
        ctx.team_output_lovelace == fx["team_output_lovelace"],
        ctx.partner_output_lovelace == fx["partner_output_lovelace"],
        ctx.own_pool_script_hash == fx["own_pool_script_hash"],
        # Validity range
        ctx.validity_range.lb == vr["lb"],
        ctx.validity_range.ub == vr["ub"],
        # Treasury donation
        ctx.treasury_donation.is_some == td["is_some"],
        ctx.treasury_donation.amount == td["amount"],
        # Constants (pin to fixture's values — these MUST match the
        # `pin_protocol_constants` defaults to stay consistent)
        ctx.consts.team_address_id == co["team_address_id"],
        ctx.consts.pool_address_id == co["pool_address_id"],
        ctx.consts.policy_script_hash == co["policy_script_hash"],
        ctx.consts.min_utxo_lovelace == co["min_utxo_lovelace"],
        ctx.consts.min_premium == co["min_premium"],
        ctx.consts.partner_share_cap_bps == co["partner_share_cap_bps"],
        ctx.consts.treasury_share_bps == co["treasury_share_bps"],
        ctx.consts.protocol_fee_bps == co["protocol_fee_bps"],
    ]


def test_encoder_lists_all_expected_guards():
    """The encoder MUST expose all 14 guards from `GUARD_NAMES`."""
    ctx = fresh_underwrite_context()
    encoder = UnderwriteEncoder()
    guards = encoder.all_guard_names(ctx)
    assert set(guards) == set(UnderwriteEncoder.GUARD_NAMES)
    # Order should be deterministic and match the Aiken `&&` chain.
    assert tuple(guards) == UnderwriteEncoder.GUARD_NAMES


def test_encoder_disable_unknown_guard_raises():
    """Typos in `disable_guards` are surfaced loudly."""
    ctx = fresh_underwrite_context()
    encoder = UnderwriteEncoder(disable_guards={"this_guard_does_not_exist"})
    with pytest.raises(ValueError):
        encoder.encode(ctx)


def test_encoder_accepts_positive_fixture(positive_fixture):
    """The known-good positive Underwrite fixture MUST satisfy ALL guards."""
    ctx = fresh_underwrite_context()
    encoder = UnderwriteEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in _pin_ctx_from_fixture(ctx, positive_fixture):
        solver.add(c)
    assert solver.check() == sat, (
        "Positive fixture must be accepted by the encoder. "
        "If this fails, either the fixture has drifted from the Aiken "
        "branch or the encoder is over-constraining."
    )


def test_encoder_rejects_each_negative_fixture(negative_fixtures):
    """Each negative fixture MUST be rejected by the encoder."""
    assert negative_fixtures, "expected at least one negative fixture"
    for fx in negative_fixtures:
        ctx = fresh_underwrite_context()
        encoder = UnderwriteEncoder()
        solver = Solver()
        for c in encoder.encode(ctx):
            solver.add(c)
        for c in _pin_ctx_from_fixture(ctx, fx):
            solver.add(c)
        result = solver.check()
        assert result == unsat, (
            f"Negative fixture (_violates={fx['_violates']!r}) should be REJECTED "
            f"by the encoder, but got {result}."
        )


def test_disabling_violated_guard_recovers_acceptance(negative_fixtures):
    """For each negative fixture, disabling ONLY the violated guard
    should turn UNSAT → SAT. This proves the guard is load-bearing for
    THAT specific exploit (the counterexample-pair half of the rubric).
    """
    for fx in negative_fixtures:
        violated = fx["_violates"]
        ctx = fresh_underwrite_context()
        encoder = UnderwriteEncoder(disable_guards={violated})
        solver = Solver()
        for c in encoder.encode(ctx):
            solver.add(c)
        for c in _pin_ctx_from_fixture(ctx, fx):
            solver.add(c)
        result = solver.check()
        assert result == sat, (
            f"With guard {violated!r} disabled, the negative fixture "
            f"should be accepted — but got {result}. Either the encoder's "
            f"mapping for this guard is wrong, or the fixture also "
            f"violates another guard (in which case the fixture needs "
            f"narrowing)."
        )


def test_intermediates_pin_fee_total_on_positive_fixture(positive_fixture):
    """On the positive fixture, fee_total should evaluate to the
    expected hand-computed value (sanity check on the Hybrid Fee math
    encoding)."""
    ctx = fresh_underwrite_context()
    encoder = UnderwriteEncoder()
    solver = Solver()
    for c in encoder.encode(ctx):
        solver.add(c)
    for c in _pin_ctx_from_fixture(ctx, positive_fixture):
        solver.add(c)
    assert solver.check() == sat
    model = solver.model()
    inter = encoder._intermediates_for(ctx)
    # Positive fixture: premium=500 ADA, fee_bps=200 → raw_fee=10 ADA,
    # above floor, so fee_total=10 ADA, net_pool_growth=490 ADA.
    assert model.eval(inter.fee_total).as_long() == 10_000_000
    assert model.eval(inter.net_pool_growth).as_long() == 490_000_000
    assert model.eval(inter.team_cut).as_long() == 10_000_000
    assert model.eval(inter.partner_cut).as_long() == 0
    assert model.eval(inter.treasury_cut).as_long() == 2_500_000
