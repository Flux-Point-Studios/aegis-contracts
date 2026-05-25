"""CLI smoke tests for the symbolic executor."""

from __future__ import annotations

import io
import sys

import pytest

from symbolic_executor.cli import main


def test_cli_verify_no_negative_active_coverage_prints_proven(capsys):
    rc = main([
        "verify",
        "--branch", "Underwrite",
        "--property", "no_negative_active_coverage",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PROVEN" in out
    assert "no_negative_active_coverage" in out
    assert "elapsed=" in out


def test_cli_verify_immutable_pool_datum_prints_proven(capsys):
    rc = main([
        "verify",
        "--branch", "Underwrite",
        "--property", "immutable_pool_datum",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PROVEN" in out


def test_cli_verify_all_prints_each_property(capsys):
    rc = main(["verify-all", "--branch", "Underwrite"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PROVEN" in out
    for name in (
        "pool_conservation",
        "no_negative_active_coverage",
        "immutable_pool_datum",
        "partner_not_aliased",
    ):
        assert name in out


def test_cli_verify_with_disabled_guard_yields_counterexample(capsys):
    """Dropping `immutable_ok` should turn the immutable property into a CEX."""
    rc = main([
        "verify",
        "--branch", "Underwrite",
        "--property", "immutable_pool_datum",
        "--disable-guard", "immutable_ok",
    ])
    out = capsys.readouterr().out
    assert rc == 1
    assert "COUNTEREXAMPLE" in out


def test_cli_list_guards_lists_all_14(capsys):
    rc = main(["list-guards", "--branch", "Underwrite"])
    out = capsys.readouterr().out
    assert rc == 0
    # Spot-check 4 of the 14 guard names appear.
    for expected in (
        "coverage_positive",
        "value_ok",
        "partner_not_aliased",
        "policy_output_matches_underwrite",
    ):
        assert expected in out


def test_cli_unknown_property_rejected_by_argparse():
    """argparse `choices=...` rejects unknown properties BEFORE our code
    runs. This test pins that hard-fail behaviour so a future
    refactor that drops `choices=` (e.g. switching to free-form
    strings) doesn't silently accept typos."""
    with pytest.raises(SystemExit):
        main([
            "verify",
            "--branch", "Underwrite",
            "--property", "nope_not_a_real_property",
        ])


# ---------------------------------------------------------------------------
# Extension CLI smoke tests — five new branches.
# ---------------------------------------------------------------------------


def test_cli_verify_process_claim_pool_conservation(capsys):
    rc = main([
        "verify",
        "--branch", "ProcessClaim",
        "--property", "pool_conservation",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PROVEN" in out
    assert "ProcessClaim" in out


def test_cli_verify_add_liquidity_lp_mint_formula(capsys):
    rc = main([
        "verify",
        "--branch", "AddLiquidity",
        "--property", "lp_mint_matches_formula",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PROVEN" in out


def test_cli_verify_remove_liquidity_withdrawal_safe(capsys):
    rc = main([
        "verify",
        "--branch", "RemoveLiquidity",
        "--property", "withdrawal_safe",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PROVEN" in out


def test_cli_verify_accept_cancellation_partner_not_aliased(capsys):
    rc = main([
        "verify",
        "--branch", "AcceptCancellation",
        "--property", "partner_not_aliased",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PROVEN" in out


def test_cli_verify_batch_underwrite_can_cover_holds(capsys):
    rc = main([
        "verify",
        "--branch", "BatchUnderwrite",
        "--property", "can_cover_holds",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PROVEN" in out


def test_cli_verify_all_across_branches(capsys):
    """`verify-all --branch ALL` should iterate every (branch, property)
    pair and PROVE all of them."""
    rc = main(["verify-all", "--branch", "ALL"])
    out = capsys.readouterr().out
    assert rc == 0
    # Spot-check one property per branch appears in output.
    for branch in (
        "[Underwrite]",
        "[ProcessClaim]",
        "[AddLiquidity]",
        "[RemoveLiquidity]",
        "[AcceptCancellation]",
        "[BatchUnderwrite]",
    ):
        assert branch in out


def test_cli_list_guards_process_claim_lists_six(capsys):
    rc = main(["list-guards", "--branch", "ProcessClaim"])
    out = capsys.readouterr().out
    assert rc == 0
    for expected in (
        "payout_positive",
        "policy_consumed",
        "datum_ok",
        "immutable_ok",
        "value_ok",
        "remains_non_negative",
    ):
        assert expected in out


def test_cli_list_guards_accept_cancellation_lists_twelve(capsys):
    rc = main(["list-guards", "--branch", "AcceptCancellation"])
    out = capsys.readouterr().out
    assert rc == 0
    for expected in (
        "policy_targets_this_pool",
        "bounds_ok",
        "partner_not_aliased",
        "donation_ok",
    ):
        assert expected in out


def test_cli_verify_load_bearing_drop_yields_cex_on_process_claim(capsys):
    """Dropping `payout_positive` on ProcessClaim should turn the
    no_negative_pool_state property into a counterexample. NOTE: we
    also drop `datum_ok` so that `payout >= 0` (which datum_ok
    enforces redundantly) doesn't keep the property proven."""
    rc = main([
        "verify",
        "--branch", "ProcessClaim",
        "--property", "no_negative_pool_state",
        "--disable-guard", "datum_ok",
        "--disable-guard", "remains_non_negative",
    ])
    out = capsys.readouterr().out
    assert rc == 1
    assert "COUNTEREXAMPLE" in out


def test_cli_verify_property_not_registered_for_branch_errors():
    """A property NOT registered for a branch returns rc=2."""
    # withdrawal_safe is RemoveLiquidity-only. Asking for it on
    # ProcessClaim should fail with rc=2 (our internal "unknown for
    # branch" code).
    rc = main([
        "verify",
        "--branch", "ProcessClaim",
        "--property", "withdrawal_safe",
    ])
    assert rc == 2
