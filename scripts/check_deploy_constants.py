#!/usr/bin/env python3
"""
D:/aegis-contracts/scripts/check_deploy_constants.py

v3.2 deploy-gate guard for Aegis v8. Closes:

  * Δ39 / VR-009 — `auth_witness_nft_policy_id` placeholder ship-hazard.
    The compile-time constant in `lib/aegis/types.ak` defaults to a
    28-byte all-zero placeholder. The `auth_witness_validator` self-
    checks `own_value` against this constant; if the all-zero placeholder
    ships to mainnet, no witness ever satisfies the self-check and the
    relay-presigned-auth path is dead-on-arrival (fail-closed but not
    surfaced until the first ClaimWithAuth attempt).

  * Δ40 / VR-012 — `enterprise_addr_header_*` constants drift.
    Mainnet enterprise addresses use header byte `0x61`; testnet
    (preprod, preview) use `0x60`. The active-build constant
    `enterprise_addr_header` is pinned to one of those two values
    at compile time. If a developer accidentally swaps the
    `_mainnet` and `_testnet` constants OR hardcodes the wrong
    header into the active-build constant, every `payload.payout_address`
    check on chain would be 1 byte off and silently reject every
    claim.

  * Δ41 (v3.2 / deploy-cycle break) — `auth_witness_validator_hash`
    placeholder ship-hazard. v3.2 added a SECOND compile-time pin —
    the script hash of the deployed `auth_witness_validator` — that
    `policy_validator` references when locating witness UTxOs (it
    asserts `Script(auth_witness_validator_hash)` payment-credential
    equality). The constant defaults to a 28-byte all-zero placeholder
    until step 4 of the linear deploy ordering. If the placeholder
    ships to mainnet, ClaimWithAuth and RotateAuth silently match no
    witness UTxOs (fail-closed, dead on arrival). Same shape, same
    diagnostic style as the Δ39 check — both constants are gated
    together.

What this script checks
-----------------------
  1. `auth_witness_nft_policy_id` MUST NOT be the 28-byte all-zero
     placeholder. The deploy step replaces this constant with the
     actual `policy_id` minted by the Phase-4 mint deploy. If the
     placeholder is still in `types.ak`, this script exits 1.

  2. [Δ41 — v3.2] `auth_witness_validator_hash` MUST NOT be the
     28-byte all-zero placeholder. The deploy step replaces this
     constant with the actual script hash of the deployed
     `auth_witness_validator` (rebuilt after step 1's policy id is
     pinned). If the placeholder is still in `types.ak`, this script
     exits 1. Same diagnostic style as check #1.

  3. `enterprise_addr_header_mainnet` MUST equal `#"61"` (1 byte,
     CIP-19 type-6 mainnet header). Drift = exit 1.

  4. `enterprise_addr_header_testnet` MUST equal `#"60"` (1 byte,
     CIP-19 type-6 testnet header). Drift = exit 1.

  5. (Belt) `enterprise_addr_header` (the active-build constant)
     MUST equal one of the two pinned values, AND its value must
     match the network its build targets. We can't verify "matches
     the network" without an env var or a build flag, so this
     script asserts only that it is one of the two pinned values
     (i.e. not a typo). The full network-coupling check belongs in
     a deploy-runbook step that compares the active-build value to
     the network being deployed to.

How to invoke
-------------
    python3 scripts/check_deploy_constants.py             # default — checks types.ak in-tree
    python3 scripts/check_deploy_constants.py --types-ak <path>   # explicit override
    python3 scripts/check_deploy_constants.py --self-test         # in-memory positive/negative

Exit codes
----------
    0 — every constant is the correct, post-deploy value.
    1 — at least one constant is still a placeholder OR has drifted
        from its pinned value. The script prints exactly which
        constant failed, what its current value is, and what value
        is expected.
    2 — invocation error (missing file, bad CLI argument).

Wiring
------
This script is invoked as a CI pre-tag job and at the top of the
`deploy/preprod_v8.sh` / `deploy/mainnet_v8.sh` runbooks. The runbook
fails fast before any tx is built so an operator who forgot to
update the constants after the Phase-4 mint cannot accidentally
publish a dead-on-arrival relay-auth deployment.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TYPES_AK_PATH = (
    Path(__file__).resolve().parent.parent
    / "contracts"
    / "lib"
    / "aegis"
    / "types.ak"
)

# 28-byte hex string (56 hex chars), all zeros. The Aiken declaration is
# `#"00000000000000000000000000000000000000000000000000000000"`.
PLACEHOLDER_AUTH_WITNESS_POLICY_ID = "0" * 56

# CIP-19 type-6 enterprise-address header bytes.
EXPECTED_HEADER_MAINNET = "61"
EXPECTED_HEADER_TESTNET = "60"

# Constants we check.
CONSTANT_AUTH_WITNESS_POLICY_ID = "auth_witness_nft_policy_id"
CONSTANT_AUTH_WITNESS_VALIDATOR_HASH = "auth_witness_validator_hash"
CONSTANT_HEADER_MAINNET = "enterprise_addr_header_mainnet"
CONSTANT_HEADER_TESTNET = "enterprise_addr_header_testnet"
CONSTANT_HEADER_ACTIVE = "enterprise_addr_header"


# ---------------------------------------------------------------------------
# Aiken constant extraction
# ---------------------------------------------------------------------------

def _build_constant_regex(name: str) -> re.Pattern[str]:
    r"""
    Match `pub const <name>: ByteArray = #"<hex>"` (the canonical Aiken form
    for a hex-literal byte array constant). We anchor on the literal `pub
    const <name>` so we don't accidentally match a doc-comment that mentions
    the constant by name. The regex tolerates flexible whitespace between
    tokens because the codebase formats this declaration on one or two
    lines depending on the value's length (the all-zero policy-id is
    long enough that the value-side wraps to its own line).

    The captured group is the hex literal between the `#"` and `"`.
    """
    # `re.DOTALL` so the `.` in `.*?` can match a newline between the
    # `=` and the `#"…"` literal. Re-escape `name` defensively even
    # though our names are static identifiers.
    pattern = (
        r"pub\s+const\s+"
        + re.escape(name)
        + r"\s*:\s*ByteArray\s*=\s*#\"([0-9a-fA-F]*)\""
    )
    return re.compile(pattern, re.DOTALL)


def extract_constant(source: str, name: str) -> Optional[str]:
    """
    Pull the hex literal value of `pub const <name>: ByteArray = #"<hex>"`
    from a `types.ak` source. Returns the hex string (lowercased, no
    surrounding quotes) or None if the declaration is missing.
    """
    match = _build_constant_regex(name).search(source)
    if match is None:
        return None
    return match.group(1).lower()


# ---------------------------------------------------------------------------
# Check definitions
# ---------------------------------------------------------------------------

def _format_value(value: Optional[str]) -> str:
    """Render a constant value for the human-readable diagnostic line."""
    if value is None:
        return "<missing>"
    if len(value) == 0:
        return '#""'
    return f'#"{value}"'


class CheckResult:
    """Outcome of a single constant check."""

    def __init__(self, name: str, ok: bool, message: str) -> None:
        self.name = name
        self.ok = ok
        self.message = message


def check_auth_witness_policy_id(value: Optional[str]) -> CheckResult:
    """
    Δ39 / VR-009. The placeholder is the 28-byte all-zero hex string.
    Any other non-empty 56-character hex value is treated as a real
    minted policy id (we don't verify the value against the deploy
    state — that's the runbook's job; this guard catches the "operator
    forgot to update" class).
    """
    if value is None:
        return CheckResult(
            CONSTANT_AUTH_WITNESS_POLICY_ID,
            False,
            (
                f"DEPLOY GATE: `pub const {CONSTANT_AUTH_WITNESS_POLICY_ID}: ByteArray = #\"...\"` "
                "is missing from lib/aegis/types.ak. The Phase-4 deploy must mint the "
                "auth_witness_nft policy and pin its policy_id here before tagging."
            ),
        )
    if value == PLACEHOLDER_AUTH_WITNESS_POLICY_ID:
        return CheckResult(
            CONSTANT_AUTH_WITNESS_POLICY_ID,
            False,
            (
                f"DEPLOY GATE: `{CONSTANT_AUTH_WITNESS_POLICY_ID}` is still the "
                f"all-zero placeholder ({_format_value(value)}). Update lib/aegis/types.ak "
                "with the actual policy_id from Phase 4 mint deploy before tagging "
                "mainnet -- otherwise the auth_witness_validator self-check on "
                "`own_value` will silently match no witness UTxOs (fail-closed, "
                "dead on arrival)."
            ),
        )
    if len(value) != 56:
        return CheckResult(
            CONSTANT_AUTH_WITNESS_POLICY_ID,
            False,
            (
                f"DEPLOY GATE: `{CONSTANT_AUTH_WITNESS_POLICY_ID}` value "
                f"{_format_value(value)} is not a 28-byte (56-hex-char) value; "
                "Cardano script hashes are 28 bytes. Re-mint or fix the constant."
            ),
        )
    return CheckResult(
        CONSTANT_AUTH_WITNESS_POLICY_ID,
        True,
        (
            f"OK: `{CONSTANT_AUTH_WITNESS_POLICY_ID}` is set to a non-placeholder "
            f"28-byte value ({_format_value(value)})."
        ),
    )


def check_auth_witness_validator_hash(value: Optional[str]) -> CheckResult:
    """
    Δ41 (v3.2 / deploy-cycle break). The placeholder is the 28-byte
    all-zero hex string. Any other non-empty 56-character hex value is
    treated as the actual script hash of the deployed
    `auth_witness_validator`. Same diagnostic style as
    `check_auth_witness_policy_id`.

    The two pins compose into the v3.2 linear deploy ordering:
      * step 1 mints `auth_witness_nft_policy_id`;
      * step 4 (rebuild) freezes `auth_witness_validator_hash`;
      * step 5 (rebuild) freezes `policy.policy_validator` hash.
    Both constants are guarded together so neither can ship as
    placeholder.
    """
    if value is None:
        return CheckResult(
            CONSTANT_AUTH_WITNESS_VALIDATOR_HASH,
            False,
            (
                f"DEPLOY GATE: `pub const {CONSTANT_AUTH_WITNESS_VALIDATOR_HASH}: ByteArray = #\"...\"` "
                "is missing from lib/aegis/types.ak. v3.2 (Δ41) requires this "
                "compile-time pin so policy_validator can locate witness UTxOs "
                "by script credential. The Phase-4 deploy step 4 (rebuild after "
                "auth_witness_nft_policy_id pin) freezes this hash; pin it here "
                "before tagging."
            ),
        )
    if value == PLACEHOLDER_AUTH_WITNESS_POLICY_ID:
        # Same all-zero placeholder shape; share the constant.
        return CheckResult(
            CONSTANT_AUTH_WITNESS_VALIDATOR_HASH,
            False,
            (
                f"DEPLOY GATE: `{CONSTANT_AUTH_WITNESS_VALIDATOR_HASH}` is still "
                f"the all-zero placeholder ({_format_value(value)}). Update "
                "lib/aegis/types.ak with the actual auth_witness_validator script "
                "hash from Phase 4 deploy step 4 (rebuild after pinning "
                "auth_witness_nft_policy_id) before tagging mainnet -- otherwise "
                "ClaimWithAuth and RotateAuth will silently match no witness "
                "UTxOs (fail-closed, dead on arrival)."
            ),
        )
    if len(value) != 56:
        return CheckResult(
            CONSTANT_AUTH_WITNESS_VALIDATOR_HASH,
            False,
            (
                f"DEPLOY GATE: `{CONSTANT_AUTH_WITNESS_VALIDATOR_HASH}` value "
                f"{_format_value(value)} is not a 28-byte (56-hex-char) value; "
                "Cardano script hashes are 28 bytes. Rebuild and re-pin the constant."
            ),
        )
    return CheckResult(
        CONSTANT_AUTH_WITNESS_VALIDATOR_HASH,
        True,
        (
            f"OK: `{CONSTANT_AUTH_WITNESS_VALIDATOR_HASH}` is set to a non-placeholder "
            f"28-byte value ({_format_value(value)})."
        ),
    )


def check_enterprise_header_mainnet(value: Optional[str]) -> CheckResult:
    """Δ40 / VR-012. `enterprise_addr_header_mainnet` MUST equal `#"61"`."""
    if value is None:
        return CheckResult(
            CONSTANT_HEADER_MAINNET,
            False,
            (
                f"DEPLOY GATE: `pub const {CONSTANT_HEADER_MAINNET}: ByteArray = #\"61\"` "
                "is missing from lib/aegis/types.ak. CIP-19 type-6 mainnet header byte."
            ),
        )
    if value != EXPECTED_HEADER_MAINNET:
        return CheckResult(
            CONSTANT_HEADER_MAINNET,
            False,
            (
                f"DEPLOY GATE: `{CONSTANT_HEADER_MAINNET}` is "
                f"{_format_value(value)} but MUST equal #\"{EXPECTED_HEADER_MAINNET}\" "
                "(CIP-19 type-6 mainnet enterprise-address header byte). "
                "Drift would cause every payload.payout_address check on chain "
                "to silently reject every mainnet claim."
            ),
        )
    return CheckResult(
        CONSTANT_HEADER_MAINNET,
        True,
        f"OK: `{CONSTANT_HEADER_MAINNET}` = #\"{value}\".",
    )


def check_enterprise_header_testnet(value: Optional[str]) -> CheckResult:
    """Δ40 / VR-012. `enterprise_addr_header_testnet` MUST equal `#"60"`."""
    if value is None:
        return CheckResult(
            CONSTANT_HEADER_TESTNET,
            False,
            (
                f"DEPLOY GATE: `pub const {CONSTANT_HEADER_TESTNET}: ByteArray = #\"60\"` "
                "is missing from lib/aegis/types.ak. CIP-19 type-6 testnet header byte."
            ),
        )
    if value != EXPECTED_HEADER_TESTNET:
        return CheckResult(
            CONSTANT_HEADER_TESTNET,
            False,
            (
                f"DEPLOY GATE: `{CONSTANT_HEADER_TESTNET}` is "
                f"{_format_value(value)} but MUST equal #\"{EXPECTED_HEADER_TESTNET}\" "
                "(CIP-19 type-6 testnet enterprise-address header byte). "
                "Drift would cause every payload.payout_address check on chain "
                "to silently reject every testnet (preprod / preview) claim."
            ),
        )
    return CheckResult(
        CONSTANT_HEADER_TESTNET,
        True,
        f"OK: `{CONSTANT_HEADER_TESTNET}` = #\"{value}\".",
    )


def check_enterprise_header_active(value: Optional[str]) -> CheckResult:
    """
    Belt: the active-build constant MUST equal one of the two pinned
    values. We do not enforce "matches the targeted network" here —
    that depends on an env var or a build flag we don't have access to
    at static-check time. The deploy runbook is responsible for
    confirming the network coupling.
    """
    if value is None:
        return CheckResult(
            CONSTANT_HEADER_ACTIVE,
            False,
            (
                f"DEPLOY GATE: `pub const {CONSTANT_HEADER_ACTIVE}: ByteArray = #\"...\"` "
                "is missing from lib/aegis/types.ak. The active-build header byte "
                "MUST be set to either #\"60\" (testnet) or #\"61\" (mainnet)."
            ),
        )
    if value not in (EXPECTED_HEADER_MAINNET, EXPECTED_HEADER_TESTNET):
        return CheckResult(
            CONSTANT_HEADER_ACTIVE,
            False,
            (
                f"DEPLOY GATE: `{CONSTANT_HEADER_ACTIVE}` is "
                f"{_format_value(value)} -- must be one of "
                f"#\"{EXPECTED_HEADER_TESTNET}\" (testnet) or "
                f"#\"{EXPECTED_HEADER_MAINNET}\" (mainnet). "
                "Any other value is a typo and would brick every payout-address check."
            ),
        )
    return CheckResult(
        CONSTANT_HEADER_ACTIVE,
        True,
        f"OK: `{CONSTANT_HEADER_ACTIVE}` = #\"{value}\".",
    )


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def run_checks(source: str) -> list[CheckResult]:
    """Run every check against a `types.ak` source string."""
    return [
        check_auth_witness_policy_id(extract_constant(source, CONSTANT_AUTH_WITNESS_POLICY_ID)),
        check_auth_witness_validator_hash(extract_constant(source, CONSTANT_AUTH_WITNESS_VALIDATOR_HASH)),
        check_enterprise_header_mainnet(extract_constant(source, CONSTANT_HEADER_MAINNET)),
        check_enterprise_header_testnet(extract_constant(source, CONSTANT_HEADER_TESTNET)),
        check_enterprise_header_active(extract_constant(source, CONSTANT_HEADER_ACTIVE)),
    ]


def emit_report(results: Iterable[CheckResult]) -> bool:
    """
    Print a per-check status line. Returns True iff every check passed.
    """
    any_failure = False
    for r in results:
        prefix = "[OK]   " if r.ok else "[FAIL] "
        if r.ok:
            print(f"{prefix}{r.message}")
        else:
            print(f"{prefix}{r.message}", file=sys.stderr)
            any_failure = True
    return not any_failure


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_PLACEHOLDER_TYPES_AK = """
pub const auth_witness_nft_policy_id: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000"

pub const auth_witness_validator_hash: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000"

pub const enterprise_addr_header_testnet: ByteArray = #"60"

pub const enterprise_addr_header_mainnet: ByteArray = #"61"

pub const enterprise_addr_header: ByteArray = #"60"
"""

_REAL_DEPLOY_TYPES_AK = """
pub const auth_witness_nft_policy_id: ByteArray =
  #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f"

pub const auth_witness_validator_hash: ByteArray =
  #"7b95b1e0e02e1812bd282facbc6ebbdae8876b9e0be5b17d8dd98695"

pub const enterprise_addr_header_testnet: ByteArray = #"60"

pub const enterprise_addr_header_mainnet: ByteArray = #"61"

pub const enterprise_addr_header: ByteArray = #"60"
"""

_DRIFTED_HEADER_TYPES_AK = """
pub const auth_witness_nft_policy_id: ByteArray =
  #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f"

pub const auth_witness_validator_hash: ByteArray =
  #"7b95b1e0e02e1812bd282facbc6ebbdae8876b9e0be5b17d8dd98695"

pub const enterprise_addr_header_testnet: ByteArray = #"61"

pub const enterprise_addr_header_mainnet: ByteArray = #"60"

pub const enterprise_addr_header: ByteArray = #"60"
"""

_MISSING_HEADER_TYPES_AK = """
pub const auth_witness_nft_policy_id: ByteArray =
  #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f"

pub const auth_witness_validator_hash: ByteArray =
  #"7b95b1e0e02e1812bd282facbc6ebbdae8876b9e0be5b17d8dd98695"

pub const enterprise_addr_header_testnet: ByteArray = #"60"

pub const enterprise_addr_header: ByteArray = #"60"
"""

_BAD_LENGTH_POLICY_ID_TYPES_AK = """
pub const auth_witness_nft_policy_id: ByteArray =
  #"d2f0841"

pub const auth_witness_validator_hash: ByteArray =
  #"7b95b1e0e02e1812bd282facbc6ebbdae8876b9e0be5b17d8dd98695"

pub const enterprise_addr_header_testnet: ByteArray = #"60"

pub const enterprise_addr_header_mainnet: ByteArray = #"61"

pub const enterprise_addr_header: ByteArray = #"60"
"""

_TYPO_ACTIVE_HEADER_TYPES_AK = """
pub const auth_witness_nft_policy_id: ByteArray =
  #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f"

pub const auth_witness_validator_hash: ByteArray =
  #"7b95b1e0e02e1812bd282facbc6ebbdae8876b9e0be5b17d8dd98695"

pub const enterprise_addr_header_testnet: ByteArray = #"60"

pub const enterprise_addr_header_mainnet: ByteArray = #"61"

pub const enterprise_addr_header: ByteArray = #"00"
"""

# [v3.2 / Δ41] Negative case for auth_witness_validator_hash placeholder.
_PLACEHOLDER_VALIDATOR_HASH_TYPES_AK = """
pub const auth_witness_nft_policy_id: ByteArray =
  #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f"

pub const auth_witness_validator_hash: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000"

pub const enterprise_addr_header_testnet: ByteArray = #"60"

pub const enterprise_addr_header_mainnet: ByteArray = #"61"

pub const enterprise_addr_header: ByteArray = #"60"
"""


def _self_test() -> int:
    """Run an in-memory positive/negative suite. Returns 0 on success."""
    cases = [
        ("placeholder policy_id rejected", _PLACEHOLDER_TYPES_AK, False),
        ("real deploy accepted", _REAL_DEPLOY_TYPES_AK, True),
        ("swapped headers rejected", _DRIFTED_HEADER_TYPES_AK, False),
        ("missing _mainnet header rejected", _MISSING_HEADER_TYPES_AK, False),
        ("bad-length policy_id rejected", _BAD_LENGTH_POLICY_ID_TYPES_AK, False),
        ("typo in active header rejected", _TYPO_ACTIVE_HEADER_TYPES_AK, False),
        # [v3.2 / Δ41] auth_witness_validator_hash placeholder rejected.
        (
            "placeholder auth_witness_validator_hash rejected",
            _PLACEHOLDER_VALIDATOR_HASH_TYPES_AK,
            False,
        ),
    ]
    failed = 0
    for name, source, expect_pass in cases:
        results = run_checks(source)
        all_ok = all(r.ok for r in results)
        if all_ok == expect_pass:
            print(f"[self-test] OK: {name}")
        else:
            failed += 1
            print(
                f"[self-test] FAIL: {name} -- expected pass={expect_pass}, got pass={all_ok}",
                file=sys.stderr,
            )
            for r in results:
                if not r.ok:
                    print(f"  -> {r.message}", file=sys.stderr)
    if failed > 0:
        print(f"\n[self-test] {failed} cases failed.", file=sys.stderr)
        return 1
    print(f"\n[self-test] all {len(cases)} cases passed.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="check_deploy_constants",
        description=(
            "Aegis v8 deploy gate. Asserts auth_witness_nft_policy_id is "
            "not the all-zero placeholder (Δ39/VR-009), "
            "auth_witness_validator_hash is not the all-zero placeholder "
            "(Δ41/v3.2), and that the enterprise-address header constants "
            "are the canonical CIP-19 values (Δ40/VR-012)."
        ),
    )
    parser.add_argument(
        "--types-ak",
        type=Path,
        default=DEFAULT_TYPES_AK_PATH,
        help=(
            "Path to lib/aegis/types.ak. Defaults to the in-tree path "
            "relative to this script."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run the in-memory positive/negative suite and exit.",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    types_ak: Path = args.types_ak
    if not types_ak.is_file():
        print(
            f"check_deploy_constants: types.ak not found at {types_ak}. "
            "Pass --types-ak <path> if your layout differs from the default.",
            file=sys.stderr,
        )
        return 2

    source = types_ak.read_text(encoding="utf-8")
    print(f"check_deploy_constants: scanning {types_ak}")
    results = run_checks(source)
    ok = emit_report(results)
    if ok:
        print("check_deploy_constants: PASS -- all deploy constants are at their pinned values.")
        return 0
    print(
        "check_deploy_constants: FAIL -- at least one deploy gate did not pass. "
        "Update lib/aegis/types.ak before tagging mainnet.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
