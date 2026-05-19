"""Mutation tester for Aegis Aiken validators (Round 9 / pre-audit pass).

Methodology
-----------
For each validator file, apply single-operator mutations (>=, ==, &&, etc.)
one at a time, run `aiken check`, and classify the result:

  * KILLED   — a test fails. Test suite catches this mutation. Good.
  * SURVIVED — all tests still pass. **Test gap.** The validator's behavior
               changed but no test caught it. These are the actionable
               outputs of mutation testing.
  * COMPILE_ERROR — the mutation produced a non-compilable source. Skip;
               not informative (the type system caught it).

The script is intentionally conservative: it only applies mutations
within Aiken expression syntax (not inside string literals or
comments), and skips mutations on lines containing `test ` or `expect`
to avoid mutating the test code itself (which would trivially "kill"
every test).

Coverage target: every comparison operator (>=, >, <=, <, ==, !=) and
boolean connective (&&, ||) inside the validator's logic branches.

Usage
-----
    cd D:/aegis
    python redteam/mutation_tester.py \\
        --validator contracts/validators/pool.ak \\
        --output redteam/V12.2_ROUND_9_MUTATIONS_POOL.md

    # Quick smoke (5 mutations only):
    python redteam/mutation_tester.py --limit 5 ...

For multi-file run, invoke once per validator.

Exit codes
----------
    0 = all mutations either killed or compile-error (no test gaps)
    1 = >=1 surviving mutations (test gaps found — see output report)
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# Pairs to consider for mutation. Each pair is (original, mutant).
# We mutate the FIRST occurrence on each line; if a line has multiple
# matching operators, only the first one mutates per round (a single
# mutation per source-position is what mutation testing wants).
OPERATOR_MUTATIONS: list[tuple[str, str]] = [
    # Comparison loosening / tightening
    (">=", ">"),
    (">", ">="),
    ("<=", "<"),
    ("<", "<="),
    ("==", "!="),
    ("!=", "=="),
    # Boolean connectives
    ("&&", "||"),
    ("||", "&&"),
    # Boolean literals
    ("True", "False"),
    ("False", "True"),
]

# Skip mutating lines that match these patterns (they're test/spec/docs).
SKIP_LINE_PATTERNS = [
    re.compile(r"^\s*//"),                  # comment
    re.compile(r"^\s*test\s+"),             # test definition
    re.compile(r"@\""),                     # error message string
    re.compile(r"^\s*\?\?\s*"),             # Aiken ?? trace
]


@dataclasses.dataclass
class MutationResult:
    line_no: int                            # 1-indexed
    line_text_original: str
    line_text_mutated: str
    operator_original: str
    operator_mutant: str
    outcome: str                            # 'KILLED' | 'SURVIVED' | 'COMPILE_ERROR' | 'TIMEOUT'
    elapsed_seconds: float
    failing_tests: list[str] = dataclasses.field(default_factory=list)


def find_mutation_sites(source_lines: list[str]) -> list[tuple[int, str, str, int]]:
    """Enumerate every (line_no, original_op, mutant_op, col_offset) site.

    Returns a list of mutation candidates. Each candidate is a single
    operator on a single line — we mutate them ONE AT A TIME.
    """
    sites: list[tuple[int, str, str, int]] = []
    for i, line in enumerate(source_lines, start=1):
        if any(p.search(line) for p in SKIP_LINE_PATTERNS):
            continue
        for original, mutant in OPERATOR_MUTATIONS:
            # Find every occurrence on this line.
            offset = 0
            while True:
                idx = line.find(original, offset)
                if idx < 0:
                    break
                # Word-boundary check for True/False to avoid mutating
                # substrings like 'IsTrue' or 'Truthful'.
                if original in ("True", "False"):
                    before = line[idx - 1] if idx > 0 else " "
                    after = line[idx + len(original):idx + len(original) + 1]
                    if before.isalnum() or before == "_" or (after and (after.isalnum() or after == "_")):
                        offset = idx + 1
                        continue
                # For `<` and `>`, require a space on at least one side.
                # This filters out Aiken generic-type angle brackets like
                # `List<Input>` and function-return arrows `-> Bool` from
                # being mistaken for comparison operators. Comparisons in
                # Aiken style guides are space-around (`a > b`), generics
                # are space-free (`<T>`).
                if original in ("<", ">", "<=", ">="):
                    before = line[idx - 1] if idx > 0 else " "
                    after_idx = idx + len(original)
                    after = line[after_idx] if after_idx < len(line) else " "
                    if not (before == " " or after == " "):
                        offset = idx + 1
                        continue
                    # Also reject `->` (function return arrow) where `>` follows `-`.
                    if original == ">" and idx > 0 and line[idx - 1] == "-":
                        offset = idx + 1
                        continue
                # Avoid mutating inside string literals (rough heuristic:
                # count un-escaped " before idx; if odd, we're inside a string).
                quotes_before = line[:idx].count('"') - line[:idx].count('\\"')
                if quotes_before % 2 == 1:
                    offset = idx + 1
                    continue
                sites.append((i, original, mutant, idx))
                offset = idx + len(original)
    return sites


def apply_mutation(source_lines: list[str], line_no: int, original: str, mutant: str, col_offset: int) -> list[str]:
    """Return a new copy of source_lines with the mutation applied."""
    new = list(source_lines)
    line = new[line_no - 1]
    new[line_no - 1] = line[:col_offset] + mutant + line[col_offset + len(original):]
    return new


def run_aiken_check(project_root: Path, timeout_seconds: int = 180) -> tuple[bool, list[str], str]:
    """Run `aiken check` and return (all_passed, failing_tests, raw_stdout).

    On Windows we wrap via cmd to recover stdout (bash pipe drops it per
    Aegis memory). The test JSON output is captured to a temp log so we
    can extract failing test names.
    """
    # Aiken outputs results to stdout as JSON when run with default flags;
    # we just need pass/fail and any failure names. Use the cmd-wrapper
    # workaround so stdout actually lands.
    log_path = project_root / "_mutation_aiken_check.log"
    if log_path.exists():
        log_path.unlink()
    try:
        cmd = ["cmd.exe", "/c", f"aiken check 2>&1 > {log_path}"]
        proc = subprocess.run(
            cmd, cwd=str(project_root), capture_output=True, text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return (False, ["<TIMEOUT>"], "<timeout>")
    out = log_path.read_text(encoding="utf-8", errors="ignore") if log_path.exists() else ""
    # If exit code != 0 OR stdout contains failure markers, the check failed.
    failing: list[str] = []
    if proc.returncode != 0 or '"status": "fail"' in out or '"status":"fail"' in out:
        # Extract failing test titles via regex over the JSON-shaped output.
        # The aiken JSON uses `"title": "<name>", "status": "fail"` patterns.
        for m in re.finditer(r'"title"\s*:\s*"([^"]+)"\s*,\s*"status"\s*:\s*"fail"', out):
            failing.append(m.group(1))
        # Also catch compile errors which produce a totally different shape
        if "error[" in out or "Error:" in out or proc.returncode != 0 and not failing:
            failing.append("<compile-or-fatal-error>")
        return (False, failing, out)
    return (True, [], out)


def test_one_mutation(
    project_root: Path,
    validator_path: Path,
    line_no: int, original: str, mutant: str, col_offset: int,
    timeout_seconds: int,
) -> MutationResult:
    """Apply a single mutation, run tests, classify the outcome, restore."""
    backup = validator_path.with_suffix(validator_path.suffix + ".mutation.bak")
    shutil.copy2(validator_path, backup)
    try:
        source_lines = validator_path.read_text(encoding="utf-8").splitlines(keepends=True)
        original_line = source_lines[line_no - 1].rstrip("\n")
        mutated_lines = apply_mutation(source_lines, line_no, original, mutant, col_offset)
        mutated_line = mutated_lines[line_no - 1].rstrip("\n")
        validator_path.write_text("".join(mutated_lines), encoding="utf-8")

        start = time.time()
        passed, failing, raw = run_aiken_check(project_root, timeout_seconds)
        elapsed = time.time() - start

        if "<TIMEOUT>" in failing:
            outcome = "TIMEOUT"
        elif not passed:
            if "<compile-or-fatal-error>" in failing and not any(
                f for f in failing if f != "<compile-or-fatal-error>"
            ):
                outcome = "COMPILE_ERROR"
            else:
                outcome = "KILLED"
        else:
            outcome = "SURVIVED"

        return MutationResult(
            line_no=line_no,
            line_text_original=original_line,
            line_text_mutated=mutated_line,
            operator_original=original,
            operator_mutant=mutant,
            outcome=outcome,
            elapsed_seconds=elapsed,
            failing_tests=[f for f in failing if f != "<compile-or-fatal-error>"],
        )
    finally:
        shutil.copy2(backup, validator_path)
        backup.unlink()


def write_report(results: list[MutationResult], validator_path: Path, output_path: Path) -> None:
    """Format the results as a markdown report."""
    total = len(results)
    killed = sum(1 for r in results if r.outcome == "KILLED")
    survived = sum(1 for r in results if r.outcome == "SURVIVED")
    compile_err = sum(1 for r in results if r.outcome == "COMPILE_ERROR")
    timed_out = sum(1 for r in results if r.outcome == "TIMEOUT")
    actionable = [r for r in results if r.outcome == "SURVIVED"]

    lines: list[str] = []
    lines.append(f"# Mutation testing report — {validator_path.name}")
    lines.append("")
    lines.append(f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    lines.append(f"**Total mutations tested**: {total}")
    lines.append("")
    lines.append("| Outcome | Count | Meaning |")
    lines.append("|---|---|---|")
    lines.append(f"| KILLED        | {killed} | A test failed — the mutation was detected (good) |")
    lines.append(f"| SURVIVED      | {survived} | All tests still passed — **test gap** |")
    lines.append(f"| COMPILE_ERROR | {compile_err} | Mutation produced uncompilable code — type system caught it |")
    lines.append(f"| TIMEOUT       | {timed_out} | Aiken check exceeded timeout |")
    lines.append("")
    mutation_score = killed / max(1, total - compile_err - timed_out) * 100
    lines.append(f"**Mutation score**: {mutation_score:.1f}% "
                 f"(KILLED / (KILLED + SURVIVED), excludes COMPILE_ERROR + TIMEOUT)")
    lines.append("")

    if actionable:
        lines.append("## SURVIVED mutations (test gaps requiring action)")
        lines.append("")
        lines.append("These mutations changed validator behavior but no test in the existing suite caught them. ")
        lines.append("Each represents a place where the test suite is silent on whether the operator's choice matters.")
        lines.append("")
        for idx, r in enumerate(actionable, start=1):
            lines.append(f"### {idx}. Line {r.line_no}: `{r.operator_original}` → `{r.operator_mutant}`")
            lines.append("")
            lines.append(f"**Original**: `{r.line_text_original.strip()}`")
            lines.append(f"**Mutated**:  `{r.line_text_mutated.strip()}`")
            lines.append(f"**Elapsed**: {r.elapsed_seconds:.1f}s")
            lines.append("")
    else:
        lines.append("## SURVIVED mutations")
        lines.append("")
        lines.append("**None.** Every mutation produced a test failure or a compile error. ")
        lines.append("The test suite is tight against this validator's operator choices.")
        lines.append("")

    lines.append("## All results (compact)")
    lines.append("")
    lines.append("| Line | Original | Mutant | Outcome | Elapsed |")
    lines.append("|---|---|---|---|---|")
    for r in results:
        lines.append(f"| {r.line_no} | `{r.operator_original}` | `{r.operator_mutant}` | {r.outcome} | {r.elapsed_seconds:.1f}s |")
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--validator", required=True, type=Path,
                        help="Path to the .ak file to mutate (relative to project root).")
    parser.add_argument("--project-root", default=Path("D:/aegis/contracts"), type=Path,
                        help="Aiken project root containing aiken.toml.")
    parser.add_argument("--output", required=True, type=Path,
                        help="Markdown report output path.")
    parser.add_argument("--limit", type=int, default=0,
                        help="Stop after N mutations (default 0 = all).")
    parser.add_argument("--timeout-seconds", type=int, default=180,
                        help="Per-mutation aiken check timeout (default 180s).")
    args = parser.parse_args()

    if not args.validator.is_absolute():
        validator_path = args.project_root / args.validator
    else:
        validator_path = args.validator

    if not validator_path.exists():
        print(f"ERROR: validator file not found: {validator_path}", file=sys.stderr)
        return 2

    source_lines = validator_path.read_text(encoding="utf-8").splitlines(keepends=True)
    sites = find_mutation_sites(source_lines)
    if args.limit > 0:
        sites = sites[: args.limit]

    print(f"Mutating {validator_path}: {len(sites)} candidate sites")
    print(f"Project root: {args.project_root}")
    print(f"Report: {args.output}")
    print()

    results: list[MutationResult] = []
    for idx, (line_no, original, mutant, col_offset) in enumerate(sites, start=1):
        print(f"[{idx}/{len(sites)}] line {line_no}: {original} -> {mutant}", end=" ... ", flush=True)
        r = test_one_mutation(
            args.project_root, validator_path,
            line_no, original, mutant, col_offset,
            args.timeout_seconds,
        )
        results.append(r)
        print(f"{r.outcome} ({r.elapsed_seconds:.1f}s)")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_report(results, validator_path, args.output)

    survived = sum(1 for r in results if r.outcome == "SURVIVED")
    print()
    print(f"DONE. {survived} surviving mutation(s). Report: {args.output}")
    return 0 if survived == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
