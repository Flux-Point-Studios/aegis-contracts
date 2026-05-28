#!/usr/bin/env python3
"""Profile isolation guard for EXT-05 split.

Fails when either per-network module imports the other. The whole point of
the file-split is that a single `use aegis/types/<network>` line in types.ak
is the only operator-visible network selector; cross-imports between
preprod.ak and mainnet.ak would silently re-mix the two profiles and
re-create the bug class the split closes.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PREPROD = ROOT / "lib" / "aegis" / "types" / "preprod.ak"
MAINNET = ROOT / "lib" / "aegis" / "types" / "mainnet.ak"

USE_RE = re.compile(r"^\s*use\s+aegis/types/(preprod|mainnet)\b")


def cross_imports(path: Path, forbidden: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = USE_RE.match(line)
        if m and m.group(1) == forbidden:
            hits.append((i, line.rstrip()))
    return hits


def main() -> int:
    if not PREPROD.exists() or not MAINNET.exists():
        print(f"missing module: {PREPROD if not PREPROD.exists() else MAINNET}",
              file=sys.stderr)
        return 2
    failures = []
    for path, forbidden in ((PREPROD, "mainnet"), (MAINNET, "preprod")):
        hits = cross_imports(path, forbidden)
        if hits:
            failures.append((path, forbidden, hits))
    if not failures:
        print("profile-isolation: OK (no cross-imports between "
              "preprod.ak and mainnet.ak)")
        return 0
    for path, forbidden, hits in failures:
        rel = path.relative_to(ROOT.parent)
        for line_no, text in hits:
            print(
                f"profile-isolation FAIL: {rel}:{line_no}: imports "
                f"aegis/types/{forbidden} -> {text}",
                file=sys.stderr,
            )
    return 1


if __name__ == "__main__":
    sys.exit(main())
