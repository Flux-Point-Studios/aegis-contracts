"""Pytest plugin hooks for the fuzz directory.

The `--slow` opt-in flag and shared path bootstrap live here so
pytest picks them up before parametrize-time collection.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve()
REDTEAM_DIR = HERE.parents[2]
if str(REDTEAM_DIR) not in sys.path:
    sys.path.insert(0, str(REDTEAM_DIR))


def pytest_addoption(parser):
    """Add the `--slow` opt-in flag.

    Defined at conftest level so pytest discovers it before parametrize-
    time collection. The flag enables N=1000, N=100k, and Tier-2 Aiken
    subprocess tests.
    """
    parser.addoption(
        "--slow",
        action="store_true",
        default=False,
        help="Run the slow (N>=1000) and aiken-subprocess fuzz tiers.",
    )
