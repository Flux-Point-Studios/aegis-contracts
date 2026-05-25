"""Aegis-specific symbolic executor for Plutus V3 validators.

This package is NOT a general Plutus FV framework. It hand-encodes
specific Aegis validator branches as Z3 SMT constraints to prove safety
properties (e.g. "no Underwrite path can produce a negative
active_coverage" or "no Underwrite path can mutate pool_nft").

Worked example: the `Underwrite` branch of `validators/pool.ak`.

See `README.md` in this directory for an introduction, and
`V12.2_ROUND_9_T2_FOUNDATION.md` (one level up) for the architectural
write-up.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = [
    "context",
    "encoders",
    "properties",
]
