"""Shared deploy helpers — operator wallet, BlockFrost context, deploy-state JSON.

Run scripts from `D:/aegis/` via `python -m offchain.scripts.<name>`.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pycardano as pyc

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = REPO_ROOT / "contracts"
PLUTUS_JSON = CONTRACTS_DIR / "plutus.json"
DEPLOY_STATE_DIR = REPO_ROOT / "configs"
DEPLOY_STATE_PREPROD = DEPLOY_STATE_DIR / "deploy-state.preprod.json"

# ---------------------------------------------------------------------------
# Env loader (no python-dotenv dep — keep this script standalone)
# ---------------------------------------------------------------------------

def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if v and (v.startswith('"') and v.endswith('"') or v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        # Don't override values already set in the parent shell
        os.environ.setdefault(k, v)

_load_dotenv(REPO_ROOT / "api" / ".env")

# ---------------------------------------------------------------------------
# Operator-mode gate
# ---------------------------------------------------------------------------

def assert_operator_mode() -> None:
    if os.environ.get("AEGIS_OPERATOR_MODE", "0") != "1":
        sys.stderr.write(
            "ERROR: AEGIS_OPERATOR_MODE must be 1 to run a deploy script.\n"
            "       Set: $env:AEGIS_OPERATOR_MODE='1' (PowerShell)\n"
            "        or: AEGIS_OPERATOR_MODE=1 python -m offchain.scripts.<name> (bash)\n"
        )
        sys.exit(2)

# ---------------------------------------------------------------------------
# BlockFrost context (real Cardano preprod, NOT the Charli3 devnet)
# ---------------------------------------------------------------------------

def make_preprod_context() -> pyc.BlockFrostChainContext:
    key = os.environ.get("BLOCKFROST_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "BLOCKFROST_KEY missing. Set it in your `.env` file "
            "(value starts with `preprod`) or export it in your shell."
        )
    if not key.startswith("preprod"):
        raise RuntimeError(
            f"BLOCKFROST_KEY={key[:8]}... does not start with 'preprod'. "
            "Use a preprod project key, not mainnet."
        )
    return pyc.BlockFrostChainContext(
        project_id=key,
        base_url=os.environ.get("BLOCKFROST_BASE_URL", "https://cardano-preprod.blockfrost.io/api"),
    )

# ---------------------------------------------------------------------------
# Operator wallet loader (uses chain.derive_wallet path)
# ---------------------------------------------------------------------------

@dataclass
class OperatorWallet:
    skey: pyc.PaymentSigningKey
    vkey: pyc.PaymentVerificationKey
    address: pyc.Address  # base address with stake credential

    @property
    def vkh_hex(self) -> str:
        return bytes(self.vkey.hash()).hex()

def load_operator_wallet() -> OperatorWallet:
    # Operator must set AEGIS_OPERATOR_WALLET_PATH to the location of a
    # plain-text BIP-39 mnemonic file (24 words). NEVER commit that file.
    mnemonic_path_str = os.environ.get("AEGIS_OPERATOR_WALLET_PATH", "")
    if not mnemonic_path_str:
        raise RuntimeError(
            "AEGIS_OPERATOR_WALLET_PATH not set. Point it at a BIP-39 "
            "mnemonic file (one line of 24 words). The mnemonic file MUST "
            "live outside the repository — never commit it."
        )
    mnemonic_path = Path(mnemonic_path_str)
    if not mnemonic_path.exists():
        raise FileNotFoundError(f"Mnemonic not found at {mnemonic_path}")
    mnemonic = mnemonic_path.read_text(encoding="utf-8").splitlines()[0].strip()

    hd = pyc.HDWallet.from_mnemonic(mnemonic)
    spend = hd.derive_from_path("m/1852'/1815'/0'/0/0")
    stake = hd.derive_from_path("m/1852'/1815'/0'/2/0")
    skey = pyc.PaymentSigningKey(spend.xprivate_key[:32])
    vkey = pyc.PaymentVerificationKey.from_signing_key(skey)
    sskey = pyc.StakeSigningKey(stake.xprivate_key[:32])
    svkey = pyc.StakeVerificationKey.from_signing_key(sskey)
    addr = pyc.Address(payment_part=vkey.hash(), staking_part=svkey.hash(), network=pyc.Network.TESTNET)
    return OperatorWallet(skey=skey, vkey=vkey, address=addr)

# ---------------------------------------------------------------------------
# Deploy-state JSON (resumable across runs)
# ---------------------------------------------------------------------------

def read_deploy_state() -> dict[str, Any]:
    DEPLOY_STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not DEPLOY_STATE_PREPROD.exists():
        return {"network": "preprod", "steps": {}}
    return json.loads(DEPLOY_STATE_PREPROD.read_text(encoding="utf-8"))

def write_deploy_state(state: dict[str, Any]) -> None:
    DEPLOY_STATE_DIR.mkdir(parents=True, exist_ok=True)
    DEPLOY_STATE_PREPROD.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")

def record_step(step: str, payload: dict[str, Any]) -> None:
    state = read_deploy_state()
    state.setdefault("steps", {})[step] = payload
    write_deploy_state(state)

# ---------------------------------------------------------------------------
# UTxO selection + summary helpers
# ---------------------------------------------------------------------------

def utxo_summary(u: pyc.UTxO) -> str:
    coin = u.output.amount.coin
    has_assets = bool(getattr(u.output.amount, "multi_asset", None) and len(u.output.amount.multi_asset) > 0)
    tag = " +tokens" if has_assets else ""
    return f"{u.input.transaction_id}#{u.input.index}: {coin/1_000_000:.2f} ADA{tag}"

def pick_init_utxo(utxos: list[pyc.UTxO], min_lovelace: int = 5_000_000) -> pyc.UTxO:
    """Pick a moderately-sized pure-ADA UTxO for the init mint.

    Prefers the SMALLEST UTxO at or above ``min_lovelace`` to keep the
    larger UTxOs free for downstream ops (publish_refs, init_pool, ongoing
    user-facing builds while operator-mode is off).
    """
    pure_ada = [
        u for u in utxos
        if (not u.output.amount.multi_asset or len(u.output.amount.multi_asset) == 0)
        and u.output.amount.coin >= min_lovelace
    ]
    if not pure_ada:
        raise RuntimeError(
            f"No pure-ADA UTxO ≥ {min_lovelace/1_000_000:.0f} ADA available. "
            "Consolidate or fund the operator wallet."
        )
    return min(pure_ada, key=lambda u: u.output.amount.coin)

# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def banner(title: str) -> None:
    bar = "=" * (len(title) + 2)
    print(f"\n+{bar}+\n| {title} |\n+{bar}+")

def print_tx_summary(label: str, body: dict[str, Any]) -> None:
    banner(f"TX: {label}")
    for k, v in body.items():
        print(f"  {k:24s} {v}")
