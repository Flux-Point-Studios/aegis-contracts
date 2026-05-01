"""Publish Aegis validators as reference scripts on Cardano preprod.

A reference script UTxO is a regular UTxO that carries a Plutus script in
its `reference_script` field. Spenders consume the script as a CIP-33
reference (no script in the witness set) which dramatically reduces tx
size and fees on every claim/cancel/etc.

We publish three reference scripts in three separate small txs:
  1. policy.policy_validator
  2. pool.pool_validator
  3. lp_token.lp_token_policy (parameterized by pool script hash)

The reference UTxOs sit at the operator's enterprise address (no stake
credential — staking rewards on a ref-script UTxO would be wasted, and
keeping it enterprise simplifies auditing). Min-UTxO ada is calculated
to cover each script's bytes.

After successful submit, the resulting (tx_hash, output_index) for each
script is recorded in configs/deploy-state.preprod.json under
`steps.publish_refs`.

Usage (PowerShell):
    cd D:/aegis
    $env:AEGIS_OPERATOR_MODE = '1'
    python -m offchain.scripts.publish_refs                # dry-run
    python -m offchain.scripts.publish_refs --submit       # broadcast
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import cbor2
import pycardano as pyc

from offchain.scripts._common import (
    PLUTUS_JSON,
    OperatorWallet,
    assert_operator_mode,
    banner,
    load_operator_wallet,
    make_preprod_context,
    print_tx_summary,
    read_deploy_state,
    record_step,
    utxo_summary,
)

# ---------------------------------------------------------------------------
# Validator entries to publish
# ---------------------------------------------------------------------------

# Validator titles to publish as reference scripts.
# `param` is the source of an unapplied parameter (or None for unparameterized).
#   - "policy_validator_hash": apply policy_validator's script hash (FIX A-022).
#   - "pool_validator_hash":   apply pool_validator's (post-A-022) script hash.
VALIDATOR_TITLES: tuple[tuple[str, str, str | None], ...] = (
    ("policy.policy_validator.spend", "policy_validator", None),
    ("pool.pool_validator.spend", "pool_validator", "policy_validator_hash"),
    ("lp_token.lp_token_policy.mint", "lp_token_policy", "pool_validator_hash"),
)


def apply_blueprint_param(input_blueprint: Path, output_blueprint: Path,
                          module_name: str, validator_name: str,
                          param_cbor_hex: str) -> None:
    """Run `aiken blueprint apply` once.

    Writes the applied blueprint JSON to ``output_blueprint``. Module +
    validator must both be specified to disambiguate when several
    validators exist in the project. (Mirrors mint_pool_nft.py.)
    """
    cmd = [
        "aiken", "blueprint", "apply",
        "-i", input_blueprint.name,
        "-m", module_name,
        "-v", validator_name,
        param_cbor_hex,
    ]
    proc = subprocess.run(cmd, cwd=input_blueprint.parent, capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.strip():
        sys.stderr.write(
            "aiken blueprint apply failed.\n"
            f"  cwd:   {input_blueprint.parent}\n"
            f"  cmd:   {' '.join(cmd)}\n"
            f"  rc:    {proc.returncode}\n"
            f"  stdout (first 400 chars): {proc.stdout[:400]}\n"
            f"  stderr (first 400 chars): {proc.stderr[:400]}\n"
        )
        raise RuntimeError("aiken blueprint apply failed")
    output_blueprint.write_text(proc.stdout, encoding="utf-8")


def find_validator_hash(blueprint: dict[str, Any], title: str) -> str:
    entry = next(
        (v for v in blueprint.get("validators", []) if v.get("title") == title), None
    )
    if entry is None:
        raise RuntimeError(f"Blueprint missing validator title: {title}")
    if entry.get("parameters"):
        raise RuntimeError(
            f"Cannot fetch hash of {title}: still has unapplied parameters "
            f"{[p.get('title') for p in entry['parameters']]}"
        )
    return entry["hash"]


def parameterize_pool(policy_script_hash_hex: str) -> dict[str, Any]:
    """Apply policy_script_hash to pool.pool_validator (FIX A-022).

    Returns the applied blueprint dict. The applied pool validator's hash
    is then used to parameterize lp_token (the cascade is unchanged).
    """
    work = PLUTUS_JSON.parent / "_pool_applied.json"
    policy_hash_cbor = cbor2.dumps(bytes.fromhex(policy_script_hash_hex)).hex()
    try:
        apply_blueprint_param(
            PLUTUS_JSON, work, "pool", "pool_validator", policy_hash_cbor,
        )
        return json.loads(work.read_text(encoding="utf-8"))
    finally:
        try:
            work.unlink()
        except FileNotFoundError:
            pass


def parameterize_lp_token(pool_script_hash_hex: str) -> dict[str, Any]:
    """Apply pool_script_hash to lp_token.lp_token_policy → return applied blueprint dict."""
    work = PLUTUS_JSON.parent / "_lp_token_applied.json"
    pool_hash_cbor = cbor2.dumps(bytes.fromhex(pool_script_hash_hex)).hex()
    try:
        apply_blueprint_param(
            PLUTUS_JSON, work, "lp_token", "lp_token_policy", pool_hash_cbor,
        )
        return json.loads(work.read_text(encoding="utf-8"))
    finally:
        try:
            work.unlink()
        except FileNotFoundError:
            pass


def load_validator_script(blueprint: dict[str, Any], title: str) -> tuple[pyc.PlutusV3Script, pyc.ScriptHash]:
    entry = next(
        (v for v in blueprint.get("validators", []) if v.get("title") == title), None
    )
    if entry is None:
        raise RuntimeError(f"Blueprint missing validator title: {title}")
    if entry.get("parameters"):
        raise RuntimeError(
            f"Validator {title} still has unapplied parameters: "
            f"{[p.get('title') for p in entry['parameters']]}. "
            "Re-apply via aiken blueprint apply before publishing."
        )
    script = pyc.PlutusV3Script(bytes.fromhex(entry["compiledCode"]))
    script_hash = pyc.ScriptHash(bytes.fromhex(entry["hash"]))
    return script, script_hash


def build_publish_tx(
    ctx: pyc.ChainContext,
    wallet: OperatorWallet,
    enterprise_address: pyc.Address,
    plutus_script: pyc.PlutusV3Script,
    label: str,
) -> tuple[pyc.TransactionBuilder, int]:
    """Build a tx that creates a UTxO with the script attached as reference_script.

    The UTxO sits at `enterprise_address` (operator's enterprise address —
    payment-credential only, no stake credential). Min-UTxO ada is computed
    to comfortably cover the script bytes.
    """
    # Babbage min-UTxO formula: (160 + serialized_output_size) * coins_per_utxo_byte.
    # For a UTxO carrying a reference script the output size dominates. With
    # coins_per_utxo_byte=4310 (mainnet/preprod), allow ~300 bytes overhead
    # for envelope+address and add a 1 ADA safety margin so transient
    # protocol-param tweaks don't break the publish flow.
    script_bytes = bytes(plutus_script)
    coins_per_utxo_byte = 4310
    min_lovelace = max(
        2_000_000,
        (len(script_bytes) + 300) * coins_per_utxo_byte + 1_000_000,
    )

    builder = pyc.TransactionBuilder(ctx)
    builder.add_input_address(wallet.address)
    builder.add_output(
        pyc.TransactionOutput(
            address=enterprise_address,
            amount=min_lovelace,
            script=plutus_script,
        )
    )
    return builder, min_lovelace


def submit_one(
    ctx: pyc.ChainContext,
    wallet: OperatorWallet,
    enterprise_address: pyc.Address,
    blueprint: dict[str, Any],
    title: str,
    label: str,
    submit: bool,
) -> dict[str, Any]:
    print(f"\n[{label}] loading {title} from blueprint...")
    script, script_hash = load_validator_script(blueprint, title)
    print(f"        script_hash: {bytes(script_hash).hex()}")
    print(f"        script_size: {len(bytes(script))} bytes")

    builder, ref_lovelace = build_publish_tx(
        ctx, wallet, enterprise_address, script, label,
    )

    if submit:
        signed_tx = builder.build_and_sign(
            signing_keys=[wallet.skey],
            change_address=wallet.address,
        )
        tx_body = signed_tx.transaction_body
    else:
        tx_body = builder.build(change_address=wallet.address)

    fee = int(tx_body.fee)
    summary = {
        "label": label,
        "title": title,
        "script_hash": bytes(script_hash).hex(),
        "script_size_bytes": len(bytes(script)),
        "ref_utxo_lovelace": ref_lovelace,
        "ref_utxo_ada": f"{ref_lovelace/1_000_000:.2f}",
        "fee_lovelace": fee,
        "fee_ada": f"{fee/1_000_000:.4f}",
        "ref_utxo_address": str(enterprise_address),
    }
    print_tx_summary(f"PUBLISH_REF/{label}", summary)

    if not submit:
        return {**summary, "submitted": False}

    tx_hash = ctx.submit_tx(signed_tx.to_cbor())
    tx_hash_str = str(tx_hash)
    print(f"  tx_hash: {tx_hash_str}")
    print(f"  cexplorer: https://preprod.cexplorer.io/tx/{tx_hash_str}")

    # The reference-script output is the FIRST output in our build (index 0).
    return {
        **summary,
        "submitted": True,
        "tx_hash": tx_hash_str,
        "ref_utxo_id": f"{tx_hash_str}#0",
        "submitted_at": int(time.time()),
    }


def wait_for_confirmation(ctx: pyc.BlockFrostChainContext, tx_hash: str, timeout_s: int = 180) -> bool:
    """Poll Blockfrost until the tx shows up. Returns True on confirmation."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            ctx.api.transaction(tx_hash)
            return True
        except Exception:
            time.sleep(5)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--submit", action="store_true",
                        help="Actually broadcast (default: dry-run only)")
    parser.add_argument("--wait-between-txs", type=int, default=90,
                        help="Seconds to wait between submitting consecutive ref-script txs (default: 90)")
    parser.add_argument("--only", choices=[lbl for _, lbl, _ in VALIDATOR_TITLES],
                        help="Only publish a specific validator (resume support)")
    parser.add_argument("--force", action="store_true",
                        help="Re-submit even if a label is already recorded in deploy-state")
    args = parser.parse_args()

    assert_operator_mode()

    banner("Publish Aegis reference scripts")

    print(f"[1/4] Connecting to real Cardano preprod via Blockfrost...")
    ctx = make_preprod_context()
    print(f"      tip slot = {ctx.last_block_slot}")

    print(f"[2/4] Loading operator wallet...")
    wallet = load_operator_wallet()
    enterprise_address = pyc.Address(
        payment_part=wallet.vkey.hash(),
        network=pyc.Network.TESTNET,
    )
    print(f"      base addr:       {wallet.address}")
    print(f"      enterprise addr: {enterprise_address}")
    utxos = ctx.utxos(str(wallet.address))
    total = sum(u.output.amount.coin for u in utxos)
    print(f"      balance: {total/1_000_000:.2f} ADA across {len(utxos)} UTxOs")

    print(f"[3/4] Loading post-audit blueprint from {PLUTUS_JSON}...")
    base_blueprint = json.loads(PLUTUS_JSON.read_text(encoding="utf-8"))
    policy_validator_hash = find_validator_hash(base_blueprint, "policy.policy_validator.spend")
    print(f"      policy_validator hash: {policy_validator_hash}")

    titles_to_publish = list(VALIDATOR_TITLES)
    if args.only:
        titles_to_publish = [t for t in titles_to_publish if t[1] == args.only]

    # Skip labels that are already recorded in deploy-state (resume support).
    existing = read_deploy_state().get("steps", {}).get("publish_refs", {}).get("results", [])
    already_done = {r["label"]: r for r in existing if r.get("submitted")}
    if args.submit and not args.force and already_done:
        skipped = [lbl for _, lbl, _ in titles_to_publish if lbl in already_done]
        if skipped:
            print(f"      skipping already-recorded: {skipped}  (use --force to re-submit)")
        titles_to_publish = [t for t in titles_to_publish if t[1] not in already_done]
    print(f"      will publish {len(titles_to_publish)} script(s)")

    # [FIX A-022] Pre-parameterize the pool validator with the policy
    # validator's script hash. The applied pool blueprint is then used
    # both for the pool ref-script publish AND as the input to the
    # lp_token parameterization (the cascade — lp_token is parameterized
    # over the pool's hash, and the pool's hash now depends on the
    # policy_validator hash).
    pool_blueprint = parameterize_pool(policy_validator_hash)
    pool_validator_hash = find_validator_hash(pool_blueprint, "pool.pool_validator.spend")
    print(f"      pool_validator parameterized -> {pool_validator_hash}")

    # Pre-parameterize lp_token using the post-A-022 pool_validator hash.
    lp_token_blueprint = parameterize_lp_token(pool_validator_hash)
    print(f"      lp_token parameterized -> "
          f"{find_validator_hash(lp_token_blueprint, 'lp_token.lp_token_policy.mint')}")

    # Pick the right blueprint per label:
    #   - lp_token_policy → applied with pool_validator hash
    #   - pool_validator  → applied with policy_validator hash (FIX A-022)
    #   - policy_validator → unparameterized (base blueprint)
    blueprint_for = {
        "lp_token_policy": lp_token_blueprint,
        "pool_validator": pool_blueprint,
        "policy_validator": base_blueprint,
    }
    results: list[dict[str, Any]] = list(already_done.values())
    for i, (title, label, _param_source) in enumerate(titles_to_publish):
        bp = blueprint_for.get(label, base_blueprint)
        result = submit_one(ctx, wallet, enterprise_address, bp, title, label, args.submit)
        results.append(result)

        # Persist after EVERY successful submit so a later failure doesn't
        # lose the record of what already landed on chain.
        if args.submit and result.get("submitted"):
            record_step("publish_refs", {
                "results": results,
                "updated_at": int(time.time()),
            })

        if args.submit and i < len(titles_to_publish) - 1:
            print(f"\n  waiting {args.wait_between_txs}s for tx confirmation before next submit...")
            time.sleep(args.wait_between_txs)
            # Refresh context so we see the new UTxO state
            ctx = make_preprod_context()

    if not args.submit:
        print("\n[dry-run] No tx submitted. Re-run with --submit to broadcast.")
        return 0

    print(f"\n[4/4] Deploy state recorded incrementally during submit.")
    print("  deploy-state.preprod.json updated")
    print("\nReference UTxOs (use these in env / chain.py):")
    for r in results:
        print(f"  AEGIS_{r['label'].upper().replace('VALIDATOR', '').replace('POLICY', '').strip('_')}_REF_UTXO={r['ref_utxo_id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
