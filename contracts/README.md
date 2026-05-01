# Aegis Aiken Project

Plutus V3 / Conway-era validators for the Aegis parametric crypto-insurance protocol.

## Toolchain

- **Aiken**: `v1.1.21` or compatible. See [`aiken.toml`](aiken.toml).
- **Stdlib**: `aiken-lang/stdlib v3.0.0` (already vendored under `build/packages/` after first build).

Install Aiken:

```bash
# macOS / Linux
curl --proto '=https' --tlsv1.2 -LsSf https://install.aiken-lang.org | sh
aikup install v1.1.21
aikup use v1.1.21

# Windows: see https://aiken-lang.org/installation-instructions
```

## Build + test

```bash
aiken check         # Run all 186 tests (Aiken unit + green-path security tests)
aiken build         # Compile validators → plutus.json blueprint
aiken fmt --check   # Verify formatting
```

The committed `plutus.json` is the **parameter-free** blueprint. Production deploys re-parameterize via `aiken blueprint apply`:

- `pool.pool_validator` is parameterized over `policy_script_hash: ByteArray` (post-A-022 fix).
- `lp_token.lp_token_policy` is parameterized over `pool_script_hash: ByteArray`.
- `pool_nft.pool_nft` is parameterized over `(utxo_ref: OutputReference, token_name: ByteArray)` (one-shot mint).

The deploy scripts at [`../deploy/scripts/`](../deploy/scripts/) automate this parameterization; see [`../deploy/README.md`](../deploy/README.md).

## Project layout

```
contracts/
├── aiken.toml                 # Project config + stdlib pin
├── aiken.lock                 # Resolved dep lockfile
├── plutus.json                # Compiled blueprint (parameter-free)
└── lib/aegis/
    ├── types.ak               # Datum + redeemer schemas; protocol constants
    ├── pricing.ak             # Premium adequacy, fee math, treasury cut
    ├── pool.ak                # Pool datum-transition helpers, LP math
    ├── oracle.ak              # Charli3 oracle integration
    ├── validation.ak          # Shared signature/time/value/output helpers
    └── test_helpers/
        ├── fixtures.ak        # Test fixture constructors
        └── security_tests.ak  # green_a_NNN_* security regression tests
└── validators/
    ├── policy.ak              # Per-policy lifecycle (Claim / Cancel / Expire / batch)
    ├── pool.ak                # Liquidity pool (Underwrite / ProcessClaim / Add+Remove Liquidity / batch / AcceptCancellation)
    ├── lp_token.ak            # LP token mint policy (parameterized over pool hash)
    └── pool_nft.ak            # One-shot pool NFT mint (parameterized over init UTxO + token name)
```

## Hash stability

| Validator | Stability | Reason |
|---|---|---|
| `policy.policy_validator` | Mostly stable across deploys | Hash only rotates when shared libs (`pricing.ak`, `oracle.ak`, `validation.ak`) change. v0..v3 byte-stable; v4 rotated due to A-014/A-016. v5 byte-stable. |
| `pool.pool_validator` | Rotates per deploy version | Parameterized over `policy_script_hash`, plus its own logic changes more often (A-021/A-022/A-024/A-025). |
| `lp_token.lp_token_policy` | Cascades from pool | Parameterized over `pool_script_hash`. Rotates whenever pool rotates. |
| `pool_nft.pool_nft` | Per-deploy | Parameterized over the operator's chosen init UTxO. By design rotates per deploy. |

## Test conventions

- `green_a_NNN_*` — security regression tests, one or more per audit finding.
- Per-module unit tests live in `pricing.ak`, `pool.ak`, etc. (alongside the function under test).
- Fixtures use realistic-shape data (28-byte hashes, scaled prices, lovelace counts) so test outputs read like real on-chain state.

## Parameter constants

A few protocol-level constants are pinned at compile time in `lib/aegis/types.ak`:

| Constant | Value | Why constant |
|---|---|---|
| `min_premium` | 2_000_000 (2 ADA) | Prevents dust-policy spam |
| `max_coverage_ratio` | 50 | Caps leverage |
| `cancellation_window` | 3_600_000 ms (1 hour) | UX bound |
| `cancellation_fee_bps` | 1_000 (10%) | Cancel fee retained by pool |
| `treasury_share_bps` | 2_500 (25% of fee) | Conway treasury donation share — pinned by hash so operator can't silently raise it |
| `charli3_oracle_script_hash` | `221ee21e...c6f658` | Canonical Charli3 oracle script — pinned by hash so operator can't redirect to a fake oracle |

Changing any of these requires a redeploy that rotates `policy_validator`, `pool_validator`, and `lp_token_policy` hashes. This is intentional — it's the trust handshake.
