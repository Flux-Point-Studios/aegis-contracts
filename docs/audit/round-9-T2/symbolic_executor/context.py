"""Symbolic ScriptContext encoder for Aegis validators.

We do NOT model the full Plutus V3 `ScriptContext` here. Instead, we
encode the *subset of fields* that the Aegis validator branches actually
read. Each branch encoder declares which `Symbolic*` records it consumes.

Modelled fields (Underwrite branch, V12.2 R7):
  - PoolDatum (old)              — see SymbolicPoolDatum
  - PoolDatum (continuation out) — see SymbolicPoolDatum
  - PolicyDatum (new, on cont policy output) — see SymbolicPolicyDatum
  - Redeemer (Underwrite { coverage, premium }) — see SymbolicUnderwriteRedeemer
  - own_input lovelace + script credential hash
  - cont_output lovelace (the "pool continuation" output)
  - team_output lovelace, partner_output lovelace, partner address eq's
  - validity_range (lb, ub)                — see SymbolicValidityRange
  - treasury_donation (Option<Int>)        — see SymbolicTreasuryDonation
  - protocol script hash (compile-time pin) — see SymbolicProtocolConstants

NOT modelled (load-bearing OMISSIONS — surface as TODO when encoders need them):
  - Full `inputs`/`outputs` lists. We encode the *result of the validator's
    list-walks* (e.g. "team_output_lovelace = sum of outputs at team_address")
    rather than the lists themselves. A later agent extending to branches
    that depend on multi-output topology (e.g. BatchUnderwrite with N policy
    outputs) MUST extend `SymbolicScriptContext` with a bounded list array.
  - Full `Value`/`Asset` maps. We model only the lovelace projections that
    the Aegis validator inspects (via `assets.lovelace_of`) plus boolean
    NFT-presence predicates.
  - Mint/witnesses/redeemers-of-other-scripts. Aegis's Underwrite branch
    doesn't read these (the cross-script binding is via the policy
    output's pool_nft check), so we drop them. ProcessClaim does read mint
    indirectly via the policy validator's burn check — flag for the next
    agent.
  - `extra_signatories`, `certificates`, `withdrawals`, `vote`, `propose`.
    Aegis pool validator ignores all of these.
  - The actual CBOR encoding of any value. We encode LOGICAL fields, not
    bytes. CBOR-related bugs (e.g. canonical-encoding round-trip) are
    NOT in scope here — they live in `reference_aegis_v8_cbor_canonical`.

Design principle: each `Symbolic*` class is a plain dataclass of Z3
variables. The encoder reads these variables; the property checker reads
them. NEW fields go onto these dataclasses in dependency order so the
diff stays linear.
"""

from __future__ import annotations

import dataclasses
from typing import Optional

from z3 import Bool, BoolRef, Int, IntVal, ArithRef


# ---------------------------------------------------------------------------
# Protocol constants — pinned from contracts/lib/aegis/types.ak
# ---------------------------------------------------------------------------
# These are compile-time pins on the validator, NOT solver variables.
# Mirroring them here lets the encoder reference them by name without
# poking strings into Z3 expressions.

MIN_UTXO_LOVELACE = 2_000_000
MIN_PREMIUM_PREPROD = 2_000_000
MIN_PREMIUM_MAINNET = 100_000_000
MAX_COVERAGE_RATIO = 50
PROTOCOL_FEE_BPS_DEFAULT = 200
PARTNER_SHARE_CAP_BPS = 2_000
TREASURY_SHARE_BPS = 2_500
BPS_DENOMINATOR = 10_000


# ---------------------------------------------------------------------------
# Symbolic records
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SymbolicPoolDatum:
    """The on-chain PoolDatum, flat-encoded.

    Mirror of `contracts/lib/aegis/types.ak::PoolDatum`. Six fields,
    all Z3 Ints (ByteArrays compared by symbolic Int identity — we
    don't need byte-level reasoning for the branch-level safety props
    we care about; a future agent who needs byte-string properties
    should refactor these to BitVec/Strings).
    """

    total_liquidity: ArithRef
    active_coverage: ArithRef
    lp_token_policy: ArithRef
    protocol_fee_bps: ArithRef
    pool_nft: ArithRef
    lp_supply: ArithRef


@dataclasses.dataclass(frozen=True)
class SymbolicPolicyDatum:
    """The on-chain PolicyDatum, flat-encoded.

    Mirror of `contracts/lib/aegis/types.ak::PolicyDatum` plus the V12
    partner fields. ByteArrays are encoded as Z3 Ints (opaque-identity).

    `partner_address_is_some` is a 0/1 indicator for `Option<Address>`
    discriminator. `partner_address_id` is a symbolic Int that uniquely
    identifies the partner Address when `partner_address_is_some == 1`
    (compared by `Address` equality in Aiken — we encode that as Int
    equality here).
    """

    policy_id: ArithRef
    insured: ArithRef
    strike_price: ArithRef
    coverage_amount: ArithRef
    premium_paid: ArithRef
    start_time: ArithRef
    expiry_time: ArithRef
    oracle_nft: ArithRef
    pool_script_hash: ArithRef
    pool_nft: ArithRef
    oracle_provider: ArithRef  # Tag: 0=Charli3, 1=Orcfax, 2=AegisSelf, 3=Indigo
    partner_address_is_some: ArithRef
    partner_address_id: ArithRef
    partner_share_bps: ArithRef


@dataclasses.dataclass(frozen=True)
class SymbolicUnderwriteRedeemer:
    """The Underwrite { coverage, premium } redeemer."""

    coverage: ArithRef
    premium: ArithRef


@dataclasses.dataclass(frozen=True)
class SymbolicProcessClaimRedeemer:
    """The ProcessClaim { payout } redeemer."""

    payout: ArithRef


@dataclasses.dataclass(frozen=True)
class SymbolicAddLiquidityRedeemer:
    """The AddLiquidity { amount } redeemer."""

    amount: ArithRef


@dataclasses.dataclass(frozen=True)
class SymbolicRemoveLiquidityRedeemer:
    """The RemoveLiquidity { amount } redeemer."""

    amount: ArithRef


@dataclasses.dataclass(frozen=True)
class SymbolicBatchUnderwriteRedeemer:
    """The BatchUnderwrite { total_coverage, total_premium } redeemer."""

    total_coverage: ArithRef
    total_premium: ArithRef


@dataclasses.dataclass(frozen=True)
class SymbolicBatchFeeTotals:
    """Lifted result of `batch_policies_match_totals_v12` walker.

    The Aiken walker iterates over outputs, validates each policy
    output against its share/coverage/premium constraints, and returns
    a record of aggregate sums. We do NOT model the list itself (see
    `context.py` §3.2 in the foundation report); instead we lift each
    AGGREGATE out the walker produces to a single Z3 Int.

    Per-element invariants the walker enforces (e.g. each policy's
    partner_share in [0, cap], each policy's coverage <= 50× premium)
    are NOT individually expressible in this lifted form; we encode the
    walker's `shares_ok` boolean as a single guard. The per-element
    R8-DRAIN-1 alias check is encoded via the
    `aliased_partner_present` boolean: True iff ANY entry in
    partner_totals aliases a privileged address. The validator's
    walker would return shares_ok=False in that case; we keep the
    aliasing as a separate explicit guard for direct property targeting.

    See `D:/aegis/redteam/V12.2_ROUND_9_T2_EXTENSIONS.md` for the
    explicit list-topology scope statement.
    """

    cov_sum: ArithRef
    prem_sum: ArithRef
    fee_total_sum: ArithRef
    team_total: ArithRef
    partner_totals_sum: ArithRef   # aggregate partner_cut sum across entries
    funded_ok: ArithRef            # 0/1
    shares_ok: ArithRef            # 0/1
    partner_outputs_all_funded: ArithRef   # 0/1 - lifted list.all of partner output funding
    aliased_partner_present: ArithRef       # 0/1 - True if ANY entry aliases


@dataclasses.dataclass(frozen=True)
class SymbolicValidityRange:
    """Plutus V3 ValidityRange — (lower_bound, upper_bound) POSIX ms."""

    lb: ArithRef
    ub: ArithRef


@dataclasses.dataclass(frozen=True)
class SymbolicTreasuryDonation:
    """Conway-era `treasury_donation` body field: Option<Int>."""

    is_some: ArithRef  # 0 or 1
    amount: ArithRef


@dataclasses.dataclass(frozen=True)
class SymbolicProtocolConstants:
    """Compile-time validator pins that participate in the branch logic.

    These ARE constants on chain, but we model them as Z3 Ints so the
    encoder can reference them by symbolic name and so properties about
    them (e.g. "team_address != partner_address") admit a single Z3
    expression that is symbolic in both. The fixture layer pins each to
    a concrete value to drive the differential test.
    """

    team_address_id: ArithRef
    pool_address_id: ArithRef
    policy_script_hash: ArithRef
    min_utxo_lovelace: ArithRef
    min_premium: ArithRef
    partner_share_cap_bps: ArithRef
    treasury_share_bps: ArithRef
    protocol_fee_bps: ArithRef  # Validator reads this from datum, but we
                                # need it pinned for the conservation prop.


@dataclasses.dataclass(frozen=True)
class SymbolicScriptContext:
    """The full symbolic ScriptContext slice for the Underwrite branch.

    Each Symbolic* sub-record is independently constructable so future
    branch encoders can mix and match (e.g. ProcessClaim won't need a
    `SymbolicUnderwriteRedeemer` but WILL need a `SymbolicPolicyDatum`
    for the consumed policy input).
    """

    # Datums
    old_pool_datum: SymbolicPoolDatum
    new_pool_datum: SymbolicPoolDatum
    new_policy_datum: SymbolicPolicyDatum
    # Redeemer
    redeemer: SymbolicUnderwriteRedeemer
    # Pool value projection
    own_input_lovelace: ArithRef
    cont_output_lovelace: ArithRef
    # Off-pool output projections (the result of `output_to_address_at_least`
    # walks the validator performs — we encode the predicate result, not the
    # full Value list)
    team_output_lovelace: ArithRef     # max lovelace at team_address among outputs
    partner_output_lovelace: ArithRef  # max lovelace at partner_address among outputs
    # Address projections (the script credential of the own_input and the
    # policy output target — used for the partner_address_not_aliased prop)
    own_pool_script_hash: ArithRef
    # Validity range
    validity_range: SymbolicValidityRange
    # Treasury donation
    treasury_donation: SymbolicTreasuryDonation
    # Compile-time constants
    consts: SymbolicProtocolConstants


# ---------------------------------------------------------------------------
# Per-branch contexts for the five extended branches.
#
# Convention: each branch context exposes the same shape as
# `SymbolicScriptContext` where the fields are common, and adds branch-
# specific records (the consumed PolicyDatum for ProcessClaim /
# AcceptCancellation, the LP mint quantity for AddLiquidity /
# RemoveLiquidity, the lifted `SymbolicBatchFeeTotals` for
# BatchUnderwrite). Sharing the names lets generic properties (e.g.
# `immutable_pool_datum`) read `ctx.old_pool_datum` regardless of branch.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SymbolicProcessClaimContext:
    """ScriptContext slice for the ProcessClaim branch.

    Notable additions over Underwrite:
      * `consumed_policy_datum` — the PolicyDatum read off the consumed
        policy input. Provides `coverage_amount`, `premium_paid`,
        `pool_nft`, `pool_script_hash`, `partner_address_is_some`,
        `partner_address_id`, `partner_share_bps`.
      * `redeemer.payout` — the requested payout amount.

    Fields not used by the ProcessClaim branch (treasury_donation,
    validity_range, partner output projections, new_policy_datum) are
    omitted. The validator simply does not read them.
    """

    old_pool_datum: SymbolicPoolDatum
    new_pool_datum: SymbolicPoolDatum
    consumed_policy_datum: SymbolicPolicyDatum
    redeemer: SymbolicProcessClaimRedeemer
    own_input_lovelace: ArithRef
    cont_output_lovelace: ArithRef
    own_pool_script_hash: ArithRef
    consts: SymbolicProtocolConstants


@dataclasses.dataclass(frozen=True)
class SymbolicAddLiquidityContext:
    """ScriptContext slice for the AddLiquidity branch.

    Notable additions:
      * `redeemer.amount` — the deposit amount (in lovelace).
      * `mint_lp_qty` — the lovelace-equivalent quantity of LP tokens
        minted under `datum.lp_token_policy`/`"aLP"` asset name. Aiken
        reads this via `assets.quantity_of(mint, ..., "aLP")`. We lift
        the asset-map lookup to a single Z3 Int (the validator only
        compares it to `lp_supply_delta`; no further structure is
        needed).
    """

    old_pool_datum: SymbolicPoolDatum
    new_pool_datum: SymbolicPoolDatum
    redeemer: SymbolicAddLiquidityRedeemer
    own_input_lovelace: ArithRef
    cont_output_lovelace: ArithRef
    mint_lp_qty: ArithRef
    consts: SymbolicProtocolConstants


@dataclasses.dataclass(frozen=True)
class SymbolicRemoveLiquidityContext:
    """ScriptContext slice for the RemoveLiquidity branch.

    Notable additions:
      * `redeemer.amount` — the withdrawal amount (in lovelace).
      * `mint_lp_qty` — the lovelace-equivalent quantity of LP tokens
        in the tx's mint. Aiken expects this to be NEGATIVE (a burn);
        the validator computes `lp_burned_qty = -mint_qty` and asserts
        `direction_ok = mint_qty < 0`.
    """

    old_pool_datum: SymbolicPoolDatum
    new_pool_datum: SymbolicPoolDatum
    redeemer: SymbolicRemoveLiquidityRedeemer
    own_input_lovelace: ArithRef
    cont_output_lovelace: ArithRef
    mint_lp_qty: ArithRef
    consts: SymbolicProtocolConstants


@dataclasses.dataclass(frozen=True)
class SymbolicAcceptCancellationContext:
    """ScriptContext slice for the AcceptCancellation branch.

    The biggest branch by guard count. Adds:
      * `consumed_policy_datum` — the cancelled PolicyDatum. Fields
        accessed: `premium_paid`, `coverage_amount`, `pool_script_hash`,
        `pool_nft`, `partner_address_is_some`, `partner_address_id`,
        `partner_share_bps`.
      * `team_output_lovelace`, `partner_output_lovelace` — same lifted
        list-walks as Underwrite.
      * `treasury_donation` — Conway donation field (the cancel branch
        ALSO enforces `donation_ok`).
    """

    old_pool_datum: SymbolicPoolDatum
    new_pool_datum: SymbolicPoolDatum
    consumed_policy_datum: SymbolicPolicyDatum
    own_input_lovelace: ArithRef
    cont_output_lovelace: ArithRef
    team_output_lovelace: ArithRef
    partner_output_lovelace: ArithRef
    own_pool_script_hash: ArithRef
    treasury_donation: SymbolicTreasuryDonation
    consts: SymbolicProtocolConstants


@dataclasses.dataclass(frozen=True)
class SymbolicBatchUnderwriteContext:
    """ScriptContext slice for the BatchUnderwrite branch.

    Per the foundation report's scope statement (§3.2 list-topology),
    we LIFT the per-policy walker's outputs to a single
    `SymbolicBatchFeeTotals` record (aggregate scalars). Per-element
    properties (e.g. "EVERY policy in the batch has partner_share <=
    cap") are encoded as the walker's `shares_ok` flag — we do NOT
    model individual list elements.

    Fields:
      * `redeemer.total_coverage`, `redeemer.total_premium` — the
        aggregate values the redeemer carries.
      * `batch_totals` — the lifted walker output.
      * `team_output_lovelace` — same lifted list-walk for the team
        output funded check.
      * `treasury_donation` — same as Underwrite.
    """

    old_pool_datum: SymbolicPoolDatum
    new_pool_datum: SymbolicPoolDatum
    redeemer: SymbolicBatchUnderwriteRedeemer
    own_input_lovelace: ArithRef
    cont_output_lovelace: ArithRef
    team_output_lovelace: ArithRef
    own_pool_script_hash: ArithRef
    batch_totals: SymbolicBatchFeeTotals
    treasury_donation: SymbolicTreasuryDonation
    consts: SymbolicProtocolConstants


# ---------------------------------------------------------------------------
# Factory: build a fresh fully-symbolic ScriptContext
# ---------------------------------------------------------------------------


def _sym_pool_datum(prefix: str) -> SymbolicPoolDatum:
    return SymbolicPoolDatum(
        total_liquidity=Int(f"{prefix}.total_liquidity"),
        active_coverage=Int(f"{prefix}.active_coverage"),
        lp_token_policy=Int(f"{prefix}.lp_token_policy"),
        protocol_fee_bps=Int(f"{prefix}.protocol_fee_bps"),
        pool_nft=Int(f"{prefix}.pool_nft"),
        lp_supply=Int(f"{prefix}.lp_supply"),
    )


def _sym_policy_datum(prefix: str) -> SymbolicPolicyDatum:
    return SymbolicPolicyDatum(
        policy_id=Int(f"{prefix}.policy_id"),
        insured=Int(f"{prefix}.insured"),
        strike_price=Int(f"{prefix}.strike_price"),
        coverage_amount=Int(f"{prefix}.coverage_amount"),
        premium_paid=Int(f"{prefix}.premium_paid"),
        start_time=Int(f"{prefix}.start_time"),
        expiry_time=Int(f"{prefix}.expiry_time"),
        oracle_nft=Int(f"{prefix}.oracle_nft"),
        pool_script_hash=Int(f"{prefix}.pool_script_hash"),
        pool_nft=Int(f"{prefix}.pool_nft"),
        oracle_provider=Int(f"{prefix}.oracle_provider"),
        partner_address_is_some=Int(f"{prefix}.partner_address_is_some"),
        partner_address_id=Int(f"{prefix}.partner_address_id"),
        partner_share_bps=Int(f"{prefix}.partner_share_bps"),
    )


def fresh_underwrite_context(name: str = "ctx") -> SymbolicScriptContext:
    """Build a fully-symbolic ScriptContext for the Underwrite branch.

    Every field becomes an unconstrained Z3 Int. The encoder is then
    responsible for adding the validator's guard constraints; the
    property checker asserts the negation of the safety property.
    """
    return SymbolicScriptContext(
        old_pool_datum=_sym_pool_datum(f"{name}.old_pool"),
        new_pool_datum=_sym_pool_datum(f"{name}.new_pool"),
        new_policy_datum=_sym_policy_datum(f"{name}.new_policy"),
        redeemer=SymbolicUnderwriteRedeemer(
            coverage=Int(f"{name}.redeemer.coverage"),
            premium=Int(f"{name}.redeemer.premium"),
        ),
        own_input_lovelace=Int(f"{name}.own_input_lovelace"),
        cont_output_lovelace=Int(f"{name}.cont_output_lovelace"),
        team_output_lovelace=Int(f"{name}.team_output_lovelace"),
        partner_output_lovelace=Int(f"{name}.partner_output_lovelace"),
        own_pool_script_hash=Int(f"{name}.own_pool_script_hash"),
        validity_range=SymbolicValidityRange(
            lb=Int(f"{name}.validity_range.lb"),
            ub=Int(f"{name}.validity_range.ub"),
        ),
        treasury_donation=SymbolicTreasuryDonation(
            is_some=Int(f"{name}.treasury_donation.is_some"),
            amount=Int(f"{name}.treasury_donation.amount"),
        ),
        consts=SymbolicProtocolConstants(
            team_address_id=Int(f"{name}.consts.team_address_id"),
            pool_address_id=Int(f"{name}.consts.pool_address_id"),
            policy_script_hash=Int(f"{name}.consts.policy_script_hash"),
            min_utxo_lovelace=Int(f"{name}.consts.min_utxo_lovelace"),
            min_premium=Int(f"{name}.consts.min_premium"),
            partner_share_cap_bps=Int(f"{name}.consts.partner_share_cap_bps"),
            treasury_share_bps=Int(f"{name}.consts.treasury_share_bps"),
            protocol_fee_bps=Int(f"{name}.consts.protocol_fee_bps"),
        ),
    )


def pin_protocol_constants(ctx) -> list:
    """Return the list of Z3 constraints that pin the validator's
    compile-time constants to their preprod values.

    The validator does NOT branch on these — they are hard constants —
    so the encoder ALWAYS adds these to the solver. Returning them as
    a list (rather than baking them into the encoder) lets future
    differential tests substitute mainnet values for a single check.

    Accepts ANY of the per-branch SymbolicScriptContext variants — they
    all expose `.consts`.
    """
    return [
        ctx.consts.min_utxo_lovelace == MIN_UTXO_LOVELACE,
        ctx.consts.min_premium == MIN_PREMIUM_PREPROD,
        ctx.consts.partner_share_cap_bps == PARTNER_SHARE_CAP_BPS,
        ctx.consts.treasury_share_bps == TREASURY_SHARE_BPS,
        # protocol_fee_bps is read from the datum, but the chain pin is
        # 200 bps. The encoder enforces datum.protocol_fee_bps ==
        # consts.protocol_fee_bps via the immutable_ok guard.
        ctx.consts.protocol_fee_bps == PROTOCOL_FEE_BPS_DEFAULT,
    ]


# ---------------------------------------------------------------------------
# Per-branch context factories
# ---------------------------------------------------------------------------


def _sym_consts(prefix: str) -> SymbolicProtocolConstants:
    return SymbolicProtocolConstants(
        team_address_id=Int(f"{prefix}.consts.team_address_id"),
        pool_address_id=Int(f"{prefix}.consts.pool_address_id"),
        policy_script_hash=Int(f"{prefix}.consts.policy_script_hash"),
        min_utxo_lovelace=Int(f"{prefix}.consts.min_utxo_lovelace"),
        min_premium=Int(f"{prefix}.consts.min_premium"),
        partner_share_cap_bps=Int(f"{prefix}.consts.partner_share_cap_bps"),
        treasury_share_bps=Int(f"{prefix}.consts.treasury_share_bps"),
        protocol_fee_bps=Int(f"{prefix}.consts.protocol_fee_bps"),
    )


def _sym_treasury_donation(prefix: str) -> SymbolicTreasuryDonation:
    return SymbolicTreasuryDonation(
        is_some=Int(f"{prefix}.treasury_donation.is_some"),
        amount=Int(f"{prefix}.treasury_donation.amount"),
    )


def fresh_process_claim_context(
    name: str = "pc",
) -> SymbolicProcessClaimContext:
    return SymbolicProcessClaimContext(
        old_pool_datum=_sym_pool_datum(f"{name}.old_pool"),
        new_pool_datum=_sym_pool_datum(f"{name}.new_pool"),
        consumed_policy_datum=_sym_policy_datum(f"{name}.consumed_policy"),
        redeemer=SymbolicProcessClaimRedeemer(
            payout=Int(f"{name}.redeemer.payout"),
        ),
        own_input_lovelace=Int(f"{name}.own_input_lovelace"),
        cont_output_lovelace=Int(f"{name}.cont_output_lovelace"),
        own_pool_script_hash=Int(f"{name}.own_pool_script_hash"),
        consts=_sym_consts(name),
    )


def fresh_add_liquidity_context(
    name: str = "al",
) -> SymbolicAddLiquidityContext:
    return SymbolicAddLiquidityContext(
        old_pool_datum=_sym_pool_datum(f"{name}.old_pool"),
        new_pool_datum=_sym_pool_datum(f"{name}.new_pool"),
        redeemer=SymbolicAddLiquidityRedeemer(
            amount=Int(f"{name}.redeemer.amount"),
        ),
        own_input_lovelace=Int(f"{name}.own_input_lovelace"),
        cont_output_lovelace=Int(f"{name}.cont_output_lovelace"),
        mint_lp_qty=Int(f"{name}.mint_lp_qty"),
        consts=_sym_consts(name),
    )


def fresh_remove_liquidity_context(
    name: str = "rl",
) -> SymbolicRemoveLiquidityContext:
    return SymbolicRemoveLiquidityContext(
        old_pool_datum=_sym_pool_datum(f"{name}.old_pool"),
        new_pool_datum=_sym_pool_datum(f"{name}.new_pool"),
        redeemer=SymbolicRemoveLiquidityRedeemer(
            amount=Int(f"{name}.redeemer.amount"),
        ),
        own_input_lovelace=Int(f"{name}.own_input_lovelace"),
        cont_output_lovelace=Int(f"{name}.cont_output_lovelace"),
        mint_lp_qty=Int(f"{name}.mint_lp_qty"),
        consts=_sym_consts(name),
    )


def fresh_accept_cancellation_context(
    name: str = "ac",
) -> SymbolicAcceptCancellationContext:
    return SymbolicAcceptCancellationContext(
        old_pool_datum=_sym_pool_datum(f"{name}.old_pool"),
        new_pool_datum=_sym_pool_datum(f"{name}.new_pool"),
        consumed_policy_datum=_sym_policy_datum(f"{name}.consumed_policy"),
        own_input_lovelace=Int(f"{name}.own_input_lovelace"),
        cont_output_lovelace=Int(f"{name}.cont_output_lovelace"),
        team_output_lovelace=Int(f"{name}.team_output_lovelace"),
        partner_output_lovelace=Int(f"{name}.partner_output_lovelace"),
        own_pool_script_hash=Int(f"{name}.own_pool_script_hash"),
        treasury_donation=_sym_treasury_donation(name),
        consts=_sym_consts(name),
    )


def fresh_batch_underwrite_context(
    name: str = "bu",
) -> SymbolicBatchUnderwriteContext:
    return SymbolicBatchUnderwriteContext(
        old_pool_datum=_sym_pool_datum(f"{name}.old_pool"),
        new_pool_datum=_sym_pool_datum(f"{name}.new_pool"),
        redeemer=SymbolicBatchUnderwriteRedeemer(
            total_coverage=Int(f"{name}.redeemer.total_coverage"),
            total_premium=Int(f"{name}.redeemer.total_premium"),
        ),
        own_input_lovelace=Int(f"{name}.own_input_lovelace"),
        cont_output_lovelace=Int(f"{name}.cont_output_lovelace"),
        team_output_lovelace=Int(f"{name}.team_output_lovelace"),
        own_pool_script_hash=Int(f"{name}.own_pool_script_hash"),
        batch_totals=SymbolicBatchFeeTotals(
            cov_sum=Int(f"{name}.batch.cov_sum"),
            prem_sum=Int(f"{name}.batch.prem_sum"),
            fee_total_sum=Int(f"{name}.batch.fee_total_sum"),
            team_total=Int(f"{name}.batch.team_total"),
            partner_totals_sum=Int(f"{name}.batch.partner_totals_sum"),
            funded_ok=Int(f"{name}.batch.funded_ok"),
            shares_ok=Int(f"{name}.batch.shares_ok"),
            partner_outputs_all_funded=Int(f"{name}.batch.partner_outputs_all_funded"),
            aliased_partner_present=Int(f"{name}.batch.aliased_partner_present"),
        ),
        treasury_donation=_sym_treasury_donation(name),
        consts=_sym_consts(name),
    )
