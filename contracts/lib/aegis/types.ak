use aegis/types/preprod as network
use aiken/cbor
use aiken/collection/list
use aiken/crypto.{Blake2b_224, Hash, Script, VerificationKey, blake2b_256}
use aiken/primitive/bytearray
use cardano/address.{Address, VerificationKey as PaymentVKCred}

pub type VerificationKeyHash =
  Hash<Blake2b_224, VerificationKey>

pub type ScriptHash =
  Hash<Blake2b_224, Script>

pub type OracleProvider {
  Charli3
  Orcfax
  AegisSelf
  Indigo
  // [Pyth Wave 1] Pyth Lazer on Cardano (trusted-signer Ed25519 model).
  // Appended as the NEXT constructor index (4) so the four existing
  // providers keep their CBOR tags — Charli3=0, Orcfax=1, AegisSelf=2,
  // Indigo=3, Pyth=4. Appending (never inserting) is load-bearing: any
  // live PolicyDatum on chain encodes `oracle_provider` by constructor
  // index, so reordering would silently re-interpret deployed policies.
  Pyth
}

/// Risk class of a policy — selects which on-chain premium-floor table the
/// Underwrite branch dispatches to (and how the trigger is parameterized).
///
///   * `Barrier` — one-touch down-and-in barrier on a *price* (ADA crash,
///     Indigo CDP liquidation, Surf liquidation). Pays `coverage` if the
///     underlying touches `strike = spot × (1 − d)` at any fresh oracle
///     observation in `[start, expiry]`. Premium floor is strike-distance-,
///     duration- and vol-aware (GBM first-passage at the conservative σ=85%
///     grade), and Underwrite reads a fresh oracle reference input to derive
///     the strike distance `d`.
///   * `Depeg` — a stablecoin leaving its peg. The trigger strike is a fixed
///     band below the peg (e.g. 0.95 × peg); the premium is hazard- (Poisson-)
///     driven and duration-only, so Underwrite does NOT need a spot read for
///     this class — only a strike-band sanity check.
///
/// Set at Underwrite, immutable for the policy's life. Folding both classes
/// into one datum lets a single pool-funded validator back every product line
/// while charging each its correct actuarial floor.
pub type RiskClass {
  Barrier
  Depeg
}

pub type PolicyDatum {
  policy_id: ByteArray,
  insured: VerificationKeyHash,
  strike_price: Int,
  coverage_amount: Int,
  premium_paid: Int,
  start_time: Int,
  expiry_time: Int,
  oracle_nft: ByteArray,
  pool_script_hash: ScriptHash,
  pool_nft: ByteArray,
  oracle_provider: OracleProvider,
  partner_address: Option<Address>,
  partner_share_bps: Int,
  risk_class: RiskClass,
  // [V5] Optional script/Address payout target for the Claim coverage.
  //   * None       -> coverage pays the `insured` enterprise KEY address (V4 behaviour).
  //   * Some(addr) -> coverage pays this EXACT address (payment AND stake),
  //                   enabling a DAO-governed (script) beneficiary. `insured`
  //                   remains the cancel-authority signer + Cancel-refund recipient.
  // Appended LAST so fields #1-14 keep their positional CBOR indices.
  payout_address: Option<Address>,
  // AI-cover binding: a commitment to the Materios receipt this policy covers
  // — blake2b-256(receipt_id ++ threshold_be8 ++ config_hash). `None` for every
  // non-AI policy (price/depeg/barrier/plain-event), which keeps the existing
  // Claim path unchanged. When `Some`, the policy can ONLY be claimed via
  // `ClaimWithReceipt`, revealing a preimage that hashes to this value — so the
  // payout is bound to the exact attested receipt + threshold, on-chain.
  // Appended AFTER payout_address (index 15) so fields #0-14 keep their CBOR
  // indices — a live V4 14-field datum decodes as payout None / receipt None.
  receipt_commitment: Option<ByteArray>,
  // [V6 / #325 Plutus-treasury] Optional inline datum the Claim coverage output
  // must carry when paying a `payout_address`. The ledger requires a datum to
  // invoke a Plutus (V1/V2) spend script — a datum-less coverage output locks
  // at a Plutus treasury forever. When `Some(d)`, the Claim branch REQUIRES the
  // coverage output to `payout_address` to carry `InlineDatum(d)` exactly, so a
  // Plutus treasury (e.g. Agora — whose validator ignores the datum CONTENTS
  // but needs A datum; `unit` is the simplest valid value) can spend it. `None`
  // keeps the V5 datum-less output (native-script / key treasury). Buyer-
  // committed at Underwrite, immutable. Appended LAST (index 16) so fields
  // #0-15 keep their CBOR indices.
  payout_datum: Option<Data>,
  // [V8.2] Self-contained settlement: every mutable-config value settlement
  // needs, copied out of GOVERNED registry config at Underwrite. `None` -> the
  // policy predates the pins and settles on the vault's compiled constants.
  // Appended LAST (index 17) so fields #0-16 keep their CBOR indices. Pins may
  // only WIDEN what the policy permits: a validator compiled before this field
  // ignores it (decode-by-index defaults the tail), so a restriction placed
  // here is invisible exactly where it matters.
  settlement_pins: Option<SettlementPins>,
  /// [#390 / #403 FIX 5] RESERVED. One trailing slot, decoded by index and
  /// defaulted to `None`, so the next thing a policy has to carry does not cost
  /// a vault generation.
  ///
  /// It is ONE slot rather than two named fields on purpose. Two claimants are
  /// already known — ORACLE-ZERO E9's freeze-attestation hash (32 bytes, sizing
  /// answered) and a SHORT sale-side trailing low distinct from the 12h
  /// claim-side one — and inventing a second slot for the second claimant is
  /// how a datum acquires four half-used tails. They coordinate here.
  ///
  /// WHY THE SALE-SIDE LOW IS RESERVED AND NOT BUILT: one field cannot serve
  /// both sides. The sale gate wants a SHORT memory, because a 12-hour low
  /// makes cover unbuyable for twelve hours after a dip; the claim trigger
  /// wants a LONG one, because a 15-minute memory denies an honest claimant
  /// whose break happened an hour into a 7-day policy and recovered. Splitting
  /// them is a real design question with a real cost on either side, and it is
  /// not this generation's work — but the ROOM for it has to exist at genesis
  /// or the split becomes a migration.
  ///
  /// THE CONSTRAINT THIS SLOT INHERITS (see the module header): an
  /// already-deployed vault IGNORES a tail it does not know, so anything placed
  /// here can only ever WIDEN what a policy permits. A restriction written into
  /// the extension is invisible to exactly the vaults that would have to
  /// enforce it.
  extension: Option<Data>,
}

/// The GOVERNED values Underwrite copies into each new policy so settlement
/// never reads mutable config (Invariant S). After the copy the policy is
/// self-contained: a hostile registry can shape business that does not exist
/// yet, never a policy that does. Class-shaped budgets are resolved to the
/// policy's own class at Underwrite — pins carry concrete numbers, not tables.
pub type SettlementPins {
  /// Pyth Lazer feed id the fallback leg may settle against; empty = no
  /// fallback, primary attestation only.
  fallback_feed_id: ByteArray,
  // [#413] THE SIX BELOW ARE DISCLOSED, NOT ENFORCED. They are decoded and
  // dropped: `fallback_feed_id` and `claim_waiting_period_ms` are the only pins
  // any validator reads (vault.ak:646/:660/:669). Settlement resolves each of
  // these from a COMPILED constant instead, so a doc here that says "settlement
  // uses this" describes a protection the code does not implement — the shape
  // pool_vault.ak:270-273 already records as a G10 CRITICAL. Each line names the
  // value settlement ACTUALLY reads.
  /// DISCLOSED. Settlement checks the signer against CORE (`fallback.ak:56`).
  publisher_vkh: ByteArray,
  /// DISCLOSED. Settlement invokes the vault's COMPILE PARAMETER
  /// (`pool_vault.ak:114`, used at :458/:760/:891) — never this pin. A compile
  /// parameter is strictly more immutable than a pin, so the guarantee is
  /// stronger than the one this field appeared to make.
  observer_script_hash: ByteArray,
  /// DISCLOSED. `vault.ak:549-550` reads CORE `max_reading_validity_ms`.
  max_reading_validity_ms: Int,
  /// DISCLOSED. The Pyth leg opens on CORE grace (`fallback.ak:223`).
  fallback_grace_ms: Int,
  /// DISCLOSED. Cancel uses CORE `cancellation_window` (`pool_vault.ak:873`).
  /// [#420] Its governance rail is 24x `claim_waiting_period_ms`; the invariant
  /// `cancel_window_closes_before_any_policy_can_claim` binds the CONST, not
  /// this pin, so wiring a reader here needs the rail bound first.
  cancellation_window_ms: Int,
  /// DISCLOSED. `pricing.ak:174-176` hardcodes the 10% and takes no fee argument.
  cancellation_fee_bps: Int,
  /// [#391 F1] Delay from `start_time` before this policy may be CLAIMED — a
  /// DISCLOSED term the buyer reads before paying, not a global constant that
  /// can move under him. Underwrite floors it at `claim_waiting_period_ms` for
  /// the policy's own class, so a pin may only ever be SAFER than CORE.
  claim_waiting_period_ms: Int,
}

pub type PoolDatum {
  total_liquidity: Int,
  active_coverage: Int,
  lp_token_policy: ByteArray,
  protocol_fee_bps: Int,
  pool_nft: ByteArray,
  lp_supply: Int,
  // [V5/#265 P1] First-loss reserve tranche — the yield-funded premium rail.
  // DISTINCT from total_liquidity: protocol-owned first-loss capital credited
  // ONLY via the `DepositRevenue` arm and drawn FIRST on `ProcessClaim` (before
  // LP-attributable total_liquidity), so LP capital is protected until the
  // reserve is exhausted. EXCLUDED from `calculate_withdrawal` — accruing
  // premium here never raises the LP redemption price. Appended LAST (index 6)
  // so fields #0-5 keep their positional CBOR indices; a fresh P1 pool's datum
  // is 7-field while the live 6-field V4 pools keep running on their own
  // (unchanged) validator bytecode — no on-chain migration.
  reserve: Int,
}

pub type PolicyRedeemer {
  Claim
  BatchClaim
  Expire
  BatchExpire
  Cancel
  // Claim an AI-cover policy by REVEALING the receipt preimage bound at
  // creation. Appended LAST so existing constructor indices 0-4 (and every
  // off-chain redeemer that encodes them) are unchanged.
  ClaimWithReceipt { receipt: ReceiptWitness }
}

/// The revealed preimage of a policy's `receipt_commitment`. The
/// `ClaimWithReceipt` path recomputes the commitment from these fields and
/// requires it to equal `PolicyDatum.receipt_commitment`, so a committed policy
/// names the exact Materios receipt + threshold it settles against, on-chain.
pub type ReceiptWitness {
  /// Materios receiptId (Bytes32, exactly 32 bytes).
  receipt_id: ByteArray,
  /// The PUBLIC risk threshold (Uint64) proven by the Midnight circuit.
  threshold: Int,
  /// Hash of the AI-cover config the proof was produced under (Bytes32, 32 bytes).
  config_hash: ByteArray,
}

/// Canonical on-chain receipt commitment: blake2b-256 over
/// `receipt_id (32B) ++ threshold (Uint64 big-endian, 8B) ++ config_hash (32B)`.
/// Off-chain builders MUST reproduce this byte layout exactly to bind a policy.
pub fn receipt_commitment_hash(w: ReceiptWitness) -> ByteArray {
  blake2b_256(
    w.receipt_id
      |> bytearray.concat(bytearray.from_int_big_endian(w.threshold, 8))
      |> bytearray.concat(w.config_hash),
  )
}

/// Fail-closed structural check on a revealed witness: a 32-byte receiptId, a
/// 32-byte config hash, and a non-negative Uint64 threshold (so the 8-byte
/// big-endian encoding above is well-defined and unambiguous).
pub fn receipt_witness_ok(w: ReceiptWitness) -> Bool {
  bytearray.length(w.receipt_id) == 32 && bytearray.length(w.config_hash) == 32 && w.threshold >= 0 && w.threshold < 18_446_744_073_709_551_616
}

pub type PoolRedeemer {
  Underwrite { coverage: Int, premium: Int }
  ProcessClaim { payout: Int }
  AddLiquidity { amount: Int }
  RemoveLiquidity { amount: Int }
  BatchUnderwrite { total_coverage: Int, total_premium: Int }
  BatchExpireProcess { total_returned: Int }
  AcceptCancellation
  // [V5/#265 P1] Credit the first-loss `reserve` with `amount` lovelace from
  // the yield-funded premium rail (premium_stake_validator). The ONLY pool arm
  // that adds lovelace WITHOUT minting LP or burning a marker. Appended LAST
  // (constructor index 7) so indices 0-6 of every deployed redeemer encoding
  // are unchanged.
  DepositRevenue { amount: Int }
}

pub type LPTokenRedeemer {
  MintLP
  BurnLP
}

pub type MarkerRedeemer {
  MintMarkers { count: Int }
  BurnForClaim
  BurnForCancel
  BurnForExpire { count: Int }
}

// [Zero-premium cover] Terms baked per-enrollee into the premium_stake
// `cover_terms` param at enrollment and carried inline on every cover_escrow
// UTxO. Immutable — changing terms means unenroll + re-enroll, consistent
// with the rail's param-immutability doctrine. Together these pin the policy
// a permissionless Convert may buy: `min_strike` floors the trigger (a
// deep-out-of-the-money strike passes every premium-minimum floor while
// being economically worthless — the strike floor is what makes the bought
// cover claimable in the scenarios the enrollee enrolled for);
// `max_rate_bps` bounds the premium/coverage ratio (blocks overpriced junk);
// `min_duration_days` bounds the shortest policy.
pub type CoverTerms {
  user_vkh: VerificationKeyHash,
  oracle_nft: ByteArray,
  min_strike: Int,
  max_rate_bps: Int,
  min_duration_days: Int,
}

pub type EscrowRedeemer {
  // Permissionless: spend escrow into a real policy for `user_vkh` through
  // the audited pool Underwrite arm in the same tx.
  Convert
  // User-signed: free exit of accrued premium at any time.
  Reclaim
}

// `"AEGIS_POLICY"` (12 bytes) — discriminator on marker policy id.
pub const policy_marker_asset_name: ByteArray = #"41454749535f504f4c494359"

// ---------------------------------------------------------------------------
// Cross-network protocol constants
// ---------------------------------------------------------------------------

pub const max_coverage_ratio: Int = 50

/// [#363 red-team M1 + N4] Vault-baked ceiling on policy TERM (POSIX ms). The
/// swappable logic owns the actuarial curve, but the IMMUTABLE vault bounds how
/// long LP capital can be locked — without it a hostile enacted logic mints
/// arbitrarily long-dated, arbitrarily cheap coverage (the floor bounded price
/// but had no duration axis at all).
///
/// PINNED TO THE FLOOR TABLE'S DOMAIN (N4): `floor_table.t_band_index`
/// saturates at band 6 = 180 days, so ANY longer term is priced as if it were
/// 180d — a 400d Depeg would pay the 180d floor (~464 bps) against an honest
/// ~839 bps, ~45% structural under-pricing, with no governance compromise
/// needed. The vault must therefore never admit a term the table cannot price.
/// Raise this ONLY together with new bands past 180d.
pub const max_policy_term_ms: Int = 180 * 86_400_000

/// [#363 red-team F6] Vault-baked FLOOR on policy term, symmetric to the
/// ceiling above and justified identically: the vault must never admit a term
/// the premium table cannot price.
///
/// `floor_table.t_band_index` maps every `t_days < 7` to band 0, and for
/// BARRIER that band is a literal 0 bps in every strike-distance row — the
/// actuarial curve contributes nothing at all below a week.
///
/// The binding constraint there is not the floor table but `is_premium_adequate`:
/// `max_coverage_ratio = 50` forces premium >= coverage/50, i.e. an effective
/// 200 bps. So sub-7-day cover was not free — it was priced at a flat 2%
/// against an honest 7-day 15%-OTM rate of 1203 bps, roughly 6x under. That is
/// a real mispricing on exactly the short-dated near-money barriers a crash
/// pays out on, but it is under-pricing, not free coverage.
///
/// DEPEG's band 0 is 2 bps, which the same 200 bps ratio floor dominates
/// outright — so sub-7-day Depeg is if anything OVER-priced. The clamp still
/// covers both classes for uniformity and because the swappable-logic surface
/// can price below the table; the sharp hole is Barrier's.
///
/// 7 days is also the shortest duration the buy UI offers (chips are
/// [7, 14, 30, 60, 90]), so this clamps nothing an honest buyer can construct.
/// Lower this ONLY together with real sub-7-day bands in the floor table.
pub const min_policy_term_ms: Int = 7 * 86_400_000

/// [#363 K-1 residual] Ceiling on how long any single oracle reading may remain
/// claim-valid, measured from its own `observed_at`. Converts the unbounded
/// publisher-trust envelope into a validator-enforced window.
///
/// The Underwrite freshness leg anchors the spot to `observed_at` directly
/// (`start_time <= observed_at + max_spot_age_ms`), so it is already bounded.
/// The CLAIM/CANCEL leg is `reading_fresh`, which required
/// `tx_upper <= valid_until` with NOTHING bounding `valid_until` from above —
/// so a feed published with `valid_until = observed_at + 100y` stayed claim-fresh
/// forever. That is the trusted-publisher design, but the trust was UNBOUNDED:
/// a dead or misconfigured publisher's last reading remained settleable
/// indefinitely, and a stale frozen price is exactly what a barrier claim needs.
///
/// This bounds it. `reading_fresh` now also requires
/// `valid_until <= observed_at + max_reading_validity_ms`, so a reading expires
/// within this window of its own observation regardless of the `valid_until`
/// the publisher wrote. The publisher's own convention is a 70-minute window
/// (`created_at + 4_200_000`); 2h gives ~1.7x headroom for every honest feed
/// while capping the dead-publisher stale-claim exposure at 2h instead of
/// forever. Raise ONLY with a matching publisher-window change.
pub const max_reading_validity_ms: Int = 2 * 60 * 60 * 1000

/// [#363 red-team M1] Synthetic underwrite validity-span ceiling for the Depeg
/// path. Barrier is bounded by `tx_upper <= price.valid_until` (the feed's own
/// horizon); Depeg reads no feed, so without this an attacker sets tx_upper
/// years ahead and starts coverage in the far future (start_time is only
/// bounded INTO the tx range). Bounds `tx_upper - tx_lower`.
pub const max_underwrite_span_ms: Int = 1_200_000

/// [#363 F2] Max age of the resolved spot at the instant coverage BEGINS.
///
/// The old leg (`tx_lower <= observed_at + max_feed_age_ms`) was not merely
/// weak, it was VACUOUS: the ledger only requires `invalidBefore <=
/// currentSlot`, so a tx_lower years in the past satisfied it against a feed of
/// ANY age. Judging at `start_time` instead makes it bite, because `start_time`
/// is the value `claim_trigger_ok` gates on and the one `barrier_touched`
/// compares `low_observed_at` against.
///
/// Composed with `pd.start_time >= tx_upper` and the ledger's
/// `currentSlot < invalidHereafter`, this ALSO bounds the reading's age at
/// INCLUSION — the quantity every stale-spot attack is measured in, since
/// `barrier_touched`'s `spot <= strike` disjunct has no time gate at all and
/// `underwrite_baseline_ok` measures its strike distance against this same
/// reading. Those two quantities are physically the same number: "coverage
/// starts no earlier than this tx's deadline" plus "a long inclusion window"
/// mechanically implies "the strike is stale when coverage starts".
///
/// Per-class because the margins differ 7.5x: Barrier carries
/// `min_strike_distance_bps` = 1500, Depeg only `min_depeg_distance_bps` = 200,
/// so one shared budget under-protects Depeg by that factor.
pub fn max_spot_age_ms(risk_class: RiskClass) -> Int {
  when risk_class is {
    Barrier -> 600_000
    Depeg -> 300_000
  }
}

/// [#391 F1] CORE waiting period: how long after `start_time` a policy becomes
/// CLAIMABLE. Pinned per policy at Underwrite (`SettlementPins`), floored here.
///
/// `max_spot_age_ms` above is the age of the print that SETS the strike, and it
/// cannot be driven to zero — block time and publisher burn both fight it.
/// Whatever it is, it is HINDSIGHT: a buyer watching a DEX knows the price the
/// vault is about to bind him to is already wrong, and `barrier_touched`'s
/// `spot <= strike` disjunct has no time gate at all, so the very next print
/// settles him at full coverage. Tightening the budget cannot close that;
/// delaying the CLAIM can, because the trade only pays if the money arrives
/// before the market corrects the information advantage away.
///
/// It delays claiming; it never erases the event. `min_price_12h` is a
/// twelve-hour low-water MARK, so a genuine break inside the waiting period is
/// still claimable after it — even one that has fully recovered by then.
///
/// [#391 R2 F2b] Per-class, and the multiple is MONOTONE in the budget it
/// neutralises: `claim_waiting_period_ms(c) >= 6 * max_spot_age_ms(c)` for
/// every class (`waiting_period_is_six_budgets_or_more` pins it).
///
/// Barrier used to be the WEAKER side and that was backwards — 600_000 ms of
/// hindsight against 1_800_000 ms of wait, three budgets, while Depeg got
/// twelve on half the hindsight. The flagship ADA-crash product granted twice
/// the hindsight for half the delay.
///
/// The fix raises the WAIT rather than cutting the budget, because the budget
/// is not free: `max_spot_age_ms` is the age of the print that sets the strike,
/// and driving it down means publishing more often. The AegisSelf publisher
/// burns ~175 ADA/day at today's cadence and demand-gating exists precisely
/// because tight cadence is expensive, so tightening the Barrier budget from
/// 600_000 to 300_000 would roughly double the ADA/USD publish rate for the
/// whole book. The waiting period costs NOTHING to lengthen — it is a
/// settlement-side delay, not a publish-side one — and it is the leg that
/// actually removes the hindsight's VALUE, since the trade only pays if the
/// money arrives before the market corrects the information advantage away.
///
/// It delays claiming; it never erases the event. `min_price_12h` is a
/// twelve-hour low-water MARK, so a genuine break inside the waiting period is
/// still claimable after it — even one that has fully recovered by then.
pub fn claim_waiting_period_ms(risk_class: RiskClass) -> Int {
  when risk_class is {
    Barrier -> 3_600_000
    Depeg -> 3_600_000
  }
}

/// [#391 F2] The window `min_price_12h` is defined over. The field is a
/// TRAILING TWELVE HOUR low-water mark, so the instant it was observed cannot
/// pre-date its own reading by more than this and cannot post-date it at all.
/// Nothing bounded it before: the publisher chose, unassisted, whether a touch
/// counted as falling during a policy.
pub const trailing_low_window_ms: Int = 12 * 60 * 60 * 1000

/// [#391 R2 F2c] How long after `start_time` the insured may cancel for a 90%
/// premium refund. It MUST close strictly before the policy becomes claimable,
/// or the losing half of a hindsight bet is refunded: the attacker's breach
/// pre-dates `start_time` by construction, so the moment spot recovers the
/// policy reads out of the money and AcceptCancellation hands 90% of the
/// premium back. Heads full coverage, tails most of the stake — a free option.
/// At 3_600_000 it EQUALLED the Depeg waiting period and EXCEEDED Barrier's.
///
/// Half the shortest waiting period. That is the relation
/// `cancel_window_closes_before_any_policy_can_claim` pins, and thirty minutes
/// is what an honest buyer gets to change their mind — an honest cancel is a
/// decision about the cover, not about the market, and it does not need to wait
/// on a price. The buyer who wants OUT after the window still has the ordinary
/// exit: let the cover run and pay the premium for what it was.
pub const cancellation_window: Int = 1_800_000

pub const cancellation_fee_bps: Int = 1_000

pub const price_scale: Int = 1_000_000

pub const min_utxo_lovelace: Int = 2_000_000

// 25% of the 2% protocol fee = 0.5% of premium routes via Conway
// treasury_donation. Pinned by validator hash, not datum.
pub const treasury_share_bps: Int = 2_500

pub const orcfax_ada_usd_feed_id: ByteArray = #"4345522f4144412d5553442f"

pub const orcfax_fs_asset_name: ByteArray = #""

pub const orcfax_fsp_asset_name: ByteArray = #"000de140"

// v7 widened to 70 min based on empirical mainnet observation
// (mean 45 min, p95 51 min, max 55 min).
pub const orcfax_freshness_window_ms: Int = 70 * 60 * 1_000

// 2000 bps of protocol fee = 20% of fee = 0.4% of premium max per partner.
pub const partner_share_cap_bps: Int = 2_000

// ---------------------------------------------------------------------------
// [Pyth Wave 1] Pyth Lazer freshness + scale constants
//
// CRITICAL: the Pyth withdraw script verifies the Ed25519 signature on the
// price update but does NOT enforce freshness and does NOT prevent replay of
// the same signed update (an attacker can re-present an old, still-validly-
// signed update). Aegis closes both gaps in `aegis/oracle/pyth.ak`:
//   * Freshness: the update's `timestamp_us` (microseconds) is converted to
//     POSIX ms and surfaced as Price.observed_at; valid_until is derived as
//     observed_at + pyth_ordinary_window_ms. The downstream policy.ak gate
//     (`tx_lower >= observed_at && tx_lower <= valid_until && tx_upper <=
//     valid_until`) then rejects stale AND future-dated updates and binds the
//     price to THIS tx's validity range — defeating replay (a re-presented
//     old update fails `tx_lower <= valid_until`).
//   * Scale: Pyth prices carry their own `exponent` (typically negative,
//     e.g. -8). Aegis is fixed-point at 1e6 (price_scale). The resolver
//     rescales `price * 10^(exponent + 6)` (floor on the divide leg, matching
//     the Orcfax convention).
// ---------------------------------------------------------------------------

// [#403 FIX 2 / FROZEN DECISION 4 amendment] THREE WINDOWS, NAMED APART.
// One constant used to govern two paths with opposite justifications, so
// keeping 70 minutes for replay also left 70 minutes of print-shopping on the
// ordinary path. The three are now distinct:
//
//   SALE-SIDE     `max_spot_age_ms(risk_class)` — 300s Depeg / 600s Barrier.
//                 Bounds the Underwrite min leg. Declared above.
//   ORDINARY      `pyth_ordinary_window_ms` — this one. The ordinary fallback
//                 carries NO provenance, so age IS the risk: a wide window
//                 lets a claimant shop the worst validly-signed print inside
//                 it. Derived, not picked: over 26,903 ADA-USD 5m candles
//                 since Pyth went live, Indigo's 280s window caps divergence
//                 at 2.50% and 70 min at 7.00%; fitting the two gives
//                 divergence proportional to t^0.380, so 900s caps at 3.90%.
//                 900s rounds DOWN from the 18-min geometric mean of the two,
//                 and rounding down is the conservative direction on a
//                 hindsight window. It is not load-bearing for liveness: the
//                 ordinary leg only opens after ~100 min of proven primary
//                 silence, at which point the claimant is pulling a CURRENT
//                 update and the window only has to cover pull -> tx-lands.
//   REPLAY        `pyth_replay_window_ms` — 70 min, kept. A replayed payload
//                 is old BY DESIGN (CDP freeze -> liquidate median 165s, and
//                 the keeper may fire minutes later), and its age is justified
//                 by PROVENANCE: it is the one message that condemned this
//                 CDP. Reserved for #402 and consumed by NO arm today —
//                 deliberately, because the 70-minute window is only sound
//                 once the replay path carries a provenance predicate.
//
// `pyth_ordinary_window_is_never_the_binding_settlement_leg` below pins the
// relation these three sit in.
pub const pyth_ordinary_window_ms: Int = 15 * 60 * 1_000

pub const pyth_replay_window_ms: Int = 70 * 60 * 1_000

// Aegis price scale exponent. price_scale = 1e6 => exponent 6. Used to
// renormalise a Pyth feed's native exponent into the 1e6 fixed-point space:
// net_exp = feed.exponent + pyth_price_scale_exp.
pub const pyth_price_scale_exp: Int = 6

// [#381 V8.1 S1] Max Pyth confidence interval, in bps of the price. A
// reading whose reported confidence exceeds this is too uncertain to
// settle money against and is rejected fail-closed inside pyth.ak's
// find_feed_reading. 100 bps = 1%.
pub const pyth_max_confidence_bps: Int = 100

// [OQ3, deliberately named] Whether an ABSENT confidence field rejects.
// False until the verified Lazer subscription is confirmed to always
// deliver the confidence property (the current signed test vectors omit
// it); flipping this to True is the fail-closed end-state.
pub const pyth_reject_absent_confidence: Bool = False

// [#381 V8.1 S3] One vault-mandate entry: a primary AegisSelf feed and its
// (optional) Pyth fallback. `fallback_feed_id` is the Lazer feed-id big-endian
// (must be a member of pyth_canonical_feed_ids — the S5 coupling invariant);
// #"" = no fallback, the pair is AegisSelf-only (iUSD relay, Surf events,
// USDM). The mandate list is a COMPILE-TIME vault param: entries are pinned
// at genesis and can never be edited without a vault-level migration.
/// [#403 FIX 1] THE SECOND, ONE-SIDED LEG the Underwrite gate feeds through
/// `min`.
///
/// `underwrite_baseline_ok` is MONOTONE NON-DECREASING in the resolved spot for
/// both classes — Depeg's only spot conjunct is `depeg_peg_is_healthy(spot)`
/// and Barrier's is `(spot - strike) * 10000 / spot >= min_strike_distance_bps`
/// — so the buyer ALWAYS wants the print high. Feed any additional leg through
/// `min` and his freedom to choose it is worth exactly zero: a lower number can
/// only ever refuse him, and a stale leg causes a false DENIAL, never a false
/// sale. That is what makes a BUYER-SUPPLIED pull attestation admissible here
/// when it is inadmissible as the strike-setting primary.
///
/// THE HONEST LIMIT, said out loud: `min` defends against selection among
/// sources AT ONE INSTANT. It does NOT defend against correlated staleness — if
/// the push leg is stale-high and the second leg is stale-high too, the
/// composite is stale-high. The freshness that protects the pool is still
/// carried by the PUSH leg's cadence.
pub type SecondLeg {
  /// No mandatory second leg: `min` degenerates to the primary print and the
  /// gate is exactly what it was. The reversible genesis posture for any pair
  /// whose second source is not yet provisioned.
  NoSecondLeg
  /// The SAME feed's key 3 `min_price_12h` — the publisher's own memory of the
  /// break the stale spot forgot. THE ASYMMETRY, STATED RATHER THAN HIDDEN: for
  /// USDM / DJED / iUSD, where Pyth has no Lazer feed and never will, this leg
  /// is NOT source-independent. It defends against staleness and against a
  /// break the spot forgot; it does NOT defend against a compromised or wrong
  /// AegisSelf publisher. That is a difference in assurance level within one
  /// security model, not a second security model — and it is unavoidable: the
  /// zero-staleness alternative, a DEX reference input, is refuted by depth
  /// (DJED/ADA carries ~$206K, so faking peg health by 1% costs ~$514 of
  /// temporarily committed flow against a ~490 ADA edge per policy).
  ///
  /// Costs the vault NOTHING to arm: the validator already reads keys 3/4 and
  /// its `low_observed_at >= observed_at - trailing_low_window_ms` bound is a
  /// CEILING, so a shorter publisher window also satisfies it. On the 3-KEY
  /// shape every live depeg feed actually publishes, parsers default
  /// `min_price_12h` to spot, so `min` collapses to the spot gate and this leg
  /// is INERT — which is the graceful degradation, not a defect.
  TrailingLowLeg
  /// A buyer-supplied Pyth Lazer pull attestation on `feed_id` — a genuinely
  /// independent source with its own signers (USDC / USDT / ADA). MANDATORY:
  /// an absent or stale leg REFUSES the sale rather than falling back to the
  /// primary alone, because a leg that can be omitted is not a leg.
  ///
  /// `require_confidence` is a CONJUNCT on this leg and never a closure: the
  /// buyer supplies the payload and therefore also supplies its confidence, so
  /// requiring it can only restrict him. It is per-mandate rather than the
  /// global `pyth_reject_absent_confidence` precisely because flipping that
  /// flag globally BRICKS real payloads — Lazer subscribers choose the
  /// `properties` list and every vendored signed fixture carries no confidence.
  PythPullLeg { feed_id: ByteArray, require_confidence: Bool }
}

// [#381 V8.1 S3] One vault-mandate entry: a primary AegisSelf feed and its
// (optional) Pyth fallback. `fallback_feed_id` is the Lazer feed-id big-endian
// (must be a member of pyth_canonical_feed_ids — the S5 coupling invariant);
// #"" = no fallback, the pair is AegisSelf-only (iUSD relay, Surf events,
// USDM).
pub type OracleMandate {
  primary_nft: ByteArray,
  fallback_feed_id: ByteArray,
  /// [#403 FIX 1] WHICH pairs carry which second leg is GOVERNED and therefore
  /// reversible; the `min` MECHANISM that consumes it is compile-time and is
  /// the one-way door. That split is the whole shape of the decision: the
  /// mechanism ships at genesis because it is cheap and irreversible-later,
  /// the Pyth leg is armed per-pair afterwards without a migration.
  second_leg: SecondLeg,
}

// [#403 FIX 1] The push-leg spot-age budget when an INDEPENDENT pull leg is
// present and valid in the same transaction. `min` is what makes this safe: a
// stale push print can no longer be the number the strike is measured against,
// because the fresh pull leg caps it — so a slow publisher stops DENYING sales
// without buying anyone hindsight. Deliberately NOT extended to
// `TrailingLowLeg`, which is the same publisher's own memory: if that print is
// stale its trailing low is stale too, and correlated staleness is exactly what
// `min` does not defend against.
pub const max_dual_leg_spot_age_ms: Int = 3_600_000

// [#381 V8.1 S3/OQ5] How long past the primary feed's published valid_until
// the ledger must certify silence before the Pyth leg opens. 30 min on both
// classes for genesis (fallback opens after ~100 min of publisher silence:
// the ~70-min publish window + this grace). Class-shaped so OQ5 can split
// them without an API change.
pub fn pyth_fallback_grace_ms(risk_class: RiskClass) -> Int {
  when risk_class is {
    Barrier -> 1_800_000
    Depeg -> 1_800_000
  }
}

// ---------------------------------------------------------------------------
// Per-network re-exports
//
// Switch to mainnet by changing the `use` line above to `aegis/types/mainnet`.
// That single edit is the only human-operator surface for network promotion;
// validator hashes rotate, making the change observable on chain.
// ---------------------------------------------------------------------------

pub const min_premium: Int = network.min_premium

/// [#363] Governance timelocks are per-network: preprod short (so the
/// ProposeUpdate -> EnactUpdate cycle can be proven on-chain in-session),
/// mainnet 72h / 24h. Network-scoped so proving the cycle never needs a
/// source edit (the #378-class footgun).
pub const registry_timelock_ms: Int = network.registry_timelock_ms

pub const cancel_cooldown_ms: Int = network.cancel_cooldown_ms

pub const charli3_oracle_script_hash: ByteArray =
  network.charli3_oracle_script_hash

pub const charli3_ada_usd_nft_policy: ByteArray =
  network.charli3_ada_usd_nft_policy

pub const orcfax_fsp_script_hash: ByteArray = network.orcfax_fsp_script_hash

pub const aegis_self_publisher_vkh: ByteArray = network.aegis_self_publisher_vkh

pub const aegis_self_canonical_nfts: List<ByteArray> =
  network.aegis_self_canonical_nfts

/// [#363 F5] Per-network drift guard for the allowlist above.
pub const canonical_nft_count: Int = network.canonical_nft_count

/// AegisSelf allowlist membership, as ONE function with ONE copy of the list.
///
/// [#424] Aiken inlines a constant at every use site and hoists a function used
/// more than once. Three readers of an eleven-entry allowlist therefore put
/// three copies of it in one script; pool_vault carried two and was 263 B past
/// the publishable ceiling on mainnet while preprod, with three entries, fit.
/// Routing every reader through here is worth 347 B of mainnet vault and costs
/// nothing: the predicate is unchanged, only the number of copies of it.
pub fn is_canonical_aegis_self_nft(oracle_nft: ByteArray) -> Bool {
  list.has(aegis_self_canonical_nfts, oracle_nft)
}

/// [V8.2] The ceremony identity role that owns each canonical slot, positional
/// with the allowlist. Read by `identity_census` / `v8_anchors` to bind a feed
/// role to ITS OWN policy id: a permutation of the trust roots keeps every role
/// distinct and every witness valid, and only the assignment is wrong.
pub const ceremony_role_by_slot: List<ByteArray> = network.ceremony_role_by_slot

/// [V8.2] Flat (role, `<PURPOSE>_<GENERATION>` asset name) pairs for every
/// ceremony identity role. One map for both halves: a second list for the
/// generation is the shape this map exists to refuse.
pub const ceremony_role_names: List<ByteArray> = network.ceremony_role_names

// [POOL-FUNDED REPRICE] Established-stablecoin feeds eligible for the Depeg
// premium floor. The Underwrite Depeg branch pins the policy's oracle_nft to
// this set so the cheap duration-only floor can't be applied to a price
// barrier (ADA/BTC/CDP) or an under-priced Cardano-native depeg.
pub const depeg_eligible_nfts: List<ByteArray> = network.depeg_eligible_nfts

// [Pyth Wave 1] Pyth State NFT policy id (the `pyth_id` argument to
// `pyth.get_updates`). The shared Pyth State UTxO carries a "Pyth State"
// token under this policy and is referenced (reference input) by every
// consuming tx. Pinned per-network so a Pyth-bound policy on mainnet cannot
// be satisfied by a preprod (or attacker) state UTxO.
pub const pyth_state_nft_policy: ByteArray = network.pyth_state_nft_policy

pub const pyth_canonical_feed_ids: List<ByteArray> =
  network.pyth_canonical_feed_ids

pub const pyth_fallback_feed_ids_by_slot: List<ByteArray> =
  network.pyth_fallback_feed_ids_by_slot

// [#381 V8.1 S5] The ACTIVE network's genesis mandate list — the SINGLE
// SOURCE the deploy ceremony bakes into pool_vault's oracle_mandates param
// and the parity tests pin. Zips the canonical primaries with the positional
// fallback map; list.map2 TRUNCATES on length mismatch, so the
// s5 length parity test is load-bearing against silent drift.
pub fn oracle_mandate_entries() -> List<OracleMandate> {
  list.map2(
    aegis_self_canonical_nfts,
    pyth_fallback_feed_ids_by_slot,
    // [#403 FIX 1] Genesis arms the KEYS-3/4 leg on every pair and the Pyth
    // pull leg on none — option D inside option C, which is exactly the
    // graceful degradation the mechanism was designed for. On the 3-key shape
    // the live publisher writes it is inert; the day the publisher arms keys
    // 3/4 it bites, with zero validator change and zero migration.
    fn(nft, fb) {
      OracleMandate {
        primary_nft: nft,
        fallback_feed_id: fb,
        second_leg: TrailingLowLeg,
      }
    },
  )
}

pub const team_address: Address = network.team_address

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test policy_datum_construction() {
  let datum = PolicyDatum {
    policy_id: #"aabb",
    insured: #"0011223344556677889900112233445566778899001122334455667788",
    strike_price: 350_000,
    coverage_amount: 5_000_000_000,
    premium_paid: 100_000_000,
    start_time: 1_700_000_000_000,
    expiry_time: 1_700_604_800_000,
    oracle_nft: #"886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e",
    pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
    pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
    oracle_provider: Charli3,
    partner_address: None,
    partner_share_bps: 0,
    risk_class: Barrier,
    payout_address: None,
    receipt_commitment: None,
    payout_datum: None,
    settlement_pins: None,
    extension: None,
  }
  datum.strike_price == 350_000 && datum.coverage_amount == 5_000_000_000
}

// Cross-stack wire pin: payout_address (14), receipt_commitment (15),
// payout_datum (16), settlement_pins (17) and [#390] extension (18) are the
// LAST five positional fields, serialised AFTER risk_class. This is the on-chain counterpart of the
// SDK `encodePolicyDatum` golden and the verified live-V4 lineage (dd56e6df
// ends `…00 d87980`, decoded as all trailing Options absent). Guards against
// re-introducing a field-order collision among the appended tail fields.
test policy_datum_v6_none_trailing_options_serialise_after_payout_address() {
  let datum = PolicyDatum {
    policy_id: #"aabb",
    insured: #"0011223344556677889900112233445566778899001122334455667788",
    strike_price: 350_000,
    coverage_amount: 5_000_000_000,
    premium_paid: 100_000_000,
    start_time: 1_700_000_000_000,
    expiry_time: 1_700_604_800_000,
    oracle_nft: #"886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e",
    pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
    pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
    oracle_provider: Charli3,
    partner_address: None,
    partner_share_bps: 0,
    risk_class: Barrier,
    payout_address: None,
    receipt_commitment: None,
    payout_datum: None,
    settlement_pins: None,
    extension: None,
  }
  let bytes = cbor.serialise(datum)
  let n = bytearray.length(bytes)
  // …, risk_class Barrier (d87980), payout_address None (d87a80),
  // receipt_commitment None (d87a80), payout_datum None (d87a80),
  // settlement_pins None (d87a80), [#390] extension None (d87a80), Constr
  // indefinite-array break (ff).
  bytearray.drop(bytes, n - 19) == #"d87980d87a80d87a80d87a80d87a80d87a80ff"
}

test policy_datum_v6_some_receipt_then_payout_datum_none() {
  let commitment = #"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
  let datum = PolicyDatum {
    policy_id: #"aabb",
    insured: #"0011223344556677889900112233445566778899001122334455667788",
    strike_price: 350_000,
    coverage_amount: 5_000_000_000,
    premium_paid: 100_000_000,
    start_time: 1_700_000_000_000,
    expiry_time: 1_700_604_800_000,
    oracle_nft: #"886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e",
    pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
    pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
    oracle_provider: Charli3,
    partner_address: None,
    partner_share_bps: 0,
    risk_class: Barrier,
    payout_address: None,
    receipt_commitment: Some(commitment),
    payout_datum: None,
    settlement_pins: None,
    extension: None,
  }
  let bytes = cbor.serialise(datum)
  let n = bytearray.length(bytes)
  // risk_class Barrier (d87980), payout_address None (d87a80), then
  // receipt Some(commitment) = d8799f 5820 <32B> ff, then payout_datum None
  // (d87a80), settlement_pins None (d87a80), then the outer Constr break (ff).
  // Expected tail = 11 + 32 + 1 (close Some) + 3 + 3 (trailing Nones) + 1
  // (outer break) = 51 bytes.
  bytearray.drop(bytes, n - 54) == bytearray.concat(
    #"d87980d87a80d8799f5820",
    bytearray.concat(commitment, #"ffd87a80d87a80d87a80ff"),
  )
}

// Wire pin: [#390] `extension` (index 18) is now the genuine LAST positional
// field, and `settlement_pins` (17) sits before it. The Agora `unit` case: payout_datum = Some(Void). Some(d) = d8799f
// <d> ff; Void = d87980; so Some(unit) = d8799f d87980 ff. With the other
// trailing Options None, the tail is risk_class Barrier (d87980),
// payout_address None (d87a80), receipt None (d87a80), payout_datum Some(unit)
// (d8799f d87980 ff), settlement_pins None (d87a80), extension None (d87a80),
// then the outer Constr break (ff). Off-chain builders MUST keep this field order.
test policy_datum_v6_some_payout_datum_unit_is_last_field() {
  let unit: Data = Void
  let datum = PolicyDatum {
    policy_id: #"aabb",
    insured: #"0011223344556677889900112233445566778899001122334455667788",
    strike_price: 350_000,
    coverage_amount: 5_000_000_000,
    premium_paid: 100_000_000,
    start_time: 1_700_000_000_000,
    expiry_time: 1_700_604_800_000,
    oracle_nft: #"886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e",
    pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
    pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
    oracle_provider: Charli3,
    partner_address: None,
    partner_share_bps: 0,
    risk_class: Barrier,
    payout_address: None,
    receipt_commitment: None,
    payout_datum: Some(unit),
    settlement_pins: None,
    extension: None,
  }
  let bytes = cbor.serialise(datum)
  let n = bytearray.length(bytes)
  bytearray.drop(bytes, n - 23) == #"d87980d87a80d87a80d8799fd87980ffd87a80d87a80ff"
}

test pool_datum_construction() {
  let datum = PoolDatum {
    total_liquidity: 100_000_000_000,
    active_coverage: 20_000_000_000,
    lp_token_policy: #"aabb",
    protocol_fee_bps: 200,
    pool_nft: #"ccdd",
    lp_supply: 100_000_000_000,
    reserve: 0,
  }
  datum.total_liquidity == 100_000_000_000 && datum.protocol_fee_bps == 200 && datum.reserve == 0
}

// Wire pin: `reserve` (index 6) is the LAST positional field of PoolDatum,
// serialised AFTER lp_supply. A fresh P1 pool is 7-field; off-chain pool-datum
// builders MUST append reserve last to stay byte-compatible with this layout.
test pool_datum_reserve_serialises_last() {
  let datum = PoolDatum {
    total_liquidity: 100_000_000_000,
    active_coverage: 20_000_000_000,
    lp_token_policy: #"aabb",
    protocol_fee_bps: 200,
    pool_nft: #"ccdd",
    lp_supply: 100_000_000_000,
    reserve: 7_000_000,
  }
  let bytes = cbor.serialise(datum)
  let n = bytearray.length(bytes)
  // … lp_supply, then reserve = 7_000_000 = 0x6ACFC0 -> 1a006acfc0, then the
  // outer Constr indefinite-array break (ff).
  bytearray.drop(bytes, n - 6) == #"1a006acfc0ff"
}

// [#403 FIX 2] THE THREE WINDOWS, PINNED IN THE RELATION THEY SIT IN.
//
// Declared as a theorem rather than witnessed by a transaction, and this is
// why: once `settlement_price_and_age_ok` bounds EVERY provider by its class
// budget, the ordinary Pyth window is dominated everywhere it is reached, so
// no transaction can distinguish it — reverting it to 70 minutes leaves the
// whole suite green. It is defence in depth, not the binding leg, and saying
// so here is the honest form. What this test does forbid is the relation
// silently inverting: an ordinary window BELOW a class budget would make the
// reading expire before the budget it is supposed to sit under, which is a
// liveness break rather than a safety one, and a replay window at or under the
// ordinary one would collapse the split FROZEN DECISION 4's amendment bought.
test pyth_ordinary_window_is_never_the_binding_settlement_leg() {
  and {
    max_spot_age_ms(Barrier) <= pyth_ordinary_window_ms,
    max_spot_age_ms(Depeg) <= pyth_ordinary_window_ms,
    pyth_ordinary_window_ms < pyth_replay_window_ms,
  }
}

test spot_age_split_is_ordered_and_bounded() {
  // [#363 R4] The per-class split must not be silently collapsed back to one
  // shared constant, and neither budget may exceed the span ceiling (past that,
  // the composition `now < tx_upper <= observed_at + budget` stops bounding
  // staleness at inclusion). Depeg is strictly tighter because its margin is
  // min_depeg_distance_bps = 200 against Barrier's min_strike_distance_bps =
  // 1500 — a shared budget under-protects Depeg by 7.5x.
  and {
    max_spot_age_ms(Depeg) < max_spot_age_ms(Barrier),
    max_spot_age_ms(Barrier) <= max_underwrite_span_ms,
    max_spot_age_ms(Depeg) > 0,
  }
}

test waiting_period_outruns_the_hindsight_it_neutralises() {
  // [#391 F1] The property the two numbers exist to have. A waiting period at
  // or under the class's own spot-age budget leaves the buy-stale/claim-next-
  // block cycle intact, because the print that priced the strike is still
  // inside the window when the claim lands.
  and {
    claim_waiting_period_ms(Barrier) > max_spot_age_ms(Barrier),
    claim_waiting_period_ms(Depeg) > max_spot_age_ms(Depeg),
    // neither may eat a whole minimum-length policy
    claim_waiting_period_ms(Depeg) < min_policy_term_ms,
    claim_waiting_period_ms(Barrier) < min_policy_term_ms,
  }
}

test waiting_period_is_six_budgets_or_more() {
  // [#391 R2 F2b] STRICTLY MORE than "outruns": the multiple must not shrink as
  // the hindsight budget grows. Barrier carried the LARGER budget (600_000 vs
  // 300_000) and the SHORTER wait (1_800_000 vs 3_600_000) — twice the
  // hindsight for half the delay, on the flagship product. Pinning the ratio
  // rather than the ordering is what makes a future budget change safe: raise
  // `max_spot_age_ms` for a class and this test demands the wait follow.
  and {
    claim_waiting_period_ms(Barrier) >= 6 * max_spot_age_ms(Barrier),
    claim_waiting_period_ms(Depeg) >= 6 * max_spot_age_ms(Depeg),
  }
}

test cancel_window_closes_before_any_policy_can_claim() {
  // [#391 R2 F2c] The cancel escape. While `cancellation_window >=
  // claim_waiting_period_ms`, a buyer could still be inside the refund window
  // when the claim window opened — so a hindsight bet that LOST was handed 90%
  // of its premium back. Strictly less, for BOTH classes, is the property; the
  // constant is half the shortest wait so an honest buyer keeps a real window.
  and {
    cancellation_window < claim_waiting_period_ms(Barrier),
    cancellation_window < claim_waiting_period_ms(Depeg),
    cancellation_window > 0,
  }
}

test max_term_within_floor_table_domain() {
  // [#363 N4] floor_table.t_band_index saturates at band 6 = 180 days, so any
  // longer term is priced AS IF it were 180d — structural under-pricing that
  // needs no governance compromise. The vault's duration ceiling must never
  // exceed the domain the premium floor can actually price. Raise this ONLY
  // together with new bands past 180d.
  max_policy_term_ms <= 180 * 86_400_000
}

test depeg_feeds_are_canonical() {
  // [#363 N2] Depeg Underwrite resolves its pinned feed via attested_price,
  // which gates on aegis_self_canonical_nfts. Every depeg-eligible feed must
  // therefore BE canonical, or Depeg cover silently becomes unbuyable on that
  // network. Mainnet already satisfied this; preprod had drifted. Pinning the
  // invariant here stops it drifting again on either network.
  list.all(
    depeg_eligible_nfts,
    fn(n) { list.has(aegis_self_canonical_nfts, n) },
  )
}

test constants_are_reasonable() {
  // [#363 F5] `min_premium` is per-network (preprod 2 ADA / mainnet 20 ADA), so
  // pinning its VALUE here made the test unpassable on one profile. The
  // cross-network constants keep their exact pins; min_premium gets the bound
  // that is actually load-bearing — a premium must be at least
  // min_utxo_lovelace or its payment cannot form a valid output at all.
  // Preprod sits exactly AT that floor (2 ADA); mainnet is 10x it.
  min_premium >= min_utxo_lovelace && max_coverage_ratio == 50 && cancellation_window == 1_800_000 && cancellation_fee_bps == 1_000
}

test orcfax_freshness_window_widened_for_v7() {
  orcfax_freshness_window_ms == 4_200_000 && orcfax_freshness_window_ms > 65 * 60 * 1_000
}

test aegis_self_publisher_vkh_is_well_formed() {
  // [#363 F5] The value pin here was the OLD preprod publisher VKH
  // (6096332c…), retired when the profile was re-parameterized to the operator
  // key — so this test could never pass on the active module. A per-network
  // VALUE assertion is inexpressible in a test that must be green under BOTH
  // modules (it degenerates to `x == x`); the real value guard is the #361
  // deploy-time network-flip fingerprint, which compares compiled validators
  // against AEGIS_NETWORK. Keep the structural check here.
  bytearray.length(aegis_self_publisher_vkh) == 28 && aegis_self_publisher_vkh != #""
}

test policy_datum_aegis_self_variant_constructs() {
  let datum = PolicyDatum {
    policy_id: #"aabb",
    insured: #"0011223344556677889900112233445566778899001122334455667788",
    strike_price: 1_000_000,
    coverage_amount: 10_000_000_000,
    premium_paid: 100_000_000,
    start_time: 1_700_000_000_000,
    expiry_time: 1_700_604_800_000,
    oracle_nft: #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
    pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
    pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
    oracle_provider: AegisSelf,
    partner_address: None,
    partner_share_bps: 0,
    risk_class: Barrier,
    payout_address: None,
    receipt_commitment: None,
    payout_datum: None,
    settlement_pins: None,
    extension: None,
  }
  let is_aegis_self = when datum.oracle_provider is {
    AegisSelf -> True
    _ -> False
  }
  datum.strike_price == 1_000_000 && is_aegis_self
}

// [#363 F5] The five per-feed membership pins were hardcoded to the OLD preprod
// inventory (d2f08410 ADA / ae304e27 BTC / d80aa1a7 ETH), all retired by the V8B
// publisher re-parameterization — so they could not pass on preprod, and were
// never true on mainnet either. A drift guard that cannot pass on ANY live
// profile is worse than none: it normalizes a red bar, and a red bar is exactly
// what let an incomplete Underwrite fix ship under "zero new failures".
// Replaced with invariants that must hold under EVERY network module; the
// per-network inventory pin now lives in `canonical_nft_count`, declared beside
// the list it guards so a conscious edit is still forced.
test allowlist_is_structurally_sound() {
  let n = list.length(aegis_self_canonical_nfts)
  and {
    n > 0,
    // duplicates would silently weaken the count pin
    list.length(list.unique(aegis_self_canonical_nfts)) == n,
    // every entry is a 28-byte policy id
    list.all(aegis_self_canonical_nfts, fn(x) { bytearray.length(x) == 28 }),
  }
}

test allowlist_primary_feed_is_well_formed() {
  // The FIRST entry is the profile's primary AegisSelf feed; the shared test
  // fixtures derive from it (fixtures.aegis_self_ada_nft), so this pins the
  // derivation the whole suite depends on.
  expect [primary, ..] = aegis_self_canonical_nfts
  bytearray.length(primary) == 28
}

test allowlist_rejects_non_canonical_nft() {
  !list.has(
    aegis_self_canonical_nfts,
    #"00112233445566778899001122334455667788990011223344556677",
  )
}

test allowlist_rejects_empty_nft() {
  !list.has(aegis_self_canonical_nfts, #"")
}

// Drift guard: any allowlist change must consciously edit this pin.
// Preprod = 9 (5 spot + 4 Surf event slots); mainnet = 10 (5 spot + iUSD
// relay + 4 Surf event slots). Discriminated on the profile's publisher
// VKH so the same test is correct under either shim.
test allowlist_size_pinned_per_profile() {
  // [#363 F5] Was branching on a hardcoded publisher VKH (6096332c…) that had
  // drifted, so preprod silently fell to the mainnet arm and asserted n == 11
  // against a real length of 3 — unpassable on either profile. The expected
  // count now lives in the network module BESIDE the list it guards, so the
  // drift guard still forces a conscious edit but is correct under both.
  list.length(aegis_self_canonical_nfts) == canonical_nft_count
}

// [V8.2] The role map is positional with the allowlist, so a slot appended to
// one and not the other silently shifts every role below it onto a feed it does
// not name. list.map2 would truncate; this refuses.
test ceremony_role_by_slot_is_positional_with_the_allowlist() {
  list.length(ceremony_role_by_slot) == canonical_nft_count
}

// Flat (role, asset name) pairs: an odd length pairs a role with the next role's
// name all the way down, and every named role must own a slot or be one of the
// two one-shots that own none.
test ceremony_role_names_are_well_formed_pairs() {
  let n = list.length(ceremony_role_names)
  and {
    n > 0,
    n % 2 == 0,
    !list.has(ceremony_role_names, #""),
    list.length(list.unique(ceremony_role_names)) == n,
  }
}

// Every role that owns a canonical slot must also declare the asset name it has
// to carry, or the policy half is bound and the name half is not.
test every_slot_role_declares_a_name() {
  list.all(
    list.filter(ceremony_role_by_slot, fn(r) { r != #"" }),
    fn(role) { list.has(ceremony_role_names, role) },
  )
}

test team_address_payment_credential_28_bytes() {
  when team_address.payment_credential is {
    PaymentVKCred(h) -> bytearray.length(h) == 28
    _ -> False
  }
}

test team_address_has_stake_credential() {
  team_address.stake_credential != None
}

test partner_share_cap_bps_is_2000() {
  partner_share_cap_bps == 2_000
}

test policy_datum_v12_no_partner() {
  let datum = PolicyDatum {
    policy_id: #"aabb",
    insured: #"0011223344556677889900112233445566778899001122334455667788",
    strike_price: 350_000,
    coverage_amount: 5_000_000_000,
    premium_paid: 100_000_000,
    start_time: 1_700_000_000_000,
    expiry_time: 1_700_604_800_000,
    oracle_nft: #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
    pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
    pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
    oracle_provider: AegisSelf,
    partner_address: None,
    partner_share_bps: 0,
    risk_class: Barrier,
    payout_address: None,
    receipt_commitment: None,
    payout_datum: None,
    settlement_pins: None,
    extension: None,
  }
  datum.partner_share_bps == 0 && datum.partner_address == None
}

test policy_datum_v12_with_partner() {
  let datum = PolicyDatum {
    policy_id: #"aabb",
    insured: #"0011223344556677889900112233445566778899001122334455667788",
    strike_price: 350_000,
    coverage_amount: 5_000_000_000,
    premium_paid: 100_000_000,
    start_time: 1_700_000_000_000,
    expiry_time: 1_700_604_800_000,
    oracle_nft: #"d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f",
    pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
    pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
    oracle_provider: AegisSelf,
    partner_address: Some(team_address),
    partner_share_bps: 2_000,
    risk_class: Barrier,
    payout_address: None,
    receipt_commitment: None,
    payout_datum: None,
    settlement_pins: None,
    extension: None,
  }
  datum.partner_share_bps == 2_000
}

// [#316] The Indigo RESOLVER is retired but its CONSTRUCTOR stays, and this is
// what it buys: `oracle_provider` is encoded by constructor INDEX, so dropping
// `Indigo` would renumber `Pyth` from 4 to 3 — silently re-interpreting every
// deployed policy and every off-chain codec that decodes by index. A legacy
// Indigo-tagged datum must still decode; it simply can no longer be minted or
// settled.
test policy_datum_indigo_variant_still_decodes() {
  let datum = PolicyDatum {
    policy_id: #"aabb",
    insured: #"0011223344556677889900112233445566778899001122334455667788",
    strike_price: 1_000_000,
    coverage_amount: 10_000_000_000,
    premium_paid: 100_000_000,
    start_time: 1_700_000_000_000,
    expiry_time: 1_700_604_800_000,
    oracle_nft: #"b5b0ea68368eea547c79042a92a3779564e4987b4709d73b2e7e1ea5",
    pool_script_hash: #"aabbccdd11223344556677889900112233445566778899001122334455",
    pool_nft: #"deadbeef00112233445566778899aabbccddeeff00112233445566",
    oracle_provider: Indigo,
    partner_address: None,
    partner_share_bps: 0,
    risk_class: Barrier,
    payout_address: None,
    receipt_commitment: None,
    payout_datum: None,
    settlement_pins: None,
    extension: None,
  }
  let is_indigo = when datum.oracle_provider is {
    Indigo -> True
    _ -> False
  }
  datum.strike_price == 1_000_000 && is_indigo
}

// [V8.2 H1] The Pyth analogue, and the pin the vault's Underwrite provider
// predicate is defence-in-depth for. `is_canonical_oracle_nft(Pyth, …)` reads a
// 1-byte Lazer FEED-ID where AegisSelf and Indigo read a 28-byte policy id
// (Charli3 and Orcfax fail closed and read no handle at all), so
// no handle can currently be canonical for Pyth AND sit among the mandate
// primaries or the AegisSelf allowlist. That accident is the ONLY reason a
// missing provider predicate was survivable: the moment a feed-id also names a
// mandate primary, `in_mandate`, `canonical_feed` and `underwrite_baseline_ok`
// all hold at once for provider=Pyth, and a PULL oracle whose price the buyer
// supplies decides the strike distance. Nothing asserted the disjointness, so a
// widening of `pyth_canonical_feed_ids` could silently rejoin the two spaces.
test pyth_feed_ids_disjoint_from_nft_allowlists() {
  let primaries = list.map(oracle_mandate_entries(), fn(m) { m.primary_nft })
  list.all(
    pyth_canonical_feed_ids,
    fn(id) {
      !list.has(primaries, id) && !list.has(aegis_self_canonical_nfts, id)
    },
  )
}

// Structural guards that hold across every legitimate allowlist size: all
// entries are 28-byte policy ids and the Surf event slots are present on
// the active profile (preprod slot 5 / mainnet slot 6 = SURF1).
test aegis_self_canonical_nfts_all_entries_28_bytes() {
  list.all(aegis_self_canonical_nfts, fn(n) { bytearray.length(n) == 28 })
}
// [#363 F5] `allowlist_accepts_surf_event_slot_1` removed: it branched on the
// same drifted publisher VKH (6096332c…), so preprod fell to the mainnet arm
// and asserted a mainnet-only Surf NFT against the preprod list. The allowlist
// is now guarded by `allowlist_is_structurally_sound` +
// `allowlist_size_pinned_per_profile` (per-network count), which catch a
// dropped or added slot on EITHER profile without pinning per-feed literals
// that go stale at every ceremony.
