use aegis/eligibility.{EligibilityClaim, PolicyTerms}
use aegis/oracle.{attested_price, attested_price_opt, is_canonical_oracle_nft}
use aegis/oracle/aegis_self
use aegis/oracle/fallback
use aegis/oracle/types as oracle_types
use aegis/policy_datum.{decode_policy_datum}
use aegis/pricing.{calculate_refund}
use aegis/registry.{Admin}
use aegis/registry_v2.{
  Budgets, Fee, Floors, RegistryDatum, SettlementPins, UnderwriteConfig,
  config_within_rails, fee_sink_not_vault, provider_tag,
}
use aegis/test_helpers/fixtures
use aegis/test_helpers/pyth_fixtures
use aegis/types.{
  AegisSelf, Barrier, Depeg, NoSecondLeg, OracleMandate, PolicyDatum, Pyth,
  PythPullLeg, SecondLeg, TrailingLowLeg, aegis_self_canonical_nfts,
  cancellation_window, claim_waiting_period_ms, depeg_eligible_nfts,
  max_dual_leg_spot_age_ms, max_policy_term_ms, max_spot_age_ms,
  min_policy_term_ms, min_premium, min_utxo_lovelace,
  policy_marker_asset_name,
}
use aiken/math
use aegis/validation.{
  get_lower_bound, get_upper_bound, sum_lovelace_to_address,
  sum_lovelace_to_address_with_inline_datum, sum_lovelace_to_enterprise_pkh,
}
use aegis/vault.{
  AcceptCancellation, AddLiquidity, Claim, DepositRevenue,
  Expire, RemoveLiquidity, Underwrite, Vault, VaultRedeemer, VaultState,
  add_liquidity_ok, barrier_touched, cancel_ok, claim_ok, claim_trigger_ok,
  deposit_revenue_ok, derive_backing, expire_ok, payout_not_aliased,
  policy_fallback_feed_id, policy_waiting_period_ms, pre_start_breach,
  reading_fresh, remove_liquidity_ok,
  terms_match_datum, underwrite_baseline_ok, underwrite_ok,
  waiting_period_pin_ok,
}
use aiken/collection/list
use aiken/collection/pairs
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, Withdraw,
}

// =============================================================================
// Aegis V8 — Immutable Pool Vault (#362 §2.1)
// Location: contracts/validators/pool_vault.ak
//
// The custody heart of the stable-vault: holds ALL LP value + the one-shot pool
// NFT and owns EVERY lovelace-moving decision itself. This hash is FROZEN — the
// address is the pool forever, so LPs NEVER migrate on a coverage-logic upgrade
// (that is a registry beacon flip, not a fund move).
//
// Self-custody, structurally: funds at this script; aLP in the LP's wallet is
// the only claim; RemoveLiquidity is an ATOMIC permissionless burn-for-payout
// (no forgeable exit-intent surface — see v8-coverage-redteam CRITICAL-6). No
// admin, no governance, and no swappable logic can move principal, mint aLP,
// redirect a payout, or block an exit — there is NO pause arm, by design.
//
// The money math of every arm lives in lib/aegis/vault.ak as pure predicates
// (unit-tested + mutation-verified against value-skim / wrong-mint / over-drain
// / coverage-inflation). This validator adds the STRUCTURAL continuity: NFT
// singleton, one continuation output, exact non-lovelace value preservation,
// and the registry pin.
//
// STATUS: LP-CUSTODY arms COMPLETE (AddLiquidity / RemoveLiquidity /
// DepositRevenue). Underwrite WIRED + red-teamed SHIP. Claim WIRED (red-team
// pending) — vault self-resolves spot via baked anchors + mandate, binds
// logic-redeemer == policy-pinned == vault-resolved terms, marker locality,
// payout non-aliasing, reserve-first draw, freshness, version-independent
// trigger. AcceptCancellation / Expire WIRED. Batch underwriting has no
// redeemer arm: batching is an off-chain concern until a batch arm passes the
// full-coverage re-red-team + preprod adversarial DoD.
// =============================================================================

validator pool_vault(
  pool_nft_policy: ByteArray,
  pool_nft_name: ByteArray,
  lp_token_policy: ByteArray,
  // [V8.2 Invariant S] the custody roots — the script every policy UTxO lives
  // at and the minting policy of its marker. CORE, because settlement must
  // resolve a policy it already sold with no registry read at all: were these
  // read from governed data, a hostile or bricked registry would reach
  // SETTLEMENT, not just new business (V82-IMMUTABLE-CORE §2).
  policy_hash: ByteArray,
  marker_policy: ByteArray,
  // [V8.2 G5] `oracle_mandates` IS GONE. It was settlement-only — one lookup in
  // `fallback.settle_price`, returning a Pyth fallback feed-id that
  // `SettlementPins` already carries per policy — and on mainnet its eleven
  // canonical slots cost a measured 38 B each of applied script, which is the
  // whole of the 294 B by which the vault overran the largest script a publish
  // transaction can carry. Settlement reads the POLICY'S pin now, and Underwrite
  // binds that pin equal to the governed mandate's fallback for the policy's own
  // `oracle_nft` (`fallback_pin_ok`) — so the authority behind the feed-id is
  // the same governed mandate it always was, at the one moment a registry read
  // is admissible. Invariant S is untouched: settlement still takes no registry
  // input.
  //
  // `observer_script_hash` is NOT on the way out, and reading it from the
  // registry was the G10 red-team's CRITICAL. `attested_price` reads the Price
  // out of the redeemer of `Script(h)`, so 100% of a reading's genuineness is
  // the IDENTITY of `h`: taking that identity from governed data made the
  // Underwrite spot buyer-authored while settlement resolved the real one. ALL
  // THREE arms resolve this parameter, and Underwrite additionally binds
  // `config.observer_hash` equal to it, so the governed field means the compiled
  // leaf rather than being ignored. Where the leaf lives is design slice G4's to
  // decide (a policy pin), not governance's.
  //
  // It survives here because Claim and AcceptCancellation consult it and
  // settlement takes no registry input (Invariant S), so the value can only
  // leave via the POLICY pins each policy carries — design slice G4 (the final
  // SettlementPins shape, a one-way door once one V8.2 policy exists). Until
  // then the parameter list closes at EIGHT.
  observer_script_hash: ByteArray,
  // The registry NFT that names the config authority. The vault trusts the
  // NFT, never an address and never a hash of the registry validator.
  registry_nft_policy: ByteArray,
  registry_nft_name: ByteArray,
) {
  spend(
    datum_opt: Option<VaultState>,
    redeemer: VaultRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(state) = datum_opt
    expect Vault { reserve, registry_nft, .. } = state
    let  
        Transaction {
          inputs,
          outputs,
          mint,
          reference_inputs,
          withdrawals,
          redeemers,
          validity_range,
          extra_signatories,
          ..
        }
      = self

    expect Some(self_input) = list.find(
      inputs,
      fn(i) { i.output_reference == own_ref },
    )
    let own_addr = self_input.output.address
    let own_value = self_input.output.value

    let alp_minted = assets.quantity_of(mint, lp_token_policy, "aLP")
    // Default-deny mint discipline for the LP arms: the ONLY policy that may
    // mint in an AddLiquidity/RemoveLiquidity/DepositRevenue tx is the aLP
    // policy. Because the pool NFT lives in the vault, policy_marker's
    // `pool_is_consumed` is TRUE on every vault spend — without this an attacker
    // could co-mint a marker during a permissionless AddLiquidity and pre-park
    // it on a synthetic policy (inert while the burn arms fail-closed, but a
    // landmine for the Claim arm). Pinning it here closes that window now.
    let only_lp_minted = list.all(
      assets.policies(mint),
      fn(p) { p == lp_token_policy },
    )

    // Singleton continuity: EXACTLY one output at this address with the NFT.
    expect [cont] = list.filter(
      outputs,
      fn(o) {
        o.address == own_addr && assets.quantity_of(
          o.value,
          pool_nft_policy,
          pool_nft_name,
        ) == 1
      },
    )
    expect InlineDatum(raw_new) = cont.datum
    expect new_state: VaultState = raw_new
    expect Vault { registry_nft: n_reg, .. } = new_state

    let own_lovelace = assets.lovelace_of(own_value)
    let cont_lovelace = assets.lovelace_of(cont.value)
    let backing = derive_backing(own_lovelace, min_utxo_lovelace, reserve)

    // Structural discipline every arm shares (base_ok is in EVERY arm's
    // conjunction): all non-lovelace assets on the continuation exactly preserved
    // (the NFT stays; no token injection/exfil), the immutable registry pointer,
    // AND — critically — aLP may ONLY be minted/burned by AddLiquidity /
    // RemoveLiquidity. Every other arm (Deposit/Underwrite/Claim + the
    // fail-closed Batch/Cancel/Expire) must have alp_minted == 0. This lives in
    // base_ok on purpose: the red-team caught a free-aLP-mint drain in BOTH the
    // Underwrite and Claim arms because the guard was easy to forget per-arm;
    // structurally enforcing it here makes it impossible to omit again.
    let base_ok = and {
      assets.without_lovelace(cont.value) == assets.without_lovelace(own_value),
      n_reg == registry_nft,
      vault.alp_mint_allowed(redeemer, alp_minted),
    }

    // The vault's own script hash — a spend validator only runs for a UTxO at
    // its own script address, so the payment credential is always a Script.
    expect Script(vault_hash) = own_addr.payment_credential
    // The policy custody credential, shared by every arm that locates a
    // policy UTxO at the CORE root.
    let policy_cred = Script(policy_hash)

    when redeemer is {
      AddLiquidity { amount } -> and {
          base_ok,
          only_lp_minted,
          add_liquidity_ok(
            state,
            new_state,
            amount,
            backing,
            own_lovelace,
            cont_lovelace,
            alp_minted,
          ),
        }

      RemoveLiquidity { shares } -> {
        // The exiter is paid to a NON-ALIASED address — never the vault
        // continuation address (a payout to own_addr would let the vault's own
        // output satisfy the payment, the §2.6 pool-alias drain). Judged by
        // PAYMENT credential, not full address: an output at Script(vault_hash)
        // under any foreign stake key is unspendable forever (spending it
        // demands a pool-NFT continuation at the alias address), so counting
        // its lovelace as "paid" would let an exit burn aLP against value that
        // never left the vault's credential (V82-CONFIG-OFF-HASH §8).
        let payout_outs =
          list.filter(
            outputs,
            fn(o) { o.address.payment_credential != own_addr.payment_credential },
          )
        // sum lovelace to all non-vault outputs; the exiter's wallet is among
        // them. remove_liquidity_ok requires paid >= payout, and no value may
        // sit at own_addr beyond the continuation (single-cont already pinned).
        let paid = list.foldl(
          payout_outs,
          0,
          fn(o, acc) { acc + assets.lovelace_of(o.value) },
        )
        and {
          base_ok,
          only_lp_minted,
          remove_liquidity_ok(
            state,
            new_state,
            shares,
            backing,
            own_lovelace,
            cont_lovelace,
            alp_minted,
            paid,
          ),
        }
      }

      DepositRevenue { amount } -> and {
          base_ok,
          only_lp_minted,
          deposit_revenue_ok(
            state,
            new_state,
            amount,
            own_lovelace,
            cont_lovelace,
            alp_minted,
          ),
        }

      // ---- Underwrite: reserve coverage for one new policy ----
      // The vault SELF-RESOLVES the spot through its CORE `observer_script_hash`
      // parameter, enforces its baked security baseline over that spot, BINDS
      // the swappable logic's redeemer to the pinned policy terms, and does the
      // accounting.
      //
      // The bound that buys: a hostile enacted logic can at worst under-price
      // (72h-timelock bounded), never move principal, inflate coverage, or lie
      // about the spot. It holds for a hostile CONFIG too — but only because the
      // resolver leaf is CORE. While the leaf came out of the registry datum,
      // bounded by nothing but a 28-byte width check, "lie about the spot" was
      // exactly what an in-rails config could do, and this comment asserted a
      // protection the code did not implement. The G10 red-team's CRITICAL.
      //
      // What a hostile config can still reach is bounded by `config_within_rails`
      // at the point of use. [V8.2 G5] The mandate split that used to live here
      // — Underwrite reading `cfg.mandates` while `fallback.settle_price` read a
      // compiled `oracle_mandates` — is closed: there is one mandate list, the
      // governed one, and `fallback_pin_ok` copies its fallback into the policy
      // so settlement can resolve the leg without ever reading the registry.
      //
      // Single policy per Underwrite; the governed fee take routes to
      // `cfg.fee.team_address` and the net premium grows the pool. See
      // COVERAGE-ARM-SPEC.
      Underwrite { coverage, premium } -> {
        // 1. Registry reference input: located by the vault-baked NFT policy +
        //    name AND the datum's registry_nft pin (M6). Underwrite is the ONLY
        //    arm that reads it (Invariant S). It takes the swappable actuarial
        //    logic AND the GOVERNED config — the custody roots stay CORE.
        expect Some(reg_in) = list.find(
          reference_inputs,
          fn(i) {
            assets.quantity_of(
              i.output.value,
              registry_nft_policy,
              registry_nft_name,
            ) == 1
          },
        )
        expect InlineDatum(raw_reg) = reg_in.output.datum
        expect reg: RegistryDatum = raw_reg
        let logic_hash = reg.logic_hash
        let cfg = reg.config
        let budgets = cfg.budgets
        let registry_bound = and {
          registry_nft_policy == registry_nft,
          // The registry may not be CO-LOCATED at the vault: an NFT-bearing
          // UTxO at this address would be authenticated like any other while
          // its lovelace counted as pool backing.
          reg_in.output.address.payment_credential != Script(vault_hash),
        }

        // 1b. The rails, AT THE POINT OF USE. The registry UTxO is created by
        //     an unvalidated payment — no script runs when a UTxO is CREATED —
        //     so the epoch-0 config has passed `config_within_rails` exactly
        //     never, and `registry_v2` re-checks only what a transition writes.
        //     An `epoch >= 1` ratchet is no substitute: §3 rules that the vault
        //     trusts the NFT and never an address or a hash of the registry
        //     validator, so a hand-written UTxO carrying the NFT, epoch 5 and a
        //     hostile config is indistinguishable from an enacted one.
        //     `fee_sink_not_vault` lands here rather than in the registry
        //     because the registry takes the NFT policy and name and must never
        //     learn this hash — that back-edge makes the two scripts' hashes
        //     mutually dependent.
        //     The resolver leaf is the second conjunct the registry structurally
        //     cannot carry, for the same reason as the fee sink: it is a fact
        //     about a hash `registry_v2` must never learn. It is bound EQUAL to
        //     the CORE parameter, not merely width-checked, because settlement
        //     resolves the compiled leaf and takes no registry input — a config
        //     naming any other 28 bytes would mint policies against a resolver
        //     Claim and AcceptCancellation cannot honour. Failing that CLOSED at
        //     the point of use is what stops such a policy existing at all, and
        //     it is the one line G4 later widens to the policy-pinned form.
        let fee = cfg.fee
        let config_bound = and {
          config_within_rails(cfg),
          fee_sink_not_vault(fee, vault_hash),
          cfg.observer_hash == observer_script_hash,
        }

        // 2. The new policy output at Script(policy_hash) holding exactly 1
        //    marker, with an inline PolicyDatum.
        expect Some(pol_out) = list.find(
          outputs,
          fn(o) {
            o.address.payment_credential == policy_cred && o.address.stake_credential == None && assets.quantity_of(
              o.value,
              marker_policy,
              policy_marker_asset_name,
            ) == 1
          },
        )
        expect InlineDatum(raw_pd) = pol_out.datum
        let pd = decode_policy_datum(raw_pd)
        let policy_lovelace = assets.lovelace_of(pol_out.value)

        // 3. The pinned datum binds to THIS pool + THIS underwrite.
        let pd_bound = and {
          pd.pool_nft == pool_nft_policy,
          pd.coverage_amount == coverage,
          pd.premium_paid == premium,
        }

        // 4. VAULT resolves the spot via the GOVERNED resolver + freshness
        //    (Barrier only); Depeg carries no spot.
        // [#403 FIX 1] The mandate ENTRY, not merely its presence — the second
        // leg travels on it. `list.find` rather than `expect Some(..)`: an
        // unmandated feed must make the arm return False, and an abort here
        // would be a different failure mode for the same refusal.
        let mandate_entry = list.find(
          cfg.mandates,
          fn(m) { m.primary_nft == pd.oracle_nft },
        )
        let (in_mandate, second_leg, mandate_fallback) = when mandate_entry is {
          Some(m) -> (True, m.second_leg, m.fallback_feed_id)
          None -> (False, NoSecondLeg, #"")
        }
        // [V8.2 G5] THE SETTLEMENT-FALLBACK PIN. Claim and AcceptCancellation
        // resolve the Pyth outage leg against `pd.settlement_pins`'s
        // `fallback_feed_id` and take no registry input, so this is the only
        // moment the governed mandate can reach that value. The BUYER authors
        // the datum: `is_canonical_oracle_nft(Pyth, ..)` at settlement proves
        // the pin is A canonical Lazer feed and never that it is the feed for
        // THIS policy's underlying, so an ADA policy pinning BTC's id settled
        // against the wrong instrument — the `cover_escrow` provider-pin defect
        // (a permissionless path must pin EVERY claim-load-bearing field).
        // EQUALITY, not membership: `SettlementPins` are the governed values
        // COPIED into the policy, and a partial copy is not a copy. `#""` is
        // the no-fallback value on both sides, so a mandate arming no second
        // leg admits exactly a policy with no pins tail.
        let fallback_pin_ok = policy_fallback_feed_id(pd) == mandate_fallback
        let in_depeg = list.has(cfg.depeg_eligible, pd.oracle_nft)
        // provider<->nft canonical pairing (basis-risk / mislabel guard, V7 parity)
        let canonical_feed = is_canonical_oracle_nft(
          pd.oracle_provider,
          pd.oracle_nft,
        )
        // [V8.2 H1] ...and the PROVIDER itself, explicitly. Pyth Lazer is a PULL
        // oracle: `pyth.get_updates` reads its signed payload out of a
        // withdrawal REDEEMER the transaction builder supplies. At Underwrite
        // the BUYER builds the transaction, so a Pyth-provider policy hands the
        // buyer the spot `underwrite_baseline_ok` measures strike distance
        // against — and here the buyer wants that print HIGH, which dresses a
        // near-money barrier up as a 15%-out-of-the-money one. AegisSelf
        // resolves from a reference input pinned to the publisher's payment
        // credential, which the buyer cannot author. Pyth stays reachable at
        // Claim/Cancel through settle_price's outage leg, where the builder
        // wants the print LOW to trip a Barrier at Claim and HIGH to prove OTM
        // at Cancel (otm_ok needs !barrier_touched, and barrier_touched fires on
        // spot <= strike). Both directions are bound by primary_stale_proven
        // plus the spot-age budget, which is what makes the arm safe — not the
        // direction of the print.
        //
        // Before this the exclusion was an ACCIDENT of two disjoint constant
        // lists: with provider=Pyth, `canonical_feed` wants pd.oracle_nft among
        // `pyth_canonical_feed_ids` (1-byte Lazer ids) while `in_mandate` wants
        // it among the mandate primaries (28-byte policy ids). The mandate was
        // an operator-supplied compile parameter this validator never
        // validated, so a single mistyped ceremony row satisfied both at once.
        //
        // [V8.2 G10] The admissible SET is now governed and the PUSH property
        // is the CORE rail over it: `config_within_rails` refuses any provider
        // `provider_is_push` answers False for, so governance may open a second
        // push feed without a migration and can never open a pull one. Genesis
        // lists AegisSelf alone, because it is the only provider the rest of the
        // chain can serve today — the Claim/Cancel resolver accepts only
        // AegisSelf primaries (fallback.primary_stale_proven) and cover_escrow
        // pins the identical predicate.
        let provider_admissible = list.any(
          cfg.admissible_providers,
          fn(p) { provider_tag(p) == provider_tag(pd.oracle_provider) },
        )
        let tx_lower = get_lower_bound(validity_range)
        let tx_upper = get_upper_bound(validity_range)
        // Resolve the pinned-resolver Price ONCE; derive spot + 2-leg freshness.
        //
        // [#363 red-team N2 CRITICAL] BOTH risk classes resolve. Depeg used to
        // short-circuit to `(0, True)` — spot-blind — so cover could be bought
        // while the peg was ALREADY broken at or below the strike and claimed in
        // the very next block (barrier_touched's `spot <= strike` has no time
        // gate). The vault now resolves the SAME pinned feed the Claim will
        // judge on, for every class, and derives freshness from it.
        // `config.depeg_eligible ⊆ mandate primaries` is a CONJUNCT of
        // `config_within_rails`, not a test, so a depeg feed always resolves
        // here — see the R4 note there for why a compile-time test could not
        // keep making that promise once both lists became data.
        // [V8.2 G10 red-team CRITICAL] The CORE compile parameter, byte-
        // identical to Claim (:590) and AcceptCancellation (:725). Resolving
        // `cfg.observer_hash` here made the spot GOVERNED DATA with no rail
        // over it but a width check: `attested_price` reads the Price straight
        // out of the redeemer of `Script(h)`, so its whole genuineness is the
        // IDENTITY of `h`, and a config naming an always-true stake script made
        // the print, its `observed_at` and its `valid_until` buyer-authored.
        // The substitution is what makes the closure STRUCTURAL rather than
        // order-of-evaluation dependent: the governed field is not an input to
        // price resolution at all, so no later refactor that moves
        // `config_bound` behind a branch can silently reopen it.
        let price = attested_price(
          self,
          observer_script_hash,
          pd.oracle_provider,
          pd.oracle_nft,
        )
        let resolved_spot = price.value
        // [#403 FIX 1] THE ONE-SIDED MIN LEG.
        //
        // A tight freshness window cannot fix the sale-side hole and no window
        // is a product: the break-even MANUFACTURED strike distance — the
        // fabricated distance that eats the entire risk load on a 7-day Barrier
        // at the 1500 bps guard — is 24.3 bps, while real ADA/USD manufactures
        // 84.4 bps at a ONE-SECOND window, and ADA fell 2806 bps inside one
        // second on 2025-10-10. Selection theory says the same thing from the
        // other side: a buyer who can see every signed update in the window
        // submits the argmax, and Lazer's 1ms channel puts hundreds of
        // thousands of admissible updates inside any window a Cardano tx can
        // physically be included under.
        //
        // `min` sidesteps all of it. The leg cannot RAISE the number the strike
        // is measured against, only lower it, so the buyer's freedom to shop
        // the highest signed print is worth exactly zero — and a leg he
        // controls becomes a leg that can only refuse him.
        let (second_leg_value, second_leg_ok, leg_is_independent) = when second_leg is {
          NoSecondLeg -> (resolved_spot, True, False)
          TrailingLowLeg -> (price.min_price_12h, True, False)
          PythPullLeg { feed_id, require_confidence } ->
            when attested_price_opt(self, observer_script_hash, Pyth, feed_id) is {
              // MANDATORY. A leg that may be omitted is not a leg: the price is
              // held at the primary so `min` stays well-defined, and the arm
              // refuses on the flag.
              None -> (resolved_spot, False, False)
              Some(q) ->
                (
                  q.value,
                  and {
                    // THE SALE-SIDE WINDOW — 300s Depeg / 600s Barrier, the two
                    // numbers already shipped, now applied to a leg whose age at
                    // build is ~0 by construction instead of one that must wait
                    // on a publisher. Judged at `start_time`, the instant
                    // coverage begins, exactly as the push leg is.
                    pd.start_time <= q.observed_at + max_spot_age_ms(pd.risk_class),
                    q.observed_at <= tx_upper,
                    tx_upper <= q.valid_until,
                    // [#403 FIX 4] Confidence, per-mandate and CONJUNCT-shaped.
                    // Satisfying it unlocks nothing; it only ever removes legs.
                    !require_confidence || q.confidence_present,
                  },
                  True,
                )
            }
        }
        let effective_spot = math.min(resolved_spot, second_leg_value)
        // [#363 F2] ONE budget, judged where it matters. `pd.start_time` is the
        // instant coverage begins — the value claim_trigger_ok gates on and the
        // one barrier_touched compares low_observed_at against — so the age of
        // the reading that SET the strike is bounded there, not at tx_lower.
        //
        // The old leg (`tx_lower <= observed_at + max_feed_age_ms`) was not
        // weak, it was VACUOUS: the ledger only requires `invalidBefore <=
        // currentSlot`, so a tx_lower years in the past satisfied it against a
        // feed of any age whatsoever.
        //
        // [#391 F1a] CLAMPED AT THE CORE SETTLEMENT BUDGET. The governed value
        // sat under a 24-hour rail (registry_v2.max_spot_age_rail_ms) while
        // every settlement-side age budget is the CORE `max_spot_age_ms` that
        // fallback.settle_price enforces at its own leg — so a config inside
        // its rail made Underwrite price a strike off a print that settlement
        // itself would refuse. `min` keeps the delegation intact in the one
        // direction that is safe: governance may TIGHTEN below CORE and the
        // tighter value bites, but it can never buy hindsight the settling
        // side would not honour.
        let governed_spot_age_ms =
          when pd.risk_class is {
            Barrier -> budgets.spot_age_barrier_ms
            Depeg -> budgets.spot_age_depeg_ms
          }
        // [#403 FIX 1] ...and the CORE ceiling widens to `max_dual_leg_spot_age_ms`
        // only when an INDEPENDENT pull leg is present and valid in this same
        // transaction. That is the availability win the mechanism buys, and
        // `min` is what makes it safe: a stale push print can no longer be the
        // number the strike is measured against, it merely caps less tightly,
        // while the fresh pull leg keeps the cap real. `leg_is_independent` is
        // False for `TrailingLowLeg` on purpose — the same publisher's own
        // memory goes stale with the print it came from, and correlated
        // staleness is the one thing `min` does not defend against.
        let core_spot_age_ms =
          if leg_is_independent && second_leg_ok {
            max_dual_leg_spot_age_ms
          } else {
            max_spot_age_ms(pd.risk_class)
          }
        let spot_age_budget_ms =
          math.min(governed_spot_age_ms, core_spot_age_ms)
        let fresh = and {
          pd.start_time <= price.observed_at + spot_age_budget_ms,
          tx_upper <= price.valid_until,
          // [#391 R2 F5b] ...and the print may not be stamped in the FUTURE.
          // The budget above bounds `observed_at` only from BELOW, so a
          // publisher clock (or a datum) a day ahead of the chain bought an
          // unbounded strike-setting window. `tx_upper` is the one instant the
          // ledger certifies lies at or after inclusion.
          price.observed_at <= tx_upper,
          // [#391 R2 F5c] A trailing LOW that is above its own reading's spot
          // is not a low. Nothing constrained key 3 anywhere, and the
          // `resolved_min_12h > strike` gate immediately above reads it.
          price.min_price_12h <= price.value,
        }
        // The policy window must sit in the tx validity range (V7
        // start_time_in_tx_range) and the datum must pin THIS vault's hash — so
        // the future Claim/Expire arm cannot be handed an out-of-range window
        // or a policy that names a different pool.
        // [#363 N1/N3 CRITICAL] The policy window is ANCHORED TO TX-NOW, for
        // BOTH risk classes. The ledger only requires invalidBefore <=
        // currentSlot, so a lower bound years in the past is a perfectly valid
        // tx, and Barrier's freshness legs (`tx_lower <= observed_at + age`,
        // `tx_upper <= valid_until`) are both UPPER bounds on tx_lower — they
        // bound nothing below. `start_time >= tx_lower` was therefore vacuous,
        // and a back-dated start_time retro-captured an already-printed 12h low
        // via barrier_touched's `low_observed_at >= start_time` => full coverage
        // for ~2% premium, repeatable (the #380 drain class).
        // Anchoring start_time at or after tx_upper — the LATEST instant this tx
        // can be included — makes `low_observed_at >= start_time` unsatisfiable
        // for any PRE-purchase low. The ledger enforces
        // `currentSlot < invalidHereafter`, so tx_upper is the one quantity it
        // certifies lies at/after inclusion; tx_lower is certified in the
        // useless direction and bounds nothing below. At inclusion therefore
        // `now < tx_upper <= start_time`, and every low that PHYSICALLY EXISTS
        // at purchase carries `low_observed_at <= now < start_time`. Arithmetic,
        // with no constant to tune and no reliance on the publisher's clock.
        //
        // `>=`, NOT `==`. The equality forced the builder to reproduce the
        // ledger's slot->POSIX translation EXACTLY and wedged on any downstream
        // re-quote of the validity range — a total DoS on the main money path,
        // since no builder computes that value. An inequality asks only for a
        // CONSERVATIVE over-estimate: the builder over-shoots deliberately, and
        // a wallet that SHRINKS ttl (the common CIP-30 direction) only makes it
        // MORE true. Every direction the builder's slack runs in strictly
        // REMOVES claimable lows, so slack can never weaken the guarantee.
        let window_ok = and {
          tx_upper - tx_lower <= budgets.underwrite_span_ms,
          pd.start_time >= tx_upper,
          pd.expiry_time > pd.start_time,
          // [#391 F1b] The claim delay is a DISCLOSED TERM, pinned into the
          // datum the buyer signs rather than read from a constant that can
          // move under him. The floor is CORE, so a pin can only make the
          // policy safer for the pool; the ceiling is the policy's own term,
          // so a wait can never swallow the cover it delays.
          waiting_period_pin_ok(pd),
        }
        let pool_hash_bound = pd.pool_script_hash == vault_hash

        // The protocol take, carved at the governed rate and routed to the
        // governed sink; the NET premium is the pool's growth. `fee_sink_not_vault`
        // above is what stops the sink aliasing the pool, so `take` can never
        // be satisfied by the vault's own continuation.
        let take = premium * fee.take_bps / 10_000
        let net = premium - take
        let team_paid = sum_lovelace_to_address(outputs, fee.team_address) >= take

        // 5. Vault-baked SECURITY BASELINE over the vault-resolved spot.
        // [#403 FIX 1] THE DECISION IS MADE ON `effective_spot`. Everything the
        // vault gates on here — Barrier's strike distance, Depeg's peg health
        // — is monotone non-decreasing in this number, which is exactly why
        // feeding a buyer-suppliable leg through `min` is safe.
        let baseline = underwrite_baseline_ok(
          pd.risk_class,
          effective_spot,
          // [#391 R2 F2a] the same reading's trailing low — the memory the
          // stale spot does not have
          price.min_price_12h,
          pd.strike_price,
          // [V8.2 FEE] adequacy over the NET premium — the growth the pool
          // actually receives, not the gross the buyer paid.
          net,
          pd.coverage_amount,
          // [#363 red-team M1] the vault bounds the TERM itself; the
          // duration-scaled actuarial curve stays delegated to the logic.
          pd.expiry_time - pd.start_time,
          in_mandate,
          in_depeg,
          budgets.min_premium,
          budgets.term_min_ms,
          budgets.term_max_ms,
        )

        // 6. Delegate the actuarial curve to the registry-named logic: its
        //    withdraw-0 MUST be present and its redeemer terms MUST equal the
        //    pinned datum + its spot MUST equal the vault-resolved spot (CRITICAL-2).
        let logic_cred = Script(logic_hash)
        let logic_present = list.any(withdrawals, fn(w) { w.1st == logic_cred })
        expect Some(raw_claim) = pairs.get_first(
          redeemers,
          Withdraw(logic_cred),
        )
        expect elig: EligibilityClaim = raw_claim
        let terms_bound = list.any(
          elig.policies,
          fn(t) { terms_match_datum(t, pd) },
        )
        // [#363 N2] Now that Depeg resolves a real spot, the logic's claimed
        // spot is bound for BOTH classes — a hostile logic cannot judge on a
        // fabricated price on either path (CRITICAL-2 generalized).
        //
        // [#403 FIX 1] DELIBERATELY the PRIMARY print, not `effective_spot`.
        // This conjunct exists to stop the swappable logic judging on a number
        // nobody attested; binding it to a value derived from a BUYER-supplied
        // leg would make the actuarial redeemer depend on the buyer's payload,
        // which is the coupling the min leg is designed to avoid. The vault's
        // own floor is what the second leg tightens, and that floor is
        // `underwrite_baseline_ok` above — the logic stays delegated and
        // timelock-bounded exactly as it was.
        let spot_bound = elig.spot == resolved_spot

        // 7. Accounting (the pool grows by the NET premium) + the no-free-
        //    aLP-co-mint pin (V7 no_lp_mint — the CRITICAL an Underwrite must
        //    carry, else a permissionless MintLP drains LPs against an unchanged
        //    lp_supply) + marker locality (fresh mint, no marker consumed, exactly
        //    one marker output — closes the consume-a-marker / synthetic-policy
        //    trick regardless of the marker policy's own authority).
        let marker_minted = assets.quantity_of(
          mint,
          marker_policy,
          policy_marker_asset_name,
        )
        // fresh mint into exactly one policy output; none consumed
        let marker_local = and {
          markers_in_inputs(inputs, marker_policy) == 0,
          markers_in_outputs(outputs, marker_policy) == 1,
        }
        let acct = underwrite_ok(
          state,
          new_state,
          coverage,
          premium,
          net,
          own_lovelace,
          cont_lovelace,
          marker_minted,
          policy_lovelace,
          min_utxo_lovelace,
        )

        // 8. Payout non-aliasing (§2.6): the future claim coverage can't be
        //    pre-routed to the vault or the policy script. Shared guard (DRY),
        //    also re-checked at Claim time.
        let alias_ok = payout_not_aliased(
          pd.payout_address,
          vault_hash,
          policy_hash,
        )

        and {
          base_ok,
          registry_bound,
          config_bound,
          pd_bound,
          canonical_feed,
          provider_admissible,
          fallback_pin_ok,
          fresh,
          second_leg_ok,
          window_ok,
          pool_hash_bound,
          baseline,
          logic_present,
          terms_bound,
          spot_bound,
          acct,
          team_paid,
          marker_local,
          alias_ok,
        }
      }

      // ---- Claim: pay a triggered policy's coverage to the insured ----
      // The vault CONSUMES one marker-bearing policy, RESOLVES the spot itself,
      // recomputes the trigger (version-independent, M5), pays coverage == the
      // policy's coverage to its non-aliased payout_address (or the insured),
      // and burns the marker. Because every arm gates marker minting (Underwrite
      // marker_local + LP arms only_lp_minted + fail-closed coverage), a marker
      // can ONLY exist in a legit policy — so marker-presence IS provenance
      // (EXT-08/09 closed), and the claim's own marker_in==1/out==0 keeps it local.
      Claim { payout } -> {
        // Consume EXACTLY ONE marker-bearing policy input at Script(policy_hash).
        expect [pol_in] = list.filter(
          inputs,
          fn(i) {
            i.output.address.payment_credential == policy_cred && i.output.address.stake_credential == None && assets.quantity_of(
              i.output.value,
              marker_policy,
              policy_marker_asset_name,
            ) == 1
          },
        )
        expect InlineDatum(raw_pd) = pol_in.output.datum
        let pd = decode_policy_datum(raw_pd)
        let policy_lovelace = assets.lovelace_of(pol_in.output.value)
        let pd_bound = and {
          pd.pool_nft == pool_nft_policy,
          pd.coverage_amount == payout,
        }

        // VAULT resolves the spot itself + recomputes the trigger over the
        // policy's PINNED strike/window (version-independent; both barrier and
        // depeg read the price at claim).
        let canonical_feed = is_canonical_oracle_nft(
          pd.oracle_provider,
          pd.oracle_nft,
        )
        let tx_lower = get_lower_bound(validity_range)
        let tx_upper = get_upper_bound(validity_range)
        let (price, settle_age_ok) = settlement_price_and_age_ok(
          self,
          observer_script_hash,
          pd,
          tx_lower,
          tx_upper,
        )
        let triggered = claim_trigger_ok(
          price.value,
          price.min_price_12h,
          price.low_observed_at,
          price.observed_at,
          price.valid_until,
          pd.strike_price,
          pd.start_time,
          pd.expiry_time,
          tx_lower,
          tx_upper,
          // [#391 F1b] The wait THIS policy was sold under, gating BOTH
          // barrier_touched disjuncts at once — `spot <= strike` has no time
          // gate of its own, so a wait applied inside the trigger would have
          // closed one path and left the other wide open.
          policy_waiting_period_ms(pd),
        )

        // Coverage reaches the non-aliased payout_address, or the insured if None.
        let alias_ok = payout_not_aliased(
          pd.payout_address,
          vault_hash,
          policy_hash,
        )
        // Coverage delivery mirrors V7 claim_settles' three cases: to the
        // insured's enterprise pkh (None), to a plain payout_address, or to a
        // Plutus payout_address WITH the committed inline datum (so a treasury
        // beneficiary's coverage lands spendable, not stranded).
        let paid_ok = when pd.payout_address is {
          None -> sum_lovelace_to_enterprise_pkh(outputs, pd.insured) >= payout
          Some(addr) ->
            when pd.payout_datum is {
              None -> sum_lovelace_to_address(outputs, addr) >= payout
              Some(d) ->
                sum_lovelace_to_address_with_inline_datum(outputs, addr, d) >= payout
            }
        }

        // Burn the policy's marker: exactly 1 consumed, 0 emitted, net mint -1.
        let marker_minted = assets.quantity_of(
          mint,
          marker_policy,
          policy_marker_asset_name,
        )
        let marker_burn_ok = and {
          markers_in_inputs(inputs, marker_policy) == 1,
          markers_in_outputs(outputs, marker_policy) == 0,
        }

        let acct = claim_ok(
          state,
          new_state,
          payout,
          pd.coverage_amount,
          own_lovelace,
          cont_lovelace,
          policy_lovelace,
          marker_minted,
        )

        and {
          base_ok,
          pd_bound,
          canonical_feed,
          settle_age_ok,
          triggered,
          alias_ok,
          paid_ok,
          marker_burn_ok,
          acct,
        }
      }
      AcceptCancellation -> {
        // The insured cancels early. Gated to: within the cancellation window,
        // policy OUT of the money (over a fresh vault-resolved spot), insured-
        // signed, and SELF-FUNDED only (a DAO-funded policy is non-cancellable —
        // else the buyer pockets a refund on premium the DAO paid). The insured
        // receives calculate_refund(premium); the retention stays as LP profit;
        // the coverage returns to the pool; the marker is burned.
        // Consume EXACTLY ONE marker-bearing policy input at Script(policy_hash).
        expect [pol_in] = list.filter(
          inputs,
          fn(i) {
            i.output.address.payment_credential == policy_cred && i.output.address.stake_credential == None && assets.quantity_of(
              i.output.value,
              marker_policy,
              policy_marker_asset_name,
            ) == 1
          },
        )
        expect InlineDatum(raw_pd) = pol_in.output.datum
        let pd = decode_policy_datum(raw_pd)
        let policy_lovelace = assets.lovelace_of(pol_in.output.value)
        let pd_bound = pd.pool_nft == pool_nft_policy

        // DAO-funded (payout_address Some) policies never cancel. Explicit match,
        // never a sum-type == (Windows-aiken silent-miscompile pitfall).
        let self_funded_only = when pd.payout_address is {
          None -> True
          Some(_) -> False
        }

        // The insured authorises their own cancellation.
        let signed_by_insured = list.has(extra_signatories, pd.insured)

        // Within the cancellation window, measured from the policy start.
        let tx_lower = get_lower_bound(validity_range)
        let tx_upper = get_upper_bound(validity_range)
        let within_window = tx_upper <= pd.start_time + cancellation_window

        // OUT of the money over a FRESH vault-resolved spot: the barrier must NOT
        // be touched, else the insured has a claimable position and Cancel would
        // hand them free optionality (Claim if ITM, Cancel if OTM). Same barrier
        // definition as Claim (barrier_touched) — one source of truth.
        let canonical_feed = is_canonical_oracle_nft(
          pd.oracle_provider,
          pd.oracle_nft,
        )
        // [#381 V8.1 S4] same shared resolution as Claim — Cancel must judge
        // OTM on the SAME price the pending Claim would settle on, or a
        // publisher outage hands the insured free optionality. The age bound
        // travels with the price for the same reason: an arm that could prove
        // OTM on hindsight the Claim arm refuses is the same free option read
        // from the other side.
        let (price, settle_age_ok) = settlement_price_and_age_ok(
          self,
          observer_script_hash,
          pd,
          tx_lower,
          tx_upper,
        )
        let otm_ok = and {
          !barrier_touched(
            price.value,
            price.min_price_12h,
            price.low_observed_at,
            pd.strike_price,
            pd.start_time,
          ),
          // [#391 R2 F2c] ...and the policy must not be one the reading shows
          // was BORN BROKEN. `barrier_touched` vetoes such a policy, which
          // makes it read OTM — so without this line the losing half of the
          // hindsight bet is REFUNDED at 90%: heads full coverage, tails most
          // of the premium back. A born-broken policy claims nothing and
          // cancels nothing; it expires and the premium stays with the LPs.
          !pre_start_breach(
            price.min_price_12h,
            price.low_observed_at,
            pd.strike_price,
            pd.start_time,
          ),
          reading_fresh(
            price.low_observed_at,
            price.observed_at,
            price.valid_until,
            tx_lower,
            tx_upper,
          ),
        }

        // Refund derived from the PINNED premium, never caller-supplied. The
        // cancel_ok value equation pins exactly `refund` leaving the pool, and
        // refund_paid pins the insured receiving >= refund — together, exactly
        // the refund reaches the insured.
        let refund = calculate_refund(pd.premium_paid)
        let refund_paid = sum_lovelace_to_enterprise_pkh(outputs, pd.insured) >= refund

        // Burn the policy's marker: exactly 1 consumed, 0 emitted, net mint -1.
        let marker_minted = assets.quantity_of(
          mint,
          marker_policy,
          policy_marker_asset_name,
        )
        let marker_burn_ok = and {
          markers_in_inputs(inputs, marker_policy) == 1,
          markers_in_outputs(outputs, marker_policy) == 0,
        }

        let acct = cancel_ok(
          state,
          new_state,
          pd.coverage_amount,
          refund,
          own_lovelace,
          cont_lovelace,
          policy_lovelace,
          marker_minted,
        )

        and {
          base_ok,
          pd_bound,
          self_funded_only,
          signed_by_insured,
          within_window,
          canonical_feed,
          settle_age_ok,
          otm_ok,
          refund_paid,
          marker_burn_ok,
          acct,
        }
      }
      Expire { total_returned } -> {
        // Reclaim a policy PAST its expiry that was never claimed: its self-held
        // lovelace returns wholly to the pool, its coverage is released, and its
        // marker is burned. No oracle read and no payout — expiry is purely a
        // time gate (if the barrier fired, the insured had to Claim in-window;
        // past expiry the claim window (tx_upper <= expiry) has closed).
        // Consume EXACTLY ONE marker-bearing policy input at Script(policy_hash).
        expect [pol_in] = list.filter(
          inputs,
          fn(i) {
            i.output.address.payment_credential == policy_cred && i.output.address.stake_credential == None && assets.quantity_of(
              i.output.value,
              marker_policy,
              policy_marker_asset_name,
            ) == 1
          },
        )
        expect InlineDatum(raw_pd) = pol_in.output.datum
        let pd = decode_policy_datum(raw_pd)
        let policy_lovelace = assets.lovelace_of(pol_in.output.value)
        let pd_bound = pd.pool_nft == pool_nft_policy

        // Past-expiry gate: the tx cannot start until AFTER the policy expired.
        let tx_lower = get_lower_bound(validity_range)
        let is_expired = tx_lower > pd.expiry_time

        // Bind the declared return to the actual policy lovelace (no dead field).
        let returned_ok = total_returned == policy_lovelace

        // Burn the policy's marker: exactly 1 consumed, 0 emitted, net mint -1.
        let marker_minted = assets.quantity_of(
          mint,
          marker_policy,
          policy_marker_asset_name,
        )
        let marker_burn_ok = and {
          markers_in_inputs(inputs, marker_policy) == 1,
          markers_in_outputs(outputs, marker_policy) == 0,
        }

        let acct = expire_ok(
          state,
          new_state,
          pd.coverage_amount,
          own_lovelace,
          cont_lovelace,
          policy_lovelace,
          marker_minted,
        )

        and {
          base_ok,
          pd_bound,
          is_expired,
          returned_ok,
          marker_burn_ok,
          acct,
        }
      }
    }
  }

  else(_) {
    fail @"Unsupported purpose for the pool_vault validator (spend-only)"
  }
}

/// [#403 FIX 2] The settlement price for `pd`, AND the age bound that applies
/// to it. Shared by Claim and AcceptCancellation, which must judge the same
/// policy on the same reading under the same horizon.
///
/// AegisSelf policies resolve through `fallback.settle_price`, which enforces
/// `tx_upper <= observed_at + max_spot_age_ms(risk_class)` at its own leg, so
/// the bound is already inside the price and the second component is True.
/// EVERY OTHER PROVIDER took the direct `attested_price` read, whose only
/// horizon was the reading's own `valid_until` — up to `pyth_ordinary_window_ms`
/// of hindsight where the class budget says 300s / 600s. That gap is what made
/// admitting a non-AegisSelf provider at the SALE side silently widen
/// SETTLEMENT, in both directions: a low print trips a Barrier at Claim, a high
/// one proves OTM at Cancel. Every provider is now bounded by its class budget.
fn settlement_price_and_age_ok(
  self: Transaction,
  observer_script_hash: ByteArray,
  pd: PolicyDatum,
  tx_lower: Int,
  tx_upper: Int,
) -> (oracle_types.Price, Bool) {
  when pd.oracle_provider is {
    AegisSelf ->
      (
        fallback.settle_price(
          self,
          observer_script_hash,
          policy_fallback_feed_id(pd),
          pd.oracle_nft,
          pd.risk_class,
          pd.start_time,
          tx_lower,
          tx_upper,
        ),
        True,
      )
    _ -> {
      let p =
        attested_price(
          self,
          observer_script_hash,
          pd.oracle_provider,
          pd.oracle_nft,
        )
      (p, tx_upper <= p.observed_at + max_spot_age_ms(pd.risk_class))
    }
  }
}

/// Total marker tokens (marker_policy, "AEGIS_POLICY") across the tx inputs.
fn markers_in_inputs(inputs: List<Input>, marker_policy: ByteArray) -> Int {
  list.foldl(
    inputs,
    0,
    fn(i, acc) {
      acc + assets.quantity_of(
        i.output.value,
        marker_policy,
        policy_marker_asset_name,
      )
    },
  )
}

/// Total marker tokens across the tx outputs.
fn markers_in_outputs(outputs: List<Output>, marker_policy: ByteArray) -> Int {
  list.foldl(
    outputs,
    0,
    fn(o, acc) {
      acc + assets.quantity_of(o.value, marker_policy, policy_marker_asset_name)
    },
  )
}

// ===========================================================================
// VALIDATOR-LEVEL scenario fixtures (#362 pre-preprod prerequisite). The pure
// predicates in lib/aegis/vault.ak are unit + mutation tested; these exercise
// the WIRING — the expect [pol_in] filter, marker totals, base_ok NFT
// preservation, the redeemer routing — by invoking pool_vault.spend over a
// full Transaction. Each arm: the green path passes, and each guard, dropped,
// REJECTS (the "silently-dropped conjunct" class the red-team flagged). Short
// hex ids stand in for the compile-time script params (consistent per test).
// ===========================================================================

const sv_pool_nft_policy: ByteArray = #"90a1"

const sv_pool_nft_name: ByteArray = #"41454749535f504f4f4c"

const sv_lp_policy: ByteArray = #"91b2"

/// 28 bytes, because it now travels through the GOVERNED config and
/// `config_within_rails` refuses a resolver hash of any other width.
const sv_observer_hash: ByteArray =
  #"92c392c392c392c392c392c392c392c392c392c392c392c392c392c3"

const sv_registry_nft_policy: ByteArray = #"93d4"

const sv_registry_nft_name: ByteArray = #"41454749535f5245474953545259"

const sv_policy_hash: ByteArray = #"94e5"

const sv_marker_policy: ByteArray = #"95f6"

const sv_vault_script: ByteArray = #"96a7"

const sv_logic_hash: ByteArray = #"aa"

/// A custody root that is NOT this vault's. V8.2 deleted the registry RuleSet
/// that used to name the roots — they are CORE compile parameters now — so this
/// is the foreign root the Invariant-S negatives mint and spend under.
const sv_foreign_root: ByteArray = #"9808"

/// The FIRST canonical AegisSelf feed NFT of the ACTIVE network module.
///
/// DERIVED, never a hardcoded literal (#363 N6). Pinning the mainnet NFT made
/// every sv_* scenario abort at `expect list.has(aegis_self_canonical_nfts, …)`
/// on a preprod build — and pinning a preprod literal breaks the mainnet build
/// the same way. That whack-a-mole leaves the whole validator-level suite RED,
/// which silently MASKS real regressions: it is exactly why an incomplete
/// Underwrite fix shipped with "zero new failures". Deriving it makes the
/// oracle-path fixtures correct on BOTH builds.
fn sv_ada_nft() -> ByteArray {
  expect [nft, ..] = aegis_self_canonical_nfts
  nft
}

fn sv_script_addr(h: ByteArray) -> Address {
  Address { payment_credential: Script(h), stake_credential: None }
}

fn sv_state(supply: Int, cov: Int, reserve: Int) -> VaultState {
  Vault {
    lp_supply: supply,
    active_coverage: cov,
    reserve,
    registry_nft: sv_registry_nft_policy,
  }
}

fn sv_vault_value(lovelace: Int) -> assets.Value {
  assets.from_lovelace(lovelace)
    |> assets.add(sv_pool_nft_policy, sv_pool_nft_name, 1)
}

fn sv_own_ref() -> OutputReference {
  OutputReference { transaction_id: fixtures.tx_id_zero, output_index: 0 }
}

fn sv_vault_input(lovelace: Int, state: VaultState) -> Input {
  Input {
    output_reference: sv_own_ref(),
    output: Output {
      address: sv_script_addr(sv_vault_script),
      value: sv_vault_value(lovelace),
      datum: InlineDatum(state),
      reference_script: None,
    },
  }
}

fn sv_cont_output(lovelace: Int, state: VaultState) -> Output {
  Output {
    address: sv_script_addr(sv_vault_script),
    value: sv_vault_value(lovelace),
    datum: InlineDatum(state),
    reference_script: None,
  }
}

/// 28-byte fillers for the config fields the vault does not read yet but
/// `config_within_rails` still measures.
const sv_cfg_publisher: ByteArray =
  #"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"

const sv_cfg_state_nft: ByteArray =
  #"c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"

const sv_cfg_team_key: ByteArray =
  #"c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2"

/// The GOVERNED config the fixtures underwrite against, at its genesis
/// calibration — the same numbers the compiled constants carry, so a scenario's
/// meaning does not change when the value's SOURCE does. `mandates` is the only
/// argument because it is the only field individual scenarios vary.
///
/// `depeg_eligible` is derived from the mandate primaries rather than listed,
/// because the R4 subset rail refuses a depeg feed with no mandate: deriving it
/// keeps every fixture inside the rails by construction. Production narrows it
/// to the curated stablecoin set — `_common.genesis_config` intersects the
/// mandates with `types/<network>::depeg_eligible_nfts`, which is what keeps
/// ADA/USD off the duration-only depeg hazard curve. It did NOT narrow it while
/// this comment first claimed so.
fn sv_config(mandates: List<OracleMandate>) -> UnderwriteConfig {
  UnderwriteConfig {
    mandates,
    publisher_vkh: sv_cfg_publisher,
    observer_hash: sv_observer_hash,
    depeg_eligible: list.map(mandates, fn(m) { m.primary_nft }),
    pyth_feed_allowlist: [],
    pyth_state_nft: sv_cfg_state_nft,
    floors: Floors {
      min_strike_distance_bps: 1_500,
      min_depeg_distance_bps: 200,
      depeg_strike_lo_bps: 5_000,
      depeg_strike_hi_bps: 9_500,
      min_depeg_spot_bps: 9_900,
    },
    admissible_providers: [AegisSelf],
    budgets: Budgets {
      spot_age_barrier_ms: 600_000,
      spot_age_depeg_ms: 300_000,
      underwrite_span_ms: 1_200_000,
      term_min_ms: 604_800_000,
      term_max_ms: 15_552_000_000,
      min_premium: 2_000_000,
      utilisation_bps: 3_333,
      max_coverage_ratio: 50,
    },
    fee: Fee {
      take_bps: 200,
      treasury_bps: 2_500,
      team_address: Address {
        payment_credential: VerificationKey(sv_cfg_team_key),
        stake_credential: None,
      },
    },
    settlement_pins: SettlementPins {
      reading_validity_ms: 7_200_000,
      pyth_freshness_ms: 4_200_000,
      pyth_max_confidence_bps: 100,
      pyth_reject_absent_confidence: False,
      grace_barrier_ms: 1_800_000,
      grace_depeg_ms: 1_800_000,
      cancellation_window_ms: 3_600_000,
      cancellation_fee_bps: 1_000,
    },
  }
}

/// The registry reference input every scenario carries. Underwrite reads its
/// `config` and its `logic_hash`; every other arm must IGNORE it entirely
/// (Invariant S), which is why the settlement fixtures keep carrying it.
fn sv_registry_ref() -> Input {
  sv_registry_ref_cfg(sv_config([sv_mandate(sv_ada_nft())]))
}

fn sv_registry_ref_cfg(config: UnderwriteConfig) -> Input {
  let rd = RegistryDatum {
    epoch: 1,
    logic_hash: sv_logic_hash,
    config,
    pending: None,
    admin: Admin { keys: [#"01"], threshold: 1 },
    cooldown_until: 0,
    timelock_ms: 300_000_000,
    cancel_cooldown_ms: 172_800_000,
  }
  fixtures.make_input(
    fixtures.tx_id_one,
    1,
    sv_script_addr(#"deadbeef"),
    assets.from_lovelace(2_000_000)
      |> assets.add(sv_registry_nft_policy, sv_registry_nft_name, 1),
    InlineDatum(rd),
  )
}

/// A policy UTxO at Script(policy_hash) holding one marker + `pd`. Expiry is
/// pinned BEFORE base_tx's validity lower bound (1_700_100_000_000) so is_expired.
fn sv_expire_policy_datum() -> PolicyDatum {
  PolicyDatum {
    ..fixtures.default_policy_datum(),
    coverage_amount: 50_000_000,
    expiry_time: 1_700_000_000_000,
    pool_nft: sv_pool_nft_policy,
    payout_address: None,
  }
}

/// The policy UTxO with its datum supplied RAW, so a test can pin an arity the
/// current `PolicyDatum` type can no longer express.
fn sv_policy_input_raw(policy_lovelace: Int, raw_pd: Data) -> Input {
  fixtures.make_input(
    fixtures.tx_id_two,
    2,
    sv_script_addr(sv_policy_hash),
    assets.from_lovelace(policy_lovelace)
      |> assets.add(sv_marker_policy, policy_marker_asset_name, 1),
    InlineDatum(raw_pd),
  )
}

fn sv_policy_input(policy_lovelace: Int, pd: PolicyDatum) -> Input {
  sv_policy_input_raw(policy_lovelace, pd)
}

fn sv_expire_tx_raw(
  vault_in: Int,
  old: VaultState,
  cont: Int,
  new: VaultState,
  policy_lovelace: Int,
  raw_pd: Data,
  mint: assets.Value,
) -> Transaction {
  Transaction {
    ..fixtures.base_tx(),
    inputs: [
      sv_vault_input(vault_in, old),
      sv_policy_input_raw(policy_lovelace, raw_pd),
    ],
    reference_inputs: [sv_registry_ref()],
    outputs: [sv_cont_output(cont, new)],
    mint,
  }
}

fn sv_expire_tx(
  vault_in: Int,
  old: VaultState,
  cont: Int,
  new: VaultState,
  policy_lovelace: Int,
  pd: PolicyDatum,
  mint: assets.Value,
) -> Transaction {
  sv_expire_tx_raw(vault_in, old, cont, new, policy_lovelace, pd, mint)
}

fn sv_run_expire(old: VaultState, tx: Transaction) -> Bool {
  pool_vault.spend(
    sv_pool_nft_policy,
    sv_pool_nft_name,
    sv_lp_policy,
    sv_policy_hash,
    sv_marker_policy,
    sv_observer_hash,
    sv_registry_nft_policy,
    sv_registry_nft_name,
    Some(old),
    Expire { total_returned: 50_000_000 },
    sv_own_ref(),
    tx,
  )
}

fn sv_marker_burn() -> assets.Value {
  assets.from_asset(sv_marker_policy, policy_marker_asset_name, -1)
}

test sv_expire_green_path() {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let tx = sv_expire_tx(
    100_000_000,
    old,
    150_000_000,
    new,
    50_000_000,
    sv_expire_policy_datum(),
    sv_marker_burn(),
  )
  sv_run_expire(old, tx)
}

/// Expire spends old policy UTxOs, so the fourteen-field V4-era datums still
/// on chain must release their coverage here. Byte-for-byte the same
/// transaction as `sv_expire_green_path`; only the datum's arity differs.
test sv_expire_releases_legacy_14_field_policy() {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let tx = sv_expire_tx_raw(
    100_000_000,
    old,
    150_000_000,
    new,
    50_000_000,
    fixtures.legacy_head_datum(sv_expire_policy_datum()),
    sv_marker_burn(),
  )
  sv_run_expire(old, tx)
}

test sv_expire_rejects_not_yet_expired() {
  // expiry AFTER the tx window -> is_expired False.
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = PolicyDatum {
    ..sv_expire_policy_datum(),
    expiry_time: 1_700_200_000_000,
  }
  let tx = sv_expire_tx(
    100_000_000,
    old,
    150_000_000,
    new,
    50_000_000,
    pd,
    sv_marker_burn(),
  )
  !sv_run_expire(old, tx)
}

test sv_expire_rejects_skimmed_return() {
  // cont short of own + policy_lovelace -> expire_ok value leg fails.
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let tx = sv_expire_tx(
    100_000_000,
    old,
    149_000_000,
    new,
    50_000_000,
    sv_expire_policy_datum(),
    sv_marker_burn(),
  )
  !sv_run_expire(old, tx)
}

test sv_expire_rejects_coverage_not_released() {
  // new active_coverage unchanged -> expire_ok nc leg fails.
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 200_000_000, 10_000_000)
  let tx = sv_expire_tx(
    100_000_000,
    old,
    150_000_000,
    new,
    50_000_000,
    sv_expire_policy_datum(),
    sv_marker_burn(),
  )
  !sv_run_expire(old, tx)
}

test sv_expire_rejects_marker_not_burned() {
  // no marker burn (net mint 0) -> expire_ok marker leg fails.
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let tx = sv_expire_tx(
    100_000_000,
    old,
    150_000_000,
    new,
    50_000_000,
    sv_expire_policy_datum(),
    assets.zero,
  )
  !sv_run_expire(old, tx)
}

test sv_expire_rejects_alp_co_mint() {
  // co-mint aLP inside an Expire -> base_ok alp_mint_allowed False (the
  // structural drain guard, exercised at the validator level).
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let mint = sv_marker_burn() |> assets.add(sv_lp_policy, "aLP", 5)
  let tx = sv_expire_tx(
    100_000_000,
    old,
    150_000_000,
    new,
    50_000_000,
    sv_expire_policy_datum(),
    mint,
  )
  !sv_run_expire(old, tx)
}

// --- Claim arm scenarios (needs the observer attestation over a fresh feed) ---
// base_tx validity is [1_700_100_000_000, 1_700_100_300_000]; the feed is
// observed at 1_700_099_900_000 and valid until 1_700_100_400_000 (fresh), and
// the policy window [start, expiry] straddles the tx.

fn sv_claim_policy_datum(
  strike: Int,
  coverage: Int,
  payout_addr: Option<Address>,
) -> PolicyDatum {
  PolicyDatum {
    ..fixtures.default_policy_datum_aegis_self(),
    strike_price: strike,
    // [#391 R2 F2b] base_tx settles at [1_700_100_000_000, 1_700_100_300_000],
    // so coverage begins 4_000_000 ms earlier — past the 3_600_000 ms Barrier
    // waiting period this policy discloses. The gap tracks the constant: an
    // honest claim simply lands after the wait it was sold with, and Barrier's
    // wait rose from 1_800_000 when the hindsight ratio was made monotone.
    start_time: 1_700_096_000_000,
    expiry_time: 1_700_200_000_000,
    coverage_amount: coverage,
    oracle_nft: sv_ada_nft(),
    pool_nft: sv_pool_nft_policy,
    payout_address: payout_addr,
  }
}

fn sv_claim_tx_raw(
  vault_in: Int,
  old: VaultState,
  cont: Int,
  new: VaultState,
  policy_lovelace: Int,
  raw_pd: Data,
  spot: Int,
  payouts: List<Output>,
  mint: assets.Value,
) -> Transaction {
  let feed = fixtures.aegis_self_feed_input(
    sv_ada_nft(),
    spot,
    1_700_099_900_000,
    1_700_100_400_000,
  )
  let base = Transaction {
    ..fixtures.base_tx(),
    inputs: [
      sv_vault_input(vault_in, old),
      sv_policy_input_raw(policy_lovelace, raw_pd),
    ],
    reference_inputs: [sv_registry_ref(), feed],
    outputs: [sv_cont_output(cont, new), ..payouts],
    mint,
  }
  fixtures.with_observer_attestation(
    base,
    sv_observer_hash,
    [(AegisSelf, sv_ada_nft())],
  )
}

fn sv_claim_tx(
  vault_in: Int,
  old: VaultState,
  cont: Int,
  new: VaultState,
  policy_lovelace: Int,
  pd: PolicyDatum,
  spot: Int,
  payouts: List<Output>,
  mint: assets.Value,
) -> Transaction {
  sv_claim_tx_raw(
    vault_in,
    old,
    cont,
    new,
    policy_lovelace,
    pd,
    spot,
    payouts,
    mint,
  )
}

fn sv_run_claim(old: VaultState, payout: Int, tx: Transaction) -> Bool {
  pool_vault.spend(
    sv_pool_nft_policy,
    sv_pool_nft_name,
    sv_lp_policy,
    sv_policy_hash,
    sv_marker_policy,
    sv_observer_hash,
    sv_registry_nft_policy,
    sv_registry_nft_name,
    Some(old),
    Claim { payout },
    sv_own_ref(),
    tx,
  )
}

test sv_claim_green_path() {
  // reserve 60M > payout 50M, so from_reserve = 50M -> new reserve 10M.
  // cont = own 100M + policy 50M - payout 50M = 100M; active_coverage 200->150.
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_claim_policy_datum(100_000_000, 50_000_000, None)
  let payout_out = fixtures.pkh_output(pd.insured, 50_000_000)
  let tx = sv_claim_tx(
    100_000_000,
    old,
    100_000_000,
    new,
    50_000_000,
    pd,
    90_000_000,
    [payout_out],
    sv_marker_burn(),
  )
  sv_run_claim(old, 50_000_000, tx)
}

/// The vault hash is frozen, so the code that settles a claim today is the code
/// that has to settle every policy ever written at this address — including the
/// fourteen-field ones underwritten before `payout_address` existed. Byte for
/// byte the same transaction as `sv_claim_green_path`; only the datum's arity
/// differs. If this fails, appending a PolicyDatum field strands live policies.
test sv_claim_settles_legacy_14_field_policy() {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_claim_policy_datum(100_000_000, 50_000_000, None)
  let payout_out = fixtures.pkh_output(pd.insured, 50_000_000)
  let tx = sv_claim_tx_raw(
    100_000_000,
    old,
    100_000_000,
    new,
    50_000_000,
    fixtures.legacy_head_datum(pd),
    90_000_000,
    [payout_out],
    sv_marker_burn(),
  )
  sv_run_claim(old, 50_000_000, tx)
}

test sv_claim_rejects_not_triggered() {
  // spot 110M > strike 100M -> barrier not touched -> claim_trigger_ok False.
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_claim_policy_datum(100_000_000, 50_000_000, None)
  let payout_out = fixtures.pkh_output(pd.insured, 50_000_000)
  let tx = sv_claim_tx(
    100_000_000,
    old,
    100_000_000,
    new,
    50_000_000,
    pd,
    110_000_000,
    [payout_out],
    sv_marker_burn(),
  )
  !sv_run_claim(old, 50_000_000, tx)
}

test sv_claim_rejects_underpaid_insured() {
  // insured paid 49M < payout 50M -> paid_ok False.
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_claim_policy_datum(100_000_000, 50_000_000, None)
  let payout_out = fixtures.pkh_output(pd.insured, 49_000_000)
  let tx = sv_claim_tx(
    100_000_000,
    old,
    // cont must still satisfy claim_ok value eq for the OTHER legs to pass so
    // paid_ok is the sole failing leg; keep cont = own + policy - payout.
    100_000_000,
    new,
    50_000_000,
    pd,
    90_000_000,
    [payout_out],
    sv_marker_burn(),
  )
  !sv_run_claim(old, 50_000_000, tx)
}

test sv_claim_rejects_aliased_payout() {
  // payout_address aliased to the vault script -> alias_ok False (the §2.6 drain).
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_claim_policy_datum(
    100_000_000,
    50_000_000,
    Some(sv_script_addr(sv_vault_script)),
  )
  let payout_out = fixtures.pkh_output(pd.insured, 50_000_000)
  let tx = sv_claim_tx(
    100_000_000,
    old,
    100_000_000,
    new,
    50_000_000,
    pd,
    90_000_000,
    [payout_out],
    sv_marker_burn(),
  )
  !sv_run_claim(old, 50_000_000, tx)
}

test sv_claim_rejects_marker_not_burned() {
  // no marker burn (net mint 0) -> claim_ok marker leg + marker_burn_ok False.
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_claim_policy_datum(100_000_000, 50_000_000, None)
  let payout_out = fixtures.pkh_output(pd.insured, 50_000_000)
  let tx = sv_claim_tx(
    100_000_000,
    old,
    100_000_000,
    new,
    50_000_000,
    pd,
    90_000_000,
    [payout_out],
    assets.zero,
  )
  !sv_run_claim(old, 50_000_000, tx)
}

// --- AcceptCancellation scenarios (OTM over a fresh feed, insured-signed,
// within-window, self-funded only). premium 5M -> refund 4.5M. Policy started at
// 1_700_100_000_000 so tx_upper (1_700_100_300_000) is inside start+3.6M window.

fn sv_cancel_policy_datum(
  strike: Int,
  coverage: Int,
  premium: Int,
  start: Int,
  payout_addr: Option<Address>,
) -> PolicyDatum {
  PolicyDatum {
    ..fixtures.default_policy_datum_aegis_self(),
    strike_price: strike,
    start_time: start,
    expiry_time: 1_700_200_000_000,
    coverage_amount: coverage,
    premium_paid: premium,
    oracle_nft: sv_ada_nft(),
    pool_nft: sv_pool_nft_policy,
    payout_address: payout_addr,
  }
}

fn sv_cancel_tx_raw(
  vault_in: Int,
  old: VaultState,
  cont: Int,
  new: VaultState,
  policy_lovelace: Int,
  raw_pd: Data,
  spot: Int,
  refunds: List<Output>,
  signers: List<ByteArray>,
  mint: assets.Value,
) -> Transaction {
  let feed = fixtures.aegis_self_feed_input(
    sv_ada_nft(),
    spot,
    1_700_099_900_000,
    1_700_100_400_000,
  )
  let base = Transaction {
    ..fixtures.base_tx(),
    inputs: [
      sv_vault_input(vault_in, old),
      sv_policy_input_raw(policy_lovelace, raw_pd),
    ],
    reference_inputs: [sv_registry_ref(), feed],
    outputs: [sv_cont_output(cont, new), ..refunds],
    extra_signatories: signers,
    mint,
  }
  fixtures.with_observer_attestation(
    base,
    sv_observer_hash,
    [(AegisSelf, sv_ada_nft())],
  )
}

fn sv_cancel_tx(
  vault_in: Int,
  old: VaultState,
  cont: Int,
  new: VaultState,
  policy_lovelace: Int,
  pd: PolicyDatum,
  spot: Int,
  refunds: List<Output>,
  signers: List<ByteArray>,
  mint: assets.Value,
) -> Transaction {
  sv_cancel_tx_raw(
    vault_in,
    old,
    cont,
    new,
    policy_lovelace,
    pd,
    spot,
    refunds,
    signers,
    mint,
  )
}

fn sv_run_cancel(old: VaultState, tx: Transaction) -> Bool {
  pool_vault.spend(
    sv_pool_nft_policy,
    sv_pool_nft_name,
    sv_lp_policy,
    sv_policy_hash,
    sv_marker_policy,
    sv_observer_hash,
    sv_registry_nft_policy,
    sv_registry_nft_name,
    Some(old),
    AcceptCancellation,
    sv_own_ref(),
    tx,
  )
}

test sv_cancel_green_path() {
  // OTM (spot 110M > strike 100M), insured-signed, within window, self-funded.
  // cont = own 100M + policy 50M - refund 4.5M = 145.5M; active_coverage 200->150.
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_cancel_policy_datum(
    100_000_000,
    50_000_000,
    5_000_000,
    1_700_100_000_000,
    None,
  )
  let refund_out = fixtures.pkh_output(pd.insured, 4_500_000)
  let tx = sv_cancel_tx(
    100_000_000,
    old,
    145_500_000,
    new,
    50_000_000,
    pd,
    110_000_000,
    [refund_out],
    [pd.insured],
    sv_marker_burn(),
  )
  sv_run_cancel(old, tx)
}

/// Cancellation spends old policy UTxOs too: a fourteen-field V4-era policy is
/// self-funded by construction (`payout_address` did not exist), so its holder
/// keeps the right to cancel. Byte-for-byte the same transaction as
/// `sv_cancel_green_path`; only the datum's arity differs.
test sv_cancel_refunds_legacy_14_field_policy() {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_cancel_policy_datum(
    100_000_000,
    50_000_000,
    5_000_000,
    1_700_100_000_000,
    None,
  )
  let refund_out = fixtures.pkh_output(pd.insured, 4_500_000)
  let tx = sv_cancel_tx_raw(
    100_000_000,
    old,
    145_500_000,
    new,
    50_000_000,
    fixtures.legacy_head_datum(pd),
    110_000_000,
    [refund_out],
    [pd.insured],
    sv_marker_burn(),
  )
  sv_run_cancel(old, tx)
}

test sv_cancel_rejects_dao_funded() {
  // payout_address Some -> self_funded_only False (DAO-funded is non-cancellable).
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_cancel_policy_datum(
    100_000_000,
    50_000_000,
    5_000_000,
    1_700_100_000_000,
    Some(sv_script_addr(#"cafe")),
  )
  let refund_out = fixtures.pkh_output(pd.insured, 4_500_000)
  let tx = sv_cancel_tx(
    100_000_000,
    old,
    145_500_000,
    new,
    50_000_000,
    pd,
    110_000_000,
    [refund_out],
    [pd.insured],
    sv_marker_burn(),
  )
  !sv_run_cancel(old, tx)
}

test sv_cancel_rejects_in_the_money() {
  // spot 90M <= strike 100M -> barrier touched -> otm_ok False (no free
  // optionality: an ITM policy must Claim, not Cancel-for-refund).
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_cancel_policy_datum(
    100_000_000,
    50_000_000,
    5_000_000,
    1_700_100_000_000,
    None,
  )
  let refund_out = fixtures.pkh_output(pd.insured, 4_500_000)
  let tx = sv_cancel_tx(
    100_000_000,
    old,
    145_500_000,
    new,
    50_000_000,
    pd,
    90_000_000,
    [refund_out],
    [pd.insured],
    sv_marker_burn(),
  )
  !sv_run_cancel(old, tx)
}

test sv_cancel_rejects_out_of_window() {
  // policy started long before the tx -> tx_upper > start + cancellation_window.
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_cancel_policy_datum(
    100_000_000,
    50_000_000,
    5_000_000,
    1_700_090_000_000,
    None,
  )
  let refund_out = fixtures.pkh_output(pd.insured, 4_500_000)
  let tx = sv_cancel_tx(
    100_000_000,
    old,
    145_500_000,
    new,
    50_000_000,
    pd,
    110_000_000,
    [refund_out],
    [pd.insured],
    sv_marker_burn(),
  )
  !sv_run_cancel(old, tx)
}

test sv_cancel_rejects_non_insured_signer() {
  // the insured did not sign -> signed_by_insured False.
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_cancel_policy_datum(
    100_000_000,
    50_000_000,
    5_000_000,
    1_700_100_000_000,
    None,
  )
  let refund_out = fixtures.pkh_output(pd.insured, 4_500_000)
  let tx = sv_cancel_tx(
    100_000_000,
    old,
    145_500_000,
    new,
    50_000_000,
    pd,
    110_000_000,
    [refund_out],
    [#"99"],
    sv_marker_burn(),
  )
  !sv_run_cancel(old, tx)
}

// --- Invariant S (V82-IMMUTABLE-CORE §2): settlement takes NO registry
// reference input. A policy settles on the terms it was sold under, so a
// registry that is hostile, bricked, or simply absent cannot alter, delay or
// deny a policy that already exists. Each arm settles a transaction whose
// reference inputs contain no registry UTxO at all; each negative re-runs that
// same transaction against a vault whose CORE custody root is foreign, which is
// what now binds the policy script and its marker.

/// Strip the registry UTxO from a scenario's reference inputs — the ONE input
/// the settlement arms used to require.
fn sv_without_registry_ref(tx: Transaction) -> Transaction {
  Transaction {
    ..tx,
    reference_inputs: list.filter(
      tx.reference_inputs,
      fn(i) {
        assets.quantity_of(
          i.output.value,
          sv_registry_nft_policy,
          sv_registry_nft_name,
        ) == 0
      },
    ),
  }
}

/// Run a settlement arm with the custody roots supplied, so a negative can pin
/// a root this vault was NOT compiled with.
fn sv_run_with_roots(
  policy_hash: ByteArray,
  marker_policy: ByteArray,
  old: VaultState,
  redeemer: VaultRedeemer,
  tx: Transaction,
) -> Bool {
  pool_vault.spend(
    sv_pool_nft_policy,
    sv_pool_nft_name,
    sv_lp_policy,
    policy_hash,
    marker_policy,
    sv_observer_hash,
    sv_registry_nft_policy,
    sv_registry_nft_name,
    Some(old),
    redeemer,
    sv_own_ref(),
    tx,
  )
}

/// The green Claim settlement the custody-root tests run. The registry
/// reference input is INCLUDED: the Invariant-S variant strips it, the
/// marker-root negatives keep it, so an arm that sourced a root from that
/// datum is caught rather than merely erroring on a missing input.
fn sv_settle_claim_tx() -> Transaction {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_claim_policy_datum(100_000_000, 50_000_000, None)
  sv_claim_tx(
    100_000_000,
    old,
    100_000_000,
    new,
    50_000_000,
    pd,
    90_000_000,
    [fixtures.pkh_output(pd.insured, 50_000_000)],
    sv_marker_burn(),
  )
}

fn sv_invariant_s_claim_tx() -> Transaction {
  sv_without_registry_ref(sv_settle_claim_tx())
}

test sv_claim_settles_without_registry_ref() {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  sv_run_claim(old, 50_000_000, sv_invariant_s_claim_tx())
}

test sv_claim_without_registry_ref_rejects_foreign_root() fail {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  sv_run_with_roots(
    sv_foreign_root,
    sv_marker_policy,
    old,
    Claim { payout: 50_000_000 },
    sv_invariant_s_claim_tx(),
  )
}

fn sv_settle_cancel_tx() -> Transaction {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd = sv_cancel_policy_datum(
    100_000_000,
    50_000_000,
    5_000_000,
    1_700_100_000_000,
    None,
  )
  sv_cancel_tx(
    100_000_000,
    old,
    145_500_000,
    new,
    50_000_000,
    pd,
    110_000_000,
    [fixtures.pkh_output(pd.insured, 4_500_000)],
    [pd.insured],
    sv_marker_burn(),
  )
}

fn sv_invariant_s_cancel_tx() -> Transaction {
  sv_without_registry_ref(sv_settle_cancel_tx())
}

test sv_cancel_settles_without_registry_ref() {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  sv_run_cancel(old, sv_invariant_s_cancel_tx())
}

test sv_cancel_without_registry_ref_rejects_foreign_root() fail {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  sv_run_with_roots(
    sv_foreign_root,
    sv_marker_policy,
    old,
    AcceptCancellation,
    sv_invariant_s_cancel_tx(),
  )
}

fn sv_settle_expire_tx() -> Transaction {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  sv_expire_tx(
    100_000_000,
    old,
    150_000_000,
    new,
    50_000_000,
    sv_expire_policy_datum(),
    sv_marker_burn(),
  )
}

fn sv_invariant_s_expire_tx() -> Transaction {
  sv_without_registry_ref(sv_settle_expire_tx())
}

test sv_expire_settles_without_registry_ref() {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  sv_run_expire(old, sv_invariant_s_expire_tx())
}

test sv_expire_without_registry_ref_rejects_foreign_root() fail {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  sv_run_with_roots(
    sv_foreign_root,
    sv_marker_policy,
    old,
    Expire { total_returned: 50_000_000 },
    sv_invariant_s_expire_tx(),
  )
}

// --- Invariant S, SECOND custody root: `marker_policy`. The negatives above
// substitute a foreign `policy_hash` while passing the correct marker root, so
// on their own they freeze only one of the two roots. These pin the other, from
// both directions, because the root is load-bearing in both:
//
//   tx-side    — a settlement whose marker was minted under a policy that is
//                NOT the vault's is rejected, EVEN THOUGH the registry on the
//                table names that policy as the marker root. This is the drain
//                Invariant S closes: were the root governed, a hostile RuleSet
//                would let an attacker mint their own markers, wrap a
//                fabricated PolicyDatum at Script(policy_hash), and settle
//                against the pool. Marker-presence is the vault's ONLY
//                provenance signal on a policy UTxO (see the Claim arm's
//                EXT-08/09 note), so it is worth exactly as much as the policy
//                id it is measured under.
//   param-side — the honest settlement is rejected by a vault compiled with a
//                foreign marker root: the exact mirror of the three negatives
//                above, with the two roots swapped.

/// Re-denominate a value's policy markers under `sv_foreign_root`.
fn sv_swap_marker(v: assets.Value) -> assets.Value {
  let qty = assets.quantity_of(v, sv_marker_policy, policy_marker_asset_name)
  v
    |> assets.add(sv_marker_policy, policy_marker_asset_name, -qty)
    |> assets.add(sv_foreign_root, policy_marker_asset_name, qty)
}

/// The same transaction with every marker it moves at Script(policy_hash) — on
/// the policy UTxO it spends or creates, and in the mint field — issued by
/// `sv_foreign_root` instead of the vault's CORE `marker_policy`. Lovelace, datums, addresses, signatures, the feed and the
/// eligibility withdrawal are untouched, so every other leg of every arm still
/// holds: the marker root is the only thing left that can reject it.
fn sv_with_foreign_marker(tx: Transaction) -> Transaction {
  let policy_addr = sv_script_addr(sv_policy_hash)
  Transaction {
    ..tx,
    inputs: list.map(
      tx.inputs,
      fn(i) {
        if i.output.address == policy_addr {
          Input {
            ..i,
            output: Output { ..i.output, value: sv_swap_marker(i.output.value) },
          }
        } else {
          i
        }
      },
    ),
    outputs: list.map(
      tx.outputs,
      fn(o) {
        if o.address == policy_addr {
          Output { ..o, value: sv_swap_marker(o.value) }
        } else {
          o
        }
      },
    ),
    mint: sv_swap_marker(tx.mint),
  }
}

test sv_claim_rejects_foreign_marker_root() fail {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  sv_run_claim(
    old,
    50_000_000,
    sv_with_foreign_marker(sv_settle_claim_tx()),
  )
}

test sv_claim_rejects_foreign_marker_root_param() fail {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  sv_run_with_roots(
    sv_policy_hash,
    sv_foreign_root,
    old,
    Claim { payout: 50_000_000 },
    sv_invariant_s_claim_tx(),
  )
}

test sv_cancel_rejects_foreign_marker_root() fail {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  sv_run_cancel(old, sv_with_foreign_marker(sv_settle_cancel_tx()))
}

test sv_cancel_rejects_foreign_marker_root_param() fail {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  sv_run_with_roots(
    sv_policy_hash,
    sv_foreign_root,
    old,
    AcceptCancellation,
    sv_invariant_s_cancel_tx(),
  )
}

test sv_expire_rejects_foreign_marker_root() fail {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  sv_run_expire(old, sv_with_foreign_marker(sv_settle_expire_tx()))
}

test sv_expire_rejects_foreign_marker_root_param() fail {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  sv_run_with_roots(
    sv_policy_hash,
    sv_foreign_root,
    old,
    Expire { total_returned: 50_000_000 },
    sv_invariant_s_expire_tx(),
  )
}

// --- Underwrite scenarios: creates a policy OUTPUT (mints a marker into it),
// resolves a spot with freshness, and delegates the actuarial curve to the
// registry-named logic withdrawal with a redeemer bound to the pinned datum.
// spot 100M, strike 80M (20% distance >= 15% baseline); premium 5M, coverage
// 50M (10x <= 50x); 30-day term. logic_hash = the registry's current.logic_hash.

/// start_time is pinned to the tx UPPER bound (#363 N1) — base_tx's validity
/// range is [1_700_100_000_000, 1_700_100_300_000], so this is that upper bound.
const sv_uw_start: Int = 1_700_100_300_000

/// start + 30 days (term_days 30, matching sv_underwrite_terms)
const sv_uw_expiry: Int = 1_702_692_300_000

fn sv_underwrite_policy_datum() -> PolicyDatum {
  PolicyDatum {
    ..fixtures.default_policy_datum_aegis_self(),
    strike_price: 80_000_000,
    coverage_amount: 50_000_000,
    premium_paid: 20_000_000,
    start_time: sv_uw_start,
    expiry_time: sv_uw_expiry,
    oracle_nft: sv_ada_nft(),
    pool_nft: sv_pool_nft_policy,
    pool_script_hash: sv_vault_script,
    payout_address: None,
  }
}

fn sv_underwrite_terms(coverage: Int) -> PolicyTerms {
  PolicyTerms {
    risk_class: Barrier,
    strike: 80_000_000,
    premium: 20_000_000,
    coverage,
    term_days: 30,
    oracle_nft: sv_ada_nft(),
  }
}

fn sv_policy_output_raw(lovelace: Int, raw_pd: Data) -> Output {
  Output {
    address: sv_script_addr(sv_policy_hash),
    value: assets.from_lovelace(lovelace)
      |> assets.add(sv_marker_policy, policy_marker_asset_name, 1),
    datum: InlineDatum(raw_pd),
    reference_script: None,
  }
}

fn sv_policy_output(lovelace: Int, pd: PolicyDatum) -> Output {
  sv_policy_output_raw(lovelace, pd)
}

/// `pd` with the pins tail the fee-split builders write: the CORE wait for the
/// policy's class and no fallback (the mandate shorthand `sv_mandate` arms
/// none).
fn sv_pinned_pd(pd: PolicyDatum) -> Data {
  fixtures.policy_datum_with_pins(pd, claim_waiting_period_ms(pd.risk_class), #"")
}

fn sv_underwrite_tx_raw(
  vault_in: Int,
  old: VaultState,
  cont: Int,
  new: VaultState,
  policy_lovelace: Int,
  raw_pd: Data,
  spot: Int,
  elig_spot: Int,
  terms: PolicyTerms,
  marker_qty: Int,
) -> Transaction {
  let feed = fixtures.aegis_self_feed_input(
    sv_ada_nft(),
    spot,
    1_700_099_900_000,
    1_700_100_400_000,
  )
  let logic_cred = Script(sv_logic_hash)
  let elig: Data = EligibilityClaim { spot: elig_spot, policies: [terms] }
  // The fixture config's 200 bps take on the scenario's premium: the shared
  // builder routes it and grows the pool by the NET, so a caller's `cont` keeps
  // meaning "own + premium - coverage" while the fee carve stays in one place.
  let take = terms.premium * 200 / 10_000
  let base = Transaction {
    ..fixtures.base_tx(),
    inputs: [sv_vault_input(vault_in, old)],
    reference_inputs: [sv_registry_ref(), feed],
    outputs: [
      sv_cont_output(cont - take, new),
      sv_policy_output_raw(policy_lovelace, raw_pd),
      fixtures.pkh_output(sv_cfg_team_key, take),
    ],
    mint: assets.from_asset(
      sv_marker_policy,
      policy_marker_asset_name,
      marker_qty,
    ),
    withdrawals: [Pair(logic_cred, 0)],
    redeemers: [Pair(Withdraw(logic_cred), elig)],
  }
  fixtures.with_observer_attestation(
    base,
    sv_observer_hash,
    [(AegisSelf, sv_ada_nft())],
  )
}

fn sv_underwrite_tx(
  vault_in: Int,
  old: VaultState,
  cont: Int,
  new: VaultState,
  policy_lovelace: Int,
  pd: PolicyDatum,
  spot: Int,
  elig_spot: Int,
  terms: PolicyTerms,
  marker_qty: Int,
) -> Transaction {
  sv_underwrite_tx_raw(
    vault_in,
    old,
    cont,
    new,
    policy_lovelace,
    sv_pinned_pd(pd),
    spot,
    elig_spot,
    terms,
    marker_qty,
  )
}

/// Wrap a primary NFT as a no-fallback mandate entry (fixture shorthand).
fn sv_mandate(nft: ByteArray) -> OracleMandate {
  OracleMandate {
        primary_nft: nft,
        fallback_feed_id: #"",
        second_leg: TrailingLowLeg,
      }
}

/// Swap the registry reference input for one carrying `config`. Located by the
/// registry NFT, never by position, so a fixture that reorders its reference
/// inputs cannot silently stop replacing anything.
fn sv_with_registry_cfg(tx: Transaction, config: UnderwriteConfig) -> Transaction {
  let others =
    list.filter(
      tx.reference_inputs,
      fn(i) {
        assets.quantity_of(
          i.output.value,
          sv_registry_nft_policy,
          sv_registry_nft_name,
        ) == 0
      },
    )
  Transaction { ..tx, reference_inputs: [sv_registry_ref_cfg(config), ..others] }
}

/// The Depeg scenarios mandate the depeg feed instead of the ADA feed.
fn sv_with_depeg_cfg(tx: Transaction) -> Transaction {
  sv_with_registry_cfg(tx, sv_config([sv_mandate(sv_depeg_nft())]))
}

/// Underwrite reads its mandate out of the GOVERNED config: the vault has no
/// mandate parameter left to pass.
fn sv_run_underwrite(
  old: VaultState,
  coverage: Int,
  premium: Int,
  tx: Transaction,
) -> Bool {
  pool_vault.spend(
    sv_pool_nft_policy,
    sv_pool_nft_name,
    sv_lp_policy,
    sv_policy_hash,
    sv_marker_policy,
    sv_observer_hash,
    sv_registry_nft_policy,
    sv_registry_nft_name,
    Some(old),
    Underwrite { coverage, premium },
    sv_own_ref(),
    tx,
  )
}

/// The Underwrite tx with a CUSTOM validity range — for the tx-now anchoring
/// tests (#363 N1/N3). Everything else matches the green path.
fn sv_underwrite_tx_range(
  pd: PolicyDatum,
  old: VaultState,
  new: VaultState,
  lo: Int,
  hi: Int,
) -> Transaction {
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    pd,
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  Transaction { ..tx, validity_range: fixtures.finite_range(lo, hi) }
}

// [#363 N1 CRITICAL] The Underwrite window MUST be anchored to tx-now. The
// ledger only requires invalidBefore <= currentSlot, so a lower bound years in
// the past is a VALID tx; the Barrier freshness legs are both UPPER bounds on
// tx_lower and bound nothing below. A back-dated start_time then retro-captures
// an already-printed 12h low (barrier_touched's
// `min_price_12h <= strike && low_observed_at >= start_time`) => full coverage
// for ~2% premium, repeatable. Same class as the #380 mainnet back-date drain.
test sv_underwrite_rejects_backdated_start() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  // tx_lower back-dated ~27h behind the feed; start_time pinned to it.
  let back = 1_700_000_000_000
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: back,
    expiry_time: back + 2_592_000_000,
  }
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_underwrite_tx_range(pd, old, new, back, 1_700_100_300_000),
  )
}

/// [#363 F1] The Underwrite tx with a FULL 5-key feed — spot AND a real
/// trailing-12h low with its own observation time. `sv_underwrite_tx` builds a
/// 3-key feed, where `min_price_12h` defaults to spot and `low_observed_at` to
/// `created_ms`; under those defaults `barrier_touched`'s retro disjunct cannot
/// fire independently of the spot disjunct, so the back-date retro-capture
/// attack was INEXPRESSIBLE here.
fn sv_underwrite_tx_retro(
  pd: PolicyDatum,
  old: VaultState,
  new: VaultState,
  lo: Int,
  hi: Int,
  spot: Int,
  observed_at: Int,
  min_price_12h: Int,
  low_observed_at: Int,
) -> Transaction {
  let feed = fixtures.aegis_self_feed_input_full(
    sv_ada_nft(),
    spot,
    observed_at,
    1_700_100_400_000,
    min_price_12h,
    low_observed_at,
  )
  let logic_cred = Script(sv_logic_hash)
  let elig: Data = EligibilityClaim {
    spot,
    policies: [sv_underwrite_terms(50_000_000)],
  }
  let base = Transaction {
    ..fixtures.base_tx(),
    inputs: [sv_vault_input(300_000_000, old)],
    reference_inputs: [sv_registry_ref(), feed],
    outputs: [
      sv_cont_output(269_600_000, new),
      sv_policy_output_raw(50_000_000, sv_pinned_pd(pd)),
      fixtures.pkh_output(sv_cfg_team_key, 400_000),
    ],
    mint: assets.from_asset(sv_marker_policy, policy_marker_asset_name, 1),
    withdrawals: [Pair(logic_cred, 0)],
    redeemers: [Pair(Withdraw(logic_cred), elig)],
  }
  let tx = fixtures.with_observer_attestation(
    base,
    sv_observer_hash,
    [(AegisSelf, sv_ada_nft())],
  )
  Transaction { ..tx, validity_range: fixtures.finite_range(lo, hi) }
}

/// [#363 R4] Underwrite tx with the feed's `valid_until` parameterised, so the
/// `tx_upper <= price.valid_until` freshness leg can be exercised. Every other
/// fixture hardcodes a valid_until far past tx_upper, leaving that leg untested.
fn sv_underwrite_tx_expiring_feed(
  pd: PolicyDatum,
  old: VaultState,
  new: VaultState,
  lo: Int,
  hi: Int,
  observed_at: Int,
  valid_until: Int,
) -> Transaction {
  let feed = fixtures.aegis_self_feed_input(
    sv_ada_nft(),
    100_000_000,
    observed_at,
    valid_until,
  )
  let logic_cred = Script(sv_logic_hash)
  let elig: Data = EligibilityClaim {
    spot: 100_000_000,
    policies: [sv_underwrite_terms(50_000_000)],
  }
  let base = Transaction {
    ..fixtures.base_tx(),
    inputs: [sv_vault_input(300_000_000, old)],
    reference_inputs: [sv_registry_ref(), feed],
    outputs: [
      sv_cont_output(269_600_000, new),
      sv_policy_output_raw(50_000_000, sv_pinned_pd(pd)),
      fixtures.pkh_output(sv_cfg_team_key, 400_000),
    ],
    mint: assets.from_asset(sv_marker_policy, policy_marker_asset_name, 1),
    withdrawals: [Pair(logic_cred, 0)],
    redeemers: [Pair(Withdraw(logic_cred), elig)],
  }
  let tx = fixtures.with_observer_attestation(
    base,
    sv_observer_hash,
    [(AegisSelf, sv_ada_nft())],
  )
  Transaction { ..tx, validity_range: fixtures.finite_range(lo, hi) }
}

// [#363 F1 CRITICAL] THE back-date retro-capture drain, reproduced end to end.
//
// This is the #380 class: buy cover whose start predates a low that has ALREADY
// PRINTED, then claim it immediately. barrier_touched pays on
// `min_price_12h <= strike && low_observed_at >= start_time`, so a start_time
// dragged behind an existing low is full coverage for the ~2% ratio-floor
// premium, repeatable.
//
// The span here is DELIBERATELY LEGAL (900_000 ms, inside the 1_200_000 ms
// ceiling) so the span leg cannot be what rejects it. That distinguishes this
// test from `sv_underwrite_rejects_backdated_start` above, whose span is
// 100_300_000 ms — ~84x over the ceiling — so that test rejects on SPAN and has
// never actually exercised the anchor at all.
//
// start_time sits exactly at tx_lower: the best an attacker can do under the
// OLD `start_time >= tx_lower` predicate, and legal under it. It must be
// REJECTED by `start_time >= tx_upper`.
test sv_underwrite_rejects_backdated_start_within_legal_span() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = 1_700_100_300_000
  let lo = hi - 900_000
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: lo,
    expiry_time: lo + 2_592_000_000,
  }
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_underwrite_tx_retro(
      pd,
      old,
      new,
      lo,
      hi,
      // spot is healthy at purchase — 100.0, strike 80.0 is 2000 bps out,
      // clearing min_strike_distance_bps. Nothing about the SPOT is suspicious.
      100_000_000,
      1_700_099_500_000,
      // ...but a 70.0 low ALREADY printed, below the 80.0 strike,
      70_000_000,
      // at a moment the back-dated start_time reaches back to capture.
      1_700_099_450_000,
    ),
  )
}

// The honest twin: same feed shape, same already-printed low BEFORE the policy
// starts, but an honest start_time at/after tx_upper. It must be ACCEPTED — the
// low is then strictly before coverage begins, so barrier_touched's retro
// disjunct cannot reach it and the policy is a normal forward-looking barrier.
// This is what proves the anchor rejects the attack rather than the feed shape.
//
// [#391 R2 F2a] The low is ABOVE the 80.0 strike. It used to be 70.0, which the
// vault now refuses to SELL against at all (`resolved_min_12h > strike`) — so
// with the old value this test would have proved the trailing-low gate rather
// than the window anchor. The twin below back-dates this identical feed, so
// start_time is the ONLY difference between accept and reject.
//
// [#403 FIX 1] ...and the low is 95.0 rather than 85.0, because Underwrite now
// measures strike distance against `min(spot, trailing_low)`. At 85.0 the 80.0
// strike is 588 bps out and the MIN LEG refuses the sale, which would have made
// this pair prove the min leg instead of the anchor. At 95.0 it is 1578 bps
// out, clear of the 1500 bps guard on either leg, so the anchor is once again
// the only thing separating the twins.
test sv_underwrite_accepts_honest_start_with_prior_low() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = 1_700_100_300_000
  let lo = hi - 900_000
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: hi,
    expiry_time: hi + 2_592_000_000,
  }
  sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_underwrite_tx_retro(
      pd,
      old,
      new,
      lo,
      hi,
      100_000_000,
      1_700_099_900_000,
      95_000_000,
      1_700_099_450_000,
    ),
  )
}

// [#391 R2 F2a] The minimal pair for the window anchor: byte-identical to the
// test above except `start_time`, which is dragged behind the already-printed
// low. Nothing about the FEED distinguishes them, so the anchor is the only leg
// that can be refusing this one.
test sv_underwrite_rejects_backdated_start_with_untouched_prior_low() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = 1_700_100_300_000
  let lo = hi - 900_000
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: 1_700_099_400_000,
    expiry_time: 1_700_099_400_000 + 2_592_000_000,
  }
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_underwrite_tx_retro(
      pd,
      old,
      new,
      lo,
      hi,
      100_000_000,
      1_700_099_900_000,
      95_000_000,
      1_700_099_450_000,
    ),
  )
}

// `>=` is not a disguised `==`: an honest builder over-shoots start_time past
// tx_upper (it cannot reproduce the ledger's slot->POSIX translation exactly),
// and that MUST be accepted. This is the leg whose absence made the equality a
// total DoS on the main money path.
test sv_underwrite_accepts_start_above_tx_upper() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = 1_700_100_300_000
  let lo = hi - 900_000
  let start = hi + 120_000
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: start,
    expiry_time: start + 2_592_000_000,
  }
  sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_underwrite_tx_retro(
      pd,
      old,
      new,
      lo,
      hi,
      100_000_000,
      // [#391 R2 F5b] observed 100_000 ms before TX_UPPER, so the print does not
      // post-date the latest instant the ledger can include this tx — and
      // 220_000 ms before coverage starts, inside the 600_000 ms Barrier budget.
      hi - 100_000,
      95_000_000,
      1_700_099_450_000,
    ),
  )
}

// [#363 F2] The spot must be fresh AT THE INSTANT COVERAGE BEGINS, not merely
// at tx_lower. One ms past the Barrier budget rejects, with every other leg
// green — so only the freshness leg can be doing the rejecting.
test sv_underwrite_rejects_stale_spot_at_start_barrier() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = 1_700_100_300_000
  let lo = hi - 900_000
  let start = hi + 120_000
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: start,
    expiry_time: start + 2_592_000_000,
  }
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_underwrite_tx_retro(
      pd,
      old,
      new,
      lo,
      hi,
      100_000_000,
      // 600_001 ms of age at coverage start — one ms over Barrier's budget
      start - 600_001,
      // above the 80.0 strike, so the trailing-low gate cannot be the refuser
      95_000_000,
      1_700_099_450_000,
    ),
  )
}

// [#363 N1] The span ceiling must apply to BARRIER too (it originally landed
// inside the `Depeg` arm and never ran for Barrier). Window is otherwise valid
// (start_time >= tx_upper, feed fresh) so ONLY the span can reject this.
test sv_underwrite_rejects_wide_span_barrier() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = 1_700_100_300_000
  let lo = hi - 1_300_000
  // 21m40s span > the 20m max_underwrite_span_ms
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: hi,
    expiry_time: hi + 2_592_000_000,
  }
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_underwrite_tx_range(pd, old, new, lo, hi),
  )
}

/// First depeg-eligible feed of the ACTIVE network (also canonical — pinned by
/// the depeg_feeds_are_canonical test in types.ak).
fn sv_depeg_nft() -> ByteArray {
  expect [nft, ..] = depeg_eligible_nfts
  nft
}

fn sv_depeg_policy_datum() -> PolicyDatum {
  PolicyDatum {
    ..sv_underwrite_policy_datum(),
    risk_class: Depeg,
    strike_price: 900_000,
    oracle_nft: sv_depeg_nft(),
  }
}

fn sv_depeg_underwrite_tx(
  old: VaultState,
  new: VaultState,
  spot: Int,
) -> Transaction {
  // [#363 F2] Observed 200_000 ms before sv_uw_start — inside the 300_000 ms
  // Depeg budget. The Barrier fixtures publish at 1_700_099_900_000 (400_000 ms
  // of age), fine under Barrier's 600_000 ms budget but deliberately too stale
  // for Depeg; that asymmetry is the point of the per-class split, so this
  // fixture carries its own timestamp rather than sharing the Barrier one.
  sv_depeg_underwrite_tx_at(old, new, spot, sv_uw_start - 200_000)
}

/// [#363 R4] `sv_depeg_underwrite_tx` with the feed's `observed_at`
/// PARAMETERISED. Without this the Depeg spot-age budget had no upper pin at
/// all: widening `max_spot_age_ms(Depeg)` from 300_000 to 86_400_000 (288x)
/// left the entire suite green.
fn sv_depeg_underwrite_tx_at(
  old: VaultState,
  new: VaultState,
  spot: Int,
  observed_at: Int,
) -> Transaction {
  let feed = fixtures.aegis_self_feed_input(
    sv_depeg_nft(),
    spot,
    observed_at,
    1_700_100_400_000,
  )
  let logic_cred = Script(sv_logic_hash)
  let terms = PolicyTerms {
    ..sv_underwrite_terms(50_000_000),
    risk_class: Depeg,
    strike: 900_000,
    oracle_nft: sv_depeg_nft(),
  }
  let elig: Data = EligibilityClaim { spot, policies: [terms] }
  let base = Transaction {
    ..fixtures.base_tx(),
    inputs: [sv_vault_input(300_000_000, old)],
    reference_inputs: [sv_registry_ref(), feed],
    outputs: [
      sv_cont_output(269_600_000, new),
      sv_policy_output_raw(50_000_000, sv_pinned_pd(sv_depeg_policy_datum())),
      fixtures.pkh_output(sv_cfg_team_key, 400_000),
    ],
    mint: assets.from_asset(sv_marker_policy, policy_marker_asset_name, 1),
    withdrawals: [Pair(logic_cred, 0)],
    redeemers: [Pair(Withdraw(logic_cred), elig)],
  }
  fixtures.with_observer_attestation(
    base,
    sv_observer_hash,
    [(AegisSelf, sv_depeg_nft())],
  )
}

// [#363 N2 CRITICAL] Depeg Underwrite was SPOT-BLIND (the arm resolved
// `(0, True)` and never saw a price), so cover could be bought while the peg was
// ALREADY broken at or below the strike and claimed in the very next block —
// barrier_touched's `spot <= strike` has no time gate. Buying insurance during
// the fire, at the 50x ratio cap, chained until capacity exhausts.
test sv_underwrite_rejects_depeg_already_broken() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  // strike 0.90 with the peg ALREADY at 0.89 -> already in the money
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_with_depeg_cfg(sv_depeg_underwrite_tx(old, new, 890_000)),
  )
}

test sv_underwrite_depeg_healthy_peg_accepted() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  // healthy peg 1.00 vs strike 0.90 -> 1000 bps >= the 200 bps depeg margin
  sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_with_depeg_cfg(sv_depeg_underwrite_tx(old, new, 1_000_000)),
  )
}

// [#363 R4] The Depeg half of the per-class spot-age split had NO upper pin.
// `max_spot_age_ms(Depeg)` could be widened from 300_000 to 86_400_000 — 288x,
// a 24-HOUR staleness budget — with the entire 797-test suite still green. The
// only Depeg fixture published at a fixed 200_000 ms of age, which constrains
// the constant from BELOW only, so ef14cb1's claim that "the split is
// load-bearing" was true of the fixture and false of the harness.
//
// This matters because it is exactly the N2/F3 drain class: `barrier_touched`'s
// `spot <= strike` disjunct has no time gate, so cover underwritten against a
// stale healthy-peg reading is claimable in the next block once the peg has
// actually broken. `depeg_peg_is_healthy` cannot help — it judges that same
// stale spot. A day-old $1.00 reading of a coin now at $0.50 would sell cover
// at the 50x ratio cap, repeatable to capacity.
test sv_underwrite_accepts_spot_at_budget_edge_depeg() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  // exactly AT the 300_000 ms budget — the boundary must remain buyable
  sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_with_depeg_cfg(
      sv_depeg_underwrite_tx_at(old, new, 1_000_000, sv_uw_start - 300_000),
    ),
  )
}

test sv_underwrite_rejects_stale_spot_at_start_depeg() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  // one ms past the budget, healthy peg and in-band strike, so ONLY the
  // freshness leg can reject this
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_with_depeg_cfg(
      sv_depeg_underwrite_tx_at(old, new, 1_000_000, sv_uw_start - 300_001),
    ),
  )
}

// [#363 R4] Property pins for the two window legs that had no validator-level
// test. Both properties ARE enforced today, but by a DIFFERENT conjunct than
// the one that names them, so deleting the named leg changed nothing:
//
//   * `pd.expiry_time > pd.start_time` in window_ok is redundant with
//     underwrite_baseline_ok's `term_ms > 0` (and now `term_ms >=
//     min_policy_term_ms`), since term_ms IS expiry - start. Deleting it left
//     814/814 green. That is defense-in-depth, not a hole — but nothing pinned
//     the PROPERTY at this level, so a future edit to the baseline could remove
//     the real guard while the redundant leg kept the suite quiet.
//
// These assert the property, not the leg, so they hold whichever conjunct is
// doing the work.
test sv_underwrite_rejects_zero_length_policy_window() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = 1_700_100_300_000
  let lo = hi - 900_000
  let start = hi + 120_000
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: start,
    // expiry == start: a zero-length policy, expiring the instant it begins
    expiry_time: start,
  }
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_underwrite_tx_range(pd, old, new, lo, hi),
  )
}

test sv_underwrite_rejects_inverted_policy_window() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = 1_700_100_300_000
  let lo = hi - 900_000
  let start = hi + 120_000
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: start,
    // expiry BEFORE start — a negative term
    expiry_time: start - 86_400_000,
  }
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_underwrite_tx_range(pd, old, new, lo, hi),
  )
}

// The feed's own horizon must bound the tx: a reading whose `valid_until`
// precedes tx_upper means the policy is written against a price the publisher
// has already declared expired.
test sv_underwrite_rejects_tx_upper_past_feed_validity() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = 1_700_100_300_000
  let lo = hi - 900_000
  let start = hi + 120_000
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: start,
    expiry_time: start + 2_592_000_000,
  }
  // feed expires one ms BEFORE tx_upper; observed_at stays inside the Barrier
  // budget so only the valid_until leg can reject.
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_underwrite_tx_expiring_feed(
      pd,
      old,
      new,
      lo,
      hi,
      start - 100_000,
      hi - 1,
    ),
  )
}

test sv_underwrite_accepts_feed_valid_through_tx_upper() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = 1_700_100_300_000
  let lo = hi - 900_000
  let start = hi + 120_000
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: start,
    expiry_time: start + 2_592_000_000,
  }
  // valid_until exactly AT tx_upper is the boundary — must remain buyable.
  // [#391 R2 F5b] observed_at sits before tx_upper: a print stamped after the
  // tx's own deadline is not a reading this transaction could have seen.
  sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_underwrite_tx_expiring_feed(pd, old, new, lo, hi, hi - 100_000, hi),
  )
}

test sv_underwrite_green_path() {
  // own 300M + premium 5M - coverage 50M -> cont 255M; active_coverage 0->50M.
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  sv_run_underwrite(old, 50_000_000, 20_000_000, tx)
}

// ===========================================================================
// [V8.2 FEE] The protocol take. `cfg.fee.take_bps` of every premium routes to
// the governed `team_address`; the NET premium is what grows the pool and what
// premium adequacy is judged on. The non-vacuity anchor for every refusal in
// this block is `sv_underwrite_green_path`, which pays the take and sells.
// ===========================================================================

/// An Underwrite whose OUTPUTS are supplied verbatim — immune to the fee-aware
/// shared builder, so it can state the pre-fee shapes the vault must refuse.
/// The fixture config's take at 200 bps of the 20M premium is 400_000.
fn fee_uw_exploit_tx(cont: Int, extra_outs: List<Output>) -> Transaction {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let raw_pd =
    fixtures.policy_datum_with_pins(
      sv_underwrite_policy_datum(),
      claim_waiting_period_ms(Barrier),
      #"",
    )
  let base =
    sv_underwrite_tx_raw(
      300_000_000,
      old,
      cont,
      new,
      50_000_000,
      raw_pd,
      100_000_000,
      100_000_000,
      sv_underwrite_terms(50_000_000),
      1,
    )
  Transaction {
    ..base,
    outputs: list.concat(
      [sv_cont_output(cont, new), sv_policy_output_raw(50_000_000, raw_pd)],
      extra_outs,
    ),
  }
}

fn fee_uw_run(tx: Transaction) -> Bool {
  sv_run_underwrite(sv_state(1000, 0, 10_000_000), 50_000_000, 20_000_000, tx)
}

test fee_uw_rejects_a_sale_keeping_the_full_premium() {
  // THE FEE SKIM, isolated to `team_paid`: the pool grows by exactly the net
  // (cont = own 300M + net 19.6M - coverage 50M) so the value equation holds,
  // while the 400_000 take reaches the governed sink NOWHERE — the builder
  // simply pockets it. Only `team_paid` can refuse this transaction.
  !fee_uw_run(fee_uw_exploit_tx(269_600_000, []))
}

/// The green shape with the PREMIUM parameterised: datum, terms, redeemer and
/// the continuation all carry it, so adequacy is the only leg that can decide.
fn fee_uw_premium_run(premium: Int) -> Bool {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let pd = PolicyDatum { ..sv_underwrite_policy_datum(), premium_paid: premium }
  let terms = PolicyTerms { ..sv_underwrite_terms(50_000_000), premium }
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    250_000_000 + premium,
    new,
    50_000_000,
    pd,
    100_000_000,
    100_000_000,
    terms,
    1,
  )
  sv_run_underwrite(old, 50_000_000, premium, tx)
}

test fee_uw_rejects_a_premium_adequate_only_gross() {
  // Premium 2_000_000 sits EXACTLY on the floor, so the GROSS is adequate —
  // but the pool only ever receives the net 1_960_000, which is under it.
  // Adequacy is judged on what the pool receives. The in-test anchor nets
  // 2_009_000 from a 2_050_000 premium and still sells.
  and {
    fee_uw_premium_run(2_050_000),
    !fee_uw_premium_run(2_000_000),
  }
}

test fee_uw_rejects_full_premium_kept_while_the_take_is_paid() {
  // The take IS routed — from thin air — while the pool still keeps the FULL
  // premium. Only the net-growth slot of `underwrite_ok` can refuse this one:
  // team_paid holds, and every other conjunct is the green path.
  !fee_uw_run(
    fee_uw_exploit_tx(
      270_000_000,
      [fixtures.pkh_output(sv_cfg_team_key, 400_000)],
    ),
  )
}

/// [V8.2 G10] The registry UTxO is born of an UNVALIDATED payment — no script
/// runs when a UTxO is CREATED — so the epoch-0 config has passed
/// `config_within_rails` exactly never, and `registry_v2` re-checks only what a
/// transition writes. The vault therefore enforces the rails AT THE POINT OF
/// USE.
///
/// An `epoch >= 1` ratchet is not a cheaper substitute and must not be taken as
/// one: §3 rules that the vault trusts the NFT and never an address or a hash
/// of the registry validator, so a hand-written UTxO carrying the NFT, epoch 5
/// and a hostile config is indistinguishable from an enacted one. Validating at
/// MINT time is impossible rather than merely awkward — the mint policy would
/// have to know `registry_v2`'s hash while `registry_v2` takes the mint policy
/// id as a parameter, which is the const cycle that has deadlocked a deploy here.
test sv_underwrite_rejects_out_of_rail_config() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let cfg = sv_config([sv_mandate(sv_ada_nft())])
  let b = cfg.budgets
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  and {
    // a book cap past the rail
    !sv_run_underwrite(
      old,
      50_000_000,
      20_000_000,
      sv_with_registry_cfg(
        tx,
        UnderwriteConfig {
          ..cfg,
          budgets: Budgets { ..b, utilisation_bps: 9_999 },
        },
      ),
    ),
    // a hundred-year spot-age budget
    !sv_run_underwrite(
      old,
      50_000_000,
      20_000_000,
      sv_with_registry_cfg(
        tx,
        UnderwriteConfig {
          ..cfg,
          budgets: Budgets { ..b, spot_age_barrier_ms: 3_155_760_000_000 },
        },
      ),
    ),
    // and a take of the whole premium
    !sv_run_underwrite(
      old,
      50_000_000,
      20_000_000,
      sv_with_registry_cfg(
        tx,
        UnderwriteConfig { ..cfg, fee: Fee { ..cfg.fee, take_bps: 10_000 } },
      ),
    ),
  }
}

/// The fee sink is the one rail `registry_v2` structurally cannot carry: it
/// takes the NFT policy and name and must never learn the vault's hash, or the
/// two scripts' hashes become mutually dependent. Underwrite is where the hash
/// is a fact rather than a parameter, so this is where the check lands.
test sv_underwrite_rejects_the_vault_as_fee_sink() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let cfg = sv_config([sv_mandate(sv_ada_nft())])
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_with_registry_cfg(
      tx,
      UnderwriteConfig {
        ..cfg,
        fee: Fee {
          ..cfg.fee,
          team_address: sv_script_addr(sv_vault_script),
        },
      },
    ),
  )
}

/// A registry UTxO parked AT the vault address would be authenticated by the
/// NFT like any other, and its lovelace would count as pool backing while its
/// datum governed new business. The vault refuses to read one.
test sv_underwrite_rejects_registry_co_located_at_the_vault() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  let at_vault =
    Input {
      ..sv_registry_ref(),
      output: Output {
        ..sv_registry_ref().output,
        address: sv_script_addr(sv_vault_script),
      },
    }
  let others =
    list.filter(
      tx.reference_inputs,
      fn(i) {
        assets.quantity_of(
          i.output.value,
          sv_registry_nft_policy,
          sv_registry_nft_name,
        ) == 0
      },
    )
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    Transaction { ..tx, reference_inputs: [at_vault, ..others] },
  )
}

// ===========================================================================
// [V8.2 G10 red-team CRITICAL] The price trust root, and what a governed
// resolver leaf is worth.
//
// `attested_price` derives 100% of a reading's genuineness from the IDENTITY of
// the script whose redeemer it reads: it takes `Script(h)`, requires a
// withdrawal under it, and reads the Price straight out of that redeemer. A
// stake script the attacker controls answers True for its own withdrawal-0 and
// writes whatever it likes there. So the ONLY thing standing between an
// Underwrite and a fabricated print is which `h` the vault resolves.
//
// While Underwrite resolved `cfg.observer_hash`, that `h` came out of the
// registry DATUM, bounded by one conjunct — `bytearray.length(...) == 28`. A
// hostile-but-in-rails config therefore made the Underwrite spot, its
// `observed_at` and its `valid_until` entirely BUYER-AUTHORED, while Claim
// (:590) and AcceptCancellation (:725) went on resolving the CORE compile
// parameter. Nothing bound the two equal.
//
// The three tests below are the whole argument. The control fixes what an
// HONEST observer refuses; the fabrication test is the drain; the third is the
// conjunct that makes the governed field mean the compiled leaf rather than be
// silently ignored, so no config can mint a policy against a leaf settlement
// will not honour.
// ===========================================================================

/// A 28-byte resolver leaf that is NOT the vault's compile parameter — an
/// always-true stake script the attacker registered. Inside every rail
/// `config_within_rails` measures.
const rt_rogue_observer: ByteArray =
  #"e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"

/// The real print at purchase: ADA at 85.0, against an 84.0 strike. 117 bps of
/// distance — a barrier that fires on a 1.2% dip.
const rt_real_spot: Int = 85_000_000

/// What the rogue leaf says instead: 100.0, which dresses the same 84.0 strike
/// up as 1600 bps out of the money and clears the 1500 bps near-money floor.
const rt_fabricated_spot: Int = 100_000_000

const rt_near_money_strike: Int = 84_000_000

fn rt_config_observed_by(hash: ByteArray) -> UnderwriteConfig {
  UnderwriteConfig {
    ..sv_config([sv_mandate(sv_ada_nft())]),
    observer_hash: hash,
  }
}

/// The fabricated Price: the value is the lie, and everything else matches the
/// honest feed exactly, so the freshness legs cannot be what decides the test.
fn rt_forged_price(value: Int) -> oracle_types.Price {
  oracle_types.Price {
    value,
    observed_at: 1_700_099_900_000,
    valid_until: 1_700_100_400_000,
    min_price_12h: value,
    low_observed_at: 1_700_099_900_000,
    confidence_present: False,
  }
}

/// The near-money Underwrite, priced against a REAL 85.0 print. Everything
/// about this transaction is honest.
fn rt_near_money_tx(old: VaultState, new: VaultState, elig_spot: Int) -> Transaction {
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    strike_price: rt_near_money_strike,
  }
  let terms = PolicyTerms {
    ..sv_underwrite_terms(50_000_000),
    strike: rt_near_money_strike,
  }
  sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    pd,
    rt_real_spot,
    elig_spot,
    terms,
    1,
  )
}

/// CONTROL. Under the honest observer the same near-money policy is refused on
/// `underwrite_baseline_ok`'s 15% floor: (85.0 - 84.0) / 85.0 = 117 bps. This
/// is what the fabrication buys, and it must stay green both before and after
/// the fix — otherwise the fabrication test proves only that something changed.
test rt_control_near_money_refused_under_honest_observer() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    rt_near_money_tx(old, new, rt_real_spot),
  )
}

/// THE DRAIN. The config names the rogue leaf; the rogue leaf prints 100.0; the
/// honest observer is in the very same transaction attesting the real 85.0 and
/// the vault does not look at it. Pool pays 100% of coverage on a 1.2% dip, for
/// the ~2% ratio-floor premium, repeatable to the utilisation cap.
test rt_governed_observer_fabricates_the_underwrite_spot() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let honest = rt_near_money_tx(old, new, rt_fabricated_spot)
  let rogue = sv_with_registry_cfg(honest, rt_config_observed_by(rt_rogue_observer))
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    fixtures.with_forged_attestation(
      rogue,
      rt_rogue_observer,
      AegisSelf,
      sv_ada_nft(),
      rt_forged_price(rt_fabricated_spot),
    ),
  )
}

/// The conjunct, isolated. Nothing here is fabricated — the rogue leaf attests
/// the same 100.0 the reference input carries, and the policy is the ordinary
/// green-path one. The only defect is that the config names a leaf the
/// SETTLEMENT arms will never resolve, so a policy minted under it would be
/// unclaimable. It must fail CLOSED at the point of use.
test rt_underwrite_refuses_a_config_naming_a_non_core_observer() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  let rogue = sv_with_registry_cfg(tx, rt_config_observed_by(rt_rogue_observer))
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    fixtures.with_forged_attestation(
      rogue,
      rt_rogue_observer,
      AegisSelf,
      sv_ada_nft(),
      rt_forged_price(100_000_000),
    ),
  )
}

/// The substitution, isolated — and the reason it is not redundant with the
/// conjunct above.
///
/// `attested_price` ABORTS rather than returns False when the named leaf has no
/// withdrawal: `expect True = list.any(withdrawals, ...)`. So while the arm
/// resolved `cfg.observer_hash`, a divergent config did not merely reject new
/// business, it made Underwrite exit with no diagnostic, no `and{}` short-
/// circuit and the fee already spent — and it did so BEFORE `config_bound` was
/// ever evaluated, which is what makes an order-of-evaluation argument the only
/// thing holding the hole shut.
///
/// Reading the CORE parameter takes the governed field out of price resolution
/// entirely, so the same transaction lands on `config_bound` and is REJECTED.
/// The rogue leaf appears in this transaction only as a name in the config;
/// nothing withdraws under it.
test rt_underwrite_rejects_a_divergent_config_rather_than_aborting() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  !sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_with_registry_cfg(tx, rt_config_observed_by(rt_rogue_observer)),
  )
}

/// Underwrite decodes the FRESH policy output, so "legacy" here is a tx
/// builder that has not learned `settlement_pins` yet: it writes the
/// seventeen-field constr. Pins are Option-tail and not required, so the bind
/// must succeed with pins defaulted to None — a strict-arity decode would halt
/// all new business the moment the field shipped. Byte-for-byte the same
/// transaction as `sv_underwrite_green_path`; only the datum's arity differs.
test sv_underwrite_accepts_pre_pins_17_field_policy() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let tx = sv_underwrite_tx_raw(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    fixtures.pre_pins_datum(sv_underwrite_policy_datum()),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  sv_run_underwrite(old, 50_000_000, 20_000_000, tx)
}

test sv_underwrite_rejects_spot_mismatch() {
  // the logic redeemer's spot != the vault-resolved spot -> spot_bound False
  // (a hostile logic cannot judge on a fabricated spot; CRITICAL-2).
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    99_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  !sv_run_underwrite(old, 50_000_000, 20_000_000, tx)
}

test sv_underwrite_rejects_terms_mismatch() {
  // the logic judged DIFFERENT terms than the datum pins -> terms_bound False.
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(40_000_000),
    1,
  )
  !sv_run_underwrite(old, 50_000_000, 20_000_000, tx)
}

test sv_underwrite_rejects_coverage_inflation() {
  // redeemer coverage (40M) != the pinned datum coverage (50M) -> pd_bound False.
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 40_000_000, 10_000_000)
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  !sv_run_underwrite(old, 40_000_000, 20_000_000, tx)
}

test sv_underwrite_rejects_marker_over_mint() {
  // mint 2 markers -> underwrite_ok marker_minted==1 leg False.
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    2,
  )
  !sv_run_underwrite(old, 50_000_000, 20_000_000, tx)
}

/// [Invariant S, second root] Underwrite is the ONLY arm that still reads the
/// registry, so it is the only arm where a governed marker root could re-enter
/// — it takes the logic hash and the GOVERNED config from that datum, and no
/// custody root. Here the whole green path is minted under a foreign root
/// (`sv_foreign_root`) instead of the vault's CORE `marker_policy`: the marker
/// the buyer would carry to Claim must be one this vault's own parameter
/// authorises, or the policy is unsettleable and the coverage is reserved
/// against nothing.
test sv_underwrite_rejects_foreign_marker_root() fail {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  sv_run_underwrite(old, 50_000_000, 20_000_000, sv_with_foreign_marker(tx))
}

test sv_underwrite_rejects_out_of_mandate() {
  // the feed is NOT among the governed mandates -> in_mandate False ->
  // baseline False (the #327 pool mandate gate the vault enforces itself).
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  !sv_run_underwrite(old, 50_000_000, 20_000_000, sv_with_registry_cfg(tx, sv_config([])))
}

// ===========================================================================
// [V8.2 H1] Underwrite refuses a PULL-oracle provider outright.
//
// Pyth Lazer is a PULL oracle: `pyth.get_updates` reads its signed payload out
// of a WITHDRAWAL REDEEMER the transaction builder supplies. At Underwrite the
// BUYER builds the transaction, so a Pyth-provider policy hands the buyer the
// spot that `underwrite_baseline_ok` measures strike distance against — and at
// Underwrite the buyer wants that print HIGH, which dresses a near-money
// barrier up as a 15%-out-of-the-money one. AegisSelf resolves from a
// reference input pinned to the publisher's payment credential, which the
// buyer cannot author; that asymmetry, not the feed's identity, is what makes
// one admissible here and the other not.
//
// Until V8.2 nothing in the arm tested the provider. Pyth was excluded only
// because `pyth_canonical_feed_ids` holds 1-byte Lazer ids while the mandate
// primaries are 28-byte policy ids, so `in_mandate` and `canonical_feed` could
// not both hold. The mandate list is OPERATOR-AUTHORED — a ceremony parameter
// when it was compiled in, a governed datum now — and the vault does not
// validate its shape, so one mistyped row (a feed-id in the primary column)
// makes in_mandate, canonical_feed AND underwrite_baseline_ok all True at
// once. This test IS that ceremony: the
// mandate names #"02", the datum names Pyth, and the Lazer machinery is real
// (State NFT reference input + the signed payload in the withdraw redeemer +
// a genuine observer attestation over it).
// ===========================================================================

/// The Lazer payload's own timestamp (feed 2, `pyth_fixtures`).
const sv_uw_pyth_obs: Int = 1_772_613_309_000

/// tx_upper, and therefore `start_time` (#363 N1 anchors one to the other).
/// 300s past the reading — inside the 600s Barrier spot-age budget.
const sv_uw_pyth_start: Int = 1_772_613_609_000

/// The mistyped ceremony: a Pyth feed-id sitting in the PRIMARY column.
fn sv_uw_pyth_mandates() -> List<OracleMandate> {
  [OracleMandate {
        primary_nft: #"02",
        fallback_feed_id: #"",
        second_leg: TrailingLowLeg,
      }]
}

fn sv_underwrite_pyth_tx() -> Transaction {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    // 2051 bps under the feed-2 reading (2_013_003_316) — clears the 1500 bps
    // Barrier strike-distance baseline, so nothing but the provider can reject.
    strike_price: 1_600_000_000,
    start_time: sv_uw_pyth_start,
    expiry_time: sv_uw_pyth_start + 2_592_000_000,
    oracle_nft: #"02",
    oracle_provider: Pyth,
  }
  let terms = PolicyTerms {
    risk_class: Barrier,
    strike: 1_600_000_000,
    premium: 20_000_000,
    coverage: 50_000_000,
    term_days: 30,
    oracle_nft: #"02",
  }
  let logic_cred = Script(sv_logic_hash)
  let elig: Data = EligibilityClaim {
    spot: pyth_fixtures.feed2_value_1e6,
    policies: [terms],
  }
  let raw_updates: Data = [pyth_fixtures.pyth_test_update]
  let base = Transaction {
    ..fixtures.base_tx(),
    inputs: [sv_vault_input(300_000_000, old)],
    reference_inputs: [sv_registry_ref(), pyth_fixtures.pyth_state_ref_input()],
    outputs: [
      sv_cont_output(269_600_000, new),
      sv_policy_output(50_000_000, pd),
      fixtures.pkh_output(sv_cfg_team_key, 400_000),
    ],
    mint: assets.from_asset(sv_marker_policy, policy_marker_asset_name, 1),
    validity_range: fixtures.finite_range(sv_uw_pyth_obs, sv_uw_pyth_start),
    withdrawals: [Pair(logic_cred, 0)],
    redeemers: [
      Pair(Withdraw(logic_cred), elig),
      Pair(
        Withdraw(Script(pyth_fixtures.pyth_test_withdraw_hash)),
        raw_updates,
      ),
    ],
  }
  fixtures.with_observer_attestation(base, sv_observer_hash, [(Pyth, #"02")])
}

test sv_underwrite_rejects_pyth_provider() {
  !sv_run_underwrite(
    sv_state(1000, 0, 10_000_000),
    50_000_000,
    20_000_000,
    sv_with_registry_cfg(
      sv_underwrite_pyth_tx(),
      sv_config(sv_uw_pyth_mandates()),
    ),
  )
}

// --- Cross-cutting: a marker can ONLY be minted inside a legitimate Underwrite.
// A non-Underwrite arm (here DepositRevenue) that tries to co-mint a marker is
// rejected by only_lp_minted — closing EXT-08/09 (the pre-fabricated-marker
// landmine) at the validator level, so marker-presence == Underwrite provenance.

fn sv_deposit_tx(
  vault_in: Int,
  old: VaultState,
  cont: Int,
  new: VaultState,
  mint: assets.Value,
) -> Transaction {
  Transaction {
    ..fixtures.base_tx(),
    inputs: [sv_vault_input(vault_in, old)],
    reference_inputs: [sv_registry_ref()],
    outputs: [sv_cont_output(cont, new)],
    mint,
  }
}

fn sv_run_deposit(old: VaultState, amount: Int, tx: Transaction) -> Bool {
  pool_vault.spend(
    sv_pool_nft_policy,
    sv_pool_nft_name,
    sv_lp_policy,
    sv_policy_hash,
    sv_marker_policy,
    sv_observer_hash,
    sv_registry_nft_policy,
    sv_registry_nft_name,
    Some(old),
    DepositRevenue { amount },
    sv_own_ref(),
    tx,
  )
}

test sv_deposit_green_path() {
  // reserve 10M + amount 5M -> 15M; nothing else moves; no mint.
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 0, 15_000_000)
  let tx = sv_deposit_tx(100_000_000, old, 105_000_000, new, assets.zero)
  sv_run_deposit(old, 5_000_000, tx)
}

test sv_non_underwrite_marker_mint_fails() {
  // DepositRevenue co-minting a marker -> only_lp_minted False. A marker cannot
  // be pre-fabricated on any non-Underwrite arm.
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 0, 15_000_000)
  let marker = assets.from_asset(sv_marker_policy, policy_marker_asset_name, 1)
  let tx = sv_deposit_tx(100_000_000, old, 105_000_000, new, marker)
  !sv_run_deposit(old, 5_000_000, tx)
}

// ===========================================================================
// RemoveLiquidity at the ARM level. The exit pays pro-rata of liquid backing
// to whatever leaves the vault's PAYMENT credential — an output that merely
// varies the stake part still sits at the vault and is unspendable forever
// (spending it demands a pool-NFT continuation at the alias address), so
// counting it as "paid" destroys the exiter's value. V82-CONFIG-OFF-HASH §8.
// ===========================================================================

/// First-deposit share algebra: 100M backing minted 1e14 shares, so burning
/// 1e13 pays exactly 10M. own = min_utxo 2M + backing 100M; reserve 0.
fn rl_state(supply: Int) -> VaultState {
  Vault {
    lp_supply: supply,
    active_coverage: 0,
    reserve: 0,
    registry_nft: sv_registry_nft_policy,
  }
}

fn rl_tx(payout_out: Output) -> Transaction {
  Transaction {
    ..fixtures.base_tx(),
    inputs: [sv_vault_input(102_000_000, rl_state(100_000_000_000_000))],
    outputs: [
      sv_cont_output(92_000_000, rl_state(90_000_000_000_000)),
      payout_out,
    ],
    mint: assets.from_asset(sv_lp_policy, "aLP", -10_000_000_000_000),
  }
}

fn rl_run(tx: Transaction) -> Bool {
  pool_vault.spend(
    sv_pool_nft_policy,
    sv_pool_nft_name,
    sv_lp_policy,
    sv_policy_hash,
    sv_marker_policy,
    sv_observer_hash,
    sv_registry_nft_policy,
    sv_registry_nft_name,
    Some(rl_state(100_000_000_000_000)),
    RemoveLiquidity { shares: 10_000_000_000_000 },
    sv_own_ref(),
    tx,
  )
}

test rl_green_path_burns_and_pays_the_exiter() {
  rl_run(rl_tx(fixtures.pkh_output(#"a7a7", 10_000_000)))
}

test rl_rejects_a_vault_alias_output_counted_as_payout() {
  // The "payout" sits at the VAULT's payment credential under a foreign stake
  // key. It is not the vault continuation (no pool NFT, different address),
  // it satisfies full-address inequality — and nobody can ever spend it. The
  // exit must not count it as payment. Anchor: the green path above.
  !rl_run(
    rl_tx(
      Output {
        address: Address {
          payment_credential: Script(sv_vault_script),
          stake_credential: Some(Inline(VerificationKey(#"a7a7"))),
        },
        value: assets.from_lovelace(10_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ),
  )
}

// ===========================================================================
// [#381 V8.1 S4] Fallback settlement through the WHOLE Claim arm: a claim tx
// whose observer attests ONLY the mandated Pyth feed (real signed Lazer
// payload, State NFT ref input + Pyth withdraw redeemer) settles iff the
// primary AegisSelf feed UTxO on the table is ledger-provably stale. The
// green/red pair pins primary_stale_proven as load-bearing at the arm level —
// drop it and sv_s4_claim_fallback_rejected_when_primary_fresh goes green.
// ===========================================================================

const sv_s4_pyth_ts: Int = 1_772_613_309_000

/// [V8.2 G5] `pd` re-encoded with the settlement pins a V8.2 Underwrite wrote
/// for it: the fallback feed the governed mandate armed for its pair, and the
/// CORE waiting period, which is what a pins-less policy already resolves to.
/// The fallback lookup that used to run off the vault's compile parameter reads
/// this tail now, so a settlement fixture has to carry one to reach the Pyth leg.
fn sv_pins_pd(pd: PolicyDatum, pinned_feed: ByteArray) -> Data {
  fixtures.policy_datum_with_pins(
    pd,
    claim_waiting_period_ms(pd.risk_class),
    pinned_feed,
  )
}

/// A full Claim tx settling on the Pyth leg: green-path money math, policy
/// window straddling the Lazer timestamp, primary feed presented with the
/// given valid_until, and NO AegisSelf attestation.
fn sv_s4_fallback_claim_tx(
  primary_valid_until: Int,
  pinned_feed: ByteArray,
) -> Transaction {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  // strike above the feed-2 reading (2_013_003_316) -> barrier touched at spot.
  let pd = PolicyDatum {
    ..sv_claim_policy_datum(2_100_000_000, 50_000_000, None),
    start_time: sv_s4_pyth_ts - 86_400_000,
    expiry_time: sv_s4_pyth_ts + 86_400_000,
  }
  let raw_pd = sv_pins_pd(pd, pinned_feed)
  let primary_feed = fixtures.aegis_self_feed_input(
    sv_ada_nft(),
    2_100_000_000,
    primary_valid_until - 500_000,
    primary_valid_until,
  )
  let raw_updates: Data = [pyth_fixtures.pyth_test_update]
  let base = Transaction {
    ..fixtures.base_tx(),
    inputs: [
      sv_vault_input(100_000_000, old),
      sv_policy_input_raw(50_000_000, raw_pd),
    ],
    reference_inputs: [
      sv_registry_ref(),
      primary_feed,
      pyth_fixtures.pyth_state_ref_input(),
    ],
    outputs: [
      sv_cont_output(100_000_000, new),
      fixtures.pkh_output(pd.insured, 50_000_000),
    ],
    mint: sv_marker_burn(),
    validity_range: fixtures.finite_range(
      sv_s4_pyth_ts + 60_000,
      sv_s4_pyth_ts + 120_000,
    ),
    redeemers: [
      Pair(Withdraw(Script(pyth_fixtures.pyth_test_withdraw_hash)), raw_updates),
    ],
  }
  fixtures.with_observer_attestation(base, sv_observer_hash, [(Pyth, #"02")])
}

test sv_s4_claim_settles_via_pyth_fallback() {
  // primary died an hour before the tx window (stale past the 30-min grace),
  // and the policy pins the feed its mandate armed -> the Pyth leg settles.
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let tx = sv_s4_fallback_claim_tx(sv_s4_pyth_ts - 3_600_000, #"02")
  sv_run_claim(old, 50_000_000, tx)
}

test sv_s4_claim_fallback_rejected_when_primary_fresh() fail {
  // identical tx but the primary feed on the table is HEALTHY -> the Pyth
  // attestation must not settle the claim (R2: no oracle choice).
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let tx = sv_s4_fallback_claim_tx(sv_s4_pyth_ts + 3_600_000, #"02")
  sv_run_claim(old, 50_000_000, tx)
}

test sv_s4_claim_fallback_rejected_when_the_policy_pins_none() fail {
  // stale primary, but this policy was sold under a mandate arming no fallback
  // -> it pins #"" and no Pyth leg exists for it, whatever is attested.
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let tx = sv_s4_fallback_claim_tx(sv_s4_pyth_ts - 3_600_000, #"")
  sv_run_claim(old, 50_000_000, tx)
}

test sv_s4_claim_fallback_rejected_on_a_foreign_pinned_feed() fail {
  // [V8.2 G5] The pin is BUYER-authored. Feed 7 is canonical on Lazer and the
  // observer attests only feed 2 in this tx, so the wrong-instrument pin finds
  // no attestation and the claim dies rather than settling on the wrong price.
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let tx = sv_s4_fallback_claim_tx(sv_s4_pyth_ts - 3_600_000, #"07")
  sv_run_claim(old, 50_000_000, tx)
}

// ===========================================================================
// [#381 S12 DIAGNOSTIC] The same fallback-claim shape as
// sv_s4_claim_settles_via_pyth_fallback, but with the REAL deployed values:
// a LIVE Lazer payload for feed 16, the mandate's real fallback id #"10",
// and the live reading's own timestamp. If this is GREEN while the on-chain
// tx is RED, the divergence is environmental (ex-units / tx shape), not the
// validator logic. Tests never reach the compiled validator, so this cannot
// move the deployed pool_vault hash.
// ===========================================================================

const sv_live_update: ByteArray =
  #"b9011a821f8f165f77ec875ff0f7f7ab9a64716c2fdd5880d2d00a5fabb1ae69cc2185ede85fbcff870d531f3d78360a96f179a4be3618aa43b69e61ea2b68401279ff0a80efc1f480c5615af3fb673d42287e993da9fbc3506b6e41dfa32950820c2e6c280075d3c793805b0fe7e35706000301100000000300698403010000000004f8ff058113000000000000"

const sv_live_ts: Int = 1_785_486_206_000

fn sv_live_claim_tx(primary_valid_until: Int) -> Transaction {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  // live ADA ~0.170077 (1e6 -> 170_077); strike well above -> barrier touched.
  let pd =
    PolicyDatum {
      ..sv_claim_policy_datum(640_000, 50_000_000, None),
      start_time: sv_live_ts - 86_400_000,
      expiry_time: sv_live_ts + 86_400_000,
    }
  // the real deployed mandate armed feed #"10" for this pair; the policy pins it
  let raw_pd = sv_pins_pd(pd, #"10")
  let primary_feed =
    fixtures.aegis_self_feed_input(
      sv_ada_nft(),
      800_000,
      primary_valid_until - 500_000,
      primary_valid_until,
    )
  let raw_updates: Data = [sv_live_update]
  let base =
    Transaction {
      ..fixtures.base_tx(),
      inputs: [
        sv_vault_input(100_000_000, old),
        sv_policy_input_raw(50_000_000, raw_pd),
      ],
      reference_inputs: [
        sv_registry_ref(),
        primary_feed,
        pyth_fixtures.pyth_state_ref_input(),
      ],
      outputs: [
        sv_cont_output(100_000_000, new),
        fixtures.pkh_output(pd.insured, 50_000_000),
      ],
      mint: sv_marker_burn(),
      validity_range: fixtures.finite_range(
        sv_live_ts + 60_000,
        sv_live_ts + 120_000,
      ),
      redeemers: [
        Pair(
          Withdraw(Script(pyth_fixtures.pyth_test_withdraw_hash)),
          raw_updates,
        ),
      ],
    }
  fixtures.with_observer_attestation(base, sv_observer_hash, [(Pyth, #"10")])
}

test sv_live_fallback_claim_with_real_values() {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  // primary dead 2h before the live reading
  let tx = sv_live_claim_tx(sv_live_ts - 7_200_000)
  sv_run_claim(old, 50_000_000, tx)
}

// ===========================================================================
// [#381 S12] EXACT reproduction of the failing preprod fallback claim.
// Every value taken from the node's own TxInfo on the phase-2 failure:
// vault state (lp 99_999_966 / active 20_000_000 / reserve 0), policy datum
// (strike 640_000, coverage 20_000_000, start/expiry), the primary feed's
// valid_until offset, the 3-entry deployed mandate, extra operator-address
// reference inputs, and a validity window whose LOWER BOUND EQUALS the Pyth
// reading's observed_at (delta 0) — the boundary the synthetic tests never hit.
//
// [V8.2 H2] The recorded tx's UPPER bound is the one value that no longer
// reproduces: it sat 611_000 ms past the reading, and the spot-age budget is
// now judged against tx_upper (600_000 ms on Barrier). Both ends of that are
// asserted below, on the real payload, through the whole Claim arm — which is
// where the budget is actually wired to the validity range, as opposed to the
// settle_price unit boundaries in oracle/fallback.ak. Builders must shrink the
// claim ttl to land inside the budget; nothing else about the shape changes.
// ===========================================================================

const sv_exact_update: ByteArray =
  #"b9011a820db1bba33026310c645df72e7d4bcff85ac78b0f2df868f3887e86a61f9148413fc511e1e6d9bc79e8550e87dafb66480b89d82f0acccdf66f96f1393374900580efc1f480c5615af3fb673d42287e993da9fbc3506b6e41dfa32950820c2e6c280075d3c79300ee475eea5706000301100000000300d31401010000000004f8ff058624000000000000"

const sv_exact_obs: Int = 1785513976000

fn sv_exact_tx(ttl_ms: Int) -> Transaction {
  let old = sv_state(99_999_966, 20_000_000, 0)
  let new = sv_state(99_999_966, 0, 0)
  let pd =
    PolicyDatum {
      ..sv_claim_policy_datum(640_000, 20_000_000, None),
      // [#391 R2 F2b] 3_745_000 ms, past the 3_600_000 ms Barrier wait. This
      // window is synthetic (the recorded artifact is the Pyth update payload
      // and the ttl budget below, not the policy's dates); it was 2_745_000 and
      // moved only because Barrier's disclosed wait rose.
      start_time: sv_exact_obs - 3_745_000,
      expiry_time: sv_exact_obs + 601_450_000,
    }
  // the deployed 3-entry mandate armed #"10" for ADA/USD; the policy pins it
  let raw_pd = sv_pins_pd(pd, #"10")
  // primary died 2_444_654 ms before the reading (the real offset)
  let pvu = sv_exact_obs - 2_444_654
  let primary_feed =
    fixtures.aegis_self_feed_input(sv_ada_nft(), 800_000, pvu - 840_000, pvu)
  let raw_updates: Data = [sv_exact_update]
  let base =
    Transaction {
      ..fixtures.base_tx(),
      inputs: [
        sv_vault_input(265_417_618, old),
        sv_policy_input_raw(20_000_000, raw_pd),
      ],
      reference_inputs: [
        sv_registry_ref(),
        primary_feed,
        pyth_fixtures.pyth_state_ref_input(),
      ],
      outputs: [
        sv_cont_output(265_417_618, new),
        fixtures.pkh_output(pd.insured, 20_000_000),
      ],
      mint: sv_marker_burn(),
      // LOWER BOUND == observed_at exactly, as the real tx has it.
      validity_range: fixtures.finite_range(sv_exact_obs, sv_exact_obs + ttl_ms),
      // The real tx carries TWO withdrawals: the observer's AND the Pyth
      // withdraw script's own 0-ADA one. with_observer_attestation prepends
      // the observer's, so seeding this gives the real two-entry shape.
      withdrawals: [
        Pair(Script(pyth_fixtures.pyth_test_withdraw_hash), 0),
      ],
      redeemers: [
        Pair(
          Withdraw(Script(pyth_fixtures.pyth_test_withdraw_hash)),
          raw_updates,
        ),
      ],
    }
  fixtures.with_observer_attestation(base, sv_observer_hash, [(Pyth, #"10")])
}

test sv_exact_preprod_fallback_repro() {
  // The real shape, with the ttl at the largest value the budget admits.
  sv_run_claim(
    sv_state(99_999_966, 20_000_000, 0),
    20_000_000,
    sv_exact_tx(max_spot_age_ms(Barrier)),
  )
}

test sv_exact_preprod_fallback_rejects_recorded_ttl() fail {
  // The ttl the failing preprod tx actually carried: 11_000 ms past the budget.
  // The tx_lower form of the leg admitted it — tx_lower sits AT observed_at
  // here, so the leg held no matter how old the reading was, all the way out to
  // Pyth's own 70-minute validity window. tx_upper is what makes the ttl bite.
  sv_run_claim(
    sv_state(99_999_966, 20_000_000, 0),
    20_000_000,
    sv_exact_tx(611_000),
  )
}

// ===========================================================================
// [#391] THE ECONOMIC RED-TEAM — hindsight, the publisher-authored low, and
// the stranded book. Every `ec_` scenario below is written in POSITIVE form:
// it asserts what the vault ACCEPTS, so it PASSED on the pre-fix tree and the
// fix is what turns it into a refusal. Each carries an honest anchor that must
// go on passing after, because a refusal that also refuses honest business is
// not a fix, it is an outage.
// ===========================================================================

/// The governed Underwrite spot-age budget widened to the registry rail (24 h).
/// Everything else is the green path, so only the freshness leg can decide.
fn ec_rail_wide_cfg() -> UnderwriteConfig {
  let cfg = sv_config([sv_mandate(sv_ada_nft())])
  UnderwriteConfig {
    ..cfg,
    budgets: Budgets { ..cfg.budgets, spot_age_barrier_ms: 86_400_000 },
  }
}

/// A Barrier underwrite whose strike is priced off a print `age_ms` old at the
/// instant coverage begins, under `cfg`. tx_upper stays inside the feed's own
/// validity, so the age leg is the only one in play.
fn ec_uw_at_age(cfg: UnderwriteConfig, age_ms: Int) -> Transaction {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = sv_uw_start
  let lo = hi - 900_000
  let pd = sv_underwrite_policy_datum()
  sv_with_registry_cfg(
    sv_underwrite_tx_retro(
      pd,
      old,
      new,
      lo,
      hi,
      100_000_000,
      pd.start_time - age_ms,
      100_000_000,
      pd.start_time - age_ms,
    ),
    cfg,
  )
}

fn ec_run_uw(tx: Transaction) -> Bool {
  sv_run_underwrite(sv_state(1000, 0, 10_000_000), 50_000_000, 20_000_000, tx)
}

// [#391 F1a] The Underwrite freshness budget is GOVERNED (capped only by
// registry_v2.max_spot_age_rail_ms, 24 h) while EVERY settlement-side age
// budget is the CORE `max_spot_age_ms` that fallback.settle_price enforces.
// Governance can therefore make Underwrite price a strike off a print that
// settlement itself would refuse. One hour of age is 6x the Barrier CORE
// budget and sits comfortably inside the rail.
test ec_uw_refuses_a_strike_on_a_print_settlement_would_refuse() {
  !ec_run_uw(ec_uw_at_age(ec_rail_wide_cfg(), 3_600_000))
}

// HONEST ANCHOR for F1a. Clamping the governed budget at CORE must leave BOTH
// directions intact: governance may still TIGHTEN below CORE (and the tighter
// value must bite), and the CORE budget itself must stay buyable at its own
// boundary. A clamp that swallowed the governed value entirely would pass the
// refusal above while silently un-governing the budget.
test ec_uw_honest_anchor_budget_still_tightens_and_core_still_buys() {
  let cfg = sv_config([sv_mandate(sv_ada_nft())])
  let tight =
    UnderwriteConfig {
      ..cfg,
      budgets: Budgets { ..cfg.budgets, spot_age_barrier_ms: 180_000 },
    }
  and {
    ec_run_uw(ec_uw_at_age(tight, 120_000)),
    !ec_run_uw(ec_uw_at_age(tight, 180_001)),
    ec_run_uw(ec_uw_at_age(cfg, 600_000)),
  }
}

// --- F1b: the five minutes of hindsight the CORE budget itself grants -------

/// A Depeg policy pinned to the shared underwrite window, so the Underwrite
/// that creates it and the Claim that settles it are the same policy.
fn ec_depeg_pd() -> PolicyDatum {
  sv_depeg_policy_datum()
}

/// A Claim on `pd` with BOTH the tx window and the settling reading
/// parameterised — the pair the hindsight window is measured across.
fn ec_claim_tx(
  pd: PolicyDatum,
  lo: Int,
  hi: Int,
  spot: Int,
  observed_at: Int,
  min_price_12h: Int,
  low_observed_at: Int,
) -> Transaction {
  ec_claim_tx_raw(pd, pd, lo, hi, spot, observed_at, min_price_12h, low_observed_at)
}

/// `ec_claim_tx` with the policy datum supplied RAW, so a scenario can pin a
/// settlement-pins tail the `PolicyDatum` record cannot be cast through here.
fn ec_claim_tx_raw(
  pd: PolicyDatum,
  raw_pd: Data,
  lo: Int,
  hi: Int,
  spot: Int,
  observed_at: Int,
  min_price_12h: Int,
  low_observed_at: Int,
) -> Transaction {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let feed = fixtures.aegis_self_feed_input_full(
    pd.oracle_nft,
    spot,
    observed_at,
    observed_at + 4_200_000,
    min_price_12h,
    low_observed_at,
  )
  let base = Transaction {
    ..fixtures.base_tx(),
    inputs: [
      sv_vault_input(100_000_000, old),
      sv_policy_input_raw(50_000_000, raw_pd),
    ],
    reference_inputs: [sv_registry_ref(), feed],
    outputs: [
      sv_cont_output(100_000_000, new),
      fixtures.pkh_output(pd.insured, 50_000_000),
    ],
    mint: sv_marker_burn(),
  }
  let tx =
    fixtures.with_observer_attestation(
      base,
      sv_observer_hash,
      [(AegisSelf, pd.oracle_nft)],
    )
  Transaction { ..tx, validity_range: fixtures.finite_range(lo, hi) }
}

fn ec_run_claim(tx: Transaction) -> Bool {
  sv_run_claim(sv_state(1000, 200_000_000, 60_000_000), 50_000_000, tx)
}

// [#391 F1b] THE GENESIS RESIDUAL, and it SURVIVES the clamp by construction —
// the CORE Depeg budget IS five minutes, so a strike set from a four-minute-old
// print is still buyable and this test still passes. That is deliberate: block
// time and publisher burn both put a floor under the budget, so the hindsight
// cannot be removed at the Underwrite end. What the waiting period removes is
// its VALUE — see the money shot below, which is the same purchase and is no
// longer settleable one block later.
test ec_uw_accepts_4min_stale_healthy_peg_at_genesis() {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_with_depeg_cfg(
      sv_depeg_underwrite_tx_at(old, new, 1_000_000, sv_uw_start - 240_000),
    ),
  )
}

// [#391 F1b] THE MONEY SHOT, now refused. Buy at minute 0 on a print that says
// the peg is healthy, claim at minute 1 on the print that says it is not. This
// PASSED before the fix and paid full coverage; the disclosed waiting period is
// what stops it. Note which disjunct carries it: spot 0.80 <= strike 0.90, the
// `spot <= strike` path, which has no time gate of its own — so the wait had to
// sit ABOVE the disjunction to reach it.
test ec_claim_refused_one_block_after_the_stale_purchase() {
  let pd = ec_depeg_pd()
  !ec_run_claim(
    ec_claim_tx(
      pd,
      pd.start_time + 60_000,
      pd.start_time + 120_000,
      800_000,
      pd.start_time + 60_000,
      800_000,
      pd.start_time + 60_000,
    ),
  )
}

// [#391 F1b] The OTHER disjunct, inside the same wait. `min_price_12h <= strike
// && low_observed_at >= start_time` with spot back at peg — a wait that gated
// only this path would have left the money shot above wide open, and a wait
// that gated only that one would leave this open. Both are refused.
test ec_claim_refused_inside_the_wait_on_the_retro_path_too() {
  let pd = ec_depeg_pd()
  let settle_at = pd.start_time + 600_000
  !ec_run_claim(
    ec_claim_tx(
      pd,
      settle_at,
      settle_at + 60_000,
      1_000_000,
      settle_at,
      800_000,
      pd.start_time + 300_000,
    ),
  )
}

// HONEST ANCHOR for F1b, and the case the waiting period must NOT break. A
// genuine break at minute 10 that has FULLY RECOVERED by the time the wait
// expires is still paid: `min_price_12h` is a twelve-hour low-water MARK, so
// the event is remembered even though spot is back at peg. The waiting period
// delays the claim; it must never erase the event.
test ec_honest_break_that_recovered_inside_the_wait_is_still_paid() {
  let pd = ec_depeg_pd()
  let broke_at = pd.start_time + 600_000
  let settle_at = pd.start_time + 3_600_000
  ec_run_claim(
    ec_claim_tx(
      pd,
      settle_at,
      settle_at + 60_000,
      1_000_000,
      settle_at,
      800_000,
      broke_at,
    ),
  )
}

// --- F2: the publisher writes the field that decides whose loss it is -------

// [#391 F2] `barrier_touched`'s gate `low_observed_at >= start_time` compares
// against a raw publisher-authored datum field that NO validator constrains
// against the reading it travels with. Here the low is stamped 5000 seconds
// AFTER the reading that reports it — physically impossible — and the vault
// pays. Spot is at peg, so ONLY the retro disjunct can carry this claim.
test ec_claim_refuses_a_low_stamped_after_its_own_reading() {
  let pd = ec_depeg_pd()
  let settle_at = pd.start_time + 3_600_000
  // The wait has expired, so the ONLY leg left to reject this is the bound on
  // the low against its own reading.
  !ec_run_claim(
    ec_claim_tx(
      pd,
      settle_at,
      settle_at + 60_000,
      1_000_000,
      settle_at,
      800_000,
      settle_at + 5_000_000,
    ),
  )
}

// [#391 R2 F1] The OTHER direction of the same bound, and it needed a CLAIM to
// express: a low stamped thirteen hours before the reading that carries it is
// outside the twelve hours `min_price_12h` is defined over, so it reads as an
// event the reading cannot vouch for. The touch is genuinely IN TERM (the
// policy started a day earlier), spot has recovered, and the waiting period has
// long expired — so `reading_fresh`'s lower bound is the only leg that can
// refuse it. The Cancel arm cannot host this case at all: `within_window` keeps
// a cancellable policy within half an hour of its own start, so a low older
// than the trailing window is necessarily PRE-start there.
test ec_claim_refuses_a_low_older_than_its_own_trailing_window() {
  let pd =
    PolicyDatum { ..ec_depeg_pd(), start_time: ec_depeg_pd().start_time }
  let settle_at = pd.start_time + 86_400_000
  and {
    !ec_run_claim(
      ec_claim_tx(
        pd,
        settle_at,
        settle_at + 60_000,
        1_000_000,
        settle_at,
        800_000,
        settle_at - 46_800_000,
      ),
    ),
    // and the honest twin one hour INSIDE the window still settles
    ec_run_claim(
      ec_claim_tx(
        pd,
        settle_at,
        settle_at + 60_000,
        1_000_000,
        settle_at,
        800_000,
        settle_at - 39_600_000,
      ),
    ),
  }
}

// [#391 R2 F2a] THE FREE OPTION, on the arm that pays. The reading itself says
// the strike was already through BEFORE this policy started — the loss is not
// the insured's, the cover had not attached — and `spot <= strike` still holds
// a full waiting period later, because a real depeg persists for hours (USDC
// sat near 0.88 for ~40 hours in March 2023). Round 1 SAW the pre-start breach,
// correctly refused the retro disjunct on that ground, and paid full coverage
// through path 1 anyway. Both paths are now vetoed.
test ec_claim_refuses_a_persistent_break_that_pre_dates_the_policy() {
  let pd = ec_depeg_pd()
  let settle_at = pd.start_time + 3_600_000
  !ec_run_claim(
    ec_claim_tx(
      pd,
      settle_at,
      settle_at + 60_000,
      // spot STILL through the 900_000 strike an hour later — path 1 holds
      800_000,
      settle_at,
      800_000,
      // ...but the reading stamps that low before coverage began
      pd.start_time - 1,
    ),
  )
}

/// The Cancel arm on a policy carrying a real trailing low, with BOTH fields
/// that decide whether that low counts supplied by the publisher.
fn ec_cancel_tx(min_price_12h: Int, low_observed_at: Int) -> Transaction {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let pd =
    sv_cancel_policy_datum(
      100_000_000,
      50_000_000,
      5_000_000,
      1_700_100_000_000,
      None,
    )
  let observed_at = 1_700_099_900_000
  let feed =
    fixtures.aegis_self_feed_input_full(
      sv_ada_nft(),
      110_000_000,
      observed_at,
      1_700_100_400_000,
      min_price_12h,
      low_observed_at,
    )
  let base =
    Transaction {
      ..fixtures.base_tx(),
      inputs: [
        sv_vault_input(100_000_000, old),
        sv_policy_input(50_000_000, pd),
      ],
      outputs: [
        sv_cont_output(145_500_000, new),
        fixtures.pkh_output(pd.insured, 4_500_000),
      ],
      reference_inputs: [sv_registry_ref(), feed],
      extra_signatories: [pd.insured],
      mint: sv_marker_burn(),
    }
  fixtures.with_observer_attestation(
    base,
    sv_observer_hash,
    [(AegisSelf, sv_ada_nft())],
  )
}

// [#391 R2 F2c] THE CANCEL ESCAPE — the other half of the free option, and the
// half that made the losing bet costless. The attacker's breach pre-dates
// `start_time` by construction, so `barrier_touched` VETOES it, so the policy
// reads out of the money, so AcceptCancellation hands back 90% of the premium
// the moment spot recovers. Heads full coverage, tails most of the stake. A
// policy the reading shows was born broken now claims nothing and cancels
// nothing: it expires, and the premium stays with the LPs who carried it.
test ec_cancel_refuses_to_refund_a_policy_born_already_broken() {
  // The low is WELL FORMED against its own reading — 1000 ms before it, well
  // inside the trailing window — so `reading_fresh` cannot be the leg that
  // refuses this. It is 100_000 ms before `start_time`, and 90.0 is under the
  // 100.0 strike: the pre-start veto is the only thing standing between the
  // attacker and a 90% refund.
  !sv_run_cancel(
    sv_state(1000, 200_000_000, 10_000_000),
    ec_cancel_tx(90_000_000, 1_700_099_900_000 - 1_000),
  )
}

// HONEST ANCHOR for the escape, and the right the fix must not take away: a
// buyer who simply changes their mind. The trailing low is 105.0, clear of the
// 100.0 strike, so nothing about this policy was ever in the money — and it
// cancels for its 90% refund inside the window, exactly as before.
test ec_cancel_still_refunds_an_honest_buyer_who_changed_their_mind() {
  sv_run_cancel(
    sv_state(1000, 200_000_000, 10_000_000),
    ec_cancel_tx(105_000_000, 1_700_099_900_000 - 1_000),
  )
}

// HONEST ANCHOR for F2: a well-formed low — inside the trailing window and at
// or before the reading that reports it — must keep settling, and the SEC F-1
// refusal it exists to protect must survive intact.
test ec_honest_anchor_well_formed_low_still_settles_both_arms() {
  let pd = ec_depeg_pd()
  let settle_at = pd.start_time + 3_600_000
  and {
    ec_run_claim(
      ec_claim_tx(
        pd,
        settle_at,
        settle_at + 60_000,
        1_000_000,
        settle_at,
        800_000,
        settle_at - 1_000,
      ),
    ),
    // the touch really did pre-date the policy: refused, as SEC F-1 requires
    !ec_run_claim(
      ec_claim_tx(
        pd,
        settle_at,
        settle_at + 60_000,
        1_000_000,
        settle_at,
        800_000,
        pd.start_time - 1,
      ),
    ),
    // an out-of-the-money policy on an honest low still cancels
    sv_run_cancel(
      sv_state(1000, 200_000_000, 10_000_000),
      ec_cancel_tx(105_000_000, 1_700_099_900_000 - 1_000),
    ),
  }
}

// --- F1b: the pin itself. `waiting_period_pin_ok` is the Underwrite-side half
// of the waiting period: a policy may DISCLOSE a longer wait than CORE, never
// a shorter one, and never one that outlives the cover it delays.

fn ec_uw_with_pinned_wait(wait_ms: Int) -> Transaction {
  sv_underwrite_tx_raw(
    300_000_000,
    sv_state(1000, 0, 10_000_000),
    270_000_000,
    sv_state(1000, 50_000_000, 10_000_000),
    50_000_000,
    fixtures.policy_datum_with_pins(
      sv_underwrite_policy_datum(),
      wait_ms,
      // the fallback the fixture config's own mandate arms: none
      #"",
    ),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
}

test ec_uw_refuses_a_policy_pinning_a_wait_below_core() {
  // One millisecond under the CORE Barrier floor. Everything else is the green
  // path, so only the pin bound can decide this.
  !ec_run_uw(ec_uw_with_pinned_wait(claim_waiting_period_ms(Barrier) - 1))
}

test ec_uw_refuses_a_pinned_wait_that_outlives_the_cover() {
  // A wait longer than the policy's own term sells cover that can never be
  // claimed, at a real premium. The term here is 30 days.
  !ec_run_uw(ec_uw_with_pinned_wait(sv_uw_expiry - sv_uw_start + 1))
}

test ec_uw_accepts_a_pin_at_or_above_core() {
  and {
    // exactly at the floor
    ec_run_uw(ec_uw_with_pinned_wait(claim_waiting_period_ms(Barrier))),
    // and a buyer who wants a longer, safer disclosed wait may have one
    ec_run_uw(ec_uw_with_pinned_wait(claim_waiting_period_ms(Barrier) * 4)),
    // and a policy with no pins at all still underwrites, settling under CORE
    ec_run_uw(
      sv_underwrite_tx_raw(
        300_000_000,
        sv_state(1000, 0, 10_000_000),
        270_000_000,
        sv_state(1000, 50_000_000, 10_000_000),
        50_000_000,
        fixtures.pre_pins_datum(sv_underwrite_policy_datum()),
        100_000_000,
        100_000_000,
        sv_underwrite_terms(50_000_000),
        1,
      ),
    ),
  }
}

test ec_claim_honours_the_pinned_wait_over_core() {
  // The pin is the term the policy SETTLES under, not decoration: a policy sold
  // with four times the CORE Barrier wait is refused at the CORE boundary and
  // paid past its own. If `policy_waiting_period_ms` ignored the pin and always
  // returned CORE, the first of these would pay.
  let wait = claim_waiting_period_ms(Barrier) * 4
  let pd = sv_claim_policy_datum(100_000_000, 50_000_000, None)
  let raw_pd = fixtures.policy_datum_with_pins(pd, wait, #"")
  let core_open = pd.start_time + claim_waiting_period_ms(Barrier)
  let pinned_open = pd.start_time + wait
  and {
    !ec_run_claim(
      ec_claim_tx_raw(
        pd,
        raw_pd,
        core_open,
        core_open + 60_000,
        90_000_000,
        core_open,
        90_000_000,
        core_open,
      ),
    ),
    ec_run_claim(
      ec_claim_tx_raw(
        pd,
        raw_pd,
        pinned_open,
        pinned_open + 60_000,
        90_000_000,
        pinned_open,
        90_000_000,
        pinned_open,
      ),
    ),
  }
}


// --- [#391 R2 F1] THE DATUM SHAPE MAINNET ACTUALLY PUBLISHES ---------------
//
// The production publisher writes trailing-low history for ADA/USD ALONE
// (`publisher/main.py::TRAILING_LOW_PAIR`), and drops to a 3-key datum even
// there on a Pyth-failover tick and on a history-I/O error. Every live
// USDM / USDC / USDT depeg feed, the Indigo relay pair, the Surf event slots
// and the FEAR slot therefore publish {0:spot, 1:observed, 2:valid_until} with
// NO key 3 and NO key 4.
//
// Round 1 made `get_min_low_observed_at` `fail` on exactly that shape. The
// resolver reads it unconditionally, so the oracle_observer aborted BEFORE the
// vault was consulted and every depeg product stopped settling. The suite
// stayed green only because the round also converted the shared feed fixture to
// five keys — it edited the witness. `aegis_self_feed_input` is 3-key again,
// and these are the claims that shape has to serve.

/// A Claim over a THREE-KEY reading — no trailing low, no observation time.
fn ec_claim_tx_3key(
  pd: PolicyDatum,
  lo: Int,
  hi: Int,
  spot: Int,
  observed_at: Int,
) -> Transaction {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  let feed = fixtures.aegis_self_feed_input(
    pd.oracle_nft,
    spot,
    observed_at,
    observed_at + 4_200_000,
  )
  let base = Transaction {
    ..fixtures.base_tx(),
    inputs: [sv_vault_input(100_000_000, old), sv_policy_input(50_000_000, pd)],
    reference_inputs: [sv_registry_ref(), feed],
    outputs: [
      sv_cont_output(100_000_000, new),
      fixtures.pkh_output(pd.insured, 50_000_000),
    ],
    mint: sv_marker_burn(),
  }
  let tx = fixtures.with_observer_attestation(
    base,
    sv_observer_hash,
    [(AegisSelf, pd.oracle_nft)],
  )
  Transaction { ..tx, validity_range: fixtures.finite_range(lo, hi) }
}

test ec_claim_settles_the_three_key_datum_mainnet_publishes() {
  // A USDM depeg policy on the live depeg feed, settling on the ONLY shape that
  // feed has ever published: spot 0.80 against a 0.90 strike, one full waiting
  // period after coverage began. This is the claim the round-1 hardening
  // refused, and it pays full coverage again.
  let pd = ec_depeg_pd()
  let settle_at = pd.start_time + 3_600_000
  ec_run_claim(ec_claim_tx_3key(pd, settle_at, settle_at + 60_000, 800_000, settle_at))
}

test ec_three_key_claim_still_refuses_an_out_of_the_money_policy() {
  // Non-vacuity for the test above: the 3-key path settles on SPOT ALONE, so a
  // reading at peg must refuse. Without this, "3-key settles" could be an
  // always-true wiring rather than a working trigger.
  let pd = ec_depeg_pd()
  let settle_at = pd.start_time + 3_600_000
  !ec_run_claim(
    ec_claim_tx_3key(pd, settle_at, settle_at + 60_000, 1_000_000, settle_at),
  )
}

test ec_three_key_claim_still_honours_the_waiting_period() {
  // The second non-vacuity control: the wait gates the 3-key path too. One
  // minute after purchase, on the same in-the-money reading, is refused.
  let pd = ec_depeg_pd()
  let settle_at = pd.start_time + 60_000
  !ec_run_claim(
    ec_claim_tx_3key(pd, settle_at, settle_at + 60_000, 800_000, settle_at),
  )
}

test ec_three_key_reading_can_never_reach_the_retro_disjunct() {
  // The capability gate, stated as the property it buys: a reading with no key
  // 4 carries the `0` sentinel, which is below every real `start_time`, so the
  // `min_price_12h <= strike && low_observed_at >= start_time` path is
  // unreachable for it — and the pre-start veto stays disarmed, which is what
  // keeps the 3-key claim above settleable at all.
  and {
    !barrier_touched(1_000_000, 800_000, 0, 900_000, ec_depeg_pd().start_time),
    !pre_start_breach(800_000, 0, 900_000, ec_depeg_pd().start_time),
    // ...and a FIVE-key reading with the same numbers does reach it
    barrier_touched(
      1_000_000,
      800_000,
      ec_depeg_pd().start_time + 1,
      900_000,
      ec_depeg_pd().start_time,
    ),
  }
}

// --- [#391 R2 F5] the reading-integrity legs Underwrite was missing ---------

test ec_uw_refuses_a_print_stamped_after_the_tx_deadline() {
  // [F5b] `observed_at` was bounded BELOW at Underwrite (the spot-age budget)
  // and ABOVE only at settlement, never against tx_upper — so a publisher clock
  // running ahead of the chain, or a datum simply asserting it, bought an
  // unbounded strike-setting window. `tx_upper` is the one instant the ledger
  // certifies lies at or after inclusion.
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = 1_700_100_300_000
  let lo = hi - 900_000
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: hi + 120_000,
    expiry_time: hi + 120_000 + 2_592_000_000,
  }
  and {
    // one ms past the deadline: refused
    !sv_run_underwrite(
      old,
      50_000_000,
      20_000_000,
      sv_underwrite_tx_expiring_feed(pd, old, new, lo, hi, hi + 1, hi + 600_000),
    ),
    // exactly AT the deadline is honest — a tx whose ttl lands on the print
    sv_run_underwrite(
      old,
      50_000_000,
      20_000_000,
      sv_underwrite_tx_expiring_feed(pd, old, new, lo, hi, hi, hi + 600_000),
    ),
  }
}

test ec_uw_refuses_a_trailing_low_above_its_own_spot() {
  // [F5c] Nothing constrained key 3 anywhere. It is a LOW, so it cannot exceed
  // the reading it travels with — and `resolved_min_12h > strike` reads it, so
  // an inflated key 3 would talk the sale-side trailing-low gate out of the one
  // job it has. Every other leg is green: spot 100.0 is 40% clear of the 80.0
  // strike and the window is honest.
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let hi = 1_700_100_300_000
  let lo = hi - 900_000
  let pd = PolicyDatum {
    ..sv_underwrite_policy_datum(),
    start_time: hi,
    expiry_time: hi + 2_592_000_000,
  }
  and {
    !sv_run_underwrite(
      old,
      50_000_000,
      20_000_000,
      sv_underwrite_tx_retro(
        pd,
        old,
        new,
        lo,
        hi,
        100_000_000,
        1_700_099_900_000,
        100_000_001,
        1_700_099_450_000,
      ),
    ),
    // a low exactly AT spot is the honest boundary (a market that only rose)
    sv_run_underwrite(
      old,
      50_000_000,
      20_000_000,
      sv_underwrite_tx_retro(
        pd,
        old,
        new,
        lo,
        hi,
        100_000_000,
        1_700_099_900_000,
        100_000_000,
        1_700_099_450_000,
      ),
    ),
  }
}

// ===========================================================================
// [#403 FIX 2] SETTLEMENT AGE FOR A NON-AegisSelf PROVIDER.
//
// The Claim and AcceptCancellation arms split
// `AegisSelf -> fallback.settle_price(...)` / `_ -> attested_price(...)`. The
// spot-age budget lives INSIDE `fallback.settle_price` — the AegisSelf-only
// branch — so a Pyth-provider policy's only remaining bound was
// `reading_fresh`, whose horizon is the reading's own `valid_until`. Admitting
// a non-AegisSelf provider anywhere therefore widened SETTLEMENT hindsight for
// the policies it creates, in both directions: low to trip a Barrier at Claim,
// high to prove OTM at Cancel.
//
// The three windows are distinct and are named so: the SALE-side window
// (`max_spot_age_ms`, applied to the Underwrite min leg), the ORDINARY
// settlement window (`pyth_ordinary_window_ms`), and the REPLAY window
// (`pyth_replay_window_ms`, reserved for #402). `ssw_a` sits INSIDE the
// ordinary window and OUTSIDE the class budget, so only the class-budget
// conjunct can refuse it.
// ===========================================================================

/// A Claim on a policy whose PROVIDER is Pyth — the `_ -> attested_price`
/// branch. `hi - lo = 60_000`; `hi_off` is tx_upper's offset past the Lazer
/// payload's own timestamp, which is the only thing that varies.
fn ssw_pyth_claim_tx(hi_off: Int) -> Transaction {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  // strike above the feed-2 reading (2_013_003_316) -> barrier touched at spot
  let pd =
    PolicyDatum {
      ..sv_claim_policy_datum(2_100_000_000, 50_000_000, None),
      start_time: sv_s4_pyth_ts - 86_400_000,
      expiry_time: sv_s4_pyth_ts + 86_400_000,
      oracle_nft: #"02",
      oracle_provider: Pyth,
    }
  let raw_updates: Data = [pyth_fixtures.pyth_test_update]
  let base =
    Transaction {
      ..fixtures.base_tx(),
      inputs: [
        sv_vault_input(100_000_000, old),
        sv_policy_input(50_000_000, pd),
      ],
      reference_inputs: [
        sv_registry_ref(),
        pyth_fixtures.pyth_state_ref_input(),
      ],
      outputs: [
        sv_cont_output(100_000_000, new),
        fixtures.pkh_output(pd.insured, 50_000_000),
      ],
      mint: sv_marker_burn(),
      validity_range: fixtures.finite_range(
        sv_s4_pyth_ts + hi_off - 60_000,
        sv_s4_pyth_ts + hi_off,
      ),
      redeemers: [
        Pair(
          Withdraw(Script(pyth_fixtures.pyth_test_withdraw_hash)),
          raw_updates,
        ),
      ],
    }
  fixtures.with_observer_attestation(base, sv_observer_hash, [(Pyth, #"02")])
}

/// THE NON-VACUITY ANCHOR. Same fixture, a print 2 minutes old: a Pyth-provider
/// policy still settles. Every refusal below must leave this GREEN, or the arm
/// is merely dead rather than bounded.
test ssw_honest_anchor_fresh_pyth_claim_settles() {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  sv_run_claim(old, 50_000_000, ssw_pyth_claim_tx(120_000))
}

/// tx_upper 700s past the print: INSIDE the ordinary Pyth window (900s) and
/// OUTSIDE the Barrier class budget (600s). Nothing but the class-budget
/// conjunct can refuse this transaction.
test ssw_a_pyth_claim_beyond_the_class_budget_is_refused() {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  !sv_run_claim(old, 50_000_000, ssw_pyth_claim_tx(700_000))
}

/// The memo's measured hole, verbatim: a 69-minute-old Pyth print settling a
/// Barrier whose class budget is 600s. Refused by the composite.
test ssw_b_pyth_claim_on_a_69_minute_old_print_is_refused() {
  let old = sv_state(1000, 200_000_000, 60_000_000)
  !sv_run_claim(old, 50_000_000, ssw_pyth_claim_tx(4_140_000))
}

/// The same bound on the OTHER settlement arm. AcceptCancellation must judge
/// OTM on a reading no older than the Claim it forecloses, or the insured picks
/// whichever side of the stale print pays: Claim if it reads ITM, Cancel if it
/// reads OTM.
fn ssw_pyth_cancel_tx(hi_off: Int) -> Transaction {
  let old = sv_state(1000, 200_000_000, 10_000_000)
  let new = sv_state(1000, 150_000_000, 10_000_000)
  // strike 2051 bps under the feed-2 reading (2_013_003_316) -> OTM
  let pd =
    PolicyDatum {
      ..sv_cancel_policy_datum(
        1_600_000_000,
        50_000_000,
        5_000_000,
        sv_s4_pyth_ts,
        None,
      ),
      expiry_time: sv_s4_pyth_ts + 86_400_000,
      oracle_nft: #"02",
      oracle_provider: Pyth,
    }
  let raw_updates: Data = [pyth_fixtures.pyth_test_update]
  let base =
    Transaction {
      ..fixtures.base_tx(),
      inputs: [
        sv_vault_input(100_000_000, old),
        sv_policy_input(50_000_000, pd),
      ],
      reference_inputs: [
        sv_registry_ref(),
        pyth_fixtures.pyth_state_ref_input(),
      ],
      outputs: [
        sv_cont_output(145_500_000, new),
        fixtures.pkh_output(pd.insured, 4_500_000),
      ],
      extra_signatories: [pd.insured],
      mint: sv_marker_burn(),
      validity_range: fixtures.finite_range(
        sv_s4_pyth_ts + hi_off - 60_000,
        sv_s4_pyth_ts + hi_off,
      ),
      redeemers: [
        Pair(
          Withdraw(Script(pyth_fixtures.pyth_test_withdraw_hash)),
          raw_updates,
        ),
      ],
    }
  fixtures.with_observer_attestation(base, sv_observer_hash, [(Pyth, #"02")])
}

/// THE NON-VACUITY ANCHOR for the Cancel arm.
test ssw_honest_anchor_fresh_pyth_cancel_refunds() {
  sv_run_cancel(sv_state(1000, 200_000_000, 10_000_000), ssw_pyth_cancel_tx(120_000))
}

/// 700s past the print: inside the ordinary window, outside the class budget.
test ssw_c_pyth_cancel_beyond_the_class_budget_is_refused() {
  !sv_run_cancel(
    sv_state(1000, 200_000_000, 10_000_000),
    ssw_pyth_cancel_tx(700_000),
  )
}

// ===========================================================================
// [#403 FIX 1] THE ONE-SIDED MIN LEG, on every shape production actually
// writes.
//
// Round 2 wrote every economic proof on the FIVE-key fixture while every
// sellable depeg feed publishes THREE keys, so the numbers it reported were
// measured on a witness the publisher does not produce. Each result below
// names its shape, and the 3-key and 5-key cases are separate tests rather
// than one fixture with a flag.
// ===========================================================================

/// The feed-2 reading the vendored signed Lazer payload actually carries.
const ml_pull_value: Int = 2_013_003_316

fn ml_mandates(leg: SecondLeg) -> List<OracleMandate> {
  [
    OracleMandate {
      primary_nft: sv_ada_nft(),
      fallback_feed_id: #"",
      second_leg: leg,
    },
  ]
}

/// `sv_config` with the pull leg's feed on the Pyth allowlist — the S5 coupling
/// `config_within_rails` demands of any mandatory pull leg.
fn ml_config(leg: SecondLeg) -> UnderwriteConfig {
  let base = sv_config(ml_mandates(leg))
  UnderwriteConfig { ..base, pyth_feed_allowlist: [#"02"] }
}

fn ml_run(tx: Transaction) -> Bool {
  sv_run_underwrite(sv_state(1000, 0, 10_000_000), 50_000_000, 20_000_000, tx)
}

// ---------------------------------------------------------------------------
// SHAPE 1 — the FIVE-key AegisSelf feed, `TrailingLowLeg`.
// ---------------------------------------------------------------------------

/// A Barrier Underwrite over a 5-key primary: spot AND a real trailing low.
fn ml_barrier_tx(spot: Int, low: Int, strike: Int) -> Transaction {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let pd =
    PolicyDatum { ..sv_underwrite_policy_datum(), strike_price: strike }
  let terms = PolicyTerms { ..sv_underwrite_terms(50_000_000), strike: strike }
  let feed =
    fixtures.aegis_self_feed_input_full(
      sv_ada_nft(),
      spot,
      1_700_099_900_000,
      1_700_100_400_000,
      low,
      1_700_099_450_000,
    )
  let logic_cred = Script(sv_logic_hash)
  let elig: Data = EligibilityClaim { spot, policies: [terms] }
  let base =
    Transaction {
      ..fixtures.base_tx(),
      inputs: [sv_vault_input(300_000_000, old)],
      reference_inputs: [
        sv_registry_ref_cfg(sv_config(ml_mandates(TrailingLowLeg))),
        feed,
      ],
      outputs: [
        sv_cont_output(269_600_000, new),
        sv_policy_output_raw(50_000_000, sv_pinned_pd(pd)),
        fixtures.pkh_output(sv_cfg_team_key, 400_000),
      ],
      mint: assets.from_asset(sv_marker_policy, policy_marker_asset_name, 1),
      withdrawals: [Pair(logic_cred, 0)],
      redeemers: [Pair(Withdraw(logic_cred), elig)],
    }
  fixtures.with_observer_attestation(
    base,
    sv_observer_hash,
    [(AegisSelf, sv_ada_nft())],
  )
}

/// THE NON-VACUITY ANCHOR, 5-key. A market that only ROSE: the trailing low
/// equals the spot, so `min` is the identity and the honest sale goes through
/// untouched. Every refusal below must leave this GREEN.
test ml_honest_anchor_5key_flat_low_sells() {
  ml_run(ml_barrier_tx(100_000_000, 100_000_000, 80_000_000))
}

/// THE SALE-SIDE HOLE, 5-key. Strike 80.00 against a spot of 100.00 is 2000 bps
/// out of the money and clears the 1500 bps guard on the PRINT — but the same
/// reading remembers a low of 85.00, against which the same strike is 588 bps
/// out. The vault was selling barrier cover measured off a number the feed
/// itself contradicts.
test ml_5key_trailing_low_refuses_a_strike_the_spot_alone_would_sell() {
  !ml_run(ml_barrier_tx(100_000_000, 85_000_000, 80_000_000))
}

/// ...and the boundary is the LEG's, not the spot's: 68.00 against the same
/// 85.00 low is exactly 2000 bps out and sells. The refusal above is about the
/// distance, not about the presence of a low.
test ml_5key_trailing_low_still_sells_a_strike_clear_of_the_low() {
  ml_run(ml_barrier_tx(100_000_000, 85_000_000, 68_000_000))
}

// ---------------------------------------------------------------------------
// SHAPE 2 — the THREE-key AegisSelf feed, the shape every live depeg feed
// publishes today. `min_price_12h` defaults to spot, so `min` is the identity
// and the leg is INERT. That is the graceful degradation, and it is what makes
// arming keys 3/4 a publisher deploy rather than a validator change.
// ---------------------------------------------------------------------------

fn ml_barrier_3key_tx(spot: Int, strike: Int) -> Transaction {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let pd =
    PolicyDatum { ..sv_underwrite_policy_datum(), strike_price: strike }
  let terms = PolicyTerms { ..sv_underwrite_terms(50_000_000), strike: strike }
  let tx =
    sv_underwrite_tx(
      300_000_000,
      old,
      270_000_000,
      new,
      50_000_000,
      pd,
      spot,
      spot,
      terms,
      1,
    )
  sv_with_registry_cfg(tx, sv_config(ml_mandates(TrailingLowLeg)))
}

/// 3-KEY, the live shape: the identical strike the 5-key witness above REFUSES
/// is SOLD here, because the publisher writes no key 3 and the parser defaults
/// `min_price_12h` to spot. Not a defect — the pair with that test is the
/// executable statement of what arming keys 3/4 buys, and of what it costs
/// nothing until then.
test ml_3key_min_leg_is_inert_and_the_sale_still_completes() {
  ml_run(ml_barrier_3key_tx(100_000_000, 80_000_000))
}

/// 3-KEY: a strike inside the guard is still refused, so the arm is bounded
/// rather than merely open on this shape.
test ml_3key_near_money_strike_is_still_refused() {
  !ml_run(ml_barrier_3key_tx(100_000_000, 90_000_000))
}

// ---------------------------------------------------------------------------
// SHAPE 3 — DEPEG on a 5-key feed. THE MEMO'S CASE, executable: the coin has
// broken on a DEX, the last print still says 1.00 and reads "peg healthy", and
// the buyer takes ~20 ADA of cover against ~500 ADA of pool.
// ---------------------------------------------------------------------------

fn ml_depeg_tx(spot: Int, low: Int) -> Transaction {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let feed =
    fixtures.aegis_self_feed_input_full(
      sv_depeg_nft(),
      spot,
      sv_uw_start - 200_000,
      1_700_100_400_000,
      low,
      sv_uw_start - 400_000,
    )
  let logic_cred = Script(sv_logic_hash)
  let terms =
    PolicyTerms {
      ..sv_underwrite_terms(50_000_000),
      risk_class: Depeg,
      strike: 900_000,
      oracle_nft: sv_depeg_nft(),
    }
  let elig: Data = EligibilityClaim { spot, policies: [terms] }
  let depeg_cfg =
    sv_config(
      [
        OracleMandate {
          primary_nft: sv_depeg_nft(),
          fallback_feed_id: #"",
          second_leg: TrailingLowLeg,
        },
      ],
    )
  let base =
    Transaction {
      ..fixtures.base_tx(),
      inputs: [sv_vault_input(300_000_000, old)],
      reference_inputs: [sv_registry_ref_cfg(depeg_cfg), feed],
      outputs: [
        sv_cont_output(269_600_000, new),
        sv_policy_output_raw(50_000_000, sv_pinned_pd(sv_depeg_policy_datum())),
        fixtures.pkh_output(sv_cfg_team_key, 400_000),
      ],
      mint: assets.from_asset(sv_marker_policy, policy_marker_asset_name, 1),
      withdrawals: [Pair(logic_cred, 0)],
      redeemers: [Pair(Withdraw(logic_cred), elig)],
    }
  fixtures.with_observer_attestation(
    base,
    sv_observer_hash,
    [(AegisSelf, sv_depeg_nft())],
  )
}

/// THE NON-VACUITY ANCHOR, Depeg 5-key. A peg that held: low 0.995 is above the
/// 0.99 health floor, so honest depeg cover still sells against a real key 3.
test ml_honest_anchor_depeg_5key_healthy_low_sells() {
  ml_run(ml_depeg_tx(1_000_000, 995_000))
}

/// THE MEMO'S HOLE, executable. Low 0.96 sits ABOVE the 0.90 strike, so
/// `resolved_min_12h > strike` is satisfied and the #391 R2 gate does not fire
/// — but 0.96 is BELOW the 0.99 peg-health floor. Judged on the spot alone the
/// peg reads healthy and the sale completes; judged on `min` it does not.
/// Nothing but the min leg refuses this transaction.
test ml_depeg_5key_min_leg_refuses_a_peg_the_spot_calls_healthy() {
  !ml_run(ml_depeg_tx(1_000_000, 960_000))
}

// ---------------------------------------------------------------------------
// SHAPE 4 — the PYTH PULL LEG. The buyer builds the transaction and therefore
// supplies this print himself. These are the tests that decide whether that is
// safe.
// ---------------------------------------------------------------------------

/// A Barrier Underwrite whose mandate demands a Pyth pull leg. The buyer's
/// side of the transaction is real: the Pyth State reference input, the
/// withdraw redeemer carrying the vendored signed Lazer payload, and the
/// observer's attestation of feed 2 alongside the primary.
fn ml_pull_tx(spot: Int, strike: Int, leg: SecondLeg, attest_pull: Bool) -> Transaction {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let pd =
    PolicyDatum {
      ..sv_underwrite_policy_datum(),
      strike_price: strike,
      start_time: sv_uw_pyth_start,
      expiry_time: sv_uw_pyth_start + 2_592_000_000,
    }
  let terms = PolicyTerms { ..sv_underwrite_terms(50_000_000), strike: strike }
  let feed =
    fixtures.aegis_self_feed_input(
      sv_ada_nft(),
      spot,
      sv_uw_pyth_obs,
      sv_uw_pyth_start + 600_000,
    )
  let logic_cred = Script(sv_logic_hash)
  let elig: Data = EligibilityClaim { spot, policies: [terms] }
  let raw_updates: Data = [pyth_fixtures.pyth_test_update]
  let base =
    Transaction {
      ..fixtures.base_tx(),
      inputs: [sv_vault_input(300_000_000, old)],
      reference_inputs: [
        sv_registry_ref_cfg(ml_config(leg)),
        feed,
        pyth_fixtures.pyth_state_ref_input(),
      ],
      outputs: [
        sv_cont_output(269_600_000, new),
        sv_policy_output_raw(50_000_000, sv_pinned_pd(pd)),
        fixtures.pkh_output(sv_cfg_team_key, 400_000),
      ],
      mint: assets.from_asset(sv_marker_policy, policy_marker_asset_name, 1),
      validity_range: fixtures.finite_range(sv_uw_pyth_obs, sv_uw_pyth_start),
      withdrawals: [Pair(logic_cred, 0)],
      redeemers: [
        Pair(Withdraw(logic_cred), elig),
        Pair(
          Withdraw(Script(pyth_fixtures.pyth_test_withdraw_hash)),
          raw_updates,
        ),
      ],
    }
  let feeds =
    if attest_pull {
      [(AegisSelf, sv_ada_nft()), (Pyth, #"02")]
    } else {
      [(AegisSelf, sv_ada_nft())]
    }
  fixtures.with_observer_attestation(base, sv_observer_hash, feeds)
}

fn ml_pyth_leg() -> SecondLeg {
  PythPullLeg { feed_id: #"02", require_confidence: False }
}

/// THE NON-VACUITY ANCHOR, pull leg. Primary 2.100e9, pull 2.013e9, strike
/// 1.600e9 — 2052 bps clear of the LOWER of the two. Dual-leg cover sells.
test ml_honest_anchor_pull_leg_sells() {
  ml_run(ml_pull_tx(2_100_000_000, 1_600_000_000, ml_pyth_leg(), True))
}

/// THE BUYER-CHOSEN-PRICE ATTACK, REFUSED BY `min`. Strike 1.750e9 is 1666 bps
/// out of the money against the PRIMARY print of 2.100e9 and clears the 1500
/// bps guard — so on the primary alone this cover sells. Against the pull leg's
/// 2.013e9 the same strike is 1306 bps out. `min` takes the lower and the sale
/// is refused.
test ml_pull_leg_refuses_a_strike_the_primary_alone_would_sell() {
  !ml_run(ml_pull_tx(2_100_000_000, 1_750_000_000, ml_pyth_leg(), True))
}

/// THE SELECTION ARGUMENT, EXECUTABLE. Here the buyer's own leg is the HIGHER
/// number — 2.013e9 against a primary of 1.900e9 — which is exactly what an
/// attacker shopping the window would submit. `min` ignores it: the decision
/// is still made on 1.900e9, where strike 1.750e9 is 789 bps out and refused.
/// Lifting his leg cannot buy him a sale, which is the whole reason a
/// buyer-supplied print is admissible in this position at all.
test ml_pull_leg_lifted_by_the_buyer_cannot_rescue_a_near_money_strike() {
  !ml_run(ml_pull_tx(1_900_000_000, 1_750_000_000, ml_pyth_leg(), True))
}

/// ...and the same transaction with the pull leg mandated but NOT supplied is
/// refused rather than falling back to the primary alone. A leg that may be
/// omitted is not a leg.
test ml_mandated_pull_leg_absent_refuses_the_sale() {
  !ml_run(ml_pull_tx(2_100_000_000, 1_600_000_000, ml_pyth_leg(), False))
}

/// The same absent-leg transaction under a mandate that does NOT demand a pull
/// leg SELLS — so the refusal above is the mandate biting, not the fixture
/// being broken.
test ml_no_second_leg_mandate_sells_without_a_pull_leg() {
  ml_run(ml_pull_tx(2_100_000_000, 1_600_000_000, NoSecondLeg, False))
}

/// [#403 FIX 4] Confidence is a CONJUNCT on the pull leg. The vendored signed
/// Lazer payload carries NO confidence — which is precisely why the global
/// `pyth_reject_absent_confidence` stays False — so a mandate that demands it
/// refuses this otherwise-honest dual-leg sale. Paired with
/// `ml_honest_anchor_pull_leg_sells`, which is the same transaction under
/// `require_confidence: False`, this is the whole per-mandate behaviour.
test ml_pull_leg_require_confidence_refuses_a_payload_without_one() {
  !ml_run(
    ml_pull_tx(
      2_100_000_000,
      1_600_000_000,
      PythPullLeg { feed_id: #"02", require_confidence: True },
      True,
    ),
  )
}

/// The pull leg carries its OWN sale-side freshness, independent of the push
/// print's. This is the minimal pair for that leg: the PRIMARY feed is moved
/// forward with `start_time` so it stays 100s fresh in BOTH members, and the
/// vendored Lazer payload's timestamp is fixed, so the pull leg's age is the
/// only quantity that changes. `start_off` is `start_time`'s offset past the
/// payload — 600_000 is the last admissible instant on a Barrier.
fn ml_pull_age_tx(start_off: Int) -> Transaction {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let start = sv_uw_pyth_obs + start_off
  let pd =
    PolicyDatum {
      ..sv_underwrite_policy_datum(),
      strike_price: 1_600_000_000,
      start_time: start,
      expiry_time: start + 2_592_000_000,
    }
  let terms =
    PolicyTerms { ..sv_underwrite_terms(50_000_000), strike: 1_600_000_000 }
  let feed =
    fixtures.aegis_self_feed_input(
      sv_ada_nft(),
      2_100_000_000,
      start - 100_000,
      start + 600_000,
    )
  let logic_cred = Script(sv_logic_hash)
  let elig: Data =
    EligibilityClaim { spot: 2_100_000_000, policies: [terms] }
  let raw_updates: Data = [pyth_fixtures.pyth_test_update]
  let base =
    Transaction {
      ..fixtures.base_tx(),
      inputs: [sv_vault_input(300_000_000, old)],
      reference_inputs: [
        sv_registry_ref_cfg(ml_config(ml_pyth_leg())),
        feed,
        pyth_fixtures.pyth_state_ref_input(),
      ],
      outputs: [
        sv_cont_output(269_600_000, new),
        sv_policy_output_raw(50_000_000, sv_pinned_pd(pd)),
        fixtures.pkh_output(sv_cfg_team_key, 400_000),
      ],
      mint: assets.from_asset(sv_marker_policy, policy_marker_asset_name, 1),
      validity_range: fixtures.finite_range(start - 600_000, start),
      withdrawals: [Pair(logic_cred, 0)],
      redeemers: [
        Pair(Withdraw(logic_cred), elig),
        Pair(
          Withdraw(Script(pyth_fixtures.pyth_test_withdraw_hash)),
          raw_updates,
        ),
      ],
    }
  fixtures.with_observer_attestation(
    base,
    sv_observer_hash,
    [(AegisSelf, sv_ada_nft()), (Pyth, #"02")],
  )
}

/// THE HONEST BOUNDARY: coverage begins exactly 600s after the pull print, the
/// last instant the Barrier sale-side window admits. Sells.
test ml_pull_leg_at_the_sale_side_window_edge_sells() {
  ml_run(ml_pull_age_tx(600_000))
}

/// ONE MILLISECOND LATER. The primary print is 100s old in both members, so
/// nothing but the PULL leg's own window can be refusing this one.
test ml_pull_leg_one_ms_past_the_sale_side_window_is_refused() {
  !ml_run(ml_pull_age_tx(600_001))
}

// ---------------------------------------------------------------------------
// THE AVAILABILITY WIN. With an INDEPENDENT pull leg present and valid, the
// CORE ceiling on the push leg's age widens to `max_dual_leg_spot_age_ms`, so
// a slow publisher stops DENYING sales. `min` is what makes that safe: the
// stale push print can no longer be the number the strike is measured against.
// ---------------------------------------------------------------------------

/// A dual-leg Underwrite whose PRIMARY print is 30 minutes old — five times the
/// Barrier class budget — with governance having widened its own budget to
/// match. The pull leg is fresh.
fn ml_wide_tx(leg: SecondLeg) -> Transaction {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let start = sv_uw_pyth_obs + 300_000
  let pd =
    PolicyDatum {
      ..sv_underwrite_policy_datum(),
      strike_price: 1_600_000_000,
      start_time: start,
      expiry_time: start + 2_592_000_000,
    }
  let terms =
    PolicyTerms { ..sv_underwrite_terms(50_000_000), strike: 1_600_000_000 }
  let feed =
    fixtures.aegis_self_feed_input(
      sv_ada_nft(),
      2_100_000_000,
      start - 1_800_000,
      start + 600_000,
    )
  let cfg = ml_config(leg)
  let wide =
    UnderwriteConfig {
      ..cfg,
      budgets: Budgets { ..cfg.budgets, spot_age_barrier_ms: 3_600_000 },
    }
  let logic_cred = Script(sv_logic_hash)
  let elig: Data =
    EligibilityClaim { spot: 2_100_000_000, policies: [terms] }
  let raw_updates: Data = [pyth_fixtures.pyth_test_update]
  let base =
    Transaction {
      ..fixtures.base_tx(),
      inputs: [sv_vault_input(300_000_000, old)],
      reference_inputs: [
        sv_registry_ref_cfg(wide),
        feed,
        pyth_fixtures.pyth_state_ref_input(),
      ],
      outputs: [
        sv_cont_output(269_600_000, new),
        sv_policy_output_raw(50_000_000, sv_pinned_pd(pd)),
        fixtures.pkh_output(sv_cfg_team_key, 400_000),
      ],
      mint: assets.from_asset(sv_marker_policy, policy_marker_asset_name, 1),
      validity_range: fixtures.finite_range(start - 600_000, start),
      withdrawals: [Pair(logic_cred, 0)],
      redeemers: [
        Pair(Withdraw(logic_cred), elig),
        Pair(
          Withdraw(Script(pyth_fixtures.pyth_test_withdraw_hash)),
          raw_updates,
        ),
      ],
    }
  fixtures.with_observer_attestation(
    base,
    sv_observer_hash,
    [(AegisSelf, sv_ada_nft()), (Pyth, #"02")],
  )
}

/// A 30-minute-old push print SELLS when an independent pull leg caps it.
test ml_dual_leg_widens_the_push_budget_and_the_sale_completes() {
  ml_run(ml_wide_tx(ml_pyth_leg()))
}

/// ...and does NOT when the second leg is the same publisher's own memory. The
/// transaction is byte-identical but for the mandate's leg, so this pair is the
/// whole statement of why `TrailingLowLeg` is not independent: if the print is
/// stale its trailing low is stale with it, and `min` does not defend against
/// correlated staleness.
test ml_trailing_low_leg_does_not_widen_the_push_budget() {
  !ml_run(ml_wide_tx(TrailingLowLeg))
}

/// [#403 FIX 1] The S5 coupling on the pull leg. Byte-identical to
/// `ml_honest_anchor_pull_leg_sells` except that the config's Pyth allowlist no
/// longer contains the feed its own mandate demands — a config that would
/// otherwise point the sale-side leg at any 1-byte id it liked.
test ml_pull_leg_feed_outside_the_allowlist_is_out_of_rails() {
  let tx = ml_pull_tx(2_100_000_000, 1_600_000_000, ml_pyth_leg(), True)
  let unrailed =
    UnderwriteConfig { ..ml_config(ml_pyth_leg()), pyth_feed_allowlist: [] }
  !ml_run(sv_with_registry_cfg(tx, unrailed))
}

/// THE MONOTONICITY THEOREM the whole mechanism rests on, stated over the
/// predicate itself rather than a transaction: lowering the resolved spot can
/// only ever turn an ACCEPT into a REFUSE, never the reverse. If this is ever
/// false, `min` stops being a one-sided defence and a buyer-supplied leg stops
/// being safe in this position.
test ml_underwrite_is_monotone_non_decreasing_in_the_resolved_spot() {
  and {
    // Barrier: the same strike, judged on a lower spot, refuses.
    underwrite_baseline_ok(
      Barrier,
      100_000_000,
      100_000_000,
      80_000_000,
      20_000_000,
      50_000_000,
      2_592_000_000,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    !underwrite_baseline_ok(
      Barrier,
      85_000_000,
      85_000_000,
      80_000_000,
      20_000_000,
      50_000_000,
      2_592_000_000,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    // Depeg: likewise, through the peg-health floor.
    underwrite_baseline_ok(
      Depeg,
      1_000_000,
      1_000_000,
      900_000,
      20_000_000,
      50_000_000,
      2_592_000_000,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    !underwrite_baseline_ok(
      Depeg,
      960_000,
      960_000,
      900_000,
      20_000_000,
      50_000_000,
      2_592_000_000,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
    // ...and RAISING it never turns a refuse into an accept beyond the guard:
    // the pull leg's own value, fed as the spot, decides exactly as `min` does.
    !underwrite_baseline_ok(
      Barrier,
      ml_pull_value,
      ml_pull_value,
      1_750_000_000,
      20_000_000,
      50_000_000,
      2_592_000_000,
      True,
      True,
      min_premium,
      min_policy_term_ms,
      max_policy_term_ms,
    ),
  }
}

test ml_shape_witness_five_key_datum_surfaces_key_3() {
  let feed =
    fixtures.aegis_self_feed_input_full(
      sv_ada_nft(),
      100_000_000,
      1_700_099_900_000,
      1_700_100_400_000,
      85_000_000,
      1_700_099_450_000,
    )
  let p = aegis_self.resolve([feed], sv_ada_nft())
  p.value == 100_000_000 && p.min_price_12h == 85_000_000
}

// ===========================================================================
// [V8.2 G5] THE SETTLEMENT-FALLBACK PIN.
//
// Settlement resolves the Pyth outage leg against the feed THIS POLICY pins,
// and the buyer authors the policy datum. `is_canonical_oracle_nft(Pyth, ..)`
// survives that but proves only that the id is A canonical Lazer feed — never
// that it is the feed for the policy's OWN underlying. An ADA policy pinning
// BTC's feed is a basis attack of the `cover_escrow` provider-pin class: a
// permissionless path that must pin EVERY claim-load-bearing field.
//
// Underwrite is where the mandate is admissible (it is the only arm that reads
// the registry — Invariant S), so it is where the pin is bound: EXACTLY the
// governed mandate's `fallback_feed_id` for this policy's own `oracle_nft`,
// with `#""` — no pins tail at all, or a tail pinning nothing — the only value
// a mandate arming no fallback admits. Equality, not membership: the pins are
// the GOVERNED values copied into the policy, and a partial copy is not a copy.
//
// `pyth_feed_allowlist` carries both feeds in every scenario below because
// `config_within_rails` refuses a mandate whose fallback is not allowlisted —
// without it the config would be rejected before the pin was ever read, and
// the negatives would pass for the wrong reason.
// ===========================================================================

const g5_armed_feed: ByteArray = #"10"

const g5_foreign_feed: ByteArray = #"07"

fn g5_cfg(mandate_feed: ByteArray, leg: SecondLeg) -> UnderwriteConfig {
  let cfg =
    sv_config(
      [
        OracleMandate {
          primary_nft: sv_ada_nft(),
          fallback_feed_id: mandate_feed,
          second_leg: leg,
        },
      ],
    )
  UnderwriteConfig {
    ..cfg,
    pyth_feed_allowlist: [g5_armed_feed, g5_foreign_feed],
  }
}

/// The Underwrite green path with the governed mandate's fallback and the
/// policy's pinned one supplied independently. Everything else is
/// `sv_underwrite_green_path`, so only the pin can decide.
fn g5_run(mandate_feed: ByteArray, leg: SecondLeg, pinned_feed: ByteArray) -> Bool {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let tx =
    sv_underwrite_tx_raw(
      300_000_000,
      old,
      270_000_000,
      new,
      50_000_000,
      fixtures.policy_datum_with_pins(
        sv_underwrite_policy_datum(),
        claim_waiting_period_ms(Barrier),
        pinned_feed,
      ),
      100_000_000,
      100_000_000,
      sv_underwrite_terms(50_000_000),
      1,
    )
  sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_with_registry_cfg(tx, g5_cfg(mandate_feed, leg)),
  )
}

/// The honest anchor. A refusal that also refuses honest business is an outage,
/// not a fix — so the armed pair must go on selling.
test g5_uw_sells_a_policy_pinning_the_feed_its_mandate_arms() {
  g5_run(g5_armed_feed, TrailingLowLeg, g5_armed_feed)
}

/// THE HOLE. Both feeds are canonical Lazer ids and both are allowlisted, so
/// every check that existed before this conjunct passes — and the policy still
/// settles its outage leg against an instrument its own mandate never named.
test g5_uw_refuses_a_pin_the_mandate_did_not_arm() {
  !g5_run(g5_armed_feed, TrailingLowLeg, g5_foreign_feed)
}

/// ...and a mandate carrying NO second leg arms no fallback at all, so any
/// non-empty pin under it is manufactured outright.
test g5_uw_refuses_a_pin_where_the_mandate_arms_none() {
  !g5_run(#"", NoSecondLeg, g5_armed_feed)
}

/// The matching empty pin under that same mandate sells — the refusal above is
/// the pin biting, not the fixture being broken.
test g5_uw_sells_an_empty_pin_under_a_mandate_with_no_second_leg() {
  g5_run(#"", NoSecondLeg, #"")
}

// ===========================================================================
// [V8.2 G3] GOVERNED BUDGETS AT THE BASELINE. The premium floor and the term
// bounds Underwrite enforces are `Budgets.min_premium` / `term_min_ms` /
// `term_max_ms` — the governed values, rail-bounded, tightened by governance
// without a hash migration. Each pair below tightens ONE budget past the green
// scenario (premium 20M net 19.6M, term 30 days) with every compiled constant
// still satisfied, so only the governed read can refuse; the anchor half runs
// the identical transaction under the genesis budgets.
// ===========================================================================

fn g3_run(budgets: Budgets) -> Bool {
  let old = sv_state(1000, 0, 10_000_000)
  let new = sv_state(1000, 50_000_000, 10_000_000)
  let tx = sv_underwrite_tx(
    300_000_000,
    old,
    270_000_000,
    new,
    50_000_000,
    sv_underwrite_policy_datum(),
    100_000_000,
    100_000_000,
    sv_underwrite_terms(50_000_000),
    1,
  )
  let cfg = sv_config([sv_mandate(sv_ada_nft())])
  sv_run_underwrite(
    old,
    50_000_000,
    20_000_000,
    sv_with_registry_cfg(tx, UnderwriteConfig { ..cfg, budgets }),
  )
}

fn g3_genesis_budgets() -> Budgets {
  sv_config([sv_mandate(sv_ada_nft())]).budgets
}

test g3_uw_rejects_a_net_premium_under_the_governed_floor() {
  and {
    g3_run(g3_genesis_budgets()),
    !g3_run(Budgets { ..g3_genesis_budgets(), min_premium: 25_000_000 }),
  }
}

test g3_uw_rejects_a_term_over_the_governed_ceiling() {
  and {
    g3_run(g3_genesis_budgets()),
    // 14 days: in-rails, above the CORE floor, below the 30-day term
    !g3_run(Budgets { ..g3_genesis_budgets(), term_max_ms: 1_209_600_000 }),
  }
}

test g3_uw_rejects_a_term_under_the_governed_floor() {
  and {
    g3_run(g3_genesis_budgets()),
    // 60 days: in-rails, above the 30-day term, below the CORE ceiling
    !g3_run(Budgets { ..g3_genesis_budgets(), term_min_ms: 5_184_000_000 }),
  }
}
