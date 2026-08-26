// =============================================================================
// Aegis Insurance Protocol - Yield-Funded Premium Stake Validator (v2)
// Location: contracts/validators/premium_stake.ak
// Summary: A PER-ENROLLEE, non-custodial stake-credential script (a Rewarding +
//          Publishing purpose class). The enrollee's funds live at
//            Address{ payment = VerificationKey(user_vkh), stake = Script(this) }
//          so the principal is ALWAYS spendable by the enrollee (ledger
//          guarantee); this script governs ONLY delegation (publish) and reward
//          withdrawal (withdraw).
//
//          Parameterized PER-ENROLLEE by `user_vkh` so every enrollee gets a
//          DISTINCT script hash => DISTINCT stake credential => DISTINCT reward
//          account (no pooled reward account; a de-registration or re-delegation
//          touches only that one enrollee). Also parameterized by the shared
//          cover_escrow script hash, the enrollee's CoverTerms (as opaque Data,
//          compared byte-for-byte against the escrow output datum), the
//          canonical SPO, and the split rate. There is NO pool binding: a
//          harvest never spends the pool UTxO, so harvests are mutually
//          independent and survive pool ceremonies.
//
//          On `withdraw`, the ledger force-drains the full reward balance W for
//          THIS account. Exactly ONE withdrawal per tx (kills the
//          multi-withdraw double-satisfaction), then one of two paths:
//            * KEEPER SPLIT (permissionless): premium =
//              floor(W * split_bps / 10_000) >= 1.5 ADA must land in EXACTLY
//              ONE output at the cover_escrow script (enterprise form, inline
//              datum == cover_terms), and the remainder W - premium must reach
//              the enrollee's ENTERPRISE address VK(user_vkh)/None — so a
//              keeper can neither divert the remainder nor stake-graft it
//              (A-009), nor split the premium across escrow outputs.
//            * USER EXIT (user_vkh-signed): the FULL balance W to the
//              enrollee's enterprise address, no escrow, no floor. This is the
//              liveness escape: without it, any balance frozen in (0, 6 ADA)
//              could never be zeroed (the ledger rejects deregistration with a
//              nonzero reward balance), stranding the 2-ADA deposit forever —
//              permanently under a retired SPO. Skipping the split is safe: the
//              user merely skips funding THEIR OWN cover.
//
//          On `publish`, only the enrollee (user_vkh signature) may register /
//          delegate / unregister this credential, and any delegation is PINNED
//          to DelegateBoth{ target_stake_pool, AlwaysAbstain } (AlwaysAbstain
//          is mandatory post-Chang or rewards strand) — no party can re-point
//          the stake or capture the vote. Conway ledger gap, accepted: the
//          deprecated witness-free `stake_registration` cert (code 0) can
//          register this credential WITHOUT this handler running — nothing of
//          value is at risk (delegation/withdrawal/dereg still require the
//          script witness), but enroll builders must preflight the registered
//          flag and fall back to a delegation-only cert.
//
//          The off-chain harvest keeper byte-mirrors `premium_from_reward`.
// =============================================================================

use aegis/types.{VerificationKeyHash}
use aegis/validation.{must_be_signed_by, sum_lovelace_to_enterprise_pkh}
use aiken/collection/list
use cardano/address.{Address, Credential, Inline, Script, VerificationKey}
use cardano/assets
use cardano/certificate.{
  AlwaysAbstain, Certificate, Delegate, DelegateBoth, DelegateCredential,
  DelegateVote, RegisterAndDelegateCredential, RegisterCredential,
  RegisterStakePool, Registered, StakePoolId, UnregisterCredential,
}
use cardano/transaction.{InlineDatum, NoDatum, Output, Transaction}

// ---------------------------------------------------------------------------
// Shared split math — the SINGLE on-chain source the off-chain keeper /
// harvest builder MUST byte-mirror (Python `//` == Aiken `/` for non-negative
// operands; W and split_bps are always >= 0).
// ---------------------------------------------------------------------------

/// premium = floor(reward * split_bps / 10_000). Truncating integer division.
pub fn premium_from_reward(reward: Int, split_bps: Int) -> Int {
  reward * split_bps / 10_000
}

/// The keeper split settles only when the escrow slice clears the escrow
/// min-UTxO with margin; below this, harvests defer (rewards auto-compound)
/// until the balance grows or the user exits via the signed path.
pub const min_escrow_premium: Int = 1_500_000

/// The only delegation this credential ever authorizes: stake -> the canonical
/// SPO, vote -> AlwaysAbstain. Destructured (not `==`) to avoid the sum-type Eq
/// pitfall on Windows.
fn delegate_is_canonical(delegate: Delegate, target_stake_pool: StakePoolId) -> Bool {
  when delegate is {
    DelegateBoth { stake_pool, delegate_representative } -> {
      let abstain =
        when delegate_representative is {
          AlwaysAbstain -> True
          _ -> False
        }
      stake_pool == target_stake_pool && abstain
    }
    _ -> False
  }
}

// ---------------------------------------------------------------------------
// premium_stake validator
// ---------------------------------------------------------------------------

validator premium_stake(
  escrow_script_hash: ByteArray,
  cover_terms: Data,
  target_stake_pool: StakePoolId,
  split_bps: Int,
  user_vkh: VerificationKeyHash,
) {
  // Rewarding purpose: the ledger force-drains the full reward balance W of
  // `account` (this script's own stake credential).
  withdraw(_redeemer: Data, account: Credential, self: Transaction) {
    // EXACTLY ONE withdrawal in the tx, and it is THIS account. Any other
    // multiplicity rejects — this is the anti-double-count guard: two
    // premium_stake withdrawals can never share one escrow credit or one
    // remainder output.
    when self.withdrawals is {
      [Pair(wacct, w)] -> {
        // Shared across both paths — one fold over outputs, not two.
        let to_user = sum_lovelace_to_enterprise_pkh(self.outputs, user_vkh)

        // USER EXIT: the enrollee signed, and the full balance reaches their
        // enterprise address. No escrow, no floor — the liveness escape for
        // dust balances, SPO retirement, and unenrollment.
        let exit_ok =
          must_be_signed_by(self.extra_signatories, user_vkh) && to_user >= w

        // KEEPER SPLIT: premium to EXACTLY ONE escrow output (enterprise
        // form, inline datum == the enrollee's baked cover_terms), remainder
        // to the enrollee's enterprise address.
        let premium = premium_from_reward(w, split_bps)
        let split_ok =
          when
            list.filter(
              self.outputs,
              fn(o) { o.address.payment_credential == Script(escrow_script_hash) },
            )
          is {
            [escrow_out] -> and {
                premium >= min_escrow_premium,
                escrow_out.address.stake_credential == None,
                when escrow_out.datum is {
                  InlineDatum(raw) -> raw == cover_terms
                  _ -> False
                },
                assets.lovelace_of(escrow_out.value) >= premium,
                to_user >= w - premium,
              }
            _ -> False
          }

        wacct == account && (exit_ok || split_ok)
      }
      _ -> False
    }
  }

  // Publishing purpose: ONLY the enrollee (user_vkh signature) may manage this
  // credential's lifecycle, and any delegation is PINNED to the canonical
  // SPO + AlwaysAbstain. Closes the communal re-delegation / vote-capture and
  // at-will de-registration griefs (and per-enrollee scoping bounds them to one
  // enrollee regardless).
  publish(_redeemer: Data, certificate: Certificate, self: Transaction) {
    let signed = list.has(self.extra_signatories, user_vkh)
    when certificate is {
      RegisterCredential { .. } -> signed
      RegisterAndDelegateCredential { delegate, .. } ->
        signed && delegate_is_canonical(delegate, target_stake_pool)
      DelegateCredential { delegate, .. } ->
        signed && delegate_is_canonical(delegate, target_stake_pool)
      UnregisterCredential { .. } -> signed
      _ -> False
    }
  }

  else(_) {
    fail @"Unsupported purpose for premium_stake"
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const ps_escrow_hash: ByteArray =
  #"e5c60e5c60e5c60e5c60e5c60e5c60e5c60e5c60e5c60e5c60e5c60e"

const ps_user_vkh: ByteArray =
  #"00112233445566778899aabbccddeeff00112233445566778899aabb"

const ps_stake_vkh: ByteArray =
  #"aabbccddeeff00112233445566778899aabbccddeeff001122334455"

const ps_target_pool: ByteArray =
  #"0011223344556677889900112233445566778899001122334455667788"

const ps_other_pool: ByteArray =
  #"9999999999999999999999999999999999999999999999999999999999"

const ps_split_bps: Int = 2_500

// Reward 100 ADA -> premium = 100 * 2500 / 10000 = 25 ADA, remainder 75 ADA.
const ps_reward: Int = 100_000_000

const ps_premium: Int = 25_000_000

fn ps_account() -> Credential {
  Script(ps_stake_vkh)
}

fn ps_cover_terms() -> Data {
  let d: Data = "AEGIS_COVER_TERMS_FIXTURE"
  d
}

fn ps_wrong_terms() -> Data {
  let d: Data = "SOMEONE_ELSES_TERMS"
  d
}

// The enrollee remainder output. `enterprise` toggles a clean VK(user)/None
// address vs an A-009-style stake-grafted address (which must NOT count).
fn ps_user_output(value: Int, enterprise: Bool) -> Output {
  let stake =
    if enterprise {
      None
    } else {
      Some(Inline(Script(#"a77ac6a77ac6a77ac6a77ac6a77ac6a77ac6a77ac6a77ac6a77ac6")))
    }
  Output {
    address: Address {
      payment_credential: VerificationKey(ps_user_vkh),
      stake_credential: stake,
    },
    value: assets.from_lovelace(value),
    datum: NoDatum,
    reference_script: None,
  }
}

// The escrow output. Knobs isolate each negative: stake-grafted escrow,
// wrong datum, missing datum.
fn ps_escrow_output(
  value: Int,
  script_hash: ByteArray,
  enterprise: Bool,
  datum: Data,
  inline: Bool,
) -> Output {
  let stake =
    if enterprise {
      None
    } else {
      Some(Inline(VerificationKey(#"5eaf00d5eaf00d5eaf00d5eaf00d5eaf00d5eaf00d5eaf00d5eaf00d")))
    }
  Output {
    address: Address {
      payment_credential: Script(script_hash),
      stake_credential: stake,
    },
    value: assets.from_lovelace(value),
    datum: if inline {
      InlineDatum(datum)
    } else {
      NoDatum
    },
    reference_script: None,
  }
}

fn ps_tx(
  reward: Int,
  outputs: List<Output>,
  signers: List<ByteArray>,
  second_withdrawal: Bool,
) -> Transaction {
  let withdrawals =
    if second_withdrawal {
      [Pair(ps_account(), reward), Pair(Script(#"beef"), reward)]
    } else {
      [Pair(ps_account(), reward)]
    }
  Transaction {
    ..transaction.placeholder,
    outputs: outputs,
    withdrawals: withdrawals,
    extra_signatories: signers,
  }
}

fn ps_withdraw(tx: Transaction) -> Bool {
  premium_stake.withdraw(
    ps_escrow_hash,
    ps_cover_terms(),
    ps_target_pool,
    ps_split_bps,
    ps_user_vkh,
    Void,
    ps_account(),
    tx,
  )
}

// A compliant keeper split: premium -> escrow (inline cover_terms), the
// remainder -> the enrollee's enterprise address, no signature.
fn ps_split_tx(reward: Int, premium: Int) -> Transaction {
  ps_tx(
    reward,
    [
      ps_escrow_output(premium, ps_escrow_hash, True, ps_cover_terms(), True),
      ps_user_output(reward - premium, True),
    ],
    [],
    False,
  )
}

// Truncation golden — MUST byte-mirror the off-chain keeper.
test split_truncation_matches_keeper() {
  premium_from_reward(333, 2_500) == 83 && premium_from_reward(100_000_000, 2_500) == 25_000_000
}

// ---------------------------------------------------------------------------
// withdraw: keeper split path
// ---------------------------------------------------------------------------

// GREEN: compliant harvest settles. premium 25 ADA -> escrow, remainder
// 75 ADA -> user enterprise, single withdrawal, unsigned.
test ps_split_compliant_settles() {
  ps_withdraw(ps_split_tx(ps_reward, ps_premium)) == True
}

// [F1] NEGATIVE: keeper withholds the remainder (0 to the user) — keeps it
// as change.
test ps_split_remainder_withheld_rejected() {
  let tx =
    ps_tx(
      ps_reward,
      [ps_escrow_output(ps_premium, ps_escrow_hash, True, ps_cover_terms(), True)],
      [],
      False,
    )
  ps_withdraw(tx) == False
}

// [F1] NEGATIVE: remainder paid to a stake-GRAFTED VK(user) address (A-009) —
// the enterprise sum is 0, so it does not count.
test ps_split_remainder_stake_grafted_rejected() {
  let tx =
    ps_tx(
      ps_reward,
      [
        ps_escrow_output(ps_premium, ps_escrow_hash, True, ps_cover_terms(), True),
        ps_user_output(ps_reward - ps_premium, False),
      ],
      [],
      False,
    )
  ps_withdraw(tx) == False
}

// [multi-withdraw] NEGATIVE: a second withdrawal in the same tx — the
// exactly-one-withdrawal guard rejects (no shared escrow credit).
test ps_split_multi_withdrawal_rejected() {
  let tx =
    ps_tx(
      ps_reward,
      [
        ps_escrow_output(ps_premium, ps_escrow_hash, True, ps_cover_terms(), True),
        ps_user_output(ps_reward - ps_premium, True),
      ],
      [],
      True,
    )
  ps_withdraw(tx) == False
}

// NEGATIVE: escrow underfunded by 1 lovelace.
test ps_split_escrow_underfunded_rejected() {
  let tx =
    ps_tx(
      ps_reward,
      [
        ps_escrow_output(ps_premium - 1, ps_escrow_hash, True, ps_cover_terms(), True),
        ps_user_output(ps_reward - ps_premium, True),
      ],
      [],
      False,
    )
  ps_withdraw(tx) == False
}

// NEGATIVE: premium routed to a DIFFERENT script than the baked escrow hash.
test ps_split_wrong_escrow_script_rejected() {
  let tx =
    ps_tx(
      ps_reward,
      [
        ps_escrow_output(
          ps_premium,
          #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
          True,
          ps_cover_terms(),
          True,
        ),
        ps_user_output(ps_reward - ps_premium, True),
      ],
      [],
      False,
    )
  ps_withdraw(tx) == False
}

// NEGATIVE: escrow output carries someone else's CoverTerms — the harvest
// would fund another enrollee's cover.
test ps_split_wrong_terms_rejected() {
  let tx =
    ps_tx(
      ps_reward,
      [
        ps_escrow_output(ps_premium, ps_escrow_hash, True, ps_wrong_terms(), True),
        ps_user_output(ps_reward - ps_premium, True),
      ],
      [],
      False,
    )
  ps_withdraw(tx) == False
}

// NEGATIVE: escrow output with NO inline datum — unspendable at the escrow
// script (donation-burn), must never settle.
test ps_split_datumless_escrow_rejected() {
  let tx =
    ps_tx(
      ps_reward,
      [
        ps_escrow_output(ps_premium, ps_escrow_hash, True, ps_cover_terms(), False),
        ps_user_output(ps_reward - ps_premium, True),
      ],
      [],
      False,
    )
  ps_withdraw(tx) == False
}

// NEGATIVE: stake-grafted ESCROW output — a keeper skimming staking rewards
// off the escrow balance (A-009 shape on the escrow side).
test ps_split_stake_grafted_escrow_rejected() {
  let tx =
    ps_tx(
      ps_reward,
      [
        ps_escrow_output(ps_premium, ps_escrow_hash, False, ps_cover_terms(), True),
        ps_user_output(ps_reward - ps_premium, True),
      ],
      [],
      False,
    )
  ps_withdraw(tx) == False
}

// NEGATIVE: premium split across TWO escrow outputs — the singleton pin
// rejects (min-UTxO dust games + double-count shapes die here).
test ps_split_two_escrow_outputs_rejected() {
  let tx =
    ps_tx(
      ps_reward,
      [
        ps_escrow_output(ps_premium / 2, ps_escrow_hash, True, ps_cover_terms(), True),
        ps_escrow_output(
          ps_premium - ps_premium / 2,
          ps_escrow_hash,
          True,
          ps_cover_terms(),
          True,
        ),
        ps_user_output(ps_reward - ps_premium, True),
      ],
      [],
      False,
    )
  ps_withdraw(tx) == False
}

// [F5] NEGATIVE: reward so small the premium sits under the 1.5-ADA escrow
// floor (W = 5 ADA -> premium 1.25 ADA) — the keeper path must defer, even
// with otherwise-compliant outputs.
test ps_split_below_floor_rejected() {
  ps_withdraw(ps_split_tx(5_000_000, 1_250_000)) == False
}

// NEGATIVE: no outputs at all.
test ps_split_no_outputs_rejected() {
  ps_withdraw(ps_tx(ps_reward, [], [], False)) == False
}

// ---------------------------------------------------------------------------
// withdraw: user exit path
// ---------------------------------------------------------------------------

// GREEN: user-signed exit — the FULL balance to the enrollee's enterprise
// address, no escrow output, no floor.
test ps_exit_signed_full_balance_settles() {
  let tx = ps_tx(ps_reward, [ps_user_output(ps_reward, True)], [ps_user_vkh], False)
  ps_withdraw(tx) == True
}

// GREEN: the deadlock case the exit path exists for — a dust balance below
// the keeper floor (W = 3 ADA < 6 ADA threshold) exits cleanly when signed.
test ps_exit_dust_balance_settles() {
  let tx = ps_tx(3_000_000, [ps_user_output(3_000_000, True)], [ps_user_vkh], False)
  ps_withdraw(tx) == True
}

// GREEN: a user-signed tx that still performs the compliant split is valid
// via the keeper path (signing never forbids the split).
test ps_exit_signed_split_settles() {
  let tx =
    ps_tx(
      ps_reward,
      [
        ps_escrow_output(ps_premium, ps_escrow_hash, True, ps_cover_terms(), True),
        ps_user_output(ps_reward - ps_premium, True),
      ],
      [ps_user_vkh],
      False,
    )
  ps_withdraw(tx) == True
}

// NEGATIVE: the keeper cannot use the exit path — unsigned full-balance-to-
// user without an escrow output rejects (it is not a compliant split either).
test ps_exit_unsigned_rejected() {
  let tx = ps_tx(ps_reward, [ps_user_output(ps_reward, True)], [], False)
  ps_withdraw(tx) == False
}

// NEGATIVE: signed exit that diverts part of the balance (< W to the user).
test ps_exit_diverted_rejected() {
  let tx =
    ps_tx(ps_reward, [ps_user_output(ps_reward - 1, True)], [ps_user_vkh], False)
  ps_withdraw(tx) == False
}

// NEGATIVE: signed exit paid to a stake-grafted VK(user) address (A-009).
test ps_exit_stake_grafted_rejected() {
  let tx = ps_tx(ps_reward, [ps_user_output(ps_reward, False)], [ps_user_vkh], False)
  ps_withdraw(tx) == False
}

// NEGATIVE: signed exit with a second withdrawal — multiplicity still pins.
test ps_exit_multi_withdrawal_rejected() {
  let tx = ps_tx(ps_reward, [ps_user_output(ps_reward, True)], [ps_user_vkh], True)
  ps_withdraw(tx) == False
}

// ---------------------------------------------------------------------------
// publish tests (constructible certificate arms)
// ---------------------------------------------------------------------------

fn ps_publish(cert: Certificate, signed: Bool) -> Bool {
  let signers =
    if signed {
      [ps_user_vkh]
    } else {
      []
    }
  premium_stake.publish(
    ps_escrow_hash,
    ps_cover_terms(),
    ps_target_pool,
    ps_split_bps,
    ps_user_vkh,
    Void,
    cert,
    Transaction { ..transaction.placeholder, extra_signatories: signers },
  )
}

fn ps_enroll_cert(stake_pool: ByteArray, abstain: Bool) -> Certificate {
  let drep =
    if abstain {
      AlwaysAbstain
    } else {
      Registered(Script(#"deadbeef"))
    }
  RegisterAndDelegateCredential {
    credential: ps_account(),
    delegate: DelegateBoth {
      stake_pool: stake_pool,
      delegate_representative: drep,
    },
    deposit: 2_000_000,
  }
}

// GREEN: canonical enroll (target SPO + AlwaysAbstain), user-signed.
test ps_enroll_canonical_signed_authorized() {
  ps_publish(ps_enroll_cert(ps_target_pool, True), True) == True
}

// [F4] NEGATIVE: canonical enroll but NOT user-signed — only the enrollee may
// register/delegate.
test ps_enroll_unsigned_rejected() {
  ps_publish(ps_enroll_cert(ps_target_pool, True), False) == False
}

// [F4] NEGATIVE: signed but delegating to a NON-canonical SPO (stake re-point).
test ps_enroll_wrong_pool_rejected() {
  ps_publish(ps_enroll_cert(ps_other_pool, True), True) == False
}

// [F4] NEGATIVE: signed, canonical SPO, but DRep is NOT AlwaysAbstain
// (governance-vote capture).
test ps_enroll_non_abstain_drep_rejected() {
  ps_publish(ps_enroll_cert(ps_target_pool, False), True) == False
}

// [F4] NEGATIVE: a vote-only re-delegation (DelegateVote) — not the pinned
// DelegateBoth canonical form.
test ps_delegate_vote_only_rejected() {
  let cert =
    DelegateCredential {
      credential: ps_account(),
      delegate: DelegateVote { delegate_representative: AlwaysAbstain },
    }
  ps_publish(cert, True) == False
}

// GREEN: re-delegate to the canonical form, user-signed.
test ps_redelegate_canonical_signed_authorized() {
  let cert =
    DelegateCredential {
      credential: ps_account(),
      delegate: DelegateBoth {
        stake_pool: ps_target_pool,
        delegate_representative: AlwaysAbstain,
      },
    }
  ps_publish(cert, True) == True
}

// NEGATIVE: an unrelated certificate kind (stake-pool registration) default-denies.
test ps_register_stake_pool_rejected() {
  let cert =
    RegisterStakePool {
      stake_pool: ps_target_pool,
      vrf: #"99aa99aa99aa99aa99aa99aa99aa99aa99aa99aa99aa99aa99aa99aa",
    }
  ps_publish(cert, True) == False
}
