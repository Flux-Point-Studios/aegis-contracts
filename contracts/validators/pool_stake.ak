// `Admin` and its M-of-N check live in the v1 module and are shared; the DATUM
// on chain is registry_v2's. Decoding v1's RegistryDatum here would compile and
// then silently misread — v1 is {epoch, current: RuleSet, pending, admin,
// cooldown_until} and v2 is {epoch, logic_hash, config, pending, admin,
// cooldown_until, ...}, so `admin` sits at a different index. pool_vault.ak:8-9
// makes the same split; match it exactly.
use aegis/registry.{Admin, admin_signed}
use aegis/registry_v2
use aegis/registry_v2.{RegistryDatum}
use aegis/vault.{
  AddLiquidity, DepositRevenue, Expire, Vault, VaultRedeemer, deposit_revenue_ok,
}
use aiken/collection/list
use aiken/collection/pairs
use cardano/address.{Address, Credential, Inline, Script, VerificationKey}
use cardano/assets
use cardano/certificate.{
  AlwaysAbstain, AuthorizeConstitutionalCommitteeProxy, Certificate,
  DelegateBlockProduction, DelegateCredential, DelegateVote,
  RegisterAndDelegateCredential, RegisterCredential,
  RegisterDelegateRepresentative, Registered, RetireFromConstitutionalCommittee,
  RetireStakePool, UnregisterCredential, UnregisterDelegateRepresentative,
}
use cardano/transaction
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Spend, Transaction,
}

// =============================================================================
// Aegis V8.2 — pool_vault STAKE credential (#431, door 2 option C)
// Location: contracts/validators/pool_stake.ak
//
// The vault address gains a stake part so its ADA can be delegated and its
// rewards claimed (unblocks rehyp #346/#348/#349 and the yield half of #265).
// This script IS that stake part. It spends ZERO vault bytes and does not move
// pool_vault's hash: `pool_vault` reads `own_addr` from its OWN input and
// requires the continuation output to sit at that same address, so the stake
// credential is self-preserving once genesis mints there. No cycle either —
// this script is parameterised by the vault's PAYMENT hash, which does not
// depend on the stake credential.
//
// POLICY LIVES IN THE ROTATABLE HALF. Authority is the `admin` M-of-N named in
// the registry datum, read from a reference input pinned by the registry NFT.
// A mistake rotates out through governance rather than freezing the vault, and
// the handover rail (team multisig -> cMATRA) carries staking authority with it
// for free.
//
// THE ATTACK THIS EXISTS TO STOP. A reward withdrawal makes lovelace spendable
// by the transaction that performs it, so whoever composes that transaction
// could route the reward to their own output while the vault sits untouched.
// `withdraw` therefore requires the vault UTxO to be SPENT, spent under
// `DepositRevenue { amount }` with `amount >= withdrawn`, and continued at its
// own full address with at least the withdrawn amount added.
//
// The redeemer bind is the load-bearing part, and the first version of this file
// did not have it. A lovelace comparison alone measures a delta against a
// baseline the same transaction can move: `Expire` pins
// `cont == own + policy_lovelace` and `AddLiquidity` raises the vault by the
// deposit, so either arm's OWN inflow satisfies `>= own + withdrawn` while the
// whole reward walks. Requiring the arm is what makes the inflow provably BE the
// reward. Where it then lands inside the vault is pool_vault's job — its
// DepositRevenue arm pins `nr == reserve + amount` and
// `cont_lovelace == own_lovelace + amount` (ruled 2026-08-11: rewards go to
// RESERVE, decision `when-the-v8-2-vault-delegates-its-ada-an`).
//
// AUTHORITY IS SPLIT, ON PURPOSE. `publish` is governed; `withdraw` is not.
// After the bind there is nothing an authority check on `withdraw` could
// protect, and requiring one would make the vault's rewards hostage to a quorum
// that can never be routed around — this script's hash is the vault's staking
// part and cannot be replaced. The money path is permissionless; the policy path
// is governed.
//
// Deliberately NOT enforced here: which pool is delegated to. An SPO choice is
// reversible next epoch and cannot move principal — the ADA never leaves the
// vault — so railing it on chain would spend bytes to constrain the one staking
// decision that is already safe. Moving capital into a yield venue is a
// different action with its own wrong-way-risk ruling owed (#394); it is not
// reachable through this script.
// =============================================================================

/// The current admin, read from the registry UTxO named by its NFT, must have
/// signed to its own threshold. Read from a REFERENCE input: staking actions
/// must never need to spend the registry, or every delegation would contend
/// with governance for the same UTxO.
pub fn admin_authorised(
  self: Transaction,
  registry_nft_policy: ByteArray,
  registry_nft_name: ByteArray,
) -> Bool {
  when
    list.find(
      self.reference_inputs,
      fn(i) {
        assets.quantity_of(
          i.output.value,
          registry_nft_policy,
          registry_nft_name,
        ) == 1
      },
    )
  is {
    Some(reg) ->
      when reg.output.datum is {
        InlineDatum(raw) ->
          if raw is datum: RegistryDatum {
            admin_signed(datum.admin, self.extra_signatories)
          } else {
            False
          }
        _ -> False
      }
    None -> False
  }
}

/// Sum of lovelace at outputs sitting at the vault's EXACT address.
///
/// Matching the payment credential alone was a hole. `pool_vault` pins its
/// continuation to its own FULL address (pool_vault.ak:164-173) and says in its
/// own words that an output at that payment credential under a foreign stake key
/// is unspendable forever, excluding such outputs from an exit's `paid`
/// (pool_vault.ak:220-231). Counting one as retained let a withdrawal park the
/// whole reward at an address nobody can ever spend, while the stake key chosen
/// for it collects that pile's rewards and voting weight indefinitely.
///
/// The address comes from the vault INPUT rather than being rebuilt as
/// `Address { Script(vault_payment_hash), Some(Inline(account)) }`. The rebuild
/// would work today but would silently assert an OFF-CHAIN fact — that the
/// ceremony composed the stake part as an inline script hash of this very script
/// — which this script would then be trusting rather than checking. Anchoring on
/// the input asserts nothing and uses the same anchor pool_vault does, so the two
/// agree by construction instead of by two derivations of the same address.
fn lovelace_at(outs: List<Output>, addr: Address) -> Int {
  list.foldl(
    outs,
    0,
    fn(o: Output, acc: Int) {
      if o.address == addr {
        acc + assets.lovelace_of(o.value)
      } else {
        acc
      }
    },
  )
}

/// Every withdrawn lovelace must still be at the vault when the tx settles.
/// Split out from the validator arm so the attacks below can be stated as
/// tests: an arm is only reachable through the ledger, a function is reachable
/// from here.
pub fn rewards_retained(
  self: Transaction,
  account: Credential,
  vault_payment_hash: ByteArray,
) -> Bool {
  // DENY, do not ABORT. Both outcomes reject the transaction, so `expect` would
  // be safe here — but a validator that returns False states a verdict the
  // caller can compose and a test can assert, where a crash only states that
  // something went wrong. It also keeps this function honest as a `pub fn`: the
  // attack tests below call it directly, and an aborting guard cannot be shown
  // to have DECIDED anything.
  when pairs.get_first(self.withdrawals, account) is {
    // The ledger permits at most one withdrawal per reward account, so a
    // present entry is unambiguous. Absent = nothing to guard.
    Some(withdrawn) ->
      // The vault must be SPENT, so pool_vault's own arms run over this tx and
      // do the reserve accounting. Without it the withdrawal could stand alone
      // and the comparison below would be zero against zero.
      when
        list.filter(
          self.inputs,
          fn(i: Input) {
            when i.output.address.payment_credential is {
              Script(h) -> h == vault_payment_hash
              _ -> False
            }
          },
        )
      is {
        [vault] ->
          // WHICH ARM the vault is spent under is the whole guard. A lovelace
          // comparison alone measures a delta against a baseline the same
          // transaction can move: `Expire` pins `cont == own + policy_lovelace`
          // (vault.ak:787) and `AddLiquidity` raises the vault by the deposit,
          // so either one's OWN inflow satisfies `>= own + withdrawn` while the
          // entire reward is paid to a wallet. Binding the redeemer is what makes
          // the inflow provably BE the reward rather than merely equal to it.
          when pairs.get_first(self.redeemers, Spend(vault.output_reference)) is {
            Some(raw) ->
              if raw is spend_redeemer: VaultRedeemer {
                when spend_redeemer is {
                  DepositRevenue { amount } -> and {
                      // `>=`, so a tx that also books other revenue stays legal;
                      // it is the FLOOR that must cover the withdrawal.
                      amount >= withdrawn,
                      // A zero withdrawal proves nothing and would pass
                      // vacuously on a tx that only wanted the certificates.
                      withdrawn > 0,
                      // Belt and braces: measure the money itself, so this holds
                      // even if pool_vault's revenue accounting ever changed.
                      // pool_stake can never be replaced; it should not depend on
                      // another script's arithmetic staying what it is today.
                      lovelace_at(self.outputs, vault.output.address) >= assets.lovelace_of(
                        vault.output.value,
                      ) + withdrawn,
                    }
                  _ -> False
                }
              } else {
                False
              }
            None -> False
          }
        _ -> False
      }
    None -> False
  }
}

validator pool_stake(
  /// pool_vault's applied script hash — the vault address's PAYMENT credential
  vault_payment_hash: ByteArray,
  /// identifies the registry UTxO that names the current admin
  registry_nft_policy: ByteArray,
  registry_nft_name: ByteArray,
) {
  /// Registration, delegation and de-registration of THIS stake credential —
  /// the POLICY half, and the only half that stays governed.
  ///
  /// TYPED DEFAULT-DENY (ruled 2026-08-12). The first version took the
  /// certificate as opaque `Data` and never looked at it, so ONE quorum
  /// signature reached every certificate the ledger defines — including
  /// `RegisterDelegateRepresentative` over this very credential, which turns the
  /// vault's stake credential into a DRep and takes a deposit, and the committee
  /// arms. `premium_stake.ak:161-172` already does typed default-deny on this
  /// repo's other script stake credential; this matches it.
  ///
  /// The four admitted arms are the credential's LIFECYCLE and nothing else.
  /// The delegate TARGET is deliberately still unconstrained: an SPO or DRep
  /// choice is reversible next epoch and cannot move principal, and pinning it
  /// would spend the one thing this script cannot spend twice — its
  /// immutability — on a choice that is already reversible off chain. What is
  /// closed is the KIND of certificate, which is not reversible at all.
  ///
  /// NOT a value-free arm, and the original wording here claimed otherwise. A
  /// de-registration refunds the key deposit into a transaction this script does
  /// not constrain, so `publish` CAN move value — bounded by the ~2 ADA deposit,
  /// and gated on the admin quorum. A header that records a guarantee the code
  /// does not make is worse than silence.
  publish(_redeemer: Data, certificate: Certificate, self: Transaction) {
    let authorised = admin_authorised(self, registry_nft_policy, registry_nft_name)
    when certificate is {
      RegisterCredential { .. } -> authorised
      RegisterAndDelegateCredential { .. } -> authorised
      DelegateCredential { .. } -> authorised
      UnregisterCredential { .. } -> authorised
      _ -> False
    }
  }

  /// Reward withdrawal. PERMISSIONLESS, and the siphon guard is why.
  ///
  /// Ruled 2026-08-12. Once the guard binds the vault's spend redeemer to
  /// `DepositRevenue { amount >= withdrawn }`, a withdrawal can do exactly one
  /// thing: move the reward into the vault's reserve. There is nothing left for
  /// an authority check to protect, and Cardano requires withdrawing the FULL
  /// reward balance, so the arm is reachable once per accrual — there is no spam
  /// surface either. Requiring the admin here would have bought nothing and cost
  /// the one thing this design cannot afford: a permanent, un-rotatable liveness
  /// dependency on a quorum, on the half of the vault `pool_vault` deliberately
  /// left admin-free. Lose the keys and the rewards would freeze for the life of
  /// the generation. Now anyone can harvest, and the keeper is merely the party
  /// that usually bothers.
  withdraw(_redeemer: Data, account: Credential, self: Transaction) {
    rewards_retained(self, account, vault_payment_hash)
  }

  else(_) {
    fail @"pool_stake handles publish and withdraw only"
  }
}

// ---------------------------------------------------------------------------
// Tests. Attack-first: the siphon is the whole reason this script exists, so it
// is stated before the happy path. Fixtures are local, which is this repo's
// convention (pool_vault.ak and agent_vault.ak both carry their own) — and the
// safer choice here, because promoting them into test_helpers/fixtures.ak would
// collide on the two DISTINCT SettlementPins types (aegis/types has one,
// registry_v2 has another) and would edit a lib module every validator compiles
// against, days before a one-way-door ceremony.
// ---------------------------------------------------------------------------

const ps_vault_hash: ByteArray =
  #"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

const ps_reg_policy: ByteArray =
  #"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"

const ps_reg_name: ByteArray = #"41454749535f5245474953545259"

const ps_admin_key: ByteArray =
  #"c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"

const ps_attacker: ByteArray =
  #"d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"

fn ps_account() -> Credential {
  Script(#"e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5")
}

fn ps_config() -> registry_v2.UnderwriteConfig {
  registry_v2.UnderwriteConfig {
    mandates: [],
    publisher_vkh: #"f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6",
    observer_hash: #"a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
    depeg_eligible: [],
    pyth_feed_allowlist: [],
    pyth_state_nft: #"b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8",
    floors: registry_v2.Floors {
      min_strike_distance_bps: 1_500,
      min_depeg_distance_bps: 200,
      depeg_strike_lo_bps: 5_000,
      depeg_strike_hi_bps: 9_500,
      min_depeg_spot_bps: 9_900,
    },
    admissible_providers: [],
    budgets: registry_v2.Budgets {
      spot_age_barrier_ms: 600_000,
      spot_age_depeg_ms: 300_000,
      underwrite_span_ms: 1_200_000,
      term_min_ms: 604_800_000,
      term_max_ms: 15_552_000_000,
      min_premium: 2_000_000,
      utilisation_bps: 3_333,
      max_coverage_ratio: 50,
    },
    fee: registry_v2.Fee {
      take_bps: 200,
      treasury_bps: 2_500,
      team_address: Address {
        payment_credential: VerificationKey(ps_admin_key),
        stake_credential: None,
      },
    },
    settlement_pins: registry_v2.SettlementPins {
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

/// The vault's REAL address — payment credential AND the stake part, which is
/// this very script. Every fixture that means "the vault" must use it. The first
/// version of this suite built them all with `stake_credential: None`, an
/// address the ceremony never mints, so its green bar asserted acceptance at a
/// place the money would never be.
fn ps_vault_addr() -> Address {
  Address {
    payment_credential: Script(ps_vault_hash),
    stake_credential: Some(Inline(ps_account())),
  }
}

fn ps_vault_out(lovelace: Int) -> Output {
  Output {
    address: ps_vault_addr(),
    value: assets.from_lovelace(lovelace),
    datum: InlineDatum(0),
    reference_script: None,
  }
}

/// An output at the vault's PAYMENT credential under someone else's stake key.
/// pool_vault calls this address unspendable forever and refuses to count it as
/// an exit payment (pool_vault.ak:220-231); the first guard counted it as
/// retained, which parked the reward where no one can ever spend it while the
/// chosen stake key drew its rewards.
fn ps_alias_out(lovelace: Int) -> Output {
  Output {
    address: Address {
      payment_credential: Script(ps_vault_hash),
      stake_credential: Some(Inline(VerificationKey(ps_attacker))),
    },
    value: assets.from_lovelace(lovelace),
    datum: InlineDatum(0),
    reference_script: None,
  }
}

fn ps_script_out(hash: ByteArray, lovelace: Int) -> Output {
  Output {
    address: Address {
      payment_credential: Script(hash),
      stake_credential: None,
    },
    value: assets.from_lovelace(lovelace),
    datum: InlineDatum(0),
    reference_script: None,
  }
}

fn ps_registry_ref() -> Input {
  let rd =
    RegistryDatum {
      epoch: 1,
      logic_hash: #"aa",
      config: ps_config(),
      pending: None,
      admin: Admin { keys: [ps_admin_key], threshold: 1 },
      cooldown_until: 0,
      timelock_ms: 300_000_000,
      cancel_cooldown_ms: 172_800_000,
    }
  Input {
    output_reference: OutputReference {
      transaction_id: #"0000000000000000000000000000000000000000000000000000000000000001",
      output_index: 0,
    },
    output: Output {
      address: Address {
        payment_credential: Script(
          #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ),
        stake_credential: None,
      },
      value: assets.from_lovelace(2_000_000)
        |> assets.add(ps_reg_policy, ps_reg_name, 1),
      datum: InlineDatum(rd),
      reference_script: None,
    },
  }
}

const ps_vault_ref: OutputReference =
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000002",
    output_index: 0,
  }

fn ps_vault_input(lovelace: Int) -> Input {
  Input { output_reference: ps_vault_ref, output: ps_vault_out(lovelace) }
}

fn ps_attacker_output(lovelace: Int) -> Output {
  Output {
    address: Address {
      payment_credential: VerificationKey(ps_attacker),
      stake_credential: None,
    },
    value: assets.from_lovelace(lovelace),
    datum: NoDatum,
    reference_script: None,
  }
}

/// vault_in -> `outs`, withdrawing `reward`, vault spent under `spend`,
/// signed by `signers`.
fn ps_tx(
  vault_in: Int,
  outs: List<Output>,
  reward: Int,
  signers: List<ByteArray>,
  spend: VaultRedeemer,
) -> Transaction {
  let spend_data: Data = spend
  Transaction {
    ..transaction.placeholder,
    inputs: [ps_vault_input(vault_in)],
    reference_inputs: [ps_registry_ref()],
    outputs: outs,
    withdrawals: [Pair(ps_account(), reward)],
    extra_signatories: signers,
    // Bound to a Data local first: aiken 1.1.22 fails to compile an implicit
    // upcast inside a list literal, and reports nothing at all when it does.
    redeemers: [Pair(Spend(ps_vault_ref), spend_data)],
  }
}

fn ps_good_tx() -> Transaction {
  ps_tx(
    100_000_000,
    [ps_vault_out(105_000_000)],
    5_000_000,
    [ps_admin_key],
    DepositRevenue { amount: 5_000_000 },
  )
}

// --- THE SIPHON: the redeemer bind is the guard ----------------------------
//
// The first version of these tests proved the wrong thing. It measured only
// that the vault's lovelace rose by the withdrawal, which any arm that adds
// lovelace satisfies on its own — so the two carrier shapes below (Expire,
// AddLiquidity) were legal against a fully green suite.

test ps_siphon_to_attacker_rejected() {
  // The vault IS spent under the right arm — but 3 ADA of the 5 ADA reward is
  // routed to the attacker and only 2 reach the vault.
  let tx =
    ps_tx(
      100_000_000,
      [ps_vault_out(102_000_000), ps_attacker_output(3_000_000)],
      5_000_000,
      [ps_admin_key],
      DepositRevenue { amount: 5_000_000 },
    )
  rewards_retained(tx, ps_account(), ps_vault_hash) == False
}

test ps_expire_inflow_cannot_fund_the_withdrawal_rejected() {
  // THE ATTACK THE FIRST GUARD MISSED. `Expire` pins
  // `cont == own + policy_lovelace` (vault.ak:787), so an expiring policy's own
  // 5 ADA raises the vault by exactly the reward — the lovelace comparison
  // passes — while the whole 5 ADA reward is paid to a wallet. Only the arm
  // tells these apart.
  let tx =
    ps_tx(
      100_000_000,
      [ps_vault_out(105_000_000), ps_attacker_output(5_000_000)],
      5_000_000,
      [ps_admin_key],
      Expire { total_returned: 5_000_000 },
    )
  rewards_retained(tx, ps_account(), ps_vault_hash) == False
}

test ps_add_liquidity_carrier_rejected() {
  // The same shape through the permissionless arm: deposit the reward as
  // LIQUIDITY, minting aLP for it, and walk the reward out. The deposit raises
  // the vault by 5 ADA, so lovelace balances; the redeemer is what refuses.
  let tx =
    ps_tx(
      100_000_000,
      [ps_vault_out(105_000_000), ps_attacker_output(5_000_000)],
      5_000_000,
      [ps_admin_key],
      AddLiquidity { amount: 5_000_000 },
    )
  rewards_retained(tx, ps_account(), ps_vault_hash) == False
}

test ps_revenue_amount_below_the_withdrawal_rejected() {
  // The right arm, understating the deposit: book 1 lovelace of revenue while
  // withdrawing 5 ADA. pool_vault would then pin `reserve + 1`, crediting the
  // pool with a fraction of what it actually received.
  let tx =
    ps_tx(
      100_000_000,
      [ps_vault_out(105_000_000)],
      5_000_000,
      [ps_admin_key],
      DepositRevenue { amount: 1 },
    )
  rewards_retained(tx, ps_account(), ps_vault_hash) == False
}

test ps_alias_stake_credential_is_not_retention_rejected() {
  // An output at the vault's PAYMENT credential under the attacker's stake key.
  // pool_vault calls this address unspendable forever (pool_vault.ak:220-231):
  // the reward is burned, and its staking rewards accrue to the attacker.
  let tx =
    ps_tx(
      100_000_000,
      [ps_vault_out(100_000_000), ps_alias_out(5_000_000)],
      5_000_000,
      [ps_admin_key],
      DepositRevenue { amount: 5_000_000 },
    )
  rewards_retained(tx, ps_account(), ps_vault_hash) == False
}

test ps_vault_not_spent_rejected() {
  // No vault input at all: the withdrawal stands alone and nothing books it.
  let tx = Transaction { ..ps_good_tx(), inputs: [], redeemers: [] }
  rewards_retained(tx, ps_account(), ps_vault_hash) == False
}

test ps_vault_short_by_one_lovelace_rejected() {
  // The boundary. One lovelace short is still a siphon.
  let tx =
    ps_tx(
      100_000_000,
      [ps_vault_out(104_999_999)],
      5_000_000,
      [ps_admin_key],
      DepositRevenue { amount: 5_000_000 },
    )
  rewards_retained(tx, ps_account(), ps_vault_hash) == False
}

test ps_zero_withdrawal_rejected() {
  // A zero withdrawal satisfies `after >= before + 0` vacuously, so a tx that
  // only wanted the certificate side-effects would ride through the guard.
  let tx =
    ps_tx(
      100_000_000,
      [ps_vault_out(100_000_000)],
      0,
      [ps_admin_key],
      DepositRevenue { amount: 0 },
    )
  rewards_retained(tx, ps_account(), ps_vault_hash) == False
}

test ps_rewards_fully_retained_accepted() {
  rewards_retained(ps_good_tx(), ps_account(), ps_vault_hash)
}

test ps_extra_revenue_alongside_the_reward_accepted() {
  // `>=` on both legs: a tx that books 25 ADA of revenue while harvesting a
  // 5 ADA reward is legal. The floor must cover the withdrawal, not equal it.
  let tx =
    ps_tx(
      100_000_000,
      [ps_vault_out(125_000_000)],
      5_000_000,
      [ps_admin_key],
      DepositRevenue { amount: 25_000_000 },
    )
  rewards_retained(tx, ps_account(), ps_vault_hash)
}

test ps_paid_to_a_foreign_script_rejected() {
  // Retention is counted at the VAULT's address, not at "some script".
  let tx =
    ps_tx(
      100_000_000,
      [ps_vault_out(100_000_000), ps_script_out(ps_reg_policy, 5_000_000)],
      5_000_000,
      [ps_admin_key],
      DepositRevenue { amount: 5_000_000 },
    )
  rewards_retained(tx, ps_account(), ps_vault_hash) == False
}

// --- THE ARMS THEMSELVES ---------------------------------------------------
//
// Everything above calls the pub fns directly. Nothing proved that the HANDLERS
// call them: the wiring could drop a conjunct, gate the wrong arm on the wrong
// predicate, or accept where it should fail, with every test above still green.

test ps_withdraw_arm_is_permissionless_but_guarded() {
  // Ruled 2026-08-12: no admin signature on the money path. The guard decides.
  pool_stake.withdraw(
    ps_vault_hash,
    ps_reg_policy,
    ps_reg_name,
    0,
    ps_account(),
    Transaction { ..ps_good_tx(), extra_signatories: [] },
  )
}

test ps_withdraw_arm_refuses_the_siphon() {
  let tx =
    ps_tx(
      100_000_000,
      [ps_vault_out(105_000_000), ps_attacker_output(5_000_000)],
      5_000_000,
      [ps_admin_key],
      Expire { total_returned: 5_000_000 },
    )
  !pool_stake.withdraw(
    ps_vault_hash,
    ps_reg_policy,
    ps_reg_name,
    0,
    ps_account(),
    tx,
  )
}

fn ps_publish(cert: Certificate, tx: Transaction) -> Bool {
  pool_stake.publish(ps_vault_hash, ps_reg_policy, ps_reg_name, 0, cert, tx)
}

fn ps_own_cred() -> Credential {
  Script(ps_vault_hash)
}

fn ps_register() -> Certificate {
  RegisterCredential { credential: ps_own_cred(), deposit: Never }
}

test ps_publish_arm_requires_the_admin() {
  let unsigned = Transaction { ..ps_good_tx(), extra_signatories: [] }
  and {
    ps_publish(ps_register(), ps_good_tx()),
    !ps_publish(ps_register(), unsigned),
  }
}

// --- TYPED DEFAULT-DENY ON THE CERTIFICATE ---------------------------------
//
// The arm took opaque `Data` and never read it, so one quorum signature reached
// every certificate the ledger defines. These four are the credential's
// lifecycle; everything else is refused even WITH the admin.

test ps_publish_admits_the_four_lifecycle_certificates() {
  let pool = #"a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
  let to_pool = DelegateBlockProduction { stake_pool: pool }
  and {
    ps_publish(ps_register(), ps_good_tx()),
    ps_publish(
      RegisterAndDelegateCredential {
        credential: ps_own_cred(),
        delegate: to_pool,
        deposit: 2_000_000,
      },
      ps_good_tx(),
    ),
    ps_publish(
      DelegateCredential { credential: ps_own_cred(), delegate: to_pool },
      ps_good_tx(),
    ),
    ps_publish(
      UnregisterCredential {
        credential: ps_own_cred(),
        refund: Never,
      },
      ps_good_tx(),
    ),
  }
}

test ps_publish_admits_a_vote_delegation_to_any_target() {
  // The KIND is constrained; the TARGET deliberately is not. An SPO or DRep
  // choice is reversible next epoch, and pinning it would spend this script's
  // immutability on the one decision that does not need it.
  and {
    ps_publish(
      DelegateCredential {
        credential: ps_own_cred(),
        delegate: DelegateVote { delegate_representative: AlwaysAbstain },
      },
      ps_good_tx(),
    ),
    ps_publish(
      DelegateCredential {
        credential: ps_own_cred(),
        delegate: DelegateVote {
          delegate_representative: Registered(VerificationKey(ps_attacker)),
        },
      },
      ps_good_tx(),
    ),
  }
}

test ps_publish_refuses_making_the_vault_a_drep() {
  // The sharpest one the opaque arm allowed: register THIS credential as a
  // delegate representative, on one quorum signature, taking a deposit out of a
  // transaction this script does not otherwise constrain.
  !ps_publish(
    RegisterDelegateRepresentative {
      delegate_representative: ps_own_cred(),
      deposit: 500_000_000,
    },
    ps_good_tx(),
  )
}

test ps_publish_refuses_the_committee_and_pool_arms() {
  let pool = #"a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
  and {
    !ps_publish(
      AuthorizeConstitutionalCommitteeProxy {
        constitutional_committee_member: ps_own_cred(),
        proxy: VerificationKey(ps_attacker),
      },
      ps_good_tx(),
    ),
    !ps_publish(
      RetireFromConstitutionalCommittee {
        constitutional_committee_member: ps_own_cred(),
      },
      ps_good_tx(),
    ),
    !ps_publish(
      RetireStakePool { stake_pool: pool, at_epoch: 500 },
      ps_good_tx(),
    ),
    !ps_publish(
      UnregisterDelegateRepresentative {
        delegate_representative: ps_own_cred(),
        refund: 500_000_000,
      },
      ps_good_tx(),
    ),
  }
}

// --- AUTHORITY (publish only) ----------------------------------------------

test ps_unsigned_rejected() {
  let tx = Transaction { ..ps_good_tx(), extra_signatories: [] }
  admin_authorised(tx, ps_reg_policy, ps_reg_name) == False
}

test ps_wrong_signer_rejected() {
  let tx = Transaction { ..ps_good_tx(), extra_signatories: [ps_attacker] }
  admin_authorised(tx, ps_reg_policy, ps_reg_name) == False
}

test ps_admin_signed_accepted() {
  admin_authorised(ps_good_tx(), ps_reg_policy, ps_reg_name)
}

test ps_no_registry_reference_rejected() {
  // The registry is how authority is named. Absent, this must DENY rather than
  // abort, so the refusal is a verdict a caller can compose and a test can read.
  let tx = Transaction { ..ps_good_tx(), reference_inputs: [] }
  admin_authorised(tx, ps_reg_policy, ps_reg_name) == False
}

test ps_registry_located_by_nft_not_position() {
  // A decoy reference input listed FIRST carrying a different policy id.
  // Locating the registry by position rather than by its NFT would read the
  // decoy — the #421 failure mode, where a guard watched the wrong thing and
  // was green for it.
  let decoy =
    Input {
      output_reference: OutputReference {
        transaction_id: #"0000000000000000000000000000000000000000000000000000000000000009",
        output_index: 0,
      },
      output: Output {
        address: Address {
          payment_credential: Script(ps_vault_hash),
          stake_credential: None,
        },
        value: assets.from_lovelace(2_000_000)
          |> assets.add(ps_attacker, ps_reg_name, 1),
        datum: InlineDatum(0),
        reference_script: None,
      },
    }
  let tx =
    Transaction { ..ps_good_tx(), reference_inputs: [decoy, ps_registry_ref()] }
  admin_authorised(tx, ps_reg_policy, ps_reg_name)
}

// --- THE ARMS THAT DECIDE "SPENT, BUT UNREADABLE" --------------------------
//
// A mutation battery over the fixed guard found three survivors: the two arms
// that decide what happens when the vault IS an input but its redeemer cannot
// be read, and the input singleton that makes `vault.output.address` a
// well-defined anchor at all. Each killed no test. They do now.

test ps_vault_spent_with_no_redeemer_entry_rejected() {
  // The vault is an input, but the tx carries no redeemer keyed to it. Nothing
  // then establishes WHICH arm pool_vault ran, which is the whole guard — so
  // `None` must deny rather than fall through.
  let tx =
    Transaction {
      ..ps_tx(
        100_000_000,
        [ps_vault_out(105_000_000)],
        5_000_000,
        [ps_admin_key],
        DepositRevenue { amount: 5_000_000 },
      ),
      redeemers: [],
    }
  rewards_retained(tx, ps_account(), ps_vault_hash) == False
}

test ps_vault_redeemer_that_is_not_a_vault_redeemer_rejected() {
  // A redeemer IS present at the vault's OutputReference but does not decode as
  // a VaultRedeemer. The soft cast's else-branch is the only thing between that
  // and an unguarded withdrawal.
  let junk: Data = 42
  let tx =
    Transaction {
      ..ps_tx(
        100_000_000,
        [ps_vault_out(105_000_000)],
        5_000_000,
        [ps_admin_key],
        DepositRevenue { amount: 5_000_000 },
      ),
      redeemers: [Pair(Spend(ps_vault_ref), junk)],
    }
  rewards_retained(tx, ps_account(), ps_vault_hash) == False
}

test ps_two_inputs_at_the_vault_credential_rejected() {
  // With two inputs at the vault's payment credential, "the vault's address" is
  // not well defined and the retention anchor becomes a choice. Denying is what
  // keeps `vault.output.address` meaningful.
  let second =
    Input {
      output_reference: OutputReference {
        transaction_id: #"0000000000000000000000000000000000000000000000000000000000000007",
        output_index: 1,
      },
      output: ps_alias_out(50_000_000),
    }
  let base =
    ps_tx(
      100_000_000,
      [ps_vault_out(155_000_000)],
      5_000_000,
      [ps_admin_key],
      DepositRevenue { amount: 5_000_000 },
    )
  let tx = Transaction { ..base, inputs: [ps_vault_input(100_000_000), second] }
  rewards_retained(tx, ps_account(), ps_vault_hash) == False
}

// --- COMPOSITION: THE TWO SCRIPTS AGREE ON ONE TRANSACTION -----------------
//
// The entire justification for making `withdraw` permissionless is that a
// withdrawal it accepts can do nothing except move the reward into reserve —
// which is pool_vault's rule, not this script's. Nothing tested that the two
// are satisfiable together. `pool_stake` appears nowhere in pool_vault.ak, so
// no suite on either side was ever going to notice.

test ps_a_harvest_this_guard_accepts_is_one_pool_vault_accepts() {
  let own = 100_000_000
  let reward = 5_000_000
  let cont = own + reward
  let old_state = Vault { lp_supply: 1_000_000, active_coverage: 0, reserve: 0, registry_nft: ps_reg_policy }
  let new_state =
    Vault {
      lp_supply: 1_000_000,
      active_coverage: 0,
      reserve: reward,
      registry_nft: ps_reg_policy,
    }
  let tx =
    ps_tx(
      own,
      [ps_vault_out(cont)],
      reward,
      [ps_admin_key],
      DepositRevenue { amount: reward },
    )
  and {
    // pool_stake's side: the reward is retained and booked as revenue.
    rewards_retained(tx, ps_account(), ps_vault_hash),
    // pool_vault's side, over the SAME numbers: reserve grows by exactly the
    // amount, LP supply and coverage untouched, no aLP minted.
    deposit_revenue_ok(old_state, new_state, reward, own, cont, 0),
  }
}

test ps_the_guard_and_the_vault_reject_the_same_understatement() {
  // The two must also agree on a REFUSAL, or the composition is only an
  // accident of the happy path: booking 1 lovelace while withdrawing 5 ADA is
  // refused by this guard, and the accounting it would have produced is refused
  // by pool_vault.
  let own = 100_000_000
  let reward = 5_000_000
  let understated = 1
  let old_state = Vault { lp_supply: 1_000_000, active_coverage: 0, reserve: 0, registry_nft: ps_reg_policy }
  let new_state =
    Vault {
      lp_supply: 1_000_000,
      active_coverage: 0,
      reserve: understated,
      registry_nft: ps_reg_policy,
    }
  let tx =
    ps_tx(
      own,
      [ps_vault_out(own + reward)],
      reward,
      [ps_admin_key],
      DepositRevenue { amount: understated },
    )
  and {
    rewards_retained(tx, ps_account(), ps_vault_hash) == False,
    // pool_vault refuses it too: cont is own+reward, but `amount` says 1.
    deposit_revenue_ok(old_state, new_state, understated, own, own + reward, 0) == False,
  }
}
