//// Aegis V8 stable-vault — governance registry transition logic (#362 §2.2).
//// The registry is the ONLY fast-swap surface: one NFT-carrying UTxO whose
//// datum names the current eligibility RuleSet. The vault's Underwrite arm
//// reads it as a reference input; settlement does NOT (Invariant S), and LP
//// principal is never reachable from here.
////
//// Admin at launch = the 2-of-3 team multisig; the cMATRA handover is the
//// `new_admin` rail on a PendingUpdate — itself timelocked, so every
//// governance change (rules OR admin) gives LPs a 72h exit window.
////
//// Pure functions over plain values so the whole state machine is unit-tested
//// without ScriptContext mocks; `validators/registry.ak` wires them to the
//// UTxO-continuity + signature + validity-bound facts.

use aegis/types.{cancel_cooldown_ms, registry_timelock_ms}
use aiken/collection/list

// registry_timelock_ms (72h mainnet / short preprod) and cancel_cooldown_ms
// (24h mainnet) are NETWORK-SCOPED in aegis/types (#363/#378): every
// rules/admin change waits >= the timelock, and a CancelUpdate arms the
// re-propose cooldown. Proving the enact cycle on preprod needs no source edit.

/// The RuleSet the vault's UNDERWRITE arm reads, and the only field it takes is
/// `logic_hash` (`pool_vault.ak:252`) — the sole governance-swappable pointer.
///
/// `policy_hash` and `marker_policy` are custody roots, and under Invariant S
/// (V82-IMMUTABLE-CORE §2) the vault gets them from its OWN compile parameters
/// (`pool_vault.ak:75-76`), never from here: settlement must resolve a policy it
/// already sold with no registry read, so a hostile or bricked registry can
/// shape only business that does not exist yet. Rotating them would redirect
/// future coverage to an attacker script or strand every outstanding policy
/// (#363 red-team H1-H4), which is why they were pinned even when the vault did
/// read them.
///
/// The two fields still have consumers, none of them a vault arm: `ruleset_eq`
/// compares them, `check_propose` (:160-161) and `check_enact` (:190-191) pin
/// them unchanged across every transition, and `offchain/scripts/v8_genesis.py`
/// writes the derived hashes into the epoch-0 datum. Post-Invariant-S those
/// pins are belt-and-braces — the vault's compile params are what actually bind
/// custody — and the fields carry no authority a settlement path can reach.
/// Everything else (oracle trust root, mandate, resolver hash, value movement)
/// is vault-baked and NOT here by design.
pub type RuleSet {
  /// eligibility-rules withdraw-0 validator (barrier/depeg dispatch + floors) — SWAPPABLE
  logic_hash: ByteArray,
  /// policy validator new policy outputs must land at. GENESIS-FIXED custody
  /// root, mirrored here; the vault binds it as a compile param, not from this.
  policy_hash: ByteArray,
  /// marker mint policy for policy outputs. GENESIS-FIXED custody root,
  /// mirrored here; the vault binds it as a compile param, not from this.
  marker_policy: ByteArray,
}

pub type Admin {
  /// payment VKHs eligible to sign governance actions
  keys: List<ByteArray>,
  /// M-of-N threshold
  threshold: Int,
}

pub type PendingUpdate {
  rule_set: RuleSet,
  /// Some = governance handover (the team-multisig -> cMATRA rail)
  new_admin: Option<Admin>,
  /// POSIX ms; EnactUpdate requires tx.lower >= this
  effective_after: Int,
}

pub type RegistryDatum {
  /// strictly increments on every EnactUpdate; the vault stamps policies with it
  epoch: Int,
  current: RuleSet,
  pending: Option<PendingUpdate>,
  admin: Admin,
  /// ProposeUpdate requires tx.lower >= this (set by CancelUpdate)
  cooldown_until: Int,
}

pub type RegistryRedeemer {
  ProposeUpdate
  EnactUpdate
  CancelUpdate
}

// ---------------------------------------------------------------------------
// Field equality — explicit, not derived (sum-type Eq is a known Windows-aiken
// silent-miscompile pitfall; ByteArray/Int comparisons are safe primitives).
// ---------------------------------------------------------------------------

pub fn ruleset_eq(a: RuleSet, b: RuleSet) -> Bool {
  and {
    a.logic_hash == b.logic_hash,
    a.policy_hash == b.policy_hash,
    a.marker_policy == b.marker_policy,
  }
}

pub fn admin_eq(a: Admin, b: Admin) -> Bool {
  and {
    a.threshold == b.threshold,
    a.keys == b.keys,
  }
}

/// A usable admin: nonempty distinct keys, 1 <= threshold <= |keys|.
/// Guards the handover rail against bricking governance (threshold 0 = anyone;
/// threshold > |keys| = frozen rules forever).
pub fn admin_valid(a: Admin) -> Bool {
  let n = list.length(a.keys)
  and {
    n > 0,
    a.threshold >= 1,
    a.threshold <= n,
    list.length(list.unique(a.keys)) == n,
  }
}

/// M-of-N: at least `threshold` DISTINCT admin keys among the tx signatories.
pub fn admin_signed(admin: Admin, signatories: List<ByteArray>) -> Bool {
  let signers =
    list.count(list.unique(admin.keys), fn(k) { list.has(signatories, k) })
  and {
    admin.threshold >= 1,
    signers >= admin.threshold,
  }
}

// ---------------------------------------------------------------------------
// Transitions. Each takes (old, new) datums + the tx facts the validator
// extracts, returns the full conjunction. Default-deny: every field the arm
// does not change is pinned equal.
// ---------------------------------------------------------------------------

/// ProposeUpdate: admin-signed; no pending; past any cancel cooldown; the new
/// pending waits >= timelock from the LATEST possible propose time (tx upper);
/// a handover admin must be structurally valid; nothing else moves.
pub fn check_propose(
  old: RegistryDatum,
  new: RegistryDatum,
  tx_lower_ms: Int,
  tx_upper_ms: Int,
  signed: Bool,
) -> Bool {
  expect Some(p) = new.pending
  let handover_ok =
    when p.new_admin is {
      Some(a) -> admin_valid(a)
      None -> True
    }
  and {
    signed,
    old.pending == None,
    tx_lower_ms >= old.cooldown_until,
    p.effective_after >= tx_upper_ms + registry_timelock_ms,
    handover_ok,
    // [#363 red-team H1-H4] custody roots pinned: an upgrade may swap ONLY
    // logic_hash. A proposed rotation of policy_hash or marker_policy is
    // refused at propose time (fail-fast); check_enact re-pins as the
    // load-bearing guard.
    p.rule_set.policy_hash == old.current.policy_hash,
    p.rule_set.marker_policy == old.current.marker_policy,
    new.epoch == old.epoch,
    ruleset_eq(new.current, old.current),
    admin_eq(new.admin, old.admin),
    new.cooldown_until == old.cooldown_until,
  }
}

/// EnactUpdate: PERMISSIONLESS after the timelock elapses. current := pending
/// rules; admin := handover admin if present; epoch strictly increments;
/// pending cleared.
pub fn check_enact(
  old: RegistryDatum,
  new: RegistryDatum,
  tx_lower_ms: Int,
) -> Bool {
  expect Some(p) = old.pending
  let want_admin =
    when p.new_admin is {
      Some(a) -> a
      None -> old.admin
    }
  and {
    tx_lower_ms >= p.effective_after,
    ruleset_eq(new.current, p.rule_set),
    // [#363 red-team H1-H4] THE load-bearing pin: custody roots are immutable
    // across an enact — even if a rotation slipped into `pending`, it can never
    // take effect, so future coverage always lands at the genesis policy_hash
    // and outstanding policies stay locatable.
    new.current.policy_hash == old.current.policy_hash,
    new.current.marker_policy == old.current.marker_policy,
    admin_eq(new.admin, want_admin),
    new.epoch == old.epoch + 1,
    new.pending == None,
    new.cooldown_until == old.cooldown_until,
  }
}

/// CancelUpdate: admin-signed; clears the pending and arms the re-propose
/// cooldown from the tx upper bound; nothing else moves.
pub fn check_cancel(
  old: RegistryDatum,
  new: RegistryDatum,
  tx_upper_ms: Int,
  signed: Bool,
) -> Bool {
  expect Some(_) = old.pending
  and {
    signed,
    new.pending == None,
    // [#363 red-team N5] EXACT window, not an open ray. `>=` let one Cancel set
    // cooldown_until to 2^63-1 and permanently brick governance: Propose's
    // `tx_lower >= cooldown_until` becomes unsatisfiable forever, Propose and
    // Enact both pin cooldown_until unchanged, and Cancel needs a pending that
    // can never be created again. Post-FIX-A that kills the sole upgrade rail.
    new.cooldown_until == tx_upper_ms + cancel_cooldown_ms,
    new.epoch == old.epoch,
    ruleset_eq(new.current, old.current),
    admin_eq(new.admin, old.admin),
  }
}

// ---------------------------------------------------------------------------
// Tests — the timelock, the epoch monotonicity, the unsigned paths, and the
// handover-brick guard are the load-bearing ones.
// ---------------------------------------------------------------------------

fn t_rules(tag: ByteArray) -> RuleSet {
  RuleSet { logic_hash: tag, policy_hash: tag, marker_policy: tag }
}

/// A LEGITIMATE upgrade changes ONLY logic_hash; policy_hash + marker_policy
/// stay the genesis custody roots (#"01" == t_datum().current) so the H1-H4
/// pins are satisfied.
fn t_rules_logic(logic: ByteArray) -> RuleSet {
  RuleSet { logic_hash: logic, policy_hash: #"01", marker_policy: #"01" }
}

fn t_admin() -> Admin {
  Admin { keys: [#"aa", #"bb", #"cc"], threshold: 2 }
}

fn t_datum() -> RegistryDatum {
  RegistryDatum {
    epoch: 7,
    current: t_rules(#"01"),
    pending: None,
    admin: t_admin(),
    cooldown_until: 0,
  }
}

fn t_pending(eff: Int) -> PendingUpdate {
  PendingUpdate {
    rule_set: t_rules_logic(#"02"),
    new_admin: None,
    effective_after: eff,
  }
}

test registry_admin_signed_meets_threshold() {
  admin_signed(t_admin(), [#"bb", #"aa"])
}

test registry_admin_signed_below_threshold_rejected() {
  !admin_signed(t_admin(), [#"aa"])
}

test registry_admin_signed_duplicate_admin_keys_dont_double_count() {
  // a malformed admin listing the same key twice must not let 1 signer pass M=2
  let dup = Admin { keys: [#"aa", #"aa", #"bb"], threshold: 2 }
  !admin_signed(dup, [#"aa"])
}

test registry_admin_valid_rejects_brick_configs() {
  and {
    admin_valid(t_admin()),
    !admin_valid(Admin { keys: [], threshold: 1 }),
    !admin_valid(Admin { keys: [#"aa"], threshold: 0 }),
    !admin_valid(Admin { keys: [#"aa"], threshold: 2 }),
    !admin_valid(Admin { keys: [#"aa", #"aa"], threshold: 1 }),
  }
}

test registry_propose_happy_path() {
  let old = t_datum()
  let up = 1_000_000
  let new =
    RegistryDatum {
      ..old,
      pending: Some(t_pending(up + registry_timelock_ms)),
    }
  check_propose(old, new, 500_000, up, True)
}

test registry_propose_unsigned_rejected() {
  let old = t_datum()
  let up = 1_000_000
  let new =
    RegistryDatum { ..old, pending: Some(t_pending(up + registry_timelock_ms)) }
  !check_propose(old, new, 500_000, up, False)
}

test registry_propose_short_timelock_rejected() {
  let old = t_datum()
  let up = 1_000_000
  // one ms short of the 72h window
  let new =
    RegistryDatum {
      ..old,
      pending: Some(t_pending(up + registry_timelock_ms - 1)),
    }
  !check_propose(old, new, 500_000, up, True)
}

test registry_propose_second_pending_rejected() {
  let up = 1_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9)) }
  let new =
    RegistryDatum { ..old, pending: Some(t_pending(up + registry_timelock_ms)) }
  !check_propose(old, new, 500_000, up, True)
}

test registry_propose_during_cooldown_rejected() {
  let up = 1_000_000
  let old = RegistryDatum { ..t_datum(), cooldown_until: 600_000 }
  let new =
    RegistryDatum { ..old, pending: Some(t_pending(up + registry_timelock_ms)) }
  // tx.lower 500k < cooldown 600k
  !check_propose(old, new, 500_000, up, True)
}

test registry_propose_cannot_mutate_current_or_epoch_or_admin() {
  let old = t_datum()
  let up = 1_000_000
  let base =
    RegistryDatum { ..old, pending: Some(t_pending(up + registry_timelock_ms)) }
  and {
    !check_propose(
      old,
      RegistryDatum { ..base, current: t_rules(#"ff") },
      500_000,
      up,
      True,
    ),
    !check_propose(old, RegistryDatum { ..base, epoch: 8 }, 500_000, up, True),
    !check_propose(
      old,
      RegistryDatum {
        ..base,
        admin: Admin { keys: [#"ee"], threshold: 1 },
      },
      500_000,
      up,
      True,
    ),
  }
}

test registry_propose_invalid_handover_admin_rejected() {
  let old = t_datum()
  let up = 1_000_000
  let bricked = Admin { keys: [#"aa"], threshold: 2 }
  let p =
    PendingUpdate {
      rule_set: t_rules_logic(#"02"),
      new_admin: Some(bricked),
      effective_after: up + registry_timelock_ms,
    }
  !check_propose(
    old,
    RegistryDatum { ..old, pending: Some(p) },
    500_000,
    up,
    True,
  )
}

test registry_enact_happy_path_permissionless() {
  let eff = 5_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(eff)) }
  let new =
    RegistryDatum {
      ..old,
      epoch: old.epoch + 1,
      current: t_rules_logic(#"02"),
      pending: None,
    }
  // no `signed` parameter exists: enactment needs no signature at all
  check_enact(old, new, eff)
}

test registry_enact_before_timelock_rejected() {
  let eff = 5_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(eff)) }
  let new =
    RegistryDatum {
      ..old,
      epoch: old.epoch + 1,
      current: t_rules_logic(#"02"),
      pending: None,
    }
  !check_enact(old, new, eff - 1)
}

test registry_enact_wrong_rules_rejected() {
  let eff = 5_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(eff)) }
  let new =
    RegistryDatum {
      ..old,
      epoch: old.epoch + 1,
      current: t_rules_logic(#"99"),
      pending: None,
    }
  !check_enact(old, new, eff)
}

test registry_enact_epoch_must_strictly_increment() {
  let eff = 5_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(eff)) }
  let same_epoch =
    RegistryDatum { ..old, current: t_rules_logic(#"02"), pending: None }
  let jump =
    RegistryDatum {
      ..old,
      epoch: old.epoch + 2,
      current: t_rules_logic(#"02"),
      pending: None,
    }
  and {
    !check_enact(old, same_epoch, eff),
    !check_enact(old, jump, eff),
  }
}

test registry_enact_applies_admin_handover() {
  let eff = 5_000_000
  let cmatra = Admin { keys: [#"11", #"22", #"33", #"44", #"55"], threshold: 3 }
  let p =
    PendingUpdate {
      rule_set: t_rules_logic(#"02"),
      new_admin: Some(cmatra),
      effective_after: eff,
    }
  let old = RegistryDatum { ..t_datum(), pending: Some(p) }
  let new =
    RegistryDatum {
      ..old,
      epoch: old.epoch + 1,
      current: t_rules_logic(#"02"),
      admin: cmatra,
      pending: None,
    }
  let keep_old_admin =
    RegistryDatum {
      ..old,
      epoch: old.epoch + 1,
      current: t_rules_logic(#"02"),
      pending: None,
    }
  and {
    check_enact(old, new, eff),
    // refusing the handover (keeping the old admin) must be rejected
    !check_enact(old, keep_old_admin, eff),
  }
}

// [#363 red-team H1-H4] policy_hash + marker_policy are genesis-fixed custody
// roots; only logic_hash may be swapped. A propose/enact that rotates either
// MUST be refused (else a governance swap redirects/strands LP coverage).
test registry_propose_rotating_policy_hash_rejected() {
  let old = t_datum()
  let up = 1_000_000
  let bad =
    PendingUpdate {
      rule_set: RuleSet {
        logic_hash: #"02",
        policy_hash: #"ff",
        marker_policy: #"01",
      },
      new_admin: None,
      effective_after: up + registry_timelock_ms,
    }
  !check_propose(old, RegistryDatum { ..old, pending: Some(bad) }, 500_000, up, True)
}

test registry_propose_rotating_marker_policy_rejected() {
  let old = t_datum()
  let up = 1_000_000
  let bad =
    PendingUpdate {
      rule_set: RuleSet {
        logic_hash: #"02",
        policy_hash: #"01",
        marker_policy: #"ff",
      },
      new_admin: None,
      effective_after: up + registry_timelock_ms,
    }
  !check_propose(old, RegistryDatum { ..old, pending: Some(bad) }, 500_000, up, True)
}

test registry_enact_rotating_policy_hash_rejected() {
  // even if a rotation slipped into `pending`, enact must never apply it
  let eff = 5_000_000
  let bad = RuleSet { logic_hash: #"02", policy_hash: #"ff", marker_policy: #"01" }
  let old =
    RegistryDatum {
      ..t_datum(),
      pending: Some(
        PendingUpdate { rule_set: bad, new_admin: None, effective_after: eff },
      ),
    }
  let new =
    RegistryDatum { ..old, epoch: old.epoch + 1, current: bad, pending: None }
  !check_enact(old, new, eff)
}

test registry_enact_rotating_marker_policy_rejected() {
  let eff = 5_000_000
  let bad = RuleSet { logic_hash: #"02", policy_hash: #"01", marker_policy: #"ff" }
  let old =
    RegistryDatum {
      ..t_datum(),
      pending: Some(
        PendingUpdate { rule_set: bad, new_admin: None, effective_after: eff },
      ),
    }
  let new =
    RegistryDatum { ..old, epoch: old.epoch + 1, current: bad, pending: None }
  !check_enact(old, new, eff)
}

test registry_cancel_happy_arms_cooldown() {
  let up = 2_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9_000_000)) }
  let new =
    RegistryDatum {
      ..old,
      pending: None,
      cooldown_until: up + cancel_cooldown_ms,
    }
  check_cancel(old, new, up, True)
}

test registry_cancel_unsigned_rejected() {
  let up = 2_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9_000_000)) }
  let new =
    RegistryDatum {
      ..old,
      pending: None,
      cooldown_until: up + cancel_cooldown_ms,
    }
  !check_cancel(old, new, up, False)
}

// [#363 red-team N5] An open-ended lower bound on cooldown_until let ONE Cancel
// permanently BRICK governance: set it to 2^63-1 and ProposeUpdate's
// `tx_lower >= old.cooldown_until` becomes unsatisfiable forever, while Propose
// and Enact both pin cooldown_until unchanged and Cancel itself requires an
// existing pending that can never be created again. Post-FIX-A (only logic_hash
// is swappable) that destroys the protocol's SOLE remaining upgrade rail.
// Reachable by a compromised admin M-of-N or an off-chain units bug.
test registry_cancel_oversized_cooldown_rejected() {
  let up = 2_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9_000_000)) }
  let bricked =
    RegistryDatum {
      ..old,
      pending: None,
      cooldown_until: 9_223_372_036_854_775_807,
    }
  !check_cancel(old, bricked, up, True)
}

test registry_cancel_without_cooldown_rejected() {
  let up = 2_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9_000_000)) }
  let new = RegistryDatum { ..old, pending: None }
  // cooldown_until left at 0 -> rejected
  !check_cancel(old, new, up, True)
}

test registry_cancel_cannot_mutate_rules_or_epoch() {
  let up = 2_000_000
  let old = RegistryDatum { ..t_datum(), pending: Some(t_pending(9_000_000)) }
  let base =
    RegistryDatum {
      ..old,
      pending: None,
      cooldown_until: up + cancel_cooldown_ms,
    }
  and {
    !check_cancel(
      old,
      RegistryDatum { ..base, current: t_rules(#"ff") },
      up,
      True,
    ),
    !check_cancel(old, RegistryDatum { ..base, epoch: 8 }, up, True),
  }
}
