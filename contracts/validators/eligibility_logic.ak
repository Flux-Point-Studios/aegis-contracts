use aegis/eligibility.{EligibilityClaim, claim_eligible}
use aiken/collection/list
use cardano/address.{Credential}
use cardano/transaction.{Transaction}

// =============================================================================
// Aegis V8 — Eligibility Logic leaf (#362 §2.3)
// Location: contracts/validators/eligibility_logic.ak
//
// The ONLY swappable coverage surface. A leaf WITHDRAW-0 validator (observer
// pattern, #315) that runs the current premium FLOOR + product dispatch over a
// VAULT-RESOLVED spot + vault-pinned policy terms, and returns eligible/not.
//
// Trust boundary: this script never sees value, aLP, markers, or destinations —
// only the numbers the immutable vault supplies in the withdraw redeemer and
// then re-pins to the real policy outputs. A malicious ENACTED logic can at
// worst approve an underpriced policy or deny a fair one — a repricing attack
// bounded by the registry's 72h timelock (LPs exit first). It cannot move
// principal, mint aLP, inflate coverage, or lie about the spot/premium.
//
// A new pricing model / product = deploy a fresh copy of THIS validator (new
// hash), register its reward account (Conway withdrawal needs a registered
// stake credential — the register_observer lesson), then ProposeUpdate the new
// logic_hash into the registry -> 72h -> EnactUpdate. No new pool, no LP
// migration, no oracle-trust change.
//
// Unparameterized: the RULES are baked in source, so swapping = a new hash.
// The registry's `current.logic_hash` names which copy the vault must invoke.
// =============================================================================

validator eligibility_logic {
  withdraw(redeemer: EligibilityClaim, account: Credential, self: Transaction) {
    // Exactly one withdrawal for THIS credential (the ledger permits at most
    // one per reward account, so this is present-and-unambiguous). The vault
    // reads THIS redeemer sibling-style and pins spot + terms to the real
    // policy outputs; keeping it single keeps that read unambiguous. Filter
    // form (not whole-tx single) so a co-attached observer / Pyth / stake
    // withdrawal never bricks the underwrite.
    let single_own =
      list.length(list.filter(self.withdrawals, fn(w) { w.1st == account })) == 1

    // The swappable rule: every vault-supplied policy clears the current floor.
    single_own && claim_eligible(redeemer)
  }

  else(_) {
    fail @"Unsupported purpose for the eligibility_logic leaf (withdraw-only)"
  }
}
