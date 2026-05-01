// =============================================================================
// Aegis Insurance Protocol - Pool Math & Validation
// Location: contracts/lib/aegis/pool.ak
// Summary: Functions for LP token calculations and pool solvency checks.
//          Used by validators/pool.ak for verifying pool datum state
//          transitions during Underwrite, ProcessClaim, AddLiquidity,
//          and RemoveLiquidity operations.
// =============================================================================

// ---------------------------------------------------------------------------
// LP Token Calculations
// ---------------------------------------------------------------------------

/// Calculate the number of LP tokens to mint for a given deposit.
///
/// If the pool is empty (total_liquidity == 0), mint 1:1 with deposit.
/// Otherwise, mint proportional to the deposit's share of the pool:
///   lp_to_mint = deposit * existing_lp_supply / total_liquidity
///
/// Uses integer division (truncates), which slightly favors the pool.
pub fn calculate_lp_mint(
  deposit: Int,
  total_liquidity: Int,
  lp_supply: Int,
) -> Int {
  if total_liquidity == 0 {
    // First depositor: 1:1 ratio
    deposit
  } else {
    // Proportional to existing pool
    deposit * lp_supply / total_liquidity
  }
}

/// Calculate the ADA to return for burning LP tokens.
///
///   withdrawal = lp_burned * total_liquidity / lp_supply
///
/// Uses integer division (truncates), which slightly favors the pool.
pub fn calculate_withdrawal(
  lp_burned: Int,
  total_liquidity: Int,
  lp_supply: Int,
) -> Int {
  if lp_supply == 0 {
    fail @"Cannot withdraw: LP supply is zero"
  } else {
    lp_burned * total_liquidity / lp_supply
  }
}

// ---------------------------------------------------------------------------
// Pool Solvency
// ---------------------------------------------------------------------------

/// Check that the pool remains solvent after an operation.
/// The pool must always have total_liquidity >= active_coverage.
pub fn is_pool_solvent(total_liquidity: Int, active_coverage: Int) -> Bool {
  total_liquidity >= active_coverage
}

/// Calculate available liquidity (ADA not reserved for active policies).
pub fn available_liquidity(total_liquidity: Int, active_coverage: Int) -> Int {
  total_liquidity - active_coverage
}

/// Check that the pool can underwrite a new policy of the given coverage.
pub fn can_underwrite(
  total_liquidity: Int,
  active_coverage: Int,
  new_coverage: Int,
) -> Bool {
  available_liquidity(total_liquidity, active_coverage) >= new_coverage
}

/// Check that a withdrawal does not impair coverage for active policies.
/// After withdrawal, remaining liquidity must still cover active policies.
pub fn can_withdraw(
  total_liquidity: Int,
  active_coverage: Int,
  withdrawal: Int,
) -> Bool {
  total_liquidity - withdrawal >= active_coverage
}

// ---------------------------------------------------------------------------
// Pool Datum Validation
// ---------------------------------------------------------------------------

/// Verify that pool datum is updated correctly for an Underwrite operation.
/// total_liquidity increases by net_premium, active_coverage increases by coverage.
pub fn verify_underwrite_datum(
  old_total: Int,
  old_active: Int,
  new_total: Int,
  new_active: Int,
  net_premium: Int,
  coverage: Int,
) -> Bool {
  new_total == old_total + net_premium && new_active == old_active + coverage
}

/// Verify that pool datum is updated correctly for a ProcessClaim operation.
/// total_liquidity decreases by payout, active_coverage decreases by payout.
///
/// [FIX A-005] Adds explicit non-negativity + payout-bounded-by-active checks.
/// Previously, with verify_claim_datum returning True for any matching arithmetic,
/// the F-007 "solvency" check `new_total >= new_active` was tautologically satisfied
/// (both fields decrement by the same payout, so the difference is unchanged from the
/// pre-state, which was already solvent). This allowed `payout` to be arbitrarily large,
/// driving `active_coverage` deeply negative while still passing the validator.
///
/// Post-fix invariants:
///   1. payout >= 0
///   2. payout <= old_active   (cannot pay out more coverage than was reserved)
///   3. new_total = old_total - payout
///   4. new_active = old_active - payout
///   5. new_total >= 0
///   6. new_active >= 0
pub fn verify_claim_datum(
  old_total: Int,
  old_active: Int,
  new_total: Int,
  new_active: Int,
  payout: Int,
) -> Bool {
  payout >= 0
    && payout <= old_active
    && new_total == old_total - payout
    && new_active == old_active - payout
    && new_total >= 0
    && new_active >= 0
}

/// Verify that pool datum is updated correctly for AddLiquidity.
/// [FIX A-003] Now also enforces lp_supply increments by exactly the LP
/// quantity that calculate_lp_mint produces for this deposit.
pub fn verify_add_liquidity_datum(
  old_total: Int,
  old_active: Int,
  old_lp_supply: Int,
  new_total: Int,
  new_active: Int,
  new_lp_supply: Int,
  amount: Int,
) -> Bool {
  let lp_minted = calculate_lp_mint(amount, old_total, old_lp_supply)
  new_total == old_total + amount
    && new_active == old_active
    && new_lp_supply == old_lp_supply + lp_minted
}

/// Verify that pool datum is updated correctly for RemoveLiquidity.
/// [FIX A-003] Caller passes the LP burn quantity; we verify the burn corresponds
/// to the requested withdrawal `amount` and that lp_supply decrements accordingly.
pub fn verify_remove_liquidity_datum(
  old_total: Int,
  old_active: Int,
  old_lp_supply: Int,
  new_total: Int,
  new_active: Int,
  new_lp_supply: Int,
  amount: Int,
  lp_burned: Int,
) -> Bool {
  let expected_withdrawal = calculate_withdrawal(lp_burned, old_total, old_lp_supply)
  expected_withdrawal == amount
    && new_total == old_total - amount
    && new_active == old_active
    && new_lp_supply == old_lp_supply - lp_burned
    && lp_burned >= 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test lp_mint_first_depositor() {
  // First depositor gets 1:1
  calculate_lp_mint(100_000_000, 0, 0) == 100_000_000
}

test lp_mint_proportional() {
  // Pool has 1000 ADA, 1000 LP tokens. Deposit 500 ADA -> 500 LP tokens
  calculate_lp_mint(500_000_000, 1_000_000_000, 1_000_000_000) == 500_000_000
}

test lp_mint_proportional_unequal() {
  // Pool has 2000 ADA, 1000 LP tokens. Deposit 500 ADA -> 250 LP tokens
  calculate_lp_mint(500_000_000, 2_000_000_000, 1_000_000_000) == 250_000_000
}

test lp_mint_truncation() {
  // Pool has 3 ADA, 2 LP tokens. Deposit 1 ADA -> 0 LP (truncation)
  // Actually 1 * 2 / 3 = 0 (integer division)
  calculate_lp_mint(1, 3, 2) == 0
}

test withdrawal_calculation() {
  // Pool has 2000 ADA, 1000 LP tokens. Burn 250 LP -> 500 ADA
  calculate_withdrawal(250_000_000, 2_000_000_000, 1_000_000_000) == 500_000_000
}

test withdrawal_full() {
  // Burn all LP tokens -> get all liquidity
  calculate_withdrawal(1_000_000_000, 1_000_000_000, 1_000_000_000) == 1_000_000_000
}

test pool_solvent_when_covered() {
  is_pool_solvent(100_000_000, 50_000_000) == True
}

test pool_solvent_at_boundary() {
  is_pool_solvent(100_000_000, 100_000_000) == True
}

test pool_insolvent() {
  is_pool_solvent(50_000_000, 100_000_000) == False
}

test available_liquidity_calculation() {
  available_liquidity(100_000_000, 30_000_000) == 70_000_000
}

test can_underwrite_sufficient() {
  can_underwrite(100_000_000, 30_000_000, 50_000_000) == True
}

test can_underwrite_insufficient() {
  can_underwrite(100_000_000, 80_000_000, 30_000_000) == False
}

test can_underwrite_exact() {
  can_underwrite(100_000_000, 30_000_000, 70_000_000) == True
}

test can_withdraw_safe() {
  can_withdraw(100_000_000, 30_000_000, 50_000_000) == True
}

test can_withdraw_unsafe() {
  can_withdraw(100_000_000, 80_000_000, 30_000_000) == False
}

test verify_underwrite_datum_correct() {
  verify_underwrite_datum(
    1_000_000_000,
    200_000_000,
    1_050_000_000,
    700_000_000,
    50_000_000,
    500_000_000,
  ) == True
}

test verify_underwrite_datum_wrong_total() {
  verify_underwrite_datum(
    1_000_000_000,
    200_000_000,
    1_100_000_000,
    700_000_000,
    50_000_000,
    500_000_000,
  ) == False
}

test verify_claim_datum_correct() {
  verify_claim_datum(
    1_000_000_000,
    500_000_000,
    700_000_000,
    200_000_000,
    300_000_000,
  ) == True
}

test verify_add_liquidity_datum_correct() {
  // Pool: 1B total, 1B lp_supply. Deposit 500M → lp_minted = 500M (1:1 ratio).
  verify_add_liquidity_datum(
    1_000_000_000,
    300_000_000,
    1_000_000_000,
    1_500_000_000,
    300_000_000,
    1_500_000_000,
    500_000_000,
  ) == True
}

test verify_remove_liquidity_datum_correct() {
  // Pool: 1B total, 1B lp_supply. Burn 200M LP → withdraw 200M ADA (1:1 ratio).
  verify_remove_liquidity_datum(
    1_000_000_000,
    300_000_000,
    1_000_000_000,
    800_000_000,
    300_000_000,
    800_000_000,
    200_000_000,
    200_000_000,
  ) == True
}

// ---------------------------------------------------------------------------
// Security Tests: Pool Solvency Edge Cases
// ---------------------------------------------------------------------------

// [A-005 FIX] verify_claim_datum now REJECTS excessive payouts that would
// drive active_coverage negative. Previously it accepted any arithmetic
// relationship and relied on a tautological solvency check (F-007).
test verify_claim_datum_rejects_excessive_payout_a_005_fix() {
  // Pool: 1000 ADA total, 500 ADA active, payout 600 ADA (> active)
  let new_total = 1_000_000_000 - 600_000_000
  let new_active = 500_000_000 - 600_000_000  // -100M (impossible)
  let datum_passes =
    verify_claim_datum(
      1_000_000_000,
      500_000_000,
      new_total,
      new_active,
      600_000_000,
    )
  // Post-fix: helper rejects (returns False).
  datum_passes == False
}

test verify_claim_datum_accepts_legitimate_payout_a_005_fix() {
  // Pool: 1000 ADA total, 500 ADA active, payout 200 ADA (≤ active) — legitimate.
  let new_total = 1_000_000_000 - 200_000_000  // 800M
  let new_active = 500_000_000 - 200_000_000  // 300M
  verify_claim_datum(
    1_000_000_000,
    500_000_000,
    new_total,
    new_active,
    200_000_000,
  ) == True
}

test verify_claim_datum_rejects_negative_payout_a_005_fix() {
  verify_claim_datum(1_000_000_000, 500_000_000, 1_000_100_000, 500_100_000, -100_000) == False
}

// Verify underwrite cannot be called when pool has zero liquidity
test cannot_underwrite_empty_pool() {
  can_underwrite(0, 0, 1_000_000) == False
}

// Verify withdrawal when pool has exactly active_coverage
test cannot_withdraw_when_fully_committed() {
  // Pool: 100 ADA total, 100 ADA active -> 0 available
  can_withdraw(100_000_000, 100_000_000, 1) == False
}

// Verify LP mint truncation cannot be exploited with tiny deposits
test lp_mint_dust_deposit_returns_zero() {
  // Pool has 1000 ADA, 100 LP. Deposit 1 lovelace -> 0 LP tokens
  // This is correct: dust deposits yield no LP tokens
  calculate_lp_mint(1, 1_000_000_000, 100_000_000) == 0
}

// Verify withdrawal calculation is safe with large numbers
test withdrawal_large_amounts_no_overflow() {
  // Pool with 100B lovelace, 100B LP tokens, burn half
  let withdrawal =
    calculate_withdrawal(50_000_000_000, 100_000_000_000, 100_000_000_000)
  withdrawal == 50_000_000_000
}

// Verify datum manipulation is rejected: attacker tries to set wrong total
test verify_underwrite_datum_rejects_inflated_total() {
  // Attacker tries to set new_total higher than expected
  verify_underwrite_datum(
    1_000_000_000,
    200_000_000,
    2_000_000_000,
    // inflated total (should be 1_050_000_000)
    700_000_000,
    50_000_000,
    500_000_000,
  ) == False
}

// Verify datum manipulation rejected: attacker tries to set active too low
test verify_claim_datum_rejects_deflated_active() {
  // Attacker tries to set active_coverage to 0 after claiming 300 ADA
  // when old_active was 500 ADA (correct new_active would be 200 ADA)
  verify_claim_datum(
    1_000_000_000,
    500_000_000,
    700_000_000,
    0,
    // deflated active (should be 200_000_000)
    300_000_000,
  ) == False
}

// Verify add liquidity preserves active_coverage
test verify_add_liquidity_rejects_active_change() {
  // Attacker tries to decrease active_coverage during add liquidity.
  verify_add_liquidity_datum(
    1_000_000_000,
    300_000_000,
    1_000_000_000,
    1_500_000_000,
    100_000_000,
    1_500_000_000,
    500_000_000,
  ) == False
}

// Verify remove liquidity preserves active_coverage
test verify_remove_liquidity_rejects_active_change() {
  verify_remove_liquidity_datum(
    1_000_000_000,
    300_000_000,
    1_000_000_000,
    800_000_000,
    0,
    800_000_000,
    200_000_000,
    200_000_000,
  ) == False
}

// [FIX A-003] verify_remove_liquidity_datum rejects mismatched LP burn / withdrawal.
test verify_remove_liquidity_rejects_lp_burn_mismatch_a_003_fix() {
  // Pool: 1B total, 1B lp_supply. Burn only 1 LP → withdraw at most 1 ADA.
  // Attacker requests 200M withdrawal — must reject.
  verify_remove_liquidity_datum(
    1_000_000_000,
    300_000_000,
    1_000_000_000,
    800_000_000,
    300_000_000,
    999_999_999,
    200_000_000,
    1,
  ) == False
}
