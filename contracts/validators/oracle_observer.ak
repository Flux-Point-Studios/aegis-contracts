// =============================================================================
// Aegis Insurance Protocol - Oracle Observer (V5 size forwarding, #315)
// Location: contracts/validators/oracle_observer.ak
// Summary: A leaf withdraw-only validator that runs `resolve_oracle_price`
//          (including the ~7.5 KB Pyth Ed25519/Solana branch) ONCE per tx and
//          ATTESTS the resolved Price(s) in its withdrawal redeemer. The pool
//          and policy validators read the attested Price via
//          `oracle.attested_price` instead of resolving inline — which keeps the
//          pool validator under Cardano's 16 KB max-tx-size deploy ceiling.
//
//          THE TRUST HINGE: for every attested entry, the handler requires
//          `resolve_oracle_price(self, self.reference_inputs, provider,
//          oracle_nft) == price`. The SAME resolver that ran inline before runs
//          here, on the SAME `self`/`self.reference_inputs`, so the
//          cryptographic/economic boundary is byte-identical — a fabricated
//          price can never compare equal to the genuine resolution.
//
//          FRESHNESS is NOT certified here — every freshness/replay gate stays
//          consumer-side (pool/policy), byte-identical. The observer attests
//          GENUINENESS only; never move replay defense into it.
//
//          Parameterized ONLY by a `network_tag` salt (network/feed-set hash
//          rotation); NO pool/policy param -> one-way leaf dependency, no deploy
//          const cycle (MEMORY feedback_validator_const_cycles).
// =============================================================================

use aegis/oracle.{Attestation, resolve_oracle_price}
use aegis/oracle/types as oracle_types
use aegis/test_helpers/pyth_fixtures
use aegis/types.{Pyth}
use aiken/collection/list
use cardano/address.{Credential, Script}
use cardano/transaction.{Transaction}

validator oracle_observer(_network_tag: ByteArray) {
  // Rewarding purpose only. `account` is this observer's own stake credential.
  withdraw(redeemer: Data, account: Credential, self: Transaction) {
    expect attestations: List<Attestation> = redeemer

    // (M) EXACTLY ONE withdrawal FOR THIS OBSERVER CREDENTIAL — the filter form,
    // NOT a whole-tx `expect [Pair] = self.withdrawals`. A Pyth-backed tx ALSO
    // carries the Pyth withdraw-script's own 0-ADA withdrawal (pyth.get_updates
    // reads Withdraw(Script(state.withdraw_script))), and a premium_stake harvest
    // may carry one too — a whole-tx-single check would brick every such tx.
    let single_own =
      list.length(list.filter(self.withdrawals, fn(w) { w.1st == account })) == 1

    // The list must attest at least one feed.
    let nonempty = attestations != []

    // (G) GENUINENESS — the single trust hinge: every entry's price is
    // byte-identical to a fresh resolve on THIS tx's reference inputs / Pyth
    // withdraw. resolve_oracle_price fails closed on any missing/forged/wrong-NFT
    // /stale reference; the 5-Int Price record compares with total strict `==`.
    let all_genuine =
      list.all(
        attestations,
        fn(a) {
          resolve_oracle_price(
            self,
            self.reference_inputs,
            a.provider,
            a.oracle_nft,
          ) == a.price
        },
      )

    // (D) Defense-in-depth: no two entries share a (provider, oracle_nft). NOT
    // load-bearing — `all_genuine` already forecloses divergent duplicates since
    // resolve_oracle_price is a pure function of `self` (two same-feed entries
    // must carry identical prices to both pass) — kept cheap + pinned by a test.
    let no_dup_feeds =
      list.all(
        attestations,
        fn(a) {
          list.count(
            attestations,
            fn(b) { b.provider == a.provider && b.oracle_nft == a.oracle_nft },
          ) == 1
        },
      )

    single_own && nonempty && all_genuine && no_dup_feeds
  }

  else(_) {
    fail @"Unsupported purpose for oracle_observer"
  }
}

// ===========================================================================
// [#381 V8.1 S0] Substrate proof, observer leg: the genuineness hinge (G)
// recomputes resolve_oracle_price over a REAL Pyth transaction shape — State
// NFT reference input + Pyth withdraw redeemer carrying a genuine signed
// Lazer message (fixtures in aegis/test_helpers/pyth_fixtures). Proves the
// exact path a V8.1 fallback Claim will present, incl. the dual-withdrawal
// shape the (M) filter form exists for, and that a fabricated price can
// never compare equal to the genuine resolution.
// ===========================================================================

const s0_observer_cred: Credential = Script(#"92c3")

const s0_net_tag: ByteArray = #"00"

fn s0_pyth_attested_tx() -> Transaction {
  let base = pyth_fixtures.pyth_tx()
  Transaction {
    ..base,
    withdrawals: [
      // realistic fallback-claim shape: the Pyth script's own 0-ADA
      // withdrawal AND the observer's — (M) must count only its own.
      Pair(Script(pyth_fixtures.pyth_test_withdraw_hash), 0),
      Pair(s0_observer_cred, 0),
    ],
  }
}

test s0_observer_attests_genuine_pyth_price() {
  let tx = s0_pyth_attested_tx()
  let genuine =
    resolve_oracle_price(tx, tx.reference_inputs, Pyth, #"02")
  let redeemer: Data =
    [Attestation { provider: Pyth, oracle_nft: #"02", price: genuine }]
  oracle_observer.withdraw(s0_net_tag, redeemer, s0_observer_cred, tx)
}

test s0_observer_rejects_fabricated_pyth_price() fail {
  let tx = s0_pyth_attested_tx()
  let genuine =
    resolve_oracle_price(tx, tx.reference_inputs, Pyth, #"02")
  let forged = oracle_types.Price { ..genuine, value: genuine.value + 1 }
  let redeemer: Data =
    [Attestation { provider: Pyth, oracle_nft: #"02", price: forged }]
  oracle_observer.withdraw(s0_net_tag, redeemer, s0_observer_cred, tx)
}

test s0_observer_rejects_wrong_feed_handle() fail {
  // attestation names feed 99, absent from the update -> resolve aborts
  let tx = s0_pyth_attested_tx()
  let genuine =
    resolve_oracle_price(tx, tx.reference_inputs, Pyth, #"02")
  let redeemer: Data =
    [Attestation { provider: Pyth, oracle_nft: #"63", price: genuine }]
  oracle_observer.withdraw(s0_net_tag, redeemer, s0_observer_cred, tx)
}
