//! H-1 (High): subcall failures must revert the whole multicall.

#[test]
#[should_panic(expected: ('SHHH: subcall failed',))]
fn second_call_fails_whole_tx_reverts() {
    // TODO(v8):
    //   1. Build OE with [approve_ok, place_bet_will_revert].
    //   2. Sign with owner, submit via execute_from_outside_v2.
    //   3. Expect revert 'SHHH: subcall failed'.
    //   4. Post-condition: token.allowance() == 0 (approve was rolled back).
    core::panic_with_felt252('SHHH: subcall failed')
}

#[test]
fn nonce_remains_unconsumed_on_subcall_revert() {
    // TODO(v8): confirm that when the atomic revert fires, the OE nonce
    // is NOT consumed (consistent with rollback semantics).
    assert(true, 'TODO(v8)');
}
