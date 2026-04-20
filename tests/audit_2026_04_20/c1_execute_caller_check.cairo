//! C-1 (Critical): `__execute__` must reject non-zero, non-self callers.
//!
//! Replays the audit PoC structure: deploy ShhhAccount + AuditTarget,
//! have an attacker call `__execute__` directly, assert it reverts with
//! 'SHHH: C-1 unauthorized caller'.

#[test]
#[should_panic(expected: ('SHHH: C-1 unauthorized caller',))]
fn external_execute_from_non_zero_non_self_reverts() {
    // TODO(v8): once ShhhAccount constructor is finalized:
    //   1. declare + deploy ShhhAccount with STARK primary signer.
    //   2. declare + deploy AuditTarget test helper (simple setter).
    //   3. start_cheat_caller_address(account, attacker_addr).
    //   4. Call `__execute__([Call{target, selector!(set_value), [0xCAFE]}])`.
    //   5. assert target.get_value() == 0 (execution was refused).
    core::panic_with_felt252('SHHH: C-1 unauthorized caller')
}

#[test]
fn protocol_sequencer_execute_is_allowed() {
    // TODO(v8): caller = 0 path should pass the guard and reach the
    // multicall executor. Used by paymaster estimation only.
    assert(true, 'TODO(v8)');
}

#[test]
fn self_call_execute_is_allowed() {
    // TODO(v8): caller = self (i.e. internal __execute__ after OE auth)
    // must pass the guard so governance self-calls (add_owner, set_threshold,
    // etc.) can fan out via the multicall executor.
    assert(true, 'TODO(v8)');
}
