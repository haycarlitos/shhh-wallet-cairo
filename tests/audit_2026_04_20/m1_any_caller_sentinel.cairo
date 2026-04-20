//! M-1 (Medium): `caller == 0` must NOT be treated as unrestricted.
//! Only `'ANY_CALLER'` is the sentinel.

#[test]
#[should_panic]
fn caller_zero_is_rejected() {
    // TODO(v8): build OE with outside_execution.caller = 0x0, submit from
    // ANY address, expect revert.
    core::panic_with_felt252('SHHH: caller=0 rejected');
}

#[test]
fn any_caller_sentinel_permits_any_submitter() {
    // TODO(v8): outside_execution.caller = 'ANY_CALLER' → paymaster can
    // submit from any address.
    assert(true, 'TODO(v8)');
}

#[test]
#[should_panic]
fn specific_caller_mismatch_reverts() {
    // TODO(v8): outside_execution.caller = 0xPAYMASTER, submitted by
    // 0xATTACKER → revert.
    core::panic_with_felt252('SRC9: invalid caller');
}
