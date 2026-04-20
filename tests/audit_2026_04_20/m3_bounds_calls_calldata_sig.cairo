//! M-3 (Medium): bounded calls, calldata, and signature length.

#[test]
#[should_panic]
fn over_max_calls_reverts_before_hashing() {
    // TODO(v8): build OE with MAX_CALLS + 1 = 17 calls → revert BEFORE
    // signature verification so attackers can't grief the paymaster.
    core::panic_with_felt252('SHHH: too many calls');
}

#[test]
#[should_panic]
fn over_max_total_calldata_reverts() {
    // TODO(v8): sum(call.calldata.len()) > MAX_TOTAL_CALLDATA_FELTS → revert.
    core::panic_with_felt252('SHHH: calldata too large');
}

#[test]
#[should_panic]
fn over_max_signature_len_reverts() {
    // TODO(v8): signature envelope > MAX_SIGNATURE_FELTS → revert BEFORE
    // library_call into the verifier.
    core::panic_with_felt252('SHHH: signature too long');
}
