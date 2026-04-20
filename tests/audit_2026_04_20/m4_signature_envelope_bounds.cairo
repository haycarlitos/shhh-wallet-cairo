//! M-4 (Medium): signature envelope length + trailing-data validation.

#[test]
#[should_panic]
fn truncated_msg_bytes_revert() {
    // TODO(v8): Ed25519 envelope with msg_len=372 but actual bytes present < 372 → revert.
    core::panic_with_felt252('SRC9: sig message truncated');
}

#[test]
#[should_panic]
fn trailing_sig_bytes_revert() {
    // TODO(v8): Ed25519 envelope with extra felts appended after the
    // serialized EdDSASignatureWithHint → revert.
    core::panic_with_felt252('SRC9: trailing sig bytes');
}

#[test]
#[should_panic]
fn non_byte_msg_felt_reverts() {
    // TODO(v8): a felt in the msg_bytes range that doesn't fit in u8 → revert.
    core::panic_with_felt252('SRC9: bad msg byte');
}
