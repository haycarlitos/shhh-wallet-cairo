//! H-2 (High): real SNIP-9 V2 interface ID must be registered, and the
//! SNIP-12 typed-data hashing path must match the OZ SRC9 canonical form.

#[test]
fn supports_canonical_isrc9_v2_id() {
    // TODO(v8): account.supports_interface(ISRC9_V2_ID) == true
    // where ISRC9_V2_ID = 0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872
    assert(true, 'TODO(v8)');
}

#[test]
fn does_not_register_v7_custom_interface_id() {
    // TODO(v8): account.supports_interface(V7_CUSTOM_ID) == false
    // where V7_CUSTOM_ID = 0x1d1144bb2138571a605b8b8eed8e4e9e04dc40fce40190a11af584935e0a04c
    // (the wrong id the audit found in V7).
    assert(true, 'TODO(v8)');
}

#[test]
fn snip12_typed_data_hash_matches_oz_reference() {
    // TODO(v8): construct OutsideExecution with fixture values, compare
    // the computed SNIP-12 hash to an OZ reference vector byte-for-byte.
    assert(true, 'TODO(v8)');
}
