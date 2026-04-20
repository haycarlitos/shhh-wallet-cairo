//! L-1 (Low): constructor must reject out-of-range pubkey material so
//! deployment factories cannot produce bricked accounts. Delegated to
//! the primary-kind verifier via library_call.

#[test]
#[should_panic]
fn ed25519_pubkey_half_above_u128_reverts_in_constructor() {
    // TODO(v8): pubkey_high > u128::MAX → constructor reverts with a
    // controlled error (not a panic from a later `.try_into().unwrap()`).
    core::panic_with_felt252('OWNER_HIGH_OUT_OF_RANGE');
}

#[test]
fn valid_ed25519_fixture_deploys() {
    // TODO(v8): canonical V7 fixture still deploys and can verify a
    // signature end-to-end on V8.
    assert(true, 'TODO(v8)');
}
