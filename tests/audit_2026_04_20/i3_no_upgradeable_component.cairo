//! I-3 (Informational): the account class MUST NOT import or expose the
//! OpenZeppelin UpgradeableComponent. V8 is immutable; changes happen
//! via recovery or redeploy, never in-place.

#[test]
fn class_abi_has_no_upgrade_entrypoint() {
    // TODO(v8): dump the Sierra class ABI and assert `upgrade` is not a
    // public selector.
    assert(true, 'TODO(v8)');
}

#[test]
fn storage_layout_has_no_upgradeable_substorage() {
    // TODO(v8): reflection check (or a compile-time test) that the
    // storage struct does not embed OZ's UpgradeableComponent storage.
    assert(true, 'TODO(v8)');
}
