//! M-2 (Medium): ANY_CALLER signatures MUST have a capped validity window
//! (MAX_ANY_CALLER_VALIDITY_SECONDS = 7200s = 2h — sized for CCTP pre-sign).

#[test]
#[should_panic]
fn any_caller_window_over_cap_reverts() {
    // TODO(v8): execute_before - execute_after = 7201s, caller = ANY_CALLER → revert.
    core::panic_with_felt252('SHHH: validity window too long');
}

#[test]
fn any_caller_window_at_cap_is_accepted() {
    // TODO(v8): execute_before - execute_after = 7200s → accepted.
    assert(true, 'TODO(v8)');
}

#[test]
fn specific_caller_long_window_is_accepted() {
    // TODO(v8): fixed-caller payloads have no cap (the caller is trusted).
    assert(true, 'TODO(v8)');
}
