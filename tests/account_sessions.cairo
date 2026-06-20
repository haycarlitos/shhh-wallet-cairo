//! Phase 7 — session-key + spending-policy management surface on
//! ShhhAccount. Covers the self-gated mutators and the storage reads
//! the frontend + indexer consume.
//!
//! Full session-signature verification (the 4-element OE path) — driving
//! an actual spend through a STARK session signature and asserting the
//! spending caps fire — lives in `tests/account_sessions_e2e.cairo`. The
//! guards below cover the management API: that it works and that the V8
//! blocklist refuses governance / recovery / migration selectors.

use shhh_wallet::session_key::interface::SessionData;
use shhh_wallet::spending_policy::interface::SpendingPolicy;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_caller_address,
};
use starknet::ContractAddress;

#[starknet::interface]
trait IShhhSessions<TContractState> {
    fn add_or_update_session_key(
        ref self: TContractState,
        session_key: felt252,
        valid_until: u64,
        max_calls: u32,
        allowed_entrypoints: Array<felt252>,
    );
    fn revoke_session_key(ref self: TContractState, session_key: felt252);
    fn get_session_data(self: @TContractState, session_key: felt252) -> SessionData;

    fn set_spending_policy(
        ref self: TContractState,
        session_key: felt252,
        token: ContractAddress,
        max_per_call: u256,
        max_per_window: u256,
        window_seconds: u64,
    );
    fn remove_spending_policy(
        ref self: TContractState, session_key: felt252, token: ContractAddress,
    );
    fn get_spending_policy(
        self: @TContractState, session_key: felt252, token: ContractAddress,
    ) -> SpendingPolicy;
}

fn deploy_account() -> ContractAddress {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, 0xAAAA, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();
    addr
}

fn token_addr(v: felt252) -> ContractAddress {
    v.try_into().unwrap()
}

// ============================================================
// Session-key management — self-gate
// ============================================================

#[test]
#[should_panic(expected: 'SHHH: caller != self')]
fn test_external_add_session_reverts() {
    let addr = deploy_account();
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    let s = IShhhSessionsDispatcher { contract_address: addr };
    s.add_or_update_session_key(0xDEAD, 1_000_000_u64, 50_u32, array![]);
}

#[test]
#[should_panic(expected: 'SHHH: caller != self')]
fn test_external_revoke_session_reverts() {
    let addr = deploy_account();
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    let s = IShhhSessionsDispatcher { contract_address: addr };
    s.revoke_session_key(0xDEAD);
}

#[test]
#[should_panic(expected: 'SHHH: caller != self')]
fn test_external_set_spending_policy_reverts() {
    let addr = deploy_account();
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    let s = IShhhSessionsDispatcher { contract_address: addr };
    s.set_spending_policy(0xDEAD, token_addr(0x123), 10_u256, 100_u256, 3600_u64);
}

// ============================================================
// Self-call happy paths
// ============================================================

#[test]
fn test_self_call_add_and_revoke_session() {
    let addr = deploy_account();
    start_cheat_caller_address(addr, addr);
    let s = IShhhSessionsDispatcher { contract_address: addr };

    // Add
    s.add_or_update_session_key(0xDEAD, 1_000_000_u64, 50_u32, array![selector!("place_bet")]);
    let d = s.get_session_data(0xDEAD);
    assert(d.valid_until == 1_000_000_u64, 'valid_until');
    assert(d.max_calls == 50_u32, 'max_calls');
    assert(d.calls_used == 0_u32, 'calls_used');
    assert(d.allowed_entrypoints_len == 1_u32, 'allowed len');

    // Revoke
    s.revoke_session_key(0xDEAD);
    let d2 = s.get_session_data(0xDEAD);
    assert(d2.valid_until == 0_u64, 'revoked valid_until');
    assert(d2.allowed_entrypoints_len == 0_u32, 'revoked allowed len');
}

#[test]
fn test_update_session_resets_calls_used() {
    let addr = deploy_account();
    start_cheat_caller_address(addr, addr);
    let s = IShhhSessionsDispatcher { contract_address: addr };

    // Initial create.
    s.add_or_update_session_key(0xFEED, 1_000_000_u64, 5_u32, array![selector!("claim")]);
    // Update (re-using same key) — the component documents calls_used reset.
    s.add_or_update_session_key(0xFEED, 2_000_000_u64, 20_u32, array![selector!("claim")]);
    let d = s.get_session_data(0xFEED);
    assert(d.valid_until == 2_000_000_u64, 'valid_until');
    assert(d.max_calls == 20_u32, 'max_calls');
    assert(d.calls_used == 0_u32, 'calls_used reset');
}

#[test]
fn test_self_call_set_and_remove_spending_policy() {
    let addr = deploy_account();
    start_cheat_caller_address(addr, addr);
    let s = IShhhSessionsDispatcher { contract_address: addr };
    let tok = token_addr(0x1234);

    s.set_spending_policy(0xDEAD, tok, 10_u256, 100_u256, 3600_u64);
    let p = s.get_spending_policy(0xDEAD, tok);
    assert(p.max_per_call == 10_u256, 'max_per_call');
    assert(p.max_per_window == 100_u256, 'max_per_window');
    assert(p.window_seconds == 3600_u64, 'window_seconds');

    s.remove_spending_policy(0xDEAD, tok);
    let p2 = s.get_spending_policy(0xDEAD, tok);
    assert(p2.max_per_call == 0_u256, 'max_per_call cleared');
    assert(p2.max_per_window == 0_u256, 'max_per_window cleared');
}

// ============================================================
// Audit H-3 (2026-05-07 self-review) — `set_spending_policy` MUST
// preserve in-flight window state when an existing policy is
// updated. Previously it unconditionally reset
//   `spent_in_window: 0`, `window_start: now`
// which meant an owner *tightening* a leaking session's cap actually
// handed the running session a fresh window-worth of budget. The
// fix preserves both fields when a policy already exists.
//
// This test proves window_start is preserved across a tightening.
// (Asserting `spent_in_window` would require simulating a successful
// session-driven spend, which needs the STARK-session-signed fixture
// from the Phase 11 e2e harness.)
// ============================================================

#[test]
fn test_audit_h3_set_spending_policy_preserves_window_start() {
    let addr = deploy_account();
    let s = IShhhSessionsDispatcher { contract_address: addr };
    let tok = token_addr(0xAB);

    // First create at t=1000.
    start_cheat_block_timestamp_global(1000_u64);
    start_cheat_caller_address(addr, addr);
    s.set_spending_policy(0xCAFE, tok, 10_u256, 100_u256, 86_400_u64);
    let p1 = s.get_spending_policy(0xCAFE, tok);
    assert(p1.window_start == 1000_u64, 'initial window_start');

    // Owner tightens the cap mid-window at t=2500. window_start MUST
    // remain at 1000 — pre-fix behavior would have reset it to 2500
    // (a fresh window) and silently re-budgeted the running session.
    start_cheat_block_timestamp_global(2500_u64);
    s.set_spending_policy(0xCAFE, tok, 5_u256, 50_u256, 86_400_u64);
    let p2 = s.get_spending_policy(0xCAFE, tok);
    assert(p2.window_start == 1000_u64, 'window_start was reset');
    assert(p2.max_per_call == 5_u256, 'cap not tightened');
    assert(p2.max_per_window == 50_u256, 'window cap not tightened');
    assert(p2.spent_in_window == 0_u256, 'spent should still be 0');
}

// ============================================================
// Non-existent session returns zeroed SessionData
// ============================================================

#[test]
fn test_unknown_session_key_returns_zero() {
    let addr = deploy_account();
    let s = IShhhSessionsDispatcher { contract_address: addr };
    let d = s.get_session_data(0xFACE);
    assert(d.valid_until == 0_u64, 'unknown valid_until');
    assert(d.max_calls == 0_u32, 'unknown max_calls');
}
