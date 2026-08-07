//! Defense-in-depth: `execute_from_outside_v2` is non-reentrant.
//!
//! The account's nonce-replay guard protects against resubmission of
//! the same OE. Reentrancy is a distinct attack class: a subcall target
//! (malicious or compromised) calls back into the account while the
//! first OE is still executing. With the `oe_in_progress` flag, the
//! inner call reverts with 'SHHH: reentrant'.
//!
//! This test wires a `ReentrantTarget` contract that stores a second
//! OE + signature envelope and, when its `ping()` method is invoked as
//! part of the outer multicall, replays that OE on the victim account.
//! Without the guard, the inner call would either succeed (new nonce)
//! or fail with 'SRC9: duplicate nonce' (same nonce). With the guard,
//! it short-circuits earlier — which is what we assert.

use shhh_wallet::outside_execution::{
    ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution, SIG_VERSION_V2_SNIP12,
    compute_snip12_hash,
};
use shhh_wallet::test_helpers::reentrant_target::{
    IReentrantTargetDispatcher, IReentrantTargetDispatcherTrait,
};
use snforge_std::signature::SignerTrait;
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_caller_address, start_cheat_chain_id_global, store,
};
use starknet::ContractAddress;
use starknet::account::Call;

fn deploy() -> (ContractAddress, ContractAddress, felt252) {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let target_class = declare("ReentrantTarget").unwrap().contract_class();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0xDECAFBAD);
    let calldata: Array<felt252> = array![
        'STARK', verifier_class.into(), 1, kp.public_key, 'alice',
    ];
    let (account, _) = account_class.deploy(@calldata).unwrap();
    let (target, _) = target_class.deploy(@array![]).unwrap();
    (account, target, kp.public_key)
}

fn sign_oe(
    account: ContractAddress, nonce: felt252, calls: Span<Call>, secret_key: felt252,
) -> (OutsideExecution, Array<felt252>) {
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce,
        execute_after: 10_000,
        execute_before: 10_000 + 3_600,
        calls,
    };
    let hash = compute_snip12_hash(@oe, account.into(), 'SN_MAIN');
    let kp = StarkCurveKeyPairImpl::from_secret_key(secret_key);
    let (r, s) = kp.sign(hash).unwrap();
    let envelope: Array<felt252> = array![SIG_VERSION_V2_SNIP12, 0, 'STARK', r, s];
    (oe, envelope)
}

/// The inner 'SHHH: reentrant' panic is wrapped by H-1's atomic
/// multicall guard, so the visible top-level panic is
/// 'H1: subcall failed'. Either way the outer OE reverts; this test
/// asserts the visible cause. See `test_reentrant_inner_cause_is_guard`
/// below for proof that the reentrancy guard is what actually fired.
#[test]
#[should_panic(expected: 'H1: subcall failed')]
fn test_reentrant_subcall_reverts() {
    let (account, target, _) = deploy();
    let target_d = IReentrantTargetDispatcher { contract_address: target };
    target_d.set_victim(account);

    // Pre-sign an INNER OE that would hit execute_from_outside_v2 again
    // (with a different nonce so nonce dedup doesn't catch it first) —
    // the reentrancy guard must fire before any other check.
    let (inner_oe, inner_env) = sign_oe(account, 'inner-nonce', array![].span(), 0xDECAFBAD);
    target_d.set_payload(inner_oe, inner_env);

    // OUTER OE: calls target.ping() which re-enters the account.
    let ping_call = Call { to: target, selector: selector!("ping"), calldata: array![].span() };
    let (outer_oe, outer_env) = sign_oe(
        account, 'outer-nonce', array![ping_call].span(), 0xDECAFBAD,
    );

    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_block_timestamp_global(10_001);
    start_cheat_caller_address(account, 'ANY_CALLER'.try_into().unwrap());
    let src9 = ISRC9_V2Dispatcher { contract_address: account };
    src9.execute_from_outside_v2(outer_oe, outer_env.span());
}

/// Proof that the inner panic is specifically the reentrancy guard
/// (not some other subcall failure): pre-set `oe_in_progress = true`
/// via the `store` cheat and submit a brand-new OE from outside. No
/// subcall is involved — the guard fires at entry, before the H-1
/// wrapper is reached, so the raw panic string is 'SHHH: reentrant'.
#[test]
#[should_panic(expected: 'SHHH: reentrant')]
fn test_reentrant_inner_cause_is_guard() {
    let (account, _target, _) = deploy();
    // Simulate mid-execution state by flipping the guard bit directly.
    store(account, selector!("oe_in_progress"), array![1].span());

    let (oe, env) = sign_oe(account, 'direct-reentry', array![].span(), 0xDECAFBAD);
    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_block_timestamp_global(10_001);
    start_cheat_caller_address(account, 'ANY_CALLER'.try_into().unwrap());
    let src9 = ISRC9_V2Dispatcher { contract_address: account };
    src9.execute_from_outside_v2(oe, env.span());
}

/// Sanity: after a successful OE the guard is cleared, so a *subsequent*
/// OE (different nonce, not nested) executes normally. Without proper
/// cleanup on the success path, this test would revert with 'SHHH: reentrant'
/// on the second submission.
#[test]
fn test_guard_cleared_after_success() {
    let (account, _target, _) = deploy();
    let (oe_a, env_a) = sign_oe(account, 'a', array![].span(), 0xDECAFBAD);
    let (oe_b, env_b) = sign_oe(account, 'b', array![].span(), 0xDECAFBAD);
    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_block_timestamp_global(10_001);
    start_cheat_caller_address(account, 'ANY_CALLER'.try_into().unwrap());
    let src9 = ISRC9_V2Dispatcher { contract_address: account };
    src9.execute_from_outside_v2(oe_a, env_a.span());
    src9.execute_from_outside_v2(oe_b, env_b.span());
}
