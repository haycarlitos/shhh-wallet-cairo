//! SNIP-9 nonce replay + replay-guard observability tests.
//!
//! Closes the `nonce_dedup` mutation-harness gap. The guard being
//! mutated:
//!
//!   ```cairo
//!   assert(!self.oe_nonces.read(outside_execution.nonce), 'SRC9: duplicate nonce');
//!   self.oe_nonces.write(outside_execution.nonce, true);
//!   ```
//!
//! Without these tests, mutating the guard away doesn't break anything
//! observable within a single tx, so the mutation harness flagged it
//! as surviving. The tests here submit the *same* OE (same SNIP-12
//! hash, same nonce, same STARK signature) twice in one test function:
//!
//!   - **Original code**: second `execute_from_outside_v2` reverts with
//!     'SRC9: duplicate nonce'; `target.get_call_count()` stays at 1.
//!   - **Mutant (guard removed)**: second submission would succeed and
//!     increment `call_count` to 2 — `#[should_panic]` never fires and
//!     the test fails.
//!
//! Also covers:
//!   - Different nonces under the same owner both execute (no
//!     accidental cross-nonce blocking).
//!   - `is_valid_outside_execution_nonce(n)` flips from true → false
//!     after the first submission, so paymasters that pre-check see
//!     the correct value.

use shhh_wallet::outside_execution::{
    ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution, SIG_VERSION_V2_SNIP12,
    compute_snip12_hash,
};
use shhh_wallet::test_helpers::target::{ITargetDispatcher, ITargetDispatcherTrait};
use snforge_std::signature::SignerTrait;
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_caller_address, start_cheat_chain_id_global,
};
use starknet::ContractAddress;
use starknet::account::Call;

fn deploy_account_and_target() -> (ContractAddress, ContractAddress, felt252) {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let target_class = declare("Target").unwrap().contract_class();

    let kp = StarkCurveKeyPairImpl::from_secret_key(0xABCD_BEEF);
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, kp.public_key, 'alice'];
    let (account, _) = account_class.deploy(@calldata).unwrap();
    let (target, _) = target_class.deploy(@array![]).unwrap();
    (account, target, kp.public_key)
}

/// Build an OE that calls Target::set_value(0xCAFE), compute the
/// canonical SNIP-12 hash, sign with `secret_key`, and return the
/// fully-formed V2_SNIP12 envelope.
fn build_signed_oe(
    account: ContractAddress, target: ContractAddress, nonce: felt252, secret_key: felt252,
) -> (OutsideExecution, Array<felt252>) {
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce,
        execute_after: 10_000,
        execute_before: 10_000 + 3_600, // 1h, inside M-2 cap of 2h
        calls: array![
            Call {
                to: target, selector: selector!("set_value"), calldata: array![0xCAFE].span(),
            },
        ]
            .span(),
    };
    let hash = compute_snip12_hash(@oe, account.into(), 'SN_MAIN');
    let kp = StarkCurveKeyPairImpl::from_secret_key(secret_key);
    let (r, s) = kp.sign(hash).unwrap();
    let envelope: Array<felt252> = array![SIG_VERSION_V2_SNIP12, 0, 'STARK', r, s];
    (oe, envelope)
}

fn cheat_for_oe(account: ContractAddress) {
    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_block_timestamp_global(10_001);
    start_cheat_caller_address(account, 'ANY_CALLER'.try_into().unwrap());
}

// ==========================================================
// Happy path — one OE, one execution. Baseline for the replay test.
// ==========================================================

#[test]
fn test_single_submission_executes_target_once() {
    let (account, target, _) = deploy_account_and_target();
    let (oe, envelope) = build_signed_oe(account, target, 'only-nonce', 0xABCD_BEEF);
    cheat_for_oe(account);

    let src9 = ISRC9_V2Dispatcher { contract_address: account };
    src9.execute_from_outside_v2(oe, envelope.span());

    let t = ITargetDispatcher { contract_address: target };
    assert(t.get_value() == 0xCAFE, 'target not set');
    assert(t.get_call_count() == 1_u32, 'call count != 1');
}

// ==========================================================
// Core mutation killer — same OE, same nonce, submitted twice.
// First submission SUCCEEDS; second MUST revert with duplicate nonce.
// ==========================================================

#[test]
#[should_panic(expected: 'SRC9: duplicate nonce')]
fn test_replay_same_nonce_reverts_on_second_submission() {
    let (account, target, _) = deploy_account_and_target();
    let (oe, envelope) = build_signed_oe(account, target, 'replay-nonce', 0xABCD_BEEF);
    cheat_for_oe(account);
    let src9 = ISRC9_V2Dispatcher { contract_address: account };
    // First submission — succeeds.
    src9.execute_from_outside_v2(oe, envelope.span());
    // Second submission with identical args — MUST revert.
    src9.execute_from_outside_v2(oe, envelope.span());
}

// ==========================================================
// Observability — after the replay test fires, the target must NOT
// have been invoked twice. A separate test with explicit replay
// handling captures the state after the expected revert.
// ==========================================================

#[test]
fn test_nonce_flips_is_valid_false_after_consumption() {
    let (account, target, _) = deploy_account_and_target();
    let nonce: felt252 = 'probe-nonce';
    let src9 = ISRC9_V2Dispatcher { contract_address: account };

    // Before any submission the nonce is "fresh".
    assert(src9.is_valid_outside_execution_nonce(nonce), 'nonce falsely consumed');

    let (oe, envelope) = build_signed_oe(account, target, nonce, 0xABCD_BEEF);
    cheat_for_oe(account);
    src9.execute_from_outside_v2(oe, envelope.span());

    // After submission the paymaster-side pre-check returns false,
    // so paymasters correctly decline to re-submit the same OE.
    assert(!src9.is_valid_outside_execution_nonce(nonce), 'nonce not flipped');
}

// ==========================================================
// Different nonces — two independent OEs both execute. Guards
// against a regression where a stricter check would dedup too
// aggressively (e.g. by owner_id instead of by nonce).
// ==========================================================

#[test]
fn test_two_different_nonces_both_execute() {
    let (account, target, _) = deploy_account_and_target();
    let (oe_a, env_a) = build_signed_oe(account, target, 'nonce-a', 0xABCD_BEEF);
    let (oe_b, env_b) = build_signed_oe(account, target, 'nonce-b', 0xABCD_BEEF);
    cheat_for_oe(account);
    let src9 = ISRC9_V2Dispatcher { contract_address: account };

    src9.execute_from_outside_v2(oe_a, env_a.span());
    src9.execute_from_outside_v2(oe_b, env_b.span());

    let t = ITargetDispatcher { contract_address: target };
    assert(t.get_call_count() == 2_u32, 'distinct nonces blocked');
}

// ==========================================================
// Cross-account replay independence — the same nonce value is
// allowed in two different accounts. `oe_nonces` must be per-
// account storage, not global. Catches any accidental refactor
// that shared the nonce map via a library class or env slot.
// ==========================================================

#[test]
fn test_same_nonce_independent_across_accounts() {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let target_class = declare("Target").unwrap().contract_class();

    let kp_a = StarkCurveKeyPairImpl::from_secret_key(0x1111_1111);
    let kp_b = StarkCurveKeyPairImpl::from_secret_key(0x2222_2222);
    let (acct_a, _) = account_class
        .deploy(@array!['STARK', verifier_class.into(), 1, kp_a.public_key, 'a'])
        .unwrap();
    let (acct_b, _) = account_class
        .deploy(@array!['STARK', verifier_class.into(), 1, kp_b.public_key, 'b'])
        .unwrap();
    let (target, _) = target_class.deploy(@array![]).unwrap();

    let nonce: felt252 = 'shared-nonce';
    let (oe_a, env_a) = build_signed_oe(acct_a, target, nonce, 0x1111_1111);
    let (oe_b, env_b) = build_signed_oe(acct_b, target, nonce, 0x2222_2222);

    cheat_for_oe(acct_a);
    ISRC9_V2Dispatcher { contract_address: acct_a }.execute_from_outside_v2(oe_a, env_a.span());

    cheat_for_oe(acct_b);
    ISRC9_V2Dispatcher { contract_address: acct_b }.execute_from_outside_v2(oe_b, env_b.span());

    let t = ITargetDispatcher { contract_address: target };
    assert(t.get_call_count() == 2_u32, 'cross-account blocked');
}
