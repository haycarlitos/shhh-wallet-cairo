//! V8.5 — a single-owner envelope must carry the wallet's threshold.
//!
//! Through V8.4 the `V2_SNIP12` single-owner path never read the
//! threshold: on a 2-of-N wallet any one owner executed alone, and so
//! did any one approval of a multisig proposal (each approval is a
//! complete `V2_SNIP12` envelope over the proposal's hash). V8.5 requires
//! `owner.weight >= threshold` on that path, except for:
//!   - a guardian's single `initiate_recovery` (V8.4 carve-out);
//!   - an owner's single `cancel_recovery` naming itself (owner veto).
//!
//! Fixture: owner A (id 0, weight 1), owner B (id 1, weight `b_weight`),
//! guardian G (id 2), threshold 2.

use shhh_wallet::outside_execution::{
    ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution, SIG_VERSION_V2_SNIP12,
    SIG_VERSION_V2_THRESHOLD, compute_snip12_hash,
};
use shhh_wallet::owner_set::interface::{ROLE_GUARDIAN, ROLE_OWNER};
use shhh_wallet::recovery::component::RecoveryComponent::PendingRecovery;
use shhh_wallet::test_helpers::target::{ITargetDispatcher, ITargetDispatcherTrait};
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::signature::{KeyPair, SignerTrait};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_caller_address, declare,
    start_cheat_block_timestamp_global, start_cheat_caller_address, start_cheat_chain_id_global,
    stop_cheat_caller_address,
};
use starknet::ContractAddress;
use starknet::account::Call;

const TIMELOCK_ADD_OWNER: u64 = 172_800;
const OWNER_A: u32 = 0;
const OWNER_B: u32 = 1;
const GUARDIAN: u32 = 2;

#[starknet::interface]
trait IShhhGov<TContractState> {
    fn propose_add_owner(
        ref self: TContractState,
        proposer: u32,
        kind: felt252,
        pubkey_bytes: Array<felt252>,
        role: felt252,
        weight: u8,
        label: felt252,
    ) -> felt252;
    fn execute_add_owner(
        ref self: TContractState,
        op_id: felt252,
        kind: felt252,
        pubkey_bytes: Array<felt252>,
        role: felt252,
        weight: u8,
        label: felt252,
    ) -> u32;
    fn propose_set_threshold(ref self: TContractState, proposer: u32, new: u8) -> felt252;
    fn execute_set_threshold(ref self: TContractState, op_id: felt252, new: u8);
    fn threshold(self: @TContractState) -> u8;
    fn get_pending_recovery(self: @TContractState) -> PendingRecovery;
}

#[derive(Drop, Copy)]
struct Fixture {
    account: ContractAddress,
    target: ContractAddress,
    kp_a: KeyPair<felt252, felt252>,
    kp_b: KeyPair<felt252, felt252>,
    kp_g: KeyPair<felt252, felt252>,
}

fn deploy(b_weight: u8) -> Fixture {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let target_class = declare("Target").unwrap().contract_class();

    let kp_a = StarkCurveKeyPairImpl::from_secret_key(0xA11CE_u256.try_into().unwrap());
    let kp_b = StarkCurveKeyPairImpl::from_secret_key(0xB0B_u256.try_into().unwrap());
    let kp_g = StarkCurveKeyPairImpl::from_secret_key(0x6A6D_u256.try_into().unwrap());

    let (account, _) = account_class
        .deploy(@array!['STARK', verifier_class.into(), 1, kp_a.public_key, 'alice'])
        .unwrap();
    let (target, _) = target_class.deploy(@array![]).unwrap();

    start_cheat_block_timestamp_global(1_000);
    start_cheat_caller_address(account, account);
    let gov = IShhhGovDispatcher { contract_address: account };
    let op_b = gov
        .propose_add_owner(OWNER_A, 'STARK', array![kp_b.public_key], ROLE_OWNER, b_weight, 'bob');
    let op_g = gov
        .propose_add_owner(OWNER_A, 'STARK', array![kp_g.public_key], ROLE_GUARDIAN, 1, 'guard');
    let op_t = gov.propose_set_threshold(OWNER_A, 2);
    start_cheat_block_timestamp_global(1_000 + TIMELOCK_ADD_OWNER + 1);
    let b_id = gov
        .execute_add_owner(op_b, 'STARK', array![kp_b.public_key], ROLE_OWNER, b_weight, 'bob');
    let g_id = gov
        .execute_add_owner(op_g, 'STARK', array![kp_g.public_key], ROLE_GUARDIAN, 1, 'guard');
    gov.execute_set_threshold(op_t, 2);
    stop_cheat_caller_address(account);

    assert(b_id == OWNER_B && g_id == GUARDIAN, 'fixture ids');
    assert(gov.threshold() == 2, 'fixture threshold');
    Fixture { account, target, kp_a, kp_b, kp_g }
}

fn oe(calls: Array<Call>, nonce: felt252) -> OutsideExecution {
    OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce,
        execute_after: 1_000_000,
        execute_before: 1_000_000 + 3_600,
        calls: calls.span(),
    }
}

fn hash_of(account: ContractAddress, oe: @OutsideExecution) -> felt252 {
    compute_snip12_hash(oe, account.into(), 'SN_MAIN')
}

fn single(owner_id: u32, kp: KeyPair<felt252, felt252>, hash: felt252) -> Array<felt252> {
    let (r, s) = kp.sign(hash).unwrap();
    array![SIG_VERSION_V2_SNIP12, owner_id.into(), 'STARK', r, s]
}

fn both(
    kp_a: KeyPair<felt252, felt252>, kp_b: KeyPair<felt252, felt252>, hash: felt252,
) -> Array<felt252> {
    let (ra, sa) = kp_a.sign(hash).unwrap();
    let (rb, sb) = kp_b.sign(hash).unwrap();
    array![
        SIG_VERSION_V2_THRESHOLD, 2, 4, OWNER_A.into(), 'STARK', ra, sa, 4, OWNER_B.into(), 'STARK',
        rb, sb,
    ]
}

fn set_value_call(target: ContractAddress) -> Call {
    Call { to: target, selector: selector!("set_value"), calldata: array![0xCAFE].span() }
}

fn cancel_recovery_call(account: ContractAddress, owner_id: u32) -> Call {
    Call {
        to: account,
        selector: selector!("cancel_recovery"),
        calldata: array![owner_id.into()].span(),
    }
}

fn submit(account: ContractAddress, oe: OutsideExecution, signature: Array<felt252>) {
    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_block_timestamp_global(1_000_001);
    // Only the outer call sees ANY_CALLER; the account's self-calls see
    // the account, so `_assert_self_call` passes inside.
    cheat_caller_address(account, 'ANY_CALLER'.try_into().unwrap(), CheatSpan::TargetCalls(1));
    ISRC9_V2Dispatcher { contract_address: account }.execute_from_outside_v2(oe, signature.span());
}

/// Guardian G starts a recovery with its own single envelope.
fn guardian_initiates_recovery(f: @Fixture) {
    let calldata: Array<felt252> = array![
        GUARDIAN.into(), 'STARK', 1, 0xDEAD_BEEF, 'OWNER', 1, 'recovered',
    ];
    let call = Call {
        to: *f.account, selector: selector!("initiate_recovery"), calldata: calldata.span(),
    };
    let o = oe(array![call], 'nonce-initiate');
    let h = hash_of(*f.account, @o);
    submit(*f.account, o, single(GUARDIAN, *f.kp_g, h));
}

// ==========================================================
// The bug: one owner below the threshold
// ==========================================================

#[test]
#[should_panic(expected: 'SHHH: below threshold')]
fn test_v8_5_single_owner_below_threshold_reverts() {
    let f = deploy(1);
    let o = oe(array![set_value_call(f.target)], 'nonce-a-alone');
    let h = hash_of(f.account, @o);
    submit(f.account, o, single(OWNER_A, f.kp_a, h));
}

/// A multisig proposal's first approval is a complete V2_SNIP12
/// envelope over the proposal's hash. It must not execute on its own.
#[test]
#[should_panic(expected: 'SHHH: below threshold')]
fn test_v8_5_one_approval_of_a_proposal_cannot_execute() {
    let f = deploy(1);
    let o = oe(array![set_value_call(f.target)], 'nonce-proposal');
    let h = hash_of(f.account, @o);
    let _second_approval_never_given = f.kp_a;
    submit(f.account, o, single(OWNER_B, f.kp_b, h));
}

/// One owner can't lower the threshold back to 1 on its own either.
#[test]
#[should_panic(expected: 'SHHH: below threshold')]
fn test_v8_5_single_owner_cannot_propose_lower_threshold() {
    let f = deploy(1);
    let call = Call {
        to: f.account,
        selector: selector!("propose_set_threshold"),
        calldata: array![OWNER_A.into(), 1].span(),
    };
    let o = oe(array![call], 'nonce-lower');
    let h = hash_of(f.account, @o);
    submit(f.account, o, single(OWNER_A, f.kp_a, h));
}

// ==========================================================
// What still works
// ==========================================================

#[test]
fn test_v8_5_threshold_envelope_executes() {
    let f = deploy(1);
    let o = oe(array![set_value_call(f.target)], 'nonce-both');
    let h = hash_of(f.account, @o);
    submit(f.account, o, both(f.kp_a, f.kp_b, h));
    assert(ITargetDispatcher { contract_address: f.target }.get_value() == 0xCAFE, 'not executed');
}

/// An owner whose weight alone meets the threshold signs alone.
#[test]
fn test_v8_5_owner_with_threshold_weight_executes_alone() {
    let f = deploy(2);
    let o = oe(array![set_value_call(f.target)], 'nonce-heavy');
    let h = hash_of(f.account, @o);
    submit(f.account, o, single(OWNER_B, f.kp_b, h));
    assert(ITargetDispatcher { contract_address: f.target }.get_value() == 0xCAFE, 'not executed');
}

/// ...and a lighter owner on the same wallet still can't.
#[test]
#[should_panic(expected: 'SHHH: below threshold')]
fn test_v8_5_light_owner_next_to_heavy_owner_reverts() {
    let f = deploy(2);
    let o = oe(array![set_value_call(f.target)], 'nonce-light');
    let h = hash_of(f.account, @o);
    submit(f.account, o, single(OWNER_A, f.kp_a, h));
}

#[test]
fn test_v8_5_guardian_still_initiates_recovery_alone() {
    let f = deploy(1);
    guardian_initiates_recovery(@f);
    let gov = IShhhGovDispatcher { contract_address: f.account };
    assert(gov.get_pending_recovery().is_active, 'recovery not active');
}

/// The owner veto: one owner below the threshold cancels a recovery.
#[test]
fn test_v8_5_single_owner_cancels_recovery() {
    let f = deploy(1);
    guardian_initiates_recovery(@f);
    let o = oe(array![cancel_recovery_call(f.account, OWNER_A)], 'nonce-cancel');
    let h = hash_of(f.account, @o);
    submit(f.account, o, single(OWNER_A, f.kp_a, h));
    let gov = IShhhGovDispatcher { contract_address: f.account };
    assert(!gov.get_pending_recovery().is_active, 'recovery still active');
}

#[test]
#[should_panic(expected: 'SHHH: below threshold')]
fn test_v8_5_cancel_recovery_naming_another_owner_reverts() {
    let f = deploy(1);
    guardian_initiates_recovery(@f);
    let o = oe(array![cancel_recovery_call(f.account, OWNER_B)], 'nonce-cancel-other');
    let h = hash_of(f.account, @o);
    submit(f.account, o, single(OWNER_A, f.kp_a, h));
}

/// The veto carve-out can't carry anything else along.
#[test]
#[should_panic(expected: 'SHHH: below threshold')]
fn test_v8_5_cancel_recovery_bundled_with_a_call_reverts() {
    let f = deploy(1);
    guardian_initiates_recovery(@f);
    let o = oe(
        array![cancel_recovery_call(f.account, OWNER_A), set_value_call(f.target)],
        'nonce-cancel-bundle',
    );
    let h = hash_of(f.account, @o);
    submit(f.account, o, single(OWNER_A, f.kp_a, h));
}

#[test]
#[should_panic(expected: 'SHHH: below threshold')]
fn test_v8_5_cancel_recovery_with_extra_calldata_reverts() {
    let f = deploy(1);
    guardian_initiates_recovery(@f);
    let call = Call {
        to: f.account,
        selector: selector!("cancel_recovery"),
        calldata: array![OWNER_A.into(), 0x1].span(),
    };
    let o = oe(array![call], 'nonce-cancel-extra');
    let h = hash_of(f.account, @o);
    submit(f.account, o, single(OWNER_A, f.kp_a, h));
}
