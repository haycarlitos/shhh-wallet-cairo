//! Phase 4 storage + Phase 5 governance wiring in ShhhAccount.
//!
//! Every mutation flows through the timelocked propose/execute state
//! machine. Tests cheat block timestamp + caller address to exercise
//! each guard.

use shhh_wallet::owner_set::interface::ROLE_OWNER;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_caller_address,
};
use starknet::ContractAddress;

// --------------------------------------------------------------
// Account ABI surfaces the tests drive.
// --------------------------------------------------------------

#[starknet::interface]
trait IShhhAccountReads<TContractState> {
    fn primary_kind(self: @TContractState) -> felt252;
    fn primary_pubkey_hash(self: @TContractState) -> felt252;
    fn address_salt(self: @TContractState) -> felt252;
    fn owner_count(self: @TContractState) -> u32;
    fn active_owner_count(self: @TContractState) -> u32;
    fn threshold(self: @TContractState) -> u8;
    fn total_weight(self: @TContractState) -> u32;
    fn get_owner(
        self: @TContractState, owner_id: u32,
    ) -> shhh_wallet::owner_set::interface::OwnerRecord;
}

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
    fn propose_remove_owner(ref self: TContractState, proposer: u32, owner_id: u32) -> felt252;
    fn propose_set_threshold(ref self: TContractState, proposer: u32, new: u8) -> felt252;

    fn execute_add_owner(
        ref self: TContractState,
        op_id: felt252,
        kind: felt252,
        pubkey_bytes: Array<felt252>,
        role: felt252,
        weight: u8,
        label: felt252,
    ) -> u32;
    fn execute_remove_owner(ref self: TContractState, op_id: felt252, owner_id: u32);
    fn execute_set_threshold(ref self: TContractState, op_id: felt252, new: u8);

    fn cancel_pending_op(ref self: TContractState, op_id: felt252);
}

// Timelock constants mirror src/governance/pending_ops.cairo so tests
// can fast-forward exactly enough to cross each window.
const TIMELOCK_ADD_OWNER: u64 = 172_800; // 48h
const TIMELOCK_REMOVE_OWNER: u64 = 86_400; // 24h
const TIMELOCK_SET_THRESHOLD: u64 = 172_800; // 48h

// --------------------------------------------------------------
// Fixture helpers
// --------------------------------------------------------------

fn declare_verifier_and_account() -> (felt252, @snforge_std::ContractClass) {
    // Audit M-1 (V8.2) — `validate_pubkey` is now dispatched via
    // library_call to the registered verifier class, so the kind tag
    // and verifier class MUST match. These tests deploy with kind
    // 'ED25519' and 2-felt pubkeys, so register Ed25519Verifier
    // (was StarkVerifier under V8.1; V8.1's length-only check didn't
    // catch the mismatch).
    let verifier_class = *declare("Ed25519Verifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    (verifier_class.into(), account_class)
}

fn deploy_account(
    account_class: @snforge_std::ContractClass,
    verifier_class_hash_felt: felt252,
    kind: felt252,
    pubkey_low: felt252,
    pubkey_high: felt252,
) -> ContractAddress {
    let calldata: Array<felt252> = array![
        kind, verifier_class_hash_felt, 2, pubkey_low, pubkey_high, 'primary',
    ];
    let (addr, _) = account_class.deploy(@calldata).unwrap();
    addr
}

// --------------------------------------------------------------
// Initial state + deterministic addresses
// --------------------------------------------------------------

#[test]
fn test_initial_state_primary_owner_at_id_zero() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let reads = IShhhAccountReadsDispatcher { contract_address: addr };

    assert(reads.primary_kind() == 'ED25519', 'bad primary_kind');
    assert(reads.owner_count() == 1_u32, 'bad owner_count');
    assert(reads.active_owner_count() == 1_u32, 'bad active_owner_count');
    assert(reads.threshold() == 1_u8, 'bad threshold');
    assert(reads.total_weight() == 1_u32, 'bad total_weight');

    let owner_0 = reads.get_owner(0);
    assert(owner_0.kind == 'ED25519', 'owner_0 bad kind');
    assert(owner_0.role == ROLE_OWNER, 'owner_0 bad role');
    assert(owner_0.weight == 1_u8, 'owner_0 bad weight');
    assert(!owner_0.revoked, 'owner_0 revoked?');
}

#[test]
fn test_address_salt_binds_kind_and_pubkey_hash() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr1 = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let addr2 = deploy_account(account_class, verifier_felt, 'SECP256K1', 0xAAAA, 0xBBBB);
    let reads1 = IShhhAccountReadsDispatcher { contract_address: addr1 };
    let reads2 = IShhhAccountReadsDispatcher { contract_address: addr2 };
    assert(reads1.address_salt() != reads2.address_salt(), 'salt: kind collision');
    assert(reads1.primary_pubkey_hash() != reads2.primary_pubkey_hash(), 'hash: kind collision');
}

#[test]
fn test_deterministic_salt_is_stable() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr1 = deploy_account(account_class, verifier_felt, 'ED25519', 0xDEAD, 0xBEEF);
    let addr2 = deploy_account(account_class, verifier_felt, 'ED25519', 0xDEAD, 0xBEEF);
    let reads1 = IShhhAccountReadsDispatcher { contract_address: addr1 };
    let reads2 = IShhhAccountReadsDispatcher { contract_address: addr2 };
    assert(reads1.address_salt() == reads2.address_salt(), 'salt: non-deterministic');
}

// --------------------------------------------------------------
// Propose entrypoints — caller != self must revert
// --------------------------------------------------------------

#[test]
#[should_panic(expected: 'SHHH: caller != self')]
fn test_external_propose_add_owner_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);

    let gov = IShhhGovDispatcher { contract_address: addr };
    gov.propose_add_owner(0_u32, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');
}

#[test]
#[should_panic(expected: 'SHHH: caller != self')]
fn test_external_propose_remove_owner_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    let gov = IShhhGovDispatcher { contract_address: addr };
    gov.propose_remove_owner(0_u32, 0_u32);
}

#[test]
#[should_panic(expected: 'SHHH: caller != self')]
fn test_external_propose_set_threshold_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    let gov = IShhhGovDispatcher { contract_address: addr };
    gov.propose_set_threshold(0_u32, 2_u8);
}

#[test]
#[should_panic(expected: 'SHHH: caller != self')]
fn test_external_cancel_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    let gov = IShhhGovDispatcher { contract_address: addr };
    gov.cancel_pending_op(0x1234);
}

// --------------------------------------------------------------
// Happy path: propose → wait timelock → execute
// --------------------------------------------------------------

#[test]
fn test_propose_then_execute_add_owner() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let gov = IShhhGovDispatcher { contract_address: addr };
    let reads = IShhhAccountReadsDispatcher { contract_address: addr };

    // 1. Propose (self-call).
    start_cheat_block_timestamp_global(1000);
    start_cheat_caller_address(addr, addr);
    let op_id = gov
        .propose_add_owner(0_u32, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');
    assert(reads.owner_count() == 1_u32, 'count before execute');

    // 2. Advance past the timelock — execute is permissionless.
    start_cheat_block_timestamp_global(1000 + TIMELOCK_ADD_OWNER + 1);
    let permissionless: ContractAddress = 0xAAAA_AAAA.try_into().unwrap();
    start_cheat_caller_address(addr, permissionless);
    let new_id = gov
        .execute_add_owner(op_id, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');

    assert(new_id == 1_u32, 'new_id');
    assert(reads.owner_count() == 2_u32, 'count after execute');
    assert(reads.active_owner_count() == 2_u32, 'active after execute');
    assert(reads.total_weight() == 2_u32, 'weight after execute');
}

#[test]
#[should_panic(expected: 'OP: timelock not elapsed')]
fn test_execute_before_timelock_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let gov = IShhhGovDispatcher { contract_address: addr };

    start_cheat_block_timestamp_global(1000);
    start_cheat_caller_address(addr, addr);
    let op_id = gov
        .propose_add_owner(0_u32, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');

    // Not advancing time — still within the window.
    gov.execute_add_owner(op_id, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');
}

#[test]
#[should_panic(expected: 'OP: payload mismatch')]
fn test_execute_with_wrong_args_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let gov = IShhhGovDispatcher { contract_address: addr };

    start_cheat_block_timestamp_global(1000);
    start_cheat_caller_address(addr, addr);
    let op_id = gov
        .propose_add_owner(0_u32, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');

    // Advance past timelock; execute with a DIFFERENT label.
    start_cheat_block_timestamp_global(1000 + TIMELOCK_ADD_OWNER + 1);
    gov.execute_add_owner(op_id, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'other');
}

#[test]
#[should_panic(expected: 'OP: already executed')]
fn test_double_execute_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let gov = IShhhGovDispatcher { contract_address: addr };

    start_cheat_block_timestamp_global(1000);
    start_cheat_caller_address(addr, addr);
    let op_id = gov
        .propose_add_owner(0_u32, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');

    start_cheat_block_timestamp_global(1000 + TIMELOCK_ADD_OWNER + 1);
    gov.execute_add_owner(op_id, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');
    // Second call must revert.
    gov.execute_add_owner(op_id, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');
}

#[test]
#[should_panic(expected: 'OP: cancelled')]
fn test_cancel_prevents_execute() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let gov = IShhhGovDispatcher { contract_address: addr };

    start_cheat_block_timestamp_global(1000);
    start_cheat_caller_address(addr, addr);
    let op_id = gov
        .propose_add_owner(0_u32, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');

    // Cancel during the window.
    gov.cancel_pending_op(op_id);

    // Advance + try to execute — must fail.
    start_cheat_block_timestamp_global(1000 + TIMELOCK_ADD_OWNER + 1);
    gov.execute_add_owner(op_id, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');
}

// --------------------------------------------------------------
// Component invariants fire at execute time
// --------------------------------------------------------------

#[test]
#[should_panic(expected: 'OWNERS: duplicate pubkey_hash')]
fn test_execute_duplicate_pubkey_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let gov = IShhhGovDispatcher { contract_address: addr };

    start_cheat_block_timestamp_global(1000);
    start_cheat_caller_address(addr, addr);
    let op_id = gov
        .propose_add_owner(0_u32, 'ED25519', array![0xAAAA, 0xBBBB], ROLE_OWNER, 1_u8, 'dup');

    start_cheat_block_timestamp_global(1000 + TIMELOCK_ADD_OWNER + 1);
    gov.execute_add_owner(op_id, 'ED25519', array![0xAAAA, 0xBBBB], ROLE_OWNER, 1_u8, 'dup');
}

#[test]
#[should_panic(expected: 'OWNERS: zero active owners')]
fn test_execute_remove_last_owner_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let gov = IShhhGovDispatcher { contract_address: addr };

    start_cheat_block_timestamp_global(1000);
    start_cheat_caller_address(addr, addr);
    let op_id = gov.propose_remove_owner(0_u32, 0_u32);

    start_cheat_block_timestamp_global(1000 + TIMELOCK_REMOVE_OWNER + 1);
    gov.execute_remove_owner(op_id, 0_u32);
}

#[test]
#[should_panic(expected: 'OWNERS: threshold == 0')]
fn test_execute_threshold_zero_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let gov = IShhhGovDispatcher { contract_address: addr };

    start_cheat_block_timestamp_global(1000);
    start_cheat_caller_address(addr, addr);
    let op_id = gov.propose_set_threshold(0_u32, 0_u8);

    start_cheat_block_timestamp_global(1000 + TIMELOCK_SET_THRESHOLD + 1);
    gov.execute_set_threshold(op_id, 0_u8);
}

#[test]
#[should_panic(expected: 'OWNERS: threshold > weight')]
fn test_execute_threshold_above_weight_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let gov = IShhhGovDispatcher { contract_address: addr };

    start_cheat_block_timestamp_global(1000);
    start_cheat_caller_address(addr, addr);
    let op_id = gov.propose_set_threshold(0_u32, 5_u8);

    start_cheat_block_timestamp_global(1000 + TIMELOCK_SET_THRESHOLD + 1);
    gov.execute_set_threshold(op_id, 5_u8);
}

#[test]
fn test_remove_middle_owner_keeps_ids_stable() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let gov = IShhhGovDispatcher { contract_address: addr };
    let reads = IShhhAccountReadsDispatcher { contract_address: addr };

    // Add two more owners.
    start_cheat_caller_address(addr, addr);
    start_cheat_block_timestamp_global(1000);
    let op_a = gov
        .propose_add_owner(0_u32, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');
    let op_b = gov
        .propose_add_owner(0_u32, 'ED25519', array![0xEEEE, 0xFFFF], ROLE_OWNER, 1_u8, 'yubi');
    start_cheat_block_timestamp_global(1000 + TIMELOCK_ADD_OWNER + 1);
    gov.execute_add_owner(op_a, 'ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');
    gov.execute_add_owner(op_b, 'ED25519', array![0xEEEE, 0xFFFF], ROLE_OWNER, 1_u8, 'yubi');
    assert(reads.owner_count() == 3_u32, 'pre-remove count');

    // Propose + execute remove owner_id 1.
    let ts = 1000 + TIMELOCK_ADD_OWNER + 1;
    start_cheat_caller_address(addr, addr);
    start_cheat_block_timestamp_global(ts);
    let op_r = gov.propose_remove_owner(0_u32, 1_u32);
    start_cheat_block_timestamp_global(ts + TIMELOCK_REMOVE_OWNER + 1);
    gov.execute_remove_owner(op_r, 1_u32);

    assert(reads.owner_count() == 3_u32, 'count drifted');
    assert(reads.active_owner_count() == 2_u32, 'active count wrong');
    let removed = reads.get_owner(1);
    assert(removed.revoked, 'owner_1 not revoked');
    let owner_2 = reads.get_owner(2);
    assert(!owner_2.revoked, 'owner_2 lost');
    assert(owner_2.label == 'yubi', 'owner_2 data drift');
}
