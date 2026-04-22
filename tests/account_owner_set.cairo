//! Phase 4 — owner-set wiring in ShhhAccount.
//!
//! Covers the invariants exposed by the account's external IOwnerSet
//! surface and the self-gate on every mutator.

use shhh_wallet::owner_set::interface::ROLE_OWNER;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address};
use starknet::ContractAddress;

// Minimal external ABI for the ShhhAccount entrypoints the tests drive.
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
trait IShhhAccountMutators<TContractState> {
    fn add_owner(
        ref self: TContractState,
        kind: felt252,
        pubkey_bytes: Array<felt252>,
        role: felt252,
        weight: u8,
        label: felt252,
    ) -> u32;
    fn remove_owner(ref self: TContractState, owner_id: u32);
    fn set_threshold(ref self: TContractState, new: u8);
}

fn declare_verifier_and_account() -> (felt252, @snforge_std::ContractClass) {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
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

// ============================================================
// Initial state
// ============================================================

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
    // Same raw pubkey, two different kinds → DIFFERENT salts.
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr1 = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let addr2 = deploy_account(account_class, verifier_felt, 'SECP256K1', 0xAAAA, 0xBBBB);
    let reads1 = IShhhAccountReadsDispatcher { contract_address: addr1 };
    let reads2 = IShhhAccountReadsDispatcher { contract_address: addr2 };
    assert(reads1.address_salt() != reads2.address_salt(), 'salt: kind collision');
    // Same pubkey_hash, different kind.
    assert(reads1.primary_pubkey_hash() != reads2.primary_pubkey_hash(), 'hash: kind collision');
}

#[test]
fn test_deterministic_salt_is_stable() {
    // Two separate deployments with identical inputs → same salt.
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr1 = deploy_account(account_class, verifier_felt, 'ED25519', 0xDEAD, 0xBEEF);
    let addr2 = deploy_account(account_class, verifier_felt, 'ED25519', 0xDEAD, 0xBEEF);
    let reads1 = IShhhAccountReadsDispatcher { contract_address: addr1 };
    let reads2 = IShhhAccountReadsDispatcher { contract_address: addr2 };
    assert(reads1.address_salt() == reads2.address_salt(), 'salt: non-deterministic');
}

// ============================================================
// Mutator self-gate
// ============================================================

#[test]
#[should_panic(expected: 'SHHH: caller != self')]
fn test_external_add_owner_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);

    let muts = IShhhAccountMutatorsDispatcher { contract_address: addr };
    muts.add_owner('ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');
}

#[test]
#[should_panic(expected: 'SHHH: caller != self')]
fn test_external_remove_owner_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    let muts = IShhhAccountMutatorsDispatcher { contract_address: addr };
    muts.remove_owner(0_u32);
}

#[test]
#[should_panic(expected: 'SHHH: caller != self')]
fn test_external_set_threshold_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    let muts = IShhhAccountMutatorsDispatcher { contract_address: addr };
    muts.set_threshold(2_u8);
}

// ============================================================
// Self-call happy paths — cheat caller to the account itself.
// ============================================================

#[test]
fn test_self_call_add_owner_appends() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    start_cheat_caller_address(addr, addr);

    let muts = IShhhAccountMutatorsDispatcher { contract_address: addr };
    let new_id = muts.add_owner('ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');
    assert(new_id == 1_u32, 'new_id should be 1');

    let reads = IShhhAccountReadsDispatcher { contract_address: addr };
    assert(reads.owner_count() == 2_u32, 'owner_count should be 2');
    assert(reads.active_owner_count() == 2_u32, 'active_count should be 2');
    assert(reads.total_weight() == 2_u32, 'weight should be 2');

    let owner_1 = reads.get_owner(1);
    assert(owner_1.kind == 'ED25519', 'owner_1 bad kind');
    assert(owner_1.label == 'phone', 'owner_1 bad label');
}

#[test]
#[should_panic(expected: 'OWNERS: duplicate pubkey_hash')]
fn test_add_duplicate_pubkey_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    start_cheat_caller_address(addr, addr);

    let muts = IShhhAccountMutatorsDispatcher { contract_address: addr };
    // Try to re-register the primary owner's pubkey.
    muts.add_owner('ED25519', array![0xAAAA, 0xBBBB], ROLE_OWNER, 1_u8, 'dup');
}

#[test]
#[should_panic(expected: 'OWNERS: zero active owners')]
fn test_cannot_remove_last_owner() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    start_cheat_caller_address(addr, addr);

    let muts = IShhhAccountMutatorsDispatcher { contract_address: addr };
    muts.remove_owner(0_u32); // invariant guard must fire
}

#[test]
fn test_remove_owner_keeps_ids_stable() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    start_cheat_caller_address(addr, addr);

    let muts = IShhhAccountMutatorsDispatcher { contract_address: addr };
    muts.add_owner('ED25519', array![0xCCCC, 0xDDDD], ROLE_OWNER, 1_u8, 'phone');
    muts.add_owner('ED25519', array![0xEEEE, 0xFFFF], ROLE_OWNER, 1_u8, 'yubi');

    let reads = IShhhAccountReadsDispatcher { contract_address: addr };
    assert(reads.owner_count() == 3_u32, 'pre-remove count');

    // Remove middle owner; expect owner_id 1 tombstoned, total stays at 3.
    muts.remove_owner(1_u32);
    assert(reads.owner_count() == 3_u32, 'owner_count drifted');
    assert(reads.active_owner_count() == 2_u32, 'active count wrong');
    let removed = reads.get_owner(1);
    assert(removed.revoked, 'owner_1 not revoked');
    let owner_2 = reads.get_owner(2);
    assert(!owner_2.revoked, 'owner_2 lost');
    assert(owner_2.label == 'yubi', 'owner_2 data drift');
}

#[test]
#[should_panic(expected: 'OWNERS: threshold > weight')]
fn test_threshold_above_weight_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    start_cheat_caller_address(addr, addr);
    let muts = IShhhAccountMutatorsDispatcher { contract_address: addr };
    // total weight = 1; threshold = 5 violates invariant
    muts.set_threshold(5_u8);
}

#[test]
#[should_panic(expected: 'OWNERS: threshold == 0')]
fn test_threshold_zero_reverts() {
    let (verifier_felt, account_class) = declare_verifier_and_account();
    let addr = deploy_account(account_class, verifier_felt, 'ED25519', 0xAAAA, 0xBBBB);
    start_cheat_caller_address(addr, addr);
    let muts = IShhhAccountMutatorsDispatcher { contract_address: addr };
    muts.set_threshold(0_u8);
}
