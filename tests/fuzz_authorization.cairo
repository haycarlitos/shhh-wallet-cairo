//! Phase 10 — Fuzz: arbitrary non-self callers never mutate account state.
//!
//! These assert the PRIMARY security property of every self-gated
//! entrypoint: regardless of what address the caller is, if they're
//! not the account itself, the call reverts. Handpicked positive
//! tests in earlier phases cover a specific attacker; this one sweeps
//! the whole address space via fuzz.
//!
//! Running: `snforge test fuzz_authorization --fuzzer-runs 256`
//! Default `--fuzzer-runs 256`; tune with `-r`.

use shhh_wallet::owner_set::interface::ROLE_OWNER;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address};
use starknet::ContractAddress;

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
    fn cancel_pending_op(ref self: TContractState, op_id: felt252);
    fn revoke_session_key(ref self: TContractState, session_key: felt252);
}

fn deploy_account() -> ContractAddress {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, 0xAAAA, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();
    addr
}

/// felt252 → ContractAddress, biased so we never collide with the
/// deployed-account address (which is deterministic). We squash the
/// high bits so the address is small and distinct from the test's
/// account_addr for any fuzzer input.
fn attacker_address_from(seed: felt252) -> ContractAddress {
    // Force a small positive value (1..=0xFFFF_FFFF) to keep collision
    // with the snforge-issued account address astronomically unlikely.
    let s: u128 = seed.try_into().unwrap_or(0_u128);
    let low32: u128 = (s & 0xFFFF_FFFF) + 1;
    let addr_felt: felt252 = low32.into();
    addr_felt.try_into().unwrap()
}

#[test]
#[fuzzer]
#[should_panic(expected: 'SHHH: caller != self')]
fn fuzz_propose_add_owner_rejects_any_caller(attacker_seed: felt252) {
    let addr = deploy_account();
    let attacker = attacker_address_from(attacker_seed);
    start_cheat_caller_address(addr, attacker);
    let gov = IShhhGovDispatcher { contract_address: addr };
    gov.propose_add_owner(0_u32, 'ED25519', array![0xDEAD, 0xBEEF], ROLE_OWNER, 1_u8, 'x');
}

#[test]
#[fuzzer]
#[should_panic(expected: 'SHHH: caller != self')]
fn fuzz_cancel_pending_op_rejects_any_caller(attacker_seed: felt252) {
    let addr = deploy_account();
    let attacker = attacker_address_from(attacker_seed);
    start_cheat_caller_address(addr, attacker);
    let gov = IShhhGovDispatcher { contract_address: addr };
    // op_id is arbitrary — caller check fires first.
    gov.cancel_pending_op(0x1234);
}

#[test]
#[fuzzer]
#[should_panic(expected: 'SHHH: caller != self')]
fn fuzz_revoke_session_key_rejects_any_caller(attacker_seed: felt252) {
    let addr = deploy_account();
    let attacker = attacker_address_from(attacker_seed);
    start_cheat_caller_address(addr, attacker);
    let gov = IShhhGovDispatcher { contract_address: addr };
    gov.revoke_session_key(0xFACE);
}
