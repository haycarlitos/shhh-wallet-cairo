//! Phase 10 — Fuzz: timelock monotonicity.
//!
//! Propose a timelocked op at t=T, then at a random `now` attempt to
//! execute. The op must accept iff `now >= T + timelock` AND
//! `now <= T + timelock + expiry`.
//!
//! We encode the invariant as two symmetric tests:
//!   A. now < T + timelock            → `OP: timelock not elapsed`
//!   B. now > T + timelock + expiry   → `OP: expired`

use shhh_wallet::owner_set::interface::ROLE_OWNER;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_caller_address,
};
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
    fn execute_add_owner(
        ref self: TContractState,
        op_id: felt252,
        kind: felt252,
        pubkey_bytes: Array<felt252>,
        role: felt252,
        weight: u8,
        label: felt252,
    ) -> u32;
}

const TIMELOCK_ADD_OWNER: u64 = 172_800; // 48h
const OP_EXPIRY: u64 = 1_209_600; // 14d

fn deploy_account() -> ContractAddress {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, 0xAAAA, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();
    addr
}

/// Fuzz: any `now` earlier than (propose_ts + timelock) MUST revert with
/// 'OP: timelock not elapsed'. Clamps the input to ensure we stay in
/// the early-window range so the test is a true invariant check.
#[test]
#[fuzzer]
#[should_panic(expected: 'OP: timelock not elapsed')]
fn fuzz_execute_before_timelock_always_reverts(early_offset: felt252) {
    let propose_ts: u64 = 1_000_000;
    // Clamp to [1, TIMELOCK_ADD_OWNER - 1] — strictly before the window opens.
    let raw: u128 = early_offset.try_into().unwrap_or(0_u128);
    let offset: u64 = ((raw % (TIMELOCK_ADD_OWNER - 1).into()) + 1).try_into().unwrap();

    let addr = deploy_account();
    let gov = IShhhGovDispatcher { contract_address: addr };

    start_cheat_block_timestamp_global(propose_ts);
    start_cheat_caller_address(addr, addr);
    let op_id = gov
        .propose_add_owner(0_u32, 'ED25519', array![0xDEAD, 0xBEEF], ROLE_OWNER, 1_u8, 'x');

    // Advance to a time strictly before the timelock elapses.
    start_cheat_block_timestamp_global(propose_ts + offset);
    gov.execute_add_owner(op_id, 'ED25519', array![0xDEAD, 0xBEEF], ROLE_OWNER, 1_u8, 'x');
}

/// Fuzz: any `now` past (propose_ts + timelock + expiry) MUST revert with
/// 'OP: expired'. Clamps past the expiry wall.
#[test]
#[fuzzer]
#[should_panic(expected: 'OP: expired')]
fn fuzz_execute_after_expiry_always_reverts(far_future_offset: felt252) {
    let propose_ts: u64 = 1_000_000;
    let raw: u128 = far_future_offset.try_into().unwrap_or(0_u128);
    // Clamp to [1, 2^40] seconds past expiry — always expired.
    // 2^40 = 0x10000000000 ≈ 1099 billion seconds — enough to always blow past expiry.
    let extra: u64 = ((raw % 0x10000000000_u128) + 1).try_into().unwrap();

    let addr = deploy_account();
    let gov = IShhhGovDispatcher { contract_address: addr };

    start_cheat_block_timestamp_global(propose_ts);
    start_cheat_caller_address(addr, addr);
    let op_id = gov
        .propose_add_owner(0_u32, 'ED25519', array![0xDEAD, 0xBEEF], ROLE_OWNER, 1_u8, 'x');

    start_cheat_block_timestamp_global(propose_ts + TIMELOCK_ADD_OWNER + OP_EXPIRY + extra);
    gov.execute_add_owner(op_id, 'ED25519', array![0xDEAD, 0xBEEF], ROLE_OWNER, 1_u8, 'x');
}
