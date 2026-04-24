//! Phase 6 — guardian-initiated recovery.
//!
//! Lifecycle:
//!   1. `initiate_recovery`  — self-call, proposer MUST be ROLE_GUARDIAN.
//!      Stores the new-owner commitment with 7d timelock.
//!   2. `cancel_recovery`    — self-call, any ROLE_OWNER. Wipes pending state.
//!   3. `finalize_recovery`  — permissionless after 7d. Caller re-provides
//!      the full new-owner args, we recompute the commitment, match, and
//!      add to the owner set. Additive: existing owners stay.
//!
//! The helper layer below wires every test with:
//!   (a) a deployed account with a primary owner
//!   (b) an added GUARDIAN via the Phase 5 propose/execute path
//!   (c) time advance helpers that respect the Phase 5 timelocks too

use shhh_wallet::owner_set::interface::{ROLE_GUARDIAN, ROLE_OWNER};
use shhh_wallet::recovery::component::RecoveryComponent::PendingRecovery;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_caller_address,
};
use starknet::ContractAddress;

// --------------------------------------------------------------
// Account ABI surfaces
// --------------------------------------------------------------

#[starknet::interface]
trait IShhhReads<TContractState> {
    fn owner_count(self: @TContractState) -> u32;
    fn active_owner_count(self: @TContractState) -> u32;
    fn get_owner(
        self: @TContractState, owner_id: u32,
    ) -> shhh_wallet::owner_set::interface::OwnerRecord;
    fn get_pending_recovery(self: @TContractState) -> PendingRecovery;
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
    fn execute_add_owner(
        ref self: TContractState,
        op_id: felt252,
        kind: felt252,
        pubkey_bytes: Array<felt252>,
        role: felt252,
        weight: u8,
        label: felt252,
    ) -> u32;
    fn propose_remove_owner(ref self: TContractState, proposer: u32, owner_id: u32) -> felt252;
    fn execute_remove_owner(ref self: TContractState, op_id: felt252, owner_id: u32);
}

#[starknet::interface]
trait IShhhRecovery<TContractState> {
    fn initiate_recovery(
        ref self: TContractState,
        proposer: u32,
        new_owner_kind: felt252,
        new_pubkey_bytes: Array<felt252>,
        new_role: felt252,
        new_weight: u8,
        new_label: felt252,
    );
    fn cancel_recovery(ref self: TContractState, owner_id: u32);
    fn finalize_recovery(
        ref self: TContractState,
        new_owner_kind: felt252,
        new_pubkey_bytes: Array<felt252>,
        new_role: felt252,
        new_weight: u8,
        new_label: felt252,
    ) -> u32;
}

const TIMELOCK_ADD_OWNER: u64 = 172_800; // 48h
const TIMELOCK_REMOVE_OWNER: u64 = 86_400; // 24h
const TIMELOCK_RECOVERY: u64 = 604_800; // 7d — Argent-aligned

// --------------------------------------------------------------
// Fixture helpers
// --------------------------------------------------------------

fn deploy_account_with_guardian() -> (ContractAddress, u32) {
    // Primary owner @ id 0 (STARK kind), guardian @ id 1 (STARK kind).
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, 0xAAAA, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();

    // Add the guardian via the timelocked propose/execute flow.
    let gov = IShhhGovDispatcher { contract_address: addr };
    start_cheat_block_timestamp_global(100);
    start_cheat_caller_address(addr, addr);
    let op_id = gov
        .propose_add_owner(0_u32, 'STARK', array![0xCCCC], ROLE_GUARDIAN, 1_u8, 'guardian');
    start_cheat_block_timestamp_global(100 + TIMELOCK_ADD_OWNER + 1);
    let guardian_id = gov
        .execute_add_owner(op_id, 'STARK', array![0xCCCC], ROLE_GUARDIAN, 1_u8, 'guardian');
    (addr, guardian_id)
}

fn time_after_recovery(now: u64) -> u64 {
    now + TIMELOCK_RECOVERY + 1
}

// --------------------------------------------------------------
// Happy path
// --------------------------------------------------------------

#[test]
fn test_happy_path_recovery_adds_owner() {
    let (addr, guardian_id) = deploy_account_with_guardian();
    let reads = IShhhReadsDispatcher { contract_address: addr };
    let rec = IShhhRecoveryDispatcher { contract_address: addr };

    assert(reads.owner_count() == 2_u32, 'pre-recovery count');
    assert(reads.active_owner_count() == 2_u32, 'pre active count');

    // 1. Guardian initiates.
    let ts = 1_000_000;
    start_cheat_block_timestamp_global(ts);
    start_cheat_caller_address(addr, addr);
    rec.initiate_recovery(guardian_id, 'STARK', array![0xDEAD], ROLE_OWNER, 1_u8, 'new-phone');

    let pending = reads.get_pending_recovery();
    assert(pending.is_active, 'recovery not active');
    assert(pending.valid_after == ts + TIMELOCK_RECOVERY, 'bad valid_after');

    // 2. Fast-forward past 7d.
    start_cheat_block_timestamp_global(time_after_recovery(ts));

    // 3. Anyone can finalize (no caller cheat).
    let new_id = rec.finalize_recovery('STARK', array![0xDEAD], ROLE_OWNER, 1_u8, 'new-phone');
    assert(new_id == 2_u32, 'new owner id wrong');

    // Additive: primary + guardian + new owner all active.
    assert(reads.owner_count() == 3_u32, 'post count wrong');
    assert(reads.active_owner_count() == 3_u32, 'post active wrong');
    let new_owner = reads.get_owner(new_id);
    assert(new_owner.role == ROLE_OWNER, 'new owner role');
    assert(new_owner.label == 'new-phone', 'new owner label');

    // Pending recovery cleared.
    let cleared = reads.get_pending_recovery();
    assert(!cleared.is_active, 'recovery not cleared');
}

// --------------------------------------------------------------
// Owner can cancel during the window
// --------------------------------------------------------------

#[test]
fn test_owner_cancels_during_window() {
    let (addr, guardian_id) = deploy_account_with_guardian();
    let reads = IShhhReadsDispatcher { contract_address: addr };
    let rec = IShhhRecoveryDispatcher { contract_address: addr };

    let ts = 1_000_000;
    start_cheat_block_timestamp_global(ts);
    start_cheat_caller_address(addr, addr);
    rec.initiate_recovery(guardian_id, 'STARK', array![0xDEAD], ROLE_OWNER, 1_u8, 'new-phone');
    assert(reads.get_pending_recovery().is_active, 'expected pending');

    // Primary owner (id 0) cancels during the window (before 7d).
    start_cheat_block_timestamp_global(ts + 1_000);
    rec.cancel_recovery(0_u32);

    let cleared = reads.get_pending_recovery();
    assert(!cleared.is_active, 'recovery should be cleared');
    assert(reads.owner_count() == 2_u32, 'no owner added');
}

// --------------------------------------------------------------
// Finalize before 7d → revert
// --------------------------------------------------------------

#[test]
#[should_panic(expected: 'RECOVERY: timelock not met')]
fn test_finalize_before_timelock_reverts() {
    let (addr, guardian_id) = deploy_account_with_guardian();
    let rec = IShhhRecoveryDispatcher { contract_address: addr };

    let ts = 1_000_000;
    start_cheat_block_timestamp_global(ts);
    start_cheat_caller_address(addr, addr);
    rec.initiate_recovery(guardian_id, 'STARK', array![0xDEAD], ROLE_OWNER, 1_u8, 'new-phone');

    // Fast-forward only 1 day — nowhere near 7d.
    start_cheat_block_timestamp_global(ts + 86_400);
    rec.finalize_recovery('STARK', array![0xDEAD], ROLE_OWNER, 1_u8, 'new-phone');
}

// --------------------------------------------------------------
// Cannot double-initiate
// --------------------------------------------------------------

#[test]
#[should_panic(expected: 'RECOVERY: already pending')]
fn test_cannot_double_initiate() {
    let (addr, guardian_id) = deploy_account_with_guardian();
    let rec = IShhhRecoveryDispatcher { contract_address: addr };

    let ts = 1_000_000;
    start_cheat_block_timestamp_global(ts);
    start_cheat_caller_address(addr, addr);
    rec.initiate_recovery(guardian_id, 'STARK', array![0xDEAD], ROLE_OWNER, 1_u8, 'p1');
    // Second initiate before cancel/finalize must revert.
    rec.initiate_recovery(guardian_id, 'STARK', array![0xBEEF], ROLE_OWNER, 1_u8, 'p2');
}

// --------------------------------------------------------------
// Non-guardian cannot initiate
// --------------------------------------------------------------

#[test]
#[should_panic(expected: 'RECOVERY: not a guardian')]
fn test_owner_cannot_initiate_recovery() {
    let (addr, _guardian_id) = deploy_account_with_guardian();
    let rec = IShhhRecoveryDispatcher { contract_address: addr };

    start_cheat_block_timestamp_global(1_000_000);
    start_cheat_caller_address(addr, addr);
    // proposer=0 is the primary OWNER, not a guardian.
    rec.initiate_recovery(0_u32, 'STARK', array![0xDEAD], ROLE_OWNER, 1_u8, 'new');
}

// --------------------------------------------------------------
// Finalize with tampered args → revert
// --------------------------------------------------------------

#[test]
#[should_panic(expected: 'RECOVERY: args mismatch')]
fn test_finalize_with_wrong_args_reverts() {
    let (addr, guardian_id) = deploy_account_with_guardian();
    let rec = IShhhRecoveryDispatcher { contract_address: addr };

    let ts = 1_000_000;
    start_cheat_block_timestamp_global(ts);
    start_cheat_caller_address(addr, addr);
    rec.initiate_recovery(guardian_id, 'STARK', array![0xDEAD], ROLE_OWNER, 1_u8, 'real');

    start_cheat_block_timestamp_global(time_after_recovery(ts));
    // Wrong label — commitment mismatch → revert.
    rec.finalize_recovery('STARK', array![0xDEAD], ROLE_OWNER, 1_u8, 'fake');
}

// --------------------------------------------------------------
// Cancel when no pending recovery → revert
// --------------------------------------------------------------

#[test]
#[should_panic(expected: 'RECOVERY: no pending op')]
fn test_cancel_without_pending_reverts() {
    let (addr, _) = deploy_account_with_guardian();
    let rec = IShhhRecoveryDispatcher { contract_address: addr };

    start_cheat_caller_address(addr, addr);
    rec.cancel_recovery(0_u32);
}

// --------------------------------------------------------------
// Guardian cannot cancel (only OWNER role can)
// --------------------------------------------------------------

#[test]
#[should_panic(expected: 'RECOVERY: not an owner')]
fn test_guardian_cannot_cancel() {
    let (addr, guardian_id) = deploy_account_with_guardian();
    let rec = IShhhRecoveryDispatcher { contract_address: addr };

    start_cheat_block_timestamp_global(1_000_000);
    start_cheat_caller_address(addr, addr);
    rec.initiate_recovery(guardian_id, 'STARK', array![0xDEAD], ROLE_OWNER, 1_u8, 'new');
    // Guardian tries to cancel — not an OWNER → must revert.
    rec.cancel_recovery(guardian_id);
}

// --------------------------------------------------------------
// Revoked guardian cannot initiate recovery
// --------------------------------------------------------------

/// Edge case: once a guardian is removed (role tombstoned via
/// `execute_remove_owner`), calling `initiate_recovery` with their
/// owner_id MUST revert with 'RECOVERY: proposer revoked'. Without
/// this guard, a compromised but removed guardian could still start
/// the 7-day window, forcing the legitimate owner into a cancel race.
#[test]
#[should_panic(expected: 'RECOVERY: proposer revoked')]
fn test_revoked_guardian_cannot_initiate_recovery() {
    let (addr, guardian_id) = deploy_account_with_guardian();
    let gov = IShhhGovDispatcher { contract_address: addr };
    let rec = IShhhRecoveryDispatcher { contract_address: addr };

    // Remove the guardian via the standard timelocked flow.
    let base_ts = TIMELOCK_ADD_OWNER + 100;
    start_cheat_block_timestamp_global(base_ts);
    start_cheat_caller_address(addr, addr);
    let op = gov.propose_remove_owner(0_u32, guardian_id);
    start_cheat_block_timestamp_global(base_ts + TIMELOCK_REMOVE_OWNER + 1);
    gov.execute_remove_owner(op, guardian_id);

    // Now the (revoked) guardian tries to kick off a recovery.
    start_cheat_caller_address(addr, addr);
    rec.initiate_recovery(guardian_id, 'STARK', array![0xDEAD], ROLE_OWNER, 1_u8, 'newphone');
}
