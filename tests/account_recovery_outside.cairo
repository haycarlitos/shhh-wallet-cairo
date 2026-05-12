//! V8.4 — guardian-initiated recovery through SNIP-9 V2 outside execution.
//!
//! V8.3 had a real architectural gap: `initiate_recovery` requires
//! `_assert_self_call`, but the OE signature path only accepts
//! ROLE_OWNER signers. Guardians could not directly trigger recovery
//! — the user needed at least one healthy owner to bundle
//! `initiate_recovery` into THEIR own OE, which defeats the headline
//! "I lost my owner key" use case.
//!
//! V8.4 relaxes the OE role check with a surgical carve-out:
//! ROLE_GUARDIAN envelopes are accepted IFF the OE's calls are exactly
//! one call to `initiate_recovery` on the account AND the `proposer`
//! arg (calldata[0]) equals the signer's owner_id. Every other selector
//! still requires ROLE_OWNER; cancel and finalize stay owner-only /
//! permissionless respectively.
//!
//! This file exercises:
//!   1. Happy path: guardian signs an OE that calls initiate_recovery
//!      with their own owner_id as proposer → recovery is initiated.
//!   2. Negative: guardian OE with proposer != signer_owner_id → revert.
//!   3. Negative: guardian OE with a different selector → revert.
//!   4. Negative: guardian OE with multiple calls (initiate_recovery
//!      + something else) → revert.
//!   5. Existing owner OE that happens to call initiate_recovery →
//!      still works (no regression).

use shhh_wallet::outside_execution::{
    ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution, SIG_VERSION_V2_SNIP12,
    compute_snip12_hash,
};
use shhh_wallet::owner_set::interface::ROLE_GUARDIAN;
use shhh_wallet::recovery::component::RecoveryComponent::PendingRecovery;
use snforge_std::signature::SignerTrait;
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_caller_address, declare,
    start_cheat_block_timestamp_global, start_cheat_caller_address, start_cheat_chain_id_global,
    stop_cheat_caller_address,
};
use starknet::ContractAddress;
use starknet::account::Call;

// --------------------------------------------------------------
// Account ABI
// --------------------------------------------------------------

#[starknet::interface]
trait IShhhReads<TContractState> {
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
}

const TIMELOCK_ADD_OWNER: u64 = 172_800; // 48h
const TIMELOCK_RECOVERY: u64 = 604_800; // 7d

// --------------------------------------------------------------
// Fixture: deploy account with primary STARK owner + ROLE_GUARDIAN.
// Both have real keypairs so we can produce real ECDSA signatures
// for OE submission.
// --------------------------------------------------------------

const OWNER_SECRET: felt252 = 0xAAAA_AAAA_AAAA_BEEF;
const GUARDIAN_SECRET: felt252 = 0xCCCC_CCCC_CCCC_BEEF;

fn deploy_account_with_guardian() -> (ContractAddress, u32) {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();

    let owner_kp = StarkCurveKeyPairImpl::from_secret_key(OWNER_SECRET);
    let calldata: Array<felt252> = array![
        'STARK', verifier_class.into(), 1, owner_kp.public_key, 'primary',
    ];
    let (addr, _) = account_class.deploy(@calldata).unwrap();

    // Add the guardian via the standard governance flow (uses cheat
    // because the guardian-OE path doesn't exist yet at this point —
    // it's what this file tests).
    let guardian_kp = StarkCurveKeyPairImpl::from_secret_key(GUARDIAN_SECRET);
    let gov = IShhhGovDispatcher { contract_address: addr };
    start_cheat_block_timestamp_global(1_000);
    start_cheat_caller_address(addr, addr);
    let op_id = gov
        .propose_add_owner(
            0_u32, 'STARK', array![guardian_kp.public_key], ROLE_GUARDIAN, 1_u8, 'phantom-guardian',
        );
    start_cheat_block_timestamp_global(1_000 + TIMELOCK_ADD_OWNER + 1);
    let guardian_id = gov
        .execute_add_owner(
            op_id, 'STARK', array![guardian_kp.public_key], ROLE_GUARDIAN, 1_u8, 'phantom-guardian',
        );
    stop_cheat_caller_address(addr);
    (addr, guardian_id)
}

/// Build an OE that calls `initiate_recovery(proposer, new_kind,
/// new_pubkey_bytes, new_role, new_weight, new_label)` on the account.
/// Returns the OE + the signature envelope signed with the guardian's
/// STARK key.
fn build_guardian_initiate_recovery_oe(
    account: ContractAddress, proposer: u32, new_pubkey: felt252, nonce: felt252,
) -> (OutsideExecution, Array<felt252>, u32) {
    // initiate_recovery calldata layout (Serde):
    //   proposer (u32)
    //   new_owner_kind (felt252)
    //   new_pubkey_bytes (Array<felt252> = [len, item_0, ...])
    //   new_role (felt252)
    //   new_weight (u8)
    //   new_label (felt252)
    let proposer_felt: felt252 = proposer.into();
    let new_role: felt252 = 'OWNER';
    let new_weight_felt: felt252 = 1;
    let new_label: felt252 = 'recovered';
    let calldata: Array<felt252> = array![
        proposer_felt, 'STARK', 1, // pubkey_bytes.len()
        new_pubkey, new_role, new_weight_felt,
        new_label,
    ];

    let call = Call {
        to: account, selector: selector!("initiate_recovery"), calldata: calldata.span(),
    };
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce,
        execute_after: 1_000_000,
        execute_before: 1_000_000 + 3_600,
        calls: array![call].span(),
    };

    let hash = compute_snip12_hash(@oe, account.into(), 'SN_MAIN');
    let guardian_kp = StarkCurveKeyPairImpl::from_secret_key(GUARDIAN_SECRET);
    let (r, s) = guardian_kp.sign(hash).unwrap();
    // V2_SNIP12 single-owner envelope: [version, owner_id, kind_tag, ...payload]
    // For STARK kind: payload = [r, s].
    let envelope: Array<felt252> = array![SIG_VERSION_V2_SNIP12, proposer.into(), 'STARK', r, s];
    (oe, envelope, proposer)
}

fn cheat_oe_caller(account: ContractAddress) {
    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_block_timestamp_global(1_000_001);
    // CheatSpan::TargetCalls(1) — only the first call to the account
    // sees the cheated caller (ANY_CALLER). The internal self-call
    // issued by _execute_calls_atomic_span sees the natural caller
    // (account itself), so `_assert_self_call` inside the subcall passes.
    cheat_caller_address(account, 'ANY_CALLER'.try_into().unwrap(), CheatSpan::TargetCalls(1));
}

// ==========================================================
// Happy path — guardian OE initiates recovery
// ==========================================================

#[test]
fn test_v8_4_guardian_oe_initiates_recovery() {
    let (account, guardian_id) = deploy_account_with_guardian();
    let new_owner_pubkey: felt252 = 0xDEAD_BEEF;
    let (oe, envelope, _) = build_guardian_initiate_recovery_oe(
        account, guardian_id, new_owner_pubkey, 'g-init-1',
    );
    cheat_oe_caller(account);

    let src9 = ISRC9_V2Dispatcher { contract_address: account };
    src9.execute_from_outside_v2(oe, envelope.span());

    // Recovery state should now have a pending entry.
    let reads = IShhhReadsDispatcher { contract_address: account };
    let pending = reads.get_pending_recovery();
    assert(pending.is_active, 'recovery not active');
    assert(pending.valid_after == 1_000_001 + TIMELOCK_RECOVERY, 'wrong valid_after');
    assert(pending.new_owner_hash != 0, 'commitment empty');
}

// ==========================================================
// Guardian OE with proposer != signer_owner_id MUST revert
// ==========================================================

#[test]
#[should_panic(expected: 'SHHH: signer not an owner')]
fn test_v8_4_guardian_oe_rejects_proposer_mismatch() {
    let (account, guardian_id) = deploy_account_with_guardian();
    // Guardian signs the envelope (owner_id in signature = guardian_id),
    // but the initiate_recovery call names a DIFFERENT proposer (0 = the
    // primary owner). The carve-out helper checks calldata[0] ==
    // signer_owner_id, so this fails the role-relaxation gate and falls
    // through to the original ROLE_OWNER check, which a guardian fails.
    let fake_proposer: u32 = 0_u32; // primary owner's id, NOT the guardian's
    let new_owner_pubkey: felt252 = 0xDEAD_BEEF;

    // Build the calldata manually to force the proposer mismatch — we
    // need the OE's calldata to name proposer=0 but the envelope to
    // come from guardian_id.
    let proposer_felt: felt252 = fake_proposer.into();
    let calldata: Array<felt252> = array![
        proposer_felt, 'STARK', 1, new_owner_pubkey, 'OWNER', 1, 'recovered',
    ];
    let call = Call {
        to: account, selector: selector!("initiate_recovery"), calldata: calldata.span(),
    };
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 'mismatch-nonce',
        execute_after: 1_000_000,
        execute_before: 1_000_000 + 3_600,
        calls: array![call].span(),
    };
    let hash = compute_snip12_hash(@oe, account.into(), 'SN_MAIN');
    let guardian_kp = StarkCurveKeyPairImpl::from_secret_key(GUARDIAN_SECRET);
    let (r, s) = guardian_kp.sign(hash).unwrap();
    // owner_id in envelope = guardian_id (the actual signer).
    let envelope: Array<felt252> = array![SIG_VERSION_V2_SNIP12, guardian_id.into(), 'STARK', r, s];

    cheat_oe_caller(account);
    let src9 = ISRC9_V2Dispatcher { contract_address: account };
    src9.execute_from_outside_v2(oe, envelope.span());
}

// ==========================================================
// Guardian OE with non-initiate_recovery selector MUST revert
// ==========================================================

#[test]
#[should_panic(expected: 'SHHH: signer not an owner')]
fn test_v8_4_guardian_oe_rejects_wrong_selector() {
    let (account, guardian_id) = deploy_account_with_guardian();
    // Guardian tries to sign an OE that calls `revoke_session_key` on
    // the account — NOT initiate_recovery. The carve-out helper checks
    // call.selector == selector!("initiate_recovery"), so this fails
    // the role-relaxation gate.
    let calldata: Array<felt252> = array![0xCAFE]; // dummy session key felt
    let call = Call {
        to: account, selector: selector!("revoke_session_key"), calldata: calldata.span(),
    };
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 'wrong-selector-nonce',
        execute_after: 1_000_000,
        execute_before: 1_000_000 + 3_600,
        calls: array![call].span(),
    };
    let hash = compute_snip12_hash(@oe, account.into(), 'SN_MAIN');
    let guardian_kp = StarkCurveKeyPairImpl::from_secret_key(GUARDIAN_SECRET);
    let (r, s) = guardian_kp.sign(hash).unwrap();
    let envelope: Array<felt252> = array![SIG_VERSION_V2_SNIP12, guardian_id.into(), 'STARK', r, s];

    cheat_oe_caller(account);
    let src9 = ISRC9_V2Dispatcher { contract_address: account };
    src9.execute_from_outside_v2(oe, envelope.span());
}

// ==========================================================
// Guardian OE with multiple calls MUST revert (even if one is recovery)
// ==========================================================

#[test]
#[should_panic(expected: 'SHHH: signer not an owner')]
fn test_v8_4_guardian_oe_rejects_multiple_calls() {
    let (account, guardian_id) = deploy_account_with_guardian();
    // Guardian bundles initiate_recovery + another call. Even though
    // call 1 IS initiate_recovery, the carve-out helper requires
    // calls.len() == 1 exactly, so this fails.
    let recovery_calldata: Array<felt252> = array![
        guardian_id.into(), 'STARK', 1, 0xDEAD_BEEF, 'OWNER', 1, 'recovered',
    ];
    let call_a = Call {
        to: account, selector: selector!("initiate_recovery"), calldata: recovery_calldata.span(),
    };
    let call_b = Call {
        to: account, selector: selector!("revoke_session_key"), calldata: array![0xCAFE].span(),
    };
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 'multi-call-nonce',
        execute_after: 1_000_000,
        execute_before: 1_000_000 + 3_600,
        calls: array![call_a, call_b].span(),
    };
    let hash = compute_snip12_hash(@oe, account.into(), 'SN_MAIN');
    let guardian_kp = StarkCurveKeyPairImpl::from_secret_key(GUARDIAN_SECRET);
    let (r, s) = guardian_kp.sign(hash).unwrap();
    let envelope: Array<felt252> = array![SIG_VERSION_V2_SNIP12, guardian_id.into(), 'STARK', r, s];

    cheat_oe_caller(account);
    let src9 = ISRC9_V2Dispatcher { contract_address: account };
    src9.execute_from_outside_v2(oe, envelope.span());
}

// ==========================================================
// Regression: owner OE that calls initiate_recovery still works.
// The V8.4 carve-out adds a path for guardians; it does NOT change
// any existing owner-OE behavior. Owners can still bundle
// initiate_recovery in their OEs as before.
// ==========================================================

#[test]
fn test_v8_4_owner_oe_can_still_call_initiate_recovery() {
    // For this test the account needs at least one guardian (the
    // proposer in initiate_recovery must have ROLE_GUARDIAN), so we
    // use the same fixture.
    let (account, guardian_id) = deploy_account_with_guardian();
    // OWNER signs an OE that calls initiate_recovery, naming the
    // guardian as proposer. The function-level check at
    // `proposer.role == ROLE_GUARDIAN` is what enforces guardian
    // semantics here, not the OE role check.
    let new_owner_pubkey: felt252 = 0xDEAD_BEEF;
    let calldata: Array<felt252> = array![
        guardian_id.into(), 'STARK', 1, new_owner_pubkey, 'OWNER', 1, 'owner-driven-recovery',
    ];
    let call = Call {
        to: account, selector: selector!("initiate_recovery"), calldata: calldata.span(),
    };
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 'owner-recovery-nonce',
        execute_after: 1_000_000,
        execute_before: 1_000_000 + 3_600,
        calls: array![call].span(),
    };
    let hash = compute_snip12_hash(@oe, account.into(), 'SN_MAIN');
    // Owner_id = 0 (the primary STARK owner from the fixture).
    let owner_kp = StarkCurveKeyPairImpl::from_secret_key(OWNER_SECRET);
    let (r, s) = owner_kp.sign(hash).unwrap();
    let envelope: Array<felt252> = array![SIG_VERSION_V2_SNIP12, 0_u32.into(), 'STARK', r, s];

    cheat_oe_caller(account);
    let src9 = ISRC9_V2Dispatcher { contract_address: account };
    src9.execute_from_outside_v2(oe, envelope.span());

    let reads = IShhhReadsDispatcher { contract_address: account };
    let pending = reads.get_pending_recovery();
    assert(pending.is_active, 'recovery not active');
}
