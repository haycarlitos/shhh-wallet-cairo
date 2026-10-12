//! STARK_SNIP12 end to end on ShhhAccount: a Starknet browser wallet
//! (Bramble, Braavos, Ready) added to a live wallet as a co-owner or a
//! guardian, then signing OEs with what `wallet_signTypedData` returns.
//!
//! The wallet starts like a Chipi/Vela wallet (STARK primary only). The
//! new kind is registered through governance (propose + 48h + execute),
//! the same way it lands on an already-deployed wallet on mainnet.
//!
//! The signer account address is NOT deployed in these tests: the
//! verifier never calls it, so counterfactual Bramble/Ready accounts work.
//!
//! This file exercises:
//!   1. Registering the verifier class and a STARK_SNIP12 owner.
//!   2. Co-owner OE registers a session key (the "approve sessions" flow).
//!   3. A raw-hash signature from the same key is refused (wallets never
//!      produce it; it must not be a second way in).
//!   4. An approval signed for another wallet is refused.
//!   5. STARK_SNIP12 guardian initiates recovery through an OE.
//!   6. STARK_SNIP12 guardian cannot sign anything else.
//!   7. Without the verifier class, adding a STARK_SNIP12 owner fails.

use shhh_wallet::outside_execution::{
    ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution, SIG_VERSION_V2_SNIP12,
    compute_snip12_hash,
};
use shhh_wallet::owner_set::interface::{ROLE_GUARDIAN, ROLE_OWNER};
use shhh_wallet::recovery::component::RecoveryComponent::PendingRecovery;
use shhh_wallet::session_key::interface::SessionData;
use shhh_wallet::signer::interface::KIND_STARK_SNIP12;
use shhh_wallet::signer::stark_snip12::verifier::StarkSnip12Verifier::approval_hash;
use snforge_std::signature::SignerTrait;
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_caller_address, declare,
    start_cheat_block_timestamp_global, start_cheat_caller_address, start_cheat_chain_id_global,
    stop_cheat_caller_address,
};
use starknet::account::Call;
use starknet::{ClassHash, ContractAddress};

#[starknet::interface]
trait IShhhTest<TContractState> {
    fn propose_add_verifier_class(
        ref self: TContractState, proposer: u32, kind: felt252, class_hash: ClassHash,
    ) -> felt252;
    fn execute_add_verifier_class(
        ref self: TContractState, op_id: felt252, kind: felt252, class_hash: ClassHash,
    );
    fn get_verifier_class(self: @TContractState, kind: felt252) -> ClassHash;
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
    fn get_session_data(self: @TContractState, session_key: felt252) -> SessionData;
    fn get_pending_recovery(self: @TContractState) -> PendingRecovery;
}

const TIMELOCK_48H: u64 = 172_800;
const OWNER_SECRET: felt252 = 0xAAAA_AAAA_AAAA_BEEF;
// The external wallet's STARK key and its (undeployed) account address.
const BRAMBLE_SECRET: felt252 = 0xB4A3_B1E0_0000_0001;
const BRAMBLE_ACCOUNT: felt252 = 0x0b4a3b1e0000000000000000000000000000000000000000000000000000001;

fn bramble_pubkey() -> Array<felt252> {
    let kp = StarkCurveKeyPairImpl::from_secret_key(BRAMBLE_SECRET);
    array![kp.public_key, BRAMBLE_ACCOUNT]
}

fn deploy_wallet() -> ContractAddress {
    let stark_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let owner_kp = StarkCurveKeyPairImpl::from_secret_key(OWNER_SECRET);
    let calldata: Array<felt252> = array![
        'STARK', stark_class.into(), 1, owner_kp.public_key, 'primary',
    ];
    let (addr, _) = account_class.deploy(@calldata).unwrap();
    addr
}

/// Register STARK_SNIP12 and add the Bramble key with `role`, through the
/// owner's governance calls (self-call cheat stands in for the owner OE).
fn add_bramble(account: ContractAddress, role: felt252, label: felt252) -> u32 {
    let snip12_class = *declare("StarkSnip12Verifier").unwrap().contract_class().class_hash;
    let gov = IShhhTestDispatcher { contract_address: account };
    start_cheat_block_timestamp_global(1_000);
    start_cheat_caller_address(account, account);
    let verifier_op = gov.propose_add_verifier_class(0_u32, KIND_STARK_SNIP12, snip12_class);
    let owner_op = gov
        .propose_add_owner(0_u32, KIND_STARK_SNIP12, bramble_pubkey(), role, 1_u8, label);
    start_cheat_block_timestamp_global(1_000 + TIMELOCK_48H + 1);
    // Order matters: execute_add_owner validates the pubkey through the
    // verifier, so the class must be registered first.
    gov.execute_add_verifier_class(verifier_op, KIND_STARK_SNIP12, snip12_class);
    let owner_id = gov
        .execute_add_owner(owner_op, KIND_STARK_SNIP12, bramble_pubkey(), role, 1_u8, label);
    stop_cheat_caller_address(account);
    assert(gov.get_verifier_class(KIND_STARK_SNIP12) == snip12_class, 'verifier not set');
    owner_id
}

fn oe_for(call: Call, nonce: felt252) -> OutsideExecution {
    OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce,
        execute_after: 1_000_000,
        execute_before: 1_000_000 + 3_600,
        calls: array![call].span(),
    }
}

/// What `wallet_signTypedData` returns for the Approval typed data of
/// `oe` on `wallet`, wrapped in the V2_SNIP12 single-owner envelope.
fn bramble_envelope(
    oe: @OutsideExecution, account: ContractAddress, wallet: ContractAddress, owner_id: u32,
) -> Array<felt252> {
    let oe_hash = compute_snip12_hash(oe, account.into(), 'SN_MAIN');
    let h = approval_hash('SN_MAIN', wallet.into(), BRAMBLE_ACCOUNT, oe_hash);
    let kp = StarkCurveKeyPairImpl::from_secret_key(BRAMBLE_SECRET);
    let (r, s) = kp.sign(h).unwrap();
    array![SIG_VERSION_V2_SNIP12, owner_id.into(), KIND_STARK_SNIP12, r, s]
}

fn session_call(account: ContractAddress, session_key: felt252) -> Call {
    let calldata: Array<felt252> = array![
        session_key, 2_000_000, // valid_until
        10, // max_calls
        1, selector!("transfer"),
    ];
    Call {
        to: account, selector: selector!("add_or_update_session_key"), calldata: calldata.span(),
    }
}

fn cheat_oe(account: ContractAddress) {
    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_block_timestamp_global(1_000_001);
    cheat_caller_address(account, 'ANY_CALLER'.try_into().unwrap(), CheatSpan::TargetCalls(1));
}

// ==========================================================
// Co-owner approves a session
// ==========================================================

#[test]
fn test_bramble_co_owner_registers_session() {
    let account = deploy_wallet();
    let owner_id = add_bramble(account, ROLE_OWNER, 'bramble');
    let oe = oe_for(session_call(account, 0x5e55), 'b-sess-1');
    let envelope = bramble_envelope(@oe, account, account, owner_id);
    cheat_oe(account);
    ISRC9_V2Dispatcher { contract_address: account }.execute_from_outside_v2(oe, envelope.span());

    let session = IShhhTestDispatcher { contract_address: account }.get_session_data(0x5e55);
    assert(session.valid_until == 2_000_000, 'session not registered');
    assert(session.max_calls == 10, 'wrong max_calls');
}

#[test]
#[should_panic(expected: 'SHHH: signature invalid')]
fn test_raw_hash_signature_refused() {
    let account = deploy_wallet();
    let owner_id = add_bramble(account, ROLE_OWNER, 'bramble');
    let oe = oe_for(session_call(account, 0x5e55), 'b-sess-2');
    let oe_hash = compute_snip12_hash(@oe, account.into(), 'SN_MAIN');
    let kp = StarkCurveKeyPairImpl::from_secret_key(BRAMBLE_SECRET);
    let (r, s) = kp.sign(oe_hash).unwrap();
    let envelope = array![SIG_VERSION_V2_SNIP12, owner_id.into(), KIND_STARK_SNIP12, r, s];
    cheat_oe(account);
    ISRC9_V2Dispatcher { contract_address: account }.execute_from_outside_v2(oe, envelope.span());
}

#[test]
#[should_panic(expected: 'SHHH: signature invalid')]
fn test_approval_for_other_wallet_refused() {
    let account = deploy_wallet();
    let owner_id = add_bramble(account, ROLE_OWNER, 'bramble');
    let oe = oe_for(session_call(account, 0x5e55), 'b-sess-3');
    let other_wallet: ContractAddress = 0x0123.try_into().unwrap();
    let envelope = bramble_envelope(@oe, account, other_wallet, owner_id);
    cheat_oe(account);
    ISRC9_V2Dispatcher { contract_address: account }.execute_from_outside_v2(oe, envelope.span());
}

// ==========================================================
// Guardian: recovery only
// ==========================================================

fn initiate_recovery_call(account: ContractAddress, guardian_id: u32) -> Call {
    let calldata: Array<felt252> = array![
        guardian_id.into(), 'STARK', 1, 0xDEAD_BEEF, // new pubkey
        ROLE_OWNER, 1, 'recovered',
    ];
    Call { to: account, selector: selector!("initiate_recovery"), calldata: calldata.span() }
}

#[test]
fn test_bramble_guardian_initiates_recovery() {
    let account = deploy_wallet();
    let guardian_id = add_bramble(account, ROLE_GUARDIAN, 'bramble-guardian');
    let oe = oe_for(initiate_recovery_call(account, guardian_id), 'b-rec-1');
    let envelope = bramble_envelope(@oe, account, account, guardian_id);
    cheat_oe(account);
    ISRC9_V2Dispatcher { contract_address: account }.execute_from_outside_v2(oe, envelope.span());

    let pending = IShhhTestDispatcher { contract_address: account }.get_pending_recovery();
    assert(pending.is_active, 'recovery not active');
}

#[test]
#[should_panic(expected: 'SHHH: signer not an owner')]
fn test_bramble_guardian_cannot_register_session() {
    let account = deploy_wallet();
    let guardian_id = add_bramble(account, ROLE_GUARDIAN, 'bramble-guardian');
    let oe = oe_for(session_call(account, 0x5e55), 'b-rec-2');
    let envelope = bramble_envelope(@oe, account, account, guardian_id);
    cheat_oe(account);
    ISRC9_V2Dispatcher { contract_address: account }.execute_from_outside_v2(oe, envelope.span());
}

// ==========================================================
// The kind must be registered before an owner can use it
// ==========================================================

#[test]
#[should_panic(expected: 'SHHH: verifier missing')]
fn test_owner_needs_registered_verifier() {
    let account = deploy_wallet();
    let gov = IShhhTestDispatcher { contract_address: account };
    start_cheat_block_timestamp_global(1_000);
    start_cheat_caller_address(account, account);
    let op = gov
        .propose_add_owner(0_u32, KIND_STARK_SNIP12, bramble_pubkey(), ROLE_OWNER, 1_u8, 'b');
    start_cheat_block_timestamp_global(1_000 + TIMELOCK_48H + 1);
    gov.execute_add_owner(op, KIND_STARK_SNIP12, bramble_pubkey(), ROLE_OWNER, 1_u8, 'b');
}
