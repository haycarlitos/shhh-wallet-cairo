//! Threshold-signature envelope tests.
//!
//! Covers the `SIG_VERSION_V2_THRESHOLD` path in `execute_from_outside_v2`:
//! the account wraps N inner single-owner envelopes over the same
//! SNIP-12 hash, rejects duplicate `owner_id`s, and requires
//! `sum(weight_i) >= owner_set.threshold`.
//!
//! All fixtures use the STARK verifier because snforge_std ships a
//! STARK-curve signer out of the box — we don't need to pre-generate
//! off-chain vectors the way Ed25519 / secp256k1 do.
//!
//! Flow per test:
//!   1. Deploy ShhhAccount with STARK primary owner (keypair A).
//!   2. Via governance (propose+execute with cheat_caller_address = addr),
//!      add STARK owner B and set threshold = 2.
//!   3. Construct an OE that calls Target::set_value.
//!   4. Compute the SNIP-12 hash on the Cairo side.
//!   5. Sign with both keypairs; build the threshold envelope.
//!   6. Submit and assert.

use shhh_wallet::outside_execution::{
    ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution, SIG_VERSION_V2_SNIP12,
    SIG_VERSION_V2_THRESHOLD, compute_snip12_hash,
};
use shhh_wallet::owner_set::interface::ROLE_OWNER;
use shhh_wallet::test_helpers::target::{ITargetDispatcher, ITargetDispatcherTrait};
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::signature::{KeyPair, SignerTrait};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_caller_address, start_cheat_chain_id_global,
};
use starknet::ContractAddress;
use starknet::account::Call;

const TIMELOCK_ADD_OWNER: u64 = 172_800;
const TIMELOCK_SET_THRESHOLD: u64 = 172_800;

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
}

// --------------------------------------------------------------
// Fixture setup
// --------------------------------------------------------------

fn deploy_two_owner_threshold_account() -> (
    ContractAddress, ContractAddress, KeyPair<felt252, felt252>, KeyPair<felt252, felt252>,
) {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let target_class = declare("Target").unwrap().contract_class();

    // Deterministic keys — snforge `from_secret_key` reuses the same
    // arithmetic as mainnet, so these are real STARK pubkeys.
    let kp_a = StarkCurveKeyPairImpl::from_secret_key(0x1111_u256.try_into().unwrap());
    let kp_b = StarkCurveKeyPairImpl::from_secret_key(0x2222_u256.try_into().unwrap());

    let account_calldata: Array<felt252> = array![
        'STARK', verifier_class.into(), 1, kp_a.public_key, 'alice',
    ];
    let (account_addr, _) = account_class.deploy(@account_calldata).unwrap();
    let (target_addr, _) = target_class.deploy(@array![]).unwrap();

    // Add second owner + raise threshold to 2 via the timelocked flow.
    start_cheat_block_timestamp_global(1_000);
    start_cheat_caller_address(account_addr, account_addr);
    let gov = IShhhGovDispatcher { contract_address: account_addr };
    let op_add = gov
        .propose_add_owner(0_u32, 'STARK', array![kp_b.public_key], ROLE_OWNER, 1_u8, 'bob');
    let op_thr = gov.propose_set_threshold(0_u32, 2_u8);

    start_cheat_block_timestamp_global(1_000 + TIMELOCK_ADD_OWNER + 1);
    gov.execute_add_owner(op_add, 'STARK', array![kp_b.public_key], ROLE_OWNER, 1_u8, 'bob');
    // Threshold op uses the same 48h window; both are ready now.
    let _ = TIMELOCK_SET_THRESHOLD;
    gov.execute_set_threshold(op_thr, 2_u8);

    (account_addr, target_addr, kp_a, kp_b)
}

fn build_oe_and_hash(
    account_addr: ContractAddress, target_addr: ContractAddress, nonce: felt252,
) -> (OutsideExecution, felt252) {
    let selector = selector!("set_value");
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce,
        // ANY_CALLER window capped at 7200s (audit M-2).
        execute_after: 10_000,
        execute_before: 10_000 + 3_600,
        calls: array![Call { to: target_addr, selector, calldata: array![0xCAFE].span() }].span(),
    };
    let chain_id: felt252 = 'SN_MAIN';
    let hash = compute_snip12_hash(@oe, account_addr.into(), chain_id);
    (oe, hash)
}

fn inner_envelope(owner_id: u32, kp: KeyPair<felt252, felt252>, hash: felt252) -> Array<felt252> {
    let (r, s) = kp.sign(hash).unwrap();
    // Inner envelope shape expected by `_verify_sub_envelope`:
    //   [owner_id, kind_tag, r, s]
    array![owner_id.into(), 'STARK', r, s]
}

/// Wraps N inner envelopes into the threshold outer envelope:
///   [V2_THRESHOLD, n, env_1_len, env_1..., env_2_len, env_2..., ...]
fn build_threshold_envelope(inners: Array<Array<felt252>>) -> Array<felt252> {
    let n = inners.len();
    let mut out: Array<felt252> = array![SIG_VERSION_V2_THRESHOLD, n.into()];
    let mut i: u32 = 0;
    while i < n {
        let env = inners.at(i);
        out.append(env.len().into());
        let mut j: u32 = 0;
        while j < env.len() {
            out.append(*env.at(j));
            j += 1;
        }
        i += 1;
    }
    out
}

fn cheat_for_oe(account_addr: ContractAddress) {
    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_block_timestamp_global(10_001);
    // ANY_CALLER path — the caller address check in the account compares
    // `get_caller_address() == outside_execution.caller`, which for
    // `'ANY_CALLER'` is short-circuited by the window cap check.
    start_cheat_caller_address(account_addr, 'ANY_CALLER'.try_into().unwrap());
}

// --------------------------------------------------------------
// Happy path
// --------------------------------------------------------------

#[test]
fn test_threshold_2_of_2_happy_path() {
    let (addr, target, kp_a, kp_b) = deploy_two_owner_threshold_account();
    let (oe, hash) = build_oe_and_hash(addr, target, 'nonce-happy');
    let envelope = build_threshold_envelope(
        array![inner_envelope(0, kp_a, hash), inner_envelope(1, kp_b, hash)],
    );

    cheat_for_oe(addr);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    let results = src9.execute_from_outside_v2(oe, envelope.span());
    assert(results.len() == 1, 'multicall size');

    let t = ITargetDispatcher { contract_address: target };
    assert(t.get_value() == 0xCAFE, 'target not updated');
}

// --------------------------------------------------------------
// Below threshold — single valid envelope under threshold=2
// --------------------------------------------------------------

#[test]
#[should_panic(expected: 'THRESH: need >= 2 envelopes')]
fn test_threshold_below_count_reverts() {
    let (addr, target, kp_a, _kp_b) = deploy_two_owner_threshold_account();
    let (oe, hash) = build_oe_and_hash(addr, target, 'nonce-n1');
    // n = 1 at the outer layer is rejected by the `n >= 2` gate.
    let inner = inner_envelope(0, kp_a, hash);
    let mut envelope: Array<felt252> = array![SIG_VERSION_V2_THRESHOLD, 1];
    envelope.append(inner.len().into());
    let mut j: u32 = 0;
    while j < inner.len() {
        envelope.append(*inner.at(j));
        j += 1;
    }
    cheat_for_oe(addr);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    src9.execute_from_outside_v2(oe, envelope.span());
}

// --------------------------------------------------------------
// Duplicate owner_id — same signer repeated must revert
// --------------------------------------------------------------

#[test]
#[should_panic(expected: 'THRESH: duplicate owner_id')]
fn test_threshold_duplicate_owner_reverts() {
    let (addr, target, kp_a, _kp_b) = deploy_two_owner_threshold_account();
    let (oe, hash) = build_oe_and_hash(addr, target, 'nonce-dup');
    // Two signatures from owner_0 would double-count weight if not
    // guarded — the account tracks seen owner_ids to reject.
    let envelope = build_threshold_envelope(
        array![inner_envelope(0, kp_a, hash), inner_envelope(0, kp_a, hash)],
    );
    cheat_for_oe(addr);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    src9.execute_from_outside_v2(oe, envelope.span());
}

// --------------------------------------------------------------
// One bad inner signature — the whole OE reverts
// --------------------------------------------------------------

#[test]
#[should_panic(expected: 'THRESH: inner sig invalid')]
fn test_threshold_one_bad_inner_reverts() {
    let (addr, target, kp_a, kp_b) = deploy_two_owner_threshold_account();
    let (oe, hash) = build_oe_and_hash(addr, target, 'nonce-bad');
    // First envelope valid, second tampered: claim kp_b as owner 1 but
    // sign with kp_a (wrong key for that owner).
    let bad_sig = kp_a.sign(hash).unwrap();
    let (r, s) = bad_sig;
    let bad_inner: Array<felt252> = array![1, 'STARK', r, s];
    let envelope = build_threshold_envelope(array![inner_envelope(0, kp_a, hash), bad_inner]);
    cheat_for_oe(addr);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    src9.execute_from_outside_v2(oe, envelope.span());
}

// --------------------------------------------------------------
// Trailing bytes on the outer frame
// --------------------------------------------------------------

#[test]
#[should_panic(expected: 'THRESH: trailing bytes')]
fn test_threshold_trailing_bytes_reverts() {
    let (addr, target, kp_a, kp_b) = deploy_two_owner_threshold_account();
    let (oe, hash) = build_oe_and_hash(addr, target, 'nonce-tail');
    let mut envelope = build_threshold_envelope(
        array![inner_envelope(0, kp_a, hash), inner_envelope(1, kp_b, hash)],
    );
    envelope.append(0xDEAD); // junk appended after the last inner envelope
    cheat_for_oe(addr);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    src9.execute_from_outside_v2(oe, envelope.span());
}

// --------------------------------------------------------------
// V2_SNIP12 single-owner path still works after the refactor
// --------------------------------------------------------------

#[test]
fn test_single_owner_path_still_works_after_refactor() {
    // Deploy a fresh single-owner account so threshold = 1 — the
    // V2_SNIP12 branch must continue to verify with one signer only.
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let target_class = declare("Target").unwrap().contract_class();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0xBEEF_u256.try_into().unwrap());

    let calldata: Array<felt252> = array![
        'STARK', verifier_class.into(), 1, kp.public_key, 'alice',
    ];
    let (account_addr, _) = account_class.deploy(@calldata).unwrap();
    let (target_addr, _) = target_class.deploy(@array![]).unwrap();

    let (oe, hash) = build_oe_and_hash(account_addr, target_addr, 'nonce-single');
    let (r, s) = kp.sign(hash).unwrap();
    let envelope: Array<felt252> = array![SIG_VERSION_V2_SNIP12, 0, 'STARK', r, s];
    cheat_for_oe(account_addr);
    let src9 = ISRC9_V2Dispatcher { contract_address: account_addr };
    let results = src9.execute_from_outside_v2(oe, envelope.span());
    assert(results.len() == 1, 'multicall size');
    let t = ITargetDispatcher { contract_address: target_addr };
    assert(t.get_value() == 0xCAFE, 'target not updated');
}
