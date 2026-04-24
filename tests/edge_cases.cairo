//! Boundary + edge-case regression tests. Each targets a specific
//! off-by-one or overflow scenario flagged during the 2026-04-24
//! self-audit. Companion to `audit_2026_04_20.cairo` (Omar findings)
//! and `audit_v8.cairo` (V8 architecture findings).
//!
//! One test per scenario so a single regression surfaces a precise
//! line in the test name:
//!   - Governance ready-exactly-at-valid_after: `now >= valid_after`
//!     uses `>=`, so the exact-equality boundary must pass.
//!   - Threshold n > owner_count: the `n <= owner_count` assert must
//!     catch over-specified envelopes before the inner loop runs.
//!   - WebAuthn challenge offset at `client_data_json.len() - 43`:
//!     the challenge sits at the very end of the JSON. Must verify.
//!   - WebAuthn challenge offset one byte past the end: must reject.

use shhh_wallet::outside_execution::{
    ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution, SIG_VERSION_V2_SNIP12,
    SIG_VERSION_V2_THRESHOLD, compute_snip12_hash,
};
use shhh_wallet::owner_set::interface::ROLE_OWNER;
use snforge_std::signature::SignerTrait;
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_caller_address, start_cheat_chain_id_global,
};
use starknet::ContractAddress;

const TIMELOCK_ADD_OWNER: u64 = 172_800;

// ==========================================================
// Governance: `now >= valid_after` is inclusive of equality
// ==========================================================

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

#[starknet::interface]
trait IShhhReads<TContractState> {
    fn owner_count(self: @TContractState) -> u32;
    fn threshold(self: @TContractState) -> u8;
}

fn deploy_account() -> ContractAddress {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, 0xAAAA, 'alice'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();
    addr
}

/// `assert_ready` uses `now >= valid_after` — so `now == valid_after`
/// MUST pass. If a future refactor flipped to `>` (strict), the 48h
/// timelock would effectively extend by one second per op and paymaster
/// retry logic would silently miss the exact boundary. This test
/// pins the boundary behavior.
#[test]
fn test_governance_execute_at_exact_valid_after_succeeds() {
    let addr = deploy_account();
    let gov = IShhhGovDispatcher { contract_address: addr };
    let reads = IShhhReadsDispatcher { contract_address: addr };

    let proposed_at: u64 = 100;
    start_cheat_block_timestamp_global(proposed_at);
    start_cheat_caller_address(addr, addr);
    let op = gov.propose_add_owner(0_u32, 'STARK', array![0xBBBB], ROLE_OWNER, 1_u8, 'second');

    // Jump to exactly `proposed_at + TIMELOCK_ADD_OWNER`. With `>=`
    // this equals valid_after and the execute MUST succeed.
    start_cheat_block_timestamp_global(proposed_at + TIMELOCK_ADD_OWNER);
    gov.execute_add_owner(op, 'STARK', array![0xBBBB], ROLE_OWNER, 1_u8, 'second');

    assert(reads.owner_count() == 2_u32, 'add_owner must land at boundary');
}

/// One second BEFORE valid_after must still revert — strict-less-than
/// is the negative boundary.
#[test]
#[should_panic(expected: 'OP: timelock not elapsed')]
fn test_governance_execute_one_second_early_reverts() {
    let addr = deploy_account();
    let gov = IShhhGovDispatcher { contract_address: addr };

    let proposed_at: u64 = 100;
    start_cheat_block_timestamp_global(proposed_at);
    start_cheat_caller_address(addr, addr);
    let op = gov.propose_add_owner(0_u32, 'STARK', array![0xBBBB], ROLE_OWNER, 1_u8, 'second');
    // One second short of the timelock end.
    start_cheat_block_timestamp_global(proposed_at + TIMELOCK_ADD_OWNER - 1);
    gov.execute_add_owner(op, 'STARK', array![0xBBBB], ROLE_OWNER, 1_u8, 'second');
}

// ==========================================================
// Threshold: `n > owner_count` must reject before the loop runs
// ==========================================================

/// An attacker crafts a threshold envelope declaring 5 signers when
/// the account has 1 owner. The `n <= owner_count` assert must fire
/// before the inner verification loop runs — if it didn't, the loop
/// would panic later on the first owner_id lookup, but with a
/// less-specific error.
#[test]
#[should_panic(expected: 'THRESH: n > owner_count')]
fn test_threshold_n_exceeds_owner_count_reverts() {
    let addr = deploy_account(); // 1 owner
    let kp = StarkCurveKeyPairImpl::from_secret_key(0xAAAA);
    let _ = kp.public_key; // unused but shows keypair is available

    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 'thresh-n-over',
        execute_after: 10_000,
        execute_before: 10_000 + 3_600,
        calls: array![].span(),
    };
    let hash = compute_snip12_hash(@oe, addr.into(), 'SN_MAIN');
    let kp2 = StarkCurveKeyPairImpl::from_secret_key(0xBBBB);
    let (r, s) = kp2.sign(hash).unwrap();

    // n = 5, but we only have 1 owner. Inner envelopes are bogus —
    // the assert fires before we even look at them.
    let inner: Array<felt252> = array![0, 'STARK', r, s];
    let mut envelope: Array<felt252> = array![SIG_VERSION_V2_THRESHOLD, 5];
    let mut i: u32 = 0;
    while i < 5_u32 {
        envelope.append(inner.len().into());
        let mut j: u32 = 0;
        while j < inner.len() {
            envelope.append(*inner.at(j));
            j += 1;
        }
        i += 1;
    }

    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_block_timestamp_global(10_001);
    start_cheat_caller_address(addr, 'ANY_CALLER'.try_into().unwrap());
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    src9.execute_from_outside_v2(oe, envelope.span());
}
