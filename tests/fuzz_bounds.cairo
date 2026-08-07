//! Phase 10 — Fuzz: M-3 bounds.
//!
//! OE `calls.len()` above MAX_CALLS (16) MUST revert with
//! `M3: too many calls` — regardless of what specific call sequence is
//! used. The fuzzer picks a random count above the cap and confirms the
//! guard fires before any hashing / signature work.

use shhh_wallet::outside_execution::{ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
};
use starknet::ContractAddress;
use starknet::account::Call;

const MAX_CALLS: u32 = 16;

fn deploy_account() -> ContractAddress {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, 0xAAAA, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();
    addr
}

/// Any call count strictly above MAX_CALLS MUST be rejected before
/// hashing / signature work happens. Fuzzer picks 17..=256 calls.
#[test]
#[fuzzer]
#[should_panic(expected: 'M3: too many calls')]
fn fuzz_calls_above_max_rejected(raw_count: felt252) {
    let raw: u128 = raw_count.try_into().unwrap_or(0_u128);
    // Clamp to [MAX_CALLS + 1, MAX_CALLS + 240].
    let n_u128: u128 = (raw % 240_u128) + (MAX_CALLS + 1).into();
    let n: u32 = n_u128.try_into().unwrap();

    let addr = deploy_account();
    start_cheat_block_timestamp_global(500);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };

    let target: ContractAddress = 0xBEEF.try_into().unwrap();
    let mut calls: Array<Call> = array![];
    let mut i: u32 = 0;
    while i < n {
        calls.append(Call { to: target, selector: selector!("noop"), calldata: array![].span() });
        i += 1;
    }

    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 1,
        execute_after: 0,
        execute_before: 1000,
        calls: calls.span(),
    };
    // Signature shape irrelevant — M-3 fires first.
    src9.execute_from_outside_v2(oe, array![0, 0, 0, 0, 0].span());
}

/// Signatures longer than MAX_SIGNATURE_FELTS also fire early.
#[test]
#[fuzzer]
#[should_panic(expected: 'M3: signature too long')]
fn fuzz_signature_above_max_rejected(raw_len: felt252) {
    let raw: u128 = raw_len.try_into().unwrap_or(0_u128);
    // Clamp to [1025, 1025+512] — always over the 1024 cap.
    let n_u128: u128 = (raw % 512_u128) + 1025_u128;
    let n: u32 = n_u128.try_into().unwrap();

    let addr = deploy_account();
    start_cheat_block_timestamp_global(500);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };

    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 1,
        execute_after: 0,
        execute_before: 1000,
        calls: array![].span(),
    };
    let mut sig: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n {
        sig.append(0);
        i += 1;
    }
    src9.execute_from_outside_v2(oe, sig.span());
}
