//! V8 ShhhAccount mirror of the audit-regression suite.
//!
//! The Phase 0 tests in `tests/audit_2026_04_20.cairo` target V7
//! `ShhhWallet` (the audited mainnet contract). V8's `ShhhAccount`
//! implements the same guards in different code paths — the mutation
//! harness (scripts/mutation-test.sh) surfaced that those V8 paths
//! weren't covered. These tests close that gap.

use shhh_wallet::outside_execution::{ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_caller_address,
};
use starknet::ContractAddress;
use starknet::account::Call;

#[starknet::interface]
trait IAccountExec<TContractState> {
    fn __execute__(ref self: TContractState, calls: Array<Call>) -> Array<Span<felt252>>;
}

fn deploy_account() -> ContractAddress {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, 0xAAAA, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();
    addr
}

// ============================================================
// C-1 on V8 — external __execute__ from a non-zero, non-self caller
// must revert.
// ============================================================

#[test]
#[should_panic(expected: 'C1: unauthorized caller')]
fn test_v8_c1_external_execute_reverts() {
    let addr = deploy_account();
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    let dispatcher = IAccountExecDispatcher { contract_address: addr };
    let target: ContractAddress = 0xBEEF.try_into().unwrap();
    dispatcher
        .__execute__(
            array![Call { to: target, selector: selector!("noop"), calldata: array![].span() }],
        );
}

// ============================================================
// M-1 on V8 — OE with caller == 0 must revert.
// ============================================================

#[test]
#[should_panic(expected: 'M1: caller=0 rejected')]
fn test_v8_m1_caller_zero_rejected() {
    let addr = deploy_account();
    start_cheat_block_timestamp_global(500);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    let oe = OutsideExecution {
        caller: 0.try_into().unwrap(),
        nonce: 1,
        execute_after: 0,
        execute_before: 1000,
        calls: array![].span(),
    };
    src9.execute_from_outside_v2(oe, array![0, 0, 0].span());
}

// ============================================================
// M-2 on V8 — ANY_CALLER validity window cap.
// ============================================================

#[test]
#[should_panic(expected: 'M2: window too long')]
fn test_v8_m2_window_cap() {
    let addr = deploy_account();
    start_cheat_block_timestamp_global(500);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    // MAX_ANY_CALLER_VALIDITY_SECONDS = 7200.
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 2,
        execute_after: 0,
        execute_before: 7201, // one second past the cap
        calls: array![].span(),
    };
    src9.execute_from_outside_v2(oe, array![0, 0, 0].span());
}

// ============================================================
// M-3 on V8 — signature length > MAX_SIGNATURE_FELTS fires early.
// ============================================================

#[test]
#[should_panic(expected: 'M3: signature too long')]
fn test_v8_m3_signature_too_long() {
    let addr = deploy_account();
    start_cheat_block_timestamp_global(500);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 3,
        execute_after: 0,
        execute_before: 1000,
        calls: array![].span(),
    };
    let mut sig: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < 1025_u32 {
        sig.append(0);
        i += 1;
    }
    src9.execute_from_outside_v2(oe, sig.span());
}
// ============================================================
// Nonce replay on V8 — handled by the Phase 11 STARK-signed e2e test.
//
// Within a single failing tx the nonce write is rolled back with the
// rest of the state, so a "consume then fail" scenario is not
// expressible in snforge unit tests. A fixture-driven OE that
// succeeds on first submission and reverts with 'SRC9: duplicate
// nonce' on the second is the correct covering test and lands
// alongside the Phase 11 STARK-session-signed fixture.
// ============================================================

