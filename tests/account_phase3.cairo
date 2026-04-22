//! Phase 3 end-to-end test — ShhhAccount dispatcher + library_call to
//! Ed25519Verifier + atomic multicall.
//!
//! Flow:
//!   1. Declare Ed25519Verifier → class hash
//!   2. Declare + deploy ShhhAccount at the fixed address used by the
//!      fixture, passing the verifier's class hash
//!   3. Declare + deploy Target at the fixed target address
//!   4. Cheat chain_id + block timestamp to match the off-chain fixture
//!   5. Build OutsideExecution from fixture values
//!   6. Submit execute_from_outside_v2 with the pre-signed envelope
//!   7. Assert Target.get_value() == 0xCAFE (inner call completed)

use shhh_wallet::outside_execution::{ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution};
use shhh_wallet::test_helpers::target::{ITargetDispatcher, ITargetDispatcherTrait};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_chain_id_global,
};
use starknet::ContractAddress;
use starknet::account::Call;
use super::account_phase3_fixture::{
    phase3_account_addr, phase3_chain_id, phase3_execute_after, phase3_execute_before, phase3_nonce,
    phase3_pubkey_high, phase3_pubkey_low, phase3_set_value_arg, phase3_set_value_selector,
    phase3_signature_envelope, phase3_target_addr,
};

fn addr(v: felt252) -> ContractAddress {
    v.try_into().unwrap()
}

#[test]
fn test_phase3_e2e_ed25519_account_executes_target_call() {
    // 1. Declare the Ed25519 verifier; remember its class hash.
    let verifier_class = *declare("Ed25519Verifier").unwrap().contract_class().class_hash;

    // 2. Declare and deploy the account at the fixed fixture address.
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let mut account_calldata: Array<felt252> = array![
        'ED25519', // primary_kind
        verifier_class.into(), // primary_verifier class hash
        2, // pubkey length
        phase3_pubkey_low(), phase3_pubkey_high(), 'phantom-test' // label
    ];
    let account_addr: ContractAddress = addr(phase3_account_addr());
    account_class.deploy_at(@account_calldata, account_addr).unwrap();

    // 3. Declare + deploy Target.
    let target_class = declare("Target").unwrap().contract_class();
    let target_addr: ContractAddress = addr(phase3_target_addr());
    target_class.deploy_at(@array![], target_addr).unwrap();

    // 4. Sanity-check target starts at zero.
    let target = ITargetDispatcher { contract_address: target_addr };
    assert(target.get_value() == 0, 'target not zero');

    // 5. Cheat execution context to match the fixture.
    start_cheat_chain_id_global(phase3_chain_id());
    // Timestamp must land inside (execute_after, execute_before).
    start_cheat_block_timestamp_global(phase3_execute_after() + 1);

    // 6. Submit execute_from_outside_v2 with the pre-signed envelope.
    let src9 = ISRC9_V2Dispatcher { contract_address: account_addr };
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: phase3_nonce(),
        execute_after: phase3_execute_after(),
        execute_before: phase3_execute_before(),
        calls: array![
            Call {
                to: target_addr,
                selector: phase3_set_value_selector(),
                calldata: array![phase3_set_value_arg()].span(),
            },
        ]
            .span(),
    };
    let envelope = phase3_signature_envelope();
    let results = src9.execute_from_outside_v2(oe, envelope.span());

    // 7. Assert multicall executed.
    assert(results.len() == 1, 'multicall size wrong');
    assert(target.get_value() == phase3_set_value_arg(), 'target not updated');
}
