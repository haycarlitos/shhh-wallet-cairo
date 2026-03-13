use starknet::ContractAddress;
use starknet::account::Call;
use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait, start_cheat_block_timestamp_global,
    start_cheat_caller_address, start_cheat_chain_id_global,
};

use shhh_wallet::ed25519::interface::{IShhhWalletDispatcher, IShhhWalletDispatcherTrait};
use shhh_wallet::outside_execution::{
    OutsideExecution, ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait,
};

// Owner pubkey as LE u256 halves (matches garaga Py_twisted format).
const PUBKEY_LOW: felt252 = 0xfedcba0987654321;
const PUBKEY_HIGH: felt252 = 0x1234567890abcdef;

fn deploy_wallet() -> (ContractAddress, IShhhWalletDispatcher) {
    let contract = declare("ShhhWallet").unwrap().contract_class();
    let mut calldata: Array<felt252> = array![
        PUBKEY_LOW, PUBKEY_HIGH,
    ];
    let (addr, _) = contract.deploy(@calldata).unwrap();
    (addr, IShhhWalletDispatcher { contract_address: addr })
}

// ============================================================
// SNIP-9 (Outside Execution) Tests — pre-signature checks
// ============================================================

fn make_src9_dispatcher(addr: ContractAddress) -> ISRC9_V2Dispatcher {
    ISRC9_V2Dispatcher { contract_address: addr }
}

#[test]
fn test_initial_state() {
    let (_, dispatcher) = deploy_wallet();
    let (low, high) = dispatcher.get_owner();
    assert(low == PUBKEY_LOW, 'bad pubkey low');
    assert(high == PUBKEY_HIGH, 'bad pubkey high');
}

#[test]
fn test_nonce_availability() {
    let (addr, _) = deploy_wallet();
    let src9 = make_src9_dispatcher(addr);
    assert(src9.is_valid_outside_execution_nonce(42), 'nonce should be available');
}

#[test]
#[should_panic(expected: 'SRC9: too early')]
fn test_outside_execution_too_early() {
    let (addr, _) = deploy_wallet();
    start_cheat_block_timestamp_global(500);
    let src9 = make_src9_dispatcher(addr);

    let target: ContractAddress = 0xBEEF.try_into().unwrap();
    let oe = OutsideExecution {
        caller: 0.try_into().unwrap(),
        nonce: 1,
        execute_after: 600,
        execute_before: 2000,
        calls: array![
            Call { to: target, selector: selector!("get_owner"), calldata: array![].span() },
        ].span(),
    };
    src9.execute_from_outside_v2(oe, array![0x1, 0x2].span());
}

#[test]
#[should_panic(expected: 'SRC9: too late')]
fn test_outside_execution_too_late() {
    let (addr, _) = deploy_wallet();
    start_cheat_block_timestamp_global(500);
    let src9 = make_src9_dispatcher(addr);

    let target: ContractAddress = 0xBEEF.try_into().unwrap();
    let oe = OutsideExecution {
        caller: 0.try_into().unwrap(),
        nonce: 1,
        execute_after: 0,
        execute_before: 400,
        calls: array![
            Call { to: target, selector: selector!("get_owner"), calldata: array![].span() },
        ].span(),
    };
    src9.execute_from_outside_v2(oe, array![0x1, 0x2].span());
}

#[test]
#[should_panic(expected: 'SRC9: invalid caller')]
fn test_outside_execution_wrong_caller() {
    let (addr, _) = deploy_wallet();
    start_cheat_block_timestamp_global(500);

    let caller: ContractAddress = 0x5555.try_into().unwrap();
    start_cheat_caller_address(addr, caller);

    let src9 = make_src9_dispatcher(addr);
    let expected_caller: ContractAddress = 0x9999.try_into().unwrap();
    let target: ContractAddress = 0xBEEF.try_into().unwrap();
    let oe = OutsideExecution {
        caller: expected_caller,
        nonce: 1,
        execute_after: 0,
        execute_before: 2000,
        calls: array![
            Call { to: target, selector: selector!("get_owner"), calldata: array![].span() },
        ].span(),
    };
    src9.execute_from_outside_v2(oe, array![0x1, 0x2].span());
}

// ============================================================
// SNIP-9 Ed25519 signature tests — Garaga fixtures
// ============================================================
//
// Test keypair: seed = 0x42 (deterministic via tweetnacl)
// OE: caller=0, nonce=42, execute_after=0, execute_before=1000, calls=[]
// Contract address: 0xDEAD (deployed via deploy_at)
// Chain ID: 0x0 (snforge test VM default)

const TEST_PUBKEY_LOW: felt252 = 0xc70c79b5c7e03b55c87c26c4a23dbccc;
const TEST_PUBKEY_HIGH: felt252 = 0x8486eb169d67ccd2c36284529712125a;
const TEST_CONTRACT_ADDR: felt252 = 0xDEAD;

fn deploy_wallet_at_fixed_addr() -> (ContractAddress, ISRC9_V2Dispatcher) {
    let contract = declare("ShhhWallet").unwrap().contract_class();
    let calldata: Array<felt252> = array![
        TEST_PUBKEY_LOW, TEST_PUBKEY_HIGH,
    ];
    let target: ContractAddress = TEST_CONTRACT_ADDR.try_into().unwrap();
    let (addr, _) = contract.deploy_at(@calldata, target).unwrap();
    (addr, ISRC9_V2Dispatcher { contract_address: addr })
}

fn get_test_eddsa_signature() -> Array<felt252> {
    // Generated with: TEST_CHAIN_ID=0x0 node scripts/generate-test-fixtures.mjs
    // Chain ID: 0x0 (snforge test VM default)
    // Message: hex-encoded OE bytes (372 ASCII chars) — matches bytes_to_hex_ascii()
    // Garaga v1.0+: Py_twisted is NOT in the calldata (passed as separate param)
    array![
        0x2aa0643d318fefffd1344d2fb4983d04,
        0x87b897ee4318a4899b3b24431d27f9bc,
        0xcc448edec3ed33e79d1f351c0a6d1081,
        0x2315e42749967dfb0a55407b232a0e2,
        0x174,
        0x35, 0x33, 0x34, 0x38, 0x34, 0x38, 0x34, 0x38, 0x35, 0x66,
        0x34, 0x66, 0x34, 0x35, 0x35, 0x66, 0x35, 0x36, 0x33, 0x31,
        // chain_id = 0x0 → 64 hex zeros
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30,
        // contract_addr = 0xDEAD → 60 hex zeros + "dead"
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x64, 0x65, 0x61, 0x64,
        // caller = 0x0 → 64 hex zeros
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30,
        // nonce = 42 → 62 hex zeros + "2a"
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x32, 0x61,
        // execute_after = 0 → 16 hex zeros
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        // execute_before = 1000 → 12 hex zeros + "03e8"
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x33, 0x65, 0x38,
        // calls_hash (poseidon_hash_span([0]))
        0x30, 0x35, 0x34, 0x35, 0x64, 0x36, 0x66, 0x37, 0x64, 0x32,
        0x38, 0x61, 0x38, 0x61, 0x33, 0x39, 0x38, 0x65, 0x35, 0x34,
        0x33, 0x39, 0x34, 0x38, 0x62, 0x65, 0x35, 0x61, 0x30, 0x32,
        0x36, 0x61, 0x66, 0x36, 0x30, 0x63, 0x34, 0x64, 0x65, 0x61,
        0x34, 0x38, 0x32, 0x38, 0x36, 0x37, 0x61, 0x36, 0x65, 0x65,
        0x62, 0x32, 0x35, 0x32, 0x35, 0x62, 0x33, 0x35, 0x64, 0x31,
        0x65, 0x31, 0x65, 0x31,
        // Garaga hints
        0x14,
        0x33ae0a76a3e8d51ab47d2df0,
        0xa6226e53acf246d39c33b6d0,
        0x234944207ed17ba2,
        0x0,
        0xf7bb88a4cd5989fa894ba05f,
        0xc43d621c7426f6b83a55211a,
        0x5249f0dd391dc188,
        0x0,
        0x34af9e0f53397ec3a971e6398fe898e8,
        0x111471333fc2e3429978db47ed139cd77,
        0x1021c574b5a9b8f57a46c124,
        0xcacd6b46cdb079d5287e834a,
        0x5cb4c8a3ab224358,
        0x0,
        0x3b81b77affad9a27ba540b7e,
        0xd41caf40a11eb226ca90cb6d,
        0x54cf2dba8063075f,
        0x0,
        0x3cb44c112db991750ec9924d291b4601,
        0x7b25d750a28624bfed381982703778e,
        0xd2b06b6e79fdb29b15d36e12b2fee6e5,
        0x1da3fdd4a9c960059387e2e0736df536,
        0x20500f69b24fe710ca8f2dc5f4cce4db,
        0x2b4d984bd0a65b6bed0d5ab8cadc19c8,
    ]
}

#[test]
fn test_outside_execution_valid_ed25519() {
    let (_addr, src9) = deploy_wallet_at_fixed_addr();
    start_cheat_block_timestamp_global(500);
    start_cheat_chain_id_global(0);


    // Nonce should be available
    assert(src9.is_valid_outside_execution_nonce(42), 'nonce should be available');

    let oe = OutsideExecution {
        caller: 0.try_into().unwrap(), // ANY_CALLER
        nonce: 42,
        execute_after: 0,
        execute_before: 1000,
        calls: array![].span(), // empty calls
    };

    let signature = get_test_eddsa_signature();
    let results = src9.execute_from_outside_v2(oe, signature.span());
    assert(results.len() == 0, 'should have 0 results');

    // Nonce should now be used
    assert(!src9.is_valid_outside_execution_nonce(42), 'nonce should be used');
}

#[test]
#[should_panic(expected: 'SRC9: invalid signature')]
fn test_outside_execution_wrong_owner() {
    // Deploy with a DIFFERENT pubkey than what's in the signature.
    // Garaga v1.0+: Py comes from storage, so wrong pubkey → invalid signature.
    let contract = declare("ShhhWallet").unwrap().contract_class();
    let calldata: Array<felt252> = array![
        0xAAAA, 0xBBBB, // wrong pubkey
    ];
    let target: ContractAddress = TEST_CONTRACT_ADDR.try_into().unwrap();
    let (_, _) = contract.deploy_at(@calldata, target).unwrap();
    let src9 = ISRC9_V2Dispatcher { contract_address: target };

    start_cheat_block_timestamp_global(500);
    start_cheat_chain_id_global(0);

    let oe = OutsideExecution {
        caller: 0.try_into().unwrap(),
        nonce: 42,
        execute_after: 0,
        execute_before: 1000,
        calls: array![].span(),
    };

    // Signature was created by TEST_PUBKEY but contract stores 0xAAAA/0xBBBB
    let signature = get_test_eddsa_signature();
    src9.execute_from_outside_v2(oe, signature.span());
}

#[test]
#[should_panic(expected: 'SRC9: duplicate nonce')]
fn test_outside_execution_ed25519_replay() {
    let (_, src9) = deploy_wallet_at_fixed_addr();
    start_cheat_block_timestamp_global(500);
    start_cheat_chain_id_global(0);


    let oe1 = OutsideExecution {
        caller: 0.try_into().unwrap(),
        nonce: 42,
        execute_after: 0,
        execute_before: 1000,
        calls: array![].span(),
    };
    let sig1 = get_test_eddsa_signature();
    src9.execute_from_outside_v2(oe1, sig1.span());

    // Replay with same nonce — should fail
    let oe2 = OutsideExecution {
        caller: 0.try_into().unwrap(),
        nonce: 42,
        execute_after: 0,
        execute_before: 1000,
        calls: array![].span(),
    };
    let sig2 = get_test_eddsa_signature();
    src9.execute_from_outside_v2(oe2, sig2.span());
}

// Verify Poseidon hash compatibility with starknet.js
#[test]
fn test_poseidon_hash_compatibility() {
    let result = core::poseidon::poseidon_hash_span(array![0].span());
    assert(
        result == 0x545d6f7d28a8a398e543948be5a026af60c4dea482867a6eeb2525b35d1e1e1,
        'poseidon mismatch',
    );
}
