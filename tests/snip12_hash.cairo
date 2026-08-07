//! SNIP-12 typed-data hash determinism tests for `OutsideExecution`.
//!
//! These verify the `compute_snip12_hash` function in
//! `src/outside_execution.cairo` is:
//!   1. Deterministic (same input → same output)
//!   2. Sensitive to every field that affects authorization
//!
//! Cross-language vector tests (Cairo <-> TypeScript) live at
//! `scripts/ts/snip12-hash.test.ts` and use the same fixtures encoded
//! below — keep both in sync when you change encoding.

use shhh_wallet::outside_execution::{OutsideExecution, compute_snip12_hash};
use starknet::ContractAddress;
use starknet::account::Call;

fn addr(v: felt252) -> ContractAddress {
    v.try_into().unwrap()
}

fn make_oe_minimal() -> OutsideExecution {
    OutsideExecution {
        caller: addr('ANY_CALLER'),
        nonce: 1,
        execute_after: 0,
        execute_before: 1000,
        calls: array![].span(),
    }
}

fn make_oe_with_one_call() -> OutsideExecution {
    OutsideExecution {
        caller: addr('ANY_CALLER'),
        nonce: 2,
        execute_after: 0,
        execute_before: 1000,
        calls: array![
            Call {
                to: addr(0xBEEF), selector: selector!("foo"), calldata: array![0xAA, 0xBB].span(),
            },
        ]
            .span(),
    }
}

fn make_oe_with_two_calls() -> OutsideExecution {
    OutsideExecution {
        caller: addr('ANY_CALLER'),
        nonce: 3,
        execute_after: 0,
        execute_before: 1000,
        calls: array![
            Call {
                to: addr(0xBEEF), selector: selector!("foo"), calldata: array![0xAA, 0xBB].span(),
            },
            Call { to: addr(0xFEED), selector: selector!("bar"), calldata: array![0xCC].span() },
        ]
            .span(),
    }
}

#[test]
fn test_snip12_hash_is_deterministic() {
    let oe1 = make_oe_minimal();
    let oe2 = make_oe_minimal();
    let h1 = compute_snip12_hash(@oe1, addr(0x1234), 'SN_MAIN');
    let h2 = compute_snip12_hash(@oe2, addr(0x1234), 'SN_MAIN');
    assert(h1 == h2, 'SNIP-12: non-deterministic');
}

#[test]
fn test_snip12_hash_is_call_count_sensitive() {
    let oe_empty = make_oe_minimal();
    let oe_one = make_oe_with_one_call();
    let h_empty = compute_snip12_hash(@oe_empty, addr(0x1234), 'SN_MAIN');
    let h_one = compute_snip12_hash(@oe_one, addr(0x1234), 'SN_MAIN');
    assert(h_empty != h_one, 'SNIP-12: call count collision');

    let oe_two = make_oe_with_two_calls();
    let h_two = compute_snip12_hash(@oe_two, addr(0x1234), 'SN_MAIN');
    assert(h_one != h_two, 'SNIP-12: 1 vs 2 calls collide');
    assert(h_empty != h_two, 'SNIP-12: 0 vs 2 calls collide');
}

#[test]
fn test_snip12_hash_is_calldata_sensitive() {
    let oe_a = OutsideExecution {
        caller: addr('ANY_CALLER'),
        nonce: 10,
        execute_after: 0,
        execute_before: 1000,
        calls: array![
            Call {
                to: addr(0xBEEF), selector: selector!("foo"), calldata: array![0xAA, 0xBB].span(),
            },
        ]
            .span(),
    };
    let oe_b = OutsideExecution {
        caller: addr('ANY_CALLER'),
        nonce: 10,
        execute_after: 0,
        execute_before: 1000,
        calls: array![
            Call {
                to: addr(0xBEEF),
                selector: selector!("foo"),
                calldata: array![0xAA, 0xCC].span() // last byte changed
            },
        ]
            .span(),
    };
    let h_a = compute_snip12_hash(@oe_a, addr(0x1234), 'SN_MAIN');
    let h_b = compute_snip12_hash(@oe_b, addr(0x1234), 'SN_MAIN');
    assert(h_a != h_b, 'SNIP-12: calldata collision');
}

/// Cross-language determinism vector — MUST match the output of
/// `scripts/ts/snip12-hash.ts` when run on the same fixture (minimal
/// OE, caller='ANY_CALLER', nonce=1, execute_after=0, execute_before=1000,
/// calls=[], contract_address=0x1234, chain_id='SN_MAIN').
///
/// This guards against Cairo ↔ TypeScript drift in the hash derivation
/// so paymasters can be written in either language and agree on hashes.
#[test]
fn test_snip12_hash_matches_ts_vector() {
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 1,
        execute_after: 0,
        execute_before: 1000,
        calls: array![].span(),
    };
    let h = compute_snip12_hash(@oe, 0x1234.try_into().unwrap(), 'SN_MAIN');
    // Output from `tsx scripts/ts/snip12-hash.ts` (see docs/v8-phase-1.md)
    let expected: felt252 = 0x5bcd634ce46c7234bd7a4b0959c3c5edeed7f569dcfb7b33e23d7e2197a2a2f;
    assert(h == expected, 'SNIP-12: TS vector mismatch');
}

#[test]
fn test_snip12_hash_is_context_sensitive() {
    // Same OE, different chain_id and contract_address — hash MUST differ
    // so cross-chain and cross-account replays are impossible.
    let oe = make_oe_with_one_call();
    let h_base = compute_snip12_hash(@oe, addr(0x1234), 'SN_MAIN');
    let h_chain = compute_snip12_hash(@oe, addr(0x1234), 'SN_SEPOLIA');
    let h_addr = compute_snip12_hash(@oe, addr(0x5678), 'SN_MAIN');
    let h_nonce = compute_snip12_hash(
        @OutsideExecution {
            caller: oe.caller,
            nonce: oe.nonce + 1, // bump nonce
            execute_after: oe.execute_after,
            execute_before: oe.execute_before,
            calls: oe.calls,
        },
        addr(0x1234),
        'SN_MAIN',
    );
    assert(h_base != h_chain, 'SNIP-12: chain_id collision');
    assert(h_base != h_addr, 'SNIP-12: addr collision');
    assert(h_base != h_nonce, 'SNIP-12: nonce collision');
}
