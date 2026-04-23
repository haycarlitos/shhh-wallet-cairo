//! Phase 8 — secp256k1 verifier class tests.
//!
//! Covers:
//!   - Kind tag introspection
//!   - Envelope / pubkey shape guards
//!   - Happy-path verification from an ethers.js fixture
//!   - Wrong-key rejection
//!   - y_parity flip → invalid
//!
//! Deeper malleability + EIP-191 tests land alongside the
//! EIP191Secp256k1Verifier variant in a follow-up.

use shhh_wallet::signer::interface::{ISignerDispatcher, ISignerDispatcherTrait, KIND_SECP256K1};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use super::signer_secp256k1_fixture::{
    secp256k1_message_hash, secp256k1_pubkey, secp256k1_signature,
};

fn deploy_verifier() -> ContractAddress {
    let class = declare("Secp256k1Verifier").unwrap().contract_class();
    let (addr, _) = class.deploy(@array![]).unwrap();
    addr
}

fn dispatcher() -> ISignerDispatcher {
    ISignerDispatcher { contract_address: deploy_verifier() }
}

// ============================================================
// Kind tag
// ============================================================

#[test]
fn test_secp256k1_verifier_reports_kind() {
    let d = dispatcher();
    assert(d.kind() == KIND_SECP256K1, 'wrong kind');
}

// ============================================================
// Shape guards
// ============================================================

#[test]
fn test_rejects_empty_pubkey() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let ok = d.verify(hash, array![].span(), array![0, 0, 0, 0, 0].span());
    assert(!ok, 'empty pubkey');
}

#[test]
fn test_rejects_wrong_pubkey_len() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let pubkey = array![1, 2, 3].span(); // 3 felts — expected 4
    let ok = d.verify(hash, pubkey, array![0, 0, 0, 0, 0].span());
    assert(!ok, 'wrong pubkey len');
}

#[test]
fn test_rejects_wrong_signature_len() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let pubkey = array![1, 2, 3, 4].span();
    let ok = d.verify(hash, pubkey, array![1, 2, 3].span()); // 3 felts — expected 5
    assert(!ok, 'wrong sig len');
}

#[test]
fn test_rejects_invalid_y_parity() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let pubkey = array![1, 2, 3, 4].span();
    // y_parity must be 0 or 1; anything else → reject.
    let sig = array![0, 0, 0, 0, 2].span();
    let ok = d.verify(hash, pubkey, sig);
    assert(!ok, 'y_parity invalid');
}

// ============================================================
// Happy path + attack scenarios (fixture-driven)
// ============================================================

#[test]
fn test_secp256k1_happy_path_verifies() {
    let d = dispatcher();
    let hash = secp256k1_message_hash();
    let pubkey = secp256k1_pubkey();
    let sig = secp256k1_signature();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(ok, 'happy path must verify');
}

#[test]
fn test_secp256k1_wrong_pubkey_rejects() {
    let d = dispatcher();
    let hash = secp256k1_message_hash();
    let wrong_pk = array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE].span();
    let sig = secp256k1_signature();
    let ok = d.verify(hash, wrong_pk, sig.span());
    assert(!ok, 'wrong pubkey must reject');
}

#[test]
fn test_secp256k1_wrong_message_rejects() {
    // Correct signature, correct pubkey, but verifier is asked to check
    // a different message_hash — recovered point differs from stored.
    let d = dispatcher();
    let pubkey = secp256k1_pubkey();
    let sig = secp256k1_signature();
    let ok = d.verify(0x1234, pubkey.span(), sig.span());
    assert(!ok, 'wrong hash must reject');
}

#[test]
fn test_secp256k1_flipped_y_parity_rejects() {
    // Flip y_parity from the fixture. Recovery returns the other point
    // (mirror), which won't match the stored pubkey.
    let d = dispatcher();
    let hash = secp256k1_message_hash();
    let pubkey = secp256k1_pubkey();
    let mut sig = secp256k1_signature();
    // Replace last felt (y_parity) with the opposite value.
    let original_v = *sig.at(sig.len() - 1);
    let flipped: felt252 = if original_v == 0 {
        1
    } else {
        0
    };
    let mut flipped_sig: Array<felt252> = array![
        *sig.at(0), *sig.at(1), *sig.at(2), *sig.at(3), flipped,
    ];
    let ok = d.verify(hash, pubkey.span(), flipped_sig.span());
    assert(!ok, 'flipped y_parity must reject');
}
