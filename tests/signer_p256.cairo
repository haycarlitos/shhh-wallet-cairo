//! Phase 9 — P-256 (WebAuthn) verifier class tests.
//!
//! Mirrors the secp256k1 test shape. noble-curves v2 doesn't return a
//! recovery bit, so the happy-path test tries both y_parity candidates
//! (0 then 1) and expects exactly one to verify.

use shhh_wallet::signer::interface::{ISignerDispatcher, ISignerDispatcherTrait, KIND_WEBAUTHN_P256};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use super::signer_p256_fixture::{
    p256_message_hash, p256_pubkey, p256_signature_y_parity_0, p256_signature_y_parity_1,
};

fn deploy_verifier() -> ContractAddress {
    let class = declare("WebAuthnP256Verifier").unwrap().contract_class();
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
fn test_p256_verifier_reports_kind() {
    let d = dispatcher();
    assert(d.kind() == KIND_WEBAUTHN_P256, 'wrong kind');
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
fn test_rejects_wrong_signature_len() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let pubkey = array![1, 2, 3, 4].span();
    let ok = d.verify(hash, pubkey, array![1, 2, 3].span()); // only 3 felts
    assert(!ok, 'wrong sig len');
}

#[test]
fn test_rejects_invalid_y_parity() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let pubkey = array![1, 2, 3, 4].span();
    let sig = array![0, 0, 0, 0, 2].span(); // y_parity must be 0 or 1
    let ok = d.verify(hash, pubkey, sig);
    assert(!ok, 'y_parity invalid');
}

// ============================================================
// Happy path — try both parity candidates.
// ============================================================

#[test]
fn test_p256_happy_path_verifies() {
    // The P-256 verifier uses `is_valid_signature` (direct ECDSA verify
    // from the stored (x, y) coordinates), which does not consume the
    // y_parity hint. Either fixture envelope therefore verifies; the
    // y_parity field is a shape-check placeholder that keeps the
    // envelope compatible with the secp256k1 layout.
    let d = dispatcher();
    let hash = p256_message_hash();
    let pubkey = p256_pubkey();
    let sig = p256_signature_y_parity_0();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(ok, 'happy path must verify');
}

#[test]
fn test_p256_wrong_pubkey_rejects() {
    let d = dispatcher();
    let hash = p256_message_hash();
    let wrong_pk = array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE].span();
    let sig0 = p256_signature_y_parity_0();
    let sig1 = p256_signature_y_parity_1();
    let ok0 = d.verify(hash, wrong_pk, sig0.span());
    let ok1 = d.verify(hash, wrong_pk, sig1.span());
    assert(!ok0 && !ok1, 'wrong pubkey accepted');
}

#[test]
fn test_p256_wrong_message_rejects() {
    let d = dispatcher();
    let pubkey = p256_pubkey();
    let sig0 = p256_signature_y_parity_0();
    let sig1 = p256_signature_y_parity_1();
    let ok0 = d.verify(0x1234, pubkey.span(), sig0.span());
    let ok1 = d.verify(0x1234, pubkey.span(), sig1.span());
    assert(!ok0 && !ok1, 'wrong hash accepted');
}
