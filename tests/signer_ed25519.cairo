//! Ed25519 verifier class — direct tests.
//!
//! Exercise `Ed25519Verifier::verify` via a dispatcher. Covers the
//! audit M-4 / I-2 envelope guards with controlled bad inputs.
//!
//! The positive-vector end-to-end test (Phantom signs → verifier
//! accepts) requires an off-chain fixture produced by
//! `scripts/ts/regen-ed25519-fixtures.mjs` and lives in
//! `tests/signer_ed25519_fixture.cairo` — added alongside the TS
//! generator in a follow-up commit inside this phase.

use shhh_wallet::signer::interface::{ISignerDispatcher, ISignerDispatcherTrait, KIND_ED25519};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;

fn deploy_verifier() -> ContractAddress {
    let class = declare("Ed25519Verifier").unwrap().contract_class();
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
fn test_ed25519_verifier_reports_kind() {
    let d = dispatcher();
    assert(d.kind() == KIND_ED25519, 'ED25519: wrong kind');
}

// ============================================================
// Pubkey shape — audit L-1 equivalent at the verifier layer
// ============================================================

#[test]
fn test_rejects_empty_pubkey() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let ok = d.verify(hash, array![].span(), array![0, 0, 0, 0, 64].span());
    assert(!ok, 'should reject empty pubkey');
}

#[test]
fn test_rejects_oversize_pubkey() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let pubkey = array![1, 2, 3].span(); // 3 felts — expected 2
    let ok = d.verify(hash, pubkey, array![0, 0, 0, 0, 64].span());
    assert(!ok, 'should reject 3-felt pubkey');
}

#[test]
fn test_rejects_pubkey_half_over_u128() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    // 2^128 exceeds u128::MAX — must fail the try_into check
    let pubkey = array![0x100000000000000000000000000000000, 0x0].span();
    let ok = d.verify(hash, pubkey, array![0, 0, 0, 0, 64].span());
    assert(!ok, 'should reject OOR pubkey half');
}

// ============================================================
// Envelope shape — audit M-4
// ============================================================

#[test]
fn test_rejects_signature_too_short() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let pubkey = array![0x11, 0x22].span();
    let ok = d.verify(hash, pubkey, array![1, 2, 3, 4].span()); // only 4 felts
    assert(!ok, 'should reject 4-felt envelope');
}

#[test]
fn test_rejects_wrong_msg_len() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let pubkey = array![0x11, 0x22].span();
    // msg_len claims 32 (wrong — expected 64 for a 32-byte hash encoded as hex)
    let ok = d.verify(hash, pubkey, array![0, 0, 0, 0, 32].span());
    assert(!ok, 'should reject wrong msg_len');
}

#[test]
fn test_rejects_truncated_msg_bytes() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let pubkey = array![0x11, 0x22].span();
    // msg_len claims 64 but no msg bytes present after the 5-felt prefix
    let ok = d.verify(hash, pubkey, array![0, 0, 0, 0, 64].span());
    assert(!ok, 'should reject truncated msg');
}

#[test]
fn test_rejects_non_byte_msg_felt() {
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let pubkey = array![0x11, 0x22].span();
    // msg_len=1 but the msg felt exceeds u8
    let mut sig: Array<felt252> = array![0, 0, 0, 0, 1];
    sig.append(0x100); // 256 — doesn't fit in u8
    let ok = d.verify(hash, pubkey, sig.span());
    assert(!ok, 'should reject non-byte msg');
}

#[test]
fn test_rejects_msg_mismatch() {
    // Envelope has 64 msg bytes (correct length for a 32-byte hash) but
    // all 'x' characters — doesn't match hex_ascii(0xdead...).
    let d = dispatcher();
    let hash: felt252 = 0xdead;
    let pubkey = array![0x11, 0x22].span();
    let mut sig: Array<felt252> = array![0, 0, 0, 0, 64];
    let mut i: u32 = 0;
    while i < 64 {
        sig.append(0x78); // 'x'
        i += 1;
    }
    let ok = d.verify(hash, pubkey, sig.span());
    assert(!ok, 'should reject wrong msg bytes');
}

// ============================================================
// Malformed Garaga hints — audit I-2
// ============================================================

#[test]
fn test_rejects_malformed_hints() {
    // Correct msg bytes (hex_ascii of hash = all zeros) but garbage hints.
    let d = dispatcher();
    let hash: felt252 = 0x0;
    let pubkey = array![0x11, 0x22].span();
    let mut sig: Array<felt252> = array![0, 0, 0, 0, 64];
    let mut i: u32 = 0;
    while i < 64 {
        sig.append(0x30); // ASCII '0'
        i += 1;
    }
    // Trailing random felts — Serde deserialize will either fail or
    // consume them, and is_valid_eddsa_signature will return false on
    // nonsense hints / R / s values.
    let mut j: u32 = 0;
    while j < 200 {
        sig.append(0xAA);
        j += 1;
    }
    let ok = d.verify(hash, pubkey, sig.span());
    assert(!ok, 'should reject bad hints');
}
