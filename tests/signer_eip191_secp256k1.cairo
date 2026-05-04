//! EIP-191 secp256k1 verifier tests — MetaMask `personal_sign` shape.
//!
//! Mirrors `signer_secp256k1.cairo` but the on-chain verifier wraps
//! the message hash with the `\x19Ethereum Signed Message:\n32`
//! prefix before recovering — which is exactly what every EVM wallet
//! prepends when the user clicks "Sign" on a `personal_sign` request.
//! The fixture is produced by ethers's `Wallet.signMessage(bytes)`,
//! the canonical `personal_sign` shape.

use shhh_wallet::signer::interface::{
    ISignerDispatcher, ISignerDispatcherTrait, KIND_EIP191_SECP256K1,
};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use super::signer_eip191_fixture::{eip191_message_hash, eip191_pubkey, eip191_signature};

fn deploy_verifier() -> ContractAddress {
    let class = declare("EIP191Secp256k1Verifier").unwrap().contract_class();
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
fn test_eip191_verifier_reports_kind() {
    let d = dispatcher();
    assert(d.kind() == KIND_EIP191_SECP256K1, 'wrong kind');
}

// ============================================================
// Shape guards
// ============================================================

#[test]
fn test_rejects_empty_pubkey() {
    let d = dispatcher();
    let ok = d.verify(0xdead, array![].span(), array![0, 0, 0, 0, 0].span());
    assert(!ok, 'empty pubkey accepted');
}

#[test]
fn test_rejects_wrong_pubkey_len() {
    let d = dispatcher();
    let ok = d.verify(0xdead, array![1, 2, 3].span(), array![0, 0, 0, 0, 0].span());
    assert(!ok, 'wrong pubkey len');
}

#[test]
fn test_rejects_wrong_signature_len() {
    let d = dispatcher();
    let pubkey = array![1, 2, 3, 4].span();
    let ok = d.verify(0xdead, pubkey, array![1, 2, 3].span());
    assert(!ok, 'wrong sig len');
}

#[test]
fn test_rejects_invalid_y_parity() {
    let d = dispatcher();
    let pubkey = array![1, 2, 3, 4].span();
    let sig = array![0, 0, 0, 0, 2].span();
    let ok = d.verify(0xdead, pubkey, sig);
    assert(!ok, 'y_parity invalid');
}

// ============================================================
// Happy path — ethers `Wallet.signMessage` produces a sig the
// on-chain verifier accepts after wrapping the hash with the
// EIP-191 prefix.
// ============================================================

#[test]
fn test_eip191_happy_path_verifies() {
    let d = dispatcher();
    let hash = eip191_message_hash();
    let pubkey = eip191_pubkey();
    let sig = eip191_signature();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(ok, 'happy path must verify');
}

// ============================================================
// Critical regression: a sig produced WITHOUT the EIP-191 prefix
// (i.e., a raw secp256k1 sig over the SNIP-12 hash) MUST be
// rejected here. Otherwise the EIP-191 verifier would silently
// accept arbitrary sigs and become equivalent to the raw class.
// We borrow the raw fixture and confirm rejection.
// ============================================================

use super::signer_secp256k1_fixture::{
    secp256k1_message_hash, secp256k1_pubkey, secp256k1_signature,
};

#[test]
fn test_eip191_rejects_raw_secp256k1_signature() {
    // Same private key, same SNIP-12 hash, but the sig is raw (no
    // EIP-191 prefix). Recover under EIP-191 hashing yields a
    // different point that won't match the stored pubkey.
    let d = dispatcher();
    let hash = secp256k1_message_hash();
    let pubkey = secp256k1_pubkey();
    let raw_sig = secp256k1_signature();
    let ok = d.verify(hash, pubkey.span(), raw_sig.span());
    assert(!ok, 'raw sig must not pass EIP-191');
}

// ============================================================
// Negative: wrong key, wrong message, flipped y_parity
// ============================================================

#[test]
fn test_eip191_wrong_pubkey_rejects() {
    let d = dispatcher();
    let hash = eip191_message_hash();
    let wrong_pk = array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE].span();
    let sig = eip191_signature();
    let ok = d.verify(hash, wrong_pk, sig.span());
    assert(!ok, 'wrong pubkey accepted');
}

#[test]
fn test_eip191_wrong_message_rejects() {
    let d = dispatcher();
    let pubkey = eip191_pubkey();
    let sig = eip191_signature();
    let ok = d.verify(0x1234, pubkey.span(), sig.span());
    assert(!ok, 'wrong hash accepted');
}

#[test]
fn test_eip191_flipped_y_parity_rejects() {
    let d = dispatcher();
    let hash = eip191_message_hash();
    let pubkey = eip191_pubkey();
    let mut sig = eip191_signature();
    let original_v = *sig.at(sig.len() - 1);
    let flipped: felt252 = if original_v == 0 {
        1
    } else {
        0
    };
    let flipped_sig: Array<felt252> = array![
        *sig.at(0), *sig.at(1), *sig.at(2), *sig.at(3), flipped,
    ];
    let ok = d.verify(hash, pubkey.span(), flipped_sig.span());
    assert(!ok, 'flipped y_parity accepted');
}
