//! EIP-712 secp256k1 verifier tests — MetaMask `eth_signTypedData_v4`.
//!
//! The on-chain verifier reads `chain_id` and `get_contract_address()`
//! at verify-time and folds them into the EIP-712 domain separator.
//! The fixture is signed off-chain (ethers `Wallet.signTypedData`)
//! against pinned values: chain_id = 0, salt = 0x1d6e. The Cairo
//! test deploys the verifier at exactly 0x1d6e via `deploy_at` and
//! cheats the chain_id to 0 so the on-chain recompute lands on the
//! same final hash.
//!
//! Edge cases this file guards against:
//!   - Wrong account-binding (verifier deployed at different address)
//!   - Wrong chain (chain_id cheated to a different value)
//!   - Replay of EIP-191 sig under EIP-712 verifier
//!   - Replay of raw secp256k1 sig under EIP-712 verifier
//!   - Wrong message hash
//!   - Wrong pubkey
//!   - Flipped y_parity
//!   - Shape guards (empty pubkey, wrong pubkey/sig length, invalid y_parity)

use shhh_wallet::signer::interface::{
    ISignerDispatcher, ISignerDispatcherTrait, KIND_EIP712_SECP256K1,
};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, start_cheat_chain_id_global};
use starknet::ContractAddress;
use super::signer_eip712_fixture::{
    eip712_account_address, eip712_chain_id, eip712_message_hash, eip712_pubkey, eip712_signature,
};

fn deploy_verifier_at(addr: ContractAddress) -> ISignerDispatcher {
    let class = declare("EIP712Secp256k1Verifier").unwrap().contract_class();
    class.deploy_at(@array![], addr).unwrap();
    ISignerDispatcher { contract_address: addr }
}

fn deploy_verifier_at_fixture_addr() -> ISignerDispatcher {
    let addr: ContractAddress = eip712_account_address().try_into().unwrap();
    deploy_verifier_at(addr)
}

fn cheat_to_fixture_chain() {
    start_cheat_chain_id_global(eip712_chain_id());
}

// ============================================================
// Kind tag
// ============================================================

#[test]
fn test_eip712_verifier_reports_kind() {
    let d = deploy_verifier_at_fixture_addr();
    assert(d.kind() == KIND_EIP712_SECP256K1, 'wrong kind');
}

// ============================================================
// Shape guards (no need to pin chain/address since verify exits
// before computing the EIP-712 hash on bad shape)
// ============================================================

#[test]
fn test_rejects_empty_pubkey() {
    let d = deploy_verifier_at_fixture_addr();
    let ok = d.verify(0xdead, array![].span(), array![0, 0, 0, 0, 0].span());
    assert(!ok, 'empty pubkey accepted');
}

#[test]
fn test_rejects_wrong_pubkey_len() {
    let d = deploy_verifier_at_fixture_addr();
    let ok = d.verify(0xdead, array![1, 2, 3].span(), array![0, 0, 0, 0, 0].span());
    assert(!ok, 'wrong pubkey len');
}

#[test]
fn test_rejects_wrong_signature_len() {
    let d = deploy_verifier_at_fixture_addr();
    let pubkey = array![1, 2, 3, 4].span();
    let ok = d.verify(0xdead, pubkey, array![1, 2, 3].span());
    assert(!ok, 'wrong sig len');
}

#[test]
fn test_rejects_invalid_y_parity() {
    let d = deploy_verifier_at_fixture_addr();
    let pubkey = array![1, 2, 3, 4].span();
    let sig = array![0, 0, 0, 0, 2].span();
    let ok = d.verify(0xdead, pubkey, sig);
    assert(!ok, 'y_parity invalid');
}

// ============================================================
// Happy path
// ============================================================

#[test]
fn test_eip712_happy_path_verifies() {
    let d = deploy_verifier_at_fixture_addr();
    cheat_to_fixture_chain();
    let hash = eip712_message_hash();
    let pubkey = eip712_pubkey();
    let sig = eip712_signature();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(ok, 'happy path must verify');
}

// ============================================================
// Cross-class confusion: EIP-712 verifier MUST reject signatures
// that were produced under different prefixing rules.
// ============================================================

/// Raw secp256k1 sig (no EIP-712 envelope) MUST be rejected. Otherwise
/// the EIP-712 verifier would silently accept arbitrary sigs and
/// become equivalent to the raw class.
use super::signer_secp256k1_fixture::{
    secp256k1_message_hash, secp256k1_pubkey, secp256k1_signature,
};

#[test]
fn test_eip712_rejects_raw_secp256k1_signature() {
    let d = deploy_verifier_at_fixture_addr();
    cheat_to_fixture_chain();
    let hash = secp256k1_message_hash();
    let pubkey = secp256k1_pubkey();
    let raw_sig = secp256k1_signature();
    let ok = d.verify(hash, pubkey.span(), raw_sig.span());
    assert(!ok, 'raw sig must not pass EIP-712');
}

/// EIP-191 sig (`personal_sign` prefix) MUST be rejected by the
/// EIP-712 verifier — they're cousins but the prefix bytes differ
/// and the recovered pubkey under EIP-712 hashing won't match.
use super::signer_eip191_fixture::{eip191_message_hash, eip191_pubkey, eip191_signature};

#[test]
fn test_eip712_rejects_eip191_signature() {
    let d = deploy_verifier_at_fixture_addr();
    cheat_to_fixture_chain();
    let hash = eip191_message_hash();
    let pubkey = eip191_pubkey();
    let eip191_sig = eip191_signature();
    let ok = d.verify(hash, pubkey.span(), eip191_sig.span());
    assert(!ok, 'EIP-191 sig accepted');
}

// ============================================================
// Domain binding: changing chain_id or account address must
// invalidate the signature (replay protection).
// ============================================================

#[test]
fn test_eip712_wrong_chain_id_rejects() {
    // Sig was signed for chain_id = 0; cheat the runtime to a
    // different chain. Domain separator differs → recovered point
    // differs → mismatch with stored pubkey.
    let d = deploy_verifier_at_fixture_addr();
    start_cheat_chain_id_global('SN_MAIN');
    let hash = eip712_message_hash();
    let pubkey = eip712_pubkey();
    let sig = eip712_signature();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(!ok, 'wrong chain accepted');
}

#[test]
fn test_eip712_wrong_account_address_rejects() {
    // Deploy verifier at a different address than the fixture used
    // (fixture's salt is 0x1d6e; we use 0xBEEF here). The on-chain
    // computed domain_separator differs from the signed one → the
    // recovered pubkey won't match.
    let other: ContractAddress = 0xBEEF.try_into().unwrap();
    let d = deploy_verifier_at(other);
    cheat_to_fixture_chain();
    let hash = eip712_message_hash();
    let pubkey = eip712_pubkey();
    let sig = eip712_signature();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(!ok, 'wrong account addr accepted');
}

// ============================================================
// Standard negative cases
// ============================================================

#[test]
fn test_eip712_wrong_pubkey_rejects() {
    let d = deploy_verifier_at_fixture_addr();
    cheat_to_fixture_chain();
    let hash = eip712_message_hash();
    let wrong_pk = array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE].span();
    let sig = eip712_signature();
    let ok = d.verify(hash, wrong_pk, sig.span());
    assert(!ok, 'wrong pubkey accepted');
}

#[test]
fn test_eip712_wrong_message_rejects() {
    let d = deploy_verifier_at_fixture_addr();
    cheat_to_fixture_chain();
    let pubkey = eip712_pubkey();
    let sig = eip712_signature();
    let ok = d.verify(0x1234, pubkey.span(), sig.span());
    assert(!ok, 'wrong hash accepted');
}

#[test]
fn test_eip712_flipped_y_parity_rejects() {
    let d = deploy_verifier_at_fixture_addr();
    cheat_to_fixture_chain();
    let hash = eip712_message_hash();
    let pubkey = eip712_pubkey();
    let mut sig = eip712_signature();
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
