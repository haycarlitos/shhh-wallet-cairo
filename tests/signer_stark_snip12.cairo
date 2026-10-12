//! STARK SNIP-12 verifier tests — Starknet browser wallets
//! (`wallet_signTypedData` in Bramble, Braavos, Ready/Argent, OZ).
//!
//! The on-chain verifier reads `chain_id` and `get_contract_address()`
//! at verify-time and folds them into the SNIP-12 `Approval` typed data.
//! The fixture is signed off-chain (starknet.js `typedData.getMessageHash`
//! + STARK ECDSA) against pinned values: chain_id = 'SN_MAIN', wallet =
//! 0x5eba. The test deploys the verifier at exactly 0x5eba via
//! `deploy_at` and cheats the chain_id to 'SN_MAIN'.
//!
//! Edge cases this file guards against:
//!   - TS ↔ Cairo hash drift (approval_hash == starknet.js final hash)
//!   - Wrong wallet binding (verifier deployed at a different address)
//!   - Wrong chain
//!   - Wrong signer account (the address the wallet folded into the hash)
//!   - Wrong message hash / wrong pubkey
//!   - A raw-hash STARK signature (what StarkVerifier accepts) is refused
//!   - Shape guards and validate_pubkey

use shhh_wallet::signer::interface::{ISignerDispatcher, ISignerDispatcherTrait, KIND_STARK_SNIP12};
use shhh_wallet::signer::stark_snip12::verifier::StarkSnip12Verifier::approval_hash;
use snforge_std::signature::SignerTrait;
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, start_cheat_chain_id_global};
use starknet::ContractAddress;
use super::signer_stark_snip12_fixture::{
    stark_snip12_chain_id, stark_snip12_final_hash, stark_snip12_message_hash, stark_snip12_pubkey,
    stark_snip12_signature, stark_snip12_wallet_address,
};

fn deploy_verifier_at(addr: felt252) -> ISignerDispatcher {
    let address: ContractAddress = addr.try_into().unwrap();
    let class = declare("StarkSnip12Verifier").unwrap().contract_class();
    class.deploy_at(@array![], address).unwrap();
    ISignerDispatcher { contract_address: address }
}

fn deploy_at_fixture() -> ISignerDispatcher {
    start_cheat_chain_id_global(stark_snip12_chain_id());
    deploy_verifier_at(stark_snip12_wallet_address())
}

// ============================================================
// Kind tag + TS parity
// ============================================================

#[test]
fn test_stark_snip12_reports_kind() {
    let d = deploy_at_fixture();
    assert(d.kind() == KIND_STARK_SNIP12, 'wrong kind');
}

#[test]
fn test_approval_hash_matches_starknet_js() {
    let pubkey = stark_snip12_pubkey();
    let h = approval_hash(
        stark_snip12_chain_id(),
        stark_snip12_wallet_address(),
        *pubkey.at(1),
        stark_snip12_message_hash(),
    );
    assert(h == stark_snip12_final_hash(), 'TS/Cairo hash drift');
}

// ============================================================
// Happy path — the starknet.js (wallet) signature verifies
// ============================================================

#[test]
fn test_wallet_signature_verifies() {
    let d = deploy_at_fixture();
    let ok = d
        .verify(
            stark_snip12_message_hash(),
            stark_snip12_pubkey().span(),
            stark_snip12_signature().span(),
        );
    assert(ok, 'wallet sig rejected');
}

// ============================================================
// Binding — wallet, chain, signer account, hash, key
// ============================================================

#[test]
fn test_rejects_other_wallet() {
    start_cheat_chain_id_global(stark_snip12_chain_id());
    let d = deploy_verifier_at(0x5ebb);
    let ok = d
        .verify(
            stark_snip12_message_hash(),
            stark_snip12_pubkey().span(),
            stark_snip12_signature().span(),
        );
    assert(!ok, 'other wallet accepted');
}

#[test]
fn test_rejects_other_chain() {
    let d = deploy_at_fixture();
    start_cheat_chain_id_global('SN_SEPOLIA');
    let ok = d
        .verify(
            stark_snip12_message_hash(),
            stark_snip12_pubkey().span(),
            stark_snip12_signature().span(),
        );
    assert(!ok, 'other chain accepted');
}

#[test]
fn test_rejects_other_signer_account() {
    let d = deploy_at_fixture();
    let pubkey = stark_snip12_pubkey();
    let ok = d
        .verify(
            stark_snip12_message_hash(),
            array![*pubkey.at(0), 0x123abd].span(),
            stark_snip12_signature().span(),
        );
    assert(!ok, 'other signer accepted');
}

#[test]
fn test_rejects_other_message_hash() {
    let d = deploy_at_fixture();
    let ok = d
        .verify(
            stark_snip12_message_hash() + 1,
            stark_snip12_pubkey().span(),
            stark_snip12_signature().span(),
        );
    assert(!ok, 'other hash accepted');
}

#[test]
fn test_rejects_other_pubkey() {
    let d = deploy_at_fixture();
    let pubkey = stark_snip12_pubkey();
    let other = StarkCurveKeyPairImpl::from_secret_key(0xBEEF);
    let ok = d
        .verify(
            stark_snip12_message_hash(),
            array![other.public_key, *pubkey.at(1)].span(),
            stark_snip12_signature().span(),
        );
    assert(!ok, 'other key accepted');
}

#[test]
fn test_fresh_key_signs_approval_hash_not_raw_hash() {
    let d = deploy_at_fixture();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0xB4A3B1E);
    let signer_account: felt252 = 0xb4a3;
    let pubkey = array![kp.public_key, signer_account];
    let message_hash: felt252 = 0x1234;

    // What StarkVerifier accepts (a raw-hash signature) is refused here.
    let (raw_r, raw_s) = kp.sign(message_hash).unwrap();
    assert(!d.verify(message_hash, pubkey.span(), array![raw_r, raw_s].span()), 'raw sig accepted');

    // The SNIP-12 approval signature (what the wallet returns) verifies.
    let h = approval_hash(
        stark_snip12_chain_id(), stark_snip12_wallet_address(), signer_account, message_hash,
    );
    let (r, s) = kp.sign(h).unwrap();
    assert(d.verify(message_hash, pubkey.span(), array![r, s].span()), 'approval sig rejected');
}

// ============================================================
// Shape guards
// ============================================================

#[test]
fn test_rejects_wrong_pubkey_len() {
    let d = deploy_at_fixture();
    let pubkey = stark_snip12_pubkey();
    let sig = stark_snip12_signature();
    assert(!d.verify(stark_snip12_message_hash(), array![].span(), sig.span()), 'empty pubkey');
    assert(
        !d.verify(stark_snip12_message_hash(), array![*pubkey.at(0)].span(), sig.span()),
        'pubkey len 1',
    );
    assert(
        !d
            .verify(
                stark_snip12_message_hash(),
                array![*pubkey.at(0), *pubkey.at(1), 0].span(),
                sig.span(),
            ),
        'pubkey len 3',
    );
}

#[test]
fn test_rejects_wrong_signature_len() {
    let d = deploy_at_fixture();
    let sig = stark_snip12_signature();
    let pubkey = stark_snip12_pubkey();
    assert(
        !d.verify(stark_snip12_message_hash(), pubkey.span(), array![*sig.at(0)].span()),
        'sig len 1',
    );
    // Argent/Ready shape [1, 0, pubkey, r, s] must be normalized off-chain.
    assert(
        !d
            .verify(
                stark_snip12_message_hash(),
                pubkey.span(),
                array![1, 0, *pubkey.at(0), *sig.at(0), *sig.at(1)].span(),
            ),
        'argent shape accepted',
    );
}

// ============================================================
// validate_pubkey
// ============================================================

#[test]
fn test_validate_pubkey() {
    let d = deploy_at_fixture();
    assert(d.validate_pubkey(stark_snip12_pubkey().span()), 'valid pubkey rejected');
    assert(!d.validate_pubkey(array![].span()), 'empty accepted');
    assert(!d.validate_pubkey(array![0x77].span()), 'len 1 accepted');
    assert(!d.validate_pubkey(array![0x77, 0x88, 0x99].span()), 'len 3 accepted');
    assert(!d.validate_pubkey(array![0, 0x123abc].span()), 'zero key accepted');
    assert(!d.validate_pubkey(array![0x77, 0].span()), 'zero account accepted');
}
