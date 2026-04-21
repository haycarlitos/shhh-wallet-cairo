//! Ed25519 verifier class — happy-path Garaga verification.
//!
//! Uses the fixture produced by `scripts/ts/regen-ed25519-fixtures.mjs`.
//! If this test regresses after a Garaga or Ed25519Verifier change, re-run
//! that generator to refresh the fixture.

use shhh_wallet::signer::interface::{ISignerDispatcher, ISignerDispatcherTrait};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use super::signer_ed25519_fixture::{
    fixture_message_hash, fixture_pubkey_high, fixture_pubkey_low, fixture_signature_envelope,
};

fn deploy_verifier() -> ContractAddress {
    let class = declare("Ed25519Verifier").unwrap().contract_class();
    let (addr, _) = class.deploy(@array![]).unwrap();
    addr
}

#[test]
fn test_ed25519_happy_path_verifies() {
    let verifier = ISignerDispatcher { contract_address: deploy_verifier() };
    let msg_hash = fixture_message_hash();
    let pubkey = array![fixture_pubkey_low(), fixture_pubkey_high()].span();
    let sig = fixture_signature_envelope();
    let ok = verifier.verify(msg_hash, pubkey, sig.span());
    assert(ok, 'ED25519 happy path failed');
}

/// Same fixture, different caller pubkey → MUST fail.
#[test]
fn test_ed25519_wrong_pubkey_rejects() {
    let verifier = ISignerDispatcher { contract_address: deploy_verifier() };
    let msg_hash = fixture_message_hash();
    let wrong_pubkey = array![0xDEAD, 0xBEEF].span();
    let sig = fixture_signature_envelope();
    let ok = verifier.verify(msg_hash, wrong_pubkey, sig.span());
    assert(!ok, 'should reject wrong pubkey');
}

/// Same fixture, different message_hash → MUST fail
/// (expected msg bytes no longer match the signed bytes).
#[test]
fn test_ed25519_wrong_message_hash_rejects() {
    let verifier = ISignerDispatcher { contract_address: deploy_verifier() };
    let pubkey = array![fixture_pubkey_low(), fixture_pubkey_high()].span();
    let sig = fixture_signature_envelope();
    let ok = verifier.verify(0x1234, pubkey, sig.span());
    assert(!ok, 'should reject wrong hash');
}
