//! WebAuthn full-envelope verifier tests.
//!
//! Exercises `WebAuthnP256Verifier.verify` with a real WebAuthn
//! assertion produced by `scripts/ts/gen-webauthn-fixture.mjs`:
//!   - rpIdHash = sha256("cifra.mx")
//!   - flags    = UP | UV (0x05)
//!   - clientDataJSON = {"type":"webauthn.get","challenge":"<b64url>",...}
//!   - sha256(authData || sha256(clientDataJSON)) signed with NIST P-256
//!
//! Four cases:
//!   1. Happy path — all checks pass.
//!   2. Challenge-offset shift — the 43 bytes at `off+1` no longer match
//!      the expected base64url encoding. Verifier rejects without even
//!      running ECDSA.
//!   3. UP flag cleared — WebAuthn §7.2 step 17 violation. Verifier
//!      rejects before ECDSA.
//!   4. Wrong message_hash — challenge binding check fails (expected
//!      base64url doesn't match what was baked into the fixture).

use shhh_wallet::signer::interface::{ISignerDispatcher, ISignerDispatcherTrait, KIND_WEBAUTHN_P256};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use super::signer_webauthn_fixture::{
    webauthn_message_hash, webauthn_pubkey, webauthn_signature_envelope,
    webauthn_signature_envelope_missing_type, webauthn_signature_envelope_no_up,
    webauthn_signature_envelope_wrong_offset, webauthn_signature_envelope_wrong_type,
};

fn deploy_verifier() -> ContractAddress {
    let class = declare("WebAuthnP256Verifier").unwrap().contract_class();
    let (addr, _) = class.deploy(@array![]).unwrap();
    addr
}

fn dispatcher() -> ISignerDispatcher {
    ISignerDispatcher { contract_address: deploy_verifier() }
}

#[test]
fn test_webauthn_verifier_reports_kind() {
    let d = dispatcher();
    assert(d.kind() == KIND_WEBAUTHN_P256, 'wrong kind');
}

#[test]
fn test_webauthn_happy_path_verifies() {
    let d = dispatcher();
    let hash = webauthn_message_hash();
    let pubkey = webauthn_pubkey();
    let sig = webauthn_signature_envelope();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(ok, 'happy path must verify');
}

#[test]
fn test_webauthn_wrong_challenge_offset_rejects() {
    let d = dispatcher();
    let hash = webauthn_message_hash();
    let pubkey = webauthn_pubkey();
    let sig = webauthn_signature_envelope_wrong_offset();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(!ok, 'wrong offset accepted');
}

#[test]
fn test_webauthn_up_flag_missing_rejects() {
    let d = dispatcher();
    let hash = webauthn_message_hash();
    let pubkey = webauthn_pubkey();
    let sig = webauthn_signature_envelope_no_up();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(!ok, 'UP flag missing accepted');
}

#[test]
fn test_webauthn_wrong_message_hash_rejects() {
    let d = dispatcher();
    let pubkey = webauthn_pubkey();
    let sig = webauthn_signature_envelope();
    // Any hash different from the baked-in challenge will cause the
    // expected base64url string to mismatch the one inside clientData.
    let ok = d.verify(0xDEAD, pubkey.span(), sig.span());
    assert(!ok, 'wrong hash accepted');
}

#[test]
fn test_webauthn_rejects_empty_pubkey() {
    let d = dispatcher();
    let hash = webauthn_message_hash();
    let sig = webauthn_signature_envelope();
    let ok = d.verify(hash, array![].span(), sig.span());
    assert(!ok, 'empty pubkey accepted');
}

// ==========================================================
// H-1: webauthn.create confusion attack must be rejected
// ==========================================================

/// clientDataJSON contains `type="webauthn.create"` instead of
/// `webauthn.get`. The signature is cryptographically valid — an
/// authenticator really signed that clientData during a registration
/// ceremony. If we skipped the type check, a phishing site that
/// coerced the user into a rewards-signup flow with our challenge
/// embedded could harvest a signature that our wallet then accepts
/// as authentication. The prefix check MUST reject.
#[test]
fn test_webauthn_rejects_create_type_confusion() {
    let d = dispatcher();
    let hash = webauthn_message_hash();
    let pubkey = webauthn_pubkey();
    let sig = webauthn_signature_envelope_wrong_type();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(!ok, 'webauthn.create accepted');
}

/// clientDataJSON omits the type field entirely. Even if the challenge
/// substring is present, the verifier MUST reject because the prefix
/// check fails before any ECDSA work.
#[test]
fn test_webauthn_rejects_missing_type() {
    let d = dispatcher();
    let hash = webauthn_message_hash();
    let pubkey = webauthn_pubkey();
    let sig = webauthn_signature_envelope_missing_type();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(!ok, 'missing type accepted');
}
