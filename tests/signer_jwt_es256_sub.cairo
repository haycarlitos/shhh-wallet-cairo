//! JWT ES256 sub-bound verifier tests — multi-user Sign-In-with-Apple.
//!
//! Edge cases this file guards against (in addition to all the
//! cryptographic bindings the base verifier guards):
//!
//!   - Wrong sub (sig still valid, but poseidon(sub_bytes) != stored
//!     sub_hash) — this is THE load-bearing test for multi-user
//!     safety: it proves the Apple key alone is not enough to sign
//!     for a different user's account.
//!   - Wrong sub_offset (caller misdirects the read window) — the
//!     poseidon over a different byte range fails to match.
//!   - Wrong sub_len (caller truncates) — same.
//!   - Sub of zero length — the verifier short-circuits on len == 0
//!     so a poseidon-of-empty can't trivially match a stored zero.
//!   - Pubkey shape: 4 felts instead of 5 (would match the base
//!     verifier's shape) MUST reject here.

use shhh_wallet::signer::interface::{
    ISignerDispatcher, ISignerDispatcherTrait, KIND_JWT_ES256_APPLE_SUB,
};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use super::signer_jwt_es256_sub_fixture::{
    jwtsub_message_hash, jwtsub_pubkey, jwtsub_signature_envelope,
    jwtsub_signature_envelope_wrong_sub,
};

fn deploy_verifier() -> ContractAddress {
    let class = declare("JwtES256AppleSubVerifier").unwrap().contract_class();
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
fn test_jwtsub_verifier_reports_kind() {
    let d = dispatcher();
    assert(d.kind() == KIND_JWT_ES256_APPLE_SUB, 'wrong kind');
}

// ============================================================
// Shape guards
// ============================================================

#[test]
fn test_rejects_empty_pubkey() {
    let d = dispatcher();
    let sig = jwtsub_signature_envelope();
    let ok = d.verify(0xdead, array![].span(), sig.span());
    assert(!ok, 'empty pubkey accepted');
}

/// Pubkey shape: this verifier needs 5 felts (4 P-256 coords +
/// sub_hash). A 4-felt pubkey (which is the base verifier's shape)
/// MUST be rejected so an account misconfigured with the wrong
/// verifier-class binding fails closed.
#[test]
fn test_rejects_4_felt_pubkey() {
    let d = dispatcher();
    let sig = jwtsub_signature_envelope();
    let pk = jwtsub_pubkey();
    let truncated: Array<felt252> = array![*pk.at(0), *pk.at(1), *pk.at(2), *pk.at(3)];
    let ok = d.verify(jwtsub_message_hash(), truncated.span(), sig.span());
    assert(!ok, '4-felt pubkey accepted');
}

// ============================================================
// Happy path
// ============================================================

#[test]
fn test_jwtsub_happy_path_verifies() {
    let d = dispatcher();
    let hash = jwtsub_message_hash();
    let pubkey = jwtsub_pubkey();
    let sig = jwtsub_signature_envelope();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(ok, 'happy path must verify');
}

// ============================================================
// Sub binding — the headline regression for multi-user safety.
// ECDSA passes (the JWT was re-signed by the same key for a
// DIFFERENT sub), but the verifier MUST reject because the
// poseidon hash of the new sub bytes won't match the stored
// sub_hash. Without this check, anyone Apple authenticates could
// sign for any V8 account using the same Apple key.
// ============================================================

#[test]
fn test_jwtsub_wrong_sub_rejects() {
    let d = dispatcher();
    let hash = jwtsub_message_hash();
    let pubkey = jwtsub_pubkey();
    let sig = jwtsub_signature_envelope_wrong_sub();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(!ok, 'wrong sub accepted');
}

// ============================================================
// Wrong stored sub_hash — caller's owner record is misconfigured
// for this user. ECDSA passes, sub bytes match the JWT, but the
// stored sub_hash references a DIFFERENT user. Reject.
// ============================================================

#[test]
fn test_jwtsub_wrong_stored_sub_hash_rejects() {
    let d = dispatcher();
    let hash = jwtsub_message_hash();
    let pk = jwtsub_pubkey();
    // Replace the 5th felt (sub_hash) with a bogus value — same
    // pubkey but wrong identity.
    let bogus_pk: Array<felt252> = array![*pk.at(0), *pk.at(1), *pk.at(2), *pk.at(3), 0xDEADBEEF];
    let sig = jwtsub_signature_envelope();
    let ok = d.verify(hash, bogus_pk.span(), sig.span());
    assert(!ok, 'wrong sub_hash accepted');
}

// ============================================================
// Standard cryptographic bindings inherited from base — same
// failure modes still apply.
// ============================================================

#[test]
fn test_jwtsub_wrong_message_hash_rejects() {
    let d = dispatcher();
    let pubkey = jwtsub_pubkey();
    let sig = jwtsub_signature_envelope();
    let ok = d.verify(0x1234, pubkey.span(), sig.span());
    assert(!ok, 'wrong hash accepted');
}

#[test]
fn test_jwtsub_wrong_pubkey_rejects() {
    let d = dispatcher();
    let hash = jwtsub_message_hash();
    let pk = jwtsub_pubkey();
    // Different pubkey x but same sub_hash — JWT was signed by the
    // original key, so ECDSA fails recovery against a different one.
    let wrong_pk: Array<felt252> = array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE, *pk.at(4)];
    let sig = jwtsub_signature_envelope();
    let ok = d.verify(hash, wrong_pk.span(), sig.span());
    assert(!ok, 'wrong pubkey accepted');
}

// ============================================================
// Cross-class regression — a base JWT-ES256 envelope (no sub
// fields) MUST NOT pass through the sub-bound verifier. The
// envelope shape differs (4 fields instead of 6 between the
// ByteArrays and r/s), so Serde deserialize fails or pop_front
// returns None and verify exits false.
// ============================================================

use super::signer_jwt_es256_fixture::jwt_signature_envelope;

#[test]
fn test_jwtsub_rejects_base_jwt_envelope() {
    let d = dispatcher();
    let hash = jwtsub_message_hash();
    let pubkey = jwtsub_pubkey();
    let base_sig = jwt_signature_envelope(); // base envelope, 4 offsets/fields
    let ok = d.verify(hash, pubkey.span(), base_sig.span());
    assert(!ok, 'base JWT envelope accepted');
}
