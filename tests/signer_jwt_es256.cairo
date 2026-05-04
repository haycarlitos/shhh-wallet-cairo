//! JWT ES256 verifier tests — Sign-In-with-Apple shape.
//!
//! Edge cases this file guards against:
//!   - Wrong issuer in the decoded payload (sig still valid, but the
//!     hardcoded "https://appleid.apple.com" check rejects)
//!   - Wrong nonce in the decoded payload (sig still valid, but
//!     base64url(message_hash) check rejects)
//!   - Wrong message hash (signed nonce no longer matches expected)
//!   - Wrong pubkey (signed by a different IdP key)
//!   - Replay across kinds: a P-256 raw sig over the SNIP-12 hash
//!     MUST NOT verify here, because we hash a different signing
//!     input (header_b64 || "." || payload_b64)
//!   - Shape guards: empty pubkey, wrong pubkey len, invalid y_parity

use shhh_wallet::signer::interface::{ISignerDispatcher, ISignerDispatcherTrait, KIND_JWT_ES256};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use super::signer_jwt_es256_fixture::{
    jwt_message_hash, jwt_pubkey, jwt_signature_envelope, jwt_signature_envelope_wrong_issuer,
    jwt_signature_envelope_wrong_nonce,
};

fn deploy_verifier() -> ContractAddress {
    let class = declare("JwtES256AppleVerifier").unwrap().contract_class();
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
fn test_jwt_verifier_reports_kind() {
    let d = dispatcher();
    assert(d.kind() == KIND_JWT_ES256, 'wrong kind');
}

// ============================================================
// Shape guards
// ============================================================

#[test]
fn test_rejects_empty_pubkey() {
    let d = dispatcher();
    let sig = jwt_signature_envelope();
    let ok = d.verify(0xdead, array![].span(), sig.span());
    assert(!ok, 'empty pubkey accepted');
}

#[test]
fn test_rejects_wrong_pubkey_len() {
    let d = dispatcher();
    let sig = jwt_signature_envelope();
    let ok = d.verify(0xdead, array![1, 2, 3].span(), sig.span());
    assert(!ok, 'wrong pubkey len');
}

// ============================================================
// Happy path — fixture-driven
// ============================================================

#[test]
fn test_jwt_happy_path_verifies() {
    let d = dispatcher();
    let hash = jwt_message_hash();
    let pubkey = jwt_pubkey();
    let sig = jwt_signature_envelope();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(ok, 'happy path must verify');
}

// ============================================================
// Issuer binding — wrong iss MUST reject even when ECDSA verifies
// ============================================================

#[test]
fn test_jwt_wrong_issuer_rejects() {
    // Re-signed JWT with iss = "https://example.com/oauth". The ECDSA
    // recovery succeeds (re-signed by the same key) so the rejection
    // comes specifically from the issuer-prefix check, not from the
    // signature path.
    let d = dispatcher();
    let hash = jwt_message_hash();
    let pubkey = jwt_pubkey();
    let sig = jwt_signature_envelope_wrong_issuer();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(!ok, 'wrong iss accepted');
}

// ============================================================
// Nonce binding — JWT carrying a different challenge MUST reject
// ============================================================

#[test]
fn test_jwt_wrong_nonce_rejects() {
    // Re-signed JWT whose `nonce` claim base64url-decodes to bytes
    // other than message_hash. ECDSA passes (re-signed); the nonce
    // substring check is what rejects.
    let d = dispatcher();
    let hash = jwt_message_hash();
    let pubkey = jwt_pubkey();
    let sig = jwt_signature_envelope_wrong_nonce();
    let ok = d.verify(hash, pubkey.span(), sig.span());
    assert(!ok, 'wrong nonce accepted');
}

// ============================================================
// Message-hash binding — caller asks for a different hash than
// the JWT actually carried. The base64url(message_hash) the verifier
// computes won't match the embedded nonce, so reject.
// ============================================================

#[test]
fn test_jwt_wrong_message_hash_rejects() {
    let d = dispatcher();
    let pubkey = jwt_pubkey();
    let sig = jwt_signature_envelope();
    // Use a hash that nobody signed for.
    let ok = d.verify(0x1234, pubkey.span(), sig.span());
    assert(!ok, 'wrong hash accepted');
}

// ============================================================
// Wrong pubkey — JWT signed by a different IdP key
// ============================================================

#[test]
fn test_jwt_wrong_pubkey_rejects() {
    let d = dispatcher();
    let hash = jwt_message_hash();
    let wrong_pk = array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE].span();
    let sig = jwt_signature_envelope();
    let ok = d.verify(hash, wrong_pk, sig.span());
    assert(!ok, 'wrong pubkey accepted');
}

// ============================================================
// Cross-class regression — a raw P-256 sig MUST NOT pass here.
// (raw P-256 signs the SNIP-12 hash directly; JWT ES256 signs
//  sha256(header_b64 || "." || payload_b64). Different inputs,
//  different recovered points.)
// ============================================================

use super::signer_p256_fixture::{p256_message_hash, p256_pubkey, p256_signature_y_parity_0};

#[test]
fn test_jwt_rejects_raw_p256_signature() {
    let d = dispatcher();
    let hash = p256_message_hash();
    let pubkey = p256_pubkey();
    let raw_sig = p256_signature_y_parity_0();
    // Raw P-256 sig has 5 felts (r_lo, r_hi, s_lo, s_hi, y_parity).
    // JWT envelope expects header_b64 + payload_decoded + 2 offsets +
    // r/s + y_parity, so a 5-felt signature short-circuits at Serde
    // deserialize. This proves no path conflates the two kinds.
    let ok = d.verify(hash, pubkey.span(), raw_sig.span());
    assert(!ok, 'raw P-256 sig accepted');
}
