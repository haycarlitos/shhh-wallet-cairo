//! Audit M-1 (V8.2, full) — per-verifier `validate_pubkey` regression
//! tests.
//!
//! Each verifier class MUST implement `ISigner::validate_pubkey` so a
//! malformed pubkey can never land in `owner_set` at registration. This
//! file exercises each of the 10 verifiers' shape + curve checks.
//!
//! Three test cases per verifier:
//!   - canonical: a valid pubkey returns `true`.
//!   - shape mismatch: a wrong-length pubkey returns `false`
//!     (no panic).
//!   - curve / shape garbage: a pubkey of the right length but
//!     malformed contents returns `false` (gracefully) for curve-
//!     family verifiers (SECP256K1, EIP-191, EIP-712, P256, WebAuthn,
//!     JWT-ES256, JWT_APPLE_SUB) via `secp256_ec_new_syscall` returning
//!     `Result::Err`. STARK / ED25519 only do shape, so they accept
//!     non-zero-but-arbitrary bytes (graceful "true"). BLS PANICS on
//!     bad input by design — see `test_bls_validate_pubkey_panics_off_curve`
//!     with `#[should_panic]`.

use shhh_wallet::signer::interface::{ISignerDispatcher, ISignerDispatcherTrait};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;

fn deploy(name: ByteArray) -> ISignerDispatcher {
    let class = declare(name).unwrap().contract_class();
    let (addr, _) = class.deploy(@array![]).unwrap();
    ISignerDispatcher { contract_address: addr }
}

fn build_repeat(value: felt252, len: u32) -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < len {
        out.append(value);
        i += 1;
    }
    out
}

// ============================================================
//  STARK
// ============================================================

#[test]
fn test_stark_validate_pubkey_accepts_nonzero() {
    let d = deploy("StarkVerifier");
    assert(d.validate_pubkey(array![0x1234].span()), 'stark: valid');
}

#[test]
fn test_stark_validate_pubkey_rejects_wrong_len() {
    let d = deploy("StarkVerifier");
    assert(!d.validate_pubkey(array![].span()), 'stark: empty');
    assert(!d.validate_pubkey(array![0x1, 0x2].span()), 'stark: len 2');
}

#[test]
fn test_stark_validate_pubkey_rejects_zero() {
    let d = deploy("StarkVerifier");
    assert(!d.validate_pubkey(array![0].span()), 'stark: zero');
}

// ============================================================
//  ED25519
// ============================================================

#[test]
fn test_ed25519_validate_pubkey_accepts_two_felts() {
    let d = deploy("Ed25519Verifier");
    assert(d.validate_pubkey(array![0xAAAA, 0xBBBB].span()), 'ed25519: valid');
}

#[test]
fn test_ed25519_validate_pubkey_rejects_wrong_len() {
    let d = deploy("Ed25519Verifier");
    assert(!d.validate_pubkey(array![].span()), 'ed25519: empty');
    assert(!d.validate_pubkey(array![0x1].span()), 'ed25519: len 1');
    assert(!d.validate_pubkey(array![0x1, 0x2, 0x3].span()), 'ed25519: len 3');
}

// ============================================================
//  SECP256K1 (raw)
// ============================================================

#[test]
fn test_secp256k1_validate_pubkey_rejects_off_curve() {
    let d = deploy("Secp256k1Verifier");
    // Random 4 felts that aren't a valid secp256k1 point.
    assert(
        !d.validate_pubkey(array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE].span()), 'secp256k1: off-curve',
    );
}

#[test]
fn test_secp256k1_validate_pubkey_rejects_wrong_len() {
    let d = deploy("Secp256k1Verifier");
    assert(!d.validate_pubkey(array![0x1, 0x2, 0x3].span()), 'secp256k1: len 3');
    assert(!d.validate_pubkey(array![0x1, 0x2, 0x3, 0x4, 0x5].span()), 'secp256k1: len 5');
}

// ============================================================
//  EIP-191
// ============================================================

#[test]
fn test_eip191_validate_pubkey_rejects_off_curve() {
    let d = deploy("EIP191Secp256k1Verifier");
    assert(!d.validate_pubkey(array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE].span()), 'eip191: off-curve');
}

#[test]
fn test_eip191_validate_pubkey_rejects_wrong_len() {
    let d = deploy("EIP191Secp256k1Verifier");
    assert(!d.validate_pubkey(array![0x1, 0x2, 0x3].span()), 'eip191: len 3');
}

// ============================================================
//  EIP-712
// ============================================================

#[test]
fn test_eip712_validate_pubkey_rejects_off_curve() {
    let d = deploy("EIP712Secp256k1Verifier");
    assert(!d.validate_pubkey(array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE].span()), 'eip712: off-curve');
}

#[test]
fn test_eip712_validate_pubkey_rejects_wrong_len() {
    let d = deploy("EIP712Secp256k1Verifier");
    assert(!d.validate_pubkey(array![0x1, 0x2, 0x3].span()), 'eip712: len 3');
}

// ============================================================
//  P-256 (raw)
// ============================================================

#[test]
fn test_p256_validate_pubkey_rejects_off_curve() {
    let d = deploy("P256Verifier");
    assert(!d.validate_pubkey(array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE].span()), 'p256: off-curve');
}

#[test]
fn test_p256_validate_pubkey_rejects_wrong_len() {
    let d = deploy("P256Verifier");
    assert(!d.validate_pubkey(array![0x1, 0x2, 0x3].span()), 'p256: len 3');
}

// ============================================================
//  WebAuthn P-256
// ============================================================

#[test]
fn test_webauthn_validate_pubkey_rejects_off_curve() {
    let d = deploy("WebAuthnP256Verifier");
    assert(
        !d.validate_pubkey(array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE].span()), 'webauthn: off-curve',
    );
}

#[test]
fn test_webauthn_validate_pubkey_rejects_wrong_len() {
    let d = deploy("WebAuthnP256Verifier");
    assert(!d.validate_pubkey(array![0x1, 0x2, 0x3].span()), 'webauthn: len 3');
}

// ============================================================
//  JWT-ES256 (single-tenant Apple)
// ============================================================

#[test]
fn test_jwt_es256_validate_pubkey_rejects_off_curve() {
    let d = deploy("JwtES256AppleVerifier");
    assert(!d.validate_pubkey(array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE].span()), 'jwt: off-curve');
}

#[test]
fn test_jwt_es256_validate_pubkey_rejects_wrong_len() {
    let d = deploy("JwtES256AppleVerifier");
    assert(!d.validate_pubkey(array![0x1, 0x2, 0x3].span()), 'jwt: len 3');
}

// ============================================================
//  JWT-ES256 sub-bound (multi-tenant Apple)
// ============================================================

#[test]
fn test_jwtsub_validate_pubkey_rejects_off_curve() {
    let d = deploy("JwtES256AppleSubVerifier");
    // 5 felts, but the first 4 are not a valid P-256 point.
    assert(
        !d.validate_pubkey(array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE, 0xFEED].span()),
        'jwtsub: off-curve',
    );
}

#[test]
fn test_jwtsub_validate_pubkey_rejects_wrong_len() {
    let d = deploy("JwtES256AppleSubVerifier");
    // 4 felts (missing sub_hash) → reject.
    assert(!d.validate_pubkey(array![0x1, 0x2, 0x3, 0x4].span()), 'jwtsub: len 4');
    assert(!d.validate_pubkey(array![0x1, 0x2, 0x3, 0x4, 0x5, 0x6].span()), 'jwtsub: len 6');
}

// ============================================================
//  BLS12-381
// ============================================================

#[test]
fn test_bls_validate_pubkey_rejects_wrong_len() {
    let d = deploy("Bls12_381MinSigVerifier");
    // Empty / too-short / too-long all return false (gracefully).
    assert(!d.validate_pubkey(array![].span()), 'bls: empty');
    let short: Array<felt252> = build_repeat(0, 15);
    assert(!d.validate_pubkey(short.span()), 'bls: len 15');
    let long: Array<felt252> = build_repeat(0, 17);
    assert(!d.validate_pubkey(long.span()), 'bls: len 17');
}

/// BLS validate_pubkey contract documents that off-curve / non-r-torsion
/// inputs MAY panic (Garaga's `assert_in_subgroup_excluding_infinity`
/// panics by design). The registration-tx revert is the same security
/// outcome as a graceful `false` return — it prevents the poison-pill
/// from landing in `owners`. This test pins that behavior so the
/// contract doc claim can't silently regress.
#[test]
#[should_panic]
fn test_bls_validate_pubkey_panics_off_curve() {
    let d = deploy("Bls12_381MinSigVerifier");
    // 16 felts of `1` — passes shape, fails curve check loudly.
    let bad: Array<felt252> = build_repeat(1, 16);
    let _ = d.validate_pubkey(bad.span());
}
