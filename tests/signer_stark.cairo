//! STARK-curve verifier shape-guard + cryptographic tests.
//!
//! Mirrors the test shape of `signer_secp256k1.cairo` and
//! `signer_p256.cairo` so every verifier class has the same coverage
//! surface: kind-tag report, envelope shape guards, happy path, wrong
//! key, wrong message, and cryptographic edge cases.
//!
//! Uses `snforge_std::signature::stark_curve::StarkCurveKeyPair` to
//! produce real on-curve signatures — no off-chain fixture file needed.
//! This gives us the same "real ECDSA under test" posture the other
//! verifiers have via their noble-curves / ethers.js fixtures.

use shhh_wallet::signer::interface::{ISignerDispatcher, ISignerDispatcherTrait, KIND_STARK};
use snforge_std::signature::SignerTrait;
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;

fn deploy_verifier() -> ContractAddress {
    let class = declare("StarkVerifier").unwrap().contract_class();
    let (addr, _) = class.deploy(@array![]).unwrap();
    addr
}

fn dispatcher() -> ISignerDispatcher {
    ISignerDispatcher { contract_address: deploy_verifier() }
}

// ==========================================================
// Kind tag
// ==========================================================

#[test]
fn test_stark_verifier_reports_kind() {
    let d = dispatcher();
    assert(d.kind() == KIND_STARK, 'wrong kind');
}

// ==========================================================
// Shape guards — envelope / pubkey length
// ==========================================================

#[test]
fn test_rejects_empty_pubkey() {
    // pubkey MUST be a single felt252 (the x-coordinate). Empty span
    // fails the `pubkey.len() != 1` gate before any curve work.
    let d = dispatcher();
    let ok = d.verify(0xdead, array![].span(), array![1, 2].span());
    assert(!ok, 'empty pubkey accepted');
}

#[test]
fn test_rejects_too_long_pubkey() {
    // STARK pubkey is 1 felt. Anything else is ill-formed — reject.
    // Important because secp256k1 / p256 use 4-felt pubkeys, and a
    // paymaster that misroutes a 4-felt pubkey into the STARK verifier
    // must be caught rather than have the first felt silently used.
    let d = dispatcher();
    let ok = d.verify(0xdead, array![1, 2, 3, 4].span(), array![1, 2].span());
    assert(!ok, 'too-long pubkey accepted');
}

#[test]
fn test_rejects_empty_signature() {
    let d = dispatcher();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0x99);
    let ok = d.verify(0xdead, array![kp.public_key].span(), array![].span());
    assert(!ok, 'empty sig accepted');
}

#[test]
fn test_rejects_sig_too_short() {
    // [r, s] required — passing [r] only short-circuits on len check.
    let d = dispatcher();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0x99);
    let ok = d.verify(0xdead, array![kp.public_key].span(), array![0x1234].span());
    assert(!ok, 'sig len 1 accepted');
}

#[test]
fn test_rejects_sig_too_long() {
    // Trailing felts after (r, s) MUST cause rejection, matching the
    // M-4 shape-check posture of the other verifier classes. No
    // consumer ever intends to sign a STARK envelope with 3+ felts —
    // such shapes are envelope confusion and must be refused.
    let d = dispatcher();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0x99);
    let ok = d.verify(0xdead, array![kp.public_key].span(), array![1, 2, 3].span());
    assert(!ok, 'sig len 3 accepted');
}

// ==========================================================
// Happy path + attack scenarios
// ==========================================================

#[test]
fn test_stark_happy_path_verifies() {
    let d = dispatcher();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0x1234_5678_9abc_def0);
    let message_hash: felt252 = 0xca11ab1ec0ffee;
    let (r, s) = kp.sign(message_hash).unwrap();

    let ok = d.verify(message_hash, array![kp.public_key].span(), array![r, s].span());
    assert(ok, 'happy path must verify');
}

#[test]
fn test_stark_wrong_pubkey_rejects() {
    // Real signature under kp_signer but verifier told the pubkey is
    // kp_attacker's x — curve math rejects.
    let d = dispatcher();
    let kp_signer = StarkCurveKeyPairImpl::from_secret_key(0x1111);
    let kp_attacker = StarkCurveKeyPairImpl::from_secret_key(0x2222);
    let message_hash: felt252 = 0xdeadbeef;
    let (r, s) = kp_signer.sign(message_hash).unwrap();

    let ok = d.verify(message_hash, array![kp_attacker.public_key].span(), array![r, s].span());
    assert(!ok, 'wrong pubkey accepted');
}

#[test]
fn test_stark_wrong_message_rejects() {
    // Correct key, correct signature for message_a, but verifier is
    // asked about message_b — ECDSA rejects.
    let d = dispatcher();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0xABCDEF);
    let message_a: felt252 = 0xAAAA;
    let message_b: felt252 = 0xBBBB;
    let (r, s) = kp.sign(message_a).unwrap();

    let ok = d.verify(message_b, array![kp.public_key].span(), array![r, s].span());
    assert(!ok, 'wrong message accepted');
}

#[test]
fn test_stark_swapped_r_s_rejects() {
    // Swapping r and s produces a well-formed but invalid envelope for
    // almost every signature. Regression guard against any future
    // refactor that mis-orders the verifier's arguments to
    // check_ecdsa_signature.
    let d = dispatcher();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0xFACE);
    let message_hash: felt252 = 0xfeedface;
    let (r, s) = kp.sign(message_hash).unwrap();

    let ok = d.verify(message_hash, array![kp.public_key].span(), array![s, r].span());
    assert(!ok, 'swapped r/s accepted');
}

#[test]
fn test_stark_zero_signature_rejects() {
    // (r=0, s=0) is not a valid ECDSA signature. `check_ecdsa_signature`
    // MUST return false rather than short-circuit to true.
    let d = dispatcher();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0x7777);
    let ok = d.verify(0xdead, array![kp.public_key].span(), array![0, 0].span());
    assert(!ok, 'zero sig accepted');
}

#[test]
fn test_stark_zero_pubkey_rejects() {
    // pubkey = 0 is off-curve and `check_ecdsa_signature` rejects. Guard
    // against any future regression that treats "uninitialised owner"
    // slots as legitimate.
    let d = dispatcher();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0x42);
    let (r, s) = kp.sign(0xdead).unwrap();
    let ok = d.verify(0xdead, array![0].span(), array![r, s].span());
    assert(!ok, 'zero pubkey accepted');
}

#[test]
fn test_stark_different_messages_produce_different_sigs_each_verifies() {
    // Sanity: two distinct messages under the same key produce
    // distinct signatures, and each verifies against its own message.
    // If a future regression returns a constant-ish signature the
    // first assert fails; if verification is order-sensitive, the
    // second pair of asserts catch it.
    let d = dispatcher();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0xC0FFEE);
    let msg_a: felt252 = 0x1111;
    let msg_b: felt252 = 0x2222;
    let (r_a, s_a) = kp.sign(msg_a).unwrap();
    let (r_b, s_b) = kp.sign(msg_b).unwrap();
    assert(r_a != r_b || s_a != s_b, 'sigs unexpectedly equal');

    let pk = array![kp.public_key].span();
    assert(d.verify(msg_a, pk, array![r_a, s_a].span()), 'a verify');
    assert(d.verify(msg_b, pk, array![r_b, s_b].span()), 'b verify');
    // Cross-pair MUST fail.
    assert(!d.verify(msg_a, pk, array![r_b, s_b].span()), 'a accepts b-sig');
    assert(!d.verify(msg_b, pk, array![r_a, s_a].span()), 'b accepts a-sig');
}

#[test]
fn test_stark_verify_is_deterministic() {
    // The verifier is a pure computation — calling it twice with the
    // same args MUST produce the same answer. Guards against any
    // future accidental reliance on ambient state (block timestamp,
    // tx info, RNG, etc.).
    let d = dispatcher();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0x5005);
    let message_hash: felt252 = 0xabcd;
    let (r, s) = kp.sign(message_hash).unwrap();
    let pk = array![kp.public_key].span();
    let ok_1 = d.verify(message_hash, pk, array![r, s].span());
    let ok_2 = d.verify(message_hash, pk, array![r, s].span());
    assert(ok_1 && ok_2, 'non-deterministic verify');
}
