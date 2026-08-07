//! BLS12-381 (min-sig-size, drand DST) verifier tests.
//!
//! What this suite proves:
//!
//!   - The verifier reports its kind tag (`KIND_BLS12_381`).
//!   - A canonical Python-generated fixture verifies (full hash-to-curve
//!     + 2P_2F pairing check on chain).
//!   - Shape-level junk envelopes return `false` instead of panicking
//!     (empty signature, wrong-length pubkey, lines_len mismatch).
//!   - A *valid in-subgroup* but wrong signature (signed under a
//!     different scalar) is rejected via `Result::Err` from the
//!     pairing-check helper. This is the "graceful crypto fail" path.
//!   - Submitting the canonical signature against a *valid in-subgroup*
//!     but wrong pubkey is rejected the same way. Catches stale-key
//!     replay or substitution by an off-chain caller.
//!
//! Failure modes that revert (panic) by design — not unit-tested here
//! because they're catastrophic-input cases handled by the dispatcher's
//! revert semantics, not "soft false" returns:
//!   - On-curve but not-in-r-torsion pubkey or signature
//!     (`assert_in_subgroup_excluding_infinity` panics).
//!   - HashToCurveHint inconsistent with the message_hash that was
//!     actually signed (`map_to_curve` square-root assertion panics).
//!   - Truncated mpcheck_hint span (Garaga's deserializer panics on
//!     `unwrap`).
//! All three result in the entire `__execute__` reverting, which is
//! correct for a structurally malformed signature envelope.

use shhh_wallet::signer::interface::{ISignerDispatcher, ISignerDispatcherTrait, KIND_BLS12_381};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use super::signer_bls12_381_fixture::{
    fixture_alt_sig_envelope, fixture_message_hash, fixture_other_pubkey, fixture_pubkey,
    fixture_signature_envelope,
};

fn deploy_verifier() -> ContractAddress {
    let class = declare("Bls12_381MinSigVerifier").unwrap().contract_class();
    let (addr, _) = class.deploy(@array![]).unwrap();
    addr
}

fn dispatcher() -> ISignerDispatcher {
    ISignerDispatcher { contract_address: deploy_verifier() }
}

// ============================================================
//  Identity / kind tag
// ============================================================

#[test]
fn test_bls_verifier_reports_kind() {
    let d = dispatcher();
    assert(d.kind() == KIND_BLS12_381, 'wrong kind');
}

// ============================================================
//  Shape guards (return false; no panic)
// ============================================================

#[test]
fn test_rejects_empty_pubkey() {
    let d = dispatcher();
    let sig = fixture_signature_envelope();
    let ok = d.verify(fixture_message_hash(), array![].span(), sig.span());
    assert(!ok, 'empty pubkey accepted');
}

#[test]
fn test_rejects_truncated_pubkey() {
    let d = dispatcher();
    let pk = fixture_pubkey();
    let mut short: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i != 15 {
        short.append(*pk.at(i));
        i += 1;
    }
    let sig = fixture_signature_envelope();
    let ok = d.verify(fixture_message_hash(), short.span(), sig.span());
    assert(!ok, 'short pubkey accepted');
}

#[test]
fn test_rejects_oversized_pubkey() {
    let d = dispatcher();
    let pk = fixture_pubkey();
    let mut padded: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i != 16 {
        padded.append(*pk.at(i));
        i += 1;
    }
    padded.append(0);
    let sig = fixture_signature_envelope();
    let ok = d.verify(fixture_message_hash(), padded.span(), sig.span());
    assert(!ok, 'oversize pubkey accepted');
}

#[test]
fn test_rejects_empty_signature() {
    let d = dispatcher();
    let pk = fixture_pubkey();
    let ok = d.verify(fixture_message_hash(), pk.span(), array![].span());
    assert(!ok, 'empty signature accepted');
}

/// The lines_len felt sits at offset 20 (sig_g1: 8 + h2c_hint: 12).
/// Setting it to 137 makes the verifier reject before running the Miller
/// loop — the cheap up-front guard that protects against attackers
/// padding the envelope to confuse downstream deserializers.
#[test]
fn test_rejects_wrong_lines_len() {
    let d = dispatcher();
    let pk = fixture_pubkey();
    let sig = fixture_signature_envelope();

    let mut mutated: Array<felt252> = array![];
    let mut i: u32 = 0;
    let len = sig.len();
    while i != len {
        if i == 20 {
            mutated.append(137);
        } else {
            mutated.append(*sig.at(i));
        }
        i += 1;
    }
    let ok = d.verify(fixture_message_hash(), pk.span(), mutated.span());
    assert(!ok, 'wrong lines_len accepted');
}

// ============================================================
//  Cryptographic checks (return false via mpcheck Err)
// ============================================================

#[test]
fn test_happy_path_verifies() {
    let d = dispatcher();
    let pk = fixture_pubkey();
    let sig = fixture_signature_envelope();
    let ok = d.verify(fixture_message_hash(), pk.span(), sig.span());
    assert(ok, 'fresh fixture rejected');
}

/// Submit `sig' = sk_other · H(m)` (still on-curve, still in r-torsion)
/// against the original pubkey. The mpcheck_hint inside the envelope
/// was bound off chain to the original (sig, pk) pair so the
/// transcript-derived `z` mismatches and the helper returns Err.
#[test]
fn test_wrong_signature_rejects() {
    let d = dispatcher();
    let pk = fixture_pubkey();
    let alt_sig = fixture_alt_sig_envelope();
    let ok = d.verify(fixture_message_hash(), pk.span(), alt_sig.span());
    assert(!ok, 'wrong sig accepted');
}

/// Submit the canonical signature against a *different* in-subgroup
/// pubkey. The hint was generated for `pk = sk · G2`; pairing it
/// against a different G2 point breaks the witness → false.
#[test]
fn test_wrong_pubkey_rejects() {
    let d = dispatcher();
    let other_pk = fixture_other_pubkey();
    let sig = fixture_signature_envelope();
    let ok = d.verify(fixture_message_hash(), other_pk.span(), sig.span());
    assert(!ok, 'wrong pubkey accepted');
}
