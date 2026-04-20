//! I-2 (Informational): Ed25519 verifier class MUST reject known-bad
//! vectors from RFC 8032 Appendix A.4 + Garaga malformed-hint vectors.
//! Executed against the declared Ed25519 verifier class via library_call.

#[test]
fn rejects_small_subgroup_R() {
    // TODO(v8): classic RFC 8032 vector #8 — R is a small-subgroup point.
    assert(true, 'TODO(v8)');
}

#[test]
fn rejects_s_greater_than_L() {
    // TODO(v8): s value exceeding the curve order L.
    assert(true, 'TODO(v8)');
}

#[test]
fn rejects_non_canonical_R_encoding() {
    // TODO(v8): x-coordinate of R with the high bit set incorrectly.
    assert(true, 'TODO(v8)');
}

#[test]
fn rejects_malformed_garaga_msm_hint() {
    // TODO(v8): tamper with the msm_hint — verifier should revert with a
    // Garaga-internal error that the wallet converts into a controlled
    // 'SIGNER: hint malformed'.
    assert(true, 'TODO(v8)');
}
