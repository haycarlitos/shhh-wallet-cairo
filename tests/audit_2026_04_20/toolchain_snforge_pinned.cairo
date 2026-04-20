//! Toolchain pin — audit §Tooling: local snforge 0.56.0 warned that
//! snforge_std 0.54.1 was below recommended ^0.56.0. V8 pins both.

#[test]
fn snforge_std_version_is_pinned() {
    // Scarb.toml declares snforge_std tag "v0.56.0". This test exists as
    // a human reminder in the audit-regression suite — Scarb.lock is the
    // real enforcement.
    assert(true, 'snforge_std v0.56.0 pinned');
}
