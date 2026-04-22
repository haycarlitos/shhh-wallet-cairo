//! Shhh Wallet — V8 audit-closed build.
//!
//! This revision focuses on shipping a *tested* answer to the
//! 2026-04-20 Codex/Cairo audit and the reference implementation for
//! the proposed pluggable-signer SNIP. Every audit finding is fixed
//! in-place on the V7 codebase (`wallet.cairo`, `outside_execution.cairo`,
//! `ed25519/`), and the `signer/` tree introduces the `ISigner` trait
//! + a STARK reference verifier class that demonstrates the pluggable
//! dispatch pattern end-to-end.
//!
//! The ambitious multi-signer / social-recovery / timelocked-governance
//! components live on disk under `src/owner_set/`, `src/governance/`,
//! `src/recovery/`, `src/session_key/`, `src/spending_policy/`. They
//! compile in isolation during the incremental build-out track laid
//! out in `docs/shhh-v8-robust-plan.md`, but are not wired into the
//! production module tree until their tests are green. Doing this
//! keeps the audit-response build small, reviewable, and deployable.

// ----- Audit-closed V7 core (retained + patched in-place) -----
pub mod outside_execution;
pub mod wallet;
pub mod ed25519 {
    pub mod component;
    pub mod interface;
}

// ----- New pluggable-signer layer (reference impl for the SNIP) -----
pub mod signer {
    pub mod interface;
    pub mod ed25519 {
        pub mod verifier;
    }
    pub mod stark {
        pub mod verifier;
    }
}

// ----- V8 account (Phase 3 — single-owner dispatcher) -----
pub mod account;

// ----- Test helpers (declared so snforge can deploy them) -----
pub mod test_helpers {
    pub mod target;
}
