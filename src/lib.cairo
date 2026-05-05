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
    pub mod secp256k1 {
        pub mod verifier;
    }
    pub mod stark {
        pub mod verifier;
    }
    pub mod webauthn_p256 {
        pub mod verifier;
    }
    pub mod p256 {
        pub mod verifier;
    }
    pub mod eip191_secp256k1 {
        pub mod verifier;
    }
    pub mod eip712_secp256k1 {
        pub mod verifier;
    }
    pub mod jwt_es256 {
        pub mod verifier;
    }
    pub mod jwt_es256_apple_sub {
        pub mod verifier;
    }
    pub mod bls12_381 {
        pub mod verifier;
    }
}

// ----- Multi-owner storage (Phase 4) -----
pub mod owner_set {
    pub mod component;
    pub mod interface;
}

// ----- Timelocked governance (Phase 5) -----
pub mod governance {
    pub mod component;
    pub mod pending_ops;
}

// ----- Guardian recovery (Phase 6) -----
pub mod recovery {
    pub mod component;
}

// ----- Session keys + spending policy (Phase 7, from SNIPs#163) -----
pub mod session_key {
    pub mod component;
    pub mod interface;
}
pub mod spending_policy {
    pub mod component;
    pub mod interface;
}

// ----- V8 account (Phase 3 dispatcher + Phase 4 multi-owner) -----
pub mod account;

// ----- Test helpers (declared so snforge can deploy them) -----
pub mod test_helpers {
    pub mod reentrant_target;
    pub mod target;
}
