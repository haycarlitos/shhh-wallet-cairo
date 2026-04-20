//! Shhh Wallet — V8 (robust-from-day-one)
//!
//! Reference implementation for the proposed pluggable-signer SNIP and
//! audit-response to the 2026-04-20 Codex/Cairo report. See:
//!   - docs/shhh-v8-robust-plan.md
//!   - docs/snip-draft-pluggable-signer.md
//!   - docs/audit-response-omar.md
//!   - https://github.com/starknet-io/SNIPs/pull/163  (session-keys SNIP — already merged)
//!
//! V7 (mainnet class `0x2e599a09…`) source remains in `wallet.cairo` +
//! `outside_execution.cairo` + `ed25519/` for reference during the
//! migration period. New code lives under `signer/`, `owner_set/`,
//! `governance/`, `recovery/`, `session_key/`, `spending_policy/`,
//! and the entry point is `account::ShhhAccount`.

// ---------- V7 (retained for reference until mainnet cut-over) ----------
pub mod wallet;
pub mod outside_execution;
pub mod ed25519 {
    pub mod interface;
    pub mod component;
}

// ---------- V8 ----------
pub mod signer {
    pub mod interface;
    pub mod ed25519 {
        pub mod verifier;
    }
    pub mod secp256k1 {
        pub mod verifier;
    }
    pub mod webauthn_p256 {
        pub mod verifier;
    }
    pub mod stark {
        pub mod verifier;
    }
}

pub mod owner_set {
    pub mod interface;
    pub mod component;
}

pub mod governance {
    pub mod pending_ops;
    pub mod component;
}

pub mod recovery {
    pub mod component;
}

pub mod session_key {
    pub mod interface;
    pub mod component;
}

pub mod spending_policy {
    pub mod interface;
    pub mod component;
}

pub mod account;
