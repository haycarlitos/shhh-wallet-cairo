//! Timelocked governance operations. Every structural mutation to the
//! account — add owner, remove owner, rotate owner, change threshold,
//! add/remove verifier class, add/remove guardian — goes through the same
//! pattern:
//!
//!     1. `propose_op(op)` stores a PendingOp with `valid_after = now + timelock`.
//!     2. Owners can call `cancel_pending_op(op_id)` at any time during the
//!        window.
//!     3. After the window, anyone can call `execute_pending_op(op_id)`.
//!
//! Timelocks protect against: compromised signer, social engineering,
//! and key-leak incidents the user has seconds to seconds-to-days to
//! detect.

// ------------------------------------------------------------------
// Operation kinds
// ------------------------------------------------------------------

pub const OP_ADD_OWNER: felt252 = 'ADD_OWNER';
pub const OP_REMOVE_OWNER: felt252 = 'REMOVE_OWNER';
pub const OP_ROTATE_OWNER: felt252 = 'ROTATE_OWNER';
pub const OP_SET_THRESHOLD: felt252 = 'SET_THRESHOLD';
pub const OP_ADD_VERIFIER_CLASS: felt252 = 'ADD_VERIFIER';
pub const OP_REMOVE_VERIFIER_CLASS: felt252 = 'REMOVE_VERIFIER';
pub const OP_ADD_GUARDIAN: felt252 = 'ADD_GUARDIAN';
pub const OP_REMOVE_GUARDIAN: felt252 = 'REMOVE_GUARDIAN';
pub const OP_INITIATE_RECOVERY: felt252 = 'INIT_RECOVERY';
pub const OP_FINALIZE_RECOVERY: felt252 = 'FIN_RECOVERY';

// ------------------------------------------------------------------
// Default timelock windows (seconds). Can be overridden per account at
// deploy time.
// ------------------------------------------------------------------

pub const TIMELOCK_ADD_OWNER: u64 = 172_800; // 48h
pub const TIMELOCK_REMOVE_OWNER: u64 = 86_400; // 24h
pub const TIMELOCK_ROTATE_OWNER: u64 = 86_400; // 24h
pub const TIMELOCK_SET_THRESHOLD: u64 = 172_800; // 48h
pub const TIMELOCK_ADD_VERIFIER: u64 = 172_800; // 48h
pub const TIMELOCK_REMOVE_VERIFIER: u64 = 86_400; // 24h
pub const TIMELOCK_ADD_GUARDIAN: u64 = 86_400; // 24h
pub const TIMELOCK_REMOVE_GUARDIAN: u64 = 86_400; // 24h
pub const TIMELOCK_RECOVERY: u64 = 604_800; // 7d — Argent-aligned

// ------------------------------------------------------------------
// Pending operation record
// ------------------------------------------------------------------

#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct PendingOp {
    pub op_kind: felt252, // OP_* constant
    pub proposer: u32, // owner_id
    pub proposed_at: u64, // block_timestamp of proposal
    pub valid_after: u64, // earliest execution timestamp
    pub expires_at: u64, // latest execution timestamp (prevents stale ops)
    pub payload: felt252, // poseidon commitment of op-specific arguments
    pub executed: bool,
    pub cancelled: bool,
}

pub const ERR_OP_NOT_READY: felt252 = 'OP: timelock not elapsed';
pub const ERR_OP_EXPIRED: felt252 = 'OP: expired';
pub const ERR_OP_EXECUTED: felt252 = 'OP: already executed';
pub const ERR_OP_CANCELLED: felt252 = 'OP: cancelled';
pub const ERR_OP_UNKNOWN: felt252 = 'OP: unknown op_id';
pub const ERR_OP_PAYLOAD: felt252 = 'OP: payload mismatch';

/// Standard op expiry window (14 days). Longer than any timelock so that
/// a proposal always has at least 24h of executable window, but short
/// enough that stale operations don't accumulate forever.
pub const DEFAULT_OP_EXPIRY_SECONDS: u64 = 1_209_600;
