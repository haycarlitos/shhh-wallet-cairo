//! Owner-set interface. An OwnerRecord identifies one authorized signer
//! on the account. The set is mutable via threshold-authorized governance
//! operations (see `governance/pending_ops.cairo`).

use starknet::storage_access::StorageBaseAddress;

// ------------------------------------------------------------------
// Roles
// ------------------------------------------------------------------

pub const ROLE_OWNER:         felt252 = 'OWNER';
pub const ROLE_GUARDIAN:      felt252 = 'GUARDIAN';
pub const ROLE_RECOVERY_ONLY: felt252 = 'RECOVERY_ONLY';

// ------------------------------------------------------------------
// Record
// ------------------------------------------------------------------

/// One owner's metadata. The full public key bytes are kept in a separate
/// append-only byte log; `pubkey_hash` is the Poseidon commitment used for
/// fast comparison and for address-salt derivation.
#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct OwnerRecord {
    pub kind:         felt252,   // one of the signer-SNIP kind tags
    pub pubkey_hash:  felt252,   // poseidon(kind, pubkey_bytes...)
    pub pubkey_len:   u32,       // length of the pubkey bytes segment
    pub pubkey_slot:  u64,       // offset into the pubkey_bytes map
    pub role:         felt252,   // ROLE_OWNER | ROLE_GUARDIAN | ROLE_RECOVERY_ONLY
    pub weight:       u8,        // weight for threshold schemes; 1 = standard
    pub added_at:     u64,       // block_timestamp at insertion
    pub label:        felt252,   // user-provided tag; optional
    pub revoked:      bool,      // tombstone; kept so owner_id remains stable
}

// ------------------------------------------------------------------
// External trait
// ------------------------------------------------------------------

#[starknet::interface]
pub trait IOwnerSet<TContractState> {
    fn get_owner(self: @TContractState, owner_id: u32) -> OwnerRecord;
    fn find_owner_by_hash(self: @TContractState, pubkey_hash: felt252) -> Option<u32>;
    fn owner_count(self: @TContractState) -> u32;
    fn active_owner_count(self: @TContractState) -> u32;
    fn total_weight(self: @TContractState) -> u32;
    fn threshold(self: @TContractState) -> u8;
    fn primary_owner_id(self: @TContractState) -> u32;
}

// ------------------------------------------------------------------
// Invariants — enforced on every mutation
// ------------------------------------------------------------------

pub const ERR_ZERO_OWNERS:           felt252 = 'OWNERS: zero active owners';
pub const ERR_THRESHOLD_TOO_HIGH:    felt252 = 'OWNERS: threshold > weight';
pub const ERR_THRESHOLD_ZERO:        felt252 = 'OWNERS: threshold == 0';
pub const ERR_DUPLICATE_HASH:        felt252 = 'OWNERS: duplicate pubkey_hash';
pub const ERR_UNKNOWN_OWNER:         felt252 = 'OWNERS: unknown owner_id';
pub const ERR_PRIMARY_IMMUTABLE:     felt252 = 'OWNERS: primary immutable';
pub const ERR_ROLE_INVALID:          felt252 = 'OWNERS: invalid role';
pub const ERR_WEIGHT_ZERO:           felt252 = 'OWNERS: weight == 0';
