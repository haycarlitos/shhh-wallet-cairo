/// Session key interface definitions.
///
/// This module contains the public types, traits, and constants for the
/// session key management system.  Any wallet embedding the SessionKeyComponent
/// should re-export these for callers and tests.

/// Stored per-session-key data.
#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct SessionData {
    pub valid_until: u64,
    pub max_calls: u32,
    pub calls_used: u32,
    pub allowed_entrypoints_len: u32,
}

/// External interface for session key management.
#[starknet::interface]
pub trait ISessionKeyManager<TContractState> {
    fn add_or_update_session_key(
        ref self: TContractState,
        session_key: felt252,
        valid_until: u64,
        max_calls: u32,
        allowed_entrypoints: Array<felt252>
    );
    fn revoke_session_key(ref self: TContractState, session_key: felt252);
    fn get_session_data(self: @TContractState, session_key: felt252) -> SessionData;
}

/// SRC-5 interface ID for ISessionKeyManager.
/// Computed as: starknetKeccak("add_or_update_session_key")
///            ^ starknetKeccak("revoke_session_key")
///            ^ starknetKeccak("get_session_data")
pub const SESSION_KEY_MANAGER_ID: felt252 =
    0x037ab4f01106526662a612eaa2926df2aa314c4144b964f183805880bbcfa55d;
