//! Minimal target contract used by the Phase 3 end-to-end test. The
//! account's multicall calls `set_value(x)` through SNIP-9; reading back
//! via `get_value()` confirms that authorization → library_call verify →
//! atomic multicall → subcall all completed.
//!
//! Not used in production — purely test infrastructure.

#[starknet::interface]
pub trait ITarget<TContractState> {
    fn set_value(ref self: TContractState, v: felt252);
    fn get_value(self: @TContractState) -> felt252;
    /// Number of times `set_value` has been invoked. Distinguishes "did
    /// the call execute at all" from "did it execute and write the same
    /// value" — load-bearing for the nonce-replay mutation test.
    fn get_call_count(self: @TContractState) -> u32;
}

#[starknet::contract]
pub mod Target {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        value: felt252,
        call_count: u32,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl TargetImpl of super::ITarget<ContractState> {
        fn set_value(ref self: ContractState, v: felt252) {
            self.value.write(v);
            self.call_count.write(self.call_count.read() + 1);
        }
        fn get_value(self: @ContractState) -> felt252 {
            self.value.read()
        }
        fn get_call_count(self: @ContractState) -> u32 {
            self.call_count.read()
        }
    }
}
