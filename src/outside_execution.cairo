use starknet::ContractAddress;
use starknet::account::Call;

#[derive(Drop, Copy, Serde)]
pub struct OutsideExecution {
    pub caller: ContractAddress,
    pub nonce: felt252,
    pub execute_after: u64,
    pub execute_before: u64,
    pub calls: Span<Call>,
}

#[starknet::interface]
pub trait ISRC9_V2<TContractState> {
    fn execute_from_outside_v2(
        ref self: TContractState, outside_execution: OutsideExecution, signature: Span<felt252>,
    ) -> Array<Span<felt252>>;

    fn is_valid_outside_execution_nonce(self: @TContractState, nonce: felt252) -> bool;
}

// SNIP-9 v2 SRC5 interface ID.
//
// Audit H-2: the V7 value (`0x1d1144bb2138571a605b8b8eed8e4e9e04dc40fce40190a11af584935e0a04c`)
// did not match the canonical OZ / SNIP-9 V2 identifier. V8 registers the
// published value. Any dapp that probes SRC-5 for SNIP-9 V2 support now
// gets the correct answer.
pub const ISRC9_V2_ID: felt252 = 0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872;
