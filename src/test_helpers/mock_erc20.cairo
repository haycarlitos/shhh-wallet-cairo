//! Minimal ERC-20 stand-in used by the session-key spending-cap E2E
//! test (`tests/account_sessions_e2e.cairo`). It implements just enough
//! of the ERC-20 surface for `SpendingPolicyComponent::is_spending_selector`
//! to recognise the call (`transfer`) and for the atomic multicall
//! executor to get a successful (non-reverting) subcall back.
//!
//! `transfer(recipient: ContractAddress, amount: u256)` serialises to the
//! calldata layout the spending policy reads — `[recipient, amount.low,
//! amount.high]` — so an in-cap session spend lands here and an over-cap
//! one is rejected by the account before this contract is ever called.
//!
//! Not used in production — purely test infrastructure. Declaring it adds
//! a separate class; it does not affect the `ShhhAccount` class hash.

use starknet::ContractAddress;

#[starknet::interface]
pub trait IMockErc20<TContractState> {
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
    /// Number of successful `transfer` calls — proves the in-cap spend
    /// actually reached the token (vs. being rejected at the policy gate).
    fn transfer_count(self: @TContractState) -> u32;
    /// Cumulative amount moved through `transfer` — lets the test assert
    /// that exactly the in-cap amounts (and none of the over-cap ones) ran.
    fn total_transferred(self: @TContractState) -> u256;
}

#[starknet::contract]
pub mod MockErc20 {
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        transfer_count: u32,
        total_transferred: u256,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl MockErc20Impl of super::IMockErc20<ContractState> {
        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
            self.transfer_count.write(self.transfer_count.read() + 1);
            self.total_transferred.write(self.total_transferred.read() + amount);
            true
        }

        fn transfer_count(self: @ContractState) -> u32 {
            self.transfer_count.read()
        }

        fn total_transferred(self: @ContractState) -> u256 {
            self.total_transferred.read()
        }
    }
}
