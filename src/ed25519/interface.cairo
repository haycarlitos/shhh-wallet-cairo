#[starknet::interface]
pub trait IShhhWallet<TContractState> {
    fn get_owner(self: @TContractState) -> (felt252, felt252);
}
