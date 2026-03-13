pub trait HasOwner<TContractState> {
    fn get_owner_keys(self: @TContractState) -> (felt252, felt252);
}

#[starknet::component]
pub mod Ed25519WalletComponent {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use super::HasOwner;

    #[storage]
    pub struct Storage {
        /// Lower 128 bits of Ed25519 pubkey as LE u256 (matches garaga Py_twisted.low)
        pub owner_pubkey_low: felt252,
        /// Upper 128 bits of Ed25519 pubkey as LE u256 (matches garaga Py_twisted.high)
        pub owner_pubkey_high: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {}

    #[generate_trait]
    pub impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +HasOwner<TContractState>,
        +Drop<TContractState>,
    > of InternalTrait<TContractState> {
        fn initializer(
            ref self: ComponentState<TContractState>,
            owner_pubkey_low: felt252,
            owner_pubkey_high: felt252,
        ) {
            self.owner_pubkey_low.write(owner_pubkey_low);
            self.owner_pubkey_high.write(owner_pubkey_high);
        }

        /// Returns (owner_pubkey_low, owner_pubkey_high) — LE u256 halves
        fn _get_owner(self: @ComponentState<TContractState>) -> (felt252, felt252) {
            (self.owner_pubkey_low.read(), self.owner_pubkey_high.read())
        }
    }
}
