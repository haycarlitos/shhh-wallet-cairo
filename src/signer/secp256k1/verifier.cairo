//! secp256k1 ECDSA verifier class — MetaMask, WalletConnect, any EVM wallet.
//!
//! TODO(v8):
//!   - Use Garaga's secp256k1 verifier primitives.
//!   - Enforce low-s (reject malleable signatures).
//!   - Support both raw ECDSA and EIP-191 / EIP-712 envelope variants
//!     via separate kind tags.

#[starknet::contract]
pub mod Secp256k1Verifier {
    use crate::signer::interface::{ISigner, KIND_SECP256K1};

    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl ISignerImpl of ISigner<ContractState> {
        fn verify(
            self: @ContractState,
            message_hash: felt252,
            pubkey: Span<felt252>,
            signature: Span<felt252>,
        ) -> bool {
            // pubkey layout: [x_low, x_high, y_low, y_high] — uncompressed point
            if pubkey.len() != 4_u32 {
                return false;
            }
            // signature layout: [r_low, r_high, s_low, s_high, v]
            if signature.len() != 5_u32 {
                return false;
            }
            let _ = message_hash;
            core::panic_with_felt252('SECP256K1: not yet implemented')
        }

        fn kind(self: @ContractState) -> felt252 {
            KIND_SECP256K1
        }
    }
}
