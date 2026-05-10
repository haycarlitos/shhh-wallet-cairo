//! STARK-curve ECDSA verifier class. Wraps `core::ecdsa::check_ecdsa_signature`.
//! Deployed once, declared as a library class, referenced by `verifier_classes['STARK']`
//! in every ShhhAccount that trusts the STARK curve for an owner.

#[starknet::contract]
pub mod StarkVerifier {
    use core::ecdsa::check_ecdsa_signature;
    use crate::signer::interface::{ISigner, KIND_STARK};

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
            // STARK owner envelope payload: [r, s]
            // pubkey is a single felt252
            if pubkey.len() != 1_u32 {
                return false;
            }
            if signature.len() != 2_u32 {
                return false;
            }
            check_ecdsa_signature(message_hash, *pubkey.at(0), *signature.at(0), *signature.at(1))
        }

        fn kind(self: @ContractState) -> felt252 {
            KIND_STARK
        }

        /// Audit M-1 (V8.2) — STARK pubkey is a single non-zero felt252.
        /// No curve check beyond shape: any non-zero felt252 fits in the
        /// STARK prime field. Off-curve points are rejected at verify
        /// time by `check_ecdsa_signature` returning false.
        fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
            if pubkey.len() != 1_u32 {
                return false;
            }
            let pk: felt252 = *pubkey.at(0);
            if pk == 0 {
                false
            } else {
                true
            }
        }
    }
}
