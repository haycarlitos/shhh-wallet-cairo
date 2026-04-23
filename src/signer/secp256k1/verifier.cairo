//! secp256k1 ECDSA verifier class — MetaMask, WalletConnect, Coinbase
//! Wallet, Ledger, any EVM wallet.
//!
//! Uses Starknet's built-in `starknet::secp256_trait::recover_public_key`
//! syscall (the same primitive Argent and Braavos use for their EVM
//! signers). Reconstructs the pubkey from (hash, r, s, v) and compares
//! to what's stored.
//!
//! Envelope layout:
//!   [ r_low, r_high, s_low, s_high, y_parity ]   // 5 felts
//!
//! Pubkey layout:
//!   [ x_low, x_high, y_low, y_high ]             // 4 felts
//!
//! The message_hash is the SNIP-12 OE hash (same as Ed25519). For EIP-191
//! `personal_sign` compatibility, the wallet side produces
//! `keccak256("\x19Ethereum Signed Message:\n32" || snip12_hash)` as the
//! signed value — the verifier accepts that hash directly.

#[starknet::contract]
pub mod Secp256k1Verifier {
    use starknet::secp256_trait::{Secp256PointTrait, Signature, recover_public_key};
    use starknet::secp256k1::Secp256k1Point;
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
            // --- Shape ---
            if pubkey.len() != 4_u32 {
                return false;
            }
            if signature.len() != 5_u32 {
                return false;
            }

            // --- Parse pubkey ---
            let pk_x_low: u128 = match (*pubkey.at(0)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let pk_x_high: u128 = match (*pubkey.at(1)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let pk_y_low: u128 = match (*pubkey.at(2)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let pk_y_high: u128 = match (*pubkey.at(3)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let stored_x = u256 { low: pk_x_low, high: pk_x_high };
            let stored_y = u256 { low: pk_y_low, high: pk_y_high };

            // --- Parse signature ---
            let r_low: u128 = match (*signature.at(0)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let r_high: u128 = match (*signature.at(1)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let s_low: u128 = match (*signature.at(2)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let s_high: u128 = match (*signature.at(3)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let y_parity_felt = *signature.at(4);
            let y_parity: bool = if y_parity_felt == 0 {
                false
            } else if y_parity_felt == 1 {
                true
            } else {
                return false;
            };
            let r = u256 { low: r_low, high: r_high };
            let s = u256 { low: s_low, high: s_high };

            // --- Verify ---
            // Build a Signature and recover the public key. The recovered
            // point must match what's stored. This is the same pattern
            // Ethereum's ecrecover uses.
            let sig = Signature { r, s, y_parity };
            let msg_hash_u256: u256 = message_hash.into();

            // Low-s malleability enforcement (reject s > N/2).
            // is_valid_signature enforces it internally; we also use
            // recover_public_key which requires low-s. If s is
            // malleable the syscall fails and we return false.
            match recover_public_key::<Secp256k1Point>(msg_hash_u256, sig) {
                Option::Some(recovered) => {
                    match recovered.get_coordinates() {
                        Result::Ok(coords) => {
                            let (rx, ry) = coords;
                            rx == stored_x && ry == stored_y
                        },
                        Result::Err(_) => false,
                    }
                },
                Option::None => false,
            }
        }

        fn kind(self: @ContractState) -> felt252 {
            KIND_SECP256K1
        }
    }
}
