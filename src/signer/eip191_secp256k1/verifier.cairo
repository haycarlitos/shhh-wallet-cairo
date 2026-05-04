//! EIP-191 secp256k1 verifier class — MetaMask, WalletConnect, Coinbase
//! Wallet, Rabby, every EVM wallet that exposes `personal_sign`.
//!
//! Why a separate class from `Secp256k1Verifier`:
//! MetaMask doesn't expose raw secp256k1 signing — only `personal_sign`
//! and `eth_signTypedData_v4`, both of which prepend their own bytes
//! to the message before hashing + signing. The raw `Secp256k1Verifier`
//! expects a sig directly over the SNIP-12 hash, which requires
//! low-level key access most wallets don't expose. This class accepts
//! the `personal_sign` envelope as the wallet ships it.
//!
//! EIP-191 v0x45 personal_sign recipe (Ethereum yellow paper § Appendix F):
//!
//!     prefix      = "\x19Ethereum Signed Message:\n32"
//!     msg_be_bytes = 32-byte big-endian encoding of the SNIP-12 hash
//!     eip191_hash  = keccak256(prefix || msg_be_bytes)   // BE-interpreted u256
//!     sig          = secp256k1_sign(eip191_hash, priv_key)
//!
//! The verifier recomputes `eip191_hash` from the SNIP-12 hash the
//! account passes in, then runs the standard `recover_public_key`
//! match against the stored owner pubkey.
//!
//! Envelope layout (same shape as raw secp256k1 verifier):
//!   [ r_low, r_high, s_low, s_high, y_parity ]   // 5 felts
//! Pubkey layout:
//!   [ x_low, x_high, y_low, y_high ]             // 4 felts

#[starknet::contract]
pub mod EIP191Secp256k1Verifier {
    use core::keccak::compute_keccak_byte_array;
    use starknet::secp256_trait::{Secp256PointTrait, Signature, recover_public_key};
    use starknet::secp256k1::Secp256k1Point;
    use crate::signer::interface::{ISigner, KIND_EIP191_SECP256K1};

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

            // --- Compute the EIP-191 hash that the wallet actually signed ---
            let eip191_hash = compute_eip191_hash(message_hash);

            // --- Recover + match ---
            let sig = Signature { r, s, y_parity };
            match recover_public_key::<Secp256k1Point>(eip191_hash, sig) {
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
            KIND_EIP191_SECP256K1
        }
    }

    /// Computes `keccak256("\x19Ethereum Signed Message:\n32" || hash_be_32)`
    /// as a BE-interpreted u256 (the same value MetaMask / ethers / web3.py
    /// hash internally before signing).
    ///
    /// Uses Cairo stdlib's `compute_keccak_byte_array` (returns LE u256)
    /// then byte-reverses to BE — this is the canonical pattern stdlib
    /// itself uses in `eth_signature.cairo` (`public_key_point_to_eth_address`).
    fn compute_eip191_hash(message_hash: felt252) -> u256 {
        let msg_u256: u256 = message_hash.into();
        let mut buf: ByteArray = "\x19Ethereum Signed Message:\n32";
        // 32 BE bytes of message_hash: 16 bytes from `high`, then 16 from `low`.
        buf.append_word(msg_u256.high.into(), 16);
        buf.append_word(msg_u256.low.into(), 16);

        let le = compute_keccak_byte_array(@buf);
        u256 {
            low: core::integer::u128_byte_reverse(le.high),
            high: core::integer::u128_byte_reverse(le.low),
        }
    }
}
