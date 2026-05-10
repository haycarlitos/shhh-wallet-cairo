//! EIP-712 typed-data secp256k1 verifier — MetaMask `eth_signTypedData_v4`.
//!
//! Why a third secp256k1 verifier (in addition to raw + EIP-191):
//! `eth_signTypedData_v4` is the structured-data popup MetaMask
//! shows when a dapp wants the user to sign something with named
//! fields ("Domain: Shhh, hash: 0x…") instead of a raw hex blob. This
//! is the ergonomic path most modern EVM dapps default to for non-tx
//! signing because users can read what they're approving.
//!
//! Recipe (EIP-712 v0x01 final-hash):
//!
//!     domain_separator = keccak256(
//!         DOMAIN_TYPEHASH ||
//!         NAME_HASH ||
//!         VERSION_HASH ||
//!         chainId  (uint256, 32 BE bytes) ||
//!         salt     (bytes32, 32 BE bytes — the V8 account address)
//!     )
//!     struct_hash      = keccak256(MSG_TYPEHASH || msg_hash_be32)
//!     eip712_hash      = keccak256("\x19\x01" || domain_separator || struct_hash)
//!     sig              = secp256k1_sign(eip712_hash, priv_key)
//!
//! Domain shape:
//!
//!     EIP712Domain(string name,string version,uint256 chainId,bytes32 salt)
//!
//! We use the standard EIP-712 `salt` field (also `bytes32`) to carry
//! the Starknet account address rather than `verifyingContract`. This
//! is lossless (Starknet addresses are 252-bit felts; bytes32 fits
//! them) and avoids ethers v6's ENS-resolution path which fires when
//! `verifyingContract` is a non-20-byte value.
//!
//! Struct shape:
//!
//!     MessageHash(bytes32 hash)
//!
//! Where `hash` is the SNIP-12 OE hash the account passed to verify().
//! This produces a popup like:
//!
//!     Sign Typed Data v4
//!     Domain:
//!       name: Shhh
//!       version: 1
//!       chainId: 393402133025997798000961  (= 'SN_MAIN' as uint256)
//!       salt: 0x01d6e475... (the V8 account address)
//!     MessageHash:
//!       hash: 0x5bcd634c...
//!
//! Envelope layout (same shape as raw + EIP-191):
//!   [ r_low, r_high, s_low, s_high, y_parity ]   // 5 felts
//! Pubkey layout:
//!   [ x_low, x_high, y_low, y_high ]             // 4 felts

#[starknet::contract]
pub mod EIP712Secp256k1Verifier {
    use core::keccak::{compute_keccak_byte_array, keccak_u256s_be_inputs};
    use starknet::secp256_trait::{Secp256PointTrait, Signature, recover_public_key};
    use starknet::secp256k1::Secp256k1Point;
    use starknet::{get_contract_address, get_tx_info};
    use crate::signer::interface::{ISigner, KIND_EIP712_SECP256K1};

    // ------------------------------------------------------------------
    // Precomputed type hashes (keccak256 of the canonical strings).
    // Computed off-chain with ethers `keccak256(toUtf8Bytes(...))` and
    // pinned here. Any edit to the domain or struct shape MUST update
    // these constants — silent drift would produce signatures the
    // verifier accepts but MetaMask doesn't render coherently.
    // ------------------------------------------------------------------

    /// keccak256("EIP712Domain(string name,string version,uint256 chainId,bytes32 salt)")
    const DOMAIN_TYPEHASH: u256 =
        0xa604fff5a27d5951f334ccda7abff3286a8af29caeeb196a6f2b40a1dce7612b_u256;

    /// keccak256("Shhh")
    const NAME_HASH: u256 = 0x739833112d6eabd360f8f9f248eda53e82afe789ed3866e609dcec4ac4fd8916_u256;

    /// keccak256("1")
    const VERSION_HASH: u256 =
        0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6_u256;

    /// keccak256("MessageHash(bytes32 hash)")
    const MSG_TYPEHASH: u256 =
        0xddbb42c14c926ce2b204d00ecc48d770e111c85fe954c1bbbb4a7f6f4b2fbbb9_u256;

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

            // --- Compute EIP-712 final hash from runtime context ---
            // chainId comes from the tx itself, verifyingContract is the
            // account address (we are running inside the account via
            // library_call_syscall). This binds each signature to one
            // specific account on one specific chain — replay across
            // either dimension fails because the domain separator
            // differs.
            let chain_id_felt = get_tx_info().unbox().chain_id;
            let account_addr_felt: felt252 = get_contract_address().into();

            let domain_separator = compute_domain_separator(chain_id_felt, account_addr_felt);
            let struct_hash = compute_struct_hash(message_hash);
            let eip712_hash = compute_final_hash(domain_separator, struct_hash);

            // --- Recover + match ---
            let sig = Signature { r, s, y_parity };
            match recover_public_key::<Secp256k1Point>(eip712_hash, sig) {
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
            KIND_EIP712_SECP256K1
        }

        /// Audit M-1 (V8.2) — same `(x, y)` secp256k1 pubkey shape +
        /// on-curve check as EIP-191 / raw secp256k1. Graceful.
        fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
            if pubkey.len() != 4_u32 {
                return false;
            }
            let x_low: u128 = match (*pubkey.at(0)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let x_high: u128 = match (*pubkey.at(1)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let y_low: u128 = match (*pubkey.at(2)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let y_high: u128 = match (*pubkey.at(3)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let x = u256 { low: x_low, high: x_high };
            let y = u256 { low: y_low, high: y_high };
            match starknet::secp256_trait::Secp256Trait::<
                starknet::secp256k1::Secp256k1Point,
            >::secp256_ec_new_syscall(x, y) {
                Result::Ok(Option::Some(_)) => true,
                Result::Ok(Option::None) => false,
                Result::Err(_) => false,
            }
        }
    }

    // ------------------------------------------------------------------
    // EIP-712 hash helpers
    // ------------------------------------------------------------------

    /// `keccak256(DOMAIN_TYPEHASH || NAME_HASH || VERSION_HASH || chainId || salt)`.
    /// All five inputs are 32 BE bytes each (160 bytes total). `salt`
    /// carries the V8 account address (32 BE bytes of the Starknet felt).
    fn compute_domain_separator(chain_id: felt252, account_addr: felt252) -> u256 {
        let chain_u256: u256 = chain_id.into();
        let salt_u256: u256 = account_addr.into();
        keccak_be([DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, chain_u256, salt_u256].span())
    }

    /// `keccak256(MSG_TYPEHASH || msg_hash_be32)`. 64 bytes total.
    fn compute_struct_hash(message_hash: felt252) -> u256 {
        let msg_u256: u256 = message_hash.into();
        keccak_be([MSG_TYPEHASH, msg_u256].span())
    }

    /// `keccak256("\x19\x01" || domain_separator || struct_hash)`. 66 bytes
    /// total. Not 32-byte aligned, so we use `compute_keccak_byte_array`
    /// instead of `keccak_u256s_be_inputs`.
    fn compute_final_hash(domain_separator: u256, struct_hash: u256) -> u256 {
        let mut buf: ByteArray = "\x19\x01";
        // 32 BE bytes of domain_separator, then 32 BE bytes of struct_hash.
        buf.append_word(domain_separator.high.into(), 16);
        buf.append_word(domain_separator.low.into(), 16);
        buf.append_word(struct_hash.high.into(), 16);
        buf.append_word(struct_hash.low.into(), 16);

        let le = compute_keccak_byte_array(@buf);
        u256 {
            low: core::integer::u128_byte_reverse(le.high),
            high: core::integer::u128_byte_reverse(le.low),
        }
    }

    /// Wraps `keccak_u256s_be_inputs` and converts the result from the
    /// stdlib's "LE u256" output to the BE u256 ethers / Solidity treat
    /// the digest as. Same pattern stdlib uses in
    /// `core::starknet::eth_signature::public_key_point_to_eth_address`.
    fn keccak_be(inputs: Span<u256>) -> u256 {
        let le = keccak_u256s_be_inputs(inputs);
        u256 {
            low: core::integer::u128_byte_reverse(le.high),
            high: core::integer::u128_byte_reverse(le.low),
        }
    }
}
