//! P-256 raw-ECDSA verifier class.
//!
//! Accepts a pre-hashed SNIP-12 message and a raw ECDSA (r, s) signature.
//! Use this kind for:
//!   - PIV smart cards (corporate / gov issued)
//!   - eIDAS qualified certificates
//!   - Apple DeviceCheck attestations
//!   - any NIST P-256 signer that produces a raw signature over the
//!     SNIP-12 hash directly, without a WebAuthn envelope.
//!
//! For passkeys / Face ID / Touch ID / Windows Hello / YubiKey FIDO2 use
//! the `WebAuthnP256Verifier` class under kind `'WEBAUTHN_P256'` — that
//! verifier parses `authenticatorData` + `clientDataJSON` and binds the
//! challenge to the SNIP-12 hash.
//!
//! Envelope layout (matches Secp256k1Verifier for consistency):
//!   signature = [ r_low, r_high, s_low, s_high, y_parity ]
//!   pubkey    = [ x_low, x_high, y_low, y_high ]

#[starknet::contract]
pub mod P256Verifier {
    use starknet::secp256_trait::{Secp256Trait, is_valid_signature};
    use starknet::secp256r1::Secp256r1Point;
    use crate::signer::interface::{ISigner, KIND_P256};

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
            if pubkey.len() != 4_u32 {
                return false;
            }
            if signature.len() != 5_u32 {
                return false;
            }

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
            if y_parity_felt != 0 && y_parity_felt != 1 {
                return false;
            }
            let r = u256 { low: r_low, high: r_high };
            let s = u256 { low: s_low, high: s_high };
            let msg_hash_u256: u256 = message_hash.into();

            let point =
                match Secp256Trait::<Secp256r1Point>::secp256_ec_new_syscall(stored_x, stored_y) {
                Result::Ok(Option::Some(p)) => p,
                Result::Ok(Option::None) => { return false; },
                Result::Err(_) => { return false; },
            };

            is_valid_signature::<Secp256r1Point>(msg_hash_u256, r, s, point)
        }

        fn kind(self: @ContractState) -> felt252 {
            KIND_P256
        }

        /// Audit M-1 (V8.2) — P-256 pubkey is `(x, y)` as 4 u128 halves.
        /// On-curve check via `secp256_ec_new_syscall<Secp256r1Point>`.
        /// Graceful (no panic).
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
            match Secp256Trait::<Secp256r1Point>::secp256_ec_new_syscall(x, y) {
                Result::Ok(Option::Some(_)) => true,
                Result::Ok(Option::None) => false,
                Result::Err(_) => false,
            }
        }
    }
}
