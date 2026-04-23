//! P-256 ECDSA verifier class.
//!
//! Serves two roles:
//!   1. Base primitive for WebAuthn (passkeys / Face ID / Touch ID /
//!      Windows Hello / YubiKey / 1Password).
//!   2. Raw P-256 for corporate PIV smart cards, eIDAS eIDs, Apple
//!      DeviceCheck, and any NIST P-256 signer.
//!
//! For the MVP the verifier accepts a pre-hashed message and verifies
//! a raw ECDSA signature over it. Full WebAuthn envelope parsing
//! (authenticatorData || sha256(clientDataJSON), challenge extraction)
//! lands in a WebAuthn-specific wrapper class in a follow-up commit
//! inside this phase. The contract name kept as `WebAuthnP256Verifier`
//! so the kind tag 'WEBAUTHN_P256' matches; the raw-P256 variant will
//! be registered under the 'P256' kind once split.
//!
//! Envelope layout (matches Secp256k1Verifier for consistency):
//!   signature = [ r_low, r_high, s_low, s_high, y_parity ]
//!   pubkey    = [ x_low, x_high, y_low, y_high ]
//!
//! Uses Cairo's built-in `starknet::secp256r1` syscalls via the shared
//! `starknet::secp256_trait::recover_public_key` primitive with the
//! Secp256r1Point generic parameter — the same pattern Cartridge
//! Controller and Argent's passkey guardian use.

#[starknet::contract]
pub mod WebAuthnP256Verifier {
    use starknet::secp256_trait::{Secp256Trait, is_valid_signature};
    use starknet::secp256r1::Secp256r1Point;
    use crate::signer::interface::{ISigner, KIND_WEBAUTHN_P256};

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
            // Envelope is [r_low, r_high, s_low, s_high, y_parity].
            // y_parity is informational — `is_valid_signature` constructs
            // the point directly from (x, y), so parity isn't needed
            // for verification. We still range-check the value so bad
            // envelopes fail cleanly.
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

            // Build the public key point from coordinates. This both
            // validates that (x, y) lies on the P-256 curve and gives us
            // the verifier input.
            let point =
                match Secp256Trait::<Secp256r1Point>::secp256_ec_new_syscall(stored_x, stored_y) {
                Result::Ok(Option::Some(p)) => p,
                Result::Ok(Option::None) => { return false; },
                Result::Err(_) => { return false; },
            };

            is_valid_signature::<Secp256r1Point>(msg_hash_u256, r, s, point)
        }

        fn kind(self: @ContractState) -> felt252 {
            KIND_WEBAUTHN_P256
        }
    }
}
