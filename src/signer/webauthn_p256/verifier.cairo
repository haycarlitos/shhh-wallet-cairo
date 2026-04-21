//! WebAuthn P-256 verifier class — Apple passkeys, Android passkeys,
//! Windows Hello, YubiKey, 1Password.
//!
//! The WebAuthn envelope is:
//!
//!     signed_bytes = authenticatorData || sha256(clientDataJSON)
//!
//! and the SNIP-12 typed-data hash MUST appear in
//! `clientDataJSON.challenge` (base64url-encoded).
//!
//! TODO(v8):
//!   - Use Garaga's P-256 verifier primitives.
//!   - Parse clientDataJSON to extract `.challenge` and assert it matches
//!     the expected SNIP-12 hash.
//!   - Reject non-canonical ECDSA (low-s) and off-curve points.

#[starknet::contract]
pub mod WebAuthnP256Verifier {
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
            // pubkey layout: [x_low, x_high, y_low, y_high]
            if pubkey.len() != 4_u32 {
                return false;
            }
            // signature layout (bounded by M-3):
            //   [ r_low, r_high, s_low, s_high,
            //     auth_data_len, auth_data...,
            //     client_data_len, client_data... ]
            let _ = message_hash;
            let _ = signature;
            core::panic_with_felt252('WEBAUTHN_P256: not yet implemented')
        }

        fn kind(self: @ContractState) -> felt252 {
            KIND_WEBAUTHN_P256
        }
    }
}
