//! Ed25519 verifier class. Uses Garaga v1.0.1's on-chain Ed25519 primitive
//! (`is_valid_eddsa_signature`). Expected calldata encoding matches what
//! the V7 Shhh wallet produced — the audit-closed V7 Ed25519 logic is
//! lifted into this class unchanged.
//!
//! TODO(v8):
//!   - Port the EdDSASignatureWithHint serde + verification flow from
//!     V7 `src/wallet.cairo::execute_from_outside_v2` into this class.
//!   - Reject `s >= L`, small-subgroup R, non-canonical encoding
//!     (audit I-2 negative vectors).
//!   - Post-deserialize emptiness check on the signature span (audit M-4).

#[starknet::contract]
pub mod Ed25519Verifier {
    use crate::signer::interface::{ISigner, KIND_ED25519};

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
            // pubkey layout: [low_u128, high_u128]
            if pubkey.len() != 2_u32 { return false; }

            // signature envelope layout (from V7, post-audit):
            //   [ Ry_low, Ry_high, s_low, s_high,
            //     msg_len, msg_bytes...,
            //     msm_hint..., sqrt_Rx_hint..., sqrt_Px_hint... ]
            //
            // The canonical message bytes are the SNIP-12 typed-data hash
            // re-encoded as 64 hex-ASCII bytes (preserves Phantom's
            // "show the user a hex string" UX).
            let _ = message_hash;
            let _ = signature;

            // TODO(v8): lift V7's `execute_from_outside_v2` Ed25519 path
            // verbatim, minus the audit findings:
            //   - H-1: panic on sub-call failure (not relevant in verifier)
            //   - M-4: assert(signature.len() >= 5 + msg_len)
            //   - M-4: assert(sig_span.is_empty()) after Serde
            //   - I-2: reject small-subgroup R / s >= L
            core::panic_with_felt252('ED25519: not yet implemented')
        }

        fn kind(self: @ContractState) -> felt252 { KIND_ED25519 }
    }
}
