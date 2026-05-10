//! Ed25519 verifier class — Phantom, Solana, and any Ed25519 signer.
//!
//! Dispatched to via `library_call_syscall` from `ShhhAccount` (Phase 3).
//! Also directly testable as a standalone contract so audit and fuzz
//! suites can exercise the primitive without going through the account.
//!
//! Envelope layout (audit-closed, M-4 enforced):
//!
//!     [ Ry_low, Ry_high, s_low, s_high,          // 4 felts, little-endian u256 halves
//!       msg_len,                                  // 1 felt (u32-range)
//!       msg_bytes...,                             // `msg_len` felts, each in u8 range
//!       msm_hint..., sqrt_Rx_hint..., sqrt_Px_hint... ]  // Garaga v1+ hints
//!
//! The signed bytes are the 64-char lowercase hex-ASCII encoding of
//! `message_hash` (32 bytes → 64 ASCII chars). Phantom signs the hex
//! string so users see a human-readable value in the popup while we
//! keep on-chain verification cheap.
//!
//! Audit fixes applied (match V7 wallet.cairo, which is mainnet-deployed
//! and audit-closed):
//!   - M-4: `signature.len() >= 5 + msg_len` asserted before indexing
//!   - M-4: `sig_span.is_empty()` asserted after Serde deserialize
//!   - I-2: malformed-hint rejection comes from Garaga's own
//!          `is_valid_eddsa_signature` (returns false on bad hints);
//!          RFC 8032 negative vectors sit in `tests/signer_ed25519.cairo`
//!
//! Pubkey layout: `[low_u128_felt, high_u128_felt]` — the little-endian
//! u256 halves of the Ed25519 public key bytes (matches Garaga's
//! `Py_twisted` format, same as V7).

#[starknet::contract]
pub mod Ed25519Verifier {
    use garaga::signatures::eddsa_25519::{EdDSASignatureWithHint, is_valid_eddsa_signature};
    use crate::signer::interface::{ISigner, KIND_ED25519};

    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState) {}

    // Lowercase hex ASCII table (0-9, a-f).
    const HEX_CHARS: [u8; 16] = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65,
        0x66,
    ];

    /// Re-encode `message_hash` (a felt252 viewed as 32-byte BE) as 64
    /// lowercase hex-ASCII bytes. This is what Phantom signed.
    fn hash_to_hex_ascii(message_hash: felt252) -> Array<u8> {
        // Convert felt252 → u256, then serialize 32 bytes big-endian.
        let as_u256: u256 = message_hash.into();
        let mut raw: Array<u8> = array![];
        append_u128_be(ref raw, as_u256.high);
        append_u128_be(ref raw, as_u256.low);

        let hex_span = HEX_CHARS.span();
        let mut out: Array<u8> = array![];
        let mut i: u32 = 0;
        while i < raw.len() {
            let b: u16 = (*raw.at(i)).into();
            out.append(*hex_span.at((b / 16).try_into().unwrap()));
            out.append(*hex_span.at((b % 16).try_into().unwrap()));
            i += 1;
        }
        out
    }

    fn append_u128_be(ref bytes: Array<u8>, value: u128) {
        let mut temp: Array<u8> = array![];
        let mut remaining = value;
        let mut i: u32 = 0;
        while i < 16 {
            let byte: u8 = (remaining % 256).try_into().unwrap();
            temp.append(byte);
            remaining = remaining / 256;
            i += 1;
        }
        let mut j: u32 = 16;
        while j > 0 {
            j -= 1;
            bytes.append(*temp.at(j));
        }
    }

    #[abi(embed_v0)]
    impl ISignerImpl of ISigner<ContractState> {
        fn verify(
            self: @ContractState,
            message_hash: felt252,
            pubkey: Span<felt252>,
            signature: Span<felt252>,
        ) -> bool {
            // --- Pubkey shape ---
            if pubkey.len() != 2_u32 {
                return false;
            }
            let low_felt = *pubkey.at(0);
            let high_felt = *pubkey.at(1);
            let owner_low: u128 = match low_felt.try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let owner_high: u128 = match high_felt.try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let owner_u256 = u256 { low: owner_low, high: owner_high };

            // --- Envelope shape (audit M-4) ---
            if signature.len() < 5_u32 {
                return false;
            }
            let msg_len_felt = *signature.at(4);
            let msg_len: u32 = match msg_len_felt.try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            // Expected msg is hex_ascii(message_hash) → always 64 bytes.
            let expected_bytes = hash_to_hex_ascii(message_hash);
            if msg_len != expected_bytes.len() {
                return false;
            }
            if signature.len() < 5_u32 + msg_len {
                return false;
            }

            // --- msg byte match ---
            let mut i: u32 = 0;
            while i < msg_len {
                let msg_byte_felt = *signature.at(5 + i);
                let msg_byte: u8 = match msg_byte_felt.try_into() {
                    Option::Some(v) => v,
                    Option::None => { return false; },
                };
                if msg_byte != *expected_bytes.at(i) {
                    return false;
                }
                i += 1;
            }

            // --- Garaga verification (audit I-2 malformed hints) ---
            let mut sig_span = signature;
            let sig_with_hints = match Serde::<EdDSASignatureWithHint>::deserialize(ref sig_span) {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            // Audit M-4: no trailing felts after serde.
            if !sig_span.is_empty() {
                return false;
            }

            is_valid_eddsa_signature(sig_with_hints, owner_u256)
        }

        fn kind(self: @ContractState) -> felt252 {
            KIND_ED25519
        }

        /// Audit M-1 (V8.2) — Ed25519 pubkey is two LE u256 halves
        /// (32-byte twisted-Edwards-encoded public key). Shape-only
        /// check; Garaga's `is_valid_eddsa_signature` rejects any
        /// off-curve / not-in-subgroup pubkey at verify time by
        /// returning false (no panic), so a bad pubkey landing in
        /// `owners` produces only "soft fail" verifies — no DoS.
        fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
            if pubkey.len() != 2_u32 {
                return false;
            }
            let _: u128 = match (*pubkey.at(0)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let _: u128 = match (*pubkey.at(1)).try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            true
        }
    }
}
