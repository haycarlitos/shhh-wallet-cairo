//! WebAuthn P-256 full-envelope verifier class.
//!
//! Implements the authentication-assertion verification defined in the
//! WebAuthn Level 2 spec (§7.2). The authenticator never signs our raw
//! SNIP-12 hash — it signs `sha256(authenticatorData || sha256(clientDataJSON))`,
//! and we must cryptographically bind the clientDataJSON's `challenge`
//! field to our SNIP-12 message hash.
//!
//! Envelope layout (Serde over `Span<felt252>`):
//!
//!   authenticator_data: ByteArray     — 37+ bytes from the authenticator
//!   client_data_json:   ByteArray     — JSON covered by clientDataJSON
//!   challenge_offset:   u32           — byte index in client_data_json where
//!                                        the base64url-encoded challenge begins
//!   r:                  u256 (low, high)
//!   s:                  u256 (low, high)
//!   y_parity:           felt252 (0|1) — shape-only, unused by is_valid_signature
//!
//! Verification (any failure ⇒ `return false`):
//!   1. `authenticator_data.len() >= 37`
//!   2. UP flag bit set: `authenticator_data[32] & 0x01 == 0x01`
//!   3. Type binding: `client_data_json` starts with the exact bytes
//!      `{"type":"webauthn.get"` (22 bytes). WebAuthn Level 3 §5.8.1.1
//!      mandates `type` as the first key in the CollectedClientData
//!      serialization, so a strict prefix check is sufficient. This
//!      closes the H-1 finding — otherwise a phishing site could
//!      collect a `webauthn.create` signature over our SNIP-12
//!      challenge and replay it as authentication.
//!   4. Challenge binding: 43 ASCII bytes at `client_data_json[off..off+43]`
//!      equal base64url(`message_hash` as 32 big-endian bytes, no padding)
//!   5. `sha_inner  = sha256(client_data_json)`
//!   6. `sha_outer  = sha256(authenticator_data || sha_inner)`
//!   7. ECDSA verify (r, s) against `sha_outer` under stored (x, y)
//!
//! We deliberately do *not* fully JSON-parse; callers supply
//! `challenge_offset` and the checks reduce to two substring
//! equalities against deterministic expected byte sequences.

#[starknet::contract]
pub mod WebAuthnP256Verifier {
    use core::sha256::compute_sha256_byte_array;
    use starknet::secp256_trait::{Secp256Trait, is_valid_signature};
    use starknet::secp256r1::Secp256r1Point;
    use crate::signer::interface::{ISigner, KIND_WEBAUTHN_P256};

    const UP_BIT: u8 = 0x01;
    const CHALLENGE_B64URL_LEN: u32 = 43;
    const POW_2_96: u128 = 0x1000000000000000000000000;
    const POW_2_64: u128 = 0x10000000000000000;
    const POW_2_32: u128 = 0x100000000;

    /// 22 bytes: `{"type":"webauthn.get"` — the mandatory prefix of a
    /// WebAuthn authentication assertion's clientDataJSON per WebAuthn
    /// Level 3 §5.8.1.1 (type comes first in the canonical order).
    const TYPE_PREFIX_LEN: u32 = 22;

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

            // Deserialize the envelope.
            let mut cursor = signature;
            let auth_data: ByteArray = match Serde::deserialize(ref cursor) {
                Option::Some(b) => b,
                Option::None => { return false; },
            };
            let client_data: ByteArray = match Serde::deserialize(ref cursor) {
                Option::Some(b) => b,
                Option::None => { return false; },
            };
            let challenge_offset_felt = match cursor.pop_front() {
                Option::Some(v) => *v,
                Option::None => { return false; },
            };
            let challenge_offset: u32 = match challenge_offset_felt.try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let r_low_felt = match cursor.pop_front() {
                Option::Some(v) => *v,
                Option::None => { return false; },
            };
            let r_high_felt = match cursor.pop_front() {
                Option::Some(v) => *v,
                Option::None => { return false; },
            };
            let s_low_felt = match cursor.pop_front() {
                Option::Some(v) => *v,
                Option::None => { return false; },
            };
            let s_high_felt = match cursor.pop_front() {
                Option::Some(v) => *v,
                Option::None => { return false; },
            };
            let y_parity_felt = match cursor.pop_front() {
                Option::Some(v) => *v,
                Option::None => { return false; },
            };
            if !cursor.is_empty() {
                return false;
            }
            if y_parity_felt != 0 && y_parity_felt != 1 {
                return false;
            }

            let r_low: u128 = match r_low_felt.try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let r_high: u128 = match r_high_felt.try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let s_low: u128 = match s_low_felt.try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let s_high: u128 = match s_high_felt.try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let r = u256 { low: r_low, high: r_high };
            let s = u256 { low: s_low, high: s_high };

            // 1. Length + 2. UP flag.
            if auth_data.len() < 37_u32 {
                return false;
            }
            let flags_byte: u8 = match auth_data.at(32_u32) {
                Option::Some(b) => b,
                Option::None => { return false; },
            };
            if (flags_byte & UP_BIT) != UP_BIT {
                return false;
            }

            // 3. Type binding — clientDataJSON MUST start with the exact
            // bytes `{"type":"webauthn.get"`. Rejects `webauthn.create`
            // confusion attacks and any tampered clientData whose type
            // field has been displaced from the canonical first position.
            if client_data.len() < TYPE_PREFIX_LEN {
                return false;
            }
            let prefix = webauthn_get_prefix();
            let mut p: u32 = 0;
            let mut type_ok = true;
            while p < TYPE_PREFIX_LEN {
                let got = match client_data.at(p) {
                    Option::Some(b) => b,
                    Option::None => {
                        type_ok = false;
                        break;
                    },
                };
                let want = *prefix.at(p);
                if got != want {
                    type_ok = false;
                    break;
                }
                p += 1;
            }
            if !type_ok {
                return false;
            }

            // 4. Challenge binding.
            if challenge_offset + CHALLENGE_B64URL_LEN > client_data.len() {
                return false;
            }
            let expected = base64url_encode_32(message_hash);
            let mut j: u32 = 0;
            let mut chall_ok = true;
            while j < CHALLENGE_B64URL_LEN {
                let got = match client_data.at(challenge_offset + j) {
                    Option::Some(b) => b,
                    Option::None => {
                        chall_ok = false;
                        break;
                    },
                };
                let want = match expected.at(j) {
                    Option::Some(b) => b,
                    Option::None => {
                        chall_ok = false;
                        break;
                    },
                };
                if got != want {
                    chall_ok = false;
                    break;
                }
                j += 1;
            }
            if !chall_ok {
                return false;
            }

            // 4. sha256(clientDataJSON)
            let sha_inner = compute_sha256_byte_array(@client_data);
            let [i0, i1, i2, i3, i4, i5, i6, i7] = sha_inner;

            // 5. sha256(authenticatorData || sha_inner)
            let mut concat: ByteArray = auth_data.clone();
            append_u32_be(ref concat, i0);
            append_u32_be(ref concat, i1);
            append_u32_be(ref concat, i2);
            append_u32_be(ref concat, i3);
            append_u32_be(ref concat, i4);
            append_u32_be(ref concat, i5);
            append_u32_be(ref concat, i6);
            append_u32_be(ref concat, i7);
            let sha_outer = compute_sha256_byte_array(@concat);
            let [o0, o1, o2, o3, o4, o5, o6, o7] = sha_outer;
            let msg_hash_u256 = sha_words_to_u256(o0, o1, o2, o3, o4, o5, o6, o7);

            // 6. ECDSA verify.
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

        /// Audit M-1 (V8.2) — WebAuthn pubkey is the same P-256 `(x, y)`
        /// shape as raw P256. Curve check via
        /// `secp256_ec_new_syscall<Secp256r1Point>`.
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

    // ------------------------------------------------------------------
    // base64url (no padding) encoder specialized for a 32-byte input.
    // Encodes the big-endian bytes of `message_hash` into 43 ASCII bytes:
    // 10 full 3-byte groups (40 chars) + tail of 2 bytes (3 chars).
    // ------------------------------------------------------------------
    fn base64url_encode_32(message_hash: felt252) -> ByteArray {
        let bytes = felt_to_be_bytes_32(message_hash);
        let mut out: ByteArray = Default::default();

        let mut i: u32 = 0;
        while i < 30_u32 {
            let b0: u32 = (*bytes.at(i)).into();
            let b1: u32 = (*bytes.at(i + 1)).into();
            let b2: u32 = (*bytes.at(i + 2)).into();
            let v: u32 = (b0 * 0x10000_u32) + (b1 * 0x100_u32) + b2;
            out.append_byte(b64url_char((v / 0x40000_u32) & 0x3f_u32));
            out.append_byte(b64url_char((v / 0x1000_u32) & 0x3f_u32));
            out.append_byte(b64url_char((v / 0x40_u32) & 0x3f_u32));
            out.append_byte(b64url_char(v & 0x3f_u32));
            i += 3;
        }

        let b30: u32 = (*bytes.at(30_u32)).into();
        let b31: u32 = (*bytes.at(31_u32)).into();
        let v: u32 = (b30 * 0x10000_u32) + (b31 * 0x100_u32);
        out.append_byte(b64url_char((v / 0x40000_u32) & 0x3f_u32));
        out.append_byte(b64url_char((v / 0x1000_u32) & 0x3f_u32));
        out.append_byte(b64url_char((v / 0x40_u32) & 0x3f_u32));

        out
    }

    /// Returns the canonical 22-byte WebAuthn authentication assertion
    /// prefix: `{"type":"webauthn.get"`.
    fn webauthn_get_prefix() -> Array<u8> {
        array![
            0x7B, // '{'
            0x22, // '"'
            0x74, // 't'
            0x79, // 'y'
            0x70, // 'p'
            0x65, // 'e'
            0x22, // '"'
            0x3A, // ':'
            0x22, // '"'
            0x77, // 'w'
            0x65, // 'e'
            0x62, // 'b'
            0x61, // 'a'
            0x75, // 'u'
            0x74, // 't'
            0x68, // 'h'
            0x6E, // 'n'
            0x2E, // '.'
            0x67, // 'g'
            0x65, // 'e'
            0x74, // 't'
            0x22 // '"'
        ]
    }

    fn b64url_char(v: u32) -> u8 {
        // A-Z (0-25), a-z (26-51), 0-9 (52-61), `-` (62), `_` (63).
        if v < 26_u32 {
            (65_u32 + v).try_into().unwrap()
        } else if v < 52_u32 {
            (97_u32 + v - 26_u32).try_into().unwrap()
        } else if v < 62_u32 {
            (48_u32 + v - 52_u32).try_into().unwrap()
        } else if v == 62_u32 {
            45_u8
        } else {
            95_u8
        }
    }

    fn felt_to_be_bytes_32(x: felt252) -> Array<u8> {
        let v: u256 = x.into();
        let hi = v.high;
        let lo = v.low;
        let mut out: Array<u8> = array![];
        let mut i: u32 = 0;
        while i < 16_u32 {
            let shift: u128 = pow2_u128(8 * (15 - i));
            let byte: u128 = (hi / shift) & 0xff_u128;
            out.append(byte.try_into().unwrap());
            i += 1;
        }
        let mut j: u32 = 0;
        while j < 16_u32 {
            let shift: u128 = pow2_u128(8 * (15 - j));
            let byte: u128 = (lo / shift) & 0xff_u128;
            out.append(byte.try_into().unwrap());
            j += 1;
        }
        out
    }

    fn pow2_u128(exp: u32) -> u128 {
        let mut result: u128 = 1_u128;
        let mut i: u32 = 0;
        while i < exp {
            result = result * 2_u128;
            i += 1;
        }
        result
    }

    fn append_u32_be(ref out: ByteArray, w: u32) {
        out.append_byte(((w / 0x1000000_u32) & 0xff_u32).try_into().unwrap());
        out.append_byte(((w / 0x10000_u32) & 0xff_u32).try_into().unwrap());
        out.append_byte(((w / 0x100_u32) & 0xff_u32).try_into().unwrap());
        out.append_byte((w & 0xff_u32).try_into().unwrap());
    }

    fn sha_words_to_u256(
        w0: u32, w1: u32, w2: u32, w3: u32, w4: u32, w5: u32, w6: u32, w7: u32,
    ) -> u256 {
        let a0: u128 = w0.into();
        let a1: u128 = w1.into();
        let a2: u128 = w2.into();
        let a3: u128 = w3.into();
        let a4: u128 = w4.into();
        let a5: u128 = w5.into();
        let a6: u128 = w6.into();
        let a7: u128 = w7.into();
        let hi: u128 = (a0 * POW_2_96) + (a1 * POW_2_64) + (a2 * POW_2_32) + a3;
        let lo: u128 = (a4 * POW_2_96) + (a5 * POW_2_64) + (a6 * POW_2_32) + a7;
        u256 { low: lo, high: hi }
    }
}
