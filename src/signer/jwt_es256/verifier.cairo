//! JWT ES256 verifier — "Sign in with Apple", and any other ES256
//! JWT-based authentication (Auth0, Okta, Firebase Auth, OpenID
//! Connect IdPs that sign with P-256).
//!
//! Recipe (RFC 7515 + RFC 7518 ES256):
//!
//!     signing_input = header_b64url || "." || payload_b64url
//!     digest        = sha256(signing_input)
//!     sig           = ecdsa_p256_sign(digest, priv_key)   // 64 bytes raw r||s
//!
//! This is the exact envelope every standards-compliant ES256 IdP
//! produces. Apple, in particular, returns this verbatim from the
//! token endpoint after a Sign-In-with-Apple flow.
//!
//! Owner storage:
//!   pubkey = [x_low, x_high, y_low, y_high]   // 4 felts, IdP signing key
//!
//! Envelope layout (Serde over Span<felt252>):
//!   header_b64url:    ByteArray       // base64url JOSE header bytes
//!   payload_decoded:  ByteArray       // raw JSON claims (NOT base64url)
//!   nonce_offset:     u32             // index of the 43-byte base64url
//!                                      // challenge inside payload_decoded
//!   iss_offset:       u32             // index of the literal issuer
//!                                      // string inside payload_decoded
//!   r:                u256
//!   s:                u256
//!   y_parity:         felt252 (0 | 1)
//!
//! Why pass `payload_decoded` instead of `payload_b64url`:
//! the nonce + issuer claims appear as literal ASCII inside the JSON,
//! not inside its base64url encoding. To scan them by offset we need
//! the decoded form. The verifier re-encodes `payload_decoded` to
//! base64url on chain and uses THAT (concatenated with the dot and
//! the supplied header_b64url) as the signing input fed to sha256
//! and ECDSA. This closes the lie surface: a malicious caller can't
//! pass a forged decoded payload because the ECDSA recovery would
//! fail against the IdP's actual signature.
//!
//! Verification (any failure → return false):
//!   1. P-256 ECDSA over sha256(header_b64 || "." || base64url(payload_decoded))
//!      verifies under the stored owner pubkey
//!   2. The 43 ASCII bytes at payload_decoded[nonce_offset..nonce_offset+43]
//!      equal base64url(message_hash as 32 BE bytes, no padding)
//!   3. The 25 ASCII bytes at payload_decoded[iss_offset..iss_offset+25]
//!      equal "https://appleid.apple.com"
//!
//! Trust model + multi-user note:
//!
//! With `iss = appleid.apple.com` hardcoded, this verifier proves
//! "Apple's signing key signed a JWT containing our SNIP-12 hash
//! as the nonce claim". The owner is identified only by Apple's
//! signing key, not by which user logged in. For multi-user account
//! safety (a wallet provider authenticating distinct end users with
//! the same Apple key) the recommended pattern is a wrapping
//! `JwtES256SubBoundVerifier` that additionally checks the JWT `sub`
//! claim against a stored identity hash. That variant composes with
//! this base verifier rather than replacing it.

#[starknet::contract]
pub mod JwtES256AppleVerifier {
    use core::sha256::compute_sha256_byte_array;
    use starknet::secp256_trait::{Secp256Trait, is_valid_signature};
    use starknet::secp256r1::Secp256r1Point;
    use crate::signer::interface::{ISigner, KIND_JWT_ES256};

    const CHALLENGE_B64URL_LEN: u32 = 43;
    /// Length of "https://appleid.apple.com" — 25 ASCII chars.
    const ISSUER_LEN: u32 = 25;
    const POW_2_96: u128 = 0x1000000000000000000000000;
    const POW_2_64: u128 = 0x10000000000000000;
    const POW_2_32: u128 = 0x100000000;

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
            let header_b64: ByteArray = match Serde::deserialize(ref cursor) {
                Option::Some(b) => b,
                Option::None => { return false; },
            };
            let payload_decoded: ByteArray = match Serde::deserialize(ref cursor) {
                Option::Some(b) => b,
                Option::None => { return false; },
            };
            let nonce_offset_felt = match cursor.pop_front() {
                Option::Some(v) => *v,
                Option::None => { return false; },
            };
            let iss_offset_felt = match cursor.pop_front() {
                Option::Some(v) => *v,
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

            let nonce_offset: u32 = match nonce_offset_felt.try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let iss_offset: u32 = match iss_offset_felt.try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
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

            // 1. Nonce binding (43 ASCII bytes at nonce_offset must
            //    equal base64url(message_hash_be32, no padding)).
            if nonce_offset + CHALLENGE_B64URL_LEN > payload_decoded.len() {
                return false;
            }
            let expected_nonce = base64url_encode_32(message_hash);
            let mut j: u32 = 0;
            let mut nonce_ok = true;
            while j < CHALLENGE_B64URL_LEN {
                let got = match payload_decoded.at(nonce_offset + j) {
                    Option::Some(b) => b,
                    Option::None => {
                        nonce_ok = false;
                        break;
                    },
                };
                let want = match expected_nonce.at(j) {
                    Option::Some(b) => b,
                    Option::None => {
                        nonce_ok = false;
                        break;
                    },
                };
                if got != want {
                    nonce_ok = false;
                    break;
                }
                j += 1;
            }
            if !nonce_ok {
                return false;
            }

            // 2. Issuer binding (25 ASCII bytes at iss_offset must
            //    equal "https://appleid.apple.com").
            if iss_offset + ISSUER_LEN > payload_decoded.len() {
                return false;
            }
            let expected_iss = apple_issuer();
            let mut k: u32 = 0;
            let mut iss_ok = true;
            while k < ISSUER_LEN {
                let got = match payload_decoded.at(iss_offset + k) {
                    Option::Some(b) => b,
                    Option::None => {
                        iss_ok = false;
                        break;
                    },
                };
                let want = *expected_iss.at(k);
                if got != want {
                    iss_ok = false;
                    break;
                }
                k += 1;
            }
            if !iss_ok {
                return false;
            }

            // 3. Re-encode the decoded payload to base64url and build
            //    the canonical signing input. The ECDSA recovery
            //    against the stored pubkey is what locks the decoded
            //    form to what Apple actually signed — no separate
            //    consistency check needed.
            let payload_b64 = base64url_encode_bytes(@payload_decoded);
            let mut signing_input: ByteArray = header_b64.clone();
            signing_input.append_byte(0x2E); // '.'
            let mut bp: u32 = 0;
            while bp < payload_b64.len() {
                signing_input.append_byte(payload_b64.at(bp).unwrap());
                bp += 1;
            }
            let digest_words = compute_sha256_byte_array(@signing_input);
            let [w0, w1, w2, w3, w4, w5, w6, w7] = digest_words;
            let digest_u256 = sha_words_to_u256(w0, w1, w2, w3, w4, w5, w6, w7);

            // 4. ECDSA verify.
            let point =
                match Secp256Trait::<Secp256r1Point>::secp256_ec_new_syscall(stored_x, stored_y) {
                Result::Ok(Option::Some(p)) => p,
                Result::Ok(Option::None) => { return false; },
                Result::Err(_) => { return false; },
            };

            is_valid_signature::<Secp256r1Point>(digest_u256, r, s, point)
        }

        fn kind(self: @ContractState) -> felt252 {
            KIND_JWT_ES256
        }
    }

    /// Returns `b"https://appleid.apple.com"` (25 bytes).
    fn apple_issuer() -> Array<u8> {
        array![
            0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x61, 0x70, 0x70, 0x6C, 0x65, 0x69,
            0x64, 0x2E, 0x61, 0x70, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D,
        ]
    }

    // ------------------------------------------------------------------
    // Generic base64url encoder for variable-length input.
    //
    // Each 3 input bytes produce 4 ASCII chars. Tail of 1 byte → 2
    // chars; tail of 2 bytes → 3 chars; no `=` padding (URL-safe).
    // Standard alphabet A-Z, a-z, 0-9, `-`, `_`.
    // ------------------------------------------------------------------
    fn base64url_encode_bytes(input: @ByteArray) -> ByteArray {
        let mut out: ByteArray = Default::default();
        let total = input.len();
        if total == 0_u32 {
            return out;
        }

        // Process groups of 3 bytes.
        let full_groups = total / 3_u32;
        let mut g: u32 = 0;
        while g < full_groups {
            let i = g * 3_u32;
            let b0: u32 = input.at(i).unwrap().into();
            let b1: u32 = input.at(i + 1_u32).unwrap().into();
            let b2: u32 = input.at(i + 2_u32).unwrap().into();
            let v: u32 = (b0 * 0x10000_u32) + (b1 * 0x100_u32) + b2;
            out.append_byte(b64url_char((v / 0x40000_u32) & 0x3f_u32));
            out.append_byte(b64url_char((v / 0x1000_u32) & 0x3f_u32));
            out.append_byte(b64url_char((v / 0x40_u32) & 0x3f_u32));
            out.append_byte(b64url_char(v & 0x3f_u32));
            g += 1_u32;
        }

        // Tail: 0, 1, or 2 leftover bytes.
        let tail_start = full_groups * 3_u32;
        let tail = total - tail_start;
        if tail == 1_u32 {
            let b0: u32 = input.at(tail_start).unwrap().into();
            // Pack into 16 bits with two trailing zero bits, drop low char.
            let v: u32 = b0 * 0x10000_u32;
            out.append_byte(b64url_char((v / 0x40000_u32) & 0x3f_u32));
            out.append_byte(b64url_char((v / 0x1000_u32) & 0x3f_u32));
        } else if tail == 2_u32 {
            let b0: u32 = input.at(tail_start).unwrap().into();
            let b1: u32 = input.at(tail_start + 1_u32).unwrap().into();
            let v: u32 = (b0 * 0x10000_u32) + (b1 * 0x100_u32);
            out.append_byte(b64url_char((v / 0x40000_u32) & 0x3f_u32));
            out.append_byte(b64url_char((v / 0x1000_u32) & 0x3f_u32));
            out.append_byte(b64url_char((v / 0x40_u32) & 0x3f_u32));
        }

        out
    }

    // ------------------------------------------------------------------
    // Helpers for the 32-byte challenge encoder (used for nonce binding).
    // Same pattern as WebAuthnP256Verifier.
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

    fn b64url_char(v: u32) -> u8 {
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
