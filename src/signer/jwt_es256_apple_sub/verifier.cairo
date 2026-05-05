//! JWT ES256 sub-bound verifier — multi-user safe "Sign in with Apple".
//!
//! Same cryptographic surface as `JwtES256AppleVerifier` (RFC 7515 JWT
//! signed with ECDSA P-256, hardcoded Apple issuer), with one extra
//! binding: the JWT's `sub` claim (the user's stable Apple
//! identifier) must match a stored identity hash.
//!
//! Why this exists:
//!
//! With the base Apple verifier, the owner is identified only by
//! Apple's signing key. If a wallet provider sets up many V8 accounts
//! all using the same Apple-issued public key (which is the natural
//! deployment), then any Apple user could sign for any of those
//! accounts as long as they got Apple to issue them a JWT with the
//! right nonce. Apple does NOT scope JWTs to specific Starknet
//! accounts — only to the dapp's `aud` claim. So multi-tenant safety
//! requires binding the on-chain owner to a specific Apple `sub`.
//!
//! Owner storage:
//!   pubkey = [x_low, x_high, y_low, y_high, sub_hash]   // 5 felts
//!   - first 4 felts: Apple's current ES256 signing key
//!   - sub_hash:      poseidon_hash_span over the bytes of the user's
//!                    Apple `sub` claim (e.g. "001234.abcdef.5678"),
//!                    one felt per byte. Same encoding mirrored in
//!                    the TS fixture so off-chain registration and
//!                    on-chain check agree.
//!
//! Envelope layout (Serde over Span<felt252>):
//!   header_b64:        ByteArray
//!   payload_decoded:   ByteArray
//!   nonce_offset:      u32
//!   iss_offset:        u32
//!   sub_offset:        u32       // index of sub claim VALUE in payload
//!   sub_len:           u32       // byte length of sub claim VALUE
//!   r:                 u256
//!   s:                 u256
//!   y_parity:          felt252 (0|1)
//!
//! Verification (any failure → return false):
//!   1. P-256 ECDSA over sha256(header_b64 || "." || base64url(payload_decoded))
//!      verifies under stored pubkey (first 4 felts)
//!   2. Nonce binding: 43 bytes at payload_decoded[nonce_offset..]
//!      equal base64url(message_hash, 32 BE bytes, no padding)
//!   3. Issuer binding: 25 bytes at payload_decoded[iss_offset..]
//!      equal "https://appleid.apple.com"
//!   4. Sub binding: poseidon over bytes at
//!      payload_decoded[sub_offset..sub_offset+sub_len] equals the
//!      stored sub_hash (5th felt of pubkey)
//!
//! Mutual binding implication: even if Apple rotates its signing key
//! (forcing a pubkey rotation) the user's identity (sub_hash) stays
//! constant, so account ownership survives key rotation. Conversely
//! if the user changes their Apple ID (rare; sub is meant to be
//! stable per (app, user)) the owner record needs an explicit rotate.

#[starknet::contract]
pub mod JwtES256AppleSubVerifier {
    use core::poseidon::poseidon_hash_span;
    use core::sha256::compute_sha256_byte_array;
    use starknet::secp256_trait::{Secp256Trait, is_valid_signature};
    use starknet::secp256r1::Secp256r1Point;
    use crate::signer::interface::{ISigner, KIND_JWT_ES256_APPLE_SUB};

    const CHALLENGE_B64URL_LEN: u32 = 43;
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
            if pubkey.len() != 5_u32 {
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
            let stored_sub_hash: felt252 = *pubkey.at(4);
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
            let sub_offset_felt = match cursor.pop_front() {
                Option::Some(v) => *v,
                Option::None => { return false; },
            };
            let sub_len_felt = match cursor.pop_front() {
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
            let sub_offset: u32 = match sub_offset_felt.try_into() {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            let sub_len: u32 = match sub_len_felt.try_into() {
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

            // 1. Nonce binding.
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

            // 2. Issuer binding.
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

            // 3. Sub binding — read sub_len bytes at sub_offset, hash
            // them with poseidon over felt252 (one byte per felt), and
            // compare to the stored sub_hash. We also require sub_len
            // > 0 so a zero-length window can't trivially match a
            // poseidon-of-empty.
            if sub_len == 0_u32 {
                return false;
            }
            if sub_offset + sub_len > payload_decoded.len() {
                return false;
            }
            let mut sub_felts: Array<felt252> = array![];
            let mut m: u32 = 0;
            while m < sub_len {
                let b = match payload_decoded.at(sub_offset + m) {
                    Option::Some(byte) => byte,
                    Option::None => { return false; },
                };
                sub_felts.append(b.into());
                m += 1;
            }
            let computed_sub_hash = poseidon_hash_span(sub_felts.span());
            if computed_sub_hash != stored_sub_hash {
                return false;
            }

            // 4. ECDSA over the canonical signing input.
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

            let point =
                match Secp256Trait::<Secp256r1Point>::secp256_ec_new_syscall(stored_x, stored_y) {
                Result::Ok(Option::Some(p)) => p,
                Result::Ok(Option::None) => { return false; },
                Result::Err(_) => { return false; },
            };

            is_valid_signature::<Secp256r1Point>(digest_u256, r, s, point)
        }

        fn kind(self: @ContractState) -> felt252 {
            KIND_JWT_ES256_APPLE_SUB
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
    // Generic base64url encoder for variable-length input (mirrors the
    // one in JwtES256AppleVerifier; kept inline for clarity rather
    // than shared because each verifier class is its own audit unit).
    // ------------------------------------------------------------------
    fn base64url_encode_bytes(input: @ByteArray) -> ByteArray {
        let mut out: ByteArray = Default::default();
        let total = input.len();
        if total == 0_u32 {
            return out;
        }

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

        let tail_start = full_groups * 3_u32;
        let tail = total - tail_start;
        if tail == 1_u32 {
            let b0: u32 = input.at(tail_start).unwrap().into();
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
