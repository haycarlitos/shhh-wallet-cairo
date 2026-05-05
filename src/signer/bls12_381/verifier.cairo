//! BLS12-381 verifier — pairing-based signatures for validator multisigs,
//! DAO multi-sig flows, randomness beacons, and any application that
//! aggregates signatures on a single public key.
//!
//! Variant: **min-sig-size** (drand-compatible).
//!     - Signatures live in G1 (~48 bytes off chain)
//!     - Public keys live in G2  (~96 bytes off chain)
//!     - Hash-to-curve maps the SNIP-12 message digest into G1
//!
//! Domain Separation Tag (DST):
//!     `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_+`
//! This matches the drand-quicknet ciphersuite (Garaga's
//! `hash_to_curve_bls12_381` helper hardcodes this DST). It differs
//! from IETF BLS-Signatures `_NUL_` / `_AUG_` / `_POP_` only by the
//! trailing `+` separator inherited from drand. Off-chain signers
//! MUST use this exact DST string when computing `H(m)` so the
//! on-chain hash-to-curve agrees byte-for-byte.
//!
//! Owner storage (16 felts):
//!     pubkey = [
//!         x0_l0, x0_l1, x0_l2, x0_l3,   // u384 limbs, little-endian
//!         x1_l0, x1_l1, x1_l2, x1_l3,
//!         y0_l0, y0_l1, y0_l2, y0_l3,
//!         y1_l0, y1_l1, y1_l2, y1_l3,
//!     ]
//! where the G2 point in Fp2 coordinates is
//!     x = x0 + x1·u,   y = y0 + y1·u   (u² = -1).
//! Each u384 v has limb0..limb3 as 96-bit little-endian limbs:
//!     v = limb0 + limb1·2^96 + limb2·2^192 + limb3·2^288.
//!
//! Signature envelope layout (felt252 span, in this order):
//!     1. signature_g1: G1Point Serde         (8 felts)
//!     2. h2c_hint:     HashToCurveHint Serde (12 felts: 2 × MapToCurveHint)
//!     3. lines_len:    felt252 (= 136)       (1 felt)
//!     4. lines:        G2Line<u384> × 136    (2176 felts)
//!     5. mpcheck_hint: MPCheckHintBLS12_381  (~2079 felts)
//!
//! Total envelope on a happy path: ~4276 felts. This is the cost of a
//! BLS pairing check; it is signed off chain in one shot and submitted
//! through the paymaster like any other OE.
//!
//! Verification (any failure → revert; bool return is for the no-panic
//! pairing-mismatch case where everything parsed but the equation
//! didn't hold):
//!     1. pubkey length is exactly 16 felts        (false on mismatch)
//!     2. signature deserializes cleanly           (revert on truncation)
//!     3. lines_len is exactly 136                  (revert otherwise)
//!     4. pubkey G2 in r-torsion subgroup           (revert otherwise)
//!     5. signature G1 in r-torsion subgroup        (revert otherwise)
//!     6. message_hash → 32-byte BE → [u32; 8]
//!     7. H(m) = hash_to_curve_bls12_381(msg, h2c_hint)
//!     8. multi_pairing_check_bls12_381_2P_2F(
//!            (sig, G2_GEN), (H(m), -pubkey), lines, mpcheck_hint
//!        ) returns Ok(true).                       (false on Err)
//!
//! The pairing-check rewrite uses the BLS verification identity
//!     e(sig, G2_GEN) == e(H(m), pubkey)
//! ⇔ e(sig, G2_GEN) · e(H(m), -pubkey) == 1
//! which is exactly what `multi_pairing_check_bls12_381_2P_2F`
//! evaluates. We negate `pubkey` on chain so off-chain signers can
//! register their key in its natural form.
//!
//! Use cases:
//!   - Validator-style multisigs that already use BLS aggregation.
//!   - DAO governance keys aggregated via Lagrange interpolation off
//!     chain and submitted as a single G1 signature.
//!   - Backend service signers in throughput-critical paths.
//!
//! Limitations / scope fences:
//!   - Min-sig-size only. Eth-validator-style (G2 sigs, G1 pubkeys,
//!     hash-to-curve to G2) needs `hash_to_curve_g2_bls12_381` which
//!     Garaga has not yet shipped at v1.0.1; that variant ships in a
//!     follow-up verifier under kind `BLS12_381_MIN_PK`.
//!   - DST is fixed to drand's `..._NUL_+`. Custom DSTs need a SNIP
//!     amendment.
//!   - `hash_to_curve` consumes a 32-byte digest, not the original
//!     pre-image bytes. Off-chain signers must commit to the SNIP-12
//!     digest first (every V8 verifier already does this).

#[starknet::contract]
pub mod Bls12_381MinSigVerifier {
    use core::array::{ArrayTrait, SpanTrait};
    use core::circuit::u384;
    use core::option::OptionTrait;
    use core::serde::Serde;
    use core::traits::{Into, TryInto};
    use garaga::apps::drand::{HashToCurveHint, hash_to_curve_bls12_381};
    use garaga::definitions::structs::fields::deserialize_u384;
    use garaga::definitions::structs::points::G2Line;
    use garaga::definitions::{BLS_G2_GENERATOR, G1G2Pair, G1Point, G2Point};
    use garaga::ec::ec_ops::G1PointTrait;
    use garaga::ec::ec_ops_g2::G2PointTrait;
    use garaga::ec::pairing::pairing_check::multi_pairing_check_bls12_381_2P_2F;
    use garaga::pairing_check::MPCheckHintBLS12_381;
    use garaga::utils::calldata::deserialize_mpcheck_hint_bls12_381;
    use crate::signer::interface::{ISigner, KIND_BLS12_381};

    /// Number of precomputed Miller-loop lines for `multi_pairing_check_bls12_381_2P_2F`
    /// with two precomputed G2 points (G2_GEN + pubkey).
    const BLS_2P_2F_LINES_LEN: u32 = 136;

    /// Number of felts in the pubkey span (4 u384 × 4 limbs).
    const PUBKEY_LEN: u32 = 16;

    /// BLS12-381 curve index used by Garaga's subgroup checks.
    const BLS_CURVE_INDEX: usize = 1;

    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl ISignerImpl of ISigner<ContractState> {
        fn verify(
            self: @ContractState,
            message_hash: felt252,
            mut pubkey: Span<felt252>,
            mut signature: Span<felt252>,
        ) -> bool {
            // ---------- 1. shape guards ----------
            if pubkey.len() != PUBKEY_LEN {
                return false;
            }
            if signature.is_empty() {
                return false;
            }

            // ---------- 2. parse pubkey G2 point ----------
            let x0 = deserialize_u384(ref pubkey);
            let x1 = deserialize_u384(ref pubkey);
            let y0 = deserialize_u384(ref pubkey);
            let y1 = deserialize_u384(ref pubkey);
            let pubkey_g2 = G2Point { x0: x0, x1: x1, y0: y0, y1: y1 };

            // ---------- 3. parse signature envelope ----------
            // signature_g1
            let signature_g1: G1Point = match Serde::<G1Point>::deserialize(ref signature) {
                Option::Some(s) => s,
                Option::None => { return false; },
            };
            // h2c_hint
            let h2c_hint: HashToCurveHint =
                match Serde::<HashToCurveHint>::deserialize(ref signature) {
                Option::Some(h) => h,
                Option::None => { return false; },
            };
            // lines length
            let lines_len_felt: felt252 = match signature.pop_front() {
                Option::Some(v) => *v,
                Option::None => { return false; },
            };
            let lines_len: u32 = match lines_len_felt.try_into() {
                Option::Some(n) => n,
                Option::None => { return false; },
            };
            if lines_len != BLS_2P_2F_LINES_LEN {
                return false;
            }
            // lines: 136 G2Line<u384>, each 16 felts
            let mut lines_arr: Array<G2Line<u384>> = ArrayTrait::new();
            let mut i: u32 = 0;
            while i != lines_len {
                let r0a0 = deserialize_u384(ref signature);
                let r0a1 = deserialize_u384(ref signature);
                let r1a0 = deserialize_u384(ref signature);
                let r1a1 = deserialize_u384(ref signature);
                lines_arr.append(G2Line { r0a0: r0a0, r0a1: r0a1, r1a0: r1a0, r1a1: r1a1 });
                i += 1;
            }
            // mpcheck_hint — consumes the rest of the span; helper panics
            // on truncation, which is the right failure mode for a
            // structurally malformed envelope.
            let mpcheck_hint: MPCheckHintBLS12_381 = deserialize_mpcheck_hint_bls12_381(
                ref signature,
            );

            // ---------- 4. subgroup checks ----------
            // Both helpers panic if the point is not in the r-torsion;
            // that is correct behavior — a malformed point means the
            // owner registration was wrong upstream.
            pubkey_g2.assert_in_subgroup_excluding_infinity(BLS_CURVE_INDEX);
            signature_g1.assert_in_subgroup_excluding_infinity(BLS_CURVE_INDEX);

            // ---------- 5. felt252 → [u32; 8] big-endian ----------
            let msg_u32s = felt252_to_u32x8_be(message_hash);

            // ---------- 6. compute H(m) on chain ----------
            let msg_pt = hash_to_curve_bls12_381(msg_u32s, h2c_hint);

            // ---------- 7. pairing check ----------
            let neg_pubkey_g2 = pubkey_g2.negate(BLS_CURVE_INDEX);
            let result = multi_pairing_check_bls12_381_2P_2F(
                pair0: G1G2Pair { p: signature_g1, q: BLS_G2_GENERATOR },
                pair1: G1G2Pair { p: msg_pt, q: neg_pubkey_g2 },
                lines: lines_arr.span(),
                hint: mpcheck_hint,
            );

            match result {
                Result::Ok(_) => true,
                Result::Err(_) => false,
            }
        }

        fn kind(self: @ContractState) -> felt252 {
            KIND_BLS12_381
        }
    }

    /// Convert a `felt252` (≤252 bits) to its 32-byte big-endian
    /// representation, then split into eight u32 big-endian words.
    /// Matches Garaga's `[u32; 8]` shape.
    fn felt252_to_u32x8_be(m: felt252) -> [u32; 8] {
        let m_u256: u256 = m.into();
        let high: u128 = m_u256.high;
        let low: u128 = m_u256.low;

        let h0: u32 = (high / 0x1000000000000000000000000_u128).try_into().unwrap();
        let h1: u32 = ((high / 0x10000000000000000_u128) & 0xffffffff_u128).try_into().unwrap();
        let h2: u32 = ((high / 0x100000000_u128) & 0xffffffff_u128).try_into().unwrap();
        let h3: u32 = (high & 0xffffffff_u128).try_into().unwrap();
        let l0: u32 = (low / 0x1000000000000000000000000_u128).try_into().unwrap();
        let l1: u32 = ((low / 0x10000000000000000_u128) & 0xffffffff_u128).try_into().unwrap();
        let l2: u32 = ((low / 0x100000000_u128) & 0xffffffff_u128).try_into().unwrap();
        let l3: u32 = (low & 0xffffffff_u128).try_into().unwrap();
        [h0, h1, h2, h3, l0, l1, l2, l3]
    }
}
