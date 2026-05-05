#!/usr/bin/env python3
"""
BLS12-381 min-sig-size fixture generator for the Shhh V8 verifier.

Emits  tests/signer_bls12_381_fixture.cairo  containing:
    fixture_message_hash       : felt252 — SNIP-12-canonical 32-byte hash
    fixture_pubkey             : Span<felt252> (16 felts) — G2 pubkey
    fixture_signature_envelope : Span<felt252> (~4276 felts) — full envelope
    fixture_wrong_message_hash : a felt252 distinct from the signed one
                                 (used by negative-path tests)

Runtime dependency:
    pip install garaga         (≥ 1.1.0; ships hash_to_curve, build_hash_to_curve_hint,
                                MPCheckCalldataBuilder, precompute_lines, signature.hash_to_curve)

Why Python instead of TypeScript:
    Garaga's npm package only exposes drand-specific BLS hint generation
    (`drand_calldata_builder` is locked to round-numbered messages).
    The Python `garaga` package ships a generic `build_hash_to_curve_hint`
    + `MPCheckCalldataBuilder` that work for arbitrary 32-byte digests,
    which is exactly what the V8 verifier needs (felt252 SNIP-12 hashes).
    Track upstream PR `bls_calldata_builder` for the npm-side parity:
    once Garaga ships it, this generator can be ported back to TS.
"""

import hashlib
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

try:
    from garaga.curves import CURVES, CurveID
    from garaga.points import G1G2Pair, G1Point, G2Point
    from garaga.signature import hash_to_curve
    from garaga.starknet.tests_and_calldata_generators.map_to_curve import (
        build_hash_to_curve_hint,
    )
    from garaga.starknet.tests_and_calldata_generators.mpcheck import (
        MPCheckCalldataBuilder,
    )
    from garaga.precompiled_circuits.multi_miller_loop import precompute_lines
    from garaga.hints.io import bigint_split
except ImportError as e:
    print(
        "ERROR: garaga Python package missing.\n"
        "  pip install garaga\n"
        f"  (underlying import failure: {e})",
        file=sys.stderr,
    )
    sys.exit(1)


# ----------------------------------------------------------------
# Deterministic fixture inputs (match the convention of every other
# V8 fixture: fixed sk, fixed message_hash so test diffs are stable).
# ----------------------------------------------------------------
SK = 0x12345678  # tiny mock secret key, deterministic
SK_OTHER = 0x87654321  # used to construct a "wrong but valid" pubkey
MESSAGE_HASH = 0x05BCD634CE46C7234BD7A4B0959C3C5EDEED7F569DCFB7B33E23D7E2197A2A2F

OUT_PATH = REPO_ROOT / "tests" / "signer_bls12_381_fixture.cairo"


def msg_hash_to_32be(m: int) -> bytes:
    """felt252 → 32-byte big-endian (left-padded with zeros)."""
    if not (0 <= m < (1 << 252)):
        raise ValueError("message_hash must fit in a felt252 (252 bits)")
    return m.to_bytes(32, byteorder="big")


def u384_limbs(v: int) -> list[int]:
    """A u384 ↔ four 96-bit little-endian limbs (matches Cairo limb0..limb3)."""
    limbs = bigint_split(v)
    assert len(limbs) == 4, f"expected 4 limbs, got {len(limbs)}"
    return limbs


def serialize_u384(v: int, out: list[int]) -> None:
    out.extend(u384_limbs(v))


def serialize_g1(p: G1Point, out: list[int]) -> None:
    serialize_u384(p.x, out)
    serialize_u384(p.y, out)


def serialize_g2(p: G2Point, out: list[int]) -> None:
    serialize_u384(p.x[0], out)
    serialize_u384(p.x[1], out)
    serialize_u384(p.y[0], out)
    serialize_u384(p.y[1], out)


def serialize_h2c_hint(hint, out: list[int]) -> None:
    """Match Cairo derive Serde for HashToCurveHint = {f0_hint, f1_hint}."""
    for fh in (hint.f0_hint, hint.f1_hint):
        out.append(int(fh.gx1_is_square))
        serialize_u384(fh.y1.value, out)
        out.append(int(fh.y_flag))


def serialize_lines(lines_pyfelts, out: list[int]) -> None:
    """Emit length prefix + 4 u384 limbs per (r0a0, r0a1, r1a0, r1a1)."""
    n_lines = len(lines_pyfelts) // 4
    out.append(n_lines)
    for pf in lines_pyfelts:
        serialize_u384(pf.value, out)


def cairo_array_lines(values: list[int], indent: str = "        ") -> list[str]:
    """Emit Cairo `array![ 0x..., 0x..., ... ]` body, 2 felts per line."""
    out_lines = []
    for i in range(0, len(values), 2):
        chunk = values[i : i + 2]
        out_lines.append(indent + ", ".join(f"0x{v:x}" for v in chunk) + ",")
    return out_lines


def main() -> None:
    print(f"[bls fixture] sk={hex(SK)}")
    print(f"[bls fixture] message_hash={hex(MESSAGE_HASH)}")

    # ---------- pubkey ----------
    G2_GEN = G2Point.get_nG(CurveID.BLS12_381, 1)
    pubkey = G2_GEN.scalar_mul(SK)
    print(f"[bls fixture] pubkey x0 = {hex(pubkey.x[0])}")

    # ---------- H(m) + signature ----------
    msg_bytes = msg_hash_to_32be(MESSAGE_HASH)
    Hm = hash_to_curve(msg_bytes, CurveID.BLS12_381, "sha256")
    sig = Hm.scalar_mul(SK)
    print(f"[bls fixture] sig x = {hex(sig.x)}")

    # ---------- hash-to-curve hint ----------
    h2c_hint = build_hash_to_curve_hint(msg_bytes)

    # ---------- pairing-check hint + lines ----------
    # Match the on-chain pair convention used by the verifier:
    #   pair0 = (sig, G2_GEN)
    #   pair1 = (H(m), -pubkey)
    neg_pk = -pubkey
    pairs = [
        G1G2Pair(p=sig, q=G2_GEN, curve_id=CurveID.BLS12_381),
        G1G2Pair(p=Hm, q=neg_pk, curve_id=CurveID.BLS12_381),
    ]
    builder = MPCheckCalldataBuilder(
        curve_id=CurveID.BLS12_381,
        pairs=pairs,
        n_fixed_g2=2,  # both G2 points fixed → precomputed lines
        public_pair=None,
    )
    mpcheck_calldata = builder.serialize_to_calldata(use_rust=True)
    print(f"[bls fixture] mpcheck_hint felts = {len(mpcheck_calldata)}")

    lines_pyfelts = builder.lines()
    n_lines = len(lines_pyfelts) // 4
    print(f"[bls fixture] precomputed lines = {n_lines} (×16 felts = {n_lines * 16})")

    if n_lines != 136:
        raise SystemExit(
            f"expected 136 precomputed lines for BLS12-381 2P_2F, got {n_lines}"
        )

    # ---------- assemble envelope ----------
    envelope: list[int] = []
    serialize_g1(sig, envelope)
    serialize_h2c_hint(h2c_hint, envelope)
    serialize_lines(lines_pyfelts, envelope)
    envelope.extend(mpcheck_calldata)
    print(f"[bls fixture] envelope felts = {len(envelope)}")

    pubkey_felts: list[int] = []
    serialize_g2(pubkey, pubkey_felts)
    assert len(pubkey_felts) == 16

    # ---------- alternate pubkey (still in subgroup, just different) ----------
    other_pubkey = G2_GEN.scalar_mul(SK_OTHER)
    other_pubkey_felts: list[int] = []
    serialize_g2(other_pubkey, other_pubkey_felts)
    assert len(other_pubkey_felts) == 16

    # ---------- alternate signature G1 (sk_other × H(m), still in subgroup) ----------
    # This is a valid G1 point — same H(m), different scalar — so the
    # subgroup check passes on chain, but the pairing equation
    #     e(sig', G2_GEN) · e(H(m), -sk·G2) ≠ 1
    # fails because sig' was generated under sk_other, not sk. The
    # mpcheck_hint embedded below is the ORIGINAL hint (computed for the
    # right pairing), so feeding the alt signature breaks the
    # transcript-bound z value and the helper returns Err — which the
    # verifier maps to false.
    other_sig = Hm.scalar_mul(SK_OTHER)
    alt_envelope: list[int] = []
    serialize_g1(other_sig, alt_envelope)
    serialize_h2c_hint(h2c_hint, alt_envelope)
    serialize_lines(lines_pyfelts, alt_envelope)
    alt_envelope.extend(mpcheck_calldata)
    assert len(alt_envelope) == len(envelope)

    # ---------- emit Cairo ----------
    header = f"""//! AUTO-GENERATED by scripts/py/gen_bls_fixture.py — do not edit by hand.
//!
//! Curve   : BLS12-381 (min-sig-size, drand DST)
//! sk      : {hex(SK)}
//! pubkey  : G2 point, see fixture_pubkey()
//! message : {hex(MESSAGE_HASH)} (felt252; left-padded to 32 BE bytes)
//! envelope: {len(envelope)} felts (sig 8 + h2c_hint 12 + lines_len 1 + lines {n_lines * 16} + mpcheck_hint {len(mpcheck_calldata)})

"""

    body = []
    body.append("pub fn fixture_message_hash() -> felt252 {")
    body.append(f"    0x{MESSAGE_HASH:x}")
    body.append("}")
    body.append("")
    body.append("pub fn fixture_pubkey() -> Array<felt252> {")
    body.append("    array![")
    body.extend(cairo_array_lines(pubkey_felts))
    body.append("    ]")
    body.append("}")
    body.append("")
    body.append("pub fn fixture_other_pubkey() -> Array<felt252> {")
    body.append("    array![")
    body.extend(cairo_array_lines(other_pubkey_felts))
    body.append("    ]")
    body.append("}")
    body.append("")
    body.append("pub fn fixture_signature_envelope() -> Array<felt252> {")
    body.append("    array![")
    body.extend(cairo_array_lines(envelope))
    body.append("    ]")
    body.append("}")
    body.append("")
    body.append("pub fn fixture_alt_sig_envelope() -> Array<felt252> {")
    body.append("    array![")
    body.extend(cairo_array_lines(alt_envelope))
    body.append("    ]")
    body.append("}")
    body.append("")

    OUT_PATH.write_text(header + "\n".join(body))
    print(f"[bls fixture] wrote {OUT_PATH.relative_to(REPO_ROOT)}")
    print(f"[bls fixture] envelope total = {len(envelope)} felts")


if __name__ == "__main__":
    main()
