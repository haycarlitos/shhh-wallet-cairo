# Upstream Garaga PR draft — `bls_calldata_builder` for the npm bundle

> **Status:** drafted, not yet opened upstream. The Cairo verifier in
> `src/signer/bls12_381/verifier.cairo` works today using the Python
> `garaga` package for fixture generation; this PR makes the JS-side
> story match so wallet SDKs can build BLS calldata in the browser.

## Problem

`garaga` (npm) currently exposes BLS-related calldata builders only
through `drand_calldata_builder` / `getDrandCallData`. Both are
hardcoded to the drand round-number message format:

```text
message = sha256(round_be_8B)        // 8-byte round → 32-byte digest
ciphersuite = BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_+
```

That's fine for the drand beacon, but it shuts the door on every
other BLS use case: validator multisigs, DAO governance keys, backend
signers, Shhh Wallet's V8 BLS signer kind. None of those want to
embed their message into a 64-bit round number.

The Python `garaga` package already has the generic helper:

- `garaga.starknet.tests_and_calldata_generators.map_to_curve.build_hash_to_curve_hint(message: bytes)`
  produces a `HashToCurveHint` for any 32-byte digest with the same DST.
- `garaga.starknet.tests_and_calldata_generators.mpcheck.MPCheckCalldataBuilder`
  produces the `MPCheckHintBLS12_381` and the precomputed
  `G2Line<u384>` array for arbitrary `[G1G2Pair]` inputs.

The Rust core (`tools/garaga_rs`) already exposes
`mpc_calldata_builder` over WASM. What's missing is a top-level
JS-facing entry point that wraps these primitives into a single
`bls_calldata_builder(...)` for arbitrary-message BLS verification.

## Proposed API

```ts
/**
 * Build the on-chain calldata for a BLS12-381 min-sig-size signature
 * verification (drand-DST ciphersuite,
 * BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_+).
 *
 * @param messageHash  32-byte big-endian digest of the message to verify
 *                      (matches the input to `hash_to_curve_bls12_381`
 *                      in the Cairo `garaga::apps::drand` module).
 * @param signatureG1  Compressed (48 B) or uncompressed (96 B) G1
 *                      signature point.
 * @param pubkeyG2     Compressed (96 B) or uncompressed (192 B) G2
 *                      public key point.
 * @returns            Array of bigint felts encoding:
 *                       1. signature_g1: G1Point Serde       (8 felts)
 *                       2. h2c_hint:     HashToCurveHint     (12 felts)
 *                       3. lines_len:    u32 (= 136)         (1 felt)
 *                       4. lines:        G2Line<u384> × 136  (2176 felts)
 *                       5. mpcheck_hint: MPCheckHintBLS12_381 (~2079 felts)
 */
export function bls_calldata_builder(
    messageHash: Uint8Array,    // exactly 32 bytes
    signatureG1: Uint8Array,    // 48 or 96 bytes
    pubkeyG2: Uint8Array,       // 96 or 192 bytes
): bigint[];
```

A min-pubkey-size variant (`bls_calldata_builder_g2sigs`) would mirror
the same shape once Garaga ships hash-to-curve to G2.

## Implementation sketch

In `tools/garaga_rs/src/bls/`:

```rust
#[wasm_bindgen]
pub fn bls_calldata_builder(
    message_hash: Vec<u8>,    // 32 bytes
    signature_g1: Vec<u8>,    // 48 or 96 bytes
    pubkey_g2: Vec<u8>,       // 96 or 192 bytes
) -> Result<Vec<JsValue>, JsError> {
    // 1. deserialize_bls_point on signature_g1 → G1Point
    // 2. deserialize_bls_point on pubkey_g2 → G2Point
    // 3. build_hash_to_curve_hint(message_hash) → HashToCurveHint
    // 4. compute H(m) via lambdaworks BLS hash-to-curve
    // 5. neg_pk = -pk
    // 6. precompute_lines([G2_GEN, neg_pk]) → 136 G2Lines
    // 7. mpc_calldata_builder(BLS12_381,
    //        pairs = [(sig, G2_GEN), (Hm, neg_pk)],
    //        n_fixed_g2 = 2, public_pair = None)
    // 8. concat into final calldata felt vector
}
```

Most of the building blocks already exist in `garaga_rs`. The new
function is essentially the `drand_calldata_builder` flow with
`round_to_message(round)` replaced by the direct 32-byte input.

## Test vector

Anchor it to the same fixture this repo uses
(`scripts/py/gen_bls_fixture.py`):

```text
message_hash = 0x05bcd634ce46c7234bd7a4b0959c3c5edeed7f569dcfb7b33e23d7e2197a2a2f
sk           = 0x12345678
pubkey       = sk · G2_GEN
sig          = sk · hash_to_curve_g1(message_hash)
expected envelope length = 4276 felts
```

A single round-trip test that runs `bls_calldata_builder`, deploys a
2P_2F BLS verifier on starknet-foundry, and asserts `verify` returns
true is enough proof that the JS path matches the existing Python
path byte-for-byte.

## What we ship while waiting

The Shhh V8 verifier doesn't block on this PR. We use the Python
package today and `scripts/py/gen_bls_fixture.py` for offline fixture
generation (see `tests/signer_bls12_381_fixture.cairo`). The Cairo
verifier class hash is determined by the Cairo source alone — when
this upstream PR lands we swap the fixture generator from Python to
TS without changing the on-chain class.

## How to open the PR

1. Fork `keep-starknet-strange/garaga`, branch from `main`.
2. Copy the Rust sketch above into `tools/garaga_rs/src/bls/calldata.rs`.
3. Add `bls_calldata_builder` to the `#[wasm_bindgen]` exports.
4. Mirror the function signature in `tools/garaga_ts/src/index.ts`.
5. Add a unit test under `tools/garaga_rs/tests/bls.rs` that pins the
   fixture above.
6. PR title: `feat(bls): expose generic bls_calldata_builder for npm`
7. Body: link this doc + the Shhh V8 verifier as a downstream
   consumer.

When opened, link the upstream PR back here for review.
