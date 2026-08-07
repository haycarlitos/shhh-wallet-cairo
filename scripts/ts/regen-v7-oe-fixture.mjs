#!/usr/bin/env node
/**
 * V7 Ed25519 OutsideExecution fixture generator.
 *
 * Re-signs the V7 SNIP-9 V2 OE fixture used by
 * `tests/test_contract.cairo` under the post-audit M-1 convention
 * (`caller = 'ANY_CALLER'` instead of `0`). Runs end-to-end:
 *
 *   1. Build the 186-byte canonical OE encoding that V7's
 *      `encode_outside_execution_bytes` produces on-chain.
 *   2. Hex-ASCII encode it to 372 bytes — what V7's
 *      `bytes_to_hex_ascii` produces before handing off to the
 *      verifier (Phantom-UX-friendly path).
 *   3. Sign those 372 bytes with a deterministic Ed25519 key.
 *   4. Pack the result into the Garaga `EdDSASignatureWithHint`
 *      calldata layout the V7 verifier accepts.
 *   5. Emit `tests/v7_oe_fixture.cairo` exporting the pubkey halves
 *      and the signature envelope; `tests/test_contract.cairo`
 *      imports from there and drops the `#[ignore]` markers.
 *
 * Deterministic inputs (must match tests/test_contract.cairo):
 *   - TEST_CONTRACT_ADDR = 0xDEAD
 *   - chain_id           = 0x0 (snforge default)
 *   - nonce              = 42
 *   - execute_after      = 0
 *   - execute_before     = 1000
 *   - calls              = []
 *   - caller             = 'ANY_CALLER'  (post-audit M-1 convention)
 *
 * Run: `node scripts/ts/regen-v7-oe-fixture.mjs`
 */

import * as ed from '@noble/ed25519';
import * as garaga from 'garaga';
import { hash, shortString } from 'starknet';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

await garaga.init();

// ----------------------------------------------------------------
// Deterministic fixture inputs — MUST match tests/test_contract.cairo
// ----------------------------------------------------------------
const CONTRACT_ADDR = 0xdeadn;
const CHAIN_ID = 0x0n;
const NONCE = 42n;
const EXECUTE_AFTER = 0n;
const EXECUTE_BEFORE = 1000n;
const CALLER_FELT = BigInt(shortString.encodeShortString('ANY_CALLER')); // post-M-1
const CALLS_TAG = BigInt(shortString.encodeShortString('SHHH_CALLS_V1'));
const NUM_CALLS = 0n;

// Deterministic key — 32 bytes of 0x42 matches the comment in
// tests/test_contract.cairo ("seed = 0x42").
const PRIV = new Uint8Array(32).fill(0x42);

// ----------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------
function pushBeBytes(arr, value, nBytes) {
  const bytes = [];
  let v = BigInt(value);
  for (let i = 0; i < nBytes; i++) {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  for (const b of bytes) arr.push(b);
}

function bytesToLeU256(bytes) {
  let low = 0n;
  let high = 0n;
  for (let i = 0; i < 16; i++) low += BigInt(bytes[i]) << BigInt(8 * i);
  for (let i = 0; i < 16; i++) high += BigInt(bytes[16 + i]) << BigInt(8 * i);
  return { low, high };
}

function bytesToLeBigInt(bytes) {
  let x = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(bytes[i]);
  return x;
}

function hexAsciiBytes(bytes) {
  // V7's `bytes_to_hex_ascii`: each input byte emits two ASCII hex chars.
  const out = new Uint8Array(bytes.length * 2);
  for (let i = 0; i < bytes.length; i++) {
    const hi = (bytes[i] >> 4) & 0x0f;
    const lo = bytes[i] & 0x0f;
    out[2 * i] = hi < 10 ? 0x30 + hi : 0x61 + (hi - 10);
    out[2 * i + 1] = lo < 10 ? 0x30 + lo : 0x61 + (lo - 10);
  }
  return out;
}

// ----------------------------------------------------------------
// 1) Build the canonical 186-byte OE encoding
// ----------------------------------------------------------------
const rawBytes = [];
// Domain separator "SHHH_OE_V1" (10 bytes).
for (const c of 'SHHH_OE_V1') rawBytes.push(c.charCodeAt(0));
pushBeBytes(rawBytes, CHAIN_ID, 32);
pushBeBytes(rawBytes, CONTRACT_ADDR, 32);
pushBeBytes(rawBytes, CALLER_FELT, 32);
pushBeBytes(rawBytes, NONCE, 32);
pushBeBytes(rawBytes, EXECUTE_AFTER, 8);
pushBeBytes(rawBytes, EXECUTE_BEFORE, 8);

// calls_hash = poseidon_hash_span(['SHHH_CALLS_V1', num_calls])  (empty calls)
// starknet.js's `computePoseidonHashOnElements` == Cairo's `poseidon_hash_span`.
const callsHash = BigInt(
  hash.computePoseidonHashOnElements([
    '0x' + CALLS_TAG.toString(16),
    '0x' + NUM_CALLS.toString(16),
  ]),
);
pushBeBytes(rawBytes, callsHash, 32);

if (rawBytes.length !== 186) {
  throw new Error(`unexpected raw byte length: ${rawBytes.length}, expected 186`);
}

// ----------------------------------------------------------------
// 2) Hex-ASCII encode for the Ed25519 sign payload
// ----------------------------------------------------------------
const signedMsg = hexAsciiBytes(rawBytes);
if (signedMsg.length !== 372) throw new Error('hex ASCII length != 372');

// ----------------------------------------------------------------
// 3) Ed25519 keypair + signature
// ----------------------------------------------------------------
const pub = await ed.getPublicKeyAsync(PRIV);
const sig = await ed.signAsync(signedMsg, PRIV);
const R = sig.slice(0, 32);
const s = sig.slice(32, 64);

const pubPy = bytesToLeU256(pub);

// ----------------------------------------------------------------
// 4) Garaga calldata (EdDSASignatureWithHint Serde layout)
// ----------------------------------------------------------------
const envelope = garaga.eddsaCalldataBuilder(
  bytesToLeBigInt(R),   // Ry_twisted_le
  bytesToLeBigInt(s),   // s
  bytesToLeBigInt(pub), // Py_twisted_le
  signedMsg,            // signed bytes
  false,                // prependPublickey — V7 reads Py from storage
);

// ----------------------------------------------------------------
// 5) Emit the Cairo fixture
// ----------------------------------------------------------------
const felt = (x) => '0x' + x.toString(16);

const cairo = `//! AUTO-GENERATED by scripts/ts/regen-v7-oe-fixture.mjs.
//! Do not edit by hand — regenerate if the V7 OE encoding, the Garaga
//! hint layout, or the fixture inputs change.
//!
//! Deterministic inputs (MUST match tests/test_contract.cairo):
//!   contract_address = 0xDEAD
//!   chain_id         = 0x0
//!   caller           = 'ANY_CALLER'  (post-audit M-1 convention)
//!   nonce            = 42
//!   execute_after    = 0
//!   execute_before   = 1000
//!   calls            = []
//!
//! Private key : ${Array.from(PRIV).map(b => b.toString(16).padStart(2, '0')).join('')}
//! Pubkey (LE) : ${Array.from(pub).map(b => b.toString(16).padStart(2, '0')).join('')}
//! Signed msg  : ${Array.from(signedMsg).map(b => String.fromCharCode(b)).join('')}
//! R (LE)      : ${Array.from(R).map(b => b.toString(16).padStart(2, '0')).join('')}
//! s (LE)      : ${Array.from(s).map(b => b.toString(16).padStart(2, '0')).join('')}

pub fn v7_test_pubkey_low() -> felt252 {
    ${felt(pubPy.low)}
}

pub fn v7_test_pubkey_high() -> felt252 {
    ${felt(pubPy.high)}
}

pub fn v7_test_eddsa_signature() -> Array<felt252> {
    array![
${envelope.map(e => `        ${felt(e)},`).join('\n')}
    ]
}
`;

const here = dirname(fileURLToPath(import.meta.url));
const out = resolve(here, '../../tests/v7_oe_fixture.cairo');
writeFileSync(out, cairo);

console.log('Wrote', out);
console.log('Envelope length:', envelope.length, 'felts');
console.log('pubkey.low  =', felt(pubPy.low));
console.log('pubkey.high =', felt(pubPy.high));
console.log('calls_hash  =', felt(callsHash));
console.log('signed bytes=', signedMsg.length);
