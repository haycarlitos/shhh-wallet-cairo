/**
 * Cifra SDK — per-curve signer adapters.
 *
 * Each adapter returns a `DetectedSigner` that the rest of the SDK
 * can use interchangeably:
 *   - `pubkey`    — Cairo-shaped pubkey halves
 *   - `signHash`  — takes the SNIP-12 message hash, returns the
 *                   verifier-payload felts the envelope needs
 *
 * Frontend wires these to its wallet-connect UI. Each adapter is a
 * separate import so Phantom-only / MetaMask-only / passkey-only
 * builds don't pull in all three dep chains.
 */

import { getBytes, SigningKey, type Signer as EthersSigner } from 'ethers';
import type { DetectedSigner } from './index.ts';

// ============================================================
// Helpers shared across signers
// ============================================================

function hashToBe32Bytes(h: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let rem = h;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(rem & 0xffn);
    rem >>= 8n;
  }
  return bytes;
}

function bytesToLeU256(bytes: Uint8Array): { low: bigint; high: bigint } {
  let low = 0n;
  let high = 0n;
  for (let i = 0; i < 16; i++) low += BigInt(bytes[i]) << BigInt(8 * i);
  for (let i = 0; i < 16; i++) high += BigInt(bytes[16 + i]) << BigInt(8 * i);
  return { low, high };
}

function bytesBeToU256(bytes: Uint8Array): { low: bigint; high: bigint } {
  let x = 0n;
  for (let i = 0; i < bytes.length; i++) x = (x << 8n) | BigInt(bytes[i]);
  const low = x & ((1n << 128n) - 1n);
  const high = x >> 128n;
  return { low, high };
}

function hashToHexAsciiBytes(h: bigint): Uint8Array {
  const hex = h.toString(16).padStart(64, '0');
  return new TextEncoder().encode(hex);
}

function toBase64Url(bytes: Uint8Array): string {
  // Node.js (>=16) and modern browsers both support 'base64url'.
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    return Buffer.from(bytes).toString('base64url');
  }
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const b64 = btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Serialize a Uint8Array into the Cairo ByteArray Serde sequence:
 *   [num_full_words: u32, ...full_words: felt252, pending_word: felt252, pending_len: u32]
 * Each full word packs 31 bytes as a big-endian felt252.
 */
function byteArrayToFelts(bytes: Uint8Array): bigint[] {
  const out: bigint[] = [];
  const numFull = Math.floor(bytes.length / 31);
  out.push(BigInt(numFull));
  for (let i = 0; i < numFull; i++) {
    let v = 0n;
    for (let j = 0; j < 31; j++) v = (v << 8n) | BigInt(bytes[i * 31 + j]);
    out.push(v);
  }
  const rem = bytes.length - numFull * 31;
  let pending = 0n;
  for (let j = 0; j < rem; j++) pending = (pending << 8n) | BigInt(bytes[numFull * 31 + j]);
  out.push(pending);
  out.push(BigInt(rem));
  return out;
}

// ============================================================
// Ed25519 (Phantom / Solana)
// ============================================================

export async function detectEd25519Signer(options: {
  /** Bytes the wallet will sign. Typically `hex_ascii(hash)` per V8 verifier contract. */
  getMessageBytes?: (hash: bigint) => Uint8Array;
  /** Wallet signer, conforming to Phantom's `{ signMessage(msg: Uint8Array) }` shape. */
  phantomLike: {
    publicKey: { toBytes(): Uint8Array };
    signMessage(message: Uint8Array, encoding?: 'utf8'): Promise<{ signature: Uint8Array }>;
  };
  /**
   * Optional Garaga calldata builder — if absent, returns the raw
   * (R || s) concatenation the frontend can forward to a helper.
   * Import `eddsaCalldataBuilder` from `garaga` in the Cifra app.
   */
  eddsaCalldataBuilder?: (
    ry: bigint,
    s: bigint,
    py: bigint,
    msg: Uint8Array,
    prependPublickey?: boolean,
  ) => bigint[];
}): Promise<DetectedSigner> {
  const pub = options.phantomLike.publicKey.toBytes();
  const pubHalves = bytesToLeU256(pub);

  return {
    kind: 'ED25519',
    pubkey: [pubHalves.low, pubHalves.high],
    handle: options.phantomLike,
    async signHash(hash) {
      const msg = (options.getMessageBytes ?? hashToHexAsciiBytes)(hash);
      const { signature } = await options.phantomLike.signMessage(msg, 'utf8');
      if (signature.length !== 64) throw new Error('Unexpected Ed25519 signature length');
      if (!options.eddsaCalldataBuilder) {
        throw new Error(
          'Ed25519 signer needs `eddsaCalldataBuilder` from garaga — pass it in options.',
        );
      }
      const ryHalves = bytesToLeU256(signature.slice(0, 32));
      const sHalves = bytesToLeU256(signature.slice(32, 64));
      const pyHalves = pubHalves;
      return options.eddsaCalldataBuilder(
        (ryHalves.high << 128n) | ryHalves.low,
        (sHalves.high << 128n) | sHalves.low,
        (pyHalves.high << 128n) | pyHalves.low,
        msg,
        false,
      );
    },
  };
}

// ============================================================
// secp256k1 (MetaMask / EVM)
// ============================================================

export async function detectSecp256k1Signer(options: {
  /** ethers Signer (JsonRpcSigner, HDWallet, etc.) */
  signer: EthersSigner & { provider: { getSigningKey?: () => Promise<SigningKey> } };
  /** Raw uncompressed public key hex `0x04 || X || Y`. Required. */
  publicKey: string;
}): Promise<DetectedSigner> {
  const pubBytes = getBytes(options.publicKey);
  if (pubBytes[0] !== 0x04 || pubBytes.length !== 65) {
    throw new Error('Expected uncompressed secp256k1 public key (0x04 || X || Y)');
  }
  const x = bytesBeToU256(pubBytes.slice(1, 33));
  const y = bytesBeToU256(pubBytes.slice(33, 65));

  return {
    kind: 'SECP256K1',
    pubkey: [x.low, x.high, y.low, y.high],
    handle: options.signer,
    async signHash(hash) {
      // ethers' low-level SigningKey gives us (r, s, v). We can't go
      // through eth_personalSign directly because the verifier expects
      // a signature over the raw SNIP-12 hash, not the personal-sign-
      // prefixed hash. The frontend should use the ethers SigningKey
      // imported from the wallet, OR the EIP191 envelope variant (not
      // yet shipped — see plan).
      const key = await options.signer.provider.getSigningKey?.();
      if (!key) {
        throw new Error(
          'Secp256k1 adapter requires `provider.getSigningKey()` or a pre-supplied SigningKey',
        );
      }
      const hashHex = '0x' + hash.toString(16).padStart(64, '0');
      const sig = key.sign(hashHex);
      const r = bytesBeToU256(getBytes(sig.r));
      const s = bytesBeToU256(getBytes(sig.s));
      const yParity = sig.yParity ? 1n : 0n;
      return [r.low, r.high, s.low, s.high, yParity];
    },
  };
}

// ============================================================
// WebAuthn P-256 (Face ID / Touch ID / passkeys)
// ============================================================

export async function detectWebAuthnSigner(options: {
  /** Credential public key bytes (uncompressed 0x04 || X || Y form after COSE decoding). */
  publicKey: Uint8Array;
  /** WebAuthn `get()` response → (authenticatorData, clientDataJSON, compact signature). */
  ceremony: (challengeB64Url: string) => Promise<{
    authenticatorData: Uint8Array;
    clientDataJSON: Uint8Array;
    /** 64-byte compact (r || s) — DER-encoded signatures must be converted beforehand. */
    signatureCompact: Uint8Array;
  }>;
}): Promise<DetectedSigner> {
  if (options.publicKey[0] !== 0x04 || options.publicKey.length !== 65) {
    throw new Error('Expected uncompressed P-256 public key (0x04 || X || Y)');
  }
  const x = bytesBeToU256(options.publicKey.slice(1, 33));
  const y = bytesBeToU256(options.publicKey.slice(33, 65));

  return {
    kind: 'WEBAUTHN_P256',
    pubkey: [x.low, x.high, y.low, y.high],
    handle: options,
    async signHash(hash) {
      // V8 WebAuthn verifier requires a full authenticator-assertion
      // envelope bound to `hash` via the base64url-encoded challenge
      // embedded inside clientDataJSON.
      //
      // Caller builds the challenge from the 32-byte BE encoding of
      // `hash`, passes it into `navigator.credentials.get({ publicKey:
      // { challenge: ... } })`, and hands us back the authenticator
      // output verbatim — we do NOT reparse the challenge.
      const challengeBytes = hashToBe32Bytes(hash);
      const challengeB64Url = toBase64Url(challengeBytes);
      const { authenticatorData, clientDataJSON, signatureCompact } =
        await options.ceremony(challengeB64Url);
      if (signatureCompact.length !== 64) {
        throw new Error(
          'WebAuthn signer expects a 64-byte compact signature (r || s). ' +
          'Call ecdsa-lite / @noble/curves Signature.fromDER().toCompactRawBytes() first.',
        );
      }
      const cdStr = new TextDecoder().decode(clientDataJSON);
      const challengeOffset = cdStr.indexOf(challengeB64Url);
      if (challengeOffset < 0) {
        throw new Error(
          "WebAuthn clientDataJSON did not echo our challenge — either the " +
          "browser stripped the base64url string or the challenge bytes " +
          "didn't round-trip. Refuse to sign.",
        );
      }
      const authDataFelts = byteArrayToFelts(authenticatorData);
      const clientDataFelts = byteArrayToFelts(clientDataJSON);
      const r = bytesBeToU256(signatureCompact.slice(0, 32));
      const s = bytesBeToU256(signatureCompact.slice(32, 64));
      return [
        ...authDataFelts,
        ...clientDataFelts,
        BigInt(challengeOffset),
        r.low, r.high,
        s.low, s.high,
        0n, // y_parity: verifier accepts either; shape-only field.
      ];
    },
  };
}

// ============================================================
// STARK (native Starknet wallets)
// ============================================================

export async function detectStarkSigner(options: {
  publicKey: bigint;
  /** Any Starknet signer that exposes `sign(msgHash: string): Promise<[string, string]>` */
  starknetSigner: { sign(msgHash: string): Promise<string[] | [string, string]> };
}): Promise<DetectedSigner> {
  return {
    kind: 'STARK',
    pubkey: [options.publicKey],
    handle: options.starknetSigner,
    async signHash(hash) {
      const hashHex = '0x' + hash.toString(16);
      const sig = await options.starknetSigner.sign(hashHex);
      if (sig.length < 2) throw new Error('STARK sign returned fewer than 2 components');
      const r = BigInt(sig[0]);
      const s = BigInt(sig[1]);
      return [r, s];
    },
  };
}
