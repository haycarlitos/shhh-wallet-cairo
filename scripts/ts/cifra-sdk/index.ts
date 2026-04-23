/**
 * Cifra SDK — Drop-in TypeScript surface for the Cifra Next.js
 * frontend to consume V8 ShhhAccount.
 *
 * This module composes the Phase 1 SNIP-12 hashing primitive, the
 * deterministic address derivation, and the signer-kind dispatch so
 * the frontend never has to reach into per-curve wallet APIs directly.
 *
 * Typical flow for a new user:
 *
 *   const signer = await detectPrimarySigner();           // Phantom / MetaMask / passkey
 *   const { address, alreadyDeployed } = await computeAccountAddress(signer, CLASSES);
 *   if (!alreadyDeployed) await deployViaPaymaster(address, signer, CLASSES);
 *   const signed = await signOutsideExecution(signer, {
 *     accountAddress: address,
 *     chainId: SN_MAIN,
 *     nonce: randomNonce(),
 *     executeAfter: 0n,
 *     executeBefore: nowSec() + 3600n,
 *     calls: [{ contractAddress: MARKET, entrypoint: 'place_bet', calldata: [...] }],
 *   });
 *   await paymaster.submit(address, signed.oe, signed.envelope);
 */

import { hash, shortString, type Call } from 'starknet';
import {
  SIG_VERSION_V2_SNIP12,
  computeSnip12Hash,
  type OutsideExecution,
} from '../snip12-hash.ts';
import { computeShhhAddress, ownerCommitment } from '../compute-wallet-address.ts';

// ============================================================
// Types
// ============================================================

export type SignerKind = 'ED25519' | 'SECP256K1' | 'WEBAUTHN_P256' | 'STARK';

export type DetectedSigner = {
  kind: SignerKind;
  /** Raw pubkey bytes, curve-specific shape: Ed25519 [low,high], others [x_lo,x_hi,y_lo,y_hi]. */
  pubkey: bigint[];
  /** Opaque wallet handle — Phantom, ethers Signer, WebAuthn credential id, etc. */
  handle: unknown;
  /** Function that signs a 32-byte BE hash and returns the verifier-ready envelope payload. */
  signHash: (message: bigint) => Promise<bigint[]>;
};

export type CifraClasses = {
  shhhAccountClassHash: bigint;
  verifierClassHashes: Record<SignerKind, bigint>;
};

export type SignedEnvelope = {
  oe: OutsideExecution;
  envelope: bigint[];
  messageHash: bigint;
};

// ============================================================
// Address derivation — mirrors ShhhAccount constructor
// ============================================================

export function computeAccountAddress(
  signer: DetectedSigner,
  classes: CifraClasses,
  label = 'primary',
): bigint {
  return computeShhhAddress({
    classHash: classes.shhhAccountClassHash,
    primaryKind: signer.kind,
    pubkey: signer.pubkey,
    verifierClassHash: classes.verifierClassHashes[signer.kind],
    label,
  });
}

// ============================================================
// OE envelope construction
// ============================================================

const OWNER_ID_PRIMARY = 0n;

/**
 * Builds an OutsideExecution, computes its SNIP-12 hash, asks the
 * detected signer to sign, and assembles the full owner envelope the
 * V8 ShhhAccount accepts:
 *   [ SIG_VERSION_V2_SNIP12, owner_id=0, kind_tag, curve_payload... ]
 */
export async function signOutsideExecution(
  signer: DetectedSigner,
  input: {
    accountAddress: bigint;
    chainId: bigint;
    nonce: bigint;
    executeAfter: bigint;
    executeBefore: bigint;
    calls: Call[];
    /** Omit / set 'ANY_CALLER' for paymaster-style bearer execution. */
    caller?: bigint;
  },
): Promise<SignedEnvelope> {
  const ANY_CALLER = BigInt(shortString.encodeShortString('ANY_CALLER'));
  const oe: OutsideExecution = {
    caller: input.caller ?? ANY_CALLER,
    nonce: input.nonce,
    execute_after: input.executeAfter,
    execute_before: input.executeBefore,
    calls: input.calls,
  };

  const messageHash = computeSnip12Hash(oe, input.accountAddress, input.chainId);
  const curvePayload = await signer.signHash(messageHash);

  const kindTag = BigInt(shortString.encodeShortString(signer.kind));
  const envelope: bigint[] = [
    BigInt(SIG_VERSION_V2_SNIP12),
    OWNER_ID_PRIMARY,
    kindTag,
    ...curvePayload,
  ];

  return { oe, envelope, messageHash };
}

// ============================================================
// Session key + spending policy flows
// ============================================================

const SELECTOR_ADD_OR_UPDATE_SESSION_KEY = hash.getSelectorFromName(
  'add_or_update_session_key',
);
const SELECTOR_REVOKE_SESSION_KEY = hash.getSelectorFromName('revoke_session_key');
const SELECTOR_SET_SPENDING_POLICY = hash.getSelectorFromName('set_spending_policy');
const SELECTOR_REMOVE_SPENDING_POLICY = hash.getSelectorFromName('remove_spending_policy');

export function callAddOrUpdateSessionKey(args: {
  accountAddress: bigint;
  sessionKey: bigint;
  validUntil: bigint;
  maxCalls: number;
  allowedEntrypoints: string[];
}): Call {
  const selectors = args.allowedEntrypoints.map((e) => hash.getSelectorFromName(e));
  return {
    contractAddress: '0x' + args.accountAddress.toString(16),
    entrypoint: 'add_or_update_session_key',
    calldata: [
      '0x' + args.sessionKey.toString(16),
      '0x' + args.validUntil.toString(16),
      String(args.maxCalls),
      String(selectors.length),
      ...selectors,
    ],
  };
}

export function callRevokeSessionKey(args: {
  accountAddress: bigint;
  sessionKey: bigint;
}): Call {
  return {
    contractAddress: '0x' + args.accountAddress.toString(16),
    entrypoint: 'revoke_session_key',
    calldata: ['0x' + args.sessionKey.toString(16)],
  };
}

export function callSetSpendingPolicy(args: {
  accountAddress: bigint;
  sessionKey: bigint;
  token: bigint;
  maxPerCall: bigint;
  maxPerWindow: bigint;
  windowSeconds: bigint;
}): Call {
  const asU256 = (x: bigint) => {
    const low = x & ((1n << 128n) - 1n);
    const high = x >> 128n;
    return ['0x' + low.toString(16), '0x' + high.toString(16)];
  };
  return {
    contractAddress: '0x' + args.accountAddress.toString(16),
    entrypoint: 'set_spending_policy',
    calldata: [
      '0x' + args.sessionKey.toString(16),
      '0x' + args.token.toString(16),
      ...asU256(args.maxPerCall),
      ...asU256(args.maxPerWindow),
      '0x' + args.windowSeconds.toString(16),
    ],
  };
}

// ============================================================
// Recovery flow helpers
// ============================================================

const SELECTOR_INITIATE_RECOVERY = hash.getSelectorFromName('initiate_recovery');
const SELECTOR_CANCEL_RECOVERY = hash.getSelectorFromName('cancel_recovery');
const SELECTOR_FINALIZE_RECOVERY = hash.getSelectorFromName('finalize_recovery');

export function callInitiateRecovery(args: {
  accountAddress: bigint;
  proposer: number; // owner_id of the guardian
  newOwnerKind: SignerKind;
  newPubkey: bigint[];
  role: 'OWNER' | 'GUARDIAN' | 'RECOVERY_ONLY';
  weight: number;
  label: string;
}): Call {
  const kindTag = BigInt(shortString.encodeShortString(args.newOwnerKind));
  const roleTag = BigInt(shortString.encodeShortString(args.role));
  const labelFelt = BigInt(shortString.encodeShortString(args.label));
  return {
    contractAddress: '0x' + args.accountAddress.toString(16),
    entrypoint: 'initiate_recovery',
    calldata: [
      String(args.proposer),
      '0x' + kindTag.toString(16),
      String(args.newPubkey.length),
      ...args.newPubkey.map((x) => '0x' + x.toString(16)),
      '0x' + roleTag.toString(16),
      String(args.weight),
      '0x' + labelFelt.toString(16),
    ],
  };
}

export function callCancelRecovery(args: {
  accountAddress: bigint;
  ownerId: number;
}): Call {
  return {
    contractAddress: '0x' + args.accountAddress.toString(16),
    entrypoint: 'cancel_recovery',
    calldata: [String(args.ownerId)],
  };
}

export function callFinalizeRecovery(args: {
  accountAddress: bigint;
  newOwnerKind: SignerKind;
  newPubkey: bigint[];
  role: 'OWNER' | 'GUARDIAN' | 'RECOVERY_ONLY';
  weight: number;
  label: string;
}): Call {
  const kindTag = BigInt(shortString.encodeShortString(args.newOwnerKind));
  const roleTag = BigInt(shortString.encodeShortString(args.role));
  const labelFelt = BigInt(shortString.encodeShortString(args.label));
  return {
    contractAddress: '0x' + args.accountAddress.toString(16),
    entrypoint: 'finalize_recovery',
    calldata: [
      '0x' + kindTag.toString(16),
      String(args.newPubkey.length),
      ...args.newPubkey.map((x) => '0x' + x.toString(16)),
      '0x' + roleTag.toString(16),
      String(args.weight),
      '0x' + labelFelt.toString(16),
    ],
  };
}

// ============================================================
// Utility
// ============================================================

export function randomNonce(): bigint {
  // 252-bit random nonce (first bit zero for felt252 safety).
  const buf = new Uint8Array(31);
  crypto.getRandomValues(buf);
  let x = 0n;
  for (const b of buf) x = (x << 8n) | BigInt(b);
  return x;
}

export function nowSec(): bigint {
  return BigInt(Math.floor(Date.now() / 1000));
}

// Re-export the key selectors so the frontend can reference by name.
export const SELECTORS = {
  addOrUpdateSessionKey: SELECTOR_ADD_OR_UPDATE_SESSION_KEY,
  revokeSessionKey: SELECTOR_REVOKE_SESSION_KEY,
  setSpendingPolicy: SELECTOR_SET_SPENDING_POLICY,
  removeSpendingPolicy: SELECTOR_REMOVE_SPENDING_POLICY,
  initiateRecovery: SELECTOR_INITIATE_RECOVERY,
  cancelRecovery: SELECTOR_CANCEL_RECOVERY,
  finalizeRecovery: SELECTOR_FINALIZE_RECOVERY,
};

export { ownerCommitment, computeSnip12Hash };
