/**
 * SNIP-12 typed-data hash for `OutsideExecution` — TypeScript reference.
 *
 * This MUST produce byte-identical output to
 * `compute_snip12_hash` in `src/outside_execution.cairo`.
 *
 * Run with: `node --experimental-strip-types scripts/ts/snip12-hash.ts`
 * or compile with: `npx tsx scripts/ts/snip12-hash.ts`.
 *
 * Verification: `scripts/ts/snip12-hash.test.ts` computes the same
 * fixture vectors that the Cairo test in `tests/snip12_hash.cairo`
 * uses, asserts the two outputs are equal, and additionally asserts
 * hash sensitivity to every field.
 */

import { hash, shortString, CallData, type Call, type RawArgs } from 'starknet';

// ================================================================
// Constants — MUST match src/outside_execution.cairo exactly.
// ================================================================

export const OUTSIDE_EXECUTION_TYPE_HASH_REV1 =
  0x5a4b49e17039355cd95d1f0981d75901191d1319b1f4b05a9a791d218d7e0cn;

export const CALL_TYPE_HASH_REV1 =
  0x3635c7f2a7ba93844c0d064e18e487f35ab90f7c39d00f186a781fc3f0c2ca9n;

export const STARKNET_DOMAIN_TYPE_HASH_REV1 =
  0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210n;

export const STARKNET_MESSAGE_PREFIX = shortString.encodeShortString('StarkNet Message');

export const OE_DOMAIN_NAME     = shortString.encodeShortString('Account.execute_from_outside');
export const OE_DOMAIN_VERSION  = 2n;
export const OE_DOMAIN_REVISION = 1n;

export const SIG_VERSION_V1_HEX_ASCII = shortString.encodeShortString('V1_HEX_ASCII');
export const SIG_VERSION_V2_SNIP12    = shortString.encodeShortString('V2_SNIP12');
export const SIG_VERSION_V2_THRESHOLD = shortString.encodeShortString('V2_THRESHOLD');

// ================================================================
// Types
// ================================================================

export type OutsideExecution = {
  caller:          bigint | string;  // ContractAddress (hex or bigint)
  nonce:           bigint | string;
  execute_after:   bigint;           // u64
  execute_before:  bigint;           // u64
  calls:           Call[];
};

// ================================================================
// Hash functions
// ================================================================

function toBigInt(x: bigint | string | number): bigint {
  if (typeof x === 'bigint') return x;
  if (typeof x === 'number') return BigInt(x);
  return BigInt(x); // accepts "0x..." or decimal strings
}

function poseidonSpan(values: Array<bigint | string>): bigint {
  const felts = values.map((v) =>
    typeof v === 'bigint' ? '0x' + v.toString(16) : v,
  );
  return BigInt(hash.computePoseidonHashOnElements(felts));
}

export function hashCall(call: Call): bigint {
  const calldataFelts: string[] = CallData.toHex(
    (Array.isArray(call.calldata) ? call.calldata : [call.calldata]) as RawArgs,
  );
  const calldataItems = calldataFelts.map((x) => BigInt(x));
  const calldataHash = poseidonSpan(calldataItems);
  return poseidonSpan([
    CALL_TYPE_HASH_REV1,
    toBigInt(call.contractAddress),
    toBigInt(hash.getSelectorFromName(call.entrypoint)),
    calldataHash,
  ]);
}

export function hashCalls(calls: Call[]): bigint {
  const callHashes = calls.map(hashCall);
  return poseidonSpan(callHashes);
}

export function hashStarknetDomain(chainIdFelt: bigint | string): bigint {
  return poseidonSpan([
    STARKNET_DOMAIN_TYPE_HASH_REV1,
    BigInt(OE_DOMAIN_NAME),
    OE_DOMAIN_VERSION,
    toBigInt(chainIdFelt),
    OE_DOMAIN_REVISION,
  ]);
}

export function hashOutsideExecutionStruct(oe: OutsideExecution): bigint {
  const callsArrayHash = hashCalls(oe.calls);
  return poseidonSpan([
    OUTSIDE_EXECUTION_TYPE_HASH_REV1,
    toBigInt(oe.caller),
    toBigInt(oe.nonce),
    oe.execute_after,
    oe.execute_before,
    callsArrayHash,
  ]);
}

/**
 * The authoritative SNIP-12 message hash for an OutsideExecution.
 * Signers sign over this felt252 (or its hex-ASCII re-encoding for
 * Phantom UX compatibility).
 */
export function computeSnip12Hash(
  oe: OutsideExecution,
  contractAddress: bigint | string,
  chainIdFelt: bigint | string,
): bigint {
  const domainHash = hashStarknetDomain(chainIdFelt);
  const structHash = hashOutsideExecutionStruct(oe);
  return poseidonSpan([
    BigInt(STARKNET_MESSAGE_PREFIX),
    domainHash,
    toBigInt(contractAddress),
    structHash,
  ]);
}

// ================================================================
// Phantom hex-ASCII envelope helper.
// ================================================================
//
// Phantom signs a string. We give it a 64-byte hex-ASCII
// representation of the SNIP-12 hash, and the Cairo verifier
// re-computes the hash and compares byte-by-byte.

export function snip12HashToHexAsciiBytes(h: bigint): Uint8Array {
  const hex = h.toString(16).padStart(64, '0'); // 32 bytes -> 64 ASCII chars
  return new TextEncoder().encode(hex);
}

// ================================================================
// CLI entry — print hashes for the canonical test fixtures so the
// Cairo and TS outputs can be diffed by hand during development.
// ================================================================

if (import.meta.url.endsWith(process.argv[1] ?? '')) {
  const ANY_CALLER = BigInt(shortString.encodeShortString('ANY_CALLER'));
  const DEV_CHAIN: bigint = BigInt(shortString.encodeShortString('SN_MAIN'));
  const DEV_ADDR = 0x1234n;

  const oeMinimal: OutsideExecution = {
    caller: ANY_CALLER, nonce: 1n, execute_after: 0n, execute_before: 1000n, calls: [],
  };
  const oeOneCall: OutsideExecution = {
    caller: ANY_CALLER, nonce: 2n, execute_after: 0n, execute_before: 1000n,
    calls: [{
      contractAddress: '0xBEEF',
      entrypoint: 'foo',
      calldata: ['0xAA', '0xBB'],
    }],
  };

  console.log('SNIP-12 hash (minimal OE):        0x' + computeSnip12Hash(oeMinimal, DEV_ADDR, DEV_CHAIN).toString(16));
  console.log('SNIP-12 hash (one-call OE):       0x' + computeSnip12Hash(oeOneCall, DEV_ADDR, DEV_CHAIN).toString(16));
  console.log('SIG_VERSION_V1_HEX_ASCII tag:     0x' + BigInt(SIG_VERSION_V1_HEX_ASCII).toString(16));
  console.log('SIG_VERSION_V2_SNIP12    tag:     0x' + BigInt(SIG_VERSION_V2_SNIP12).toString(16));
}
