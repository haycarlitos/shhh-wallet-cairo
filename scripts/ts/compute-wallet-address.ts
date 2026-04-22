/**
 * Deterministic ShhhAccount (V8) address derivation.
 *
 * Given the primary owner (kind + raw pubkey bytes) and the
 * ShhhAccount class hash, returns the Starknet address the account
 * will deploy to. Useful for:
 *   - paymaster pre-funding ("send USDC to this address before deploy")
 *   - "connect your wallet" flows that look up existing deployments
 *   - indexers that need to match events to predicted addresses
 *
 * The salt binds `primary_kind` into the address so the same raw key
 * encoded under two different kinds produces two distinct addresses.
 * MUST match `src/account.cairo::constructor`.
 *
 * Exports both a programmatic API and a CLI for ops tooling.
 */

import { hash, shortString, CallData } from 'starknet';

export type ComputeAddressInput = {
  classHash: bigint;                     // ShhhAccount class hash
  primaryKind: string;                   // e.g. 'ED25519'
  pubkey: bigint[];                      // u256-halves or whatever the verifier expects
  verifierClassHash: bigint;             // kind-specific verifier class
  label?: string;                        // optional user tag
  deployerAddress?: bigint;              // factory / UDC address; default 0 for self-deploy
};

// poseidon_hash_span matches core::poseidon::poseidon_hash_span on-chain.
function poseidon(values: Array<bigint | string>): bigint {
  const felts = values.map((v) =>
    typeof v === 'bigint' ? '0x' + v.toString(16) : v,
  );
  return BigInt(hash.computePoseidonHashOnElements(felts));
}

/**
 * Mirrors `src/signer/interface.cairo::owner_commitment`.
 * `poseidon(kind_tag, pubkey...)`.
 */
export function ownerCommitment(kindTag: bigint, pubkey: bigint[]): bigint {
  return poseidon([kindTag, ...pubkey]);
}

/**
 * Mirrors the constructor's salt derivation:
 *   salt = poseidon(primary_kind, primary_pubkey_hash)
 * where `primary_pubkey_hash = owner_commitment(primary_kind, pubkey)`.
 */
export function computeAddressSalt(primaryKind: string, pubkey: bigint[]): bigint {
  const kindTag = BigInt(shortString.encodeShortString(primaryKind));
  const pubkeyHash = ownerCommitment(kindTag, pubkey);
  return poseidon([kindTag, pubkeyHash]);
}

/**
 * Computes the deterministic deployment address for a ShhhAccount.
 */
export function computeShhhAddress(input: ComputeAddressInput): bigint {
  const {
    classHash,
    primaryKind,
    pubkey,
    verifierClassHash,
    label = 'primary',
    deployerAddress = 0n,
  } = input;

  const salt = computeAddressSalt(primaryKind, pubkey);
  const kindTag = BigInt(shortString.encodeShortString(primaryKind));
  const labelFelt = BigInt(shortString.encodeShortString(label));

  // Constructor calldata: [primary_kind, primary_verifier, pubkey_len, pubkey..., label]
  const ctor: Array<bigint | string> = [
    kindTag,
    verifierClassHash,
    BigInt(pubkey.length),
    ...pubkey,
    labelFelt,
  ];

  const addressHex = hash.calculateContractAddressFromHash(
    '0x' + salt.toString(16),
    '0x' + classHash.toString(16),
    ctor.map((x) => (typeof x === 'bigint' ? '0x' + x.toString(16) : x)),
    '0x' + deployerAddress.toString(16),
  );
  return BigInt(addressHex);
}

// --------------------------------------------------------------
// CLI entry — run with:
//   tsx scripts/ts/compute-wallet-address.ts <class_hash> <kind> <verifier_class> <pk_lo> <pk_hi> [label]
// --------------------------------------------------------------

if (import.meta.url.endsWith(process.argv[1] ?? '')) {
  const [classArg, kindArg, vArg, pkLoArg, pkHiArg, labelArg] = process.argv.slice(2);
  if (!classArg || !kindArg || !vArg || !pkLoArg || !pkHiArg) {
    console.error(
      'usage: tsx compute-wallet-address.ts <class_hash> <kind> <verifier_class> <pk_lo> <pk_hi> [label]',
    );
    process.exit(1);
  }
  const addr = computeShhhAddress({
    classHash: BigInt(classArg),
    primaryKind: kindArg,
    pubkey: [BigInt(pkLoArg), BigInt(pkHiArg)],
    verifierClassHash: BigInt(vArg),
    label: labelArg,
  });
  console.log('0x' + addr.toString(16));
}
