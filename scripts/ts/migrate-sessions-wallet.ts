/**
 * Migration SDK for sessions-smart-contract → V8.
 *
 * Given a sessions-wallet (`chipi-pay/sessions-smart-contract`,
 * starknet-io/SNIPs#163) and its owner's STARK key, builds the
 * single atomic OutsideExecution multicall that migrates it to V8:
 *
 *     [
 *       upgrade(SHHH_ACCOUNT_CLASS_HASH),
 *       bootstrap_from_sessions(public_key, STARK_VERIFIER_CLASS_HASH, label),
 *     ]
 *
 * Atomicity is the security property — if an attacker front-runs
 * `bootstrap_from_sessions` between the upgrade and bootstrap, they
 * could claim the account. The SDK always bundles them in one OE so
 * that window doesn't exist.
 *
 * Usage:
 *   import { buildMigrationCalls } from './migrate-sessions-wallet.ts';
 *   const calls = buildMigrationCalls({
 *     sessionsAccountAddress: '0x...',
 *     sessionsPublicKey: '0x...',
 *     shhhAccountClassHash: '0x...',
 *     starkVerifierClassHash: '0x...',
 *     label: 'migrated',
 *   });
 *   // Feed `calls` to the sessions wallet's OutsideExecution signer.
 */

import { hash, CallData, type Call } from 'starknet';

export type MigrationParams = {
  sessionsAccountAddress: string | bigint;
  sessionsPublicKey: string | bigint;
  shhhAccountClassHash: string | bigint;
  starkVerifierClassHash: string | bigint;
  label?: string;
};

const UPGRADE_SELECTOR = hash.getSelectorFromName('upgrade');
const BOOTSTRAP_SELECTOR = hash.getSelectorFromName('bootstrap_from_sessions');

function asHex(x: string | bigint): string {
  return typeof x === 'bigint' ? '0x' + x.toString(16) : x;
}

function labelToFelt(label: string): string {
  if (label.length === 0) return '0x0';
  if (label.length > 31) {
    throw new Error('Label too long; must fit in felt252 short-string (≤31 bytes)');
  }
  return '0x' + Buffer.from(label).toString('hex');
}

/**
 * Builds the two-call atomic multicall for a sessions-wallet → V8
 * migration. The caller feeds this array to the sessions wallet's
 * OutsideExecution signer; one signature covers both calls.
 */
export function buildMigrationCalls(params: MigrationParams): Call[] {
  const { sessionsAccountAddress, sessionsPublicKey, shhhAccountClassHash, starkVerifierClassHash } = params;
  const label = params.label ?? 'migrated';

  const upgradeCall: Call = {
    contractAddress: asHex(sessionsAccountAddress),
    entrypoint: 'upgrade',
    calldata: [asHex(shhhAccountClassHash)],
  };

  const bootstrapCall: Call = {
    contractAddress: asHex(sessionsAccountAddress),
    entrypoint: 'bootstrap_from_sessions',
    calldata: [
      asHex(sessionsPublicKey),
      asHex(starkVerifierClassHash),
      labelToFelt(label),
    ],
  };

  return [upgradeCall, bootstrapCall];
}

// --------------------------------------------------------------
// CLI for ops tooling. Prints the calldata in the order a paymaster
// can feed to an OutsideExecution builder.
// --------------------------------------------------------------

if (import.meta.url.endsWith(process.argv[1] ?? '')) {
  const [acct, pk, v8Class, verifierClass, label] = process.argv.slice(2);
  if (!acct || !pk || !v8Class || !verifierClass) {
    console.error(
      'usage: tsx migrate-sessions-wallet.ts <sessions_account_addr> <public_key> <v8_class_hash> <verifier_class_hash> [label]',
    );
    process.exit(1);
  }
  const calls = buildMigrationCalls({
    sessionsAccountAddress: acct,
    sessionsPublicKey: pk,
    shhhAccountClassHash: v8Class,
    starkVerifierClassHash: verifierClass,
    label,
  });
  console.log(JSON.stringify(calls, null, 2));
  console.log('---');
  console.log(
    'Selectors: upgrade =',
    UPGRADE_SELECTOR,
    '| bootstrap_from_sessions =',
    BOOTSTRAP_SELECTOR,
  );
}
