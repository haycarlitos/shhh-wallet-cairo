/**
 * Force-submit a single invoke with EXPLICIT v3 resource bounds, skipping
 * fee estimation — so a transaction whose *execution* reverts still lands
 * on-chain as REVERTED (estimation-based tooling like sncast aborts on the
 * simulated revert and never broadcasts).
 *
 * Used to capture the on-chain over-cap-revert receipt for mainnet Test 14.
 * Reads the call from .test14-invokes.json (written by
 * mainnet-test-14-spending-cap.ts --sncast phase 2) and signs the outer
 * account transaction with the keystore account's key — read locally, never
 * printed.
 *
 *   tsx force-invoke.ts <stepIndex>   # 2 = the over-cap step
 *
 * Env: STARKNET_RPC, SNCAST_ACCOUNT (default deployer_oz),
 *      ACCOUNTS_FILE (default ~/.starknet_accounts/starknet_open_zeppelin_accounts.json),
 *      ACCOUNTS_NETWORK (default alpha-mainnet).
 */

import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { RpcProvider, Account, hash } from 'starknet';

const RPC = process.env.STARKNET_RPC ?? 'https://starknet-rpc.publicnode.com';
const ACCOUNT_NAME = process.env.SNCAST_ACCOUNT ?? 'deployer_oz';
const NETWORK = process.env.ACCOUNTS_NETWORK ?? 'alpha-mainnet';
const ACCOUNTS_FILE =
  process.env.ACCOUNTS_FILE ?? `${homedir()}/.starknet_accounts/starknet_open_zeppelin_accounts.json`;

const stepIndex = Number(process.argv[2] ?? '2');

function bn(x: bigint | string | number): bigint {
  return typeof x === 'bigint' ? x : BigInt(x);
}
function h(x: bigint): string {
  return '0x' + x.toString(16);
}

async function main(): Promise<void> {
  const invokes = JSON.parse(readFileSync(new URL('./.test14-invokes.json', import.meta.url).pathname, 'utf8'));
  const step = invokes.steps[stepIndex];
  const wallet: string = invokes.wallet;
  if (!step) throw new Error(`no step ${stepIndex} in .test14-invokes.json`);

  const accounts = JSON.parse(readFileSync(ACCOUNTS_FILE, 'utf8'));
  const acct = accounts[NETWORK]?.[ACCOUNT_NAME];
  if (!acct?.private_key) throw new Error(`account ${ACCOUNT_NAME} not found in ${ACCOUNTS_FILE}`);

  const provider = new RpcProvider({ nodeUrl: RPC });
  const account = new Account({ provider, address: acct.address, signer: acct.private_key });

  // Current gas prices → set generous max prices (3×) so the node accepts
  // the tx; a reverting tx still consumes gas up to the revert point.
  const block: any = await provider.getBlockWithTxHashes('latest');
  const l1 = bn(block.l1_gas_price?.price_in_fri ?? block.l1_gas_price?.price_in_wei ?? '0x174876e800');
  const l2 = bn(block.l2_gas_price?.price_in_fri ?? '0x5f5e100');
  const l1d = bn(block.l1_data_gas_price?.price_in_fri ?? '0x3b9aca00');
  const resourceBounds = {
    l1_gas: { max_amount: 20_000n, max_price_per_unit: l1 * 3n },
    l2_gas: { max_amount: 200_000_000n, max_price_per_unit: l2 * 3n },
    l1_data_gas: { max_amount: 200_000n, max_price_per_unit: l1d * 3n },
  };

  console.log(`force-invoke step ${stepIndex} (${step.label}) on ${wallet}`);
  console.log(`expect: ${step.expect}${step.reason ? ` ("${step.reason}")` : ''}`);

  const { transaction_hash } = await account.execute(
    [{ contractAddress: wallet, entrypoint: 'execute_from_outside_v2', calldata: step.calldata }],
    { resourceBounds, tip: 0n } as any,
  );
  console.log('submitted:', transaction_hash);
  console.log(`starkscan: https://starkscan.co/tx/${transaction_hash}`);

  // Poll the receipt (don't let waitForTransaction throw on REVERTED).
  let receipt: any;
  for (let i = 0; i < 60; i++) {
    try {
      receipt = await provider.getTransactionReceipt(transaction_hash);
      const exec = receipt.execution_status ?? receipt.executionStatus;
      if (exec === 'SUCCEEDED' || exec === 'REVERTED') break;
    } catch {
      /* not found yet */
    }
    await new Promise((r) => setTimeout(r, 5000));
  }
  const exec = receipt?.execution_status ?? receipt?.executionStatus ?? 'UNKNOWN';
  const reason = String(receipt?.revert_reason ?? receipt?.revertReason ?? '');
  console.log('execution_status:', exec);
  if (reason) console.log('revert_reason:', reason);

  const reasonOk =
    step.expect !== 'REVERTED' ||
    reason.includes(step.reason) ||
    reason.includes(h(BigInt('0x' + Buffer.from(step.reason).toString('hex'))));
  const pass = exec === step.expect && reasonOk;
  console.log(`=> ${pass ? 'PASS' : 'FAIL'}`);
  if (!pass) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
