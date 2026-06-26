/**
 * Mainnet "Test 4" — EIP-712 typed-data (MetaMask `eth_signTypedData_v4`)
 * owner OE on a live V8.4 ShhhAccount.
 *
 * Smokes `EIP712Secp256k1Verifier` end-to-end: deploy a V8.4 wallet whose
 * primary owner is a secp256k1 key, then sign one OE as an EIP-712 typed
 * message and relay it. The verifier recomputes the EIP-712 final hash on
 * chain from runtime context (chainId = tx.chain_id, salt = account address)
 * and ecrecovers the pubkey.
 *
 * Domain   : EIP712Domain(string name,string version,uint256 chainId,bytes32 salt)
 *            name='Shhh', version='1', chainId='SN_MAIN', salt=wallet address
 * Struct   : MessageHash(bytes32 hash)   where hash = the SNIP-12 OE hash
 * Envelope : [V2_SNIP12, owner_id=0, 'EIP712_SECP256K1', r_lo, r_hi, s_lo, s_hi, y_parity]
 *
 * Recipe matches scripts/ts/gen-eip712-fixture.mjs (ethers signTypedData),
 * with chainId/salt set to the live mainnet values instead of the snforge
 * test constants (0 / 0x1d6e).
 *
 *   tsx mainnet-test-04-eip712.ts            # dry-run
 *   tsx mainnet-test-04-eip712.ts --submit   # deploy + relay on mainnet
 */

import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { Wallet, getBytes } from 'ethers';
import { RpcProvider, Account, hash, shortString } from 'starknet';
import { computeSnip12Hash, type OutsideExecution } from './snip12-hash';

const SUBMIT = process.argv.includes('--submit');
const RPC = process.env.STARKNET_RPC ?? 'https://starknet-rpc.publicnode.com';
const SHHH_ACCOUNT_CLASS = process.env.SHHH_ACCOUNT_CLASS ?? '0x075dfb396145926bffa6beb659897f46cc082a50b211d80871cff7f1038fa58a';
const EIP712_VERIFIER_CLASS = process.env.EIP712_VERIFIER_CLASS ?? '0x072a3f77e8c28bfea2ade91ec3fb83b6290169d1ed8c1b2396704231841c6474';
const STRK = '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d';

const ACCOUNTS_FILE = process.env.ACCOUNTS_FILE ?? `${homedir()}/.starknet_accounts/starknet_open_zeppelin_accounts.json`;
const ACCOUNTS_NETWORK = process.env.ACCOUNTS_NETWORK ?? 'alpha-mainnet';
const DEPLOYER = process.env.SNCAST_ACCOUNT ?? 'deployer_oz';

const KEYS_FILE = new URL('./.test04-keys.json', import.meta.url).pathname;
const CHAIN_ID = shortString.encodeShortString('SN_MAIN'); // 0x534e5f4d41494e
const ANY_CALLER = BigInt(shortString.encodeShortString('ANY_CALLER'));
const V2_SNIP12 = BigInt(shortString.encodeShortString('V2_SNIP12'));
const KIND_EIP712 = shortString.encodeShortString('EIP712_SECP256K1');

type Felt = string;
const hx = (x: bigint | number | string): string =>
  typeof x === 'string' ? (x.startsWith('0x') ? x : '0x' + BigInt(x).toString(16)) : '0x' + BigInt(x).toString(16);
const pad32 = (x: bigint): string => '0x' + x.toString(16).padStart(64, '0');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function beToU256(b: Uint8Array): [bigint, bigint] {
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return [x & ((1n << 128n) - 1n), x >> 128n];
}

function privHex(): string {
  if (process.env.EIP712_PRIV) return process.env.EIP712_PRIV;
  if (existsSync(KEYS_FILE)) return JSON.parse(readFileSync(KEYS_FILE, 'utf8')).priv;
  const pk = '0x' + randomBytes(32).toString('hex');
  if (SUBMIT) writeFileSync(KEYS_FILE, JSON.stringify({ priv: pk, note: 'ephemeral test04 EIP-712 secp256k1 key' }, null, 2));
  return pk;
}

const WALLET_ETH = new Wallet(privHex());
const PUB = getBytes(WALLET_ETH.signingKey.publicKey); // 0x04 || X(32) || Y(32)
const [xLo, xHi] = beToU256(PUB.slice(1, 33));
const [yLo, yHi] = beToU256(PUB.slice(33, 65));
const PUBKEY: Felt[] = [hx(xLo), hx(xHi), hx(yLo), hx(yHi)];

async function signEip712(walletAddr: bigint, msgHash: bigint): Promise<Felt[]> {
  const domain = { name: 'Shhh', version: '1', chainId: BigInt(CHAIN_ID), salt: pad32(walletAddr) };
  const types = { MessageHash: [{ name: 'hash', type: 'bytes32' }] };
  const value = { hash: pad32(msgHash) };
  const sig = getBytes(await WALLET_ETH.signTypedData(domain, types, value)); // 65 bytes r||s||v
  const [rLo, rHi] = beToU256(sig.slice(0, 32));
  const [sLo, sHi] = beToU256(sig.slice(32, 64));
  const yParity = sig[64] === 28 ? 1 : 0;
  return [hx(rLo), hx(rHi), hx(sLo), hx(sHi), hx(yParity)];
}

function serializeOe(oe: OutsideExecution, calls: { to: string; selector: string; calldata: Felt[] }[], sig: Felt[]): Felt[] {
  const out: Felt[] = [hx(oe.caller as bigint), hx(oe.nonce as bigint), hx(oe.execute_after), hx(oe.execute_before), hx(calls.length)];
  for (const c of calls) out.push(c.to, c.selector, hx(c.calldata.length), ...c.calldata);
  out.push(hx(sig.length), ...sig);
  return out;
}
function relayer(provider: RpcProvider): Account {
  const a = JSON.parse(readFileSync(ACCOUNTS_FILE, 'utf8'))[ACCOUNTS_NETWORK]?.[DEPLOYER];
  if (!a?.private_key) throw new Error(`${DEPLOYER} not found in ${ACCOUNTS_FILE}`);
  return new Account({ provider, address: a.address, signer: a.private_key });
}
async function waitReceipt(provider: RpcProvider, txHash: string): Promise<any> {
  for (let i = 0; i < 60; i++) {
    try { const r: any = await provider.getTransactionReceipt(txHash); const e = r.execution_status ?? r.executionStatus; if (e === 'SUCCEEDED' || e === 'REVERTED') return r; } catch {}
    await sleep(5000);
  }
  throw new Error('receipt timeout: ' + txHash);
}
async function execWithRetry(acct: Account, call: any[]): Promise<string> {
  for (let attempt = 0; attempt < 6; attempt++) {
    const nonce = await acct.getNonce('latest');
    try { const { transaction_hash } = await acct.execute(call, { nonce } as any); return transaction_hash; }
    catch (e) { const m = String((e as any)?.message ?? e); if (m.toLowerCase().includes('nonce') && attempt < 5) { await sleep(8000); continue; } throw e; }
  }
  throw new Error('exec failed');
}

const nowSec = BigInt(Math.floor(Date.now() / 1000));

async function main(): Promise<void> {
  console.log('='.repeat(64));
  console.log('Mainnet Test 4 — EIP-712 typed-data owner OE', SUBMIT ? '(SUBMIT)' : '(DRY-RUN)');
  console.log('='.repeat(64));
  console.log('account class    :', SHHH_ACCOUNT_CLASS);
  console.log('EIP712 verifier  :', EIP712_VERIFIER_CLASS);
  console.log('domain.chainId   :', hx(BigInt(CHAIN_ID)), "('SN_MAIN')");
  console.log('pubkey [x,y]     :', PUBKEY.join(' '));

  const provider = new RpcProvider({ nodeUrl: RPC });
  const ctor: Felt[] = [hx(KIND_EIP712), hx(EIP712_VERIFIER_CLASS), hx(4), ...PUBKEY, hx(shortString.encodeShortString('primary'))];

  if (!SUBMIT) {
    console.log('\nDRY-RUN — constructor calldata:\n ', JSON.stringify(ctor));
    console.log('(salt + final EIP-712 hash depend on the deployed address; computed at --submit time.)');
    return;
  }

  const acct = relayer(provider);
  console.log('\ndeploying EIP-712 wallet via UDC…');
  const dep = await acct.deployContract({ classHash: SHHH_ACCOUNT_CLASS, constructorCalldata: ctor, salt: PUBKEY[0], unique: false });
  await waitReceipt(provider, dep.transaction_hash);
  const wallet = dep.contract_address;
  console.log(`  wallet: ${wallet}\n    https://starkscan.co/contract/${wallet}`);

  const calls = [{ to: STRK, selector: hash.getSelectorFromName('transfer'), calldata: [wallet, hx(0), hx(0)] }];
  const oe: OutsideExecution = { caller: ANY_CALLER, nonce: nowSec, execute_after: nowSec - 120n, execute_before: nowSec + 3000n, calls: [] as any };
  const h = computeSnip12Hash({ ...oe, calls: [{ contractAddress: STRK, entrypoint: 'transfer', calldata: [wallet, hx(0), hx(0)] }] } as any, wallet, CHAIN_ID);
  const envelope: Felt[] = [hx(V2_SNIP12), hx(0), hx(KIND_EIP712), ...(await signEip712(BigInt(wallet), h))];
  const calldata = serializeOe(oe, calls, envelope);

  console.log('\nrelaying EIP-712-signed OE (no-op transfer) — expect SUCCESS:');
  const txHash = await execWithRetry(acct, [{ contractAddress: wallet, entrypoint: 'execute_from_outside_v2', calldata }]);
  console.log(`  ${txHash}\n    https://starkscan.co/tx/${txHash}`);
  const r = await waitReceipt(provider, txHash);
  const exec = r.execution_status ?? r.executionStatus;
  const rr = String(r.revert_reason ?? '').replace(/\s+/g, ' ');
  console.log(`  execution_status: ${exec}${rr ? `  (${rr.slice(-80)})` : ''}`);
  console.log(`\n=> Test 4 (EIP-712) ${exec === 'SUCCEEDED' ? 'PASS ✅' : 'FAIL ❌'}`);
  if (exec !== 'SUCCEEDED') process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
