/**
 * Mainnet "Test 5" — raw secp256k1 owner OE on a live V8.4 ShhhAccount.
 *
 * Smokes the `Secp256k1Verifier` (hardware wallets / programmatic low-level
 * signing) end-to-end: deploy a V8.4 wallet whose primary owner is a raw
 * secp256k1 key, then sign and relay one OutsideExecution (a no-op
 * `STRK.transfer(self, 0)`). The verifier ecrecovers the pubkey from
 * (hash, r, s, y_parity) and compares to the stored pubkey, so y_parity
 * must be correct (ethers provides it).
 *
 * Single phase, no timelock. Encoding mirrors gen-secp256k1-fixture.mjs:
 *   - sign the raw 32-byte big-endian SNIP-12 hash (no EIP-191 prefix)
 *   - pubkey  = [x_lo, x_hi, y_lo, y_hi]
 *   - payload = [r_lo, r_hi, s_lo, s_hi, y_parity]
 *   - envelope = [V2_SNIP12, owner_id=0, 'SECP256K1', ...payload]
 *
 *   tsx mainnet-test-05-secp256k1.ts            # dry-run
 *   tsx mainnet-test-05-secp256k1.ts --submit   # deploy + relay on mainnet
 */

import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { SigningKey, getBytes } from 'ethers';
import { RpcProvider, Account, hash, shortString } from 'starknet';
import { computeSnip12Hash, type OutsideExecution } from './snip12-hash';

const SUBMIT = process.argv.includes('--submit');
const RPC = process.env.STARKNET_RPC ?? 'https://starknet-rpc.publicnode.com';
const SHHH_ACCOUNT_CLASS = process.env.SHHH_ACCOUNT_CLASS ?? '0x075dfb396145926bffa6beb659897f46cc082a50b211d80871cff7f1038fa58a';
const SECP_VERIFIER_CLASS = process.env.SECP_VERIFIER_CLASS ?? '0x03e81667a46bd5287e09a9600fa98d28fdc477735f2689f5f4e8e95f37b67b74';
const STRK = '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d';

const ACCOUNTS_FILE = process.env.ACCOUNTS_FILE ?? `${homedir()}/.starknet_accounts/starknet_open_zeppelin_accounts.json`;
const ACCOUNTS_NETWORK = process.env.ACCOUNTS_NETWORK ?? 'alpha-mainnet';
const DEPLOYER = process.env.SNCAST_ACCOUNT ?? 'deployer_oz';

const KEYS_FILE = new URL('./.test05-keys.json', import.meta.url).pathname;
const CHAIN_ID = shortString.encodeShortString('SN_MAIN');
const ANY_CALLER = BigInt(shortString.encodeShortString('ANY_CALLER'));
const V2_SNIP12 = BigInt(shortString.encodeShortString('V2_SNIP12'));
const KIND_SECP256K1 = shortString.encodeShortString('SECP256K1');

type Felt = string;
const hx = (x: bigint | number | string): string =>
  typeof x === 'string' ? (x.startsWith('0x') ? x : '0x' + BigInt(x).toString(16)) : '0x' + BigInt(x).toString(16);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function beToU256(b: Uint8Array): [bigint, bigint] {
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return [x & ((1n << 128n) - 1n), x >> 128n];
}

function privHex(): string {
  if (process.env.SECP_PRIV) return process.env.SECP_PRIV;
  if (existsSync(KEYS_FILE)) return JSON.parse(readFileSync(KEYS_FILE, 'utf8')).priv;
  const pk = '0x' + randomBytes(32).toString('hex');
  if (SUBMIT) writeFileSync(KEYS_FILE, JSON.stringify({ priv: pk, note: 'ephemeral test05 secp256k1 key' }, null, 2));
  return pk;
}

const SK = new SigningKey(privHex());
const PUB = getBytes(SK.publicKey); // 0x04 || X(32) || Y(32)
const [xLo, xHi] = beToU256(PUB.slice(1, 33));
const [yLo, yHi] = beToU256(PUB.slice(33, 65));
const PUBKEY: Felt[] = [hx(xLo), hx(xHi), hx(yLo), hx(yHi)];

function signSecp(msgHash: bigint): Felt[] {
  const sig = SK.sign('0x' + msgHash.toString(16).padStart(64, '0')); // raw ECDSA over the 32-byte hash
  const [rLo, rHi] = beToU256(getBytes(sig.r));
  const [sLo, sHi] = beToU256(getBytes(sig.s));
  return [hx(rLo), hx(rHi), hx(sLo), hx(sHi), hx(sig.yParity ? 1 : 0)];
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
  console.log('Mainnet Test 5 — raw secp256k1 owner OE', SUBMIT ? '(SUBMIT)' : '(DRY-RUN)');
  console.log('='.repeat(64));
  console.log('account class    :', SHHH_ACCOUNT_CLASS);
  console.log('secp256k1 verifier:', SECP_VERIFIER_CLASS);
  console.log('pubkey [x,y]     :', PUBKEY.join(' '));

  const provider = new RpcProvider({ nodeUrl: RPC });
  const ctor: Felt[] = [hx(KIND_SECP256K1), hx(SECP_VERIFIER_CLASS), hx(4), ...PUBKEY, hx(shortString.encodeShortString('primary'))];

  if (!SUBMIT) {
    console.log('\nDRY-RUN — constructor calldata:\n ', JSON.stringify(ctor));
    console.log('Re-run with --submit to deploy + relay on mainnet.');
    return;
  }

  const acct = relayer(provider);
  console.log('\ndeploying secp256k1 wallet via UDC…');
  const dep = await acct.deployContract({ classHash: SHHH_ACCOUNT_CLASS, constructorCalldata: ctor, salt: PUBKEY[0], unique: false });
  await waitReceipt(provider, dep.transaction_hash);
  const wallet = dep.contract_address;
  console.log(`  wallet: ${wallet}\n    https://starkscan.co/contract/${wallet}`);

  const calls = [{ to: STRK, selector: hash.getSelectorFromName('transfer'), calldata: [wallet, hx(0), hx(0)] }];
  const oe: OutsideExecution = { caller: ANY_CALLER, nonce: nowSec, execute_after: nowSec - 120n, execute_before: nowSec + 3000n, calls: [] as any };
  const h = computeSnip12Hash({ ...oe, calls: [{ contractAddress: STRK, entrypoint: 'transfer', calldata: [wallet, hx(0), hx(0)] }] } as any, wallet, CHAIN_ID);
  const envelope: Felt[] = [hx(V2_SNIP12), hx(0), hx(KIND_SECP256K1), ...signSecp(h)];
  const calldata = serializeOe(oe, calls, envelope);

  console.log('\nrelaying secp256k1-signed OE (no-op transfer) — expect SUCCESS:');
  const txHash = await execWithRetry(acct, [{ contractAddress: wallet, entrypoint: 'execute_from_outside_v2', calldata }]);
  console.log(`  ${txHash}\n    https://starkscan.co/tx/${txHash}`);
  const r = await waitReceipt(provider, txHash);
  const exec = r.execution_status ?? r.executionStatus;
  const rr = String(r.revert_reason ?? '').replace(/\s+/g, ' ');
  console.log(`  execution_status: ${exec}${rr ? `  (${rr.slice(-80)})` : ''}`);
  console.log(`\n=> Test 5 (secp256k1) ${exec === 'SUCCEEDED' ? 'PASS ✅' : 'FAIL ❌'}`);
  if (exec !== 'SUCCEEDED') process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
