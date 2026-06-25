/**
 * Mainnet "Test 6" — raw P-256 owner OE on a live V8.4 ShhhAccount.
 *
 * Smokes the `P256Verifier` (smart cards / eIDAS / PIV) end-to-end: deploy a
 * V8.4 wallet whose primary owner is a raw P-256 key, then sign and relay one
 * OutsideExecution (a no-op `STRK.transfer(self, 0)`), confirming the account
 * dispatches to the P-256 verifier class and the inner call runs.
 *
 * Single phase, no timelock. Submits via the deployer keystore key (read
 * locally, never printed); the ephemeral P-256 key is persisted to a
 * gitignored file.
 *
 * Encoding mirrors scripts/ts/gen-p256-fixture.mjs:
 *   - sign the 32-byte big-endian SNIP-12 hash with prehash:false (raw ECDSA)
 *   - pubkey  = [x_lo, x_hi, y_lo, y_hi]   (u256 halves, big-endian)
 *   - payload = [r_lo, r_hi, s_lo, s_hi, y_parity]   (verifier ignores parity)
 *   - envelope = [V2_SNIP12, owner_id=0, 'P256', ...payload]
 *
 *   tsx mainnet-test-06-p256.ts            # dry-run (build + sign, no broadcast)
 *   tsx mainnet-test-06-p256.ts --submit   # deploy + relay on mainnet
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { p256 } from '@noble/curves/nist.js';
import { RpcProvider, Account, hash, shortString } from 'starknet';
import { computeSnip12Hash, type OutsideExecution } from './snip12-hash';

const SUBMIT = process.argv.includes('--submit');
const RPC = process.env.STARKNET_RPC ?? 'https://starknet-rpc.publicnode.com';
const SHHH_ACCOUNT_CLASS = process.env.SHHH_ACCOUNT_CLASS ?? '0x075dfb396145926bffa6beb659897f46cc082a50b211d80871cff7f1038fa58a';
const P256_VERIFIER_CLASS = process.env.P256_VERIFIER_CLASS ?? '0x01b600709af54c8838e5f18ddad3a26feeb47cb124c239f55a0f1b7a780e2d8a';
const STRK = '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d';

const ACCOUNTS_FILE = process.env.ACCOUNTS_FILE ?? `${homedir()}/.starknet_accounts/starknet_open_zeppelin_accounts.json`;
const ACCOUNTS_NETWORK = process.env.ACCOUNTS_NETWORK ?? 'alpha-mainnet';
const DEPLOYER = process.env.SNCAST_ACCOUNT ?? 'deployer_oz';

const KEYS_FILE = new URL('./.test06-keys.json', import.meta.url).pathname;
const CHAIN_ID = shortString.encodeShortString('SN_MAIN');
const ANY_CALLER = BigInt(shortString.encodeShortString('ANY_CALLER'));
const V2_SNIP12 = BigInt(shortString.encodeShortString('V2_SNIP12'));
const KIND_P256 = shortString.encodeShortString('P256');

type Felt = string;
const hx = (x: bigint | number | string): string =>
  typeof x === 'string' ? (x.startsWith('0x') ? x : '0x' + BigInt(x).toString(16)) : '0x' + BigInt(x).toString(16);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function feltTo32BE(h: bigint): Uint8Array {
  const b = new Uint8Array(32);
  let x = h;
  for (let i = 31; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n; }
  return b;
}
function beToU256(b: Uint8Array): [bigint, bigint] {
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return [x & ((1n << 128n) - 1n), x >> 128n];
}

// Ephemeral P-256 key (persisted so a re-run hits the same wallet).
function privKey(): Uint8Array {
  if (process.env.P256_PRIV) return Uint8Array.from(Buffer.from(process.env.P256_PRIV.replace(/^0x/, ''), 'hex'));
  if (existsSync(KEYS_FILE)) return Uint8Array.from(Buffer.from(JSON.parse(readFileSync(KEYS_FILE, 'utf8')).priv, 'hex'));
  const pk = p256.utils.randomSecretKey();
  if (SUBMIT) writeFileSync(KEYS_FILE, JSON.stringify({ priv: Buffer.from(pk).toString('hex'), note: 'ephemeral test06 P-256 key' }, null, 2));
  return pk;
}

const PRIV = privKey();
const PUB = p256.getPublicKey(PRIV, false); // 0x04 || X(32) || Y(32)
const [xLo, xHi] = beToU256(PUB.slice(1, 33));
const [yLo, yHi] = beToU256(PUB.slice(33, 65));
const PUBKEY: Felt[] = [hx(xLo), hx(xHi), hx(yLo), hx(yHi)];

function signP256(msgHash: bigint): Felt[] {
  const sig = p256.sign(feltTo32BE(msgHash), PRIV, { prehash: false }); // 64-byte r||s, low-s
  const [rLo, rHi] = beToU256(sig.slice(0, 32));
  const [sLo, sHi] = beToU256(sig.slice(32, 64));
  return [hx(rLo), hx(rHi), hx(sLo), hx(sHi), hx(0)]; // y_parity ignored by the direct-ECDSA verifier
}

function serializeOe(oe: OutsideExecution, calls: { to: string; selector: string; calldata: Felt[] }[], sig: Felt[]): Felt[] {
  const out: Felt[] = [hx(oe.caller as bigint), hx(oe.nonce as bigint), hx(oe.execute_after), hx(oe.execute_before), hx(calls.length)];
  for (const c of calls) { out.push(c.to, c.selector, hx(c.calldata.length), ...c.calldata); }
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
  console.log('Mainnet Test 6 — raw P-256 owner OE', SUBMIT ? '(SUBMIT)' : '(DRY-RUN)');
  console.log('='.repeat(64));
  console.log('account class :', SHHH_ACCOUNT_CLASS);
  console.log('P256 verifier :', P256_VERIFIER_CLASS);
  console.log('pubkey [x,y]  :', PUBKEY.join(' '));

  const provider = new RpcProvider({ nodeUrl: RPC });
  const ctor: Felt[] = [hx(KIND_P256), hx(P256_VERIFIER_CLASS), hx(4), ...PUBKEY, hx(shortString.encodeShortString('primary'))];

  if (!SUBMIT) {
    console.log('\nDRY-RUN — constructor calldata:\n ', JSON.stringify(ctor));
    console.log('Re-run with --submit to deploy + relay on mainnet.');
    return;
  }

  const acct = relayer(provider);
  console.log('\ndeploying P-256 wallet via UDC…');
  const dep = await acct.deployContract({ classHash: SHHH_ACCOUNT_CLASS, constructorCalldata: ctor, salt: PUBKEY[0], unique: false });
  await waitReceipt(provider, dep.transaction_hash);
  const wallet = dep.contract_address;
  console.log(`  wallet: ${wallet}\n    https://starkscan.co/contract/${wallet}`);

  // No-op OE: STRK.transfer(self, 0) — proves dispatch + inner call, moves nothing.
  const calls = [{ to: STRK, selector: hash.getSelectorFromName('transfer'), calldata: [wallet, hx(0), hx(0)] }];
  const oe: OutsideExecution = { caller: ANY_CALLER, nonce: nowSec, execute_after: nowSec - 120n, execute_before: nowSec + 3000n, calls: [] as any };
  const h = computeSnip12Hash({ ...oe, calls: [{ contractAddress: STRK, entrypoint: 'transfer', calldata: [wallet, hx(0), hx(0)] }] } as any, wallet, CHAIN_ID);
  const envelope: Felt[] = [hx(V2_SNIP12), hx(0), hx(KIND_P256), ...signP256(h)];
  const calldata = serializeOe(oe, calls, envelope);

  console.log('\nrelaying P-256-signed OE (no-op transfer) — expect SUCCESS:');
  const txHash = await execWithRetry(acct, [{ contractAddress: wallet, entrypoint: 'execute_from_outside_v2', calldata }]);
  console.log(`  ${txHash}\n    https://starkscan.co/tx/${txHash}`);
  const r = await waitReceipt(provider, txHash);
  const exec = r.execution_status ?? r.executionStatus;
  const rr = String(r.revert_reason ?? '').replace(/\s+/g, ' ');
  console.log(`  execution_status: ${exec}${rr ? `  (${rr.slice(-80)})` : ''}`);
  console.log(`\n=> Test 6 (P-256) ${exec === 'SUCCEEDED' ? 'PASS ✅' : 'FAIL ❌'}`);
  if (exec !== 'SUCCEEDED') process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
