/**
 * Mainnet "Test 13a" driver — V8.4 guardian-OE recovery carve-out (audit C-1).
 *
 * Proves on the live V8.4 class `0x075dfb39…` that a ROLE_GUARDIAN signer:
 *   (positive) CAN sign an OutsideExecution that calls `initiate_recovery`
 *              with its own owner_id as proposer, and
 *   (negative) CANNOT sign any other OE — that reverts with
 *              `'SHHH: signer not an owner'`,
 * and that a ROLE_OWNER can `cancel_recovery`.
 *
 * Two phases, because installing the guardian goes through the 48h
 * `propose_add_owner` → `execute_add_owner` governance timelock:
 *
 *   --phase a : deploy a fresh V8.4 wallet + propose the guardian (owner OE).
 *               Captures the op_id from the OpProposed event and persists
 *               state. Starts the 48h clock.
 *   --phase b : (run after valid_after) execute_add_owner → guardian live;
 *               guardian OE initiate_recovery (SUCCEEDS); guardian OE with a
 *               different call (REVERTS 'SHHH: signer not an owner'); owner OE
 *               cancel_recovery (SUCCEEDS).
 *
 * Submits via the deployer keystore account (read locally, never printed).
 * Ephemeral owner/guardian/recovery keys persisted to a gitignored file.
 *
 *   tsx mainnet-test-13-guardian-recovery.ts --phase a
 *   # wait ~48h, then:
 *   tsx mainnet-test-13-guardian-recovery.ts --phase b
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { RpcProvider, Account, ec, hash, shortString } from 'starknet';
import { computeSnip12Hash, type OutsideExecution } from './snip12-hash';

const PHASE = (process.argv.includes('--phase') ? process.argv[process.argv.indexOf('--phase') + 1] : 'a').toLowerCase();
const RPC = process.env.STARKNET_RPC ?? 'https://starknet-rpc.publicnode.com';
const SHHH_ACCOUNT_CLASS = process.env.SHHH_ACCOUNT_CLASS ?? '0x075dfb396145926bffa6beb659897f46cc082a50b211d80871cff7f1038fa58a';
const STARK_VERIFIER_CLASS = process.env.STARK_VERIFIER_CLASS ?? '0x00d09209b2da9d49fc805ba26380ba4ce25aa641116c10eb178e1051a71dbf68';
const STRK = '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d';

const ACCOUNTS_FILE = process.env.ACCOUNTS_FILE ?? `${homedir()}/.starknet_accounts/starknet_open_zeppelin_accounts.json`;
const ACCOUNTS_NETWORK = process.env.ACCOUNTS_NETWORK ?? 'alpha-mainnet';
const DEPLOYER = process.env.SNCAST_ACCOUNT ?? 'deployer_oz';

const STATE_FILE = new URL('./.test13-state.json', import.meta.url).pathname;
const CHAIN_ID = shortString.encodeShortString('SN_MAIN');
const ANY_CALLER = BigInt(shortString.encodeShortString('ANY_CALLER'));
const V2_SNIP12 = BigInt(shortString.encodeShortString('V2_SNIP12'));
const STARK = shortString.encodeShortString('STARK');
const ROLE_OWNER = shortString.encodeShortString('OWNER');
const ROLE_GUARDIAN = shortString.encodeShortString('GUARDIAN');
const OP_PROPOSED_SEL = hash.getSelectorFromName('OpProposed');

type Felt = string;
type Call = { contractAddress: string; entrypoint: string; calldata: Felt[] };

function hx(x: bigint | string | number): string {
  if (typeof x === 'string') return x.startsWith('0x') ? x : '0x' + BigInt(x).toString(16);
  return '0x' + BigInt(x).toString(16);
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const genPk = () => '0x' + Buffer.from(ec.starkCurve.utils.randomPrivateKey()).toString('hex');
const pub = (pk: string) => BigInt(ec.starkCurve.getStarkKey(pk));
function sign(pk: string, msg: bigint) {
  const s = ec.starkCurve.sign(hx(msg), pk);
  return { r: hx(s.r), s: hx(s.s) };
}

let nonceCounter = BigInt(Date.now());
const nowSec = BigInt(Math.floor(Date.now() / 1000));

/** OE serialized + a V2_SNIP12 owner/guardian envelope, ready for execute_from_outside_v2. */
function buildOe(wallet: string, calls: Call[], signerPk: string, ownerId: number): Felt[] {
  const oe: OutsideExecution = {
    caller: ANY_CALLER,
    nonce: nonceCounter++,
    execute_after: nowSec - 120n,
    execute_before: nowSec + 3000n,
    calls,
  };
  const h = computeSnip12Hash(oe, wallet, CHAIN_ID);
  const { r, s } = sign(signerPk, h);
  const sig: Felt[] = [hx(V2_SNIP12), hx(ownerId), hx(STARK), r, s];
  const out: Felt[] = [hx(oe.caller as bigint), hx(oe.nonce as bigint), hx(oe.execute_after), hx(oe.execute_before), hx(calls.length)];
  for (const c of calls) {
    out.push(hx(c.contractAddress), hx(hash.getSelectorFromName(c.entrypoint)), hx(c.calldata.length));
    for (const d of c.calldata) out.push(hx(d));
  }
  out.push(hx(sig.length), ...sig);
  return out;
}

function relayer(provider: RpcProvider): Account {
  const accounts = JSON.parse(readFileSync(ACCOUNTS_FILE, 'utf8'));
  const a = accounts[ACCOUNTS_NETWORK]?.[DEPLOYER];
  if (!a?.private_key) throw new Error(`${DEPLOYER} not found in ${ACCOUNTS_FILE}`);
  return new Account({ provider, address: a.address, signer: a.private_key });
}

async function waitReceipt(provider: RpcProvider, txHash: string): Promise<any> {
  for (let i = 0; i < 60; i++) {
    try {
      const r: any = await provider.getTransactionReceipt(txHash);
      const e = r.execution_status ?? r.executionStatus;
      if (e === 'SUCCEEDED' || e === 'REVERTED') return r;
    } catch {}
    await sleep(5000);
  }
  throw new Error('receipt timeout: ' + txHash);
}

async function bounds(provider: RpcProvider) {
  const b: any = await provider.getBlockWithTxHashes('latest');
  const p = (g: any, d: string) => BigInt(g?.price_in_fri ?? d) * 3n;
  return {
    l1_gas: { max_amount: 20_000n, max_price_per_unit: p(b.l1_gas_price, '0x174876e800') },
    l2_gas: { max_amount: 200_000_000n, max_price_per_unit: p(b.l2_gas_price, '0x5f5e100') },
    l1_data_gas: { max_amount: 200_000n, max_price_per_unit: p(b.l1_data_gas_price, '0x3b9aca00') },
  };
}

async function submit(
  provider: RpcProvider, acct: Account, wallet: string, label: string, calldata: Felt[],
  expect: 'SUCCEEDED' | 'REVERTED', reason?: string,
): Promise<boolean> {
  const details = expect === 'REVERTED' ? { resourceBounds: await bounds(provider), tip: 0n } : undefined;
  const { transaction_hash } = await acct.execute(
    [{ contractAddress: wallet, entrypoint: 'execute_from_outside_v2', calldata }],
    details as any,
  );
  console.log(`  ${label}: ${transaction_hash}\n    https://starkscan.co/tx/${transaction_hash}`);
  const r = await waitReceipt(provider, transaction_hash);
  const exec = r.execution_status ?? r.executionStatus;
  const rr = String(r.revert_reason ?? r.revertReason ?? '').replace(/\s+/g, ' ');
  const reasonOk = expect !== 'REVERTED' || !reason || rr.includes(reason) || rr.includes(hx(BigInt('0x' + Buffer.from(reason).toString('hex'))));
  const pass = exec === expect && reasonOk;
  console.log(`    execution_status: ${exec}${rr && exec === 'REVERTED' ? `  (${rr.slice(-70)})` : ''}  => ${pass ? 'PASS' : 'FAIL'}`);
  return pass;
}

// ----------------------------------------------------------------

async function phaseA(): Promise<void> {
  const provider = new RpcProvider({ nodeUrl: RPC });
  const acct = relayer(provider);
  const keys = { ownerPk: genPk(), guardianPk: genPk(), recoveryPk: genPk() };

  console.log('PHASE A — deploy V8.4 wallet + propose guardian (starts 48h clock)\n');
  const ctor: Felt[] = [hx(STARK), hx(STARK_VERIFIER_CLASS), hx(1), hx(pub(keys.ownerPk)), hx(shortString.encodeShortString('primary'))];
  const dep = await acct.deployContract({ classHash: SHHH_ACCOUNT_CLASS, constructorCalldata: ctor, salt: hx(pub(keys.ownerPk)), unique: false });
  await waitReceipt(provider, dep.transaction_hash);
  const wallet = dep.contract_address;
  console.log(`  deployed wallet: ${wallet}\n    https://starkscan.co/contract/${wallet}`);

  // owner OE: propose_add_owner(proposer=0, STARK, [guardianPub], GUARDIAN, 1, 'guardian')
  const calls: Call[] = [{
    contractAddress: wallet, entrypoint: 'propose_add_owner',
    calldata: [hx(0), hx(STARK), hx(1), hx(pub(keys.guardianPk)), hx(ROLE_GUARDIAN), hx(1), hx(shortString.encodeShortString('guardian'))],
  }];
  const calldata = buildOe(wallet, calls, keys.ownerPk, 0);
  const { transaction_hash } = await acct.execute([{ contractAddress: wallet, entrypoint: 'execute_from_outside_v2', calldata }]);
  console.log(`  propose guardian: ${transaction_hash}\n    https://starkscan.co/tx/${transaction_hash}`);
  const receipt = await waitReceipt(provider, transaction_hash);
  if ((receipt.execution_status ?? receipt.executionStatus) !== 'SUCCEEDED') throw new Error('propose reverted');

  // Extract op_id (keys[1]) + valid_after from the OpProposed event emitted by the wallet.
  const ev = (receipt.events ?? []).find(
    (e: any) => BigInt(e.from_address) === BigInt(wallet) && e.keys?.[0] && BigInt(e.keys[0]) === BigInt(OP_PROPOSED_SEL),
  );
  if (!ev) throw new Error('OpProposed event not found');
  const opId = ev.keys[1];
  const validAfter = Number(ev.data[ev.data.length - 2]); // [proposer, payload, valid_after, expires_at]
  writeFileSync(STATE_FILE, JSON.stringify({ wallet, ...keys, opId, validAfter }, null, 2));

  console.log(`\n  op_id: ${opId}`);
  console.log(`  guardian executable after: ${new Date(validAfter * 1000).toISOString()}`);
  console.log(`  state -> ${STATE_FILE}`);
  console.log('\nPhase A done. Run --phase b after the timestamp above.');
}

async function phaseB(): Promise<void> {
  if (!existsSync(STATE_FILE)) throw new Error('no .test13-state.json — run --phase a first');
  const st = JSON.parse(readFileSync(STATE_FILE, 'utf8'));
  const provider = new RpcProvider({ nodeUrl: RPC });
  const acct = relayer(provider);
  const w = st.wallet;
  const GUARDIAN_ID = 1;
  if (nowSec < BigInt(st.validAfter)) throw new Error(`timelock not elapsed; wait until ${new Date(st.validAfter * 1000).toISOString()}`);

  console.log(`PHASE B — wallet ${w}\n`);
  let pass = true;

  // 1. execute_add_owner(op_id, STARK, [guardianPub], GUARDIAN, 1, 'guardian') — owner OE, expect SUCCESS.
  console.log('1/4 execute_add_owner (install guardian) — expect SUCCESS:');
  pass = (await submit(provider, acct, w, 'execute_add_owner', buildOe(w, [{
    contractAddress: w, entrypoint: 'execute_add_owner',
    calldata: [st.opId, hx(STARK), hx(1), hx(pub(st.guardianPk)), hx(ROLE_GUARDIAN), hx(1), hx(shortString.encodeShortString('guardian'))],
  }], st.ownerPk, 0), 'SUCCEEDED')) && pass;

  // 2. guardian OE initiate_recovery(proposer=GUARDIAN_ID, ...) — expect SUCCESS (carve-out positive).
  console.log('2/4 guardian initiate_recovery — expect SUCCESS:');
  pass = (await submit(provider, acct, w, 'guardian_initiate_recovery', buildOe(w, [{
    contractAddress: w, entrypoint: 'initiate_recovery',
    calldata: [hx(GUARDIAN_ID), hx(STARK), hx(1), hx(pub(st.recoveryPk)), hx(ROLE_OWNER), hx(1), hx(shortString.encodeShortString('recovered'))],
  }], st.guardianPk, GUARDIAN_ID), 'SUCCEEDED')) && pass;

  // 3. guardian OE with a non-recovery call — expect REVERT 'SHHH: signer not an owner' (carve-out negative).
  console.log("3/4 guardian signs a NON-recovery OE — expect REVERT 'SHHH: signer not an owner':");
  pass = (await submit(provider, acct, w, 'guardian_arbitrary_oe', buildOe(w, [{
    contractAddress: STRK, entrypoint: 'transfer', calldata: [w, hx(0), hx(0)],
  }], st.guardianPk, GUARDIAN_ID), 'REVERTED', 'SHHH: signer not an owner')) && pass;

  // 4. owner OE cancel_recovery(0) — expect SUCCESS.
  console.log('4/4 owner cancel_recovery — expect SUCCESS:');
  pass = (await submit(provider, acct, w, 'cancel_recovery', buildOe(w, [{
    contractAddress: w, entrypoint: 'cancel_recovery', calldata: [hx(0)],
  }], st.ownerPk, 0), 'SUCCEEDED')) && pass;

  console.log(`\n=> Test 13a ${pass ? 'ALL PASS ✅' : 'FAILED ❌'}`);
  if (!pass) process.exit(1);
}

(PHASE === 'b' ? phaseB() : phaseA()).catch((e) => {
  console.error(e);
  process.exit(1);
});
