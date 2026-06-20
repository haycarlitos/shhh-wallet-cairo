/**
 * Mainnet "Test 14" driver — session-key spending-cap E2E on a live
 * V8.4 ShhhAccount.
 *
 * This is the on-chain counterpart to `tests/account_sessions_e2e.cairo`.
 * It produces the two receipts that close the last open item in the
 * session-key spending-cap evidence trail:
 *
 *   - one IN-CAP session-signed call that SUCCEEDS, and
 *   - one OVER-CAP session-signed call that REVERTS with
 *     `'Spending: exceeds per-call'`,
 *
 * proving that `check_and_update_spending` (account.cairo:397) is wired
 * into the execute path of the *deployed* class and rejects an over-cap
 * call before it runs.
 *
 * It uses `approve(spender, amount)` rather than `transfer` as the metered
 * operation: `approve` is one of the four tracked spending selectors and,
 * unlike `transfer`, it succeeds regardless of the wallet's token balance —
 * so the IN-CAP case demonstrates the *cap* allowing the call rather than
 * accidentally depending on funding. (Swap to `transfer` via OP=transfer if
 * you specifically want to prove a balance-moving spend; fund the wallet
 * first.)
 *
 * SAFETY: defaults to DRY-RUN. It builds every address, hash, signature,
 * and calldata blob and prints them WITHOUT touching the network or
 * spending funds. Pass `--submit` to actually deploy/relay on mainnet.
 *
 * ----------------------------------------------------------------------
 * Usage
 * ----------------------------------------------------------------------
 *   cd scripts/ts && npm install
 *
 *   # 1) Review everything offline (no network, no funds):
 *   tsx mainnet-test-14-spending-cap.ts
 *
 *   # 2) Run it for real:
 *   STARKNET_RPC=https://starknet-rpc.publicnode.com \
 *   RELAYER_ADDRESS=0x... RELAYER_PK=0x... \
 *   OWNER_PK=0x...  SESSION_PK=0x... \
 *   TOKEN_ADDRESS=0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8 \
 *   tsx mainnet-test-14-spending-cap.ts --submit
 *
 * Env:
 *   STARKNET_RPC      RPC node (default: publicnode mainnet)
 *   RELAYER_ADDRESS   funded account that submits the OE invokes + (if no
 *   RELAYER_PK        WALLET_ADDRESS) deploys the test wallet via the UDC
 *   OWNER_PK          STARK private key of the wallet's primary owner
 *   SESSION_PK        STARK private key of the session key
 *   WALLET_ADDRESS    (optional) reuse an already-deployed V8.4 wallet
 *                     instead of deploying a fresh one
 *   TOKEN_ADDRESS     ERC-20 to scope the policy to (default: mainnet USDC)
 *   SPENDER_ADDRESS   approve() spender (default: the relayer)
 *   MAX_PER_CALL      policy per-call cap, token base units (default 1_000000)
 *   MAX_PER_WINDOW    policy window cap, token base units (default 1_500000)
 *   WINDOW_SECONDS    policy window length (default 3600)
 *   IN_CAP_AMOUNT     in-cap approve amount (default 500000  = ½ cap)
 *   OVER_CAP_AMOUNT   over-cap approve amount (default 5_000000 = 5× cap)
 *   OP                metered op: 'approve' (default) | 'transfer'
 *   STARKSCAN_API_KEY (optional) cross-check receipts via Starkscan's API
 *
 * Class hashes default to the V8.4 production values from
 * docs/class-hashes.md; override via SHHH_ACCOUNT_CLASS / STARK_VERIFIER_CLASS.
 */

import { RpcProvider, Account, ec, hash, shortString } from 'starknet';
import { computeSnip12Hash, type OutsideExecution } from './snip12-hash';
import { computeShhhAddress } from './compute-wallet-address';

// ----------------------------------------------------------------
// Config
// ----------------------------------------------------------------

const SUBMIT = process.argv.includes('--submit');

const RPC = process.env.STARKNET_RPC ?? 'https://starknet-rpc.publicnode.com';

// V8.4 production class hashes — docs/class-hashes.md (declared 2026-05-15).
const SHHH_ACCOUNT_CLASS =
  process.env.SHHH_ACCOUNT_CLASS ??
  '0x075dfb396145926bffa6beb659897f46cc082a50b211d80871cff7f1038fa58a';
const STARK_VERIFIER_CLASS =
  process.env.STARK_VERIFIER_CLASS ??
  '0x00d09209b2da9d49fc805ba26380ba4ce25aa641116c10eb178e1051a71dbf68';

// Mainnet USDC by default (6 decimals).
const TOKEN_ADDRESS =
  process.env.TOKEN_ADDRESS ??
  '0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8';

const OP = (process.env.OP ?? 'approve').toLowerCase(); // 'approve' | 'transfer'
if (OP !== 'approve' && OP !== 'transfer') {
  fail(`OP must be 'approve' or 'transfer', got '${OP}'`);
}

const CHAIN_ID = shortString.encodeShortString('SN_MAIN');
const ANY_CALLER = BigInt(shortString.encodeShortString('ANY_CALLER'));
const SIG_VERSION_V2_SNIP12 = BigInt(shortString.encodeShortString('V2_SNIP12'));

const MAX_PER_CALL = BigInt(process.env.MAX_PER_CALL ?? '1000000'); // 1.0 USDC
const MAX_PER_WINDOW = BigInt(process.env.MAX_PER_WINDOW ?? '1500000'); // 1.5 USDC
const WINDOW_SECONDS = BigInt(process.env.WINDOW_SECONDS ?? '3600');
const IN_CAP_AMOUNT = BigInt(process.env.IN_CAP_AMOUNT ?? '500000'); // 0.5 USDC
const OVER_CAP_AMOUNT = BigInt(process.env.OVER_CAP_AMOUNT ?? '5000000'); // 5.0 USDC

const EXPECTED_REVERT = 'Spending: exceeds per-call';
const STARKSCAN = 'https://starkscan.co';
const STARKSCAN_API = process.env.STARKSCAN_API_KEY;

// ----------------------------------------------------------------
// Keys (dummy values in dry-run so the build path can be inspected
// without secrets).
// ----------------------------------------------------------------

const OWNER_PK = process.env.OWNER_PK ?? (SUBMIT ? required('OWNER_PK') : '0x1');
const SESSION_PK = process.env.SESSION_PK ?? (SUBMIT ? required('SESSION_PK') : '0x2');

const OWNER_PUBKEY = BigInt(ec.starkCurve.getStarkKey(OWNER_PK));
const SESSION_PUBKEY = BigInt(ec.starkCurve.getStarkKey(SESSION_PK));

// ----------------------------------------------------------------
// Selectors
// ----------------------------------------------------------------

const SEL = {
  add_session: hash.getSelectorFromName('add_or_update_session_key'),
  set_policy: hash.getSelectorFromName('set_spending_policy'),
  op: hash.getSelectorFromName(OP),
  execute_from_outside_v2: hash.getSelectorFromName('execute_from_outside_v2'),
};

// ----------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------

function fail(msg: string): never {
  console.error('error: ' + msg);
  process.exit(1);
}
function required(name: string): never {
  return fail(`${name} is required with --submit`);
}
function hex(x: bigint | string | number): string {
  if (typeof x === 'string') return x.startsWith('0x') ? x : '0x' + BigInt(x).toString(16);
  return '0x' + BigInt(x).toString(16);
}
function u256(x: bigint): [string, string] {
  const MASK = (1n << 128n) - 1n;
  return [hex(x & MASK), hex(x >> 128n)];
}
function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
function signHash(privKey: string, msgHash: bigint): { r: string; s: string } {
  const sig = ec.starkCurve.sign(hex(msgHash), privKey);
  return { r: hex(sig.r), s: hex(sig.s) };
}

type Felt = string;
type Call = { contractAddress: string; entrypoint: string; calldata: Felt[] };

/** Serde layout of `OutsideExecution` followed by the signature array —
 *  the exact calldata `execute_from_outside_v2(oe, signature)` expects. */
function serializeOeCall(oe: OutsideExecution, calls: Call[], signature: Felt[]): Felt[] {
  const out: Felt[] = [
    hex(oe.caller as bigint),
    hex(oe.nonce as bigint),
    hex(oe.execute_after),
    hex(oe.execute_before),
    hex(calls.length),
  ];
  for (const c of calls) {
    out.push(hex(c.contractAddress), hex(hash.getSelectorFromName(c.entrypoint)), hex(c.calldata.length));
    for (const d of c.calldata) out.push(hex(d));
  }
  out.push(hex(signature.length));
  for (const s of signature) out.push(hex(s));
  return out;
}

// ----------------------------------------------------------------
// Build the three OEs
// ----------------------------------------------------------------

let nonceCounter = BigInt(Date.now());
function nextNonce(): bigint {
  return nonceCounter++;
}

const nowSec = BigInt(Math.floor(Date.now() / 1000));
const EXEC_AFTER = nowSec - 120n;
const EXEC_BEFORE = nowSec + 3000n; // window 3120s < MAX_ANY_CALLER_VALIDITY_SECONDS (7200)
const SESSION_VALID_UNTIL = nowSec + 86_400n;

function makeOe(calls: Call[], nonce: bigint): OutsideExecution {
  return {
    caller: ANY_CALLER,
    nonce,
    execute_after: EXEC_AFTER,
    execute_before: EXEC_BEFORE,
    calls,
  };
}

/** Owner-signed setup OE: register the session key + spending policy
 *  (both are self-call-gated mutators, so they ride inside an OE the
 *  owner signs and the account self-executes). */
function buildSetupOe(wallet: string): { oe: OutsideExecution; calls: Call[]; signature: Felt[] } {
  const calls: Call[] = [
    {
      contractAddress: wallet,
      entrypoint: 'add_or_update_session_key',
      calldata: [
        hex(SESSION_PUBKEY),
        hex(SESSION_VALID_UNTIL),
        hex(10), // max_calls
        hex(1), // allowed_entrypoints.len
        SEL.op, // whitelist the metered selector
      ],
    },
    {
      contractAddress: wallet,
      entrypoint: 'set_spending_policy',
      calldata: [
        hex(SESSION_PUBKEY),
        hex(TOKEN_ADDRESS),
        ...u256(MAX_PER_CALL),
        ...u256(MAX_PER_WINDOW),
        hex(WINDOW_SECONDS),
      ],
    },
  ];
  const oe = makeOe(calls, nextNonce());
  const h = computeSnip12Hash(oe, wallet, CHAIN_ID);
  const { r, s } = signHash(OWNER_PK, h);
  // Single-owner V2_SNIP12 envelope for primary owner (owner_id 0, STARK).
  const signature: Felt[] = [
    hex(SIG_VERSION_V2_SNIP12),
    hex(0),
    shortString.encodeShortString('STARK'),
    r,
    s,
  ];
  return { oe, calls, signature };
}

/** Session-signed spend OE: a single `approve`/`transfer` of `amount`. */
function buildSpendOe(
  wallet: string,
  spender: string,
  amount: bigint,
): { oe: OutsideExecution; calls: Call[]; signature: Felt[] } {
  const calls: Call[] = [
    {
      contractAddress: TOKEN_ADDRESS,
      entrypoint: OP,
      calldata: [hex(spender), ...u256(amount)],
    },
  ];
  const oe = makeOe(calls, nextNonce());
  const h = computeSnip12Hash(oe, wallet, CHAIN_ID);
  const { r, s } = signHash(SESSION_PK, h);
  // 4-element session envelope.
  const signature: Felt[] = [hex(SESSION_PUBKEY), r, s, hex(SESSION_VALID_UNTIL)];
  return { oe, calls, signature };
}

// ----------------------------------------------------------------
// Network — submission + receipt reading
// ----------------------------------------------------------------

const provider = new RpcProvider({ nodeUrl: RPC });

async function waitReceipt(txHash: string): Promise<any> {
  for (let i = 0; i < 60; i++) {
    try {
      const r: any = await provider.getTransactionReceipt(txHash);
      const exec = r.execution_status ?? r.executionStatus;
      if (exec === 'SUCCEEDED' || exec === 'REVERTED') return r;
    } catch {
      // TXN_HASH_NOT_FOUND yet — keep polling.
    }
    await sleep(5000);
  }
  throw new Error('timed out waiting for receipt: ' + txHash);
}

function revertReason(receipt: any): string {
  return String(receipt.revert_reason ?? receipt.revertReason ?? '');
}

async function starkscanCrossCheck(txHash: string): Promise<void> {
  if (!STARKSCAN_API) return;
  try {
    const res = await fetch(`https://api.starkscan.co/api/v0/transaction/${txHash}`, {
      headers: { 'x-api-key': STARKSCAN_API, accept: 'application/json' },
    });
    const body: any = await res.json();
    console.log(
      `    starkscan-api: status=${body.transaction_status ?? body.status ?? '?'}` +
        (body.revert_error ? ` revert=${JSON.stringify(body.revert_error)}` : ''),
    );
  } catch (e) {
    console.log(`    starkscan-api: cross-check failed (${(e as Error).message})`);
  }
}

async function relayOe(
  relayer: Account,
  wallet: string,
  label: string,
  built: { oe: OutsideExecution; calls: Call[]; signature: Felt[] },
  expect: 'SUCCEEDED' | 'REVERTED',
): Promise<{ txHash: string; ok: boolean }> {
  const calldata = serializeOeCall(built.oe, built.calls, built.signature);
  const { transaction_hash } = await relayer.execute({
    contractAddress: wallet,
    entrypoint: 'execute_from_outside_v2',
    calldata,
  });
  console.log(`  ${label}: submitted ${transaction_hash}`);
  console.log(`    ${STARKSCAN}/tx/${transaction_hash}`);
  const receipt = await waitReceipt(transaction_hash);
  const exec = receipt.execution_status ?? receipt.executionStatus;
  const reason = revertReason(receipt);
  console.log(`    execution_status: ${exec}${reason ? `  revert_reason: ${reason}` : ''}`);
  await starkscanCrossCheck(transaction_hash);

  let ok = exec === expect;
  if (expect === 'REVERTED') {
    const matches = reason.includes(EXPECTED_REVERT) || reason.includes(hex(BigInt(shortString.encodeShortString(EXPECTED_REVERT))));
    ok = ok && matches;
    if (exec === 'REVERTED' && !matches) {
      console.log(`    WARNING: reverted, but reason did not mention "${EXPECTED_REVERT}"`);
    }
  }
  console.log(`    => ${ok ? 'PASS' : 'FAIL'} (expected ${expect})`);
  return { txHash: transaction_hash, ok };
}

// ----------------------------------------------------------------
// Main
// ----------------------------------------------------------------

async function main(): Promise<void> {
  const spender = process.env.SPENDER_ADDRESS ?? process.env.RELAYER_ADDRESS ?? '0xdead';

  console.log('='.repeat(68));
  console.log('Mainnet Test 14 — session-key spending-cap E2E', SUBMIT ? '(SUBMIT)' : '(DRY-RUN)');
  console.log('='.repeat(68));
  console.log('rpc:            ', RPC);
  console.log('account class:  ', SHHH_ACCOUNT_CLASS);
  console.log('stark verifier: ', STARK_VERIFIER_CLASS);
  console.log('token:          ', TOKEN_ADDRESS);
  console.log('metered op:     ', OP, `(spender ${spender})`);
  console.log('owner pubkey:   ', hex(OWNER_PUBKEY));
  console.log('session pubkey: ', hex(SESSION_PUBKEY));
  console.log(
    `policy:          max_per_call=${MAX_PER_CALL} max_per_window=${MAX_PER_WINDOW} window=${WINDOW_SECONDS}s`,
  );
  console.log(`amounts:         in_cap=${IN_CAP_AMOUNT}  over_cap=${OVER_CAP_AMOUNT}`);
  console.log('');

  // ---- resolve / deploy the wallet ----
  let wallet = process.env.WALLET_ADDRESS ?? '';
  let relayer: Account | undefined;

  if (SUBMIT) {
    relayer = new Account({
      provider,
      address: process.env.RELAYER_ADDRESS ?? required('RELAYER_ADDRESS'),
      signer: process.env.RELAYER_PK ?? required('RELAYER_PK'),
    });
  }

  if (!wallet) {
    const ctor: Felt[] = [
      shortString.encodeShortString('STARK'),
      hex(STARK_VERIFIER_CLASS),
      hex(1),
      hex(OWNER_PUBKEY),
      shortString.encodeShortString('primary'),
    ];
    if (SUBMIT) {
      console.log('deploying fresh V8.4 wallet via UDC...');
      const salt = hex(nowSec);
      const dep = await relayer!.deployContract({
        classHash: SHHH_ACCOUNT_CLASS,
        constructorCalldata: ctor,
        salt,
        unique: false,
      });
      await waitReceipt(dep.transaction_hash);
      wallet = dep.contract_address;
      console.log(`  deployed: ${wallet}`);
      console.log(`  ${STARKSCAN}/contract/${wallet}`);
    } else {
      // Dry-run: show the deterministic self-deploy prediction so the OE
      // hashes are computed against a real address. (At --submit time the
      // wallet is UDC-deployed and its address is read from the receipt.)
      wallet = hex(
        computeShhhAddress({
          classHash: BigInt(SHHH_ACCOUNT_CLASS),
          primaryKind: 'STARK',
          pubkey: [OWNER_PUBKEY],
          verifierClassHash: BigInt(STARK_VERIFIER_CLASS),
          label: 'primary',
        }),
      );
      console.log('deploy (dry-run): constructor calldata =', JSON.stringify(ctor));
      console.log('deploy (dry-run): predicted self-deploy address =', wallet);
    }
  } else {
    console.log('reusing wallet:', wallet);
  }
  console.log('');

  // ---- build the three OEs ----
  const setup = buildSetupOe(wallet);
  const inCap = buildSpendOe(wallet, spender, IN_CAP_AMOUNT);
  const overCap = buildSpendOe(wallet, spender, OVER_CAP_AMOUNT);

  if (!SUBMIT) {
    console.log('DRY-RUN — built and signed, not submitted. Calldata blobs:');
    console.log('  setup OE   :', JSON.stringify(serializeOeCall(setup.oe, setup.calls, setup.signature)));
    console.log('  in-cap OE  :', JSON.stringify(serializeOeCall(inCap.oe, inCap.calls, inCap.signature)));
    console.log('  over-cap OE:', JSON.stringify(serializeOeCall(overCap.oe, overCap.calls, overCap.signature)));
    console.log('');
    console.log('Re-run with --submit (and RELAYER_*/OWNER_PK/SESSION_PK set) to execute on mainnet.');
    return;
  }

  // ---- submit ----
  console.log('STEP 1 — register session key + spending policy (owner-signed):');
  const s1 = await relayOe(relayer!, wallet, 'setup', setup, 'SUCCEEDED');
  console.log('');
  console.log('STEP 2 — in-cap session-signed spend (expect SUCCEEDED):');
  const s2 = await relayOe(relayer!, wallet, 'in-cap', inCap, 'SUCCEEDED');
  console.log('');
  console.log('STEP 3 — over-cap session-signed spend (expect REVERTED):');
  const s3 = await relayOe(relayer!, wallet, 'over-cap', overCap, 'REVERTED');
  console.log('');

  // ---- evidence summary (paste into docs/v8-3-smoke-tests.md) ----
  const allPass = s1.ok && s2.ok && s3.ok;
  console.log('='.repeat(68));
  console.log(`RESULT: ${allPass ? 'ALL PASS ✅' : 'FAILURE ❌'}`);
  console.log('='.repeat(68));
  console.log('Evidence (Test 14 — V8.4 session-key spending cap):');
  console.log(`  wallet      ${STARKSCAN}/contract/${wallet}`);
  console.log(`  setup       ${STARKSCAN}/tx/${s1.txHash}`);
  console.log(`  in-cap  ✅  ${STARKSCAN}/tx/${s2.txHash}`);
  console.log(`  over-cap ⛔ ${STARKSCAN}/tx/${s3.txHash}  (reverted: ${EXPECTED_REVERT})`);

  if (!allPass) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
