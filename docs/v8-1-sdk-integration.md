# Shhh V8.1 — SDK Integration Spec (Internal)

> **Audience**: Chipi Pay engineering, Cifra integration, Shhh frontend, anyone wiring V8.1 into a TypeScript / wallet codebase.
>
> **Status**: V8.1 audit-closed, declared on Starknet mainnet 2026-05-07 (class hash `0x01e7f69e3c22c5a209c24fcd4c31683f7cf2f1850cd0037635bd582c93f363b5`). One smoke-test deployment + signed OE confirmed end-to-end on mainnet 2026-05-10. Ten verifier classes also live (one per signing kind).
>
> **Repo references**:
>   - Cairo source: `haycarlitos/shhh-wallet-cairo`, branch `v8-robust`, latest at merge commit `f17209c`.
>   - Smoke-test reference deployment: [`0xa2220b05b5d16f52c4ce179e5386bd4b23dc5f4b7a1e0b51c579dbd9129b31`](https://voyager.online/contract/0x00a2220b05b5d16f52c4ce179e5386bd4b23dc5f4b7a1e0b51c579dbd9129b31).
>   - Smoke-test OE: [`0x0625297020b1c7503628d2353505e4a8f027f33ba2f4083523e300ac846200c9`](https://voyager.online/tx/0x0625297020b1c7503628d2353505e4a8f027f33ba2f4083523e300ac846200c9).

---

## 1. What V8.1 is, in one paragraph

V8.1 is one Starknet account class (`ShhhAccount`) that authenticates owners signing under any of ten cryptographic primitives — STARK, Ed25519, raw secp256k1, EIP-191 `personal_sign`, EIP-712 typed data, raw P-256, WebAuthn P-256, JWT-ES256 single-tenant Apple, JWT-ES256 sub-bound multi-tenant Apple, and BLS12-381 min-sig-size. Signature verification dispatches via `library_call_syscall` to a separately-declared verifier class. New signing kinds land by declaring a new verifier class and registering it through governance — no account redeployment. Multi-owner, weighted threshold, timelocked governance, 7-day guardian recovery, and SNIP-163 session keys are all built in. Outside execution (SNIP-9 V2) is the sole execution path; `__validate__` always reverts.

---

## 2. Class hashes (V8.1, mainnet)

Pin these exactly. All hashes are deterministic functions of the compiled Sierra; changing a single character of source code changes the hash.

| Contract | Class hash | Role |
|---|---|---|
| `ShhhAccount` (V8.1) | `0x01e7f69e3c22c5a209c24fcd4c31683f7cf2f1850cd0037635bd582c93f363b5` | Account contract — dispatcher + multi-owner + governance + recovery + sessions |
| `StarkVerifier` | `0x06e671d2c70cf6d28ad18de864b82ffcbc60251b4dbcdb630ec17d4e1e43729b` | STARK ECDSA |
| `Ed25519Verifier` | `0x004f075cb1dbbafde78faaa037824cc327e3a038ecd4ff7b8e2aa4ef039b1774` | Ed25519 (Phantom / Solana) |
| `Secp256k1Verifier` | `0x0473d8215659c5e91a8431557618f6664f698d16ba300d8d626027011391d8c6` | Raw secp256k1 ECDSA |
| `EIP191Secp256k1Verifier` | `0x025c6a15e84aae7a999b449b08dc37da5071319eb09eec935161090148821c7f` | EIP-191 `personal_sign` (MetaMask, Rabby) |
| `EIP712Secp256k1Verifier` | `0x0729a2303c20fb3ba8994809b9ae923301c7489a069ae7401fb13a55c9184b2b` | EIP-712 typed data (`eth_signTypedData_v4`) |
| `P256Verifier` | `0x029693329bb6f061e15c470ce2b169120cacfab47af024897b5588026c857810` | Raw P-256 ECDSA |
| `WebAuthnP256Verifier` | `0x078fd4ce33370699f44c221191ce0d8b7ccfccff77297f798dc7948b4201b9f4` | Apple passkeys / Touch ID / Face ID / WebAuthn |
| `JwtES256AppleVerifier` | `0x06da4abb7fec87a9844d4a128b40621f282f694f56b108de76137b5174266ef8` | Sign in with Apple, single-tenant |
| `JwtES256AppleSubVerifier` | `0x034bfab90a072ea8717379ad50185692378a5048a2105c2928da3777ee09a316` | Sign in with Apple, multi-tenant (sub-bound) |
| `Bls12_381MinSigVerifier` | `0x052a0625cffd197b6aeb0de4806e16605d95d6bf0229efbc45b96a38e41b513d` | BLS12-381 min-sig (drand DST) |

Deprecated (do **not** use for new deploys):

| Contract | Class hash | Why |
|---|---|---|
| `ShhhAccount` V8.0 | `0x01d6e475…` | Vulnerable to C-1 (guardian role bypass) and H-1 (bootstrap front-run); kept declared only so legacy-recognition tooling can route to the rotation path. |

---

## 3. Architecture in one diagram

```
┌──────────────────────────────────────────────────┐
│                ShhhAccount (V8.1)                │
│                                                  │
│  Storage:                                        │
│    primary_kind, primary_pubkey_hash             │
│    verifier_classes: Map<kind_tag, ClassHash>    │
│    oe_nonces:        Map<nonce, bool>            │
│    oe_in_progress:   bool   (reentrancy guard)   │
│    inside_verifier:  bool   (audit M-2 flag)     │
│                                                  │
│  Components:                                     │
│    src5, owners, governance, recovery,           │
│    session_key, spending_policy                  │
│                                                  │
│  ABI (paymaster-routable):                       │
│    execute_from_outside_v2(oe, sig)              │
│    propose_*, execute_*, cancel_pending_op       │
│    initiate_recovery, finalize_recovery,         │
│    cancel_recovery                               │
│    add_or_update_session_key,                    │
│    set_spending_policy, ...                      │
└────────────────────────┬─────────────────────────┘
                         │ library_call_syscall
       ┌─────────┬───────┴──────┬──────────┬─────────┐
       ▼         ▼              ▼          ▼         ▼
   ┌───────┐ ┌────────┐ ┌─────────────┐ ┌──────┐ ┌───────┐
   │STARK  │ │Ed25519 │ │EIP-191/712  │ │P-256 │ │BLS12- │
   │       │ │(Phantom│ │secp256k1    │ │ ECDSA│ │ 381   │
   │       │ │/Solana)│ │(MetaMask)   │ │+ Web │ │       │
   │       │ │        │ │             │ │Authn │ │       │
   └───────┘ └────────┘ └─────────────┘ └──────┘ └───────┘
                                          + JWT-ES256 (Apple, single + sub-bound)
```

Trust model:

- **Account class is immutable per class hash.** No `upgrade` selector. Migrating accounts means a new V8.x class hash + opt-in user-driven rotation.
- **Verifier classes are immutable per class hash.** Adding a new signing kind = declaring a new class + registering via the timelocked `add_verifier_class` flow (48h, requires unanimous owners).
- **Verifier classes are governance-vetted.** The `add_verifier_class` op kind has the longest timelock (48h) and the strictest weight requirement (unanimous). The M-2 `inside_verifier` flag is defense-in-depth in case a malicious class makes it through the timelock unanimously.

---

## 4. Constants the SDK must export

```ts
// All hex strings in starknet.js convention (lowercase, 0x-prefixed).
// In TypeScript these MUST be `as const` so type narrowing works.

export const V8_SHHH_ACCOUNT_CLASS_HASH =
  "0x01e7f69e3c22c5a209c24fcd4c31683f7cf2f1850cd0037635bd582c93f363b5";

export const V8_VERIFIER_CLASS_HASHES = {
  STARK:               "0x06e671d2c70cf6d28ad18de864b82ffcbc60251b4dbcdb630ec17d4e1e43729b",
  ED25519:             "0x004f075cb1dbbafde78faaa037824cc327e3a038ecd4ff7b8e2aa4ef039b1774",
  SECP256K1:           "0x0473d8215659c5e91a8431557618f6664f698d16ba300d8d626027011391d8c6",
  EIP191_SECP256K1:    "0x025c6a15e84aae7a999b449b08dc37da5071319eb09eec935161090148821c7f",
  EIP712_SECP256K1:    "0x0729a2303c20fb3ba8994809b9ae923301c7489a069ae7401fb13a55c9184b2b",
  P256:                "0x029693329bb6f061e15c470ce2b169120cacfab47af024897b5588026c857810",
  WEBAUTHN_P256:       "0x078fd4ce33370699f44c221191ce0d8b7ccfccff77297f798dc7948b4201b9f4",
  JWT_ES256:           "0x06da4abb7fec87a9844d4a128b40621f282f694f56b108de76137b5174266ef8",
  JWT_ES256_APPLE_SUB: "0x034bfab90a072ea8717379ad50185692378a5048a2105c2928da3777ee09a316",
  BLS12_381:           "0x052a0625cffd197b6aeb0de4806e16605d95d6bf0229efbc45b96a38e41b513d",
} as const;

export type V8SignerKind = keyof typeof V8_VERIFIER_CLASS_HASHES;

// Canonical felt252 short-string kind tags (must match
// shhh-wallet-cairo:src/signer/interface.cairo).
export const KIND_TAG_FELT: Record<V8SignerKind, string> = {
  STARK:               "0x535441524b",                      // 'STARK'
  ED25519:             "0x4544323535313900000000000000",     // 'ED25519' (left-padded)
  SECP256K1:           "0x534543503235364b3100000000000",    // ...
  // ... compute via shortString.encodeShortString(kind) at runtime instead
};

// SRC-5 interface IDs the account advertises:
export const ISIGNER_ID =
  "0x94c5a761f34b25a4e603c651ac0e1fc4fad9cdb5517f7fa1bb54044c7e5ef8";
export const ISRC9_V2_ID =
  "0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872";

// SNIP-12 OE domain
export const OE_DOMAIN_NAME = "Account.execute_from_outside";  // shortstring
export const OE_DOMAIN_VERSION = 2;
export const OE_DOMAIN_REVISION = 1;

// SIG version tags for owner envelopes
export const SIG_VERSION_V2_SNIP12 = "V2_SNIP12";        // shortstring
export const SIG_VERSION_V2_THRESHOLD = "V2_THRESHOLD";  // shortstring

// Audit-driven bounds (account.cairo)
export const MAX_CALLS = 16;
export const MAX_TOTAL_CALLDATA_FELTS = 1024;
export const MAX_SIGNATURE_FELTS = 1024;
export const MAX_ANY_CALLER_VALIDITY_SECONDS = 7200;

// Timelock windows (seconds, governance/pending_ops.cairo)
export const TIMELOCK_ADD_OWNER          = 172_800;  // 48h
export const TIMELOCK_REMOVE_OWNER       =  86_400;  // 24h
export const TIMELOCK_ROTATE_OWNER       =  86_400;  // 24h
export const TIMELOCK_SET_THRESHOLD      = 172_800;  // 48h
export const TIMELOCK_ADD_VERIFIER       = 172_800;  // 48h, unanimous-required
export const TIMELOCK_REMOVE_VERIFIER    =  86_400;  // 24h
export const TIMELOCK_ADD_GUARDIAN       =  86_400;  // 24h
export const TIMELOCK_REMOVE_GUARDIAN    =  86_400;  // 24h
export const TIMELOCK_RECOVERY           = 604_800;  // 7d
export const DEFAULT_OP_EXPIRY_SECONDS   = 1_209_600; // 14d
```

---

## 5. Address derivation (counterfactual)

V8 addresses are deterministic from `(class_hash, primary_kind, primary_pubkey)`. You can compute the address before any tx hits chain.

```ts
import { hash, shortString } from "starknet";

function ownerCommitment(kindShortString: string, pubkey: bigint[]): bigint {
  const kind = BigInt(shortString.encodeShortString(kindShortString));
  return BigInt(
    hash.computePoseidonHashOnElements([
      kind.toString(),
      ...pubkey.map((x) => "0x" + x.toString(16)),
    ])
  );
}

function addressSalt(kindShortString: string, pubkey: bigint[]): bigint {
  const kind = BigInt(shortString.encodeShortString(kindShortString));
  const commitment = ownerCommitment(kindShortString, pubkey);
  return BigInt(
    hash.computePoseidonHashOnElements([
      kind.toString(),
      "0x" + commitment.toString(16),
    ])
  );
}

export function computeShhhAddress(args: {
  primaryKind: V8SignerKind;
  pubkey: bigint[];
  verifierClassHash: bigint;
  label?: string;
}): bigint {
  const {
    primaryKind,
    pubkey,
    verifierClassHash,
    label = "primary",
  } = args;
  const kind = BigInt(shortString.encodeShortString(primaryKind));
  const labelFelt = BigInt(shortString.encodeShortString(label));
  const salt = addressSalt(primaryKind, pubkey);
  // Constructor calldata: [primary_kind, primary_verifier, pubkey_len, ...pubkey, label]
  const ctor = [
    kind,
    verifierClassHash,
    BigInt(pubkey.length),
    ...pubkey,
    labelFelt,
  ];
  return BigInt(
    hash.calculateContractAddressFromHash(
      "0x" + salt.toString(16),
      V8_SHHH_ACCOUNT_CLASS_HASH,
      ctor.map((x) => "0x" + x.toString(16)),
      "0x0", // deployer_address = 0 for the canonical address
    )
  );
}
```

**Key invariant**: changing `primaryKind` produces a different salt → different address. The same raw key encoded under two different kinds lives at two different addresses. This is intentional — prevents cross-kind address collisions.

**Pubkey shape per kind** (must match the account's `_assert_pubkey_shape` check):

| Kind | Pubkey length | Layout |
|---|---|---|
| STARK | 1 felt | `[pk_x]` (field element) |
| ED25519 | 2 felts | `[pk_low, pk_high]` (LE u256 halves) |
| SECP256K1 | 4 felts | `[x_low, x_high, y_low, y_high]` |
| EIP191_SECP256K1 | 4 felts | `[x_low, x_high, y_low, y_high]` |
| EIP712_SECP256K1 | 4 felts | `[x_low, x_high, y_low, y_high]` |
| P256 | 4 felts | `[x_low, x_high, y_low, y_high]` |
| WEBAUTHN_P256 | 4 felts | `[x_low, x_high, y_low, y_high]` |
| JWT_ES256 | 4 felts | `[x_low, x_high, y_low, y_high]` (Apple's signing key) |
| JWT_ES256_APPLE_SUB | 5 felts | `[x_low, x_high, y_low, y_high, sub_hash]` (`sub_hash = poseidon(sub_bytes)`) |
| BLS12_381 | 16 felts | G2 point as 4 × u384 (x0, x1, y0, y1), each u384 = 4 × 96-bit limbs LE |

**At registration time** the account checks `pubkey.len() == expected_len` per kind. Wrong shape → reverts with `'M1: bad pubkey shape'` (audit M-1 partial fix). On-curve / subgroup-membership checks happen inside the verifier on every `verify(...)` call.

---

## 6. Deploy flow

The V8 account does **not** support `DEPLOY_ACCOUNT v3` (because `__validate__` always reverts). Use UDC.

```ts
import { Account, RpcProvider, Contract } from "starknet";

const UDC_ADDRESS = "0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf";

async function deployShhhAccount(args: {
  primaryKind: V8SignerKind;
  pubkey: bigint[];
  label?: string;
  funder: Account;       // any Starknet account that can pay gas + UDC fee
}): Promise<{ address: string; txHash: string }> {
  const verifierClassHash = BigInt(V8_VERIFIER_CLASS_HASHES[args.primaryKind]);
  const expectedAddress = computeShhhAddress({ ...args, verifierClassHash });
  const salt = addressSalt(args.primaryKind, args.pubkey);
  const labelFelt = BigInt(
    shortString.encodeShortString(args.label ?? "primary")
  );
  const kind = BigInt(shortString.encodeShortString(args.primaryKind));

  // UDC.deployContract(class_hash, salt, unique=false, [ctor_calldata])
  const udcCalldata = [
    BigInt(V8_SHHH_ACCOUNT_CLASS_HASH),  // class_hash
    salt,                                  // salt
    0n,                                    // unique = false (deterministic)
    BigInt(4 + args.pubkey.length),        // ctor calldata length:
                                           //   primary_kind, primary_verifier,
                                           //   span_len, ...span, label
    kind,
    verifierClassHash,
    BigInt(args.pubkey.length),
    ...args.pubkey,
    labelFelt,
  ];

  const tx = await args.funder.execute({
    contractAddress: UDC_ADDRESS,
    entrypoint: "deployContract",
    calldata: udcCalldata.map((x) => "0x" + x.toString(16)),
  });
  return { address: "0x" + expectedAddress.toString(16), txHash: tx.transaction_hash };
}
```

**Cost reference** (smoke test, 2026-05-10): STARK-primary deploy via UDC = **0.22 STRK**. Other primary kinds are similar (deploy cost is dominated by class-deploy syscall overhead, not by the constructor's per-kind shape check).

**Counterfactual sanity check**: before submitting the deploy tx, log `expectedAddress` and verify against the deploy-tx receipt's `contract_address`. Smoke test confirmed byte-for-byte match.

---

## 7. SNIP-12 message hashing

The OE message hash is what every signer produces a signature *over*. It is derived from the `OutsideExecution` struct + the Starknet domain separator + the account address. **MUST** match `shhh-wallet-cairo:src/outside_execution.cairo::compute_snip12_hash` byte-for-byte.

```ts
import { hash, shortString } from "starknet";

const STARKNET_MESSAGE_PREFIX = BigInt(
  shortString.encodeShortString("StarkNet Message")
);

const OUTSIDE_EXECUTION_TYPE_HASH_REV1 = BigInt(
  "0x5a4b49e17039355cd95d1f0981d75901191d1319b1f4b05a9a791d218d7e0c"
);
const CALL_TYPE_HASH_REV1 = BigInt(
  "0x3635c7f2a7ba93844c0d064e18e487f35ab90f7c39d00f186a781fc3f0c2ca9"
);
const STARKNET_DOMAIN_TYPE_HASH_REV1 = BigInt(
  "0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210"
);

function poseidonMany(values: bigint[]): bigint {
  return BigInt(
    hash.computePoseidonHashOnElements(
      values.map((v) => "0x" + v.toString(16))
    )
  );
}

export type Call = {
  to: bigint;          // contract address
  selector: bigint;    // selector (use get_selector_from_name)
  calldata: bigint[];
};

export type OutsideExecution = {
  caller: bigint;       // 'ANY_CALLER' shortstring or a specific address
  nonce: bigint;        // any unique felt252; the account dedups via oe_nonces map
  execute_after: bigint; // unix seconds
  execute_before: bigint;
  calls: Call[];
};

function hashCall(c: Call): bigint {
  const cdHash = poseidonMany(c.calldata);
  return poseidonMany([CALL_TYPE_HASH_REV1, c.to, c.selector, cdHash]);
}

function hashCalls(calls: Call[]): bigint {
  return poseidonMany(calls.map(hashCall));
}

function hashDomain(chainId: bigint): bigint {
  return poseidonMany([
    STARKNET_DOMAIN_TYPE_HASH_REV1,
    BigInt(shortString.encodeShortString(OE_DOMAIN_NAME)),
    BigInt(OE_DOMAIN_VERSION),
    chainId,
    BigInt(OE_DOMAIN_REVISION),
  ]);
}

function hashOEStruct(oe: OutsideExecution): bigint {
  return poseidonMany([
    OUTSIDE_EXECUTION_TYPE_HASH_REV1,
    oe.caller,
    oe.nonce,
    oe.execute_after,
    oe.execute_before,
    hashCalls(oe.calls),
  ]);
}

export function computeOEMessageHash(args: {
  oe: OutsideExecution;
  accountAddress: bigint;
  chainId: bigint;
}): bigint {
  return poseidonMany([
    STARKNET_MESSAGE_PREFIX,
    hashDomain(args.chainId),
    args.accountAddress,
    hashOEStruct(args.oe),
  ]);
}
```

**Reference**: `scripts/ts/snip12-hash.ts` in the Cairo repo is the canonical TypeScript implementation; cross-check via the Cairo-side `tests/audit_v8.cairo` and the smoke-test OE recipe in this doc.

**Time bounds enforcement** (matching account semantics):
- `execute_after < now < execute_before` strictly (both bounds exclusive).
- For `caller == 'ANY_CALLER'`, the validity window `execute_before - execute_after` MUST be ≤ `MAX_ANY_CALLER_VALIDITY_SECONDS` (= 7200s). The account reverts with `'M2: window too long'` otherwise.
- For a specific caller address, no window cap.

---

## 8. Owner envelope format

Every owner-signed OE wraps a single envelope at the start of the `signature` span:

```
[ SIG_VERSION_V2_SNIP12, owner_id, kind_tag, ...kind_specific_payload ]
```

| Field | Type | Meaning |
|---|---|---|
| `SIG_VERSION_V2_SNIP12` | felt252 (= shortstring `'V2_SNIP12'`) | Selects the V2 hashing path. Must be the first element. |
| `owner_id` | u32 (felt) | Index into the account's owner_set. Primary owner = `0`. |
| `kind_tag` | felt252 (shortstring) | MUST equal `owners[owner_id].kind`. Mismatch → revert `'SHHH: kind mismatch'`. |
| `kind_specific_payload` | felt252* | Per-verifier shape. See section 9. |

**The role check** (audit C-1): the account asserts `owners[owner_id].role == ROLE_OWNER`. Guardians cannot sign OEs — they can only invoke `initiate_recovery`. Reverts with `'SHHH: signer not an owner'` if a guardian tries.

**Threshold envelope** (N-of-M, mixed kinds across owners) uses a different version tag:
```
[ SIG_VERSION_V2_THRESHOLD, n, env_1_len, env_1..., env_2_len, env_2..., ... ]
```
where each `env_i` is shaped `[owner_id, kind_tag, ...payload]` (NO inner version tag). The account verifies each envelope, rejects duplicate `owner_id`s, and asserts `sum(weights) >= threshold`. See section 14.

---

## 9. Per-kind signing flows

Each verifier consumes a different envelope payload. Below is the spec for each, with concrete TypeScript flow. Reference fixture generators are in `scripts/ts/gen-*-fixture.mjs` in the Cairo repo.

### 9.1 STARK ECDSA — `'STARK'`

Native Starknet wallets (Argent, Braavos, Ledger). Used for **primary owner = STARK** and any STARK secondary owners.

**Pubkey** (1 felt): `[pk_x]`

**Envelope** (5 felts total): `[V2_SNIP12, owner_id, 'STARK', r, s]`

**Sign**:
```ts
import { ec, hash } from "starknet";

function signStark(messageHash: bigint, privKey: bigint): { r: bigint; s: bigint } {
  const sig = ec.starkCurve.sign(
    messageHash.toString(16).padStart(64, "0"),
    privKey.toString(16).padStart(64, "0")
  );
  return { r: BigInt("0x" + sig.r.toString(16)), s: BigInt("0x" + sig.s.toString(16)) };
}

function buildStarkEnvelope(args: {
  ownerId: number;
  messageHash: bigint;
  privKey: bigint;
}): bigint[] {
  const { r, s } = signStark(args.messageHash, args.privKey);
  return [
    BigInt(shortString.encodeShortString("V2_SNIP12")),
    BigInt(args.ownerId),
    BigInt(shortString.encodeShortString("STARK")),
    r,
    s,
  ];
}
```

**On-chain verification cost**: ~12M l2_gas (cheapest).

### 9.2 Ed25519 — `'ED25519'`

Phantom, Solflare, every Solana wallet. Verification via Garaga `is_valid_eddsa_signature`.

**Pubkey** (2 felts): `[pk_low, pk_high]` — LE u256 halves of the 32-byte Ed25519 pubkey.

**Envelope** (variable): `[V2_SNIP12, owner_id, 'ED25519', ...eddsa_calldata_with_hint]`

The Ed25519 envelope is large (Garaga hint generation produces ~120 felts of msm/sqrt witness data). Use Garaga's `eddsaCalldataBuilder`:

```ts
import * as garaga from "garaga";
import * as ed from "@noble/ed25519";

await garaga.init();

async function buildEd25519Envelope(args: {
  ownerId: number;
  messageHash: bigint;
  privKey: Uint8Array;
}): Promise<bigint[]> {
  // Phantom signs over the Cairo-canonical OE bytes (NOT the felt252 hash).
  // For a pure-software Ed25519 signer that signs the felt252 directly, encode
  // the message_hash as 32 BE bytes:
  const msgBytes = new Uint8Array(32);
  let h = args.messageHash;
  for (let i = 31; i >= 0; i--) { msgBytes[i] = Number(h & 0xffn); h >>= 8n; }

  // Phantom flow: Phantom signs whatever bytes you ask it to sign. The account
  // contract expects the signed message to be the canonical OE byte encoding,
  // not the felt252 message_hash. See `bytesToHexForSigning` in
  // `shhh:src/lib/starknet/outside-execution.ts` for the Phantom-compat path.

  const pubkeyBytes = await ed.getPublicKeyAsync(args.privKey);
  const sig = await ed.signAsync(msgBytes, args.privKey);

  const Ry = bytesToLeBigInt(sig.slice(0, 32));
  const s  = bytesToLeBigInt(sig.slice(32, 64));
  const Py = bytesToLeBigInt(pubkeyBytes);

  const calldata = garaga.eddsaCalldataBuilder(
    Ry,    // Ry_twisted_le
    s,     // s
    Py,    // Py_twisted_le
    msgBytes,
    false  // prepend_public_key = false
  );

  return [
    BigInt(shortString.encodeShortString("V2_SNIP12")),
    BigInt(args.ownerId),
    BigInt(shortString.encodeShortString("ED25519")),
    ...calldata.map(BigInt),
  ];
}
```

**On-chain cost**: ~28M l2_gas. **Phantom UX caveat**: Phantom cannot directly sign felt252 hashes — it signs arbitrary byte messages. The Shhh frontend uses an explicit "what-you-see-is-what-you-sign" convention (`bytesToHexForSigning` re-encodes the canonical OE bytes as hex ASCII so Phantom shows the user a hex string that matches what's signed on chain). Reference: `shhh:src/lib/starknet/outside-execution.ts`.

### 9.3 Raw secp256k1 — `'SECP256K1'`

Hardware wallets exposing low-level signing, programmatic signers. Verification via `starknet::secp256_trait::recover_public_key`.

**Pubkey** (4 felts): `[x_low, x_high, y_low, y_high]`

**Envelope** (10 felts): `[V2_SNIP12, owner_id, 'SECP256K1', r_low, r_high, s_low, s_high, y_parity]`

```ts
import { secp256k1 } from "@noble/curves/secp256k1";

function buildSecp256k1Envelope(args: {
  ownerId: number;
  messageHash: bigint;
  privKey: Uint8Array; // 32 bytes
}): bigint[] {
  const msgBytes = bigintTo32BE(args.messageHash);
  const sig = secp256k1.sign(msgBytes, args.privKey, { lowS: true });
  // recoveryBit is 0 or 1
  const yParity = BigInt(sig.recovery);

  return [
    BigInt(shortString.encodeShortString("V2_SNIP12")),
    BigInt(args.ownerId),
    BigInt(shortString.encodeShortString("SECP256K1")),
    sig.r & ((1n << 128n) - 1n),  // r_low
    sig.r >> 128n,                 // r_high
    sig.s & ((1n << 128n) - 1n),  // s_low
    sig.s >> 128n,                 // s_high
    yParity,
  ];
}
```

**On-chain cost**: ~15M l2_gas. **Note**: signature MUST be low-s (canonical form). Non-canonical signatures revert.

### 9.4 EIP-191 `personal_sign` — `'EIP191_SECP256K1'`

**This is the MetaMask-compat path.** Every EVM wallet (Rabby, Coinbase Wallet, Trust, etc.) supports `personal_sign` natively — no Snap, no plugin, no Argent install.

**Pubkey** (4 felts): `[x_low, x_high, y_low, y_high]` — secp256k1 pubkey of the EVM address.

**Envelope** (10 felts): `[V2_SNIP12, owner_id, 'EIP191_SECP256K1', r_low, r_high, s_low, s_high, y_parity]`

The verifier on chain wraps the `message_hash` as:
```
keccak256("\x19Ethereum Signed Message:\n32" || message_hash_32be)
```
and recovers the pubkey from `(r, s, y_parity)`. The user sees a popup like:
```
[MetaMask popup]
Sign this message:
0x517f3883fc6ec33edde42f11f7996076b686123ce1e9ec3ff1e2c08d4bf6cf5
```

```ts
import { ethers } from "ethers";

async function buildEIP191Envelope(args: {
  ownerId: number;
  messageHash: bigint;
  signer: ethers.Signer;
}): Promise<bigint[]> {
  const msgHashBytes = bigintTo32BE(args.messageHash); // exactly 32 bytes
  const sigHex = await args.signer.signMessage(msgHashBytes); // ethers handles the prefix
  const sig = ethers.Signature.from(sigHex);
  const r = BigInt(sig.r);
  const s = BigInt(sig.s);
  const yParity = BigInt(sig.v - 27);

  return [
    BigInt(shortString.encodeShortString("V2_SNIP12")),
    BigInt(args.ownerId),
    BigInt(shortString.encodeShortString("EIP191_SECP256K1")),
    r & ((1n << 128n) - 1n),
    r >> 128n,
    s & ((1n << 128n) - 1n),
    s >> 128n,
    yParity,
  ];
}
```

**On-chain cost**: ~18M l2_gas (most of which is the keccak — Stwo doesn't yet prove keccak natively).

### 9.5 EIP-712 typed data — `'EIP712_SECP256K1'`

Same wallets as EIP-191, but the popup is structured (the user sees field names, not a raw hex blob).

**Pubkey** (4 felts): `[x_low, x_high, y_low, y_high]`

**Envelope** (10 felts): `[V2_SNIP12, owner_id, 'EIP712_SECP256K1', r_low, r_high, s_low, s_high, y_parity]`

The verifier reads `chain_id` via `get_tx_info().unbox().chain_id` and `account_addr` via `get_contract_address()` at verify time; both feed the EIP-712 domain separator. The `salt` field of the EIP-712 domain carries the account address (deliberate choice over `verifyingContract` to avoid ethers v6's ENS resolution).

The signed structured payload is:
```js
{
  domain: {
    name: "Shhh",
    version: "1",
    chainId: <runtime value>,
    salt: <account address as bytes32>,
  },
  types: {
    MessageHash: [{ name: "hash", type: "bytes32" }],
  },
  primaryType: "MessageHash",
  message: { hash: messageHashBytes32 },
}
```

```ts
async function buildEIP712Envelope(args: {
  ownerId: number;
  messageHash: bigint;
  accountAddress: bigint;
  chainId: bigint;
  signer: ethers.Signer;
}): Promise<bigint[]> {
  const msgHash32 = "0x" + args.messageHash.toString(16).padStart(64, "0");
  const acc32     = "0x" + args.accountAddress.toString(16).padStart(64, "0");

  const sigHex = await args.signer.signTypedData(
    {
      name: "Shhh",
      version: "1",
      chainId: Number(args.chainId),
      salt: acc32,
    },
    { MessageHash: [{ name: "hash", type: "bytes32" }] },
    { hash: msgHash32 }
  );
  const sig = ethers.Signature.from(sigHex);
  const r = BigInt(sig.r);
  const s = BigInt(sig.s);
  const yParity = BigInt(sig.v - 27);

  return [
    BigInt(shortString.encodeShortString("V2_SNIP12")),
    BigInt(args.ownerId),
    BigInt(shortString.encodeShortString("EIP712_SECP256K1")),
    r & ((1n << 128n) - 1n),
    r >> 128n,
    s & ((1n << 128n) - 1n),
    s >> 128n,
    yParity,
  ];
}
```

**On-chain cost**: ~19M l2_gas.

### 9.6 Raw P-256 — `'P256'`

PIV smart cards, eIDAS qualified certificates, Apple DeviceCheck. NOT for passkeys (use `WEBAUTHN_P256` for passkeys — the envelope shape differs).

**Pubkey** (4 felts): `[x_low, x_high, y_low, y_high]`

**Envelope** (10 felts): `[V2_SNIP12, owner_id, 'P256', r_low, r_high, s_low, s_high, y_parity]`

Build flow is mirror-image of secp256k1 with `@noble/curves/nist::p256`.

### 9.7 WebAuthn P-256 — `'WEBAUTHN_P256'`

Apple passkeys, Touch ID, Face ID, Windows Hello, YubiKey FIDO2. Verifier parses the WebAuthn assertion: `authenticatorData || sha256(clientDataJSON)`, recovers the P-256 signature, and binds the challenge to the SNIP-12 hash.

**Pubkey** (4 felts): `[x_low, x_high, y_low, y_high]`

**Envelope** (variable, ~80-120 felts): `[V2_SNIP12, owner_id, 'WEBAUTHN_P256', authData_byteArray, clientDataJSON_byteArray, challenge_offset_u32, r_low, r_high, s_low, s_high, y_parity]`

`challenge_offset` is the byte index inside `clientDataJSON` where the base64url-encoded message_hash starts (after the `"challenge":"` literal).

Reference fixture generator: `scripts/ts/gen-webauthn-fixture.mjs`. Browser flow uses the native `navigator.credentials.get(...)` API; the response is parsed and reshaped. **On-chain cost**: ~46M l2_gas.

### 9.8 JWT-ES256 single-tenant Apple — `'JWT_ES256'`

Sign in with Apple, single-tenant (each user registers their *own* Apple-key-of-the-day on their account).

**Pubkey** (4 felts): `[x_low, x_high, y_low, y_high]` — Apple's current ECDSA-P256 signing key.

**Envelope** (variable, ~150-250 felts): `[V2_SNIP12, owner_id, 'JWT_ES256', header_b64_byteArray, payload_decoded_byteArray, nonce_offset_u32, iss_offset_u32, r_low, r_high, s_low, s_high, y_parity]`

The verifier:
1. Re-encodes `payload_decoded` to base64url on chain.
2. Computes `sha256(header_b64 || "." || payload_b64)`.
3. Recovers the signing key via P-256 ECDSA over that digest, asserts equality to stored pubkey.
4. Checks bytes at `payload_decoded[nonce_offset..nonce_offset+43]` equal `base64url(message_hash, no padding)`.
5. Checks bytes at `payload_decoded[iss_offset..iss_offset+25]` equal `"https://appleid.apple.com"`.

Reference: `scripts/ts/gen-jwt-es256-fixture.mjs`. **On-chain cost**: ~58M l2_gas.

### 9.9 JWT-ES256 sub-bound multi-tenant Apple — `'JWT_ES256_APPLE_SUB'`

Same recipe + multi-tenant safety. **This is the variant Chipi Pay should default to** when serving many users with one Apple key.

**Pubkey** (5 felts): `[x_low, x_high, y_low, y_high, sub_hash]` where `sub_hash = poseidon_hash_span([byte_0, byte_1, ...])` over the bytes of the user's Apple `sub` claim (e.g. `"001234.deadbeef.5678"`, one felt per byte).

**Envelope** (variable, ~150-250 felts): `[V2_SNIP12, owner_id, 'JWT_ES256_APPLE_SUB', header_b64_byteArray, payload_decoded_byteArray, nonce_offset_u32, iss_offset_u32, sub_offset_u32, sub_len_u32, r_low, r_high, s_low, s_high, y_parity]`

In addition to the base ES256 verifier:
- Bytes at `payload_decoded[sub_offset..sub_offset+sub_len]` are anchored to the literal `"sub":"` JSON preamble (audit H-2 fix) and the closing `"`.
- `poseidon_hash_span` over those bytes must equal the stored `sub_hash`.

Reference: `scripts/ts/gen-jwt-es256-sub-fixture.mjs`. **On-chain cost**: ~59M l2_gas.

### 9.10 BLS12-381 min-sig — `'BLS12_381'`

Validator multi-sigs, DAO governance keys, backend aggregator signers. NOT for end-user UX.

**Pubkey** (16 felts): G2 point as 4 × u384, each u384 = 4 × 96-bit limbs LE.

**Envelope** (~4276 felts): G1 sig + HashToCurveHint + 136 precomputed G2 lines + MPCheckHintBLS12_381.

Off-chain calldata generation: today via Python (`scripts/py/gen_bls_fixture.py` in the Cairo repo). Browser path waits on upstream Garaga PR `keep-starknet-strange/garaga#519`.

**Use case caveat**: BLS is for institutional / programmatic signers. Don't use as a primary owner kind for an end-user account.

---

## 10. OE construction + submission

```ts
async function submitOE(args: {
  account: string;            // V8.1 ShhhAccount address
  envelope: bigint[];          // owner envelope from section 9
  oe: OutsideExecution;        // from section 7
  funder: Account;             // who pays gas (could be a paymaster)
}): Promise<string> {
  // Calldata for execute_from_outside_v2(oe, signature_span)
  const calldata = [
    args.oe.caller,
    args.oe.nonce,
    args.oe.execute_after,
    args.oe.execute_before,
    BigInt(args.oe.calls.length),
    ...args.oe.calls.flatMap((c) => [
      c.to,
      c.selector,
      BigInt(c.calldata.length),
      ...c.calldata,
    ]),
    BigInt(args.envelope.length),
    ...args.envelope,
  ].map((x) => "0x" + x.toString(16));

  const tx = await args.funder.execute({
    contractAddress: args.account,
    entrypoint: "execute_from_outside_v2",
    calldata,
  });
  return tx.transaction_hash;
}
```

**Caller field** semantics:
- `caller = 'ANY_CALLER'` (shortstring): anyone can submit, validity window capped at 7200s. Use this for paymaster-sponsored OEs where the paymaster is not the user.
- `caller = <specific address>`: only that address can submit. Use this for direct user submissions or for whitelist-based paymaster routing.

**Nonce** semantics: any felt252 unique to this OE. The account dedups via `oe_nonces` map. Recommended: `nonce = poseidon(account_addr, owner_id, monotonic_counter)` or `nonce = current_unix_time_ms` — anything that's unique-in-practice.

---

## 11. Paymaster routing

V8 OEs are vanilla SNIP-9 V2; paymasters see a normal Starknet tx and sponsor it. The on-chain curve dispatch via `library_call` does NOT require paymaster awareness of the signer kind.

### Chipi Pay paymaster

```ts
async function submitOEViaChipi(args: {
  oe: OutsideExecution;
  envelope: bigint[];
  account: string;
  apiKey: string;
}): Promise<{ txHash: string }> {
  const oeFelts = serializeOE(args.oe);
  const sigFelts = args.envelope;
  const res = await fetch("https://paymaster.chipipay.com/paymaster_executeSponsoredRaw", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${args.apiKey}`,
    },
    body: JSON.stringify({
      account_address: args.account,
      entrypoint: "execute_from_outside_v2",
      calldata: [
        ...oeFelts.map((x) => "0x" + x.toString(16)),
        "0x" + BigInt(sigFelts.length).toString(16),
        ...sigFelts.map((x) => "0x" + x.toString(16)),
      ],
    }),
  });
  return await res.json();
}
```

### AVNU paymaster

```ts
async function submitOEViaAVNU(args: {
  oe: OutsideExecution;
  envelope: bigint[];
  account: string;
  apiKey: string;
}): Promise<{ txHash: string }> {
  // AVNU's `paymaster_executeDirectTransaction` endpoint accepts any
  // SNIP-9 V2 OE.  Routing is via `account_address` + `calldata` fields.
  const res = await fetch("https://starknet.paymaster.avnu.fi/paymaster_executeDirectTransaction", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": args.apiKey,
    },
    body: JSON.stringify({
      // ... same calldata shape as above
    }),
  });
  return await res.json();
}
```

**Recommendation**: try Chipi paymaster first, fall back to AVNU. Reference: `shhh:src/lib/paymaster.ts`.

**Paymaster does NOT see** which signer kind was used. The paymaster sees: "one OE call to ShhhAccount". The kind dispatch happens on chain. This is the structural property that makes V8 paymaster-agnostic.

---

## 12. Multi-owner setup

Adding a secondary owner (e.g., a Phantom Ed25519 alongside a primary STARK) is a 2-step timelocked flow:

1. **Propose** (immediate, gated to self-call):
   ```cairo
   propose_add_owner(
     proposer: u32 = 0,                  // any active owner_id
     kind: felt252 = 'ED25519',
     pubkey_bytes: Array<felt252> = [pk_low, pk_high],
     role: felt252 = ROLE_OWNER,         // ROLE_OWNER | ROLE_GUARDIAN | ROLE_RECOVERY_ONLY
     weight: u8 = 1,
     label: felt252 = 'phantom',
   ) -> op_id: felt252
   ```
   Returns `op_id`. Emits `OwnerProposed { op_id, kind, role, ... }`.

2. **Wait** at least `TIMELOCK_ADD_OWNER` = 48 hours.

3. **Execute** (permissionless, anyone can call):
   ```cairo
   execute_add_owner(
     op_id: felt252,
     kind: felt252 = 'ED25519',         // MUST match proposal exactly
     pubkey_bytes: Array<felt252> = ..., // MUST match
     role: felt252 = ROLE_OWNER,
     weight: u8 = 1,
     label: felt252 = 'phantom',
   ) -> new_owner_id: u32
   ```
   The account recomputes the payload hash and asserts equality with the stored commitment, then performs the side effect. Emits `OwnerAdded { owner_id, kind, role, ... }`.

**Cancel** (during the window, any owner):
```cairo
cancel_pending_op(op_id: felt252)
```

Same propose/execute pattern for `remove_owner`, `rotate_owner_pubkey`, `set_threshold`, `add_verifier_class`, `remove_verifier_class`, `add_guardian`, `remove_guardian`. Timelocks vary per op kind (see section 4 constants).

---

## 13. Recovery flow (cross-ecosystem guardians)

The recovery story: a user adds N guardians (any kinds — Phantom + MetaMask + passkey are all fine). If they lose access to their primary key, the guardians can collectively start recovery. After 7 days, recovery finalizes and the new owner is added (additive — existing owners stay).

1. **Add guardian** (timelocked propose/execute, role = `ROLE_GUARDIAN`):
   ```ts
   await proposeAddOwner({ kind: 'EIP191_SECP256K1', pubkey: metamaskPubkey, role: 'GUARDIAN', weight: 1, label: 'laptop-metamask' });
   // ... wait 24h ...
   await executeAddOwner(op_id, ...);
   ```

2. **Initiate recovery** (guardian-only, self-call from the account's OE path):
   ```cairo
   initiate_recovery(
     proposer_owner_id: u32,            // MUST be a ROLE_GUARDIAN owner
     new_owner_kind: felt252,
     new_owner_pubkey: Array<felt252>,
     new_owner_label: felt252,
   )
   ```
   Records a `PendingRecovery { initiated_at, valid_after = now + 7d, new_owner_hash, ... }`. Emits `RecoveryInitiated`.

3. **Cancel** (during the 7-day window, ROLE_OWNER only — single-owner cancel:
   ```cairo
   cancel_recovery(owner_id: u32)
   ```
   `owner_id` MUST be `ROLE_OWNER`. Emits `RecoveryCancelled`.

4. **Finalize** (after 7 days, permissionless):
   ```cairo
   finalize_recovery()
   ```
   Adds the new owner to `owner_set` with `ROLE_OWNER`, weight 1. Existing owners stay. Emits `RecoveryFinalized`.

**Key safety properties**:
- Guardians cannot cancel recovery (only owners can — audit C-1 + I-6 confirmed clean).
- Guardians cannot sign arbitrary OEs (audit C-1 fix).
- Recovery is additive — losing your primary key means you add a new key, not lose anything.

---

## 14. Threshold envelope (N-of-M, mixed kinds)

Aggregate signatures from multiple owners on the same OE.

**Setup**:
1. Add multiple owners with non-zero weights (each via the timelocked add_owner flow).
2. Set the account threshold:
   ```cairo
   propose_set_threshold(proposer: u32, new: u8) -> op_id
   // wait 48h
   execute_set_threshold(op_id, new)
   ```

**Signing**:

Each signer produces their inner envelope (omit the `V2_SNIP12` version tag — it's only on the outer frame):
```
inner_i = [owner_id_i, kind_tag_i, ...kind_specific_payload_i]
```

Aggregator builds the threshold envelope:
```
[ V2_THRESHOLD, n,
  inner_1_len, inner_1...,
  inner_2_len, inner_2...,
  ...,
  inner_n_len, inner_n... ]
```

The account:
1. Verifies each inner envelope (same role + kind + curve checks as single-owner path).
2. Rejects duplicate `owner_id`s.
3. Computes `sum(weights)`; reverts if `< threshold`.

**Use case**: 2-of-3 across a laptop MetaMask (EIP-191), a phone passkey (WEBAUTHN_P256), and a hardware-key (raw secp256k1). Any 2 sign, the OE clears.

---

## 15. Session keys + spending policies

Same SNIP-163 reference impl chipi-pay/sessions-smart-contract uses, ported verbatim into V8.

**Add a session key** (self-call):
```cairo
add_or_update_session_key(
  session_key: felt252,                // session pubkey hash
  valid_until: u64,                    // expiration
  max_calls: u32,                      // total calls budget
  allowed_entrypoints: Array<felt252>, // selector whitelist
)
```

**Set spending policy** (self-call):
```cairo
set_spending_policy(
  session_key: felt252,
  token: ContractAddress,
  max_per_call: u256,
  max_per_window: u256,
  window_seconds: u64,
)
```

**Audit H-3 behavior**: when updating an existing policy, `spent_in_window` and `window_start` are **preserved** (not reset). New policies start a fresh window.

**Session signature envelope** (different shape from owner envelopes — 4-element fixed):
```
[ session_pubkey, r, s, valid_until ]
```

The account routes this via signature length: if `signature.len() == 4`, treat as session OE. If variable, treat as owner OE (V2_SNIP12 or V2_THRESHOLD frame).

**Admin blocklist** (V8-extended): session keys CANNOT call any of these selectors, regardless of whitelist:
- `add_owner`, `remove_owner`, `rotate_owner_pubkey`, `set_threshold`
- `add_verifier_class`, `remove_verifier_class`
- `add_guardian`, `remove_guardian`
- `initiate_recovery`, `cancel_recovery`, `finalize_recovery`
- `add_or_update_session_key`, `revoke_session_key`
- `set_spending_policy`, `remove_spending_policy`
- `__execute__`, `execute_from_outside_v2`
- `bootstrap_from_sessions` (the migration entrypoint)

These are the 17 V8 admin selectors. A session key calling any of them reverts with `'SESSION: V8-blocked selector'`.

---

## 16. Common revert codes

When a paymaster relays an OE that reverts, the receipt's revert_reason will be one of:

| Code | Layer | Meaning | Likely cause |
|---|---|---|---|
| `M1: caller=0 rejected` | OE entry | Caller field is 0 | Wrong `caller` shortstring; should be `'ANY_CALLER'` or a specific address |
| `M2: window too long` | OE entry | ANY_CALLER validity window > 7200s | Reduce `execute_before - execute_after` |
| `M3: too many calls` | OE entry | `calls.len() > 16` | Split into two OEs |
| `M3: signature too long` | OE entry | Signature span > 1024 felts | Validate envelope length client-side |
| `SRC9: too early` | Time bound | `now <= execute_after` | Wait or shrink `execute_after` |
| `SRC9: too late` | Time bound | `now >= execute_before` | Resign with later expiry |
| `SRC9: duplicate nonce` | Replay | OE nonce already consumed | Use a fresh nonce |
| `SRC9: invalid caller` | Caller mismatch | Specific-caller OE submitted by different address | Check `oe.caller` matches `tx.sender` |
| `SHHH: unsupported sig version` | Envelope | First felt isn't `V2_SNIP12` or `V2_THRESHOLD` | Use canonical version tag |
| `SHHH: unknown owner_id` | Envelope | `owner_id >= owner_count` | Check owner registration |
| `SHHH: owner revoked` | Envelope | The owner was tombstoned | Resign with another active owner |
| **`SHHH: signer not an owner`** | Envelope (audit C-1) | The owner exists but has `ROLE_GUARDIAN` or `ROLE_RECOVERY_ONLY` | Use a `ROLE_OWNER` to sign arbitrary OEs |
| `SHHH: kind mismatch` | Envelope | `kind_tag` ≠ `owner.kind` | The envelope must match the owner's stored kind |
| `SHHH: verifier missing` | Dispatch | `verifier_classes[kind]` is unset | Class hash must be registered via add_verifier_class |
| `SHHH: signature invalid` | Verifier | Cryptographic verification failed | Wrong sig, wrong message, wrong pubkey |
| **`SHHH: verifier reentry`** | Audit M-2 | A self-call landed while inside a library_call'd verifier | Defense-in-depth — should never fire under legit flows |
| `SHHH: caller != self` | Mutator | A mutator was called from outside the account | Wrap the call in an OE (self-call gate) |
| `SHHH: reentrant` | Reentrancy | OE call landed while another OE was in flight | The second OE will revert; retry after the first lands |
| `M1: bad pubkey shape` | add_owner (audit M-1 partial) | Pubkey length wrong for the kind tag | Match the per-kind length table in section 5 |
| `M1: unknown owner kind` | add_owner | Kind tag is not in the registered list | Use one of the 10 canonical kind tags |
| `OP: wrong op_kind` | Governance execute | Op was proposed with a different kind than executed | Match propose/execute payload exactly |
| `OWNERS: threshold == 0` | Governance | Tried to set threshold to 0 | Threshold must be ≥ 1 |
| `MIG: already initialized` | Migration | `bootstrap_from_sessions` called on a non-zero `primary_kind` | One-shot only |

---

## 17. Test fixture references

The Cairo repo ships off-chain reference signers as scratch scripts. They're battle-tested (used to generate the on-chain test fixtures the verifier classes are tested against). Not packaged but copy-pasteable.

| Kind | Script (in `shhh-wallet-cairo:scripts/ts/`) |
|---|---|
| STARK | `gen-phase3-account-fixture.mjs` |
| ED25519 | `regen-ed25519-fixtures.mjs` (uses `@noble/ed25519` + Garaga npm) |
| SECP256K1 | `gen-secp256k1-fixture.mjs` (uses `@noble/curves`) |
| EIP191_SECP256K1 | `gen-eip191-fixture.mjs` (uses `ethers v6`) |
| EIP712_SECP256K1 | `gen-eip712-fixture.mjs` (uses `ethers v6`) |
| P256 | `gen-p256-fixture.mjs` |
| WEBAUTHN_P256 | `gen-webauthn-fixture.mjs` |
| JWT_ES256 | `gen-jwt-es256-fixture.mjs` |
| JWT_ES256_APPLE_SUB | `gen-jwt-es256-sub-fixture.mjs` |
| BLS12_381 | `scripts/py/gen_bls_fixture.py` (Python; browser path waits on Garaga upstream PR #519) |

The Cairo repo's test suite exercises every kind via these fixtures. **218/218 tests passing** as of the V8.1 audit-closed merge (`f17209c` on `v8-robust`).

---

## 18. Out of scope for this SDK / known limitations

These are NOT supported and require either upstream changes or a future V8.x:

1. **Sign in with Google / JWT-RS256** (RSA-2048 SHA-256). Google uses RS256, not ES256. Reserved kind `JWT_RS256`, not built. Path: zk-jwt circuit + on-chain SNARK verifier, or a native RSA-2048 verifier.
2. **DKIM-RSA email-based recovery.** Same RSA-2048 family. Reserved kind, not built.
3. **BLS12-381 min-pubkey-size** (Eth-validator style with G2 sigs). Garaga's `hash_to_curve_g2_bls12_381` is not yet shipped; the BLS verifier we have is min-sig-size only (drand ciphersuite).
4. **`ShhhMigrationFromSessions` class.** The atomic-upgrade path for existing chipi-pay/sessions-smart-contract users (one OE: `[upgrade(MIGRATION_CLASS), bootstrap_from_sessions(...)]`). Not declared. Existing sessions users today must deploy a fresh V8.1 account and transfer assets; no in-place migration. Gating step before V8.1 fully replaces V7.5/sessions for legacy users.
5. **Full M-1**: per-kind `validate_pubkey` method on the `ISigner` trait so each verifier can run its own curve-membership / subgroup check at registration. Currently V8.1 has the partial fix (per-kind length check). The full fix touches all 10 verifiers + redeclares them. Documented as a V8.2 candidate. Cost: ~210 STRK in redeclares. The Medium-severity gap left open is BLS poison-pill multisig DoS — see section 19.
6. **H-2 dedicated bypass-attempt fixture** (Apple JWT with `sub_offset` pointing into `name.firstName`). The inline anchor check in V8.1 closes the bug; a dedicated regression test is a follow-up.
7. **Phase 13 external audit** (Omar/Codex or Zellic/Nethermind/OZ). V8.1 is audit-ready, not audited externally. The 2026-04-20 Codex pass and the 2026-04-13 Nethermind AuditAgent scan are lower-tier than a full institutional audit.

---

## 19. M-1 partial — what it is, what's needed for full

**What V8.1 ships (the partial fix)**:
- `_assert_pubkey_shape(kind, pubkey)` in `account.cairo` checks `pubkey.len() == expected_len` per kind tag at every registration site (`execute_add_owner`, `execute_rotate_owner`, `bootstrap_from_sessions` indirectly). Unknown kind → revert.
- Catches ~80% of registration footguns: wrong-shape garbage like "16 felts of `1` for BLS", "4 felts where 5 are needed for sub-bound JWT", etc.

**What it does NOT catch**:
- A 16-felt BLS pubkey that has correct shape but is **not in the BLS12-381 G2 r-torsion subgroup** (cofactor-style attack). Such a pubkey passes the length check, lands in `owners`, and every subsequent verify involving that owner panics inside `Bls12_381MinSigVerifier::verify` because `pubkey_g2.assert_in_subgroup_excluding_infinity(...)` reverts on a non-r-torsion point.
- For `secp256k1` / `P256` / `WEBAUTHN_P256` etc., a `(x, y)` off the curve. The respective verifier's `secp256_ec_new_syscall` returns `false` gracefully (not a panic) — so it's not a DoS, just a permanent "false return" for that owner. Less severe than BLS.

**Impact** (audit-rated Medium):
- No fund-theft path. The verifier still rejects sigs from a poisoned owner.
- The actual harm is **multisig DoS**: any threshold OE that includes the poisoned `owner_id` reverts before reaching a passing inner envelope. Legitimate signers can't satisfy the threshold without going through the timelocked `remove_owner` flow first.

**What "full M-1" requires**:

1. **Add `validate_pubkey(self: @TContractState, pubkey: Span<felt252>) -> bool` to the `ISigner` trait** in `src/signer/interface.cairo`:
   ```cairo
   #[starknet::interface]
   pub trait ISigner<TContractState> {
       fn verify(self: @TContractState, message_hash: felt252, pubkey: Span<felt252>, signature: Span<felt252>) -> bool;
       fn kind(self: @TContractState) -> felt252;
       fn validate_pubkey(self: @TContractState, pubkey: Span<felt252>) -> bool;  // NEW
   }
   ```

2. **Implement `validate_pubkey` in each of the 10 verifier classes**:
   - **STARK**: `pubkey.len() == 1 && pubkey.at(0) is non-zero` — shape only.
   - **ED25519**: `pubkey.len() == 2 && halves fit u128` — shape only; Garaga handles in-curve at verify time.
   - **SECP256K1 / EIP191 / EIP712**: `pubkey.len() == 4 && halves fit u128 && match secp256_ec_new_syscall(x, y) { Ok(_) => true, Err(_) => false }` — true on-curve check via syscall.
   - **P256 / WEBAUTHN_P256**: same shape, P-256 variant of the syscall.
   - **JWT_ES256**: same as P256 (4 felts, must be valid P-256 pubkey).
   - **JWT_ES256_APPLE_SUB**: 5 felts, first 4 must be valid P-256 pubkey, 5th (sub_hash) any felt252.
   - **BLS12_381**: 16 felts, limbs fit u96, `is_on_curve_excluding_infinity(BLS_CURVE_INDEX)` (non-panicking, returns bool), **and a non-panicking subgroup check** that mirrors Garaga's `assert_in_subgroup_excluding_infinity` but returns `bool` instead of panicking. ~80 LOC of BLS12-381 G2 subgroup math: compute `psi(Q)` and `seed * Q`, check equality, return bool.

3. **Update `account.cairo` to call `validate_pubkey` via library_call** before `owners.add_owner(...)`:
   ```cairo
   let v_class = self.verifier_classes.read(kind);
   assert(Into::<ClassHash, felt252>::into(v_class) != 0, 'SHHH: verifier missing');
   let validator = ISignerLibraryDispatcher { class_hash: v_class };
   self.inside_verifier.write(true);   // M-2 reuse
   let ok = validator.validate_pubkey(pubkey_span);
   self.inside_verifier.write(false);
   assert(ok, 'M1: invalid pubkey');
   ```

4. **Redeclare all 11 classes** (V8.2 ShhhAccount + 10 verifier classes). Class hashes change because Sierra changes when the trait shape changes.

5. **Update SDK constants** to V8.2 hashes.

6. **Update tests** to use V8.2 (test count probably 230+ with new validate_pubkey regression tests per kind).

**Cost estimate**:

| Class | Sierra delta vs V8.1 | Redeclare fee (est.) |
|---|---|---|
| ShhhAccount V8.2 | small (~5% larger) | ~45 STRK |
| StarkVerifier | trivial (3-line method) | ~1.4 STRK |
| Ed25519Verifier | trivial | ~32 STRK |
| Secp256k1Verifier | small (syscall) | ~3.5 STRK |
| EIP191Secp256k1Verifier | small | ~7 STRK |
| EIP712Secp256k1Verifier | small | ~8 STRK |
| P256Verifier | small | ~3.2 STRK |
| WebAuthnP256Verifier | small | ~12.5 STRK |
| JwtES256AppleVerifier | small | ~14 STRK |
| JwtES256AppleSubVerifier | small | ~15 STRK |
| Bls12_381MinSigVerifier | larger (~80 LOC subgroup helper) | ~62 STRK |
| **Total** | | **~204 STRK (≈$8)** |

**Effort estimate**: 2-3 days focused.
- Day 1: `validate_pubkey` for the 8 simpler verifiers + ISigner trait update + tests for each
- Day 2: BLS12-381 non-panicking subgroup check + tests; account.cairo wiring
- Day 3: integration tests + V8.2 redeclares + doc + SDK constants update

**Why we shipped the partial first**: the audit was clear that M-1 is **Medium severity, no fund-theft path**. Critical/High findings (C-1, H-1, H-2, H-3) were the gating items for V8.1; M-1 partial closes ~80% of the surface. Full M-1 is a V8.2 candidate that compounds with future audit findings — it's worth doing in one batch rather than one-off.

---

## 20. Glossary

- **Counterfactual address**: the deterministic Starknet address an account will have *before* any deploy tx hits the chain. Computed from class hash + salt + ctor calldata. V8 uses `salt = poseidon(primary_kind, primary_pubkey_commitment)` so the address binds the primary owner.
- **Library call** (`library_call_syscall`): Starknet syscall that runs a class's code in the *caller's* storage and address context. V8 uses this to dispatch `verify(...)` to the registered verifier class without giving that class its own state.
- **OE / Outside Execution / SNIP-9 V2**: a Starknet AA pattern where the account exposes `execute_from_outside_v2(oe, signature)` that any caller can invoke. The account validates the signature internally, runs the multicall, and emits events. Enables paymaster-sponsored UX.
- **SNIP-12**: typed-data hashing standard for Starknet, analog of EIP-712. Domain separator includes chain_id + contract_address.
- **Owner record**: one entry in the account's owner_set. Has `(kind, pubkey_hash, role, weight, label, revoked)`. Indexed by `owner_id: u32`.
- **Role**: `ROLE_OWNER` (can sign OEs) | `ROLE_GUARDIAN` (can initiate recovery) | `ROLE_RECOVERY_ONLY` (cannot sign anything; reserved for future use).
- **Threshold**: `u8` value in `owner_set.threshold`. Sum of weights from valid signers in a threshold OE must `>=` this value.
- **Verifier class**: a separately-declared Cairo class implementing `ISigner`. Library_call'd by the account on every `verify(...)`. Immutable per class hash.
- **Kind tag**: a `felt252` short-string identifying the signing primitive (e.g. `'STARK'`, `'ED25519'`, `'BLS12_381'`). Pinned canonically in `src/signer/interface.cairo`.
- **Inside verifier flag** (audit M-2): the `inside_verifier: bool` storage flag raised around every `dispatcher.verify(...)`. `_assert_self_call` refuses self-calls while the flag is set, blocking malicious-verifier reentry.
- **Drand DST**: `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_+`, the only BLS hash-to-curve ciphersuite Garaga's `apps::drand::hash_to_curve_bls12_381` ships. Our BLS verifier uses this.
- **Sub-bound** (JWT): the `JWT_ES256_APPLE_SUB` variant binds an account to a specific Apple `sub` (user identifier) via a `poseidon(sub_bytes)` claim. Lets a wallet provider use one Apple key across many users safely.

---

## 21. Quick checklist for Chipi Pay SDK integration

- [ ] Pin `V8_SHHH_ACCOUNT_CLASS_HASH` and `V8_VERIFIER_CLASS_HASHES` from section 4.
- [ ] Implement `computeShhhAddress` from section 5 (or copy `shhh-wallet-cairo:scripts/ts/compute-wallet-address.ts`, fix the 2-felt-pubkey hardcode).
- [ ] Implement `computeOEMessageHash` from section 7 (matches `scripts/ts/snip12-hash.ts`).
- [ ] Pick the signer kinds Chipi will support first. Recommended priority: `STARK` (existing chipi sessions users) → `EIP191_SECP256K1` (MetaMask) → `ED25519` (Phantom) → `WEBAUTHN_P256` (passkeys) → `JWT_ES256_APPLE_SUB` (Sign in with Apple multi-tenant).
- [ ] Implement the per-kind envelope builders from section 9 for each kind.
- [ ] Wire the OE submission flow from section 10 through Chipi paymaster (section 11).
- [ ] Add timelock helpers for owner / governance / recovery flows (sections 12-13).
- [ ] (Optional first cycle) Add session-key + spending-policy helpers from section 15.
- [ ] Run a mainnet smoke test: deploy one V8.1 account with each supported kind as primary, sign one OE per kind, confirm in a block.
- [ ] Document revert codes (section 16) in your SDK error mapping.

**Suggested first integration scope**: support `STARK` + `EIP191_SECP256K1` + `WEBAUTHN_P256` for net-new users. That covers ~80% of self-custody crypto wallets in the wild. Add Phantom (`ED25519`) and Apple (`JWT_ES256_APPLE_SUB`) in cycle 2.

---

## 22. Contact + escalation

- Cairo source: `haycarlitos/shhh-wallet-cairo` (carlos@chipipay.com is the maintainer)
- Audit doc reference: `audits/2026-05-07-claude-opus-pre-phase13-review.md`
- Mainnet smoke test reference: this doc, section 1 + the receipts
- Open issues / questions: file against `haycarlitos/shhh-wallet-cairo` with the `sdk-integration` label

Last reviewed: 2026-05-10. If reading this doc more than ~3 months later, double-check the class hashes against `docs/class-hashes.md` on the latest `v8-robust` commit — V8.x redeclares may have happened.
