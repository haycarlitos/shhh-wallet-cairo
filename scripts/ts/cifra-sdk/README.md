# Cifra SDK

Drop-in TypeScript surface for the Cifra Next.js frontend to consume V8 `ShhhAccount`. Copy the `cifra-sdk/` folder into `cifra`'s codebase or consume via a local workspace.

## Install

```bash
cd scripts/ts
npm install
```

Deps already in `scripts/ts/package.json`: `starknet@^9`, `ethers@^6`, `@noble/ed25519`, `@noble/curves`, `garaga@1.0.1`.

## Surface

```ts
import {
  signOutsideExecution,
  computeAccountAddress,
  callAddOrUpdateSessionKey,
  callInitiateRecovery,
  callFinalizeRecovery,
  callCancelRecovery,
  callSetSpendingPolicy,
  callRevokeSessionKey,
  SELECTORS,
  randomNonce,
  nowSec,
} from './cifra-sdk';

import {
  detectEd25519Signer,       // Phantom
  detectSecp256k1Signer,     // MetaMask / EVM
  detectWebAuthnSigner,      // Face ID / passkeys
  detectStarkSigner,         // native Starknet
} from './cifra-sdk/signers';
```

## Typical flows

### 1. "Sign up with Phantom"

```ts
import { Phantom } from '@solana/wallet-adapter-phantom';
import { eddsaCalldataBuilder, init as initGaraga } from 'garaga';
await initGaraga();

const phantom = window.phantom?.solana;
await phantom.connect();

const signer = await detectEd25519Signer({
  phantomLike: phantom,
  eddsaCalldataBuilder,
});

const CLASSES = {
  shhhAccountClassHash: BigInt(process.env.NEXT_PUBLIC_SHHH_ACCOUNT_CLASS),
  verifierClassHashes: {
    ED25519: BigInt(process.env.NEXT_PUBLIC_ED25519_VERIFIER),
    SECP256K1: BigInt(process.env.NEXT_PUBLIC_SECP256K1_VERIFIER),
    WEBAUTHN_P256: BigInt(process.env.NEXT_PUBLIC_WEBAUTHN_P256_VERIFIER),
    STARK: BigInt(process.env.NEXT_PUBLIC_STARK_VERIFIER),
  },
};

const accountAddress = computeAccountAddress(signer, CLASSES, 'phantom');
// ^ deterministic. If the account isn't yet deployed, deploy via paymaster.
```

### 2. "Place a Cifra bet" (OE signing)

```ts
const signed = await signOutsideExecution(signer, {
  accountAddress,
  chainId: BigInt(shortString.encodeShortString('SN_MAIN')),
  nonce: randomNonce(),
  executeAfter: 0n,
  executeBefore: nowSec() + 600n, // 10 min
  calls: [{
    contractAddress: CIFRA_MARKET_ADDR,
    entrypoint: 'place_bet',
    calldata: [marketId, outcome, amount_lo, amount_hi],
  }],
});

await chipipay.paymaster.executeOutside(accountAddress, signed.oe, signed.envelope);
```

### 3. "Delegate betting to a session key" (Cifra gasless UX)

```ts
const sessionStarkKey = generateStarkKey();

const signed = await signOutsideExecution(signer, {
  accountAddress,
  chainId: SN_MAIN,
  nonce: randomNonce(),
  executeAfter: 0n,
  executeBefore: nowSec() + 300n,
  calls: [
    callAddOrUpdateSessionKey({
      accountAddress,
      sessionKey: sessionStarkKey.pub,
      validUntil: nowSec() + 7n * 24n * 3600n,  // 7 days
      maxCalls: 50,
      allowedEntrypoints: ['place_bet'],
    }),
    callSetSpendingPolicy({
      accountAddress,
      sessionKey: sessionStarkKey.pub,
      token: USDC_ADDR,
      maxPerCall: 10_000_000n,            // 10 USDC (6 decimals)
      maxPerWindow: 200_000_000n,         // 200 USDC / week
      windowSeconds: 7n * 24n * 3600n,
    }),
  ],
});

await chipipay.paymaster.executeOutside(accountAddress, signed.oe, signed.envelope);
```

After this, subsequent bets sign with `sessionStarkKey` using a 4-element session signature envelope — no popup.

### 4. "I lost my phone" (guardian-initiated recovery)

```ts
// Guardian's wallet, owner_id=1 (guardian slot).
const signed = await signOutsideExecution(guardianSigner, {
  accountAddress,
  chainId: SN_MAIN,
  nonce: randomNonce(),
  executeAfter: 0n,
  executeBefore: nowSec() + 600n,
  calls: [
    callInitiateRecovery({
      accountAddress,
      proposer: 1, // guardian owner_id
      newOwnerKind: 'WEBAUTHN_P256',
      newPubkey: newPasskeyPubkey,
      role: 'OWNER',
      weight: 1,
      label: 'new-phone',
    }),
  ],
});

// Wait 7 days. Anyone can finalize.
const finalizeSigned = await signOutsideExecution(anySigner, {
  accountAddress,
  chainId: SN_MAIN,
  nonce: randomNonce(),
  executeAfter: 0n,
  executeBefore: nowSec() + 600n,
  calls: [
    callFinalizeRecovery({
      accountAddress,
      newOwnerKind: 'WEBAUTHN_P256',
      newPubkey: newPasskeyPubkey,
      role: 'OWNER',
      weight: 1,
      label: 'new-phone',
    }),
  ],
});
```

## Notes

- **Cross-curve consistency** — `signOutsideExecution` produces the exact envelope V8 `ShhhAccount::execute_from_outside_v2` accepts, regardless of kind.
- **Deterministic addresses** — `computeAccountAddress` is a pure function, so the Cifra frontend can render "You'll be at 0x..." on the signup screen before the deploy tx lands.
- **No paymaster dep** — the SDK returns `{ oe, envelope }` for any paymaster (Chipi Pay, AVNU) to consume. Use Chipi Pay's client for gasless.
- **Session keys** are STARK-curve (cheapest to verify on Starknet). Generate with `starknet.js`'s `hash.computeStarkKey`.

## What's not here yet

- EIP-712 typed-data variant for MetaMask (currently uses raw secp256k1 sign — works, but lacks the typed-data popup UX).
- Full WebAuthn envelope with clientDataJSON parsing (current verifier takes the pre-computed SNIP-12 hash; Phase 9b adds the full ceremony).
- Threshold-signature envelopes (multi-owner OEs with multiple signatures).

These are all follow-up work that doesn't block Cifra MVP.
