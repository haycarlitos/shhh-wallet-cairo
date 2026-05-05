# What V8 unlocks for Starknet

Concrete, no-buzzword summary of what the seven V8 classes declared on
mainnet (2026-04-28 + 2026-05-05) make possible. Audience: Cifra
integrators, wallet infra providers (Chipi Pay, Privy, Cavos, Argent),
and Starknet ecosystem reviewers.

## TL;DR

A Starknet smart account that any major self-custody wallet can sign
for, with cross-ecosystem recovery, AI-agent-friendly session keys, and
no extra wallet install for the user. Built to cover roughly 99% of
self-custodial signers in production today.

What's live on Starknet mainnet right now (2026-05-05), via class
hashes in [`class-hashes.md`](./class-hashes.md):

- `ShhhAccount` — the account class
- `StarkVerifier` — Argent, Braavos, Ledger Starknet app, native
- `Ed25519Verifier` — Phantom, Solflare, every Solana wallet
- `Secp256k1Verifier` — raw secp256k1 (hardware wallets exposing
  low-level signing)
- `EIP191Secp256k1Verifier` — MetaMask, Rabby, Coinbase Wallet,
  Trust, every EVM wallet via `personal_sign`
- `EIP712Secp256k1Verifier` — same wallets, structured-data popup
  via `eth_signTypedData_v4` (MetaMask shows named fields like
  "Domain: Shhh, hash: 0x…" instead of an opaque hex blob)
- `JwtES256AppleVerifier` — "Sign in with Apple". Accepts an RFC 7515
  JWT signed by Apple with ECDSA P-256, full verification on chain
  (signature + nonce binding + hardcoded `appleid.apple.com` issuer)
- `P256Verifier` — PIV smart cards, eIDAS qualified certificates,
  Apple DeviceCheck
- `WebAuthnP256Verifier` — Apple passkeys, Touch ID, Face ID,
  Windows Hello, YubiKey FIDO2

## Audience 1: end users

What kind of wallet UX a Starknet dapp can now offer:

1. **"Sign up with Phantom"** — a Solana user with a Phantom wallet
   creates a Starknet account at the same address every time, signs
   transactions through the existing Phantom popup, and never installs
   a new wallet.

2. **"Sign up with MetaMask"** — same, but for any EVM wallet. The
   `personal_sign` MetaMask popup ("Sign this message") is exactly what
   the user sees. No new RPC config, no Snap.

3. **"Sign up with Face ID"** — first-time crypto users tap their
   phone's biometric sensor, no seed phrase, no wallet download. Behind
   the scenes a passkey is created on the device's secure element via
   the browser's native WebAuthn API.

4. **Cross-ecosystem recovery** — if your phone dies, your laptop's
   MetaMask, your watch's passkey, a YubiKey, or a family member's
   Phantom can all be set up as guardians for your Starknet account.
   Recovery is a 7-day timelocked flow that any guardian (matching the
   account's threshold) can initiate. No seed phrase to remember.

5. **AI-agent permissions** — grant an agent a session key with
   per-token spending caps that expires automatically. The agent can
   trade or rebalance within strict limits, then loses access without
   any further user action.

## Audience 2: developers integrating V8

Things a developer who picks up V8 doesn't have to build:

1. **Per-curve cryptography** — Cairo verifier classes for Ed25519
   (Garaga), secp256k1 (raw + EIP-191), P-256 (raw + WebAuthn full
   envelope), STARK ECDSA are already declared. Devs reference them by
   class hash and never touch the curve math.

2. **Wallet connection lifecycle** — the existing kits each ecosystem
   already ships handle this: wagmi or viem for MetaMask,
   `@solana/wallet-adapter` for Phantom, the browser's native WebAuthn
   API for passkeys, `starknet-react` / `get-starknet` for Argent and
   Braavos. Dev keeps these as is.

3. **Signature → envelope conversion** — a small adapter (30 to 100
   lines per wallet) takes whatever bytes the wallet returns and
   reshapes them into the V8 envelope. We're targeting these as PRs
   into starknet.js, Chipi SDK, Privy and Cavos rather than a
   standalone library.

4. **Paymaster routing** — one Starknet paymaster integration covers
   every wallet kind because the curve check happens on chain. The
   paymaster never sees which wallet signed, just a Starknet tx to
   sponsor.

5. **Account governance** — multi-owner storage, weighted threshold,
   timelocked propose/execute/cancel, and guardian-initiated recovery
   are all built in via components. Devs don't reimplement.

6. **Session keys + spending policies** — SNIP-163 sessions already
   wired into V8 with a V8-specific admin blocklist on 17 selectors.
   Drop in for AI agents, gaming sub-accounts, automation bots.

## Audience 3: the Starknet ecosystem

What the existence of this account class on mainnet does for Starknet
broadly:

1. **User inflow from other ecosystems.** Every Phantom user, every
   MetaMask user, every passkey user is now one click away from a
   Starknet account they didn't have to learn anything new for. A
   Solana dapp building cross-chain prediction markets can offer
   Starknet liquidity to its users without forcing them to leave
   Phantom. An Ethereum dapp building consumer flows can settle on
   Starknet while the user signs with their existing MetaMask.

2. **Free USDC migration via CCTP.** The Starknet side of CCTP's
   USDC bridge is paymaster-sponsored; the source-chain burn can be
   relayed by the dev's backend. End to end, a user pays $0 to bring
   their stablecoins from Solana or Ethereum into a V8 wallet. (This
   already runs on Cifra's stack today.)

3. **Cross-ecosystem recovery centered on Starknet.** A user's primary
   store of value can sit on Starknet with guardians on Phantom,
   MetaMask, passkeys, hardware wallets — all at once. Starknet's
   validity-proof finality (inheriting Ethereum L1 settlement) plus a
   multi-day timelock make it a strong recovery anchor for assets
   bridged in from across ecosystems.

4. **MPC-grade security without MPC infrastructure.** A 2-of-3
   threshold across a laptop key, a phone passkey and a hardware wallet
   gives the same "no single device compromise can move funds"
   property as MPC threshold signing, with no MPC nodes to run, no
   per-user vendor fees, and the threshold logic enforced on chain
   instead of off-chain coordination.

5. **AI agents that can transact on Starknet safely.** Session keys
   plus per-token spending policies plus automatic expiry let agents
   act on a user's behalf within strict, on-chain-enforced limits.
   This is the missing piece for agent-driven dapps.

6. **Account-abstraction flagship.** Starknet is already the only
   major chain with native AA. V8 is open-source proof that the AA
   surface can absorb every major signing primitive in production
   hardware and consumer software in 2026. Other chains shipping AA
   later via ERC-4337 will need a similar pluggable-signer story; V8
   is a working reference for what that looks like.

## What's not in V8 yet (honest list)

These are reserved kind tags or planned follow-ups, not built:

- **BLS12-381** — validator-key signing. Garaga has the pairing
  primitives but no out-of-the-box BLS signature verifier. Building
  one safely (correct hash-to-curve G2 for Eth-validator-style sigs,
  IETF ciphersuite compliance) is realistically 1-2 weeks.
- **JwtES256SubBoundVerifier** — multi-user follow-up to the Apple
  JWT verifier. Adds a stored identity hash (`poseidon(sub)`) so a
  shared Apple key authenticates distinct end users. ~1 day.
- **DKIM-RSA, JWT-RS256** — email and Google-OAuth based signers.
  Path is via zk-email / zk-jwt circuits + an on-chain SNARK
  verifier. Reserved kind tags; ~3-6 weeks per kind.
- **ZK-wrapped variants** (TOTP, JWT, email, TLS under ZK proof) —
  research stage, reserved kind tags only.

## Cost reality check

Per-user cost map and Cifra projection: see
[`mainnet-deployment.md`](./mainnet-deployment.md).

Headline numbers: a typical Cifra user (Phantom signup + 30 bets in
month one + add a guardian) costs about 27.6 STRK / $1.06 to sponsor
through Chipi Pay at 2026-05-05 STRK prices. A wallet infra provider
absorbs that as part of their existing pricing or passes it through.

## How wallet infra providers can adopt this

1. Pin the seven class hashes in your SDK constants (copy from
   [`class-hashes.md`](./class-hashes.md)).
2. For each wallet kind your users have, write the small adapter
   (signature output → V8 envelope). 30 to 100 lines per kind.
3. Use your existing paymaster integration. The curve check runs
   inside `ShhhAccount` so the paymaster path doesn't change.
4. Optionally surface multi-device guardianship and session-key UX in
   the recovery and agent-permission flows you already ship.

Net effect: more users reach Starknet apps without leaving the wallet
they already trust, and your existing UX surface absorbs the new
account class as one more option in the onboarding flow you already
own.
