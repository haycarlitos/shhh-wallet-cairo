---
snip: X
title: Pluggable Signer Interface for Smart Accounts
description: A curve-agnostic signer trait and canonical signature envelope that lets any Starknet smart account verify Ed25519, secp256k1, P-256 (WebAuthn), RSA, and BLS signatures through a single interface.
author: Carlos Castillo (@haycarlitos), Omar Espejel (@omarespejel)
discussions-to: https://community.starknet.io/t/snip-pluggable-signer-interface
status: Draft
type: Standards Track
category: SRC
created: 2026-04-16
requires: SNIP-5, SNIP-6, SNIP-9, SNIP-12, Session Keys SNIP (starknet-io/SNIPs#163, `SNIPS/snip-x.md`)
reference-impl: https://github.com/haycarlitos/shhh-wallet-cairo/tree/v8-robust (commit 6c30576)
---

## Simple Summary

Standard interface for curve-agnostic signature verification on Starknet smart accounts. Defines an `ISigner` trait, a canonical signer-kind tag registry, and a tagged signature envelope so that one account contract can verify signatures from Phantom, MetaMask, passkeys, hardware wallets, OAuth providers, and Starknet-native keys without rolling new contracts for each curve.

## Abstract

This SNIP defines:

1. An `ISigner` trait with three methods: `verify`, `owner_commitment`, `signer_kind`.
2. A canonical kind-tag registry covering six battle-tested primitives (STARK, SECP256K1, ED25519, P256, RSA_2048, BLS12_381) and seven envelope variants (WEBAUTHN_P256, EIP191_SECP256K1, EIP712_SECP256K1, DKIM_RSA, JWT_RS256, JWT_ES256, plus one custom extension slot).
3. A signature envelope format: `[kind_tag, payload...]` that lets paymasters, dapps, and SDKs dispatch to the right verifier without off-chain negotiation.
4. An integration protocol with SNIP-9 outside execution and the draft Session Keys SNIP, so that session keys and pluggable owner signatures coexist cleanly.
5. A reference component layout (one component per curve, all sharing the same `ISigner` trait) with address-salt rules that prevent cross-class confusion.

Together, these components mean a single audited account contract family can serve every major wallet type on Earth — and paymasters can sponsor any of them without per-wallet integration work.

## Motivation

Starknet's account model already permits arbitrary signature schemes: every account is a contract, and `__validate__` can verify anything. In practice, every team that has shipped a non-STARK-curve account has done so by forking a reference implementation and writing curve-specific validation inline. The result is a proliferation of narrow account classes that don't interoperate.

**Current state** — battle-tested implementations that would each benefit from a shared interface:

| Team / project              | Primary signer             | Fork surface                                                  |
|-----------------------------|----------------------------|---------------------------------------------------------------|
| Argent                      | STARK + guardian (STARK)   | Owner + guardian + escape flow, STARK-only curve              |
| Braavos                     | STARK + hardware signer    | Hardware signer via external library                          |
| Cartridge Controller        | WebAuthn P-256             | Custom SNIP-12 envelope, passkey-specific                     |
| Clave                       | WebAuthn P-256             | Passkey-specific                                              |
| Chipi Pay (this repo)       | STARK + session keys       | Session key component, shared via SNIP-sessions               |
| Shhh Wallet (Garaga)        | Ed25519 (Phantom)          | Full custom account; audited 2026-04-20 (see below)           |
| Starknet-by-example / OZ    | STARK ECDSA                | Reference-only, no multi-curve                                |
| zkLogin-style proposals     | JWT (RSA/ES256)            | Research stage; no production deployments                     |

Each is correct for its niche. None can verify a signature produced by another. A user who holds a Phantom wallet cannot use Argent's guardian recovery; a Cartridge passkey cannot sign a Chipi session-key invocation; zkLogin JWTs cannot share an account class with any of the above.

**This SNIP was motivated directly by the April 2026 security review of the Shhh wallet.** Two converging signals: a Nethermind-AuditAgent scan run on 2026-04-13 by Henri (a repo collaborator; three structural findings) followed by Omar Espejel's human Codex/Cairo audit on 2026-04-20 ([report](https://gist.github.com/omarespejel/dddcc2b7df4e8b8bb47af9d1936f8a3e); twelve findings). Three of Omar's findings converged on the same root cause Henri's scan first surfaced:

1. **H-2 — SRC-5 interface ID mismatch.** The Shhh wallet advertised SNIP-9 V2 support but registered a custom interface ID and signed a custom byte envelope. The audit correctly noted that dapps, SDKs, and paymasters probing for SNIP-9 V2 would get incorrect results. The root cause was not bad intent — it was that there is no standard way to say "this account uses Ed25519 for owner signatures."
2. **M-1 — `caller == 0` sentinel ambiguity.** The contract accepted both `0` and `'ANY_CALLER'` as unrestricted sentinels because SNIP-9 and the Phantom-specific path had diverged. Again: no standard envelope, no standard dispatcher.
3. **I-1 — Custom calls-hash collision risk.** The audit downgraded this to Informational but flagged that custom Poseidon packing instead of SNIP-12 typed data created standards drift.

The fix for all three is the same: stop rolling custom signature envelopes. Use a standard dispatcher that knows how to verify each curve, a standard SNIP-12 hash for the message, and a standard kind-tag on the signature. That standard does not exist today. This SNIP proposes it.

**Why now.** Three forces make 2026 the right year to land a signer SNIP:

- **Garaga v1.0.1** shipped production-ready Cairo implementations of Ed25519, secp256k1, and P-256 verification with msm hints. The cryptographic primitives are now cheap enough (~33M l2_gas for Ed25519) to be a normal account-contract dependency.
- **The Session Keys SNIP** (authored by Chipi Pay and Omar Espejel) was merged into the official [`starknet-io/SNIPs`](https://github.com/starknet-io/SNIPs) repository on 2026-03-03 via [PR #163](https://github.com/starknet-io/SNIPs/pull/163), currently sitting at `SNIPS/snip-x.md` with status `Draft` pending number assignment. It standardizes the *authorization* layer — what a delegated key is allowed to do. This SNIP proposes the complementary *authentication* layer — which curve an owner key uses and how it is verified. The two together form the complete modular-account stack.
- **Passkey onboarding** is becoming the consumer default (Cartridge, Clave, Braavos). Without a shared signer interface, every new passkey wallet is another integration cliff for paymasters and SDKs.

**A standard enables:**
- Any paymaster sponsors any wallet — signer-type discovery is on-chain and uniform.
- A dapp SDK written once works across Phantom, MetaMask, passkey, and STARK wallets.
- Starknet.js, Argent Wallet, Braavos can add non-STARK signer support without hardcoding each implementation.
- Audit surface consolidates: one `ISigner` trait + six Garaga/OZ components audited once, reused everywhere.

**Market coverage.** The twelve canonical kinds in Part B (six Tier-1 curves plus six Tier-2 envelope variants) enumerate essentially every cryptographic-signer primitive shipping in production hardware and consumer software in 2026:

- **Crypto self-custody wallets** (secp256k1 + Ed25519 + STARK) ≈ 100% of existing hot wallets on any chain.
- **Mobile biometric devices** (WebAuthn P-256) ≈ every iPhone, modern Android, and Mac — roughly 4–5B devices.
- **Email identity** (DKIM_RSA + JWT_RS256 + JWT_ES256) ≈ every active Gmail / Outlook / iCloud / workplace account — roughly 4–5B humans.
- **Enterprise / government ID** (P-256 + RSA_2048) ≈ every PIV/CAC/eIDAS-issued credential.
- **Validator and institutional keys** (BLS12_381) ≈ every L1 validator and large-DAO multisig.

The schemes deliberately excluded from the canonical registry — TOTP, SMS one-time codes, plaintext passwords — are not cryptographic signers but authentication *methods* that need a ZK envelope to become one. Part B reserves `'ZK_TOTP'`, `'ZK_JWT'`, `'ZK_EMAIL'`, and `'ZK_TLS'` kinds for follow-up SNIPs that specify those envelopes.

The practical consequence: **every major signing device humans use today — including those carried by users who have never held a crypto wallet — gets a one-line integration path into Starknet smart accounts.** That is the ceiling-raising effect the sessions SNIP set up, and this SNIP delivers.

**Concrete use cases unlocked per kind:**

| Kind tag             | Flow made possible                                                                                                |
|----------------------|-------------------------------------------------------------------------------------------------------------------|
| `'SECP256K1'`        | EVM user bridges USDC via CCTP to a Starknet app and signs with their existing MetaMask — no new wallet required. |
| `'EIP191_SECP256K1'` | Dapp UX parity with Ethereum: MetaMask popup reads "Sign this message" exactly as on L1.                          |
| `'ED25519'`          | Solana user deposits into a Starknet yield pool and signs everything with Phantom.                                |
| `'WEBAUTHN_P256'`    | Consumer signup with Face ID — no seed phrase, no app install. Passkey users outnumber crypto users ≈20:1.        |
| `'P256'` (raw)       | Corporate treasury signs Starknet multisig with work-issued PIV smart card.                                       |
| `'JWT_RS256'`        | "Sign in with Google" provisions a Starknet account. Google accounts (≈3B) become the onboarding funnel.           |
| `'JWT_ES256'`        | "Sign in with Apple" for iOS-first consumer apps (≈1B Apple IDs).                                                 |
| `'DKIM_RSA'`         | Email-based recovery ("send a signed email from your Gmail"); compliance-grade approval workflows.                |
| `'RSA_2048'`         | Regulated institution signs on-chain with existing eIDAS or YubiKey PIV hardware.                                  |
| `'BLS12_381'`        | Ethereum or Cosmos validators reuse their existing BLS key to vote on Starknet governance.                         |
| `'STARK'`            | Native Starknet wallets + session delegation (status quo preserved, no change).                                   |

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### Part A: The `ISigner` Trait

Compliant accounts MUST implement the following interface:

```cairo
#[starknet::interface]
pub trait ISigner<TContractState> {
    /// Verifies that `signature` authorizes `message_hash` under the account's stored owner key.
    /// MUST be pure/read-only. MUST NOT write storage.
    /// MUST return `true` only if the signature is cryptographically valid.
    /// The `signature` span has the envelope format defined in Part C.
    fn verify(
        self: @TContractState,
        message_hash: felt252,
        signature: Span<felt252>,
    ) -> bool;

    /// Returns a Poseidon commitment of the owner key material.
    /// MUST be stable for the lifetime of the account.
    /// Used for address-salt derivation (Part E) and off-chain account lookup.
    fn owner_commitment(self: @TContractState) -> felt252;

    /// Returns the canonical kind tag (Part B) identifying which curve/envelope
    /// this account's owner key uses.
    /// MUST match the kind stored at deployment.
    fn signer_kind(self: @TContractState) -> felt252;
}
```

**SRC-5 interface ID**:

```
ISIGNER_ID = starknet_keccak("ISigner_V1")
           = 0x94c5a761f34b25a4e603c651ac0e1fc4fad9cdb5517f7fa1bb54044c7e5ef8
```

The canonical label is `"ISigner_V1"`. A breaking trait-shape change (e.g. adding a new required method, or changing a parameter / return type) MUST bump to `"ISigner_V2"` and register both IDs during a migration window. Non-breaking extensions MUST NOT bump the label.

Accounts MUST register `ISIGNER_ID` via SRC-5 at construction so that paymasters, wallets, and dapps can discover signer support. Reference implementation registers the ID both on native V8 deploys and inside the sessions-wallet migration path so post-upgrade accounts look identical to fresh deployments via SRC-5 probing.

### Part B: Canonical Kind-Tag Registry

Compliant accounts MUST use one of the following `felt252` kind tags to identify their signer type. Tags are ASCII short-strings so they are human-readable in explorers and logs.

**Tier 1 — Primitive curves (MUST-support targets for library components):**

| Kind tag         | Algorithm            | Canonical message form  | Real-world signers in production                                                                                               |
|------------------|----------------------|-------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| `'STARK'`        | Stark-curve ECDSA    | felt252 hash            | Argent, Braavos, OpenZeppelin account, Ledger Starknet app, relayers                                                           |
| `'SECP256K1'`    | secp256k1 ECDSA      | 32-byte hash            | MetaMask (≈100M installs), Rainbow, Trust Wallet, Coinbase Wallet, Rabby, Frame, WalletConnect, Ledger, Trezor, GridPlus       |
| `'ED25519'`      | Edwards25519 EdDSA   | arbitrary byte string   | Phantom (≈10M MAU), Solflare, Backpack, Glow, Keplr, Leap, Near wallet, SSH agents, GPG                                         |
| `'P256'`         | NIST P-256 ECDSA     | 32-byte hash            | Enterprise PIV smart cards, eIDAS government eIDs, Apple DeviceCheck, corporate PKI                                            |
| `'RSA_2048'`     | RSA-PKCS1 + SHA-256  | 32-byte hash            | YubiKey PIV slot, DocuSign, many EU eIDAS eIDs, TLS certificate PKI                                                            |
| `'BLS12_381'`    | BLS12-381 G1         | 48-byte hash            | Ethereum validators (≈1M), Cosmos validators, Eigenlayer AVSs, threshold-sig networks                                          |

**Tier 2 — Envelope variants (RECOMMENDED for library components):**

| Kind tag                 | Inner curve  | Envelope                                     | Real-world signers / integration target                                                                   |
|--------------------------|--------------|----------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `'WEBAUTHN_P256'`        | P-256        | `authenticatorData \|\| sha256(clientData)`  | Apple passkeys (Face ID / Touch ID, ≈2B iPhones), Android passkeys, Windows Hello, 1Password, YubiKey, Titan Key |
| `'EIP191_SECP256K1'`     | secp256k1    | `"\x19Ethereum Signed Message:\n" + len`     | Every EVM wallet's `personal_sign` UI — MetaMask, Rainbow, Trust, WalletConnect                           |
| `'EIP712_SECP256K1'`     | secp256k1    | EIP-712 typed data                           | Permit2, Uniswap, OpenSea, any EIP-712-signing dapp                                                       |
| `'DKIM_RSA'`             | RSA-2048     | Canonicalized email headers                  | Every Gmail, Outlook, iCloud, or corporate email sender that publishes DKIM (≈4-5B accounts)              |
| `'JWT_RS256'`            | RSA-2048     | JWS compact serialization                    | Google OAuth (≈3B accounts), Microsoft/Entra ID, Okta, Auth0, enterprise SSO                              |
| `'JWT_ES256'`            | P-256        | JWS compact serialization                    | Sign in with Apple (≈1B Apple IDs)                                                                        |

**Tier 3 — Reserved for follow-up SNIPs:**

`'MULTISIG_K_OF_N'`, `'GUARDIAN'`, `'WEIGHTED'`, `'ZK_JWT'`, `'ZK_EMAIL'`, `'ZK_TLS'`, `'ZK_TOTP'`.

**Non-normative exclusions.** Shared-secret schemes (TOTP/HOTP/OTP, SMS codes, plaintext passwords) are intentionally **not** assigned kind tags. They do not produce on-chain-verifiable signatures. Implementations that want TOTP-like UX MUST express it as a `ZK_TOTP` circuit or bridge it through WebAuthn on the user's device.

**Kind-tag registration policy.** New kinds (including Tier 3) SHOULD be proposed as amendments to this SNIP once at least one production implementation exists and an independent auditor has reviewed the verifier component. Reserved names above are listed to prevent squatting; anyone MAY implement them, but the canonical encoding MUST be defined in an amendment before library components embed it.

### Part C: Signature Envelope Format

Owner signatures produced by an `ISigner` implementation MUST use the following envelope:

```
signature = [kind_tag, payload_0, payload_1, ..., payload_n]
```

where:
- `signature[0]` is the `felt252` kind tag from Part B,
- `signature[1..]` is the kind-specific payload (curve signature + any envelope fields).

Verifiers MUST read the tag first and dispatch to the matching component. Verifiers MUST reject an envelope whose tag does not match `self.signer_kind()`.

**Kind-specific payload layouts** (non-exhaustive; full tables in reference impl):

```
ED25519:         [tag, Ry_low, Ry_high, s_low, s_high, msg_len, msg_bytes..., hints...]
SECP256K1:       [tag, r_low, r_high, s_low, s_high, v]
EIP191_SECP256K1:[tag, r_low, r_high, s_low, s_high, v]   // same as secp256k1; prefix applied in verify
P256:            [tag, r_low, r_high, s_low, s_high]
WEBAUTHN_P256:   [tag, r_low, r_high, s_low, s_high,
                  auth_data_len, auth_data..., client_data_len, client_data...]
STARK:           [tag, r, s]
RSA_2048:        [tag, sig_limbs...]                      // 64 × u32 or 32 × u64
JWT_RS256:       [tag, jwt_len, jwt_bytes..., sig_limbs...]
DKIM_RSA:        [tag, header_len, header_bytes..., sig_limbs...]
```

**Coexistence with the Session Keys SNIP** (merged via [starknet-io/SNIPs#163](https://github.com/starknet-io/SNIPs/pull/163)). Session signatures in the 4-element `[session_pubkey, r, s, valid_until]` form are distinguishable from owner envelopes because kind tags are ASCII short-strings and session_pubkey values are never valid short-strings. Accounts MUST still route by `signature.len()` as the primary discriminator:

| `signature.len()` | Interpretation                                              |
|-------------------|-------------------------------------------------------------|
| 0                 | Self-call (accept only if `caller == self`)                 |
| 4                 | Session-key signature (per Session Keys SNIP)               |
| ≥ 1, ≠ 4          | Owner envelope; dispatch on `signature[0]` kind tag         |

### Part D: Integration with SNIP-9 V2 (Outside Execution)

Compliant accounts MUST use SNIP-12 typed-data hashing for `OutsideExecution` message hashes. This fixes audit finding H-2 from the Shhh V7 audit (ibid.) by removing the incentive to ship custom hash encodings.

Implementations MAY additionally offer a fallback hash format (e.g. the felt-timestamp variant used by the Chipi Pay paymaster prior to SNIP-9 V2 finalization) to preserve compatibility with paymasters that have not yet upgraded. Fallback paths MUST be clearly documented and MUST NOT be the default path.

The verify order inside `execute_from_outside_v2` MUST be:

1. Caller check (`'ANY_CALLER'` OR `caller == outside_execution.caller`). `caller == 0` MUST be rejected (audit M-1).
2. Time window bounds, including an upper cap on window length (audit M-2; RECOMMENDED cap is 7200 seconds for `'ANY_CALLER'` payloads).
3. Nonce replay check.
4. Bounds: `calls.len() ≤ MAX_CALLS`, `signature.len() ≤ MAX_SIGNATURE_FELTS`, total calldata ≤ `MAX_TOTAL_CALLDATA_FELTS` (audit M-3).
5. Read first felt of `signature` as kind tag.
6. Dispatch to the matching `ISigner::verify` implementation.
7. Multicall, atomic: on any subcall failure, revert (audit H-1).

### Part E: Address-Salt Binding

To prevent cross-kind address collisions, the deployment salt for a pluggable-signer account MUST be:

```
salt = poseidon([signer_kind, owner_commitment])
```

This guarantees that the same underlying key material (for example, a Secp256k1 key that was re-encoded as an RSA public exponent) deployed under two different kinds yields two distinct Starknet addresses.

### Part F: Component Architecture (Non-Normative, Recommended)

The reference implementation provides one Cairo component per kind (`ed25519/component.cairo`, `secp256k1/component.cairo`, etc.), each implementing the `ISigner` trait via a `HasOwnerKey` trait that the embedding account implements. This mirrors the component architecture established by the Session Keys SNIP ([starknet-io/SNIPs#163](https://github.com/starknet-io/SNIPs/pull/163)) and has **zero OpenZeppelin dependencies** — any account framework can embed these components.

Wallets integrate in five steps:

1. Add `component!()` for the desired signer component(s).
2. Wire `self.signer.verify(...)` in `__validate__` (or `is_valid_signature`).
3. Register `ISIGNER_ID` and the kind-specific SRC-5 ID at construction.
4. Implement the `HasOwnerKey` trait for your account's storage layout.
5. Use the salt rule in Part E for deterministic addresses.

### Part G: SRC-5 Discovery

Accounts MUST register:

- `ISRC6_ID` (SNIP-6, standard account)
- `ISRC9_V2_ID` (SNIP-9 V2)
- `ISIGNER_ID` (this SNIP)
- A kind-specific SRC-5 ID (`ISIGNER_ED25519_ID`, `ISIGNER_SECP256K1_ID`, etc.) for precise discovery

Paymasters and dapps MUST probe `ISIGNER_ID` first, then call `signer_kind()` to confirm the concrete curve before constructing a signature.

## Rationale

### Why a single trait instead of curve-specific interfaces

Every curve needs the same three operations: verify, identify the owner, identify the curve. A single trait means paymasters and SDKs write one dispatcher, not six.

### Why kind-tag envelopes instead of per-class contracts

Per-class contracts are already what everyone does, and the result is that no two account classes interoperate. Tagged envelopes let one class support multiple kinds if the implementer wishes, while still making single-kind classes the recommended default for audit simplicity.

### Why SNIP-12 is required for outside execution

Because the audit report that motivated this SNIP identified exactly this as the root cause of interface-mismatch vulnerabilities. Custom hash encodings drift; SNIP-12 is the fixed point.

### Why shared-secret schemes are excluded

A signer must verify that *the account owner* authorized a specific message. TOTP and bare passwords authorize *possession of a shared secret*; anyone who scrapes the chain after the secret is placed on-chain can forge future signatures. The only way to make these schemes secure is to wrap them in a ZK proof, at which point the kind is `ZK_TOTP`, not `TOTP`.

### Why address-salt binds the kind tag

Without salt binding, a key re-encoded across curves could map to the same address, letting an attacker who compromised one encoding impersonate the other. Binding the salt eliminates the attack without any per-kind code.

## Backwards Compatibility

- **SNIP-6** (standard account): unchanged. `ISigner::verify` is the recommended implementation of `is_valid_signature` for non-STARK curves, but `is_valid_signature` itself is unchanged.
- **SNIP-9 V2** (outside execution): unchanged on the protocol level. This SNIP tightens the integration requirements (Part D).
- **Session Keys SNIP** ([starknet-io/SNIPs#163](https://github.com/starknet-io/SNIPs/pull/163), merged 2026-03-03): designed to coexist. The 4-element session signature format is explicitly preserved; kind-tagged owner envelopes can never collide with it. An account implementing both SNIPs exposes session-key delegation (authority scoping) and pluggable owner signers (curve choice) as two orthogonal layers.
- **Existing accounts** (Argent, Braavos, Cartridge, Clave, OZ reference): remain valid. They MAY adopt `ISigner` incrementally to expose their existing curve support through the standard interface.

## Security Considerations

1. **Envelope malleability**: verifiers MUST reject a signature whose kind tag does not match `self.signer_kind()`. An account that accepts envelopes for a kind it does not store is an attack surface.
2. **Trailing data**: verifiers MUST confirm the envelope deserializer consumed the entire payload (Shhh audit M-4). Trailing felts after a valid structure MUST be rejected.
3. **Curve subversion**: for Ed25519 and BLS, verifiers MUST follow the reference implementation's handling of small-subgroup / torsion points. For RSA, public exponents MUST be fixed (65537 RECOMMENDED) and never read from the signature.
4. **Message binding**: `verify()` operates on a pre-computed `message_hash`. Integrations MUST NOT call `verify()` with a hash that is not bound to the execution context (nonce, chain id, caller, calls). SNIP-12 typed data is the recommended hash.
5. **Kind squatting**: kind tags outside the canonical registry in Part B SHOULD be rejected by paymasters and SDKs. The registry is the authoritative list.
6. **Key-validation on deploy**: constructors MUST validate that the supplied key material is in-range for the chosen curve (Shhh audit L-1). Out-of-range values create bricked accounts.

## Reference Implementation

The reference implementation lives at [`haycarlitos/shhh-wallet-cairo`](https://github.com/haycarlitos/shhh-wallet-cairo), branch `v8-robust`, pinned at commit **`6c30576`** (Phase 10 exit). V8 deploys a single `ShhhAccount` class that dispatches signature verification to four separately-declared verifier classes via `library_call_syscall`:

| Kind tag             | Verifier class               | Primitive used                                                                |
|----------------------|------------------------------|-------------------------------------------------------------------------------|
| `STARK`              | `StarkVerifier`              | `core::ecdsa::check_ecdsa_signature`                                          |
| `ED25519`            | `Ed25519Verifier`            | Garaga v1.0.1 `is_valid_eddsa_signature`                                      |
| `SECP256K1`          | `Secp256k1Verifier`          | `starknet::secp256_trait::recover_public_key`                                 |
| `P256`               | `P256Verifier`               | `starknet::secp256_trait::is_valid_signature` (P-256, raw)                    |
| `WEBAUTHN_P256`      | `WebAuthnP256Verifier`       | `is_valid_signature<Secp256r1Point>` over `sha256(authData ‖ sha256(clientData))` with on-chain `webauthn.get` type + base64url challenge binding |
| `EIP191_SECP256K1`   | `EIP191Secp256k1Verifier`    | `recover_public_key` over `keccak256("\x19Ethereum Signed Message:\n32" ‖ msg)` — accepts MetaMask `personal_sign` directly |
| `EIP712_SECP256K1`   | `EIP712Secp256k1Verifier`    | EIP-712 typed-data: domain bound to `{name:"Shhh", version:"1", chainId, salt:account_address}`, struct = `MessageHash{hash}` — accepts MetaMask `eth_signTypedData_v4` structured popup |
| `JWT_ES256`          | `JwtES256AppleVerifier`      | RFC 7515 JWT signed with ECDSA P-256: verifier hashes `header_b64 ‖ "." ‖ base64url(payload_decoded)`, recovers under stored IdP pubkey, scans decoded payload for nonce + hardcoded `https://appleid.apple.com` issuer — accepts "Sign in with Apple" tokens directly |

Cross-language fixtures (`@noble/ed25519`, `ethers.js`, `@noble/curves`) sign one canonical SNIP-12 hash across all four curves so the audit surface is "one hash, four verifiers, one envelope shape."

Verification evidence on commit `6c30576`:

- **`scarb build`** — green under Scarb 2.14, Cairo 2.14, Sierra 1.7
- **`scarb fmt --check`** — clean
- **`snforge test`** — 193 passed, 0 failed, 0 ignored
- **Mutation testing** (`scripts/mutation-test.sh`) — 10 of 10 mutants killed; no documented gaps
- **Fuzz testing** — 7 `#[fuzzer]` tests × 256 runs = 1792 random sweeps across authorization, timelock, and M-3 bounds
- **Mainnet declared** — nine classes declared on Starknet mainnet (six initial classes on 2026-04-28; `EIP191Secp256k1Verifier`, `EIP712Secp256k1Verifier`, and `JwtES256AppleVerifier` on 2026-05-05). Every class hash matches its deterministic prediction byte-for-byte. Total declare cost across the nine classes: 120.10 STRK.

The V8 codebase incorporates the twelve findings from the [2026-04-20 Codex/Cairo audit](https://gist.github.com/omarespejel/dddcc2b7df4e8b8bb47af9d1936f8a3e) as regression tests. Each audit finding has a dedicated `test_*` that fires the guard on real contract code — the audit history is reviewable in the commit log (Phase 0 → Phase 10).

V8 also extends the reference to cover the full modular-account stack:

- **Multi-owner storage** with weighted threshold, roles (OWNER / GUARDIAN / RECOVERY_ONLY), tombstone-based removal.
- **Deterministic addresses**: `salt = poseidon(primary_kind, primary_pubkey_hash)`.
- **Timelocked governance**: propose/execute/cancel state machine for every structural mutation.
- **Guardian recovery**: 7-day window, additive, single-owner cancel.
- **Sessions-wallet migration**: atomic `upgrade(V8) + bootstrap_from_sessions(...)` lets existing `chipi-pay/sessions-smart-contract` wallets (Session Keys SNIP #163 reference impl) migrate into V8 in one OE.
- **Session keys + spending policies** (Session Keys SNIP #163) coexist with owner signatures via the length-routed envelope — pluggable-signer SNIP and #163 are designed to stack.

This is the first Cairo codebase that ships all four signer kinds with identical envelope surfaces, proven end-to-end, and passes a mutation sweep that confirms every audit guard is load-bearing.

## Test Cases

Reference test suites for a compliant implementation MUST include, per kind:

- **Positive vector** (valid signature from a real wallet, on-chain execution succeeds)
- **Wrong owner** (valid signature under a different key, MUST revert)
- **Malformed envelope** (truncated payload, trailing data, wrong kind tag, MUST revert with controlled errors)
- **Curve-specific edge cases** (Ed25519 small-subgroup R, secp256k1 high-s malleability, P-256 point-not-on-curve, WebAuthn tampered clientDataJSON, RSA padding attacks)

Cross-kind tests:

- Two accounts with identical raw key bytes but different `signer_kind` MUST yield different addresses (Part E).
- An envelope with kind tag `X` submitted to an account with `signer_kind() = Y` MUST revert.
- The 4-element session-key envelope MUST be correctly dispatched to the session-key path, not to owner verification.

## Acknowledgments

- **Henri ([@l-henri](https://github.com/l-henri))** — collaborator on the Shhh project. Ran the Nethermind AuditAgent scan on the V7 commit range on 2026-04-13, one week before Omar's human review, surfacing the three structural findings (unrestricted `__execute__`, non-atomic multicall, dead upgrade component) that triggered the V8 rewrite. Per the Nethermind AuditAgent license this is a credit to Henri as the collaborator who ran and triaged the scan, not a claim that the code is "audited by Nethermind."
- **Chipi Pay and Omar Espejel** — Session Keys SNIP ([starknet-io/SNIPs#163](https://github.com/starknet-io/SNIPs/pull/163)), which established the modular-account pattern this SNIP extends.
- **Garaga team (Keep Starknet Strange)** — Ed25519, secp256k1, and P-256 verification primitives that make curve-agnostic signer verification practical on Starknet today.

## Copyright

Copyright and related rights waived via [MIT](https://opensource.org/license/mit).
