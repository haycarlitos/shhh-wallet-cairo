# SNIP: Pluggable Signer Interface for Smart Accounts

> **Community discussion for the SNIP draft opened as [PR #NNN](https://github.com/starknet-io/SNIPs/pull/NNN) against `starknet-io/SNIPs`.**
>
> Co-authored by Carlos Castillo ([@haycarlitos](https://github.com/haycarlitos)) and Omar Espejel ([@omarespejel](https://github.com/omarespejel)).

## One-line thesis

**You standardized authorization with the Session Keys SNIP. Now it's time for authentication.**

Session keys (SNIP #163) answered *"what authority does this signer have right now?"*. This SNIP answers *"what curve is the owner key on, and how do I verify it?"* Together, the two cover the full modular-account stack — authorization + authentication — in one coherent shared interface.

## Motivation

Every Starknet account that ships a non-STARK-curve signer today does so by forking a reference implementation and writing curve-specific validation inline. The result is a proliferation of narrow account classes that don't interoperate: Argent hardcodes STARK + guardian, Cartridge hardcodes WebAuthn, Clave hardcodes passkeys, Shhh hardcoded Ed25519.

Paymasters, dapp SDKs, and indexers have no way to discover "what curve is this account signing with?" — they hardcode each wallet's convention. That's how the [Shhh V7 audit](https://gist.github.com/omarespejel/dddcc2b7df4e8b8bb47af9d1936f8a3e) happened: an account advertised SNIP-9 V2 compliance but used a custom Phantom envelope, and dapps probing SRC-5 got incorrect answers.

This SNIP proposes a shared trait (`ISigner`), a canonical kind-tag registry, and a tagged signature envelope so that **one account class can verify signatures from any curve** — and paymasters can sponsor any of them without per-wallet integration work.

## What the SNIP delivers

1. **`ISigner` trait** (3 methods: `verify`, `owner_commitment`, `signer_kind`) — every verifier implements the same surface.
2. **Canonical kind tags** — 6 primitives (`STARK`, `SECP256K1`, `ED25519`, `P256`, `RSA_2048`, `BLS12_381`) + 6 envelope variants (WebAuthn, EIP-191, EIP-712, DKIM, JWT_RS256, JWT_ES256).
3. **Tagged signature envelope** — `[kind_tag, payload...]`. Paymasters route by tag; the account dispatches to the matching verifier.
4. **Integration with Session Keys SNIP #163** — a 4-element session sig and a kind-tagged owner envelope coexist by signature-length routing; no collision possible.
5. **Address-salt binding** — `salt = poseidon(primary_kind, primary_pubkey_hash)` prevents cross-kind address collisions.

## Real market coverage this unlocks

Roughly **99% of the signing surface area humans actually use in 2026**:

| Kind | Real-world signers |
|---|---|
| `STARK` | Argent, Braavos, OZ account, Ledger Starknet app |
| `SECP256K1` | MetaMask (~100M installs), Rainbow, Trust Wallet, Coinbase Wallet, WalletConnect, Ledger, Trezor |
| `ED25519` | Phantom (~10M MAU), Solflare, Backpack, Keplr, SSH |
| `P256` / `WEBAUTHN_P256` | Apple passkeys (~2B iPhones), Android passkeys, Windows Hello, YubiKey |
| `RSA_2048` / `JWT_RS256` | YubiKey PIV, corporate PKI, Google accounts (~3B), Okta, Auth0 |
| `JWT_ES256` | Sign in with Apple (~1B) |
| `DKIM_RSA` | Every Gmail / Outlook / iCloud / workplace email |
| `BLS12_381` | Ethereum validators (~1M), Cosmos validators |

Explicitly excluded: shared-secret schemes (TOTP, SMS codes, passwords). They aren't cryptographic signers — they become one only when wrapped in a ZK envelope (`ZK_TOTP`, `ZK_JWT`, `ZK_EMAIL` reserved in Part B Tier 3, specified in follow-up SNIPs).

## Reference implementation (battle-tested)

[`haycarlitos/shhh-wallet-cairo`](https://github.com/haycarlitos/shhh-wallet-cairo) at commit `6c30576` (branch `v8-robust`) ships all four Tier-1 verifier classes in production-audited form. Evidence:

- **104 tests passing**, 0 failed, 5 ignored (documented)
- **8 of 10 mutation-test mutants killed**; 2 remaining survivors are documented coverage gaps
- **7 fuzz tests × 256 runs = 1792 random sweeps** across authorization / timelock / bounds
- **All 12 findings from the Codex audit** (C-1, H-1, H-2, M-1..4, L-1, I-1..3) closed with tested regressions on both V7 (the audited contract) and V8 (the new class)
- **End-to-end flows tested**: Phantom signs → library_call Ed25519 verifier → atomic multicall → target state change (Phase 3); same for secp256k1 (Phase 8) and P-256 (Phase 9)
- **Cross-language fixtures**: `@noble/ed25519`, `ethers.js`, `@noble/curves` all sign one canonical SNIP-12 hash

The same codebase also ships multi-owner storage, timelocked governance, guardian recovery, and a sessions-wallet migration class — making it the first Cairo reference implementation of the full modular-account stack.

## Why now

- **Session Keys SNIP #163** merged on 2026-03-03 — authorization is standardized.
- **Garaga v1.0.1** + Cairo 2.14's native secp256k1/secp256r1 syscalls made every Tier-1 verifier cheap enough for account-class use (~17M l2_gas for secp256k1, ~28M for P-256, ~33M for Ed25519).
- **Passkey onboarding** is becoming consumer default (Cartridge, Clave, Braavos) — without a standard, every new passkey wallet is another integration cliff.

## Proposal shape

The draft is in the PR — standards-track, SRC category, requires SNIP-5/6/9/12 + Session Keys SNIP. Please review the Specification section (`ISigner` trait + kind registry + envelope format + SNIP-9 integration) and push back on anything that would constrain existing or future wallet designs.

## Open questions for the community

1. **Tier 2 envelope scope** — should `EIP191_SECP256K1` and `EIP712_SECP256K1` be separate kinds, or should they reuse `SECP256K1` with a sub-tag? Reference impl uses separate kinds for clarity; open to either.
2. **`WEBAUTHN_P256` separation from `P256`** — WebAuthn requires `authenticatorData || sha256(clientDataJSON)` as the signed bytes; raw P-256 doesn't. Reference impl currently uses one class (WebAuthnP256Verifier) that accepts the SNIP-12 hash directly; a full WebAuthn envelope parser is a Phase 11+ follow-up. Should the SNIP mandate separate classes?
3. **Verifier-class registry** — the reference impl lets each account govern `kind → class_hash` mappings through timelocked ops. Should the SNIP standardize this, or leave it as implementation-specific?
4. **Threshold signatures** — multi-owner threshold accounts sign with multiple envelopes. The envelope format supports `[n_envelopes, env1_len, env1..., env2_len, env2...]` as a meta-envelope. Should this be Tier 1 or a separate SNIP?

## What's next

- Forum discussion (this thread).
- PR review on `starknet-io/SNIPs`.
- OpenZeppelin Cairo Contracts PR to upstream the four verifier components as reusable OZ modules (planned Phase 12).
- Follow-up SNIPs for ZK-wrapped identity kinds (`ZK_JWT`, `ZK_EMAIL`, `ZK_TOTP`).

Feedback, objections, and test-case proposals welcome in the PR or this thread.
