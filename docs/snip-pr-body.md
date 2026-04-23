# SNIP PR — Pluggable Signer Interface for Smart Accounts

> Paste this body into the GitHub PR description when opening against `starknet-io/SNIPs`.
> Title: `SNIP: Pluggable Signer Interface for Smart Accounts`

## Summary

Adds a Draft SNIP defining a curve-agnostic `ISigner` trait, a canonical kind-tag registry, and a tagged signature envelope so that one Starknet smart account class can verify signatures from Phantom (Ed25519), MetaMask (secp256k1), passkeys (WebAuthn P-256), hardware wallets, OAuth providers, and native STARK wallets without rolling new contracts for each curve.

Motivation: every Starknet account that ships a non-STARK signer today forks a reference implementation and writes curve-specific validation inline. The Shhh V7 security audit (2026-04-20, [report](https://gist.github.com/omarespejel/dddcc2b7df4e8b8bb47af9d1936f8a3e)) identified this as the root cause of an SRC-5 / SNIP-9 interface mismatch (finding H-2). A shared SNIP fixes the root cause for the whole ecosystem.

This SNIP layers on top of the already-merged Session Keys SNIP ([#163](https://github.com/starknet-io/SNIPs/pull/163), co-authored by @omarespejel):

- **Session Keys SNIP** answers *"what authority does this signer have right now?"* (authorization).
- **Pluggable Signer SNIP** (this PR) answers *"what curve is the owner key on, and how do I verify it?"* (authentication).

Together they form the complete modular-account stack.

## What's in the SNIP

- **Part A**: `ISigner` trait (3 methods).
- **Part B**: canonical kind-tag registry (Tier 1: STARK, SECP256K1, ED25519, P256, RSA_2048, BLS12_381; Tier 2: WEBAUTHN_P256, EIP191_SECP256K1, EIP712_SECP256K1, DKIM_RSA, JWT_RS256, JWT_ES256; Tier 3 reserved: ZK_JWT, ZK_EMAIL, ZK_TOTP).
- **Part C**: signature envelope format `[kind_tag, payload...]` — paymasters dispatch without off-chain negotiation.
- **Part D**: SNIP-9 V2 integration (SNIP-12 typed data as the primary hash).
- **Part E**: address-salt binding (`poseidon(primary_kind, primary_pubkey_hash)`) prevents cross-kind collisions.
- **Part F**: component architecture.
- **Part G**: SRC-5 discovery.

Non-normative exclusions: TOTP, SMS, passwords — documented as "authentication methods that need a ZK envelope to become signers."

## Reference implementation

[`haycarlitos/shhh-wallet-cairo`](https://github.com/haycarlitos/shhh-wallet-cairo) on branch `v8-robust` at commit **`6c30576`** ships the full implementation:

- Four verifier classes (Ed25519, Secp256k1, WebAuthn P-256, STARK) dispatched by the account via `library_call_syscall`
- Multi-owner storage, deterministic addresses, timelocked governance, guardian recovery, sessions-wallet migration
- All 12 audit findings closed with tested regressions
- 104 tests passing · 8/10 mutation-harness mutants killed · 1792 fuzz sweeps

Cross-language fixtures use `@noble/ed25519`, `ethers.js`, and `@noble/curves` signing one canonical SNIP-12 hash — one hash, four curves, one audit story.

## Test plan

- [x] `scarb build` green on Scarb 2.14 / Cairo 2.14 / Sierra 1.7
- [x] `scarb fmt --check` clean
- [x] `snforge test` — 104 passed, 0 failed
- [x] `bash scripts/mutation-test.sh` — 8/10 mutants killed, 2 documented gaps
- [x] Cross-language hash vector verified (Cairo output matches TypeScript for the same OutsideExecution fixture)
- [x] Deterministic address: same key under two different kinds produces two different addresses
- [x] End-to-end OE flow: Phantom signs → paymaster submits → library_call verify → atomic multicall executes target
- [ ] Community review on community.starknet.io forum thread (post pending)

## Linked discussion

- Forum thread: https://community.starknet.io/t/snip-pluggable-signer-interface (discussions-to link in the SNIP frontmatter)
- Audit report that motivated this SNIP: https://gist.github.com/omarespejel/dddcc2b7df4e8b8bb47af9d1936f8a3e

## Authors

- Carlos Castillo ([@haycarlitos](https://github.com/haycarlitos))
- Omar Espejel ([@omarespejel](https://github.com/omarespejel)) — co-author by virtue of the audit that catalyzed this SNIP; also co-author on the Session Keys SNIP that this one stacks on.

## Acknowledgments

- **Henri** — collaborator on `haycarlitos/shhh-wallet-cairo`. Ran the Nethermind AuditAgent scan on the V7 commit range (`70eeef3...f83ed1d4`) on 2026-04-13, one week before Omar's human review. His three findings (unrestricted `__execute__`, non-atomic multicall, dead upgrade component) were the first external signal that the authorization layer had structural issues and triggered the decision to ship V8 as a rewrite rather than a V7 patch. Per the Nethermind AuditAgent license this is a credit to Henri as the collaborator who ran and triaged the scan, not a claim that the code is "audited by Nethermind."

## Status

Draft — open to changes from the community review. Not finalized until the reference implementation completes an independent audit (planned Phase 13–14 on the reference repo).
