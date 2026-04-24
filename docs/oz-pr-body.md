# OZ Cairo Contracts PR — V8 Account Extensions

> Paste this body into the GitHub PR description when opening against `OpenZeppelin/cairo-contracts`.
> Suggested title: `feat(account): pluggable signers + multi-owner + timelock + recovery extensions`
> Status at PR open: Draft.

## Summary

Adds four new modules to `src/account/`:

1. **`verifiers/`** — Pluggable-signer verifier classes (Ed25519, secp256k1, P-256/WebAuthn, STARK) all implementing a shared `ISigner` trait. Account contracts dispatch to these via `library_call_syscall` by kind tag — one account class, any curve.
2. **`extensions/multi_owner/`** — Multi-owner storage with weighted threshold, roles (OWNER / GUARDIAN / RECOVERY_ONLY), tombstone-preserving removal.
3. **`extensions/timelock/`** — Timelocked propose/execute/cancel state machine for structural mutations. Generic over op_kind + payload-hash commitment.
4. **`extensions/recovery/`** — Guardian-initiated recovery with owner-cancel window and additive finalization. Uses `timelock` as its state backend.

## Motivation

Every team shipping a non-STARK-curve Starknet account (Argent, Braavos, Cartridge, Clave, Chipi, Shhh, Cartridge Controller, …) forks a reference implementation and writes curve-specific validation inline. The [April 2026 Shhh wallet audit](https://gist.github.com/omarespejel/dddcc2b7df4e8b8bb47af9d1936f8a3e) (finding H-2) identified this as the root cause of an SRC-5 / SNIP-9 interface mismatch: accounts advertised SNIP-9 V2 compliance but used custom envelopes, breaking dapp discovery.

A shared OZ module with one audited implementation per kind plus the three account extensions eliminates the fork tax. Session keys ([starknet-io/SNIPs#163](https://github.com/starknet-io/SNIPs/pull/163), merged 2026-03-03) already established the authorization layer; this PR lands the authentication layer.

Related SNIP proposal: [`Pluggable Signer Interface for Smart Accounts`](https://github.com/starknet-io/SNIPs/pull/NNN) (open separately). This OZ PR is the SNIP's reference implementation.

## What's in this PR

### New directory: `src/account/verifiers/`

- `interface.cairo` — `ISigner` trait with three methods (`verify`, `owner_commitment`, `signer_kind`) + canonical kind-tag registry (Tier 1: STARK, SECP256K1, ED25519, P256, RSA_2048, BLS12_381; Tier 2: WEBAUTHN_P256, EIP191_SECP256K1, EIP712_SECP256K1, DKIM_RSA, JWT_RS256, JWT_ES256).
- `stark.cairo` — wraps `core::ecdsa::check_ecdsa_signature`.
- `ed25519.cairo` — wraps Garaga v1.0.1 `is_valid_eddsa_signature`. Adds `garaga` as an optional feature dep.
- `secp256k1.cairo` — wraps `starknet::secp256_trait::recover_public_key<Secp256k1Point>` with y_parity recovery matching + low-s enforcement.
- `webauthn_p256.cairo` — wraps `is_valid_signature<Secp256r1Point>`. Full WebAuthn envelope (authenticatorData || sha256(clientDataJSON)) is a follow-up behind a separate kind tag.

### New directory: `src/account/extensions/multi_owner/`

- `interface.cairo` — `IOwnerSet` trait, `OwnerRecord` struct, role constants.
- `multi_owner.cairo` — component with add/remove/rotate/threshold operations, invariant checks (`active_owner_count >= 1`, `1 <= threshold <= total_weight`).

### New directory: `src/account/extensions/timelock/`

- `pending_ops.cairo` — `PendingOp` struct, op-kind constants, default timelock windows (24h / 48h / 7d).
- `timelock.cairo` — component with `propose`, `assert_ready`, `mark_executed`, `cancel`. Uses `poseidon(op_kind, payload, proposer, timestamp, counter)` for op_id derivation (collision-free even with concurrent proposals).

### New directory: `src/account/extensions/recovery/`

- `guardian_recovery.cairo` — component that pairs with `timelock` + `multi_owner`. `initiate_recovery` (guardian-gated) starts the 7-day window; `cancel_recovery` (single-owner) aborts; `finalize_recovery` (permissionless post-timelock) adds the new owner.

### Examples

- `examples/account_ed25519.cairo` — minimal account with ED25519 primary signer.
- `examples/account_multi_owner.cairo` — account embedding multi_owner + timelock.
- `examples/account_with_recovery.cairo` — full stack: multi_owner + timelock + recovery.

### Tests

Under `tests/account/`:
- `verifiers/stark_test.cairo`, `ed25519_test.cairo`, `secp256k1_test.cairo`, `webauthn_p256_test.cairo` — each with happy path + shape guards + attack scenarios.
- `extensions/multi_owner_test.cairo` — invariant sweep.
- `extensions/timelock_test.cairo` — state-machine test + propose/execute/cancel happy path + expiry + double-execute.
- `extensions/recovery_test.cairo` — happy path + guardian-collusion-with-owner-cancel + double-initiate.

All sourced from `haycarlitos/shhh-wallet-cairo@6c30576` with OZ-style docstring / naming / import conversion.

### Documentation

- `docs/modules/pages/account/verifiers.adoc`
- `docs/modules/pages/account/multi-owner.adoc`
- `docs/modules/pages/account/timelock.adoc`
- `docs/modules/pages/account/recovery.adoc`

## Test evidence from the reference implementation

At source commit `haycarlitos/shhh-wallet-cairo@6c30576`:

- `scarb build` green on Scarb 2.14
- `scarb fmt --check` clean
- `snforge test` — 104 passed, 0 failed, 5 ignored (documented)
- `bash scripts/mutation-test.sh` — 8 of 10 mutants killed, 2 documented gaps
- Fuzz — 7 tests × 256 runs = 1,792 random sweeps
- Cross-language fixture verification: `@noble/ed25519`, `ethers.js`, `@noble/curves` all produce signatures verified by the respective Cairo verifier

## Checklist

- [ ] `scarb build` green in OZ layout
- [ ] `scarb fmt --check` clean
- [ ] All verifier tests ported and passing
- [ ] All extension tests ported and passing
- [ ] Examples compile
- [ ] `docs/modules/pages/account/*.adoc` written
- [ ] `CHANGELOG.md` entry
- [ ] `Cargo.toml` / `Scarb.toml` dep: garaga as optional feature for Ed25519

## Questions for OZ maintainers

1. **Feature-gating Garaga** — Ed25519 is the only verifier needing Garaga (~200KB WASM in dev dependency). Should `verifiers/ed25519.cairo` sit behind a feature flag, or always build?
2. **Kind-tag freeze** — The canonical kind registry is Tier 1 (6) + Tier 2 (6). Adding new kinds requires a new SNIP amendment. Should OZ maintain the registry in parallel, or treat the SNIP as authoritative?
3. **Session-keys integration** — SNIP #163 session keys use 4-element signatures. Verifier kinds use tagged envelopes. OZ already has a `SRC9Component`; does the session-key + pluggable-signer integration belong in OZ's account extensions or in a follow-up PR?
4. **`WebAuthnP256Verifier` vs `P256Verifier`** — Reference impl currently wraps both into one class that accepts a pre-computed SNIP-12 hash. A full WebAuthn variant (with clientDataJSON parsing) is a follow-up. Should this PR ship two distinct kinds, or one unified class?

## Credits

- Carlos Castillo ([@haycarlitos](https://github.com/haycarlitos)) — reference implementation (V8 track, 11 phases from audit response to SNIP draft).
- Omar Espejel ([@omarespejel](https://github.com/omarespejel)) — Codex audit (2026-04-20) that identified the SRC-5 / SNIP-9 gap + Session Keys SNIP co-author.
- **Henri ([@l-henri](https://github.com/l-henri))** — collaborator on the Shhh project. Ran the Nethermind AuditAgent scan on 2026-04-13, one week before Omar's human review, surfacing the three structural findings (unrestricted `__execute__`, non-atomic multicall, dead upgrade component) that triggered the V8 rewrite. Per the Nethermind AuditAgent license this is a credit to Henri as the contributor who ran and triaged the scan — not a claim that the code is "audited by Nethermind."
- Garaga team (Keep Starknet Strange) — Ed25519 verification primitive.

## Status

Draft — open to maintainer review. Intended to land alongside the SNIP finalizing so that wallets can adopt from OZ directly instead of forking.
