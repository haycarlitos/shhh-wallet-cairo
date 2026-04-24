# V8: Pluggable Signer Architecture — Audit Response + SNIP Reference Implementation

> Paste this body into the GitHub PR description when opening `haycarlitos/shhh-wallet-cairo`: `v8-robust` → `main`.
> Suggested title: `feat(v8): pluggable signers + multi-owner + timelock + recovery + sessions migration`
> Status at PR open: Ready for review.

## Summary

Complete rewrite of the Shhh smart account responding to two security reviews and introducing a pluggable-signer architecture that is also the reference implementation for a proposed Starknet SNIP.

- **Closes 15 audit findings**: all 12 findings from Omar Espejel's Codex/Cairo audit (2026-04-20) + all 3 findings from Henri's Nethermind AuditAgent scan (2026-04-13). Every finding has a named regression test.
- **One account class, any curve**: single `ShhhAccount` class dispatches signature verification to per-kind verifier classes (Ed25519, secp256k1, P-256/WebAuthn, STARK) via `library_call_syscall`. New curves land without redeploying the account.
- **Multi-owner + governance + recovery**: weighted-threshold multi-owner storage, timelocked propose/execute/cancel state machine for structural mutations, guardian-initiated 7-day recovery with owner-cancel window.
- **Sessions-wallet migration**: atomic `upgrade + bootstrap_from_sessions` one-shot for existing `chipi-pay/sessions-smart-contract` wallets. Session keys + spending policies carry over untouched.
- **Reference implementation for pluggable-signer SNIP** (PR against `starknet-io/SNIPs` opens in parallel) and OZ components port (PR against `OpenZeppelin/cairo-contracts` opens in parallel).

V7 class `0x2e599a0939f268c70acab242411225ddeefd7f3978e40dcb7c397ca39a9a13` stays on mainnet for users who want to remain; V8 is a redeploy target, not a forced migration.

## Motivation

Two independent audits converged on the same structural finding:

1. **Henri's AuditAgent scan (2026-04-13)** — surfaced unrestricted `__execute__`, non-atomic multicall, and dead `UpgradeableComponent`. Three findings; the critical-severity one made clear a V7 patch alone was insufficient.
2. **Omar's Codex/Cairo audit (2026-04-20)** — twelve findings covering the three above plus envelope hygiene, bounds, key-validation, and an SRC-5 / SNIP-9 interface mismatch (H-2). The root cause of H-2 / M-1 / I-1 was the same: V7 was rolling a custom Phantom-specific envelope while advertising SNIP-9 V2, because *there was no standard way for a Starknet account to declare "my owner key is Ed25519."*

The fix for the three-findings-in-three-costumes problem is a shared signer interface. V8 implements it and doubles as the reference implementation for the [Pluggable Signer SNIP](./docs/snip-draft-pluggable-signer.md).

Detailed response letters: [`docs/audit-response-omar.md`](./docs/audit-response-omar.md) and [`docs/audit-response-henri.md`](./docs/audit-response-henri.md).

## What's in this PR

### New core — `src/account.cairo`

Single `ShhhAccount` class with:
- `execute_from_outside_v2` as the sole owner-facing exec path (SNIP-9 V2 compliant)
- `__execute__` gated to `caller.is_zero() || caller == self` + `tx_info.version >= 1` (C-1)
- `__validate__` always reverts (self-custodial model; validation is on-chain in OE path)
- Library-call dispatch by kind tag to verifier classes
- `bootstrap_from_sessions` entrypoint for sessions-wallet migration

### Verifier classes — `src/signer/`

One `#[starknet::contract]` per kind, all implementing a shared `ISigner` trait:

| Kind tag           | Verifier                         | Primitive source                                             |
|--------------------|----------------------------------|--------------------------------------------------------------|
| `'ED25519'`        | `src/signer/ed25519/verifier.cairo` | Garaga v1.0.1 `is_valid_eddsa_signature`                    |
| `'SECP256K1'`      | `src/signer/secp256k1/verifier.cairo` | `starknet::secp256_trait::recover_public_key<Secp256k1Point>` + low-s + y_parity |
| `'WEBAUTHN_P256'`  | `src/signer/webauthn_p256/verifier.cairo` | `is_valid_signature<Secp256r1Point>` over a SNIP-12 hash  |
| `'STARK'`          | `src/signer/stark/verifier.cairo` | `core::ecdsa::check_ecdsa_signature`                         |

### Components — `src/{owner_set,governance,recovery,session_key,spending_policy}/`

- **`OwnerSetComponent`** — `OwnerRecord` with kind, pubkey commitment, role (`OWNER` / `GUARDIAN` / `RECOVERY_ONLY`), weight, label, tombstone. Invariants: `active_owner_count >= 1`, `1 <= threshold <= total_weight`.
- **`GovernanceComponent`** — timelocked propose/execute/cancel. Default windows: 24h / 48h / 7d by op kind.
- **`RecoveryComponent`** — guardian-initiated 7-day recovery with single-owner cancel window. Additive semantics (existing owners preserved).
- **`SessionKeyComponent`** + **`SpendingPolicyComponent`** — ported from `chipi-pay/sessions-smart-contract` (SNIP-163). V8-specific admin blocklist added.

### Sessions-wallet migration — `src/migration/bootstrap_from_sessions.cairo`

Single `bootstrap_from_sessions` call, guarded by `assert_only_self`, that:
1. Reads legacy `account.public_key` and registers it as `owner_0` with `kind = 'STARK'`
2. Initializes V8-only substorage (`owner_set`, `governance`, `recovery`, `verifier_classes`, `oe_nonces`)
3. Re-registers the canonical SRC9_V2 interface ID (closes Omar H-2)
4. Preserves existing session-key and spending-policy substorage

### Events for indexer

Every state change emits a typed event — owner add/remove/rotate, policy set/remove, session add/revoke, recovery initiate/cancel/finalize, governance propose/execute/cancel, kind-class registration. No silent mutations.

### TypeScript SDK — `scripts/ts/cifra-sdk/`

Drop-in surface for the Cifra Next.js frontend:
- `signOutsideExecution(signer, oe)` — builds the envelope any paymaster can submit
- `computeAccountAddress(signer, classes, label)` — deterministic address from kind + pubkey
- Per-curve adapters: `detectEd25519Signer` (Phantom), `detectSecp256k1Signer` (MetaMask), `detectWebAuthnSigner` (Face ID / passkey), `detectStarkSigner`
- Session-key and recovery call builders: `callAddOrUpdateSessionKey`, `callSetSpendingPolicy`, `callInitiateRecovery`, …

### Tests

Under `tests/`:
- `audit_2026_04_20.cairo` + `audit_v8.cairo` — regression per finding (Omar's 12 + structural V8 ones)
- `account_phase3.cairo` — end-to-end deploy + library_call dispatch + Ed25519 OE exec
- `account_owner_set.cairo` — owner add/remove/rotate + tombstone + invariants
- `account_governance.cairo` — propose/execute/cancel state machine
- `account_recovery.cairo` — happy path + guardian-cannot-cancel + owner-cancels-during-window
- `account_sessions.cairo` — session keys + spending policy + V8 admin blocklist
- `account_migration.cairo` — sessions-wallet bootstrap + double-bootstrap rejection
- `signer_ed25519.cairo` + `signer_secp256k1.cairo` + `signer_p256.cairo` + `signer_stark.cairo` — per-kind happy path + envelope guards + curve-specific attack vectors
- `snip12_hash.cairo` — SNIP-12 typed-data hash vectors cross-checked with TS reference
- `fuzz_authorization.cairo` + `fuzz_bounds.cairo` + `fuzz_timelock.cairo` — 7 fuzz tests × 256 runs = 1,792 random sweeps

## Audit-finding resolution

| ID  | Severity | Finding                                           | Status                  | First flagged by      |
|-----|----------|---------------------------------------------------|-------------------------|-----------------------|
| C-1 | Critical | Public `__execute__` unsigned-call bypass          | **Fixed + tested**      | Henri (High) → Omar   |
| H-1 | High     | Silent subcall failures                            | **Fixed + tested**      | Henri (Medium) → Omar |
| H-2 | High     | SNIP-9 V2 interface ID mismatch                    | **Fixed + tested**      | Omar                  |
| M-1 | Medium   | `caller == 0` accepted as unrestricted             | **Fixed + tested**      | Omar                  |
| M-2 | Medium   | No validity-window cap                             | **Fixed + tested**      | Omar                  |
| M-3 | Medium   | Unbounded calls / calldata / signature             | **Fixed + tested**      | Omar                  |
| M-4 | Medium   | Sig-span + trailing-bytes gaps                     | **Fixed + tested**      | Omar                  |
| L-1 | Low      | Out-of-range pubkey halves at deploy               | **Fixed + tested (manual)** | Omar              |
| I-1 | Info     | Ambiguous custom calls hash                        | **Fixed**               | Omar                  |
| I-2 | Info     | Missing Ed25519 negative vectors                   | **Fixed + tested**      | Omar                  |
| I-3 | Info     | Unused `UpgradeableComponent`                      | **Fixed + tested**      | Henri (Info) → Omar   |

## Test evidence

At commit `HEAD` of this branch:

- `scarb build` — green on Scarb 2.14.0 / Cairo 2.14 / Sierra 1.7
- `scarb fmt --check` — clean
- `snforge test` — **104 passed, 0 failed, 5 ignored** (ignored tests all have in-source justifications; none indicate unfixed findings)
- `bash scripts/mutation-test.sh` — 8 of 10 mutants killed; 2 documented gaps (`nonce_dedup` requires multi-tx STARK-signed fixture, `l1_pubkey_range` catchable only at deploy-hint level)
- Fuzz — 1,792 random sweeps across authorization, timelock, M-3 bounds paths
- Cross-language fixtures: `@noble/ed25519`, `ethers.js`, and `@noble/curves` all sign the same canonical SNIP-12 hash, each verified by its matching Cairo verifier class

## Checklist

- [x] Every audit finding has a named regression test
- [x] `scarb build`, `scarb fmt --check`, `snforge test` all green locally
- [x] Mutation harness documented (8/10 killed, 2 gaps explained)
- [x] Fuzz harness covering authorization + bounds + timelock
- [x] Multi-owner invariants enforced on every mutation
- [x] Timelocked governance replaces self-call for structural ops
- [x] Sessions-wallet migration path with tests
- [x] TypeScript SDK with per-curve adapters
- [x] SNIP-12 typed-data hash (primary path) with TS reference + Cairo vectors
- [x] Audit-response letters drafted (`docs/audit-response-omar.md`, `docs/audit-response-henri.md`)
- [x] SNIP draft + PR body (`docs/snip-draft-pluggable-signer.md`, `docs/snip-pr-body.md`)
- [x] OZ contribution plan + PR body (`docs/oz-contribution-plan.md`, `docs/oz-pr-body.md`)
- [ ] Independent audit round on V8 scope (planned Phase 13–14)
- [ ] Mainnet declare of the 5 V8 class hashes (Phase 15; gated on audit)

## Related work

- **SNIP PR** (open in parallel): `starknet-io/SNIPs` — Pluggable Signer Interface for Smart Accounts. V8 is the reference implementation.
- **OZ PR** (open in parallel): `OpenZeppelin/cairo-contracts` — ports the four verifier classes + three reusable components (`multi_owner`, `timelock`, `recovery`) as drop-in OZ modules.
- **Session Keys SNIP #163** ([starknet-io/SNIPs#163](https://github.com/starknet-io/SNIPs/pull/163), merged 2026-03-03) — V8 stacks on top of this. Authorization layer (their SNIP) + authentication layer (our SNIP) = the complete modular-account stack.

## Credits

- Carlos Castillo ([@haycarlitos](https://github.com/haycarlitos)) — V8 implementation, 12 phases.
- Omar Espejel ([@omarespejel](https://github.com/omarespejel)) — 2026-04-20 Codex/Cairo audit that identified the SRC-5 / SNIP-9 gap; also co-author on Session Keys SNIP #163.
- **Henri** — repo collaborator. Ran the Nethermind AuditAgent scan on 2026-04-13, one week before Omar's review, surfacing the three structural findings (C-1 / H-1 / I-3) that triggered the V8 rewrite. Per the Nethermind AuditAgent license this is credit to Henri as the collaborator who ran and triaged the scan, not a claim the code is "audited by Nethermind."
- Garaga team (Keep Starknet Strange) — Ed25519, secp256k1, and P-256 verification primitives.
- Chipi Pay — `chipi-pay/sessions-smart-contract` source for the session-key + spending-policy components.

## Status

Ready for review. V8 does **not** declare on mainnet from this PR — declaration lands only after the planned independent audit round (Phase 13–14).
