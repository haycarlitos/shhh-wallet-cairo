# Shhh Wallet — Cairo

> **Status:** Active work on V8 (branch `v8-robust`). V7 is production on mainnet class hash `0x2e599a0939f268c70acab242411225ddeefd7f3978e40dcb7c397ca39a9a13` and remains the reference for the current Phantom-only wallet. V8 generalizes it into a multi-signer, multi-curve, recoverable account and is the reference implementation for a proposed pluggable-signer SNIP.

## Versions

| Version | Branch | Scope | Production? |
|---------|--------|-------|-------------|
| V7      | `main` | Phantom-only (Ed25519) self-custodial wallet, SNIP-9 V2, Garaga Ed25519 | ✅ Mainnet |
| V8      | `v8-robust` | Multi-signer (Ed25519 / secp256k1 / P-256 / WebAuthn / STARK), session keys, social recovery, all fixes for the 2026-04-20 audit | 🚧 In progress |

## V8 — What's new

V8 is a single account class that verifies signatures from any major wallet or device through a pluggable-verifier architecture. One address per user for life. Signers can be added, rotated, or recovered without migrating the account.

Core capabilities:

- **One class hash, any curve.** Verifier components (Ed25519, secp256k1, WebAuthn P-256, STARK) are separately declared classes; the account dispatches to the right one via `library_call_syscall`. New curves land later by ratifying a new class hash into the account's verifier registry — no account redeployment.
- **Multi-signer per account.** Weighted owner set with a threshold, `add/remove/rotate_owner` through timelocked governance.
- **Social recovery.** Guardian-initiated with a 7-day timelock, single-owner cancel during the window.
- **Session keys + spending policies** ported from [starknet-io/SNIPs#163](https://github.com/starknet-io/SNIPs/pull/163) (merged 2026-03-03, `SNIPS/snip-x.md`).
- **SNIP-9 V2 compliance via SNIP-12 typed data.** Fixes audit H-2 at the spec level.
- **Atomic multicall, bounded inputs, caller-gated `__execute__`.** Closes every remaining audit finding.
- **Immutable.** No `UpgradeableComponent`. Changes happen via recovery or redeploy, never in-place.

## Audit response + SNIP proposal

This branch is the combined response to:

1. The [2026-04-20 Codex/Cairo security audit](./docs/audit-response-omar.md) (Omar Espejel). Every finding — C-1 / H-1 / H-2 / M-1..4 / L-1 / I-1..3 — is addressed and tracked by a dedicated regression file in [`tests/audit_2026_04_20/`](./tests/audit_2026_04_20/).
2. A proposed SNIP for pluggable signers on Starknet smart accounts: [`docs/snip-draft-pluggable-signer.md`](./docs/snip-draft-pluggable-signer.md). V8 is the reference implementation. The SNIP layers on top of the already-merged Session Keys SNIP — authorization (session keys) was standardized by #163; this SNIP standardizes authentication (which curve the owner key is on and how to verify it). Together the two SNIPs cover roughly 99% of the signing surface area humans use in 2026 (MetaMask, Phantom, passkeys, Google / Apple OAuth, YubiKey, validator keys).

### Audit-finding → regression-test map

| ID  | Finding                                                       | Test file                                                  |
|-----|---------------------------------------------------------------|------------------------------------------------------------|
| C-1 | Public `__execute__` allowed unsigned calls                    | [`c1_execute_caller_check.cairo`](./tests/audit_2026_04_20/c1_execute_caller_check.cairo) |
| H-1 | Silent subcall failures                                        | [`h1_atomic_multicall.cairo`](./tests/audit_2026_04_20/h1_atomic_multicall.cairo) |
| H-2 | SNIP-9 V2 interface ID / semantics mismatch                    | [`h2_snip9_interface_id.cairo`](./tests/audit_2026_04_20/h2_snip9_interface_id.cairo) |
| M-1 | `caller == 0` accepted as unrestricted                         | [`m1_any_caller_sentinel.cairo`](./tests/audit_2026_04_20/m1_any_caller_sentinel.cairo) |
| M-2 | No validity-window cap                                         | [`m2_validity_window_cap.cairo`](./tests/audit_2026_04_20/m2_validity_window_cap.cairo) |
| M-3 | Unbounded calls / calldata / signature                         | [`m3_bounds_calls_calldata_sig.cairo`](./tests/audit_2026_04_20/m3_bounds_calls_calldata_sig.cairo) |
| M-4 | Signature envelope + trailing-data gaps                        | [`m4_signature_envelope_bounds.cairo`](./tests/audit_2026_04_20/m4_signature_envelope_bounds.cairo) |
| L-1 | Out-of-range pubkey halves accepted in constructor             | [`l1_pubkey_range_check.cairo`](./tests/audit_2026_04_20/l1_pubkey_range_check.cairo) |
| I-1 | Custom calls hash replaced by SNIP-12 typed data               | [`i1_custom_hash_removed.cairo`](./tests/audit_2026_04_20/i1_custom_hash_removed.cairo) |
| I-2 | Missing Ed25519 negative vectors                               | [`i2_ed25519_negative_vectors.cairo`](./tests/audit_2026_04_20/i2_ed25519_negative_vectors.cairo) |
| I-3 | Unused `UpgradeableComponent` removed                           | [`i3_no_upgradeable_component.cairo`](./tests/audit_2026_04_20/i3_no_upgradeable_component.cairo) |
| —   | `snforge_std` pinned to v0.56.0                                 | [`toolchain_snforge_pinned.cairo`](./tests/audit_2026_04_20/toolchain_snforge_pinned.cairo) |

CI runs `snforge test --filter audit_2026_04_20` as a dedicated gate.

## Architecture (V8)

```
                          ┌──────────────────────────────────┐
                          │       ShhhAccount (1 class)      │
                          │                                  │
                          │   owners, verifier_classes,      │
                          │   governance, recovery, sessions │
                          └─────────────────┬────────────────┘
                                            │  library_call_syscall
          ┌─────────────┬────────────┬──────┴──────┬────────────┐
          ▼             ▼            ▼             ▼            ▼
     ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌───────┐   (future kinds:
     │Ed25519  │  │Secp256k1 │  │WebAuthn  │  │STARK  │    RSA, BLS,
     │verifier │  │verifier  │  │P256 ver. │  │ver.   │    ZK_JWT, ...)
     │ class   │  │ class    │  │ class    │  │ class │
     └─────────┘  └──────────┘  └──────────┘  └───────┘
```

Source layout:

```
src/
├── lib.cairo                       # module tree for V7 + V8
├── account.cairo                   # V8 main contract skeleton
├── signer/
│   ├── interface.cairo             # ISigner trait + kind-tag registry
│   ├── ed25519/verifier.cairo
│   ├── secp256k1/verifier.cairo
│   ├── webauthn_p256/verifier.cairo
│   └── stark/verifier.cairo
├── owner_set/                      # multi-signer storage + invariants
├── governance/                     # timelocked pending-ops engine
├── recovery/                       # guardian + 7d recovery window
├── session_key/                    # ported from chipi-pay/sessions-smart-contract
├── spending_policy/                # ported from chipi-pay/sessions-smart-contract
│
├── wallet.cairo                    # V7 retained for reference
├── outside_execution.cairo         # V7 retained for reference
└── ed25519/                        # V7 retained for reference

tests/
├── audit_2026_04_20/               # one regression file per audit finding
├── signer/                         # per-verifier-class tests (valid + negative)
├── owner_set/                      # owner-set invariant + threshold tests
├── recovery/                       # recovery state-machine tests
└── test_contract.cairo             # V7 suite (9/9 passing)
```

## Docs

- [`docs/shhh-v8-robust-plan.md`](./docs/shhh-v8-robust-plan.md) — build plan, 12-week milestones, security model.
- [`docs/snip-draft-pluggable-signer.md`](./docs/snip-draft-pluggable-signer.md) — SNIP draft, ready to open against `starknet-io/SNIPs`.
- [`docs/audit-response-omar.md`](./docs/audit-response-omar.md) — letter to Omar documenting every finding's disposition.
- [`docs/shhh-v8-design.md`](./docs/shhh-v8-design.md) — earlier phased-V8 design, superseded by the robust plan but kept for context.

## Build & test

```bash
scarb build                               # compiles V7 + V8 skeleton
scarb fmt --check
snforge test                              # V7 suite + V8 stubs
snforge test --filter audit_2026_04_20    # audit regressions only
```

V8 is currently a skeleton: the ISigner trait, owner-set, governance, recovery, session-key, and spending-policy components compile; the four verifier classes and the main account's `execute_from_outside_v2` body are TODO-tagged for implementation. See `docs/shhh-v8-robust-plan.md` §9 for the week-by-week implementation track.

## License

MIT
