# Shhh Wallet — Cairo

> **Status:** **V8.3 live on Starknet mainnet** since 2026-05-11. 14 V8.x classes declared between 2026-04-28 and 2026-05-11 (~283 STRK cumulative declare cost). Active for new deploys: V8.3 `ShhhAccount` plus 10 V8.2 verifier classes. V8.0 / V8.1 / V8.2 `ShhhAccount` remain declared for legacy recognition only and are deprecated. V7 stays on mainnet for legacy users; V8.3 is the redeploy target for new accounts. Reference implementation for the upcoming **SNIP-108 Pluggable Signer Interface** ([draft](./docs/snip-draft-pluggable-signer.md), companion to merged Session Keys SNIP #163).

Pluggable-signer Starknet smart account: one account class authenticates owners signing under any of ten cryptographic primitives — STARK, Ed25519 (Phantom / Solana), secp256k1 raw, EIP-191 `personal_sign`, EIP-712 typed data, raw P-256, WebAuthn P-256 (Face ID / Touch ID), JWT-ES256 single-tenant Apple, JWT-ES256 sub-bound multi-tenant Apple, BLS12-381 min-sig — via `library_call_syscall` dispatch to separately-declared verifier classes. Multi-owner weighted threshold, timelocked governance, 7-day guardian recovery, and SNIP-163 session keys with spending caps stack on top.

## Versions

| Version | Status | Class hash | Notes |
|---|---|---|---|
| V7 | ✅ Mainnet (legacy, in-place patched) | `0x2e599a0939f268c70acab242411225ddeefd7f3978e40dcb7c397ca39a9a13` | Ed25519-only, single-owner. Audit-closed at the V7 commit. Existing users may stay. |
| V8.0 | ⚠️ Deprecated (2026-05-07) | `0x01d6e475…ae3` | Pre-2026-05-07 self-review. Vulnerable to C-1 (guardian role bypass) + H-1 (bootstrap front-run). |
| V8.1 | ⚠️ Deprecated (2026-05-10) | `0x01e7f69e…f363b5` | Pre-V8.2; `ISigner` trait missing `validate_pubkey` (M-1 partial only). |
| V8.2 | ⚠️ Deprecated (2026-05-11) | `0x02a0b719…1a062` | Pre-2026-05-10 audit closeout; missing `finalize_recovery` validate, asymmetric `inside_verifier`, `bootstrap_from_sessions` validate. |
| **V8.3** | ✅ **Mainnet (current)** | **`0x03bc539295abd3e59bd9ea799d12fe3331748d484bc77bff45b302b1636a87d9`** | Audit-closed against the 2026-05-10 V8.2 review (H-1, M-1 symmetric, M-2, M-3 executable). |

Existing V8.0 / V8.1 / V8.2 wallets **cannot self-upgrade** to V8.3 — V8 deliberately ships without an `upgrade` selector. Migrating from a deprecated class requires deploying a fresh V8.3 account at a new address (the class hash is bound into the deterministic salt) and migrating assets manually.

## V8.3 mainnet classes (pin these in your SDK)

Active set: V8.3 `ShhhAccount` plus 10 V8.2 verifier classes. Full deploy record (per-tx hashes, fees, Voyager links, declare cycles): [`docs/class-hashes.md`](./docs/class-hashes.md). Per-tx + per-user-op cost map: [`docs/mainnet-deployment.md`](./docs/mainnet-deployment.md).

| Contract | Class hash | Wallets / use case |
|---|---|---|
| `ShhhAccount` (V8.3) | `0x03bc539295abd3e59bd9ea799d12fe3331748d484bc77bff45b302b1636a87d9` | The account contract |
| `StarkVerifier` (V8.2) | `0x00d09209b2da9d49fc805ba26380ba4ce25aa641116c10eb178e1051a71dbf68` | Ready, Braavos, Ledger Starknet app, native |
| `Ed25519Verifier` (V8.2) | `0x030a7dfc03e59cef6e41699e734abd2df53ce393a052221c02c6e07665949f74` | Phantom, Solflare, every Solana wallet |
| `Secp256k1Verifier` (V8.2) | `0x03e81667a46bd5287e09a9600fa98d28fdc477735f2689f5f4e8e95f37b67b74` | Raw secp256k1 (programmatic / hardware) |
| `EIP191Secp256k1Verifier` (V8.2) | `0x03a75997862059c36cb8e204fb3027eb6d1fdf933488d42c2db4528118d084e6` | MetaMask `personal_sign`, Rabby, every EVM wallet |
| `EIP712Secp256k1Verifier` (V8.2) | `0x072a3f77e8c28bfea2ade91ec3fb83b6290169d1ed8c1b2396704231841c6474` | MetaMask `eth_signTypedData_v4` structured popup |
| `P256Verifier` (V8.2) | `0x01b600709af54c8838e5f18ddad3a26feeb47cb124c239f55a0f1b7a780e2d8a` | PIV smart cards, eIDAS, Apple DeviceCheck |
| `WebAuthnP256Verifier` (V8.2) | `0x074f6efd2af9025cd8cab41a4565bc73b6ef097214c31352838fcdbac0a44657` | Apple passkeys, Touch ID, Face ID, YubiKey FIDO2 |
| `JwtES256AppleVerifier` (V8.2) | `0x002efce875fa3e73e04d825d8ebade53e188cc995dfe0c55a6a2f7fa6c59f497` | "Sign in with Apple" — single-tenant (Apple key per user) |
| `JwtES256AppleSubVerifier` (V8.2) | `0x06b67762218a25fdd28e25b063480893a5cef9cdeecbc663e32d444d5734c471` | "Sign in with Apple" — multi-tenant (one Apple key, sub-bound) |
| `Bls12_381MinSigVerifier` (V8.2) | `0x02623721e74a9ad3e0ba639065f5631a09bf900913de6ab21ea6984973cd2cd1` | BLS12-381 min-sig-size (drand DST) — validator multisigs, DAO keys, backend signers |

## What V8.3 does

- **One class hash, any curve.** Owner key can be on any of the ten supported primitives. Adding a new curve declares one new verifier class and registers it through governance — no account redeployment, no fresh address derivation.
- **Stateless verifier classes.** Pubkey material passed in on every `verify` call; verifier classes hold no storage of their own and are independently auditable.
- **`ISigner` V1 trait, three methods**: `verify(message_hash, pubkey, signature)`, `kind()`, `validate_pubkey(pubkey)`. The last is called at every owner-registration site (`execute_add_owner`, `execute_rotate_owner`, `finalize_recovery`, `bootstrap_from_sessions`) before the owner record commits, so an off-curve pubkey cannot poison the multi-owner / threshold flows (audit M-1, full closure in V8.2 + V8.3 wiring).
- **Multi-owner with weighted threshold.** Each owner has a kind, weight, role (`ROLE_OWNER` / `ROLE_GUARDIAN` / `ROLE_RECOVERY_ONLY`), and label. Lifecycle ops (`add_owner` / `remove_owner` / `rotate_owner_pubkey` / `set_threshold`) go through a timelocked propose → wait → execute / cancel flow.
- **Threshold-signature envelopes.** N-of-M owners with mixed kinds across owners can sign a single OE; the account verifies each inner envelope, rejects duplicate `owner_id`, and requires `sum(weights) >= threshold`.
- **Guardian recovery.** 7-day timelocked initiate / cancel / finalize flow. Single-owner cancel during the window. Additive — `finalize_recovery` does not remove existing owners. Guardians can be any kind; cross-ecosystem guardians (laptop MetaMask, watch passkey, family member's Phantom) are supported by design.
- **Sessions-wallet migration.** Existing `chipi-pay/sessions-smart-contract` users upgrade with one atomic OE multicall: `[upgrade(V8.3_class_hash), bootstrap_from_sessions(pubkey, stark_verifier_class, label)]`. Session keys + spending-policy substorage carry over verbatim (V8.3's components are ported from SNIP #163).
- **Session keys + spending policies** from [SNIP #163](https://github.com/starknet-io/SNIPs/pull/163), with a V8-specific blocklist on 17 admin selectors so session keys cannot reach governance / recovery / migration mutators.
- **SNIP-9 V2 compliance via SNIP-12 typed data.** Closes audit H-2 from the 2026-04-20 review.
- **Verifier-class governance rotation.** `add_verifier_class` / `remove_verifier_class` go through a 48h timelock with unanimous-owner approval. A vulnerability in a single curve's verifier is fixed by declaring a patched class and proposing the rotation — existing accounts pick up the fix on their next signature without redeploying.
- **Reentrancy-safe library_call dispatch.** Every `library_call → verify` and `library_call → validate_pubkey` is wrapped with the `inside_verifier` flag (symmetric closure in V8.3); the flag rejects any self-call mutator attempted from inside a verifier-class execution context (audit M-1 / M-2, 2026-05-07 + 2026-05-10 reviews).

## Audience-by-audience: what this unlocks

See [`docs/ecosystem-impact.md`](./docs/ecosystem-impact.md) for concrete UX flows, dev-integration shortcuts, and ecosystem benefits. Headline:

- Phantom, MetaMask, Apple passkey, and Sign-in-with-Apple users sign Starknet transactions in their existing wallet popup with **no install, no chain switch, no seed phrase**.
- One paymaster integration sponsors every wallet kind because the curve check happens on chain. Per-kind gas overhead documented in [`docs/v8-3-sdk-integration.md`](./docs/v8-3-sdk-integration.md) §4 (range ~12M l2_gas for STARK to ~80M for BLS12-381; every kind is in the range a paymaster can absorb).
- Free CCTP USDC migration from Solana / Ethereum into a V8.3 wallet (combined with a relayer on the source chain).
- AI-agent UX via session keys + per-token spending caps + auto-expiry.
- MPC-grade multi-device security without MPC infrastructure: multi-owner threshold across passkey + MetaMask + Phantom + email-recovery guardian survives any single device loss.

## Audit history

Three internal review cycles since the 2026-04-20 external audit; each surfaced new findings closed in the next mainnet redeclare. Full audit-trail in [`audits/`](./audits/) + [`audits/README.md`](./audits/README.md).

| Date | Reviewer | Scope | Findings | Closure |
|---|---|---|---|---|
| 2026-04-13 | Henri Lieutaud (Nethermind AuditAgent scan) | Shhh V7 | 3 structural (High / Medium / Info) | All closed in V8.0; [response letter](./docs/audit-response-henri.md) |
| 2026-04-20 | Omar Espejel (Codex/Cairo audit) | Shhh V7 | 12 findings (Critical / High×2 / Medium×4 / Low / Info×3); 3 traced to absence of the SNIP-108 standard | All closed in V8.0; [response letter](./docs/audit-response-omar.md) |
| 2026-05-07 | Internal self-review | V8.0 → V8.1 | 1 Critical + 3 High + 3 Medium + 1 Low + 6 Info | All closed in V8.1; [audit doc](./audits/2026-05-07-claude-opus-pre-phase13-review.md) |
| 2026-05-10 | Internal self-review | V8.1 → V8.2 | M-1 full (per-kind `validate_pubkey` on `ISigner` trait) | Closed in V8.2 (all 11 classes redeclared); [audit doc](./audits/2026-05-10-claude-opus-v8-2-review.md) |
| 2026-05-11 | Internal self-review | V8.2 → V8.3 | H-1 `finalize_recovery` validate, M-1 symmetric `inside_verifier`, M-2 `bootstrap_from_sessions` validate, M-3 executable negative tests via `EvilVerifier` helpers | Closed in V8.3 (account-class redeclare only; verifier hashes unchanged); [response letter](./docs/audit-response-2026-05-10.md) |

**Phase 13 external audit** (Omar round 2 / Zellic / Nethermind / OpenZeppelin Security Services) is scheduled as post-launch hardening. Mainnet promotion of `v8-robust` → `main` is gated on its closure. Until then `v8-robust` is the canonical V8 branch and `main` stays at V7.

## SNIP-108 (Pluggable Signer Interface)

This codebase is the reference implementation for **SNIP-108: Pluggable Signer Interface for Smart Accounts** ([draft](./docs/snip-draft-pluggable-signer.md)), the authentication-layer companion to the merged [Session Keys SNIP #163](https://github.com/starknet-io/SNIPs/pull/163). SNIP-108 defines:

- The 3-method `ISigner` Cairo trait
- A canonical kind-tag registry (Tier 1 primitives + Tier 2 envelope variants + Tier 3 reserved ZK kinds)
- Three signature envelope shapes (single-owner V2, threshold V2, session V1)
- A `library_call_syscall` dispatch architecture and verifier-class governance rotation

Submission process + lifecycle map: [`docs/snip-publish-process.md`](./docs/snip-publish-process.md). The forum thread will be the canonical `discussions-to` anchor for the entire SNIP lifecycle.

## Architecture

```
                          ┌──────────────────────────────────┐
                          │     ShhhAccount V8.3 (1 class)   │
                          │                                  │
                          │   owners, verifier_classes,      │
                          │   governance, recovery,          │
                          │   sessions + spending_policy     │
                          │   inside_verifier (M-2 flag)     │
                          └─────────────────┬────────────────┘
                                            │  library_call_syscall
   ┌──────┬─────────┬──────────┬──────────┬─┴──────┬──────┬──────────┬─────────┬──────────┬──────┐
   ▼      ▼         ▼          ▼          ▼        ▼      ▼          ▼         ▼          ▼      ▼
┌──────┐┌────────┐┌──────────┐┌────────┐┌────────┐┌────┐┌──────────┐┌────────┐┌──────────┐┌──────┐
│STARK ││Ed25519 ││Secp256k1 ││EIP-191 ││EIP-712 ││P256││WebAuthn  ││ JWT    ││ JWT      ││ BLS  │
│ ver. ││ ver.   ││ ver.     ││ ver.   ││ ver.   ││ver.││ P256 ver.││ ES256  ││ ES256    ││12-381│
│      ││        ││          ││        ││        ││    ││          ││ Apple  ││ Apple-sub││ ver. │
└──────┘└────────┘└──────────┘└────────┘└────────┘└────┘└──────────┘└────────┘└──────────┘└──────┘
   ^         ^                                                                                  ^
   │         │                                                                                  │
   │         └── client-side signing via @noble/ed25519 + garaga npm           server-side until │
   │                                                                              Garaga PR #519 │
   └── all 10 verifier classes V8.2 — declared 2026-05-10; trait-shape change forced fresh hashes
```

## Source layout

```
src/
├── lib.cairo                       # module tree
├── account.cairo                   # V8.3 main account contract
├── signer/
│   ├── interface.cairo             # ISigner trait + kind-tag registry + ISIGNER_ID
│   ├── stark/verifier.cairo
│   ├── ed25519/verifier.cairo
│   ├── secp256k1/verifier.cairo
│   ├── eip191_secp256k1/verifier.cairo
│   ├── eip712_secp256k1/verifier.cairo
│   ├── p256/verifier.cairo
│   ├── webauthn_p256/verifier.cairo
│   ├── jwt_es256/verifier.cairo
│   ├── jwt_es256_apple_sub/verifier.cairo
│   └── bls12_381/verifier.cairo
├── owner_set/                      # multi-owner storage + invariants
├── governance/                     # timelocked propose/execute/cancel
├── recovery/                       # guardian + 7d recovery
├── session_key/                    # ported from SNIP #163
├── spending_policy/                # ported from SNIP #163
├── test_helpers/
│   └── evil_verifier.cairo         # EvilReentrant/ReturnTrue/Panic test classes for M-1/M-2/M-3 negatives
├── wallet.cairo                    # V7 retained for reference
├── outside_execution.cairo         # OE encoding + SNIP-12 hash
└── ed25519/                        # V7 Ed25519 retained for reference

tests/
├── audit_2026_04_20.cairo          # regressions for Omar's 12 findings
├── audit_v8.cairo                  # V8 structural regressions (C-1, H-1..H-3, M-2, etc.)
├── audit_v8_3.cairo                # 2026-05-11 closeout (M-1 symmetric, M-2 bootstrap, M-3 evil verifiers)
├── account_*.cairo                 # phase-by-phase account tests
├── signer_*.cairo                  # per-verifier-class tests
├── interface_ids.cairo             # SRC-5 + Cairo↔TS parity
├── edge_cases.cairo                # boundary conditions
└── fuzz_*.cairo                    # 1,792 random sweeps across authorization, timelock, M-3 bounds
```

## Build & test

```bash
scarb --version          # 2.14.0
snforge --version        # 0.59.0

scarb build              # compiles V7 + V8.3
scarb fmt --check        # format gate
snforge test             # 242 passed, 0 failed, 0 ignored
python3 scripts/py/gen_bls_fixture.py        # regenerate the BLS fixture (browser path waits on Garaga PR #519)

bash scripts/mutation-test.sh                # 10/10 mutants killed, no documented gaps
node scripts/ts/check-interface-ids.mjs      # Cairo ↔ TS ↔ starknet_keccak parity
```

CI runs the same toolchain on every push and PR. See `.github/workflows/ci.yml`.

## Docs

- [`docs/ecosystem-impact.md`](./docs/ecosystem-impact.md) — what V8 unlocks for users / devs / Starknet ecosystem.
- [`docs/class-hashes.md`](./docs/class-hashes.md) — 14 declared V8.x classes with reproduction commands + per-cycle costs.
- [`docs/mainnet-deployment.md`](./docs/mainnet-deployment.md) — per-tx fees, per-user-operation cost map.
- [`docs/v8-3-sdk-integration.md`](./docs/v8-3-sdk-integration.md) — 1200+ line SDK integration spec (TypeScript constants, envelope builders per kind, OE construction, paymaster routing, error mapping).
- [`docs/v8-3-smoke-tests.md`](./docs/v8-3-smoke-tests.md) — mainnet smoke-test status (1 of 14 passed: STARK OE end-to-end; rest snforge-only).
- [`docs/v8-3-m1-history.md`](./docs/v8-3-m1-history.md) — design rationale for the M-1 closure (V8.1 partial → V8.2 full → V8.3 wiring).
- [`docs/snip-draft-pluggable-signer.md`](./docs/snip-draft-pluggable-signer.md) — SNIP-108 draft, V8.3 as reference implementation.
- [`docs/snip-publish-process.md`](./docs/snip-publish-process.md) — submission process + lifecycle map for SNIP-108.
- [`docs/upstream-garaga-bls-pr.md`](./docs/upstream-garaga-bls-pr.md) — upstream contribution back ([Garaga PR #519](https://github.com/keep-starknet-strange/garaga/pull/519)): `bls_calldata_builder` for in-browser BLS12-381 signing.
- [`docs/audit-response-omar.md`](./docs/audit-response-omar.md), [`docs/audit-response-henri.md`](./docs/audit-response-henri.md), [`docs/audit-response-2026-05-10.md`](./docs/audit-response-2026-05-10.md) — per-review response letters.

## License

MIT
