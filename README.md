# Shhh Wallet — Cairo

> **Status:** V8 is **live on Starknet mainnet**. 8 classes declared (initial 6 on 2026-04-28, plus EIP-191 + EIP-712 secp256k1 verifiers on 2026-05-05). V7 stays on mainnet for legacy users; V8 is the redeploy target for new accounts.

Pluggable-signer Starknet smart account: one account class that verifies signatures from MetaMask, Phantom, Apple passkey, native Starknet wallets, and any future curve via separately-declared verifier classes. Cross-ecosystem recovery, multi-owner threshold, timelocked governance, session keys with spending caps.

## Versions

| Version | Branch       | Status                | Class hash                                                                  |
|---------|--------------|-----------------------|-----------------------------------------------------------------------------|
| V7      | `main`       | ✅ Mainnet (legacy)   | `0x2e599a0939f268c70acab242411225ddeefd7f3978e40dcb7c397ca39a9a13`         |
| V8      | `v8-robust`  | ✅ Mainnet (current)  | `0x01d6e475526c1f0dddafe47f944efa52cd1d8af273771c4bf171aeb65919eae3`         |

## V8 mainnet classes

Pin these in your SDK constants. Full deploy record (tx hashes, fees, Voyager links) in [`docs/mainnet-deployment.md`](./docs/mainnet-deployment.md).

| Contract                  | Class hash                                                                  | Wallets / use case                                       |
|---------------------------|-----------------------------------------------------------------------------|----------------------------------------------------------|
| `ShhhAccount`             | `0x01d6e475526c1f0dddafe47f944efa52cd1d8af273771c4bf171aeb65919eae3`        | The account contract                                     |
| `StarkVerifier`           | `0x06e671d2c70cf6d28ad18de864b82ffcbc60251b4dbcdb630ec17d4e1e43729b`        | Argent, Braavos, Ledger Starknet app                     |
| `Ed25519Verifier`         | `0x004f075cb1dbbafde78faaa037824cc327e3a038ecd4ff7b8e2aa4ef039b1774`        | Phantom, Solflare, every Solana wallet                   |
| `Secp256k1Verifier`       | `0x0473d8215659c5e91a8431557618f6664f698d16ba300d8d626027011391d8c6`        | Raw secp256k1 (programmatic / hardware)                  |
| `EIP191Secp256k1Verifier` | `0x025c6a15e84aae7a999b449b08dc37da5071319eb09eec935161090148821c7f`        | MetaMask `personal_sign`, Rabby, every EVM wallet        |
| `EIP712Secp256k1Verifier` | `0x0729a2303c20fb3ba8994809b9ae923301c7489a069ae7401fb13a55c9184b2b`        | MetaMask `eth_signTypedData_v4` structured popup         |
| `P256Verifier`            | `0x029693329bb6f061e15c470ce2b169120cacfab47af024897b5588026c857810`        | PIV smart cards, eIDAS, Apple DeviceCheck                |
| `WebAuthnP256Verifier`    | `0x078fd4ce33370699f44c221191ce0d8b7ccfccff77297f798dc7948b4201b9f4`        | Apple passkeys, Touch ID, Face ID, YubiKey FIDO2         |

## What V8 does

- **One class hash, any curve.** Owner key can be on any of the seven supported curves (Ed25519, secp256k1 raw / EIP-191 / EIP-712, P-256 raw / WebAuthn, STARK). Adding a new curve means declaring a new verifier class and registering it on the account — no account redeployment.
- **Multi-owner with weighted threshold.** Each owner has a kind, weight, role (OWNER / GUARDIAN / RECOVERY_ONLY), and label. `add_owner` / `remove_owner` / `rotate_owner_pubkey` / `set_threshold` go through a timelocked propose/execute/cancel flow.
- **Threshold-signature envelopes.** N-of-M owners can sign a single OE; the account verifies each inner envelope, rejects duplicate owner_ids, and requires `sum(weights) >= threshold`.
- **Cross-ecosystem recovery.** Guardian-initiated 7-day recovery with single-owner cancel window. A guardian can be any wallet from any ecosystem (laptop MetaMask, watch passkey, family member's Phantom). Additive: existing owners stay.
- **Session keys + spending policies** ported from [SNIP #163](https://github.com/starknet-io/SNIPs/pull/163), with a V8-specific blocklist on 17 admin selectors.
- **Sessions-wallet migration.** Existing `chipi-pay/sessions-smart-contract` users upgrade with one atomic call: `upgrade(V8_class_hash) + bootstrap_from_sessions(...)`.
- **SNIP-9 V2 compliance via SNIP-12 typed data.** Closes audit H-2.
- **Audit-trail-tested.** All 12 findings from Omar Espejel's 2026-04-20 audit + all 3 from Henri's 2026-04-13 AuditAgent scan have named regression tests. Two additional self-audit fixes (WebAuthn type-binding, reentrancy guard).

## Audience-by-audience: what this unlocks

See [`docs/ecosystem-impact.md`](./docs/ecosystem-impact.md) for concrete UX flows, dev-integration shortcuts, and ecosystem benefits. Headline:

- Phantom, MetaMask, Apple passkey users sign Starknet txs in their existing wallet popup with no install.
- One paymaster integration sponsors all wallet kinds because the curve check happens on chain.
- Free CCTP USDC migration from Solana / Ethereum into a V8 wallet (combined with the dev's source-chain relayer).
- AI-agent UX via session keys + per-token spending caps + auto-expiry.
- MPC-grade multi-device security without MPC infrastructure.

## Audit + response

- [2026-04-13 Henri / Nethermind AuditAgent scan](./audits/2026-04-13-henri-nethermind-auditagent-scan.pdf) — 3 findings (High / Medium / Info). [Response letter](./docs/audit-response-henri.md).
- [2026-04-20 Omar Espejel Codex/Cairo audit](./audits/2026-04-20-omar-espejel-codex-audit.md) — 12 findings (Critical / High×2 / Medium×4 / Low / Info×3). [Response letter](./docs/audit-response-omar.md).

Both reports archived in [`audits/`](./audits/) with the chronology + Nethermind-license boundary noted in `audits/README.md`.

Phase 13 + 14 independent audits are post-launch hardening (not pre-launch gating) per the maintainer's go-to-mainnet decision.

## Architecture

```
                          ┌──────────────────────────────────┐
                          │       ShhhAccount (1 class)      │
                          │                                  │
                          │   owners, verifier_classes,      │
                          │   governance, recovery,          │
                          │   sessions + spending_policy     │
                          └─────────────────┬────────────────┘
                                            │  library_call_syscall
   ┌──────────┬──────────┬──────────┬───────┴────┬──────────┬──────────┬──────────┐
   ▼          ▼          ▼          ▼            ▼          ▼          ▼          ▼
┌──────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ ┌──────┐ ┌──────────┐
│STARK │ │Ed25519  │ │Secp256k1 │ │EIP-191   │ │EIP-712 │ │ P256 │ │WebAuthn  │
│ ver. │ │ ver.    │ │ ver.     │ │ ver.     │ │ ver.   │ │ ver. │ │ P256 ver.│
└──────┘ └─────────┘ └──────────┘ └──────────┘ └────────┘ └──────┘ └──────────┘
```

Source layout:

```
src/
├── lib.cairo                       # module tree
├── account.cairo                   # V8 main account contract
├── signer/
│   ├── interface.cairo             # ISigner trait + kind-tag registry
│   ├── stark/verifier.cairo
│   ├── ed25519/verifier.cairo
│   ├── secp256k1/verifier.cairo
│   ├── eip191_secp256k1/verifier.cairo
│   ├── eip712_secp256k1/verifier.cairo
│   ├── p256/verifier.cairo
│   └── webauthn_p256/verifier.cairo
├── owner_set/                      # multi-owner storage + invariants
├── governance/                     # timelocked propose/execute/cancel
├── recovery/                       # guardian + 7d recovery
├── session_key/                    # ported from SNIP #163
├── spending_policy/                # ported from SNIP #163
├── migration/                      # bootstrap_from_sessions
├── wallet.cairo                    # V7 retained for reference
├── outside_execution.cairo         # OE encoding + SNIP-12 hash
└── ed25519/                        # V7 Ed25519 retained for reference

tests/
├── audit_2026_04_20.cairo          # regressions for Omar's 12 findings
├── audit_v8.cairo                  # V8-specific structural regressions
├── account_*.cairo                 # phase-by-phase account tests
├── signer_*.cairo                  # per-verifier-class tests
├── interface_ids.cairo             # SRC-5 + Cairo↔TS parity
├── edge_cases.cairo                # boundary conditions
└── fuzz_*.cairo                    # 1,792 random sweeps
```

## Build & test

```bash
scarb --version          # 2.14.0
snforge --version        # 0.59.0

scarb build              # compiles V7 + V8
scarb fmt --check        # format gate
snforge test             # 184 passed, 0 failed, 0 ignored

bash scripts/mutation-test.sh   # 10/10 mutants killed, no documented gaps
node scripts/ts/check-interface-ids.mjs   # Cairo ↔ TS ↔ starknet_keccak parity
```

## Docs

- [`docs/ecosystem-impact.md`](./docs/ecosystem-impact.md) — what V8 unlocks for users / devs / Starknet ecosystem.
- [`docs/class-hashes.md`](./docs/class-hashes.md) — declared class hashes + reproduction commands.
- [`docs/mainnet-deployment.md`](./docs/mainnet-deployment.md) — per-tx fees, per-user-operation cost map, Cifra projection.
- [`docs/snip-draft-pluggable-signer.md`](./docs/snip-draft-pluggable-signer.md) — pluggable-signer SNIP draft, V8 as reference implementation.
- [`docs/audit-response-omar.md`](./docs/audit-response-omar.md) and [`docs/audit-response-henri.md`](./docs/audit-response-henri.md) — per-auditor response letters.

## License

MIT
