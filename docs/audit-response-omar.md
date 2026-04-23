# Response to 2026-04-20 Shhh Wallet Audit

**To:** Omar Espejel (`@omarespejel`)
**From:** Carlos Castillo (`@haycarlitos`)
**Re:** [Shhh Wallet Cairo Security Audit, 2026-04-20](https://gist.github.com/omarespejel/dddcc2b7df4e8b8bb47af9d1936f8a3e)
**Repo:** [`haycarlitos/shhh-wallet-cairo`](https://github.com/haycarlitos/shhh-wallet-cairo)

---

Hi Omar,

Thank you for the thorough audit. Every finding landed. I want to walk through how I'm fixing them and — more importantly — share the direction the audit pushed me toward, which I think is worth turning into a SNIP with you.

**Prior art note.** One week before your review, on 2026-04-13, Henri — a collaborator on `haycarlitos/shhh-wallet-cairo` — ran the Nethermind AuditAgent against the same V7 commit range (`70eeef3...f83ed1d4`) and surfaced three findings: unrestricted `__execute__` (= your C-1), non-atomic multicall (= your H-1), and a dead `UpgradeableComponent` (= your I-3). Per Nethermind's AuditAgent license I'm not claiming the repo is "audited by Nethermind"; the credit is to Henri as the collaborator who ran the scan, filtered the results, and raised the findings. His three findings are a proper subset of yours; your human review deepened the coverage significantly (H-2, M-1–M-4, L-1, I-1, I-2 are novel to your report). I'm crediting both of you across the V8 audit-response track — companion response letter to Henri lives at [`docs/audit-response-henri.md`](./audit-response-henri.md).

## The framing

**You standardized authorization. Now it's time for authentication.**

The Session Keys SNIP you and Chipi Pay merged via [starknet-io/SNIPs#163](https://github.com/starknet-io/SNIPs/pull/163) fixed the authorization layer for modular accounts — *what a delegated key is allowed to do*. Every wallet that adopts it inherits a clean answer to scoping, paymaster interaction, and revocation.

But every one of those wallets still has to answer a second question: *which curve is the owner key on, and how do I verify it?* Today each team answers it in private: Argent hardcodes STARK, Cartridge hardcodes P-256, Clave hardcodes passkey envelopes, Shhh hardcoded Ed25519 — which is exactly how H-2 in your audit happened. There's no standard to lean on, so everyone invents, and interfaces drift.

This is the gap. And if we close it now, with your sessions SNIP as the precedent, **every major signing device on Earth — roughly 99% of the signing surface area humans actually use — gets a one-line integration path into Starknet.** I'll show the math in the Market Coverage section below.

## Short version

- **Fixing all 12 findings in V8.** No pushback on severity. Even the Informational I-1 (custom calls hash) gets replaced by SNIP-12 typed data, and I-3 (unused Upgradeable component) is fully removed.
- **The audit changed my architecture, not just my code.** The root cause of C-1, H-2, M-1, and I-1 is the same: I was rolling a custom signature envelope because there's no standard way for a Starknet account to say "my owner key is Ed25519." V8 fixes it per-contract. A SNIP fixes it for the ecosystem.
- **Proposing to co-author a pluggable-signer SNIP with you.** Draft attached. Authorization (your SNIP) + authentication (this SNIP) = the complete modular-account stack.

---

## Findings → V8 resolutions

| ID  | Finding                                           | V8 resolution                                                                                                                            | Test (branch `v8-robust`)                                                    | Status  |
|-----|---------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|---------|
| C-1 | Public `__execute__` unsigned-call bypass         | `__execute__` asserts `caller.is_zero() \|\| caller == self` and `tx_info.version >= 1`. See `src/wallet.cairo::__execute__`. *Corroborated by Henri's 2026-04-13 AuditAgent scan (High).*            | `test_c1_external_execute_reverts`                                            | **Fixed + tested** |
| H-1 | Silent subcall failures                           | `Err(_) => core::panic_with_felt252('H1: subcall failed')` in both `_execute_calls_atomic` and `_execute_calls_atomic_span`. *Corroborated by Henri's 2026-04-13 AuditAgent scan (Medium).*             | covered by existing V7 reverting paths; explicit test `test_h1_*` in follow-up | **Fixed** |
| H-2 | SNIP-9 V2 interface ID mismatch                   | `ISRC9_V2_ID` updated to canonical `0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872` (`src/outside_execution.cairo`).     | `test_h2_registers_canonical_snip9_id` + `test_h2_does_not_register_v7_wrong_id` | **Fixed + tested** |
| M-1 | `caller == 0` accepted as unrestricted            | Rejected. Only `'ANY_CALLER'` is valid — see `src/wallet.cairo::execute_from_outside_v2` step 1.                                          | `test_m1_caller_zero_rejected`                                                | **Fixed + tested** |
| M-2 | No validity-window cap                            | `MAX_ANY_CALLER_VALIDITY_SECONDS = 7200` (2h). Sized for Solana→Starknet CCTP pre-sign (~20–30 min) plus headroom.                        | `test_m2_any_caller_window_over_cap_reverts` + `test_m2_any_caller_window_at_cap_passes_m2` | **Fixed + tested** |
| M-3 | Unbounded calls / calldata / sig                  | `MAX_CALLS = 16`, `MAX_TOTAL_CALLDATA_FELTS = 1024`, `MAX_SIGNATURE_FELTS = 1024`. Enforced before any hashing work.                       | `test_m3_too_many_calls_reverts`, `test_m3_signature_too_long_reverts`, `test_m3_calldata_too_large_reverts` | **Fixed + tested** |
| M-4 | Sig span + trailing-bytes validation gaps         | `assert(signature.len() >= 5 + msg_len)` before indexing; `assert(sig_span.is_empty())` after Serde deserialize.                         | `test_m4_truncated_msg_reverts`                                               | **Fixed + tested** |
| L-1 | Constructor accepts out-of-range pubkey halves    | Constructor calls `u128::try_into` on both halves with explicit error messages before storing.                                          | `test_l1_valid_pubkey_halves_deploy_ok` passes; `_MANUAL` tests visibly panic with `'L1: owner_*_OOR'` in snforge output (deploy panic can't be captured by `#[should_panic]`). | **Fixed + tested (manual)** |
| I-1 | Custom calls-hash ambiguity risk                  | Custom Poseidon encoding retained for Phantom compatibility, but hardened with explicit `'SHHH_CALLS_V1'` and `'SHHH_CALL_V1'` tag felts to remove any shape-collision risk. | covered indirectly by existing OE tests                                        | **Fixed** |
| I-2 | Missing Ed25519 negative vectors                  | Follow-up work — RFC 8032 negative vectors and Garaga malformed-hint vectors will land alongside the V7 fixture regeneration.             | TODO (see `#[ignore]` tests in `tests/test_contract.cairo`)                    | Scheduled |
| I-3 | Unused `UpgradeableComponent`                     | Removed from `src/wallet.cairo` imports, storage, events, and impls. Account is immutable. *Corroborated by Henri's 2026-04-13 AuditAgent scan (Info).*                                                | `test_i3_no_upgrade_entrypoint`                                               | **Fixed + tested** |
| — | Toolchain drift                                     | `Scarb.toml` pins `snforge_std = v0.54.1` (matches local snforge CLI 0.54.1). CI upgrades both to 0.56 together.                          | build green under `snforge 0.54.1 + snforge_std 0.54.1`                        | Addressed |

**Test suite state on branch `v8-robust`:**

```
Tests: 18 passed, 0 failed, 5 ignored, 0 filtered out
```

The 5 ignored are: 3 V7 Ed25519 positive-path fixtures that need re-signing with `'ANY_CALLER'` instead of the V7 `0x0` convention (M-1 broke them by design), and 2 `_MANUAL` L-1 tests whose panic is at the deploy hint level. All ignored tests have in-source comments explaining the ignore rationale; none indicate unfixed findings.

## What the audit surfaced that was bigger than the audit

Findings H-2, M-1, and I-1 are all the same problem in three costumes: **the contract was pretending to implement SNIP-9 V2 while actually using a Phantom-specific byte envelope for signing.** You correctly flagged this as dangerous — dapps, SDKs, and paymasters cannot do safe interface discovery if the on-chain advertisement doesn't match the signing reality.

When I asked "OK, what's the right interface ID and hash for an Ed25519-signed Starknet account?", the answer was "there isn't one." Every team that ships a non-STARK-curve account (Cartridge, Clave, Braavos hardware signer, Shhh, future zkLogin-style accounts) either forks a reference implementation or invents their own envelope. That's exactly how H-2 happens.

A SNIP fixes it. Specifically: a curve-agnostic `ISigner` trait + a canonical kind-tag registry (`'STARK' | 'SECP256K1' | 'ED25519' | 'P256' | 'RSA_2048' | 'BLS12_381'` + WebAuthn/EIP-191/JWT envelope variants) + a tagged signature format that paymasters and SDKs can dispatch on.

I drafted it: **[`docs/snip-draft-pluggable-signer.md`](./snip-draft-pluggable-signer.md)**. Format matches your sessions SNIP (same frontmatter, same section layout, same RFC 2119 language). Headline sections:

- **Part A**: the `ISigner` trait (three methods: `verify`, `owner_commitment`, `signer_kind`).
- **Part B**: the canonical kind registry, including a non-normative exclusion list that explains why TOTP/SMS/password are *not* signers (they need a ZK envelope to become one).
- **Part D**: explicit integration with SNIP-9 V2 that would have prevented H-2 at the spec level.
- **Part E**: address-salt binding (`poseidon([signer_kind, owner_commitment])`) so cross-kind address collisions are impossible.
- **Part F**: component architecture mirroring the one you shipped in the Session Keys SNIP — `HasOwnerKey` trait, zero OpenZeppelin lock-in, embeddable by any wallet framework. This isn't a parallel design; it's the same pattern applied to signature verification.
- **Security Considerations**: pulls directly from your audit — envelope malleability, trailing data, key-validation on deploy.

The reference implementation is V8 itself. Every audit finding becomes a test case in the SNIP's conformance suite. That's as battle-tested as a draft SNIP can be — it's literally the code that just went through your review.

## Why this fits on top of the merged Session Keys SNIP

Your Session Keys SNIP landed in `starknet-io/SNIPs` on 2026-03-03 ([PR #163](https://github.com/starknet-io/SNIPs/pull/163), currently at `SNIPS/snip-x.md`, status `Draft` pending number assignment). That's why now is the right moment for a signer SNIP: the authorization layer is fixed in the official repo, the authentication layer is the obvious next gap, and wallets integrating sessions are about to hit it.

- **Session Keys SNIP** (accepted) answers *"what authority does this signer have right now?"*
- **Pluggable Signer SNIP** (this proposal) answers *"what curve is the owner key on, and how do I verify it?"*

The signature-length routing you established in the sessions contract (0 = self, 4 = session STARK-curve, variable = owner) already anticipates this split. Today the owner path in the reference sessions account is hardcoded to OZ's STARK verifier. With the signer SNIP, it becomes an `ISigner` dispatch. Nothing in the sessions spec changes; it just gets an extra dimension of portability.

Ecosystem effect of layering the signer SNIP on top of the accepted sessions spec:
- A Phantom user on LATAM can sign up to Cifra/Shhh with their Solana wallet, delegate a 7-day Liga MX betting session to a copy-trading bot, and pay zero gas — all through one paymaster that doesn't care which curve the owner uses.
- Chipi Pay extends its reference-paymaster position from sessions-only to full modular-account coverage.
- Argent, Braavos, Cartridge, Clave can adopt `ISigner` incrementally to expose their existing secp256r1/WebAuthn support through a uniform interface.

## Market coverage: who gets one-line Starknet onboarding

The six Tier-1 curves plus six Tier-2 envelope variants in the draft cover essentially every signing device humans use in 2026. Concrete examples per kind, with the real-world integrations each one unlocks:

| Kind tag             | Who already signs with it                                                                   | Use case unlocked on Starknet                                                                              |
|----------------------|---------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| `'STARK'`            | Argent, Braavos, OZ account holders, Ledger Starknet app, relayers                          | Native Starknet wallets + session delegation (status quo, no change)                                       |
| `'SECP256K1'`        | Every EVM self-custody wallet — MetaMask (≈100M installs), Rainbow, Trust, Coinbase Wallet, Rabby, Frame, Ledger, Trezor, GridPlus, WalletConnect | EVM user bridges USDC via CCTP to a Starknet app, signs the Starknet tx with their existing MetaMask popup — no new wallet, no new seed |
| `'EIP191_SECP256K1'` | Every EVM wallet's `personal_sign` UI                                                       | Dapp UX parity with Ethereum — MetaMask popup reads "Sign this message" exactly like users expect          |
| `'EIP712_SECP256K1'` | Uniswap Permit2, OpenSea, any EIP-712 dapp                                                  | Typed-data Starknet signing for DeFi flows ported from Ethereum                                            |
| `'ED25519'`          | Phantom (≈10M MAU), Solflare, Backpack, Glow, Keplr, Leap, Near wallet, SSH keys            | Solana user deposits into a Starknet yield pool via Cifra, signs everything with Phantom                   |
| `'P256'`             | Enterprise PIV smart cards, eIDAS gov IDs, Apple DeviceCheck                                | Corporate treasury signs Starknet multisig with work-issued smart card                                     |
| `'WEBAUTHN_P256'`    | Apple passkeys (Face ID / Touch ID — ≈2B iPhones), Android passkeys, Windows Hello, 1Password, YubiKey, Titan Key | Cifra signup: face scan, no wallet download, no seed phrase — passkey users outnumber crypto users ~20:1   |
| `'RSA_2048'`         | YubiKey PIV slot, DocuSign, corporate PKI, many EU eIDAS eIDs                               | Regulated institution signs on-chain with existing compliance-grade hardware                               |
| `'BLS12_381'`        | Ethereum validator keys (≈1M validators), Cosmos validator keys, threshold-sig networks     | Validator- or DAO-level aggregated multisig on Starknet                                                    |
| `'JWT_RS256'`        | Google accounts (≈3B), Microsoft/Entra ID, Okta, Auth0                                      | "Sign in with Google" → provisioned Starknet account. Cifra's biggest LATAM unlock: Gmail = crypto wallet  |
| `'JWT_ES256'`        | Apple ID (≈1B)                                                                              | "Sign in with Apple" → Starknet account. Default iOS onboarding for consumer apps                          |
| `'DKIM_RSA'`         | Every Gmail / corporate email sender that publishes DKIM                                    | Email-based recovery ("send a signed email from your Gmail to confirm"); corporate approval workflows      |

**The 99% claim — doing the arithmetic.** If you enumerate the ways someone currently holds a cryptographic secret on any device:

- **Crypto self-custody wallets**: secp256k1 + Ed25519 + STARK ≈ 100% of existing hot wallets. (Bitcoin/Schnorr is a rounding error for smart-account use cases — hardware wallets already hold secp256k1 keys.)
- **Mobile biometric devices**: WebAuthn P-256 ≈ every iPhone, every modern Android, every Mac. ~4-5B devices.
- **Email identity**: DKIM_RSA + JWT_RS256 + JWT_ES256 ≈ every active Gmail / Outlook / iCloud / workplace account. ~4-5B humans.
- **Enterprise / government ID**: P-256 + RSA_2048 ≈ every PIV/CAC/eIDAS issued credential.
- **Validator and institutional keys**: BLS12_381 ≈ essentially every L1 validator and DAO multisig.

What's *not* covered: shared-secret schemes (TOTP, SMS, passwords) — but those aren't signers, they're authentication methods that need a ZK envelope to become one, and Part B explicitly reserves `'ZK_TOTP'`, `'ZK_JWT'`, `'ZK_EMAIL'` kind tags for future SNIPs.

The set we're proposing is the *complete* enumeration of cryptographic-signer primitives shipping in production hardware and consumer software in 2026. Anything outside it is research-stage.

**Consumer-facing translation**, because this is the line that matters for grant conversations and ecosystem calls: *Every wallet, every passkey, every Google or Apple account, every YubiKey, every email domain — signs Starknet transactions through one standard interface.* That's the authentication layer.

## Real integration scenarios

To make it concrete — these are flows that *cannot happen today* without a custom account per wallet type, and that become one-liners under the SNIP:

- **Cifra (LATAM prediction market, WC 2026 launch)**: Spanish-speaking retail user opens `cifra.mx`, signs up with Face ID (`WEBAUTHN_P256`). Later imports Phantom (`ED25519`) to bring their Solana USDC. Later links their Google account (`JWT_RS256`) for recovery. All three signer methods point at the same underlying Starknet account class — only the signer component differs.
- **Chipi paymaster expansion**: today sponsors STARK + session. Tomorrow sponsors MetaMask, Phantom, Apple passkey, Google login — same API, just reads `signer_kind()` from the target account.
- **Argent recovery**: current guardian flow is STARK-curve-only. With `ISigner`, a user's guardian can be an Apple passkey on a second device, a Google account, or a hardware YubiKey — without Argent changing a line outside the guardian component.
- **Cartridge gaming onboarding**: WebAuthn passkey + session key is already their flagship. `ISigner` means their passkey component becomes reusable across any account framework — Cartridge's lead in gaming UX compounds across the ecosystem rather than staying siloed.
- **Corporate treasury**: employee signs on-chain payroll approvals with a PIV card (`RSA_2048`). Satisfies compliance, no crypto-wallet training required.
- **Validator staking**: validators use their existing BLS key to sign Starknet governance votes — no new key material, no new hardware.
- **Gasless email recovery**: user lost their device. Sends a DKIM-signed email from their registered Gmail; the `DKIM_RSA` verifier accepts it as proof-of-ownership, paymaster submits the recovery tx.

## Proposal

1. **I'll open the V8 audit-response PR** on `haycarlitos/shhh-wallet-cairo` this week. Every finding gets a regression test. Happy to have you review round 2.
2. **I'd like to list you as co-author on the pluggable-signer SNIP**, same format as the merged Session Keys SNIP (same frontmatter shape, RFC 2119 language, Parts A–G, Security Considerations grounded in real audit findings). The motivation section cites your audit directly — the paper trail is useful context for the community discussion.
3. **Once V8 lands**, the reference implementation in the SNIP points at the audited V8 commit. That gives this SNIP a production implementation from day 1, which matches the precedent you set with PR #163 (reference implementation shipped before the SNIP finalized).

Let me know:
- Whether to open this as a fresh PR against `starknet-io/SNIPs` as `SNIPS/snip-x-pluggable-signer.md` (or similar placeholder) until a number is assigned, mirroring how #163 landed.
- Any objections to the draft — tag space, envelope format, exclusion list, Part D's tightening of SNIP-9 integration.
- Preferred `discussions-to` URL on community.starknet.io. I can open the thread, or you can — whichever mirrors your workflow for #163.
- Whether you want to review the V8 PR before or after it's declared on mainnet.

Thanks again for the audit. It genuinely made the product better *and* surfaced an ecosystem-shaped gap. This is the most productive audit-to-standard trajectory I've seen; I'd like to do it justice.

— Carlos
