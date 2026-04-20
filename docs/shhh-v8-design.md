# Shhh Wallet V8 — Design Doc

> **Status:** Draft
> **Authors:** Carlos Castillo (chipipay.com)
> **Target repo:** [`haycarlitos/shhh-wallet-cairo`](https://github.com/haycarlitos/shhh-wallet-cairo)
> **Supersedes:** V7 (class hash `0x2e599a0939f268c70acab242411225ddeefd7f3978e40dcb7c397ca39a9a13`)
> **Drivers:** (1) 2026-04-20 Codex/Cairo audit response, (2) Cifra multi-wallet support, (3) Starknet ecosystem contribution: pluggable-signer standard

---

## 1. Goals

1. **Close every audit finding** from the 2026-04-20 report (C-1, H-1, H-2, M-1/2/3/4, L-1, I-1/2/3).
2. **Support Phantom + MetaMask + passkey** as first-class signers on the same account class. Cifra's user acquisition funnel requires it.
3. **Reuse the sessions-smart-contract pattern** (owner key + ephemeral session key) so users can delegate scoped authority (e.g. "place bets on this market for 24h, max 50 USDC").
4. **Ship a signer-abstraction trait** that's clean enough to upstream as a SNIP or contribute back to OpenZeppelin Cairo Contracts.

Non-goals (V8 scope cuts):
- Multi-owner / social recovery (V9).
- Account upgradeability (V8 is immutable per class).
- Formal verification of signer components (rely on Garaga + OZ audits).

---

## 2. High-level architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    ShhhAccount (V8)                           │
│                                                               │
│  ┌────────────────┐  ┌──────────────────┐  ┌──────────────┐   │
│  │ ISigner (trait)│  │ SessionKey Comp. │  │ Spending     │   │
│  │                │  │   (from Chipi)   │  │ Policy Comp. │   │
│  │ verify(h, sig) │  │                  │  │              │   │
│  └───────┬────────┘  └──────────────────┘  └──────────────┘   │
│          │                                                    │
│   ┌──────┴──────┬─────────────┬──────────────┐                │
│   │             │             │              │                │
│ Ed25519     Secp256k1      WebAuthnP256   STARK-ECDSA         │
│ (Phantom)   (MetaMask)     (Passkey)      (standard)          │
│                                                               │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │          SRC9 (Outside Execution v2) — real SNIP-9       │ │
│  │          SNIP-12 typed data + custom Shhh extension      │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                               │
│  __validate__ → always reverts (NOT_SUPPORTED)                │
│  __execute__  → protocol-only, reverts on non-zero caller     │
│  execute_from_outside_v2 → SOLE execution path                │
└───────────────────────────────────────────────────────────────┘
```

### 2.1 Core primitive — `ISigner` trait

```cairo
#[starknet::interface]
pub trait ISigner<TContractState> {
    // Returns `true` if `signature` authorizes `message_hash` under the stored owner key.
    // Must be pure/read-only. No storage writes.
    fn verify(self: @TContractState, message_hash: felt252, signature: Span<felt252>) -> bool;

    // Returns a Poseidon commitment of the owner key. Used for address salt
    // and interface probing. Stable for the lifetime of the account.
    fn owner_commitment(self: @TContractState) -> felt252;

    // Curve identifier (e.g. 'ED25519', 'SECP256K1', 'P256', 'STARK').
    // Lets dapps and paymasters select the right signing path off-chain.
    fn signer_kind(self: @TContractState) -> felt252;
}
```

Each concrete signer (ed25519, secp256k1, webauthn, stark) is a **component** implementing `ISigner` internals. The account contract picks one component at compile time via `component!(...)` — no dynamic dispatch, no upgradeability — but shares one trait surface.

### 2.2 Class-hash strategy

Four compile-time classes, one codebase, one set of tests:

| Class                   | Signer component  | Use case                                 |
|-------------------------|-------------------|------------------------------------------|
| `ShhhAccount_Ed25519`   | `ed25519/`        | Phantom (Solana), any Ed25519 wallet     |
| `ShhhAccount_Secp256k1` | `secp256k1/`      | MetaMask, WalletConnect EVM              |
| `ShhhAccount_WebAuthn`  | `webauthn_p256/`  | Chipi passkey, iOS/Android Face ID/Touch |
| `ShhhAccount_Stark`     | `stark_ecdsa/`    | Standard Starknet wallets, relayers      |

All four share:
- Same `SessionKeyComponent`
- Same `SpendingPolicyComponent`
- Same `SRC9Component` (real SNIP-9 V2 via SNIP-12)
- Same storage layout (minus owner-key storage, which the signer component owns)
- Same interface IDs registered in SRC-5

Selection is frontend-driven: Cifra's signup flow reads the connected wallet type and deploys the matching class.

---

## 3. Responding to the audit

| ID  | Finding                                         | V8 resolution                                                                                                                                   |
|-----|-------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| C-1 | `__execute__` allows unsigned calls             | `__execute__` asserts `caller.is_zero() \|\| caller == self`, asserts `tx_info.version >= 1`, then routes through spending-policy check. Session keys can use this path too (sessions pattern).  |
| H-1 | Silent subcall failures                         | Replace `Err => empty span` with `core::panic_with_felt252('SHHH: subcall failed')` in `__execute__` and `execute_from_outside_v2`. Atomic.      |
| H-2 | Advertises SNIP-9 V2 but uses custom hashing    | **Design B**: implement real SNIP-12 typed-data hashing (matches sessions repo's `_compute_outside_execution_hash`). Register correct ID `0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872`. Keep custom hex-ASCII path as a legacy fallback gated by a version byte. |
| M-1 | `caller == 0` treated as unrestricted           | Accept only `'ANY_CALLER'`. Zero reverts.                                                                                                       |
| M-2 | No validity window cap                          | `MAX_ANY_CALLER_VALIDITY_SECONDS = 7200` (2h) — covers CCTP pre-sign. Cap is a compile-time const per class.                                    |
| M-3 | No call/calldata/sig bounds                     | `MAX_CALLS = 16`, `MAX_TOTAL_CALLDATA_FELTS = 1024`, `MAX_SIGNATURE_FELTS = 512`. Enforced before hashing.                                       |
| M-4 | Signature span under-validated                  | `assert(signature.len() >= 5 + msg_len)`, `assert(sig_span.is_empty())` post-deserialize.                                                       |
| L-1 | Constructor accepts out-of-range pubkey halves  | Signer component validates key in `initializer()` — for Ed25519, `u128::try_into` both halves; for WebAuthn, verify point on curve.             |
| I-1 | Ambiguous custom calls hash                     | Replaced by SNIP-12 typed data (H-2 fix). No custom encoding remains on the primary path.                                                       |
| I-2 | Missing Ed25519 negative vectors                | Add RFC 8032 negative vectors + Garaga malformed-hint vectors to `tests/test_signer_*.cairo`. CI gate.                                          |
| I-3 | Dead `UpgradeableComponent`                     | Removed. V8 is immutable by class. Users migrate to new classes by redeploying and transferring shielded notes.                                 |

---

## 4. Session keys — borrowing from `chipi-pay/sessions-smart-contract`

Cifra's UX depends on session keys. Use cases:

| Use case                                        | Session config                                                                                           |
|-------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| "Bet on Liga MX markets for this tournament"    | 30 days, max 100 calls, selector whitelist = `place_bet`, spending policy = 200 USDC / 30d               |
| "Claim daily reward automation"                 | 90 days, max 90 calls, selector whitelist = `claim`, spending = 0 outflows                               |
| "Copy-trade leader X"                           | 7 days, max 50 calls, selector whitelist = `place_bet`, spending = 100 USDC / week                       |
| "Shield new CCTP deposits automatically"        | 365 days, max 100 calls, selector whitelist = `shield_note`, no outflow cap                              |

Reused verbatim from sessions repo (with owner-key check swapped for `ISigner::verify`):

- `SessionKeyComponent` — per-session storage, admin selector blocklist, self-call block, whitelist enforcement.
- `SpendingPolicyComponent` — per-session per-token spending caps with rolling windows.
- Admin selector blocklist (expanded for V8): `upgrade`, `add_or_update_session_key`, `revoke_session_key`, `__execute__`, `execute_from_outside_v2`, `set_spending_policy`, `remove_spending_policy`, **`set_owner_signer`** (new, V8-only).

### 4.1 Signature routing

The account picks the signature path by length, matching sessions repo convention:

| `signature.len()` | Path            | Verifier                                           |
|-------------------|-----------------|----------------------------------------------------|
| 0                 | Self-call       | Accept only if caller == self                      |
| 4                 | Session key     | `check_ecdsa_signature` (STARK curve, session key) |
| Variable          | Owner signature | `ISigner::verify(msg_hash, sig)`                   |

The owner path is length-variable because each curve has different signature sizes:

| Signer          | Signature length (felts)                        |
|-----------------|-------------------------------------------------|
| Ed25519+Garaga  | ~600-800 (sig + msm_hint + sqrt_Rx + sqrt_Px)   |
| Secp256k1       | 4 (r_low, r_high, s_low, s_high, v)             |
| WebAuthn P-256  | ~8 + clientDataJSON bytes                       |
| Stark ECDSA     | 2                                               |

To disambiguate, the first felt of the owner signature is the **signer kind tag** (`'ED25519'`, `'SECP256K1'`, `'P256'`, `'STARK'`). The dispatcher reads tag → routes to component. Session keys always start with the raw session pubkey (STARK curve), so no collision.

---

## 5. Storage layout

```cairo
#[storage]
struct Storage {
    #[substorage(v0)]
    signer: SignerComponent::Storage,       // concrete: ed25519 / secp256k1 / p256 / stark
    #[substorage(v0)]
    src5: SRC5Component::Storage,
    #[substorage(v0)]
    src9: SRC9Component::Storage,
    #[substorage(v0)]
    session_key: SessionKeyComponent::Storage,
    #[substorage(v0)]
    spending_policy: SpendingPolicyComponent::Storage,

    // V8-specific: outside-execution nonce replay protection.
    // SRC9Component already has its own SRC9_nonces map; no duplicate needed.
}
```

Notes:
- **No `UpgradeableComponent`** (I-3 fix).
- **No `AccountComponent`** from OZ — that pins STARK-curve. V8 rolls its own `__validate__` / `__execute__` around `ISigner`, same pattern as the sessions repo's custom SRC-6 impl.
- **Storage is signer-agnostic** — migrating a user between classes means redeploying and transferring shielded notes; the on-chain storage format doesn't need to migrate.

---

## 6. Constructor

```cairo
#[constructor]
fn constructor(ref self: ContractState, owner_key: Span<felt252>) {
    // Each signer component parses owner_key in its own format.
    // Ed25519: [pubkey_low, pubkey_high] — LE u256 halves
    // Secp256k1: [x_low, x_high, y_low, y_high] — uncompressed point
    // WebAuthnP256: [x_low, x_high, y_low, y_high]
    // Stark: [pubkey_felt]
    self.signer.initializer(owner_key);

    self.src9.initializer();                          // real SNIP-9 V2 registration
    self.src5.register_interface(SESSION_KEY_MANAGER_ID);
    self.src5.register_interface(ISIGNER_ID);         // new: signer-kind introspection
}
```

**Address salt** = `poseidon(signer_kind, owner_commitment)` — ensures the same underlying key deployed under different signer types gets different addresses (prevents cross-class confusion).

---

## 7. SNIP-9 V2 implementation

Adopt the sessions repo's dual-hash pattern for paymaster compatibility:

1. **Primary path**: OZ standard `OutsideExecution` SNIP-12 hash (u128 timestamps).
2. **Fallback path**: felt-timestamp variant (Chipi paymaster legacy).

For Shhh specifically (Phantom signing), a **third path** for Ed25519:
- Ed25519 signatures are over **bytes**, not a felt. The hex-ASCII encoding from V7 (`bytes_to_hex_ascii(SNIP12_hash.to_bytes())`) stays — it's the on-curve signing surface for Phantom.
- Verification: compute SNIP-12 hash felt → encode as 64 hex-ASCII bytes → verify Ed25519 sig over those bytes → compare the hash felt matches the OutsideExecution struct.

This preserves Phantom UX (user sees a hex string in the popup) while conforming to SNIP-9 V2 on-chain.

---

## 8. Execution flow (per signer)

### 8.1 Phantom user places a Cifra bet

```
1. Frontend builds OutsideExecution { calls: [shield_note, place_bet], ... }
2. Frontend computes SNIP-12 hash (OZ format, u128 timestamps)
3. Frontend encodes hash felt as 64-byte hex ASCII
4. Phantom.signMessage(hex_bytes) → Ed25519 sig + hints (Garaga)
5. Frontend wraps: [tag='ED25519', sig, hints, msg_bytes]
6. Paymaster (Chipi) calls execute_from_outside_v2(oe, signature)
7. Contract:
   - validate caller, time, nonce, M-3 bounds
   - dispatcher: first felt is 'ED25519' → route to Ed25519Component
   - recompute SNIP-12 hash → encode to hex bytes → Garaga Ed25519 verify
   - atomic multicall (shield_note then place_bet)
8. Cifra market contract emits BetPlaced with private note commitment
```

### 8.2 MetaMask user places a Cifra bet

Same flow, signer kind = `'SECP256K1'`. Ethers.js signs `personal_sign(snip12_hash_as_hex)` → recover → compare against stored secp256k1 pubkey.

### 8.3 Passkey user places a Cifra bet

Same flow, signer kind = `'P256'`. WebAuthn produces `{authenticatorData, clientDataJSON, sig}`. The Shhh verifier (using Garaga's P256) reconstructs the signed bytes as `authenticatorData || sha256(clientDataJSON)`, verifies the P-256 sig. The SNIP-12 hash must appear in `clientDataJSON.challenge` (base64url).

### 8.4 Session-key bet (any signer)

After the user has signed an `add_or_update_session_key` OE with their Phantom/MetaMask/passkey key, subsequent bets within the session's scope use the 4-element STARK-curve session sig — no wallet popup. Identical to sessions repo behavior.

---

## 9. Cifra compatibility matrix

| Cifra feature                            | V8 support                                                                      |
|------------------------------------------|---------------------------------------------------------------------------------|
| Phantom user ingress (Solana CCTP)       | `ShhhAccount_Ed25519`                                                           |
| MetaMask user ingress (EVM CCTP)         | `ShhhAccount_Secp256k1`                                                         |
| Chipi passkey signup                     | `ShhhAccount_WebAuthn`                                                          |
| Bet placement (atomic shield + bet)      | H-1 fix makes multicalls atomic                                                 |
| Copy-trading follower auto-bets          | Session key with `place_bet` whitelist, 7d / 50-call cap, spending policy       |
| Pre-signed CCTP deposits (~30min)        | M-2 cap = 2h covers it                                                          |
| Market-creation bond deposit             | Single OE call, no special handling                                             |
| Claim winnings                           | Signed at claim time, standard OE                                               |
| Refund on cancelled market               | Standard OE, session keys NOT allowed (admin-only selector)                     |
| Pro sub-app (whales, verified handles)   | Same wallet classes; handle registry is separate contract                       |

---

## 10. Test plan

| Suite                    | New in V8  | Coverage                                                    |
|--------------------------|------------|-------------------------------------------------------------|
| `test_signer_ed25519`    | extended   | Valid + RFC 8032 negative vectors + malformed Garaga hints  |
| `test_signer_secp256k1`  | new        | Valid + malleability + low-s enforcement                    |
| `test_signer_webauthn`   | new        | Valid + clientDataJSON tampering + origin binding           |
| `test_signer_stark`      | new        | Valid + wrong key                                           |
| `test_audit_c1`          | new        | External `__execute__` from non-zero caller → revert        |
| `test_audit_h1`          | new        | Two-call multicall with second failing → full revert        |
| `test_audit_h2`          | new        | SRC-5 probe `0x1d1144bb...0a04c` → false; real ID → true    |
| `test_audit_m1`          | new        | `caller = 0` → revert; `caller = 'ANY_CALLER'` → accept     |
| `test_audit_m2`          | new        | Validity window > 2h with `'ANY_CALLER'` → revert           |
| `test_audit_m3`          | new        | 17 calls → revert before hashing                            |
| `test_audit_m4`          | new        | Truncated msg → revert; trailing sig bytes → revert         |
| `test_audit_l1`          | new        | Ed25519 pubkey half > u128::MAX → deploy reverts            |
| `test_session_key`       | port       | Port from sessions repo, adapt owner check to `ISigner`     |
| `test_spending_policy`   | port       | Port from sessions repo                                     |
| `test_snip9_dual_hash`   | new        | OZ hash and felt-timestamp hash both accepted               |
| `test_phantom_bet_e2e`   | new        | Full Cifra bet flow with Ed25519 signer                     |

Target: **≥ 40 passing tests**, zero warnings, `scarb fmt --check` green, `snforge_std 0.56.0` pinned.

---

## 11. Milestones

| Week | Deliverable                                                                    |
|------|--------------------------------------------------------------------------------|
| 1    | `ISigner` trait + `ed25519` component ported; all V7 tests green on V8 class   |
| 2    | Audit fixes C-1, H-1, H-2, M-1/2/3/4, L-1, I-1/2/3; audit-response PR merged   |
| 3    | `SessionKey` + `SpendingPolicy` components ported from sessions repo           |
| 4    | `secp256k1` component + MetaMask e2e test                                      |
| 5    | `webauthn_p256` component + passkey e2e test                                   |
| 6    | Cifra flow e2e (Phantom, MetaMask, passkey all place a bet on testnet fork)    |
| 7    | External audit round 2 (Zellic / Nethermind — picked in parallel)              |
| 8    | Mainnet declare of all four classes, update `src/lib/constants.ts`             |

---

## 12. Ecosystem contribution

Two artifacts worth pitching upstream:

### 12.1 SNIP: Pluggable signer interface for smart accounts

Draft now, submit once V8 audit round 2 is clean. Covers:

- `ISigner` trait (3 methods: `verify`, `owner_commitment`, `signer_kind`)
- Canonical signer-kind constants (`'ED25519'`, `'SECP256K1'`, `'P256'`, `'STARK'`, `'RSA'`, `'BLS12_381_G1'` reserved)
- Signature-envelope format: first felt = kind tag, rest = curve-specific payload
- Interaction with SNIP-9: signer dispatcher runs after caller/time/nonce/bounds checks, before calls execution
- Interaction with Chipi sessions SNIP: session sigs coexist (4-element STARK-curve path unchanged)

This fills a real gap — Argent's multisig, OZ's STARK account, Chipi's paymaster, and Garaga-based Ed25519/WebAuthn accounts all roll their own. A SNIP lets paymasters do signer-type discovery and lets tooling (Starknet.js, Argent Wallet, Braavos) support non-STARK keys uniformly.

### 12.2 OpenZeppelin PR: Signer components

Contribute the four `signer_*` components to `openzeppelin-contracts-cairo`. OZ already has a skeleton `account/extensions/` module; signer variants are a natural fit. This also gives the V8 account credibility (OZ-shipped components = one less audit surface).

### 12.3 Positioning

- **For Starknet Foundation**: ties into the STRK20 consumer thesis — multi-signer = multi-chain users without bridging their identity. Good grant narrative.
- **For Cifra**: direct UX unlock — Phantom + MetaMask + passkey from day 1 = 10x addressable users.
- **For Chipi Pay**: sessions + pluggable signer = complete session-key story across any wallet type.

---

## 13. Risks & mitigations

| Risk                                                          | Mitigation                                                                                  |
|---------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| WebAuthn P-256 gas cost is untested in Garaga v1.0.1          | Benchmark on a devnet fork before committing; fallback is Chipi-hosted attestation if >50M  |
| Four class hashes = four declaration costs + four audits      | Share 90% of code; audit auditor-hours focus on ISigner + components; reuse V7 tests        |
| Signer-kind tag collision with existing session-sig format    | Reserve first-felt tag space; document in SNIP; session sigs always start with session_pubkey (guaranteed not to collide with curve names)  |
| Cifra launch depends on all three signers                     | Ship Ed25519 first (V7 parity), Secp256k1 + WebAuthn can follow in weeks 4-5                |
| External auditor rejects Design B (real SNIP-12)              | Sessions repo already implements real SNIP-12; reuse battle-tested code                     |
| Upstreaming SNIP takes > 6 months                             | Ship V8 under custom interface ID meanwhile; swap when SNIP lands                           |

---

## 14. Open questions

- **Multi-signer per account?** V8 is single-owner per class. Cifra users who want "Phantom OR passkey on same account" would need V9 (guardian model, Argent-style). Defer unless user research demands it.
- **Does Cifra need EIP-712 domain binding in WebAuthn?** Spec says challenge is the SNIP-12 hash — should it also bind an origin string?
- **Ed25519 session keys?** Sessions repo uses STARK curve for sessions (cheap). Do we want Ed25519 session keys for UX symmetry with the owner? Probably no — session keys are ephemeral and STARK is cheapest to verify on Starknet.
- **Remove the Chipi felt-timestamp fallback once AVNU upgrades?** Tech-debt clock.

---

## 15. Out of scope for V8 (tracked for V9+)

- Social recovery / guardian system
- Multi-owner (k-of-n)
- Upgradeability (intentionally immutable)
- Cross-account session delegation
- On-chain account discovery / ENS-like naming (separate `HandleRegistry` contract per Cifra spec)
