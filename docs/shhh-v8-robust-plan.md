# Shhh Wallet V8 — Robust-From-Day-One Plan

> **Status:** Proposal — supersedes the phased plan in `shhh-v8-design.md`
> **Authors:** Carlos Castillo (`@haycarlitos`)
> **Target repo:** [`haycarlitos/shhh-wallet-cairo`](https://github.com/haycarlitos/shhh-wallet-cairo)
> **Objective:** Ship *one* account contract that covers multi-signer, multi-curve, session keys, spending policies, and social recovery from day one — no V9 migration.
> **Audit anchors:** 2026-04-20 Codex/Cairo report (C-1, H-1, H-2, M-1..M-4, L-1, I-1..I-3); all 12 findings closed in this design.

---

## 1. Why "robust from day one"

The phased V8 design (four single-signer classes → V8.1 MultiSigner → V9 recovery) is tempting because each phase is small, but it has three long-term costs:

1. **Every phase is a migration event.** Users who deployed into a single-signer class in V8.0 must redeploy to pick up V8.1 multi-signer, and again for V9 recovery. Each migration means transferring STRK20 shielded notes, updating indexers, rewriting UX flows.
2. **Three audit cycles instead of one.** V8.0, V8.1, V9 = three rounds of auditor billable hours. Doing the harder design once is cheaper overall.
3. **The ecosystem narrative weakens.** The pluggable-signer SNIP pitch is stronger if the reference implementation demonstrates the full modular-account stack, not just a slice of it.

A single V8 class that encodes every robustness feature we'd eventually want — and ships correctly on day one — is the right target.

---

## 2. Target capability set

A robust V8 account MUST, on first deploy:

| Capability                                           | Included? | Rationale                                                              |
|------------------------------------------------------|-----------|------------------------------------------------------------------------|
| Multi-signer ownership (N owners per account)        | ✅ Yes    | Cifra users add signers over time — Phantom + passkey + Google         |
| Multiple signer kinds verifiable simultaneously      | ✅ Yes    | One account can trust Ed25519, Secp256k1, WebAuthn, STARK at once      |
| Add/remove/rotate signers                            | ✅ Yes    | Users change devices; losing one signer is not losing the account      |
| Weighted / threshold authorization                   | ✅ Yes    | Cifra Pro whales, DAO treasuries, family vaults need this              |
| Social recovery with guardians + timelock            | ✅ Yes    | "I lost my phone" — the single most-cited AA failure mode              |
| Session keys + spending policies (sessions SNIP #163) | ✅ Yes    | Gasless betting, copy-trading automation, daily-claim bots              |
| SNIP-9 V2 via SNIP-12 typed data                     | ✅ Yes    | Fixes audit H-2 at the spec level                                      |
| Deterministic addresses from primary signer          | ✅ Yes    | "Connect MetaMask" → recover same account, no server lookup            |
| Atomic multicall                                     | ✅ Yes    | Audit H-1                                                              |
| Bounded inputs (calls, calldata, signature)          | ✅ Yes    | Audit M-3                                                              |
| Paymaster-sponsored (AVNU + Chipi)                   | ✅ Yes    | Gasless UX                                                             |
| Immutable (no `upgrade()`)                           | ✅ Yes    | Audit I-3; recovery covers the "change account" failure mode           |
| Cryptographic agility (add new signer kinds later)   | ✅ Yes    | Future-proof against new curves / WebAuthn revisions                   |
| STRK20 privacy-pool integration                      | ✅ Yes    | Shielded notes are the Shhh/Cifra product                              |
| Upgradeability                                       | ❌ No     | Explicitly out per audit I-3; migration path via recovery + redeploy   |
| ZK-wrapped identity (JWT, email, TOTP)               | ❌ No     | Reserved kind tags in SNIP, but verifier circuits are research-stage   |

This set is what every other serious account contract in the ecosystem — Argent, Braavos, Cartridge Controller — has evolved toward over 2–3 years. Shhh can skip straight to it.

---

## 3. Architecture

### 3.1 One class, many verifiers (via `library_call`)

Instead of compiling every `ISigner` verifier into one fat class (bytecode bloat) *or* shipping one class per kind (migration tax), use Starknet's `library_call_syscall`:

```
┌────────────────────────────────────────────────────────────────┐
│                   ShhhAccount (single class)                   │
│                                                                │
│  State:                                                        │
│    owners: Map<owner_id, OwnerRecord>                          │
│    verifier_classes: Map<kind_tag, ClassHash>                  │
│    guardians, pending_recoveries, sessions, spending_policies  │
│                                                                │
│  verify(owner, sig):                                           │
│     class = self.verifier_classes[owner.kind]                  │
│     result = library_call(class, 'verify', [hash, sig])        │
│     return result                                              │
└────────────────────────────────────────────────────────────────┘
                 │
                 │ library_call (code runs in account's context)
                 │
   ┌─────────────┼─────────────┬──────────────┬───────────────┐
   ▼             ▼             ▼              ▼               ▼
┌────────┐  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌───────────────┐
│Ed25519 │  │Secp...  │  │WebAuthn  │  │STARK   │  │ future kind   │
│verifier│  │verifier │  │verifier  │  │verifier│  │ (added later) │
│ class  │  │ class   │  │ class    │  │ class  │  │               │
└────────┘  └─────────┘  └──────────┘  └────────┘  └───────────────┘
```

Each verifier is a **separately declared class** (Cairo contract exposing a single `verify(hash, sig) -> bool` entrypoint). The account stores a map of `kind_tag → trusted verifier class hash`. `library_call_syscall` runs the verifier's code in the account's own execution context (no cross-contract call overhead, no state changes).

**Benefits:**
- **Single class hash for the entire Shhh ecosystem.** One address-derivation formula. One audit target for the account logic.
- **Cryptographic agility.** When Garaga v1.1 releases a cheaper P-256 verifier, we declare it, and each account ratifies the swap with a single signed transaction. No redeployment.
- **Independent verifier audits.** Each verifier class is isolated; auditing a new kind doesn't re-open the account's audit.
- **Gas isolation.** A buggy verifier can't corrupt account storage (library_call runs in caller's context but is scoped by function signature).

**Security property:** the set of trusted verifier class hashes is governed by the **same threshold as `add_owner`**. A malicious verifier swap requires the same multi-sig threshold as adding a new owner — because in effect it *is* adding a new owner path.

### 3.2 The owner record

```cairo
#[derive(Drop, Copy, Serde, starknet::Store)]
struct OwnerRecord {
    kind: felt252,           // 'ED25519' | 'SECP256K1' | 'P256' | 'WEBAUTHN_P256' | 'STARK' | ...
    pubkey_hash: felt252,    // poseidon commitment of the pubkey bytes
    pubkey_ref: StorageRef,  // handle to full pubkey bytes in append-only bytes storage
    role: felt252,           // 'OWNER' | 'GUARDIAN' | 'RECOVERY_ONLY'
    weight: u8,              // for threshold schemes; 1 = standard owner
    added_at: u64,           // block timestamp; enforces timelock for new owners
    label: felt252,          // optional user-provided tag ('phone', 'yubikey', etc.)
}
```

The account maintains:
- `owners_count`, `threshold`, `guardian_count`, `guardian_threshold`
- `primary_owner_commitment` — frozen at deploy; used for address salt

### 3.3 Authorization policies

Every mutating operation has an explicit policy defining who can authorize it:

| Operation                              | Policy                                                          | Timelock  |
|----------------------------------------|-----------------------------------------------------------------|-----------|
| Normal tx (multicall)                  | Any single OWNER signature above threshold                      | None      |
| `add_owner(new_owner)`                 | Owner-threshold + timelock OR unanimous existing owners         | 48h       |
| `remove_owner(owner_id)`               | Owner-threshold OR unanimous remaining owners                   | 24h       |
| `rotate_owner(owner_id, new_record)`   | Owner-threshold                                                 | 24h       |
| `set_threshold(new_threshold)`         | Unanimous existing owners                                       | 48h       |
| `add_verifier_class(kind, class_hash)` | Unanimous existing owners (cryptographic agility)               | 48h       |
| `remove_verifier_class(kind)`          | Owner-threshold                                                 | 24h       |
| `add_guardian(guardian_record)`        | Owner-threshold                                                 | 24h       |
| `remove_guardian(guardian_id)`         | Owner-threshold                                                 | 24h       |
| `initiate_recovery(new_owner)`         | Guardian-threshold                                              | 7d        |
| `cancel_recovery()`                    | Any single OWNER signature                                      | Immediate |
| `finalize_recovery()`                  | Anyone (permissionless execute after timelock)                  | —         |
| `add_session_key(...)`                 | Any single OWNER signature                                      | None      |
| `revoke_session_key(...)`              | Any single OWNER signature OR the session key itself            | None      |
| `set_spending_policy(...)`             | Any single OWNER signature                                      | None      |
| **`upgrade()`**                        | **Not supported. Account is immutable.**                        | —         |

Timelocks are enforced in `__execute__` / `execute_from_outside_v2` by storing pending operations with a `valid_after` timestamp. Owners can cancel any pending operation with a signed `cancel_pending_op(op_id)` during the window — this is the anti-social-engineering defense.

### 3.4 Social recovery

Recovery is **guardian-initiated with a timelock the owner can abort**:

```
 t=0   Guardians meet threshold and call initiate_recovery(new_owner_record)
       → account stores pending_recovery { new_owner, valid_after = now + 7d }
       → notifications fire (on-chain event + off-chain push)

 t<7d  Original owner can call cancel_recovery() at any time with ONE signature
       → pending_recovery wiped, status quo restored

 t=7d  Anyone can call finalize_recovery()
       → new_owner added with role=OWNER, weight=1
       → original owners are NOT removed; this is additive recovery
       → user is expected to follow up with remove_owner() for lost devices
```

This matches Argent's battle-tested pattern and gives owners 7 days to detect and reverse a guardian compromise.

### 3.5 Session keys + spending policies

Ported verbatim from [starknet-io/SNIPs#163](https://github.com/starknet-io/SNIPs/pull/163):

- `SessionKeyComponent` — per-session storage, admin blocklist, self-call block, selector whitelist.
- `SpendingPolicyComponent` — per-(session, token) caps with rolling window.
- The admin blocklist expands to include `add_owner`, `remove_owner`, `add_verifier_class`, `set_threshold`, `initiate_recovery`, `finalize_recovery` — session keys MUST NOT touch governance operations.
- Session keys remain STARK-curve (cheapest verification) regardless of owner kind.

### 3.6 Signature routing

| `signature.len()` | Interpretation                                                         |
|-------------------|------------------------------------------------------------------------|
| 0                 | Self-call (accept only if `caller == self`)                            |
| 4                 | Session-key signature per SNIP #163                                    |
| ≥ 2, ≠ 4          | Owner envelope: `[owner_id, kind_tag, curve_payload...]`               |

The owner envelope prepends an `owner_id` so the account knows *which* of its registered owners signed, without scanning the whole owner set.

For **threshold** operations, the signature is a concatenation of owner envelopes: `[n_sigs, envelope_1, envelope_2, ...]`. Each envelope is verified independently; the account counts unique owner_ids and checks the weight sum against the threshold.

### 3.7 SNIP-9 V2 integration

Every owner-authorized action goes through `execute_from_outside_v2`:

1. Caller check (`'ANY_CALLER'` OR `caller == oe.caller`; `caller == 0` rejected per audit M-1).
2. Time-window bounds + 2h cap for `'ANY_CALLER'` (audit M-2).
3. Nonce replay check (SRC9 map).
4. Size bounds: MAX_CALLS=16, MAX_TOTAL_CALLDATA=1024, MAX_SIG_FELTS=1024 per envelope (M-3).
5. Compute SNIP-12 typed-data hash (fixes H-2).
6. Parse owner envelope(s), `library_call` into each verifier, sum weights, compare against operation policy threshold.
7. Atomic multicall — panic on any subcall failure (H-1).

### 3.8 Deterministic addresses

```
address = compute_address(
    class_hash = ShhhAccount_class_hash,
    salt       = poseidon([primary_kind, primary_pubkey_hash]),
    calldata   = [primary_kind, primary_pubkey_hash, primary_pubkey_bytes_len, ...],
)
```

The **primary owner** (the one specified at deploy) binds the address. Adding or removing owners later never changes the address. This preserves the "connect MetaMask → always get the same Starknet address" property while allowing full owner-set evolution post-deployment.

---

## 4. Storage layout

```cairo
#[storage]
struct Storage {
    // --- Core identity ---
    primary_kind: felt252,
    primary_pubkey_hash: felt252,
    deployed_at: u64,

    // --- Owner set ---
    owners: Map<u32 /* owner_id */, OwnerRecord>,
    owners_count: u32,
    threshold: u8,                    // weight threshold for normal ops
    owner_by_hash: Map<felt252, u32>, // pubkey_hash → owner_id for fast lookup

    // --- Guardians ---
    guardians: Map<u32, OwnerRecord>,
    guardians_count: u32,
    guardian_threshold: u8,

    // --- Verifier registry ---
    verifier_classes: Map<felt252 /* kind_tag */, ClassHash>,

    // --- Pending operations (timelocked) ---
    pending_ops: Map<felt252 /* op_id */, PendingOp>,

    // --- Pending recovery ---
    pending_recovery: Option<PendingRecovery>,

    // --- SRC9 nonces ---
    #[substorage(v0)]
    src9: SRC9Component::Storage,

    // --- Session keys + spending policy ---
    #[substorage(v0)]
    session_key: SessionKeyComponent::Storage,
    #[substorage(v0)]
    spending_policy: SpendingPolicyComponent::Storage,

    // --- SRC5 introspection ---
    #[substorage(v0)]
    src5: SRC5Component::Storage,
}
```

Key invariants (asserted on every mutation):
- `owners_count >= 1` — cannot brick the account by removing all owners.
- `threshold >= 1 && threshold <= sum(owners.weight)` — cannot make ops impossible.
- `guardian_threshold >= 1 && guardian_threshold <= guardians_count` when guardians exist.
- `primary_kind ∈ verifier_classes.keys()` — the founding signer kind is always verifiable.
- No pending op can be executed before `valid_after`.

---

## 5. Operations catalog

| Entrypoint                              | Access          | Description                                                         |
|-----------------------------------------|-----------------|---------------------------------------------------------------------|
| `execute_from_outside_v2(oe, sig)`      | Public          | Primary auth path. Verifies sig(s), executes atomic multicall.      |
| `__execute__(calls)`                    | Self + protocol | Hardened per audit C-1. Used by paymaster estimation path only.     |
| `__validate__(calls)`                   | Protocol        | Always reverts (NOT_SUPPORTED) — route via OE.                      |
| `propose_op(op)`                        | Self            | Creates a timelocked pending op.                                    |
| `execute_pending_op(op_id)`             | Anyone          | Executes after `valid_after`.                                       |
| `cancel_pending_op(op_id)`              | Self            | Owner-threshold cancels any pending op within its timelock.         |
| `initiate_recovery(new_owner)`          | Guardian-thresh | Starts 7-day recovery timer.                                        |
| `cancel_recovery()`                     | Self            | Any single owner aborts recovery.                                   |
| `finalize_recovery()`                   | Anyone          | After 7d, adds new_owner.                                           |
| `add_verifier_class(kind, hash)`        | Self (unanimous)| Ratifies a new signer kind into the verifier registry.              |
| `remove_verifier_class(kind)`           | Self (thresh)   | Removes a kind (cannot remove primary).                             |
| `add_session_key / revoke / set_policy` | Self            | Per sessions SNIP.                                                  |
| View: `get_owner(id)`, `is_valid_signature(hash, sig)`, `owner_commitment()`, `signer_kind()` | Public | Standard introspection per SNIP-5 / SNIP-6. |

---

## 6. Security considerations

### 6.1 Audit-finding coverage

| Finding | Mitigation in this design                                                                  |
|---------|---------------------------------------------------------------------------------------------|
| C-1     | `__execute__` guarded with `caller.is_zero() \|\| caller == self` + tx-version check.       |
| H-1     | Multicall panics on any subcall failure.                                                    |
| H-2     | SNIP-12 typed-data hashing; correct ISRC9_V2 interface ID registered.                       |
| M-1     | `caller == 0` rejected; only `'ANY_CALLER'` is the unrestricted sentinel.                   |
| M-2     | 2h cap on `'ANY_CALLER'` validity; unrestricted-caller ops require explicit window.         |
| M-3     | MAX_CALLS=16, MAX_TOTAL_CALLDATA=1024, MAX_SIG_FELTS=1024 per envelope.                     |
| M-4     | Post-Serde emptiness check; explicit length bounds before indexing into msg bytes.          |
| L-1     | Constructor validates primary_pubkey material via the primary verifier's own deploy check. |
| I-1     | Custom Poseidon packing removed; SNIP-12 typed data is the sole hashing path.               |
| I-2     | RFC 8032 / secp256k1 / P-256 negative-vector tests per verifier class.                       |
| I-3     | No `UpgradeableComponent`. Immutable per class.                                              |

### 6.2 New attack surfaces introduced by robustness features (and how they're closed)

| Risk                                                                | Mitigation                                                                                 |
|---------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| Malicious verifier class injected into registry                     | `add_verifier_class` requires **unanimous** existing owners + 48h timelock                 |
| Guardian collusion (fake "lost device" takeover)                    | 7-day timelock + owner's `cancel_recovery` + on-chain event + off-chain push notifications |
| Owner set reduced to zero via repeated `remove_owner`               | Invariant check: `owners_count >= 1` always                                                |
| Threshold set to 0 or above total weight                             | Invariant check: `1 <= threshold <= sum(weight)`                                           |
| Replay of signature across owners                                   | Owner envelope includes `owner_id`; accepted only once per operation                       |
| `library_call` to a verifier that mutates caller storage            | Verifier classes expose `verify` only; audit each verifier for storage-touching syscalls   |
| Cross-kind address collision                                        | Salt binds `primary_kind` into address derivation                                          |
| Session key abuses `initiate_recovery` or `add_verifier_class`      | Admin blocklist extended; all governance selectors blocked for sessions                    |
| Timelock bypass via reordering                                      | Pending ops store `valid_after` at creation, re-checked at execution                       |
| Signature malleability (high-s secp256k1, small-subgroup Ed25519)   | Per-verifier canonical-form enforcement (Garaga primitives already do this)                |
| Griefing via oversize envelopes                                     | M-3 bounds applied before any hashing or library_call                                      |

### 6.3 Invariants to prove (property tests)

1. If `verify(owner, sig)` returns true, then `sig` was produced with the private key corresponding to the public key stored under `owner`.
2. No non-authorized call can mutate `owners`, `threshold`, `verifier_classes`, `pending_recovery`.
3. `execute_pending_op` can only run after `block.timestamp >= pending_op.valid_after`.
4. `cancel_recovery` removes `pending_recovery` entirely — no residual state.
5. `finalize_recovery` adds exactly one owner and leaves existing owners intact.
6. After any successful `execute_from_outside_v2`, the nonce is consumed and cannot be replayed.
7. After any reverted `execute_from_outside_v2`, the nonce is **not** consumed (this matters because the sessions SNIP does mid-validation state mutation).

---

## 7. Test plan

### 7.1 Unit / component tests

| Suite                           | Scope                                                               | Target count |
|---------------------------------|---------------------------------------------------------------------|--------------|
| `test_signer_ed25519`           | RFC 8032 + Garaga hint malformations                                | 15           |
| `test_signer_secp256k1`         | Valid + high-s + wrong key + envelope malleability                  | 12           |
| `test_signer_p256`              | Valid + invalid-point + tampered ClientDataJSON (WebAuthn variant)  | 15           |
| `test_signer_stark`             | Valid + wrong key                                                   | 4            |
| `test_verifier_registry`        | add/remove verifier, blocklist session-key selectors                | 10           |
| `test_owner_set`                | add/remove/rotate, threshold invariants, primary-owner immutability | 18           |
| `test_recovery`                 | Happy path + cancel + guardian collusion + timelock bypass          | 12           |
| `test_pending_ops`              | Timelock enforcement, owner cancel, race conditions                 | 10           |
| `test_session_key`              | Port from sessions repo                                             | ~25          |
| `test_spending_policy`          | Port from sessions repo                                             | ~10          |
| `test_src9_v2`                  | SNIP-12 hash, nonce replay, time window, caller sentinel            | 15           |
| `test_audit_2026_04_20`         | Regression for every finding (PoC-style)                            | 12           |
| `test_e2e_cifra`                | Phantom bet, MetaMask bet, passkey bet, session auto-bet            | 8            |

**Target: ≥ 170 tests, all green, zero warnings, `scarb fmt --check` passing.**

### 7.2 Property / fuzz tests (Starknet Foundry `#[fuzzer]`)

1. **No unauthorized mutation.** Fuzz arbitrary callers, arbitrary calldata → `owners` storage unchanged unless caller = self + valid multi-sig.
2. **Threshold math.** Fuzz owner weights + threshold → authorization returns true iff weight sum ≥ threshold.
3. **Timelock monotonicity.** Fuzz `valid_after` and `block.timestamp` → execution accepts iff `now >= valid_after`.
4. **Nonce unforgeability.** Fuzz signature spans → no valid signature exists for a random hash other than those produced by registered owners.
5. **Envelope robustness.** Fuzz oversize / truncated / wrong-kind envelopes → all controlled reverts, no panics with cryptic errors.

### 7.3 Mutation tests (manual script)

Following Omar's Section "Tooling and Test Hardening" suggestions — a small `scripts/mutate.py` that inverts each guard and confirms the test suite fails. Target guards:
- `caller.is_zero()` in `__execute__`
- Subcall panic in multicall
- Nonce duplicate check in SRC9
- Threshold comparison
- Timelock comparison (`>=` vs `>`)
- Admin blocklist membership checks
- Verifier-class authorization check

Every mutant must cause ≥ 1 test failure. Automated in CI.

---

## 8. Audit strategy

| Round | Scope                                                                                | Auditor options        | Target date      |
|-------|--------------------------------------------------------------------------------------|------------------------|------------------|
| 1     | Audit response + full V8 robust design                                               | Codex (Omar)           | Before mainnet declare |
| 2     | Independent deep-dive on recovery, threshold, verifier registry                      | Zellic / Nethermind    | Pre-Cifra launch |
| 3     | Formal-methods-lite pass on timelock state machine + invariants                      | Nethermind / Kudelski  | Optional, H2 2026|

Budget: $60–120k across rounds 1+2; round 3 deferred unless Cifra TVL > $5M.

---

## 9. Milestones

| Week | Milestone                                                                    | Deliverable                                      |
|------|------------------------------------------------------------------------------|--------------------------------------------------|
| 1    | Branch `v8-robust` on `haycarlitos/shhh-wallet-cairo`; `ISigner` trait + STARK verifier class | First verifier declared on mainnet testnet fork  |
| 2    | Ed25519 verifier class (Garaga port from V7); owner set component             | `test_owner_set` green, V7 Phantom fixture working on V8 |
| 3    | Secp256k1 verifier class; envelope parser; library_call dispatcher           | `test_signer_secp256k1` + 2-verifier account     |
| 4    | WebAuthn P-256 verifier class; ClientDataJSON parser                         | Cifra Face ID e2e on testnet                     |
| 5    | Session keys + spending policy components ported from sessions repo          | `test_session_key`, `test_spending_policy` green |
| 6    | Guardian component + recovery state machine + timelock engine                | `test_recovery` green                            |
| 7    | SRC9 V2 hardening (SNIP-12, bounds, caller rules); audit-regression suite    | All 12 audit findings fixed with regression tests |
| 8    | Property tests + mutation tests; CI pins Scarb 2.14 + snforge 0.56           | CI green on 5 parallel matrices                  |
| 9    | Round 1 audit with Omar / Codex; fix round                                   | Audit report + diff                              |
| 10   | Round 2 audit with independent firm; fix round                               | Clean audit                                      |
| 11   | Cifra frontend integration (signer selection, connect flow, recovery UX)     | Working `cifra.mx` on testnet                    |
| 12   | Mainnet declare of V8 class + verifier classes; deployment factory           | Class hash published, constants updated          |

**Total: 12 weeks solo.** Cuts to ~8 weeks with +1 Cairo engineer.

---

## 10. Cifra alignment

Mapping Cifra's UX promises to V8 capabilities:

| Cifra promise                                      | V8 capability that delivers it                                            |
|----------------------------------------------------|---------------------------------------------------------------------------|
| "Sign up with Face ID"                             | WebAuthn verifier + deterministic address                                 |
| "Connect Phantom / MetaMask"                       | Ed25519 / Secp256k1 verifier + deterministic address recovery             |
| "Later add a passkey for convenience"              | `add_owner` operation with timelock                                       |
| "Lost my phone" (support case)                     | Guardian-initiated recovery + 7d owner cancellation window                |
| "Gasless betting"                                  | Session keys + Chipi/AVNU paymaster via SNIP-9 V2                         |
| "Copy-trade bot follows leader X"                  | Session key scoped to `place_bet` + spending policy                       |
| "Pro whale: 2-of-3 multisig for bets over 10k USDC"| Weighted owner set + per-amount authorization policy                      |
| "Private bet size via STRK20"                      | Wallet holds shielded notes; account address never changes through owner rotation |

---

## 11. Ecosystem deliverables

Shipping V8 robust also means shipping three artifacts to the Starknet ecosystem:

1. **Pluggable Signer SNIP** (draft in `docs/snip-draft-pluggable-signer.md`): reference implementation = V8 verifier classes.
2. **OpenZeppelin contribution**: `account/verifiers/` module with Ed25519, Secp256k1, WebAuthn, RSA, BLS components. PR after round 2 audit.
3. **Reference recovery pattern**: document the guardian + timelock state machine as a reusable blueprint — this is the capability most in demand from builders polling Starknet Discord and has no canonical reference.

---

## 12. Open questions for Omar (before freeze)

1. **Verifier-class library_call** — any objection? It's the natural way to get cryptographic agility without upgradeability.
2. **Unanimous approval for `add_verifier_class`** — is this too strict? Alternative: threshold with doubled timelock (e.g., 14 days).
3. **Recovery window length** — 7 days is Argent-aligned but feels long for a LATAM consumer product. Is 72 hours defensible?
4. **Envelope format for threshold sigs** — `[n_sigs, env_1, env_2, ...]` vs. tagged map. Any precedent in sessions SNIP discussion we should mirror?
5. **Should the primary owner be special** (immutable / higher weight / only-one-with-recovery-cancel-power), or symmetric with other owners after deploy?

---

## 13. Risks

| Risk                                                                | Mitigation                                                                              |
|---------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| Scope creep blows the 12-week schedule                              | Hard gate: every capability in §2 has a test before we accept new features.             |
| Audit surface is too large for one round                            | Split into structured rounds; Omar on the account core, external firm on recovery math. |
| Library_call gas cost exceeds simple per-class dispatch             | Benchmark in week 3; fall back to one-class-per-kind if dispatch > 2M l2_gas overhead.  |
| Garaga primitives regress in future releases                        | Pin exact Garaga version per verifier class; upgrade = new verifier class + ratification. |
| Timelock UX feels slow to retail users                              | Session keys + sub-threshold operations (like single-owner normal tx) cover the hot path. |
| Cifra launch depends on V8 being live                               | V7 stays in production during V8 development; migration is opt-in per user.             |
| Regulators flag recovery as custodial                               | Guardians are user-chosen; recovery is permissionless post-timelock; Panama entity unchanged. |

---

## 14. Success criteria

V8 robust is done when all of the following are true:

- ✅ All 12 audit findings have regression tests, all green.
- ✅ ≥ 170 tests passing, including Cifra e2e flows for Phantom / MetaMask / passkey.
- ✅ Two independent audit rounds clean.
- ✅ Mainnet declare of V8 + 4 verifier classes (Ed25519, Secp256k1, P-256/WebAuthn, STARK).
- ✅ Pluggable Signer SNIP opened as a PR against `starknet-io/SNIPs` with V8 as the reference impl.
- ✅ Cifra `cifra.mx` testnet bet flow works end-to-end with all three signer methods.
- ✅ A user can: sign up with passkey → add Phantom later → lose passkey → recover via guardians → remove the lost passkey. All on mainnet.
- ✅ Class hash is published and immutable; no plans for V9 for at least 12 months.

---

## Appendix A: What this supersedes

- `docs/shhh-v8-design.md` — initial four-class plan. Still useful as a simpler reference, but the "V9 deferred" items (multi-signer, recovery) are now in scope for V8.
- Memory notes describing V7 as "self-custodial, single-owner, immutable" — V8 preserves self-custody and immutability but adds multi-owner and recovery.

## Appendix B: Non-goals (explicit)

- Upgradeability of the account class itself — intentionally out, per audit I-3. Migration is via recovery-to-new-class if ever needed.
- ZK-wrapped identity kinds (`ZK_JWT`, `ZK_EMAIL`, `ZK_TOTP`) — kind tags reserved in the SNIP, circuits deferred.
- Multi-tenant accounts (one account shared by multiple humans) — out; use separate accounts.
- Fiat on-chain KYC hooks — lives in an adjacent contract, not the wallet.
- Full formal verification of Ed25519 / secp256k1 arithmetic — rely on Garaga's audits.
