# V8.4 audit entry — start here

> **Purpose**: orient an external auditor to the V8.4 ShhhAccount + 10 V8.2 verifier classes. After ~30 minutes with this doc + the recommended reading path, you should have a working map of the scope, threat model, and known surface — enough to plan your review.
>
> **Status**: V8.4 closes five internal review cycles (2026-04-13 → 2026-05-14). External audit is the next milestone. Pre-declare verdict from the most recent self-review (2026-05-14): **READY TO DECLARE**. V8.4 declared on Starknet mainnet 2026-05-15.

---

## 1. Pinned reference

| Item | Value |
|---|---|
| Repo | `haycarlitos/shhh-wallet-cairo` |
| Tag / commit | `v8.4` / `3975532` |
| Branch | `v8-robust` (will roll up to `main` post-audit) |
| Toolchain | Scarb `2.14.0`, Cairo `2.14`, Sierra `1.7`, snforge `0.59.0` |
| `snforge test` baseline | **259 passed, 0 failed, 0 ignored** at this commit |

**V8.4 class hash (mainnet)**: `0x075dfb396145926bffa6beb659897f46cc082a50b211d80871cff7f1038fa58a` — declared 2026-05-15, declare tx [`0x0737570e…ea0dfd`](https://voyager.online/tx/0x0737570e0430bed8e21c05bcb88a6f649f99d8a5f3d36dd0350a0dd172ea0dfd), block 9,787,252, fee 43.67 STRK.

**Ten verifier class hashes (mainnet)** — all declared 2026-05-18 (see [`docs/class-hashes.md`](./class-hashes.md) for the full table + reproduction recipe):

```
STARK               0x00d09209b2da9d49fc805ba26380ba4ce25aa641116c10eb178e1051a71dbf68
ED25519             0x030a7dfc03e59cef6e41699e734abd2df53ce393a052221c02c6e07665949f74
SECP256K1           0x03e81667a46bd5287e09a9600fa98d28fdc477735f2689f5f4e8e95f37b67b74
EIP191_SECP256K1    0x03a75997862059c36cb8e204fb3027eb6d1fdf933488d42c2db4528118d084e6
EIP712_SECP256K1    0x072a3f77e8c28bfea2ade91ec3fb83b6290169d1ed8c1b2396704231841c6474
P256                0x01b600709af54c8838e5f18ddad3a26feeb47cb124c239f55a0f1b7a780e2d8a
WEBAUTHN_P256       0x074f6efd2af9025cd8cab41a4565bc73b6ef097214c31352838fcdbac0a44657
JWT_ES256           0x002efce875fa3e73e04d825d8ebade53e188cc995dfe0c55a6a2f7fa6c59f497
JWT_ES256_APPLE_SUB 0x06b67762218a25fdd28e25b063480893a5cef9cdeecbc663e32d444d5734c471
BLS12_381           0x02623721e74a9ad3e0ba639065f5631a09bf900913de6ab21ea6984973cd2cd1
```

Hashes are deterministic outputs of `scarb build` at this commit; they're reproducible byte-for-byte (recipe: `docs/class-hashes.md §"How to reproduce"`).

---

## 2. Scope

### In scope

- `src/account.cairo` — V8.4 ShhhAccount class
- `src/signer/interface.cairo` + the ten `src/signer/<kind>/verifier.cairo` files
- `src/governance/`, `src/recovery/`, `src/session_key/`, `src/owner_set/`, `src/outside_execution.cairo`
- `tests/` (correctness reference; positive + negative + adversarial fixtures)
- The five audit response letters in `docs/audit-response-*.md`

### Out of scope

- **V8.0 / V8.1 / V8.2 / V8.3 ShhhAccount classes** — deprecated for new deploys but kept declared for legacy recognition. They have known unfixed-in-class findings (V8.1 lacks M-1 `validate_pubkey`; V8.0 has unfixed C-1 + H-1). No production accounts deployed against them per Shhh tracking. New deploys MUST use V8.4.
- **V7 ShhhWallet** (`0x2e599…ca9a13`) — single-kind Ed25519-only account from the 2026-02 batch. Already mainnet-audited under a separate scope. Retained on chain for existing users; not the redeploy target.
- **`chipi-pay/sessions-smart-contract`** — counterparty class. V8.4's `bootstrap_from_sessions_signed` reads its preserved `Account_public_key` storage slot but doesn't modify it. Sessions class has its own audit history.
- **Off-chain TypeScript glue** (`scripts/ts/`, `_internal/`, `haycarlitos/shhh` frontend) — useful as integration reference but not part of the Cairo audit surface.

### Threat model — top-level

V8.4 is a self-custodial account class. The wallet's job is to authenticate that an off-chain signer authorized a specific on-chain action, then execute it atomically. Critical properties:

1. **Only the registered owner can sign arbitrary OEs.** No path lets an unregistered key, a guardian, or a recovery-only role take generic actions. (Audit C-1.)
2. **Signer verification can't be bypassed.** Every OE goes through `library_call_syscall` to a registered verifier; there's no fallback path that skips it.
3. **Atomicity.** OE multicall is all-or-nothing; partial execution can't leave the wallet stranded for legitimate flows. (Audit H-1.)
4. **Replay protection.** OE nonce dedup, 2h validity window cap for `caller='ANY_CALLER'` OEs (audit M-2).
5. **Verifier-class reentrancy is bounded.** A malicious verifier class can't re-enter `_assert_self_call`-gated mutators while a `library_call` is on the stack (`inside_verifier` flag, audit M-2).
6. **Pubkey validation at registration.** Every owner add / rotate / recover validates the new pubkey via the verifier's `validate_pubkey` (audit M-1).
7. **Timelocked governance.** 48h for owner add/remove/rotate/verifier add, 7d for recovery finalize, with permissionless cancel by any active owner during the window.
8. **No upgrade path.** V8.4 deliberately ships without an `upgrade` selector; migration from a deprecated class is fresh-address deploy + funds transfer.

The detailed invariant list lives in [`docs/audit-response-2026-05-10.md`](./audit-response-2026-05-10.md). Read that letter early — it's the canonical record of what the prior reviews tightened.

---

## 3. Recommended ~30-minute reading path

In this order, you should walk away with a working mental model:

1. **This doc** (you're here) — 5 min.
2. **[`docs/snip-draft-pluggable-signer.md`](./snip-draft-pluggable-signer.md)** — 5 min. The standards-track spec under which V8 sits. Three parts: Part A (`ISigner` trait), Part B (kind-tag registry), Part C (envelope format).
3. **[`docs/audit-response-2026-05-10.md`](./audit-response-2026-05-10.md)** — 10 min. The canonical record of which audit findings closed at which commit; lists the audit-mapped assertions in source.
4. **`src/account.cairo`**, focused on:
   - Lines 60-110: storage layout + `LEGACY_OZ_ACCOUNT_PUBKEY_SLOT` const
   - Lines 263-306: constructor
   - Lines 340-540: `execute_from_outside_v2` (the only user-facing entry) — this is the dispatcher. Walk every `assert` and the `library_call` site.
   - Lines 1025-1180: `bootstrap_from_sessions` + `bootstrap_from_sessions_signed` (V8.4-specific; stranded-state migration recovery)
   - Lines 1380-1430: `_is_single_initiate_recovery_call` (V8.4 guardian-OE carve-out)
   - Lines 1430-1470: V8 admin selector blocklist (`_v8_blocklist_ok`)
5. **`src/signer/interface.cairo`** — 2 min. Three trait methods: `verify`, `kind`, `validate_pubkey`. Constants `KIND_STARK`, `KIND_ED25519`, etc.
6. **One verifier as a worked example** — `src/signer/stark/verifier.cairo` (~50 lines, the simplest) or `src/signer/webauthn_p256/verifier.cairo` (~430 lines, the most complex). Each verifier is independently auditable.
7. **`tests/account_migration.cairo`** — 5 min. The 17 tests around the V8.4 stranded-bootstrap recovery, including the audit-C-1 PoC `audit_poc_attacker_can_seize_any_stranded_wallet` that the gate now blocks.

Total: ~30 minutes to get oriented.

---

## 4. Prior internal review cycles

All findings closed; review files in [`audits/`](../audits/).

| Date | Auditor | Findings | Status |
|---|---|---|---|
| 2026-04-13 | Henri (Nethermind audit-agent scan) — [`audits/2026-04-13-henri-nethermind-auditagent-scan.pdf`](../audits/2026-04-13-henri-nethermind-auditagent-scan.pdf) | Initial baseline; pre-V8 surface | Reviewed |
| 2026-04-20 | Omar Espejel (Codex) — [`audits/2026-04-20-omar-espejel-codex-audit.md`](../audits/2026-04-20-omar-espejel-codex-audit.md) | Single-kind V7 audit; carryover findings folded into V8 work | Reviewed |
| 2026-05-07 | Claude Opus pre-Phase-13 self-review — [`audits/2026-05-07-claude-opus-pre-phase13-review.md`](../audits/2026-05-07-claude-opus-pre-phase13-review.md) | 1 Crit (C-1) + 3 Highs (H-1/H-2/H-3) + 3 Meds (M-1 partial, M-2, M-3) + 1 Low + 6 Info | All Crit/High closed at V8.1; M-1 fully closed at V8.2 |
| 2026-05-10 | Claude Opus V8.2 review — [`audits/2026-05-10-claude-opus-v8-2-review.md`](../audits/2026-05-10-claude-opus-v8-2-review.md) | H-1 finalize_recovery, M-1 symmetric inside_verifier, M-2 bootstrap_from_sessions, M-3 evil-verifier negative tests | Closed at V8.3 |
| 2026-05-12 | Claude Opus V8.4 pre-merge — [`audits/2026-05-12-claude-opus-v8-4-review.md`](../audits/2026-05-12-claude-opus-v8-4-review.md) | 1 Crit (C-1: `bootstrap_from_sessions_signed` missing pubkey-binding) + 1 Low (L-1) | Closed at the V8.4 commit (pre-declare) |
| 2026-05-14 | Claude Opus V8.4 pre-declare re-review — [`audits/2026-05-14-claude-opus-v8-4-pre-declare-audit.md`](../audits/2026-05-14-claude-opus-v8-4-pre-declare-audit.md) | 2 Info (defense-in-depth gaps, no realistic exploit) | **Verdict: READY TO DECLARE** |

Audit attribution disclaimer: the AI-assisted reviews don't claim third-party endorsement. They were authored by the maintainer with AI assistance. The repo is explicit about this in `audits/README.md`.

---

## 5. Known residual surface

Items the prior reviews accepted as residual + things worth your independent eye:

1. **INFO-1 (2026-05-14)** — `bootstrap_from_sessions_signed` does not consult `inside_verifier`. Documented as a defense-in-depth gap with no realistic exploit path; deferred to V8.5 as optional. See `audits/2026-05-14-claude-opus-v8-4-pre-declare-audit.md`.
2. **INFO-2 (2026-05-14)** — All V8 components use `#[substorage(v0)]`; if a future component declared a field named `Account_public_key`, it would collide with the C-1 fix slot. Mitigated by docstring at `src/account.cairo:104`; recommended migration to namespaced substorage in V9.
3. **Governance compromise scenario** — A timelocked-but-effective compromise of the owner set could register a malicious verifier class and (via 48h wait) gain owner-add rights. Documented threat: the 48h cancellation window + any-active-owner cancel is the user's only recourse. Worth a focused look.
4. **No `upgrade` selector** — Deliberate. Means V8.4 can never patch itself in place. If your review finds a Critical, V8.5 will be a fresh-address opt-in deploy with a separate `bootstrap_from_v8.4` primitive (analogous to today's `bootstrap_from_sessions_signed`). Worth confirming the migration plan is sound.
5. **Chipi paymaster behavior, off-chain but adjacent** — During Cycle-1 smoke testing (2026-05-18), we observed `paymaster_executeSponsoredRaw` silently swallows inner-OE reverts and returns top-level `SUCCEEDED`. Not a Cairo finding, but worth flagging in your report because it affected our own diagnostic loop. See [`docs/v8-3-smoke-tests.md`](./v8-3-smoke-tests.md) §"Two corrections."

---

## 6. Mainnet status as of 2026-05-19

Real (trace-verified) Cycle-1 receipts via Chipi paymaster on V8.4:

| Test | Kind | OE tx | Inner revert? |
|---|---|---|---|
| 1 | STARK (V8.1 carry-forward) | `0x0625297020…00c9` | No |
| 1a | V8.4 deploy state-readback | `0x02670017…0c568a6` | n/a |
| 15 | STARK on V8.4 + Chipi | `0x5dc71618…aa4daf4f` | No (trace-verified) |
| 3 | EIP-191 MetaMask `personal_sign` | `0x677f414e…4993b15` | No (trace-verified) |
| 2 | ED25519 Phantom (Garaga v1.0.1) | `0x7472be95…25f86dbb` | No (trace-verified) |
| 7 | WEBAUTHN_P256 synthesized passkey | `0x34d6c4f1…cdb2695e` | No (trace-verified) |
| 11 | `propose_add_owner` (48h timelock, execute opens 2026-05-20T23:28Z) | `0x6bd9aeb0…3c6a66ad4` | No (trace-verified) |

Full receipt blocks + reproduction scripts in [`docs/v8-3-smoke-tests.md`](./v8-3-smoke-tests.md). Smokes are *empirical evidence*, not a substitute for code review — every kind dispatches into a separate verifier you should still walk through.

---

## 7. Build + repro

```bash
git clone https://github.com/haycarlitos/shhh-wallet-cairo
cd shhh-wallet-cairo
git checkout v8.4   # tag at commit 3975532
scarb --version     # expect 2.14.0
snforge --version   # expect 0.59.0
scarb build
snforge test        # expect 259 passed, 0 failed
```

Class-hash reproduction:

```bash
for c in ShhhAccount StarkVerifier Ed25519Verifier Secp256k1Verifier \
         EIP191Secp256k1Verifier EIP712Secp256k1Verifier P256Verifier \
         WebAuthnP256Verifier JwtES256AppleVerifier \
         JwtES256AppleSubVerifier Bls12_381MinSigVerifier; do
  sncast utils class-hash --contract-name "$c"
done
```

Output must match the hashes in §1 byte-for-byte. If not, toolchain has drifted from the pinned versions in `Scarb.toml`.

---

## 8. Contact

- Maintainer: Carlos Castillo — `carlos@chipipay.com`
- Issues: file against `haycarlitos/shhh-wallet-cairo` with the `audit` label, or ping the maintainer directly
- Audit-response artifact: the canonical record of which findings closed at which commit is [`docs/audit-response-2026-05-10.md`](./audit-response-2026-05-10.md). Treat that as the source of truth when comparing your findings against prior closure.
