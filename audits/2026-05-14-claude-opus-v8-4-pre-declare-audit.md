# V8.4 Pre-Declare Audit — `v8-robust` post-merge (audit-response delta)

**Date:** 2026-05-14
**Auditor:** Claude Opus 4.7 (1M context), adversarial re-review of fix commits after the 2026-05-12 V8.4 pre-merge audit
**Scope:** `v8-robust @ f573290` (squash-merged PR #10). ONLY the audit-response delta from the 2026-05-12 review is in scope; the V8.4 initial commits (`d8baac2`, `0440e78`, `cacd0c8`) were covered by the prior audit. Five commits in scope:
  - `190afaa` — `audits: V8.4 pre-merge review + README update through 2026-05-12`
  - `4876aa7` — `fix(v8.4): bind bootstrap_from_sessions_signed to preserved sessions owner (audit C-1)`
  - `00997d6` — `fix(v8.4): tighten _is_single_initiate_recovery_call calldata-length floor (audit L-1)`
  - `d933fe7` — `docs(v8.4): SNIP draft threshold-exclusion lead + helper invariant comment (audit informational)`
  - `fafe69e` — `fix(v8.4): extract LEGACY_OZ_ACCOUNT_PUBKEY_SLOT const for OZ version dependency`
**Trigger:** the 2026-05-12 pre-merge audit found a Critical (`bootstrap_from_sessions_signed` missing pubkey-binding gate) that the author missed in self-review. The fix introduced ~50 new lines of Cairo + 17 new tests + 1 new module-level const — load-bearing surface area that had not been independently reviewed. This audit gates the mainnet declare.

## Attribution note

This document is an **independent re-review** of self-authored fix commits, intended to land before the V8.4 mainnet declare. It is not a third-party audit. Per the same convention applied to other AI-assisted reviews in this folder (see `audits/README.md`): **this repository does not claim to be "audited by Anthropic" or "audited by Claude"** — the credit is to the project maintainer who ran the review with AI assistance and triaged the findings.

**Methodology:** ran `scarb build` (green) and `snforge test` (259/259 passed); read the full diff of each in-scope commit against `f573290^^^^^`; walked every gate in `bootstrap_from_sessions_signed` (`src/account.cairo:1102-1167`) and `_initialize_v8_from_sessions` (`src/account.cairo:1190-1233`); verified slot derivation against the upstream OZ AccountComponent v3.0.0 source resolved by Scarb at `~/Library/Caches/com.swmansion.scarb/registry/git/checkouts/cairo-contracts-9cboa8jg3jldq/ddd3338e/packages/account/src/account.cairo:22-25` (`pub Account_public_key: felt252`); cross-referenced the preserved-storage write site in the legacy class at `/Users/diosplan/Documents/sessions-smart-contract/src/account.cairo:125-158` (`#[substorage(v0)] account: AccountComponent::Storage` + `self.account.initializer(public_key)`); enumerated every top-level + substorage-v0-hoisted field name in V8 (account.cairo:124-170, plus the five component storage structs) for `Account_public_key` collision; walked each of the 17 `account_migration` tests' expected revert string against the gate ordering in the source to confirm tests are passing for the right reason (not for a wrong-but-earlier gate); replayed the C-1 PoC scenario mentally against the new gate ordering; re-checked the V8 admin selector blocklist (`_v8_blocklist_ok` at `src/account.cairo:1430-1460`) for `bootstrap_from_sessions_signed` inclusion; audited the residual reentrancy surface (verifier-class library_call paths) against the `primary_kind == 0` one-shot gate.

---

## Findings

### INFO-1 — `bootstrap_from_sessions_signed` does not consult `inside_verifier` (M-2 pattern not propagated)

- **Severity:** **Informational** — defense-in-depth gap with no realistic exploit path; documented as a deliberate scoping decision
- **File:** `src/account.cairo:1102-1167`
- **Description:** Every other entry point in V8 that mutates owner-set state is either `_assert_self_call`-gated (which also checks `!self.inside_verifier.read()`) or is `permissionless after timelock` and threads through `_validate_pubkey_via_verifier` (which raises and lowers the M-2 flag around its `library_call`). `bootstrap_from_sessions_signed` is intentionally not self-call-gated — that is the whole point of the entry — but it also does **not** consult `inside_verifier`. A future maintainer adding any path that re-enters this entry while a verifier library_call is on the stack would not be caught by the M-2 pattern.

  The realistic attack chain that would exercise this gap requires governance compromise (timelocked verifier registration → timelocked owner-of-malicious-kind addition → trigger `_validate_pubkey_via_verifier` → malicious verifier overwrites `selector!("Account_public_key")` AND resets `primary_kind` to zero AND clears `owners_count` AND re-enters `bootstrap_from_sessions_signed`). At every step the malicious verifier already has unrestricted `storage_write_syscall` access — it can drain funds, plant arbitrary owners, and re-enter via `call_contract_syscall` to anything else, with or without this gap. The bootstrap re-entry vector provides no escalation beyond what the compromised verifier already has. **Not exploitable in any realistic threat model.**

- **Recommended fix:** one-line defense-in-depth that mirrors the M-2 pattern used in `_assert_self_call`:
  ```cairo
  // src/account.cairo:1113 — after the primary_kind == 0 assertion
  assert(!self.inside_verifier.read(), 'SHHH: verifier reentry');
  ```
  Optional. The maintainer may choose to defer to V8.5 or never apply — the residual surface is bounded by the `primary_kind == 0` gate, which fires before `_validate_pubkey_via_verifier` is reached on the legitimate path.
- **Regression test (if applied):**
  ```cairo
  // tests/account_migration.cairo
  // Would require a malicious-verifier fixture that re-enters from inside library_call.
  // Probably not worth the test infra cost given the attack requires governance compromise.
  ```

---

### INFO-2 — All V8 components use `#[substorage(v0)]`; a future component field named `Account_public_key` would silently collide with the preserved-pk slot

- **Severity:** **Informational** — future-proofing concern; no current collision and no obvious reason for a future maintainer to introduce one
- **File:** `src/account.cairo:155-169`
- **Description:** V8 embeds all six components with `#[substorage(v0)]`, the legacy "subless" layout where each component storage field hoists to a top-level slot keyed by `starknet_keccak(field_name)`. The C-1 fix reads `selector!("Account_public_key")` directly via `storage_read_syscall`. If any future V8 component adds a field named `Account_public_key` (extremely unlikely given the OZ-namespaced name, but not enforced anywhere), it would write to the same slot the migration path reads and could either:
  (a) accidentally satisfy the pk-binding gate with garbage data,
  (b) accidentally overwrite the preserved legacy pubkey,
  rendering `bootstrap_from_sessions_signed` either too permissive or unreachable.

  Verified at audit time that no V8 storage field collides — the top-level fields (`primary_kind`, `primary_pubkey_hash`, `address_salt`, `verifier_classes`, `oe_nonces`, `oe_in_progress`, `inside_verifier`) and every substorage-v0-hoisted field across SRC5 / OwnerSet / Governance / Recovery / SessionKey / SpendingPolicy use distinct names. The risk is purely forward-looking.
- **Recommended fix:** either (a) migrate to namespaced substorage in V9 when the storage layout next breaks anyway, or (b) add a comment to the `LEGACY_OZ_ACCOUNT_PUBKEY_SLOT` docstring noting "no V8 component may declare a storage field named `Account_public_key`." Option (b) is the lighter-weight mitigation and consistent with how the OZ-version dependency was handled by the `fafe69e` const refactor.

---

## Items verified clean (positive findings)

These are the specific concerns the audit prompt called out, each verified to be correctly handled. Recording them inline so the next audit pass can see what was checked, not just what was found.

### C-1 fix — preserved-pubkey slot binding (`4876aa7`)

- **Slot derivation correct.** `selector!("Account_public_key")` in `#[substorage(v0)]` resolves to the same top-level slot the sessions-smart-contract wrote at constructor time. Verified against the OZ source at `cairo-contracts-9cboa8jg3jldq/ddd3338e/packages/account/src/account.cairo:22-25` and against the sessions-smart-contract embedding at `~/Documents/sessions-smart-contract/src/account.cairo:125`.
- **No slot collision.** Walked every top-level + substorage-v0-hoisted field name. None match `Account_public_key`. The probability of a `starknet_keccak` or `pedersen(map_base, key)` collision is `~ 1 / 2^250`, not a realistic concern.
- **Gate ordering correct.** Sequence at `src/account.cairo:1113-1164`: `primary_kind == 0` → `public_key != 0` → `verifier_felt != 0` → `preserved_slot != 0` → `public_key == preserved_slot` → ECDSA. Each of the 17 `account_migration` tests panics at the first gate that fires (verified one-by-one against the expected panic string).
- **Read-before-write.** The slot read happens before any V8-level storage write. No risk of reading post-write state.
- **`storage_read_syscall` safety.** `LEGACY_OZ_ACCOUNT_PUBKEY_SLOT.try_into()` is safe — `selector!()` produces a `felt252` < 2^250, well within `StorageAddress`'s 2^251 bound. `.unwrap()` on the syscall cannot fail for a valid same-contract domain-0 read.
- **Double-bootstrap blocked.** After the self-call happy path succeeds, `primary_kind != 0` and the signed entry rejects with `'MIG: already initialized'` (covered by `test_v8_4_signed_bootstrap_one_shot_gate`).
- **C-1 PoC test regresses cleanly.** `test_v8_4_audit_c1_rejects_fresh_attacker_keypair` is the exact attacker scenario from the prior audit; it now panics with `'MIG: pk mismatch'` instead of seizing the wallet. Matches the prior audit's PoC test exactly.
- **Edge case: `preserved_slot == 0`.** `test_v8_4_signed_bootstrap_rejects_when_no_preserved_pk` exercises this with a distinct `'MIG: no legacy pk'` revert. Fails closed — no takeover surface, but legitimate users of a hypothetical non-OZ-AccountComponent class cannot recover via this path. Acceptable as the docstring documents.
- **Edge case: `r == 0, s == 0`.** `test_v8_4_signed_bootstrap_rejects_zero_signature_components` pins the Cairo stdlib's ECDSA rejection of zero pairs. Defensive against future stdlib regressions.
- **Cross-account replay closed.** `compute_bootstrap_message` includes `get_contract_address()`, so a sig valid at A fails at B (covered by `test_v8_4_signed_bootstrap_rejects_cross_account_replay`).

### L-1 fix — `calldata.len() >= 7` floor (`00997d6`)

- **Well-formed Serde minimum.** For `initiate_recovery(proposer, kind, pubkey_bytes, role, weight, label)`, the smallest legitimate calldata is `[proposer, kind, 1, pk_0, role, weight, label]` = 7 felts (STARK 1-felt pubkey). Larger kinds (Ed25519 8, secp256k1 9, P-256 9, JWT-Apple 10, BLS12-381 22) all exceed. The floor rejects no legitimate call.
- **Defense-in-depth, not a sole gate.** A 7-felt calldata with `pubkey_bytes.len > 1` claim (e.g., `[proposer, 'BLS12_381', 16, 0xAA, 'OWNER', 1, label]`) passes the predicate but fails Serde inside `initiate_recovery`. The OE wraps with `'H1: subcall failed'`. The L-1 fix is explicitly defense-in-depth — the docstring at `src/account.cairo:1406-1416` documents that safety previously relied on `_execute_calls_atomic_span`'s panic-on-error behavior, and the floor removes that coupling.
- **Regression test.** `test_v8_4_audit_l1_guardian_oe_rejects_truncated_initiate_recovery` confirms a 1-felt calldata reverts at the role-relaxation gate with `'SHHH: signer not an owner'` — never reaches the syscall.

### Const refactor — `LEGACY_OZ_ACCOUNT_PUBKEY_SLOT` (`fafe69e`)

- **Bit-identical semantics.** `selector!()` evaluates at compile time. The const at `src/account.cairo:92` (`pub const LEGACY_OZ_ACCOUNT_PUBKEY_SLOT: felt252 = selector!("Account_public_key")`) produces the same felt252 as the prior inline `selector!("Account_public_key")` at the call site. Empirically confirmed: build green, suite green, C-1 PoC test still rejects with `'MIG: pk mismatch'`.
- **OZ-version maintenance contract documented.** The 26-line docstring (lines 68-91) names the tied-version (`v3.0.0`), the upstream verification source path, the failure mode if OZ renames the field in a future version (`'MIG: no legacy pk'` — fail-closed, no takeover), and the mitigation requirement at the OZ-bump merge gate.

### Informational fixes (`d933fe7`)

- **SNIP draft Part C.** The threshold-exclusion sentence now leads the role-relaxation paragraph and explicitly calls out `V2_THRESHOLD` envelopes + M-of-N guardian recovery as out of scope. A reviewer reading top-down hits the restriction immediately.
- **`_initialize_v8_from_sessions` invariant comment.** The 17-line doc-comment at `src/account.cairo:1169-1189` establishes the "CALLER MUST AUTHORIZE BEFORE INVOKING" invariant, names the two current callers and their authorization mechanisms, and notes that a future third caller MUST install its own auth gate. Acceptable for two callers; the prior audit's suggested `AuthProof` enum is documented as the heavier-weight alternative.

### V8 admin selector blocklist

- **`bootstrap_from_sessions_signed` is in the blocklist.** Confirmed at `src/account.cairo:1453` — sessions cannot reach the new entry point. The original `bootstrap_from_sessions` was already blocklisted.

### Test coverage

- **17/17 migration tests pass.** Each expected revert string matches the FIRST gate that fires (manual walk-through of each test against the source). No test passes for the wrong reason.
- **259/259 overall.** No regression in any other test suite.

---

## Residual threat model

What's left after the C-1 fix:

- **Pre-bootstrap (`primary_kind == 0`):** no `verifier_classes` are registered (the storage `Map<felt252, ClassHash>` is empty by default). Any V8 entry that calls `_validate_pubkey_via_verifier` reverts at the `verifier_class != 0` check. No malicious verifier can be library_called pre-bootstrap. No attacker has a way to overwrite `selector!("Account_public_key")` from inside the V8 contract pre-bootstrap.
- **Post-bootstrap (`primary_kind != 0`):** `bootstrap_from_sessions_signed`'s first gate (`assert(self.primary_kind.read() == 0, 'MIG: already initialized')`) blocks any re-entry. Even a malicious verifier that overwrites every storage slot would also need to overwrite `primary_kind` AND `Account_public_key` AND clear `owners_count` to re-bootstrap; at that point the attacker has unrestricted storage access and can drain the wallet without going through `bootstrap_from_sessions_signed`.
- **Cross-protocol replay:** the canonical bootstrap message is bound to `'SHHH_BOOTSTRAP_V8_4'` + `get_contract_address()` + supplied pubkey + supplied verifier + supplied label. Cross-account replay fails (B's address ≠ A's). Cross-protocol replay fails (different domain separator). A future V8.5 that uses the same domain separator would inherit the same risk; the `primary_kind == 0` gate blocks unless the wallet is reset to stranded state.
- **Quantum:** out of scope.

---

## Decision

**`READY TO DECLARE`**

The C-1 fix correctly binds stranded-bootstrap recovery to the preserved sessions-owner pubkey via the OZ AccountComponent v3.0.0 `Account_public_key` storage slot. The L-1 fix removes a fragile coupling on `_execute_calls_atomic_span`'s panic-on-error behavior without restricting any legitimate calldata shape. The const refactor is a pure rename with bit-identical compile-time semantics. The two doc-only Informational fixes from the prior audit are addressed and read cleanly. The two new Informational findings raised in this audit (`bootstrap_from_sessions_signed` not consulting `inside_verifier`; `#[substorage(v0)]` future-collision footgun) are non-blocking with documented mitigations and no realistic exploit path.

No Critical. No High. No Medium. No Low.

Recommend declaring V8.4 `ShhhAccount` on Starknet mainnet at commit `f573290` and tagging the branch `v8.4`.
