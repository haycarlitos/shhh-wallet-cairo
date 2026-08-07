# V8.4 Pre-Phase-13 Audit — `feat/v8-4-bootstrap-safety-and-guardian-oe`

**Date:** 2026-05-12
**Auditor:** Claude Opus 4.7 (1M context), adversarial independent pass after author self-review
**Scope:** `feat/v8-4-bootstrap-safety-and-guardian-oe` (HEAD `cacd0c8`) — PR #10, not yet merged into `v8-robust`. Three commits in scope:
  - `d8baac2` — `fix(v8.4): stranded-bootstrap recovery via legacy-pubkey signature`
  - `0440e78` — `feat(v8.4): initiate_recovery_outside via guardian-OE carve-out`
  - `cacd0c8` — `docs(v8.4): SNIP draft — guardian-OE selector-scoped role relaxation`
**Trigger:** independent review requested by the author before merge — closes the two architectural gaps surfaced in the 2026-05-12 SDK-integration review.

## Attribution note

This document is an **independent review** of a self-authored PR, intended
to land alongside the V8.4 PR before merge. It is not a third-party audit.
Per the same convention applied to other AI-assisted reviews in this folder
(see `audits/README.md`): **this repository does not claim to be "audited
by Anthropic" or "audited by Claude"** — the credit is to the project
maintainer who ran the review with AI assistance and triaged the findings.

**Methodology:** read PR description; SNIP draft Part C + Security
Considerations #9; the full diff against `v8-robust @ 77d8c50` for
`src/account.cairo`, `tests/account_migration.cairo`, and
`tests/account_recovery_outside.cairo`; cross-referenced the new
`bootstrap_from_sessions_signed` entry point against the preserved
sessions-smart-contract storage layout
(`/Users/diosplan/Documents/sessions-smart-contract/src/account.cairo`,
lines 120-162 for the storage struct, 674-692 for the non-atomic
`_execute_calls`); audited every `_assert_self_call` callsite to confirm
the bypass is intentional only where dropped; walked the four predicate
conditions of `_is_single_initiate_recovery_call` against the
attacker-models from the 2026-05-07 C-1 finding; wrote a proof-of-concept
test to confirm the Critical finding below empirically.

---

## Findings

### C-1 — `bootstrap_from_sessions_signed` does not bind to the original sessions owner; any stranded wallet can be permanently captured by whoever wins the post-strand race

- **Severity:** **Critical** — universal takeover of any stranded sessions wallet that has been upgraded to a V8.4 class
- **File:** `src/account.cairo:1051-1082` (entry point) + `src/account.cairo:1088-1131` (`_initialize_v8_from_sessions`)
- **Description:** `bootstrap_from_sessions_signed` accepts `public_key` as a *user-supplied parameter* and only checks that `(signature_r, signature_s)` is valid **under that same supplied pubkey**. There is no check anywhere that `public_key` matches the legacy sessions-wallet owner pubkey that is *preserved in storage* across the OZ `upgrade()` syscall (the OZ `AccountComponent::Storage::public_key` slot written by sessions-smart-contract's constructor at line 158 survives the class swap losslessly — same property `oe_nonces` and `verifier_classes` rely on in V8.2's Informational note on class-upgrade nonce replay). The author's "authorization is the signature check below" comment is self-referential: an attacker chooses `public_key`, signs under their own key, and the contract has no concept of a "legitimate" pubkey to compare against.

  This is a **regression vs V8.3.** Before V8.4 the only path into `bootstrap_from_sessions` was `_assert_self_call`-gated — only the wallet itself could invoke it, which in practice meant only the sessions owner (via a multicall signed inside the OLD class's OE) could initialize the V8 owner-set. The H-1 fix from 2026-05-07 expressly noted this property: "any address watching the mempool could race the upgrade tx and call `bootstrap_from_sessions(attacker_pk, …)` first, seizing the account before the legitimate owner's bootstrap arrives" — the self-call gate closed that. The new signed-bootstrap entry point reopens the same attack with a different surface: instead of racing the upgrade tx, the attacker races the *recovery* tx.

  Pre-conditions for the attack:
  1. A stranded wallet exists: a sessions wallet whose migration OE `[upgrade(V8.4), bootstrap_from_sessions(...)]` executed on the OLD class's non-atomic `_execute_calls`
     (sessions-smart-contract `src/account.cairo:684`, `Result::Err(_) => res.append(array![].span())`), and whose bootstrap subcall reverted silently (gas, validate_pubkey panic, bad calldata, etc.). End-of-tx: class is V8.4, `primary_kind == 0`, no V8 owners.
  2. Wallet has assets (almost always true — migration is from a funded sessions wallet).
  3. The stranded state is on-chain observable: `Upgraded` event without a matching `PrimaryOwnerInitialized` is the public signal.

  Both pre-conditions are realistic; the author's own commit message (`d8baac2`) explicitly motivates V8.4 by listing all the ways a real migration tx can hit a silent bootstrap revert.

- **Concrete exploit:**
  ```cairo
  // Attacker generates a fresh STARK keypair — no relation to any
  // legitimate user. They watch the chain for stranded migrations
  // and front-run the legitimate signed bootstrap.
  let attacker = StarkCurveKeyPairImpl::from_secret_key(0xDEAD_BEEF_F00D);

  // Compute the canonical msg with THEIR pubkey + chosen label.
  let msg = core::poseidon::poseidon_hash_span(
      array![
          'SHHH_BOOTSTRAP_V8_4', stranded_addr.into(),
          attacker.public_key, verifier_class.into(), 'pwned',
      ].span(),
  );
  let (r, s) = attacker.sign(msg).unwrap();

  // Submit from any relay. The contract:
  //   - `primary_kind == 0` ✓ (stranded state)
  //   - `public_key != 0` ✓ (attacker chose 0xDEAD…)
  //   - `verifier != 0` ✓
  //   - `check_ecdsa_signature(msg, attacker.public_key, r, s)` ✓ (just signed)
  // → `_initialize_v8_from_sessions(...)` writes attacker as primary STARK owner.
  let mig = IShhhMigrationDispatcher { contract_address: stranded_addr };
  mig.bootstrap_from_sessions_signed(
      attacker.public_key, verifier_class, 'pwned', r, s,
  );

  // Attacker now signs OEs as the primary owner; drains the wallet.
  ```

  **Proof-of-concept test:** `tests/account_migration.cairo::audit_poc_attacker_can_seize_any_stranded_wallet`. It generates a fresh attacker keypair, signs the canonical bootstrap message under it, submits, and asserts the post-state matches the legitimate bootstrap (primary_kind == 'STARK', owner_count == 1, owner_0.role == ROLE_OWNER, owner_0.label == 'pwned'). The test **passes** on the current branch:
  ```
  [PASS] shhh_wallet_integrationtest::account_migration::audit_poc_attacker_can_seize_any_stranded_wallet
         (l1_gas: ~0, l1_data_gas: ~1920, l2_gas: ~11633554)
  ```

  After the fix, this test should be flipped to `#[should_panic(expected: 'MIG: pubkey mismatch')]` (or whatever revert string the gate uses).

- **Why the PR's existing tests miss this:** the 5 signed-bootstrap negative tests
  (`test_v8_4_signed_bootstrap_rejects_invalid_signature`, `…rejects_wrong_signer`, `…rejects_cross_account_replay`, `…rejects_pubkey_substitution`, `…rejects_zero_pubkey`) all assume the attacker is impersonating a *specific* legitimate party — they cover pubkey-substitution-with-reused-sig, cross-account replay, wrong-signer, zero-pubkey, zero-verifier. None covers "attacker generates a fresh keypair and signs the canonical msg under their own pubkey." The test enumeration biased the threat model toward "the user is the only one who would sign," which is exactly the assumption the contract fails to enforce.

  The PR description's "Threat model coverage" list reflects the same bias: every entry assumes a specific legitimate pubkey exists. None considers a fresh attacker keypair.

- **Recommended fix:** bind `public_key` to the preserved legacy sessions owner pubkey. Two implementation paths:

  **Path A — raw storage read (preferred, no layout change):**
  ```cairo
  // In bootstrap_from_sessions_signed, BEFORE the canonical-msg poseidon:
  // Read the OZ AccountComponent's preserved public_key slot. The sessions
  // class wrote this at constructor time (sessions-smart-contract
  // src/account.cairo:158 — `self.account.initializer(public_key)`).
  // Verify the exact slot name against OZ AccountComponent's
  // #[storage] attribute — Cairo storage variable selectors are
  // derived from the field name at the substorage path.
  let preserved_pk = starknet::syscalls::storage_read_syscall(
      0, selector!("Account_public_key"),
  ).expect('MIG: preserved pk read');
  assert(preserved_pk != 0, 'MIG: no legacy pubkey');
  assert(public_key == preserved_pk, 'MIG: pubkey mismatch');
  ```

  **Path B — declare AccountComponent substorage on ShhhAccount V8.4 (cleaner, requires layout add):**
  ```cairo
  // src/account.cairo, in the #[storage] struct:
  #[substorage(v0)]
  account: openzeppelin_account::AccountComponent::Storage,
  ...

  // Then in bootstrap_from_sessions_signed:
  let preserved_pk: felt252 = self.account.public_key.read();
  assert(preserved_pk != 0, 'MIG: no legacy pubkey');
  assert(public_key == preserved_pk, 'MIG: pubkey mismatch');
  ```

  Path B is more obviously correct (named field access, no magic selector) but adds a substorage to the V8.4 layout that V8.3 doesn't carry. Path A leaves the layout untouched and uses the same lossless-preservation property that V8.2's Informational note relies on for `oe_nonces`.

  Either path closes the takeover by making `public_key` a *verified-consistent* parameter rather than a free one. The remaining residual surface — a legitimate user whose private key is genuinely lost — has *no recovery path* through this entrypoint after the fix, which is the correct outcome. Those wallets must use guardian recovery once V8.4's owner-set ships its own guardian, or be considered lost (no different from any other self-custodial wallet with a lost-key-and-no-guardian).

- **Regression tests:**
  ```cairo
  // tests/account_migration.cairo
  #[test]
  #[should_panic(expected: 'MIG: pubkey mismatch')]
  fn test_v8_4_signed_bootstrap_rejects_fresh_attacker_keypair() {
      let (addr, verifier) = declare_and_deploy();
      reset_for_migration_simulation(addr);
      // Simulate a stranded sessions wallet — write the preserved legacy
      // pubkey to the OZ Account substorage slot.
      let legacy_pk = 0xC0FFEE_BEEF;
      store(addr, selector!("Account_public_key"), array![legacy_pk].span());

      // Attacker generates a fresh keypair and signs the canonical msg
      // under THEIR own pubkey.
      let attacker = StarkCurveKeyPairImpl::from_secret_key(0xDEAD_BEEF_F00D);
      let msg = compute_bootstrap_message(addr, attacker.public_key, verifier, 'pwned');
      let (r, s) = attacker.sign(msg).unwrap();

      let mig = IShhhMigrationDispatcher { contract_address: addr };
      mig.bootstrap_from_sessions_signed(attacker.public_key, verifier, 'pwned', r, s);
  }

  #[test]
  fn test_v8_4_signed_bootstrap_accepts_preserved_legacy_pubkey() {
      let (addr, verifier) = declare_and_deploy();
      reset_for_migration_simulation(addr);
      let legacy = StarkCurveKeyPairImpl::from_secret_key(0xC0FFEE_BEEF);
      // Simulate the preserved sessions-class storage.
      store(addr, selector!("Account_public_key"), array![legacy.public_key].span());

      let msg = compute_bootstrap_message(addr, legacy.public_key, verifier, 'recovered');
      let (r, s) = legacy.sign(msg).unwrap();
      let mig = IShhhMigrationDispatcher { contract_address: addr };
      mig.bootstrap_from_sessions_signed(legacy.public_key, verifier, 'recovered', r, s);

      let reads = IShhhReadsDispatcher { contract_address: addr };
      assert(reads.primary_kind() == 'STARK', 'primary_kind');
  }
  ```

---

### L-1 — `_is_single_initiate_recovery_call` accepts truncated calldata; downstream Serde catches it but the coupling is fragile

- **Severity:** **Low** — defense-in-depth / future-proofing; no exploit on V8.4 as shipped
- **File:** `src/account.cairo:1285-1313`
- **Description:** The helper returns `true` when `calls[0].calldata.len() >= 1` (only `proposer` present). After the carve-out fires, `_execute_calls_atomic_span` invokes `initiate_recovery(...)` with the truncated calldata; Serde-deserialization of the remaining arguments (`new_owner_kind`, `new_pubkey_bytes`, `new_role`, `new_weight`, `new_label`) fails inside the call, the syscall returns `Result::Err(_)`, and `_execute_calls_atomic_span` panics with `'H1: subcall failed'`. The OE reverts atomically — safe today.

  The fragility: the predicate-relaxation lives in `_is_single_initiate_recovery_call`; the safety relies on a *separate function's* error-propagation behavior. A future change that catches Serde errors more leniently (e.g., a multicall-with-best-effort variant, or a Sierra-level deserialization fallback) would let a malformed `initiate_recovery` reach the recovery component with default-zero fields. There is no in-test demonstration that this path reverts cleanly, so any future regression would surface only as a Critical.

- **Recommended fix:** tighten the predicate to assert the expected calldata shape. The minimum well-formed `initiate_recovery` calldata after Serde flattening is 7 felts (`proposer + new_owner_kind + pubkey_bytes_len + ≥1 pubkey felt + new_role + new_weight + new_label`):
  ```cairo
  fn _is_single_initiate_recovery_call(
      calls: Span<Call>, self_addr: ContractAddress, signer_owner_id: u32,
  ) -> bool {
      if calls.len() != 1_u32 { return false; }
      let call = calls.at(0);
      if *call.to != self_addr { return false; }
      if *call.selector != selector!("initiate_recovery") { return false; }
      let calldata: Span<felt252> = *call.calldata;
      // initiate_recovery's minimum well-formed Serde calldata is 7 felts.
      // Tighter than the literal arg-count to reject truncated payloads
      // before they reach the recovery component.
      if calldata.len() < 7_u32 { return false; }
      // proposer == signer_owner_id binding (unchanged):
      let proposer_id: u32 = match (*calldata.at(0)).try_into() {
          Option::Some(v) => v,
          Option::None => { return false; },
      };
      proposer_id == signer_owner_id
  }
  ```

- **Regression test:**
  ```cairo
  // tests/account_recovery_outside.cairo
  #[test]
  #[should_panic(expected: 'SHHH: signer not an owner')]
  fn test_v8_4_guardian_oe_rejects_truncated_initiate_recovery() {
      let (account, guardian_id) = deploy_account_with_guardian();
      // Calldata: only proposer felt, no other args.
      let calldata: Array<felt252> = array![guardian_id.into()];
      let call = Call {
          to: account, selector: selector!("initiate_recovery"),
          calldata: calldata.span(),
      };
      let oe = OutsideExecution {
          caller: 'ANY_CALLER'.try_into().unwrap(),
          nonce: 'trunc-nonce',
          execute_after: 1_000_000,
          execute_before: 1_000_000 + 3_600,
          calls: array![call].span(),
      };
      let hash = compute_snip12_hash(@oe, account.into(), 'SN_MAIN');
      let guardian_kp = StarkCurveKeyPairImpl::from_secret_key(GUARDIAN_SECRET);
      let (r, s) = guardian_kp.sign(hash).unwrap();
      let envelope: Array<felt252> = array![
          SIG_VERSION_V2_SNIP12, guardian_id.into(), 'STARK', r, s,
      ];
      cheat_oe_caller(account);
      let src9 = ISRC9_V2Dispatcher { contract_address: account };
      src9.execute_from_outside_v2(oe, envelope.span());
  }
  ```

---

### Informational — `_initialize_v8_from_sessions` defensive re-checks omit authorization

- **Severity:** Informational — future-maintainer footgun, not a bug today
- **File:** `src/account.cairo:1088-1131`
- **Description:** The shared helper re-asserts `primary_kind == 0`, `public_key != 0`, `verifier_felt != 0` as a defense-in-depth measure. The doc comment says callers are responsible for authorization. With two callers today (`bootstrap_from_sessions` self-call, `bootstrap_from_sessions_signed` signature check), the pattern works. If a future third entry point forgets the auth check, the helper silently authorizes the call: defense-in-depth without authorization-in-depth.
- **Recommended fix (optional):** pass an explicit `authorization_proof` enum (`SelfCall | SignatureChecked`) and assert one variant matches:
  ```cairo
  enum AuthProof { SelfCall, SignatureChecked }

  fn _initialize_v8_from_sessions(
      ref self: ContractState,
      auth: AuthProof,
      public_key: felt252,
      stark_verifier_class: ClassHash,
      label: felt252,
  ) {
      // Caller must construct the AuthProof — there's no constructor
      // without doing the corresponding check.
      let _ = match auth {
          AuthProof::SelfCall => _assert_self_call(@self),
          AuthProof::SignatureChecked => (),
      };
      // …rest unchanged
  }
  ```
  Lower priority than C-1 / L-1. Not blocking.

---

### Informational — PR description's threat-model coverage list is incomplete; same gap is the root cause of C-1

- **Severity:** Informational — process / review-quality observation
- **File:** PR #10 description, "Threat model coverage (all in test suite)" section
- **Description:** The five bulleted negative cases for stranded-bootstrap recovery all share the assumption "there is exactly one legitimate user; the attacker is trying to impersonate them." That mental model makes the contract's missing pubkey-binding check invisible, because under that model the canonical msg's commitment to `public_key` looks sufficient. Surfacing the missing case ("attacker generates their own keypair and signs the canonical msg under their own pubkey") in the test list would have made C-1 obvious. Carry this as a SNIP-108 reviewer-instruction note: signed-recovery entrypoints must explicitly enumerate "fresh-attacker-keypair" in their threat model.

---

### Informational — SNIP draft Part C wording on threshold-envelope exclusion

- **Severity:** Informational — documentation clarity
- **File:** `docs/snip-draft-pluggable-signer.md:240-262`
- **Description:** Part C reads cleanly and matches the four predicate conditions shipped in `_is_single_initiate_recovery_call`. One minor improvement: the closing paragraph notes "The threshold envelope (`V2_THRESHOLD`) does NOT carry the relaxation" — easy to miss. Consider promoting this sentence near the top of the relaxation paragraph so reviewers don't have to read to the bottom to see the boundary condition. Non-blocking.

Security Considerations #9 correctly cites `_is_single_initiate_recovery_call` as the canonical predicate. ABI shape (trait, kind tags, envelope routing) is unchanged in this PR. ✓

---

## Reviewed sections with no findings

- **`bootstrap_from_sessions` (V8.3 path, unchanged) at `src/account.cairo:987-1016`** — `_assert_self_call` retained; combined with the `primary_kind == 0` one-shot gate, the original H-1 fix from 2026-05-07 remains intact for the happy-path migration. The legitimate atomic-multicall flow is unchanged. ✓

- **Guardian-OE carve-out role check at `src/account.cairo:446-475`** — the four predicate conditions (`calls.len() == 1`, `call.to == get_contract_address()`, `call.selector == selector!("initiate_recovery")`, `calldata[0] == signer_owner_id`) are AND-joined and verified before the dispatcher.verify call. The carve-out cannot bypass signature verification — the OE's V2_SNIP12 envelope ECDSA check happens *after* the role assertion. A guardian without their private key cannot trigger the carve-out. ✓

- **Threshold envelope path at `src/account.cairo:1371-1399` (`_verify_sub_envelope`)** — line 1383 still asserts `owner.role == ROLE_OWNER`. The V8.4 carve-out is single-owner-only; guardian envelopes cannot satisfy a threshold sub-envelope. ✓

- **`proposer == signer_owner_id` binding** — analyzed against the author's "load-bearing or cosmetic?" question. Verdict: **mostly cosmetic for immediate effect, but load-bearing for audit trail.** Without the binding, guardian A could sign an OE naming guardian B as proposer; both are equivalent in V8.4 (no role distinction between guardians), so the recovery outcome is identical. The binding ties the on-chain `OutsideExecutionExecuted.owner_id` event to the `RecoveryInitiated.new_owner_hash` commitment via the calls span — preserving "who proposed this" forensics. Recommend keeping the binding; doc comment correctly captures the rationale. ✓

- **`get_contract_address()` inside `_initialize_v8_from_sessions`** — returns the called contract's address inside any external entrypoint's invocation, regardless of call origin. Carlos's concern that "the function might run in a syscall-call context where `get_contract_address()` returns the wrong address" is unfounded — `get_contract_address()` always returns the contract being executed (i.e., `self`). ✓

- **`_assert_self_call` callsite audit** — every other callsite (`src/account.cairo:587, 597, 614, 633, 650, 671, 791, 835, 851`) retains the gate; the V8.4 drop applies *only* to `bootstrap_from_sessions_signed` where the doc comment intentionally documents the bypass. No accidental relaxation elsewhere. ✓

- **`inside_verifier` flag in `bootstrap_from_sessions_signed`** — the ECDSA primitive used (`core::ecdsa::check_ecdsa_signature`) is a syscall, not a library_call'd verifier, so there's no reentrancy surface around it. The downstream `_validate_pubkey_via_verifier` inside `_initialize_v8_from_sessions` (line 1122) correctly raises the flag around the library_call. ✓

- **`bootstrap_from_sessions_signed` reentrancy via verifier-class library_call** — even if a malicious verifier class were registered (which would require the V8.2 ADD_VERIFIER_CLASS 48-hour timelock and unanimous owner approval — not reachable on a stranded wallet with no owners), a reentrant call back into `bootstrap_from_sessions_signed` would hit the `primary_kind != 0` revert because storage writes happen *before* the library_call (lines 1108-1114). ✓

- **STARK ECDSA signature malleability** — `check_ecdsa_signature` accepts both `s` and `n-s`. Does not enable any attack on V8.4: the carve-out path verifies a guardian OE, where malleability lets an attacker produce a second valid `(r, s')` for the same message — but they still need to know the guardian's private key. The signed-bootstrap path is broken by C-1 regardless of malleability. ✓

- **`kind = 'STARK'` hardcode in `_initialize_v8_from_sessions`** — safe today because sessions-smart-contract is STARK-only. If sessions ever ships a non-STARK variant, this becomes silently wrong. Carry as a code-comment invariant note when the C-1 fix lands (the same preserved-storage read used for the pubkey gate would also expose the sessions-class kind, making the assertion runtime-enforceable). Not a finding on V8.4 as-is. ✓

- **`recovery.initiate()` re-initiation protection** — the recovery component asserts `!existing.is_active` (`src/recovery/component.cairo:80`), so a guardian cannot overwrite a pending recovery via the new OE-guardian path. Cancel/finalize semantics unchanged. ✓

- **Session-key blocklist coverage of new entrypoint** — `_v8_blocklist_ok` at `src/account.cairo:1316-1345` correctly lists both `bootstrap_from_sessions` and `bootstrap_from_sessions_signed`. Session keys cannot reach either. ✓

- **Nonce replay across class upgrade** — `oe_nonces` is a top-level `Map<felt252, bool>`; same lossless-preservation property covered by the V8.2 review applies. Confirmed clean. ✓

---

## Executive Summary

I do **not** recommend merging this commit as-is. The critical finding is **C-1: `bootstrap_from_sessions_signed` does not bind to the original sessions owner pubkey** — `public_key` is a free parameter committed only to a self-referential signature check, so any attacker with a fresh STARK keypair can permanently capture any stranded wallet by winning the post-strand race. The PoC test (`audit_poc_attacker_can_seize_any_stranded_wallet`) confirms the takeover succeeds empirically. The V8.3 happy-path migration is unaffected — `bootstrap_from_sessions` retains its `_assert_self_call` gate, and the H-1 fix from 2026-05-07 (the original frontrunner block on the upgrade tx) remains intact. The Critical lives entirely in the new entry point.

The guardian-OE carve-out (commits `0440e78` + `cacd0c8`) is **clean and mergeable**: the four predicate conditions in `_is_single_initiate_recovery_call` are well-formed, the threshold path is correctly left untouched, the inner-recovery role check at `initiate_recovery` provides defense-in-depth, tests cover the four meaningful cases (proposer-mismatch, wrong-selector, multi-call, owner-OE-regression), and the SNIP draft tracks the implementation. The only carve-out finding is **L-1** — `_is_single_initiate_recovery_call` accepts truncated calldata (`calldata.len() >= 1` instead of `>= 7`), with safety relying on `_execute_calls_atomic_span`'s panic-on-error behavior. Cheap to tighten; recommended for future-proofing.

The two changes I'd require before merge are:

1. **Bind `public_key` to the preserved legacy sessions owner pubkey** (Path A or Path B in C-1's recommendation). Add the `should_panic('MIG: pubkey mismatch')` regression test and convert the PoC test to assert the gate fires.
2. **Tighten `_is_single_initiate_recovery_call`** to require `calldata.len() >= 7`. Add the truncated-calldata regression test.

With those changes, V8.4 closes both architectural gaps from the 2026-05-12 SDK-integration review without reintroducing the original 2026-05-07 H-1 frontrunner surface. The codebase is then ready for Phase-13 external audit handoff with the same scope envelope the PR description proposes.

The Informational findings (helper authorization plumbing, PR threat-model enumeration, SNIP draft wording) are nice-to-have polish — none blocks merge.
