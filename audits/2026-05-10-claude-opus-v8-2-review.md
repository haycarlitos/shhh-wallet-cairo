# V8.2 Pre-Phase-13 Audit — `feat/v8-2-validate-pubkey`

**Date:** 2026-05-10
**Auditor:** Claude Opus 4.7 (1M context), adversarial pluggable-signer review
**Scope:** `feat/v8-2-validate-pubkey` (HEAD `135f1de`) — PR #5, not yet merged into `v8-robust`. The 11 mainnet class hashes declared 2026-05-10 correspond to the V8.2 build of this branch.
**Trigger:** pre-Phase-13 sign-off / SNIP-108 submission readiness review.

**Methodology:** read `src/account.cairo`, all 10 verifier classes, governance / recovery / owner_set / spending_policy components, `src/outside_execution.cairo`, and the regression tests under `tests/`. Cross-referenced V8.2-introduced changes (the diff vs. `v8-robust`) against the 10 attack-surface targets called out in the audit brief.

---

## Findings

### H-1 — `finalize_recovery` does not call `_validate_pubkey_via_verifier` (M-1 incomplete)

- **Severity:** **High** — defense-in-depth + integrity-of-claim violation
- **File:** `src/account.cairo:842-862`
- **Description:** V8.2 advertises "M-1 fully closed via `validate_pubkey` ISigner method" and inserts `_validate_pubkey_via_verifier` into `execute_add_owner` (line 699) and `execute_rotate_owner` (line 726). But the **third path that adds an owner — `finalize_recovery`** — calls `self.owners.add_owner(...)` directly with no per-kind validation. A guardian can `initiate_recovery` with any malformed `(new_owner_kind, new_pubkey_bytes)`; after the 7-day timelock anyone permissionlessly invokes `finalize_recovery`, and a poison-pill pubkey lands in `owners` with role `ROLE_OWNER`, contributing to `total_weight`. The malformed owner cannot sign (verify returns false) but their weight inflates `_recompute_total_weight`, which can be combined with a later `set_threshold` proposal to brick threshold-required ops if legitimate active weight falls below the new threshold.
- **Concrete exploit:**
  ```cairo
  // Compromised guardian (owner_id = 1) submits an OE multicall:
  rec.initiate_recovery(1, 'BLS12_381', array![0xDEAD; 16], ROLE_OWNER, 99_u8, 'phone');
  // 7 days pass, no owner cancels (owner offline).
  start_cheat_block_timestamp_global(now + 604_800 + 1);
  rec.finalize_recovery('BLS12_381', array![0xDEAD; 16], ROLE_OWNER, 99_u8, 'phone');
  // Owner with off-curve BLS pubkey now sits at owner_id 2, weight 99.
  ```
- **Recommended fix:** add the same one-liner used in `execute_add_owner`:
  ```cairo
  // src/account.cairo:858 — after `assert(stored == expected, ...)` and before add_owner
  _validate_pubkey_via_verifier(@self, new_owner_kind, pubkey_span);
  ```
- **Regression test:**
  ```cairo
  // tests/account_recovery.cairo
  #[test]
  #[should_panic(expected: 'M1: invalid pubkey')]
  fn test_finalize_recovery_rejects_off_curve_secp256k1() {
      let (addr, guardian_id) = deploy_account_with_guardian();
      let rec = IShhhRecoveryDispatcher { contract_address: addr };
      // Register secp256k1 verifier first
      register_secp256k1_verifier(addr);
      start_cheat_caller_address(addr, addr);
      // Guardian initiates with deliberately off-curve secp256k1 point
      rec.initiate_recovery(guardian_id, 'SECP256K1',
          array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE], ROLE_OWNER, 1_u8, 'evil');
      start_cheat_block_timestamp_global(time_after_recovery(1_000_000));
      rec.finalize_recovery('SECP256K1',
          array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE], ROLE_OWNER, 1_u8, 'evil');
  }
  ```

---

### M-1 — `_call_validate_pubkey_with_flag` deliberately omits `inside_verifier`; trade-off rationale is incorrect

- **Severity:** **Medium** — defense-in-depth gap; requires a governance-vetted-but-malicious verifier (same trust boundary the M-2 fix already chose to harden against)
- **File:** `src/account.cairo:1117-1149`
- **Description:** V8.2's helper acknowledges in its body comments that the M-2 reentrancy guard does *not* wrap `validate_pubkey`. The justification given is "validate_pubkey is only called inside the governance-gated execute_add_owner / execute_rotate_owner / bootstrap_from_sessions paths, all of which are already self-call gated and timelock-protected upstream." **This claim is wrong about `execute_add_owner` and `execute_rotate_owner`**: both are explicitly **permissionless** post-timelock (the file's own header comment at line 506 says "execute_pending_* is PERMISSIONLESS after the timelock"). Neither carries `_assert_self_call`. A library-called `validate_pubkey` runs in the wallet's storage and address context, so a `call_contract_syscall(self_addr, 'propose_*', ...)` from inside it satisfies `_assert_self_call`'s `caller == get_contract_address()` check. The verify path raises `inside_verifier` precisely to block this; the validate path does not. Asymmetric defense for the same trust assumption.
- **Concrete exploit:**
  ```cairo
  // Inside a malicious verifier class registered for kind=ED25519_V2 via the
  // 48h ADD_VERIFIER timelock, validate_pubkey re-enters during execute_add_owner:
  fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
      let evil_call: Array<felt252> = array![/* attacker_owner_id, attacker_kind, attacker_pubkey, ROLE_OWNER, weight, label */];
      starknet::syscalls::call_contract_syscall(get_contract_address(),
          selector!("propose_add_owner"), evil_call.span()).unwrap();
      // _assert_self_call passes because inside_verifier is FALSE on this path
      true  // accept registration so the host tx succeeds
  }
  ```
- **Recommended fix:** plumb `ref self` through to the helper and wrap the library_call:
  ```cairo
  fn _call_validate_pubkey_with_flag(
      ref self: ContractState, dispatcher: ISignerLibraryDispatcher, pubkey: Span<felt252>,
  ) -> bool {
      self.inside_verifier.write(true);
      let ok = dispatcher.validate_pubkey(pubkey);
      self.inside_verifier.write(false);
      ok
  }
  // and call site at line 699 / 726 must pass `ref self`
  ```
  Yes, this is the "V8.3 candidate" the source comment defers — but the rationale defers it for the wrong reason. Close it now while M-1 is fresh.
- **Regression test:**
  ```cairo
  // tests/account_reentrancy.cairo
  #[test]
  #[should_panic(expected: 'SHHH: verifier reentry')]
  fn test_validate_pubkey_blocks_reentry_into_self_call_mutator() {
      // 1. Deploy a TestEvilValidatePubkeyVerifier whose validate_pubkey
      //    issues call_contract_syscall(self, 'propose_set_threshold', ...).
      // 2. Use ADD_VERIFIER timelock to register it for kind 'TEST'.
      // 3. Schedule and execute add_owner with kind='TEST'.
      // 4. Expect 'SHHH: verifier reentry'.
  }
  ```

---

### M-2 — `bootstrap_from_sessions` does not call `_validate_pubkey_via_verifier`

- **Severity:** **Medium** — incomplete M-1 closure; today benign (kind hardcoded to STARK and `assert(public_key != 0)` matches what `StarkVerifier.validate_pubkey` does), but the V8.2 pattern is "always delegate to verifier" and this path silently breaks the invariant.
- **File:** `src/account.cairo:962-1007`
- **Description:** The bootstrap path hardcodes `kind = 'STARK'` and only checks `public_key != 0`. That happens to coincide with `StarkVerifier::validate_pubkey` (`pubkey.len()==1 && pk!=0`) because STARK is shape-only — but if a future amendment adds, e.g., `kind='ED25519'` for ed25519-keyed sessions wallets, or generalizes the signature, this path silently drops curve checks. Today it's correct by coincidence; tomorrow it's a footgun.
- **Concrete exploit:** none today (hardcoded STARK + non-zero check is equivalent). Future-extensibility violation only.
- **Recommended fix:**
  ```cairo
  // src/account.cairo:996 — after verifier_classes.write(kind, stark_verifier_class)
  _validate_pubkey_via_verifier(@self, kind, pubkey_span);
  ```
  (Place after `verifier_classes.write` so the lookup hits.)
- **Regression test:**
  ```cairo
  #[test]
  #[should_panic(expected: 'M1: invalid pubkey')]
  fn test_bootstrap_from_sessions_rejects_zero_pubkey_via_verifier() {
      // Construct a sessions-style upgrade scenario, attempt bootstrap
      // with public_key=0 and assert the new validate_pubkey path fires
      // (currently the path that fires is 'MIG: public_key is zero' — the
      // test name and panic should change once the helper is wired in).
  }
  ```

---

### M-3 — Negative-case M-2 regression test does not exist; V8.2 validate_pubkey integration is untested

- **Severity:** **Medium** — test coverage gap. Without a negative test the M-2 + M-1 (V8.2) defense-in-depth claims are unverified.
- **Files:** `tests/audit_v8.cairo:406-415`, `tests/signer_validate_pubkey.cairo` (entire file)
- **Description:** The M-2 regression test is openly documented as a positive-only check ("Direct positive test would require a malicious verifier helper class […] expressed by inspection of the storage-flag invariant"). The actual M-2 negative case — a verifier IS prevented from re-entering — has no executable test. Worse, the V8.2 `validate_pubkey` tests deploy each verifier as a standalone contract and call `dispatcher.validate_pubkey` directly. They do NOT exercise the integration path (`execute_add_owner` → library_call → verifier), the `inside_verifier` flag interaction during validate_pubkey (the M-1 finding above), nor the `finalize_recovery` / `bootstrap_from_sessions` paths that lack validation entirely. The test helper `src/test_helpers/reentrant_target.cairo` already proves the harness can express adversarial verifiers; it just needs an `EvilVerifier` analog.
- **Recommended fix:** add `src/test_helpers/evil_verifier.cairo` that exposes a configurable misbehavior (panic, reentry into selected mutator, return-true-on-invalid), then add the tests under H-1, M-1, and M-2 above plus the explicit M-2 negative.
- **Regression test:** see code blocks under H-1 / M-1 / M-2.

---

### L-1 — JWT base verifier `iss` check has no anchor (asymmetric with H-2 sub anchor)

- **Severity:** **Low** — practical exploitability is essentially zero today (JSON string-escape semantics + ECDSA binding to Apple's signing key), but inconsistent with the H-2 fix in the sub-bound verifier and fragile to upstream JSON serialization changes.
- **Files:** `src/signer/jwt_es256/verifier.cairo:215-240`, `src/signer/jwt_es256_apple_sub/verifier.cairo:228-252`
- **Description:** The `iss` check confirms 25 ASCII bytes at `iss_offset` equal `https://appleid.apple.com`, but does not verify the bytes are the *value* of an `iss` claim (no `"iss":"` preamble check, no closing `"` check). The H-2 fix in `check_sub_preamble` sets the precedent for JSON-anchored byte windows; the iss check should follow the same pattern. In practice the only place `https://appleid.apple.com` legitimately appears in an Apple-signed JWT is the `iss` value, and JSON quote-escaping prevents direct embedding inside other string fields, so the practical attack surface is nil — but the structural inconsistency is worth closing now while you're standardizing the SNIP.
- **Recommended fix:** add `check_iss_preamble` (`"iss":"` = `0x22 0x69 0x73 0x73 0x22 0x3A 0x22`) and a closing-quote check, mirroring `check_sub_preamble`. Update the same in the sub-bound verifier.
- **Regression test:**
  ```cairo
  // tests/signer_jwt_es256.cairo
  #[test]
  fn test_iss_check_rejects_unanchored_substring_match() {
      // Hand-construct a payload where 'https://appleid.apple.com' appears
      // inside an unquoted custom claim string (would currently pass).
      // After the fix, expect verify -> false.
  }
  ```

---

### Informational — Threshold path: duplicate-owner_id check runs after the inner library_call

- **Severity:** Informational — gas inefficiency, not a security issue
- **File:** `src/account.cairo:387-415`
- **Description:** `_verify_sub_envelope(...)` (which dispatches the library_call verifier) executes **before** the duplicate-`owner_id` rejection. A malicious caller can submit `n` copies of the same valid envelope and force the wallet to pay `n × verifier_gas` before the loop reverts at the duplicate check. The OE reverts atomically so no state moves, but a paymaster-paid OE leaks gas to a griefer. Hoist the duplicate scan above `_verify_sub_envelope` for cheap-fail-first ordering.

### Informational — Storage-write atomicity under panic (verified clean)

- **Severity:** Informational — no finding; verifying the prompt's specific concern
- **Files:** `src/account.cairo:469-472`, `1257-1259`
- **Description:** Confirmed Starknet/Cairo transaction semantics: a panic inside `dispatcher.verify(...)` reverts **the entire tx** including the preceding `self.inside_verifier.write(true)` write. There is no try/catch; there is also no partial commit. The flag therefore cannot get stuck `true`. Same applies to `oe_in_progress`. Add a regression test that uses a deliberately-panicking test verifier to make this provable rather than inferred:
  ```cairo
  #[test]
  fn test_panicking_verifier_does_not_stick_inside_verifier_flag() {
      // 1. Register a TestPanicVerifier (validate or verify panics).
      // 2. Submit an OE that hits it; expect tx revert.
      // 3. Submit a second, valid OE on a different nonce.
      // 4. Assert it succeeds (would fail with 'SHHH: verifier reentry'
      //    if the flag had stuck).
  }
  ```

### Informational — Class-upgrade nonce replay (verified clean)

- **Severity:** Informational — no finding
- **File:** `src/account.cairo:109`
- **Description:** `oe_nonces` is a top-level `Map<felt252, bool>` whose storage slot is derived from the field name; it persists losslessly across V8.0 → V8.1 → V8.2 class upgrades. Consumed nonces stay consumed. Verified.

### Informational — Verifier_classes change between propose and execute (verified bounded)

- **Severity:** Informational — no finding
- **Files:** `src/account.cairo:677-703`, `714-729`
- **Description:** `_validate_pubkey_via_verifier` reads `self.verifier_classes.read(kind)` at execute time. Between propose and execute, verifier_classes for non-primary kinds CAN be removed (24h timelock) and re-added (48h timelock + slot-must-be-empty re-check), so the verifier class can change. However: (a) all governance proposals are owner-controlled via `_assert_self_call`, (b) the verify path also uses the current verifier class, so a swapped class affects both validate and verify symmetrically, (c) the trust assumption ("verifier classes are governance-vetted") covers this. No exploit.

### Informational — `bootstrap_from_sessions` self-call gate (verified)

- **Severity:** Informational — no finding
- **File:** `src/account.cairo:962-1007`
- **Description:** Combined with the `primary_kind == 0` one-shot gate, `_assert_self_call` is robust. Multicall inner calls preserve `caller == self_addr` by Starknet syscall semantics, and external `__execute__` invocation is impossible on V8 because `__validate__` panics. Note: a freshly-upgraded V8 with `primary_kind == 0` is structurally bricked until `bootstrap_from_sessions` runs from inside the legacy class's atomic OE — the H-1 fix correctly forces this, and a separate-tx migration cannot succeed (which is the protective property; an attacker likewise cannot succeed).

### Informational — Spending-policy fresh-window edge case (verified clean for production)

- **Severity:** Informational — no finding on mainnet; tests-only quirk
- **File:** `src/spending_policy/component.cairo:100-105`
- **Description:** `if existing.window_start == 0` correctly distinguishes "no policy yet" from "in-flight policy" on any chain where `block_timestamp > 0`, which is true on all production Starknet networks. The only edge case is snforge tests that don't cheat block_timestamp, where a policy set at ts=0 would be re-classified as fresh on the second update. Add a comment to the source noting "assumes `block_timestamp != 0`" and document the test cheat assumption. Not a production concern.

---

## Reviewed sections with no findings

- **`src/outside_execution.cairo`** — SNIP-12 hashing binds `chain_id` and `contract_address` (line 169). Cross-account and cross-chain replay are cryptographically impossible. ✓
- **`src/signer/eip712_secp256k1/verifier.cairo`** — Domain separator reads `chain_id` from `get_tx_info()` and `salt` from `get_contract_address()` (lines 162-163). Both bind during library_call. ✓
- **`src/signer/eip191_secp256k1/verifier.cairo`** and **`src/signer/secp256k1/verifier.cairo`** — Replay protection inherited from the SNIP-12 hash (which they consume directly or via the EIP-191 keccak wrapper). ✓
- **`src/signer/webauthn_p256/verifier.cairo`** — Type prefix check (`{"type":"webauthn.get"`) closes the previous H-1 finding. UP-bit + challenge-binding + sha-of-sha all correct. ✓
- **`src/signer/jwt_es256_apple_sub/verifier.cairo`** sub-claim path — H-2 anchor (`"sub":"` preamble + closing `"`) is correctly enforced before ECDSA. The order is: nonce → iss → sub → ECDSA, with all anchor checks running first; ECDSA cannot rescue a broken anchor. ✓
- **`src/signer/bls12_381/verifier.cairo`** — `assert_in_subgroup_excluding_infinity` panic in `validate_pubkey` is functionally equivalent to `false` because Cairo reverts atomically. The "MAY panic" contract documented in `src/signer/interface.cairo:109-113` is honored. ✓
- **Threshold envelope role check** — C-1 fix correctly enforced inside `_verify_sub_envelope` (line 1246: `assert(owner.role == ROLE_OWNER)`). Tombstoned owners rejected via `!owner.revoked` (line 1241). ✓
- **`oe_in_progress` reentrancy guard** — set at the top of `execute_from_outside_v2`, cleared at every return path; combined with atomic-revert semantics, indirect re-entry is impossible. ✓

---

## Executive Summary

I do **not** recommend Phase-13 sign-off on this commit as-is. The critical finding is **H-1: `finalize_recovery` lacks `_validate_pubkey_via_verifier`** — V8.2 advertises "M-1 fully closed" but the recovery path quietly bypasses the new helper, allowing a malicious or compromised guardian to stage a poison-pill owner addition that survives the 7-day window. This is not a SNIP-blocker (no fund theft is enabled), but it is an *integrity-of-claim* blocker: shipping a SNIP-108 reference implementation that says "M-1 fully closed" while the recovery path skips validation undermines the reference quality. The companion **M-1 finding** (`_call_validate_pubkey_with_flag` deliberately omits `inside_verifier` based on incorrect upstream-gating reasoning) is the same defense-in-depth tier that motivated the M-2 fix; closing M-2 but not its mirror in V8.2 is asymmetric and the source comment says so explicitly. **M-3** is also serious: there is no executable negative test for the M-2 reentrancy guard, and the V8.2 validate_pubkey tests verify each verifier in isolation rather than through the account integration, leaving every "defense-in-depth" claim unproven by CI. The two changes I'd require before mainnet promotion are (1) wire `_validate_pubkey_via_verifier` into both `finalize_recovery` and `bootstrap_from_sessions`, and (2) refactor `_call_validate_pubkey_with_flag` to take `ref self` and raise the `inside_verifier` flag — together they fully close M-1 and M-2 across all three owner-mutation entry points, without changing the public ABI. The L-1 (JWT iss anchor) and the threshold ordering note are nice-to-have polish for the SNIP draft. With those three changes in place — and a `TestEvilVerifier` test helper added to make the negative cases CI-enforced — the codebase is ready for SNIP-108 submission and Phase-13 mainnet sign-off.
