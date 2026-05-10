# M-1 partial — what shipped, what's missing, V8.2 path

> Audit-finding M-1 from the [2026-05-07 self-review](./../audits/2026-05-07-claude-opus-pre-phase13-review.md) was rated Medium severity (no fund-theft path). V8.1 ships the **partial fix**. This doc captures what was deferred and what V8.2 needs to close it fully.

---

## The finding in one sentence

`add_owner` accepted any `pubkey_bytes: Span<felt252>` without per-kind shape or curve-membership validation, so a malformed pubkey could be registered, lock that `owner_id` out of every multisig flow, and DoS the threshold path.

## What V8.1 shipped (the partial)

- A new helper in `account.cairo`: `_assert_pubkey_shape(kind, pubkey)` runs at every registration site (`execute_add_owner`, `execute_rotate_owner`, and indirectly `bootstrap_from_sessions`).
- It enforces the per-kind length table:

| Kind tag | Expected `pubkey.len()` |
|---|---|
| `STARK` | 1 |
| `ED25519` | 2 |
| `SECP256K1` | 4 |
| `EIP191_SECP256K1` | 4 |
| `EIP712_SECP256K1` | 4 |
| `P256` | 4 |
| `WEBAUTHN_P256` | 4 |
| `JWT_ES256` | 4 |
| `JWT_ES256_APPLE_SUB` | 5 |
| `BLS12_381` | 16 |

- Wrong length → revert `'M1: bad pubkey shape'`. Unknown kind → revert `'M1: unknown owner kind'`.

- Test coverage: the V8 audit-regression suite (`tests/audit_v8.cairo`) covers length-mismatch rejections via the existing add_owner test fixtures.

## What V8.1 does NOT catch

The partial fix catches "wrong number of felts" registration mistakes (the most common footgun) but does NOT validate that the pubkey is on its curve or in the correct subgroup. Specifically:

| Kind | Failure mode if a malformed-but-shape-correct pubkey is registered |
|---|---|
| `BLS12_381` | **Hard panic** inside `pubkey_g2.assert_in_subgroup_excluding_infinity(...)` on every verify involving that owner. → Permanent DoS of the multisig path that includes that `owner_id`. **Most severe failure mode.** |
| `SECP256K1` / `P256` / `WEBAUTHN_P256` | `secp256_ec_new_syscall(x, y)` returns `Err`; the verifier maps that to `false`. **Soft fail** — owner can never satisfy a sig but doesn't break the threshold path. |
| `ED25519` | Garaga's `is_valid_eddsa_signature` returns `false` for invalid pubkey halves. Soft fail. |
| `EIP191` / `EIP712` | The pubkey isn't directly used (verification recovers from `(r, s, v)` and asserts equality to stored). Mismatch → soft fail. |
| `JWT_ES256` / `_APPLE_SUB` | First 4 felts are P-256 pubkey; soft fail like `P256`. The 5th felt (`sub_hash`) is any felt252; no validation needed. |
| `STARK` | Single felt; mismatch → ECDSA verify returns false. Soft fail. |

So the residual gap is **BLS12-381**: a non-r-torsion-but-on-curve G2 point can land in `owners` and poison-pill any multisig that includes it. The audit rated this Medium because:
- No fund-theft path (the verifier's subgroup check still rejects sigs from a poisoned owner).
- The harm is multisig DoS, not key compromise.
- A poisoned owner can be `remove_owner`'d (timelocked) by remaining owners.

## Why it wasn't fully fixed in V8.1

Three reasons, in order:

1. **Critical/High findings were the V8.1 gating items.** C-1, H-1, H-2, H-3 close in V8.1 with single-line fixes touching only `account.cairo` + one verifier file. M-1 full fix touches all 10 verifier classes + the `ISigner` trait + the account, and forces a full redeclare. Lumping it with C/H would have stretched the audit-closure cycle from days to weeks.

2. **The full fix needs a non-panicking BLS subgroup check** in Cairo. Garaga's `assert_in_subgroup_excluding_infinity` panics by design. To return `bool` instead, we have to mirror the function logic ourselves: compute `psi(Q)` and `seed * Q`, check equality, return bool. ~80 LOC of careful BLS12-381 G2 math that needs its own regression tests.

3. **Cost.** Adding `validate_pubkey` to the `ISigner` trait changes the trait shape, which changes Sierra, which changes every verifier class hash. Redeclaring all 11 classes costs ~204 STRK (≈$8). Worth doing in one batch after Phase 13 audit findings, not one-off.

## V8.2 path — what's needed for full closure

### 1. Add `validate_pubkey` to `ISigner`

```cairo
// src/signer/interface.cairo

#[starknet::interface]
pub trait ISigner<TContractState> {
    fn verify(
        self: @TContractState,
        message_hash: felt252,
        pubkey: Span<felt252>,
        signature: Span<felt252>,
    ) -> bool;
    fn kind(self: @TContractState) -> felt252;

    /// Audit M-1 (full) — returns true iff `pubkey` is a structurally
    /// valid public key for this verifier's kind. MUST be pure (no
    /// storage writes) and MUST NOT panic on malformed input.
    /// On-curve / subgroup-membership checks happen here so the
    /// account can reject bad pubkeys at registration before they
    /// poison the owner_set.
    fn validate_pubkey(self: @TContractState, pubkey: Span<felt252>) -> bool;
}
```

### 2. Per-verifier implementations

- **STARK**:
  ```cairo
  fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
      pubkey.len() == 1 && *pubkey.at(0) != 0
  }
  ```
- **ED25519**: shape only (Garaga handles in-curve at verify time).
  ```cairo
  fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
      if pubkey.len() != 2 { return false; }
      let _: u128 = match (*pubkey.at(0)).try_into() { Option::Some(v) => v, Option::None => { return false; } };
      let _: u128 = match (*pubkey.at(1)).try_into() { Option::Some(v) => v, Option::None => { return false; } };
      true
  }
  ```
- **SECP256K1 / EIP191 / EIP712**: try-construct via syscall.
  ```cairo
  fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
      if pubkey.len() != 4 { return false; }
      let x_low:  u128 = match (*pubkey.at(0)).try_into() { Option::Some(v) => v, _ => { return false; } };
      let x_high: u128 = match (*pubkey.at(1)).try_into() { Option::Some(v) => v, _ => { return false; } };
      let y_low:  u128 = match (*pubkey.at(2)).try_into() { Option::Some(v) => v, _ => { return false; } };
      let y_high: u128 = match (*pubkey.at(3)).try_into() { Option::Some(v) => v, _ => { return false; } };
      let x = u256 { low: x_low, high: x_high };
      let y = u256 { low: y_low, high: y_high };
      // secp256_ec_new_syscall returns Result; Err on off-curve/zero.
      match secp256k1_ec_new_syscall(x, y) {
          Ok(opt) => opt.is_some(),
          Err(_) => false,
      }
  }
  ```
- **P256 / WEBAUTHN_P256**: same as secp256k1 but the P-256 syscall variant.
- **JWT_ES256**: same as P256 (4 felts must be a valid P-256 pubkey).
- **JWT_ES256_APPLE_SUB**: 5 felts; first 4 must be valid P-256 pubkey, 5th (sub_hash) any felt252:
  ```cairo
  fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
      if pubkey.len() != 5 { return false; }
      // ... validate first 4 as P-256 ...
      // sub_hash (pubkey.at(4)) is any felt252 — no validation needed.
      true
  }
  ```
- **BLS12_381** — the hard one:
  ```cairo
  fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
      if pubkey.len() != 16 { return false; }
      // Limb fit: every felt must be < 2^96 (otherwise downcast::<u96> fails)
      let mut i: u32 = 0;
      while i < 16 {
          let _: u96 = match (*pubkey.at(i)).try_into() {
              Option::Some(v) => v,
              Option::None => { return false; },
          };
          i += 1;
      }
      let pk_g2 = parse_g2_point(pubkey);  // shape-checked above
      // Use the non-panicking variant:
      pk_g2.is_on_curve_excluding_infinity(BLS_CURVE_INDEX)
          && _try_in_subgroup_g2_bls12_381(pk_g2)
  }

  /// Audit M-1 (BLS subgroup check) — mirrors
  /// `garaga::ec::ec_ops_g2::G2PointTrait::assert_in_subgroup_excluding_infinity`
  /// but returns bool instead of panicking on a non-r-torsion point.
  /// Subgroup check: psi(Q) == seed * Q (BLS12-381 specific).
  fn _try_in_subgroup_g2_bls12_381(q: G2Point) -> bool {
      // Compute psi(Q) — Frobenius endomorphism on the twisted curve.
      let modulus = get_modulus(BLS_CURVE_INDEX);
      let psi_Q = ec::run_PSI_G2_BLS12_381_circuit(q, modulus);
      // Compute seed * Q (BLS x-seed scalar mul).
      let seed_Q = scalar_mul_by_bls12_381_seed(q);
      // Subgroup membership ⇔ psi(Q) == seed*Q.
      psi_Q == seed_Q
  }
  ```
  ~80 LOC for `_try_in_subgroup_g2_bls12_381` + dependent helpers.

### 3. Update `account.cairo` to call `validate_pubkey`

Replace `_assert_pubkey_shape(kind, pubkey)` with a library_call to the registered verifier:

```cairo
// In execute_add_owner / execute_rotate_owner / bootstrap_from_sessions:
let v_class = self.verifier_classes.read(kind);
assert(Into::<ClassHash, felt252>::into(v_class) != 0, 'SHHH: verifier missing');
let validator = ISignerLibraryDispatcher { class_hash: v_class };
self.inside_verifier.write(true);   // M-2 reuse — same flag
let ok = validator.validate_pubkey(pubkey_span);
self.inside_verifier.write(false);
assert(ok, 'M1: invalid pubkey');
```

### 4. Tests

Per-verifier `validate_pubkey` regression test (10 verifiers × ~3 cases each = ~30 new tests):
- Valid pubkey → returns true
- Wrong length → returns false (no panic)
- On-curve but not-in-subgroup (BLS only) → returns false (no panic)
- Garbage limbs → returns false (no panic)

Account-level integration test:
- `propose_add_owner` + `execute_add_owner` with invalid BLS pubkey → reverts `'M1: invalid pubkey'`
- Same with valid BLS pubkey → succeeds
- `execute_rotate_owner` with invalid pubkey → reverts

Expected test count: 218 (V8.1) + ~35 (V8.2) ≈ **253 tests**.

### 5. Mainnet redeclares

V8.2 redeclares of all 11 classes. Hashes will be different (Sierra changes when trait shape changes).

Cost projection:

| Class | Sierra Δ vs V8.1 | Redeclare fee (est.) |
|---|---|---|
| ShhhAccount V8.2 | ~+5% (~870 KB) | ~45 STRK |
| StarkVerifier | trivial | ~1.5 STRK |
| Ed25519Verifier | trivial | ~32 STRK |
| Secp256k1Verifier | small (one syscall + match) | ~3.5 STRK |
| EIP191Secp256k1Verifier | small | ~7 STRK |
| EIP712Secp256k1Verifier | small | ~8 STRK |
| P256Verifier | small | ~3.2 STRK |
| WebAuthnP256Verifier | small | ~12.5 STRK |
| JwtES256AppleVerifier | small | ~14 STRK |
| JwtES256AppleSubVerifier | small | ~15 STRK |
| Bls12_381MinSigVerifier | larger (~+80 LOC subgroup helper) | ~62 STRK |
| **Total** | | **~204 STRK (≈$8)** |

### 6. SDK / docs updates

- `src/lib/constants.ts` (Shhh app): bump `V8_SHHH_ACCOUNT_CLASS_HASH` to V8.2; update `V8_VERIFIER_CLASS_HASHES` map; rename V8.1 to `V8_SHHH_ACCOUNT_CLASS_HASH_V1_DEPRECATED`.
- `docs/class-hashes.md`: V8.2 row + deprecation banner on V8.1.
- `docs/mainnet-deployment.md`: declare-tx record for V8.2.
- `docs/v8-1-sdk-integration.md`: bump to v8-2-sdk-integration.md (or version-tag).

## Effort estimate

**2-3 days focused work**:

- Day 1 — `validate_pubkey` for the 8 simpler verifiers + ISigner trait update + their tests
- Day 2 — BLS12-381 non-panicking subgroup check + its tests
- Day 3 — `account.cairo` integration + integration tests + V8.2 redeclares + doc updates + SDK constants

## Sequencing decision

**Recommended**: defer V8.2 until after Phase 13 external audit. Reasons:

1. The audit may surface other findings worth bundling into the same V8.2 redeclare cycle.
2. Phase 13 firms typically prefer auditing the version that's about to ship, not a "we'll fix it next quarter" version.
3. ~204 STRK is non-trivial; doing it once with all known fixes is cheaper than two redeclares.

**Alternative**: ship V8.2 immediately if Chipi Pay or another integrator hits the BLS poison-pill DoS in practice. Until that happens, the partial fix is sufficient.

## Tracking

- Audit doc: [`audits/2026-05-07-claude-opus-pre-phase13-review.md`](./../audits/2026-05-07-claude-opus-pre-phase13-review.md), section M-1.
- V8.1 partial fix: PR #3, commit `f17209c` on `v8-robust`.
- This doc: source of truth for V8.2 scope. Update when V8.2 work starts.
- Open issue: file against `haycarlitos/shhh-wallet-cairo` with the `audit-m1-full` label when ready to start.

Last reviewed: 2026-05-10.
