# Shhh Wallet Cairo — Pre-Phase-13 Self-Review

Date: 2026-05-07
Reviewer: Carlos Castillo (`@haycarlitos`), assisted by Anthropic Claude Opus 4.7
Repository: https://github.com/haycarlitos/shhh-wallet-cairo
Branch / commit: `v8-robust` @ `05087b8`
Scope: V8 ShhhAccount + 10 verifier classes + owner-set / governance / recovery / session-key / spending-policy components, OE replay protection, regression-test fixtures.

## Attribution note

This document is an **in-flight self-review** intended to feed the Phase 13
human audit (round-2 by Omar / Zellic / Nethermind / OZ). It is not a third-
party audit. Per the same convention applied to Henri's Nethermind AuditAgent
scan (`audits/README.md`): **this repository does not claim to be "audited
by Anthropic" or "audited by Claude"** — the credit is to the project
maintainer who ran the review with AI assistance and triaged the findings.

The findings below were produced by manual code reading + adversarial
reasoning over the V8 codebase as it stands on `v8-robust`, with focus on the
attack surfaces newest to V8 (multi-role owner set, sessions-wallet
migration, BLS12-381 verifier declared 2026-05-06, JWT sub-binding, library-
call dispatcher trust model). The 12 findings from Omar's 2026-04-20 audit
and the 3 from Henri's 2026-04-13 scan are NOT re-litigated; their regression
tests in `tests/audit_2026_04_20.cairo` + `tests/audit_v8.cairo` were
verified against current contract code.

## Executive summary

**Recommendation: do NOT close Phase 13 in the current shape.**

The codebase is well-structured, the existing audit response (Omar 2026-04-20
+ Henri 2026-04-13) is genuinely closed with named regression tests, and the
new pluggable-signer architecture is the right direction. The 10 verifiers
reviewed are individually careful (correct subgroup ordering on BLS, correct
EIP-712 domain binding, correct WebAuthn type-confusion fix per the self-
audit, correct Ed25519 envelope hardening per audit M-4).

However, V8 introduced two structural primitives — multi-role owners and a
sessions-wallet migration entrypoint — that ship with **one Critical**,
**three High**, and **three Medium** findings that are not artifacts of the
new verifier code; they live in the account itself and on already-mainnet-
declared classes.

The Critical finding (C-1, guardian-role bypass) is a true silent privilege
escalation: a user adding a `ROLE_GUARDIAN` thinking they are enabling
recovery is, today, adding a co-owner with full drain authority. This
invalidates the recovery security model the docs advertise. Combined with
H-1 (front-runnable migration), this gives an attacker two distinct paths to
seize a victim account: either be added as a "guardian friend" or front-run
the SNIPs#163 migration window.

Because the V8 `ShhhAccount` class hash `0x01d6e475…` is already declared on
mainnet (2026-04-28), the fix requires a V8.1 declare and an opt-in
migration path. Recommended sequencing:

1. Land C-1, H-1, H-2, H-3 fixes on `v8-robust` with named regression tests.
2. Declare V8.1; mark V8.0 deprecated for new deploys (existing instances
   keep working but should rotate).
3. Hand the V8.1 commit to the Phase 13 firm with this self-review attached
   so they verify the role-check is in BOTH the single-owner OE path and the
   threshold sub-envelope path before they pass off.

## Severity scale

Per `audits/README.md`: Critical / High / Medium / Low / Informational.

## Findings index

| ID  | Severity      | Title                                                                                       |
|-----|---------------|---------------------------------------------------------------------------------------------|
| C-1 | Critical      | Guardian role grants full owner-equivalent signing privileges                               |
| H-1 | High          | `bootstrap_from_sessions` is front-runnable on every upgraded SNIPs#163 wallet              |
| H-2 | High          | JWT-ES256 sub binding is anchorless inside the JSON payload                                 |
| H-3 | High          | Spending-policy update silently resets `spent_in_window`                                    |
| M-1 | Medium        | `add_owner` does not validate kind-specific pubkey shape; bad BLS12-381 pubkey panics       |
| M-2 | Medium        | Library-call verifier can re-enter `_assert_self_call`-gated mutators                       |
| M-3 | Medium        | V8 audit-regression suite is missing M-4, H-2, I-3, L-1 mirrors                             |
| L-1 | Low           | `OP_INITIATE_RECOVERY` / `OP_FINALIZE_RECOVERY` op-kind constants are dead code             |
| I-1 | Informational | `__execute__` is unreachable in practice; intent should be commented inline                 |
| I-2 | Informational | `_total_calldata_felts` re-iterates `Span<Call>` independently of the multicall executor    |
| I-3 | Informational | BLS12-381 verifier subgroup-check ordering, pubkey negation, lines_len gate, DST: no findings |
| I-4 | Informational | EIP-712 domain binding (chain_id + account address): no findings                            |
| I-5 | Informational | OE replay protection (SNIP-12 hash + nonce map): no findings                                |
| I-6 | Informational | Recovery cancel-window arithmetic: no findings (modulo C-1)                                 |

---

## C-1: Guardian role grants full owner-equivalent signing privileges

Files:
- `src/account.cairo:431-446` (single-owner OE path)
- `src/account.cairo:1103-1121` (`_verify_sub_envelope`, threshold inner)

Severity: **Critical**

### Vulnerability

Both OE verification paths gate on `!owner.revoked` and
`owner.kind == kind_tag`, but **never check `owner.role`**. The role
distinction (`ROLE_OWNER` / `ROLE_GUARDIAN` / `ROLE_RECOVERY_ONLY`) is
enforced only at `initiate_recovery` (must be `ROLE_GUARDIAN`) and
`cancel_recovery` (must be `ROLE_OWNER`). Everywhere else — including
arbitrary multicalls, governance proposals, treasury moves, and threshold-
weight contribution — a non-revoked `ROLE_GUARDIAN` is indistinguishable
from a primary owner. A user who follows the documented Argent-style
recovery pattern ("add a friend's key as a guardian for emergency
recovery") is silently giving that key full account-drain authority.

### Concrete exploit (5-line pseudo-Cairo)

```cairo
// Owner adds a guardian intending recovery-only trust.
gov.propose_add_owner(0, 'STARK', array![attacker_pk], ROLE_GUARDIAN, 1, 'friend');
gov.execute_add_owner(op_id, 'STARK', array![attacker_pk], ROLE_GUARDIAN, 1, 'friend');
// Guardian (attacker) signs an OE that calls `transfer(victim, all_funds)`.
let envelope = array![SIG_VERSION_V2_SNIP12, guardian_id, 'STARK', r, s];
src9.execute_from_outside_v2(drain_oe, envelope.span());  // succeeds — no role check
```

### Recommended fix

In both verification paths, after the `!owner.revoked` assert, add:

```cairo
// account.cairo line 435 (single-owner) AND line 1110 (_verify_sub_envelope)
assert(owner.role == ROLE_OWNER, 'SHHH: signer not an owner');
```

If the design intends weighted multisig that explicitly INCLUDES guardians'
signatures toward threshold, that should be opt-in via a per-account flag,
not the default. The threshold path's `_verify_sub_envelope` should likewise
refuse to count a guardian's weight unless an explicit
`allow_guardian_in_threshold` flag is set on the owner record.

### Regression test

```cairo
#[test]
#[should_panic(expected: 'SHHH: signer not an owner')]
fn test_guardian_cannot_sign_arbitrary_oe() {
    let (addr, target, _kp_owner, kp_guardian, guardian_id) = deploy_account_with_guardian_kp();
    let (oe, hash) = build_oe_and_hash(addr, target, 'guardian-drain');
    let (r, s) = kp_guardian.sign(hash).unwrap();
    let envelope: Array<felt252> = array![SIG_VERSION_V2_SNIP12, guardian_id.into(), 'STARK', r, s];
    cheat_for_oe(addr);
    ISRC9_V2Dispatcher { contract_address: addr }
        .execute_from_outside_v2(oe, envelope.span());
}
```

---

## H-1: `bootstrap_from_sessions` is front-runnable on every upgraded SNIPs#163 wallet

File: `src/account.cairo:924-961`

Severity: **High**

### Vulnerability

The migration entrypoint is `external(v0)` with no caller gate beyond
`assert(self.primary_kind.read() == 0, 'MIG: already initialized')`. The
acknowledged design ("trust the SDK to bundle `upgrade` +
`bootstrap_from_sessions` in the same OE multicall") is fragile — every
non-bundled upgrade leaves a window in which any address watching the
mempool can call `bootstrap_from_sessions(attacker_pk, …)` first and seize
the account. There is no on-chain enforcement that bundling occurred. The
migration test fixture `tests/account_migration.cairo:98-128` deliberately
calls `bootstrap_from_sessions` directly (not via OE multicall), which
proves the path is reachable from any caller.

### Concrete exploit

```cairo
// Mempool watcher sees victim's `upgrade(SHHH_V8)` tx land. Race with:
let mig = IShhhMigrationDispatcher { contract_address: victim_account };
let attacker_class: ClassHash = stark_verifier_class;
mig.bootstrap_from_sessions(attacker_pubkey, attacker_class, 'pwned');
// Attacker is now the only owner; victim's old sessions-wallet signer
// is gone from V8 storage and they cannot re-bootstrap because
// primary_kind != 0.
```

### Recommended fix

Force atomic bundling by gating on self-call (matches every other mutator
in the contract):

```cairo
// account.cairo line 925
fn bootstrap_from_sessions(
    ref self: ContractState, public_key: felt252,
    stark_verifier_class: ClassHash, label: felt252,
) {
    _assert_self_call();                                     // <— add
    assert(self.primary_kind.read() == 0, 'MIG: already initialized');
    // … rest unchanged
}
```

This is non-breaking: the legitimate path is the OLD class's multicall
executing `[upgrade, bootstrap_from_sessions]` in one OE, where call 2's
caller is the account itself. Direct external invocation reverts.

### Regression test

```cairo
#[test]
#[should_panic(expected: 'SHHH: caller != self')]
fn test_bootstrap_rejects_external_caller() {
    let (addr, verifier) = declare_and_deploy();
    reset_for_migration_simulation(addr);
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    IShhhMigrationDispatcher { contract_address: addr }
        .bootstrap_from_sessions(0xCAFE, verifier, 'pwned');
}
```

---

## H-2: JWT-ES256 sub binding is anchorless inside the JSON payload

File: `src/signer/jwt_es256_apple_sub/verifier.cairo:254-278`

Severity: **High**

### Vulnerability

The sub binding hashes whatever bytes live at
`payload_decoded[sub_offset .. sub_offset+sub_len]` and compares to
`stored_sub_hash`. The verifier never enforces that `sub_offset` actually
points at the value of the JSON `"sub"` claim — i.e., that those bytes are
immediately preceded by `"sub":"` and immediately followed by `"`. Apple's
JWT contains many user-controlled string fields (notably `email`, and during
onboarding `name.firstName` / `name.lastName` set via the
`ASAuthorizationAppleIDRequest`). An attacker who controls any string field
whose contents can be made to equal the victim's `sub` bytes can submit
their *own* Apple-signed JWT with `sub_offset` pointing into the controlled
field, pass the sub binding, and authenticate against the victim's V8
account. ECDSA over the canonical signing input still validates because the
JWT was genuinely signed by Apple — for the attacker.

### Concrete exploit

```typescript
// Attacker controls Apple account; target sub = "001234.deadbeef.5678".
// Attacker sets their Apple "name" field to include the victim's sub bytes.
const myJWT = await appleSignIn({
  name: { firstName: "001234.deadbeef.5678", lastName: "X" },
  nonce: snip12HashOfDrainOE,
});
// sub_offset → byte index of "001234..." inside the firstName field
// (NOT the real "sub" claim), sub_len = 19.
submitOE(victimAccount, drainOE, encodeJwtSubEnvelope(myJWT, sub_offset_to_firstName));
// Verifier: ECDSA OK (Apple really signed this for me),
//           iss OK ("https://appleid.apple.com" present),
//           sub OK (poseidon over firstName bytes == victim's sub_hash).
```

### Recommended fix

Anchor the sub read to a JSON marker. Either parse the payload once before
hashing, or require a 7-byte preamble check `"sub":"` immediately before
`sub_offset` and a closing `"` at `sub_offset + sub_len`:

```cairo
// Before line 265 in the verifier:
assert(sub_offset >= 7_u32, 'JWTSUB: sub_offset underflow');
const SUB_MARKER: [u8; 7] = [0x22, 0x73, 0x75, 0x62, 0x22, 0x3A, 0x22]; // "sub":"
let mut a: u32 = 0;
while a < 7_u32 {
    let want = SUB_MARKER[a];
    let got = payload_decoded.at(sub_offset - 7 + a).expect('JWTSUB: oob');
    if got != want { return false; }
    a += 1;
}
let closer = payload_decoded.at(sub_offset + sub_len).expect('JWTSUB: oob');
if closer != 0x22 { return false; }
```

A more defensive long-term fix is a true JSON parser; the marker check
above closes this exact attack at low cost.

### Regression test

```cairo
#[test]
fn test_jwtsub_rejects_sub_offset_pointing_into_email_field() {
    // Fixture: JWT with "email":"victim_sub" (or any non-sub field whose
    // value byte-matches a stored sub_hash for a different user).
    let d = dispatcher();
    let pk = jwtsub_pubkey_for_attacker_account();
    let sig = jwtsub_envelope_sub_offset_in_email_fixture();
    let ok = d.verify(jwtsub_message_hash(), pk.span(), sig.span());
    assert(!ok, 'sub anchor missing — bypass possible');
}
```

---

## H-3: Spending-policy update silently resets `spent_in_window`

File: `src/spending_policy/component.cairo:78-104`

Severity: **High**

### Vulnerability

`set_spending_policy` *unconditionally* writes `spent_in_window: 0` and
`window_start: get_block_timestamp()`. There is no merge with the existing
record. The function is `_assert_self_call`-gated so an external attacker
cannot trigger it directly, but a session-key creator who calls
`set_spending_policy` to *tighten* a cap mid-window (e.g., realizing a
session is leaking) hands the running session a fresh window worth of
budget. If the OE that adjusts the policy is bundled in the same multicall
as a session-driven transfer, the order matters: a malicious paymaster or
a deliberately-chosen call order can cause the new (looser-than-intended)
cap to apply to the very transfer the owner was trying to throttle.

### Concrete exploit

```cairo
// Session-key has spent 95 USDC of 100/day cap. Owner panics, signs an OE
// to LOWER cap to 50/day. Same block, attacker's session-tx lands in:
//   [ owner.set_spending_policy(session, USDC, 25, 50, 86400) ]   // resets
//     → spent_in_window := 0, window_start := now
// followed by [ session.transfer(USDC, 25) ]                       // 25 ≤ 25, passes
// followed by [ session.transfer(USDC, 25) ]                       // 25 ≤ 25, passes
// Attacker drained 50 more USDC despite the "tightening".
```

### Recommended fix

Preserve in-flight window state when a policy is updated:

```cairo
// component.cairo line 89
let existing = self.policies.read((session_key, token));
let policy = SpendingPolicy {
    max_per_call,
    max_per_window,
    window_seconds,
    spent_in_window: existing.spent_in_window,    // <— preserve
    window_start: if existing.window_start == 0 { get_block_timestamp() }
                  else { existing.window_start }, // <— preserve
};
```

Document explicitly that `set_spending_policy` only changes caps and window
length; window state is preserved. Add a separate `reset_spending_window`
entrypoint if reset semantics are wanted.

### Regression test

```cairo
#[test]
fn test_set_spending_policy_preserves_spent_in_window() {
    let (addr, sk, token) = deploy_with_session_and_policy(/*cap*/ 100);
    consume_session_spend(addr, sk, token, 95);
    start_cheat_caller_address(addr, addr);
    IShhhSessionsDispatcher { contract_address: addr }
        .set_spending_policy(sk, token, 25, 50, 86400);
    let p = read_policy(addr, sk, token);
    assert(p.spent_in_window == 95, 'window state was reset');
    assert(p.max_per_window == 50, 'cap not tightened');
}
```

---

## M-1: `add_owner` does not validate kind-specific pubkey shape; bad BLS12-381 pubkey is registrable

Files:
- `src/owner_set/component.cairo:115-151`
- `src/account.cairo::execute_add_owner` (lines 651-668)

Severity: **Medium**

### Vulnerability

`add_owner` accepts any `pubkey_bytes: Span<felt252>` and stores it verbatim.
There is no per-kind shape or curve-membership check. For BLS12-381 in
particular, `Bls12_381MinSigVerifier::verify` calls
`pubkey_g2.assert_in_subgroup_excluding_infinity(BLS_CURVE_INDEX)`, which
**panics** on a non-r-torsion point. Once a malformed pubkey is registered
for owner_id N, every subsequent OE that includes owner N — single-owner
*or* threshold inner — reverts before the pairing check, permanently DoS-ing
that owner slot. For P-256 / secp256k1, an `(x,y)` pair off the curve fails
`secp256_ec_new_syscall` and returns `false` (graceful), which is fine. For
Ed25519 the verifier accepts any `u128` halves and offloads checks to Garaga
(graceful). The BLS panic-on-bad-pubkey is the unique failure mode worth
catching at registration.

The verifier docstring acknowledges this: *"a malformed point means the
owner registration was wrong upstream"* — but upstream does no validation.

### Concrete exploit

```cairo
gov.propose_add_owner(0, 'BLS12_381',
    /* 16 felts of nonsense not on the BLS12-381 G2 r-torsion */
    array![1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0],
    ROLE_OWNER, 1, 'attack');
gov.execute_add_owner(op_id, 'BLS12_381', /*…same…*/, ROLE_OWNER, 1, 'attack');
// Now any threshold OE that names this owner_id reverts inside the
// dispatcher — they're a poison pill in a multisig set.
```

Severity is Medium because there is no fund-theft path; subgroup check still
gates the pairing in the verifier itself, so cofactor-style forgery is
blocked. Impact is targeted DoS of multisig flows that include the poisoned
owner.

### Recommended fix

Add a `validate_pubkey(pubkey: Span<felt252>) -> bool` method to the
`ISigner` trait and call it from `execute_add_owner`,
`bootstrap_from_sessions`, and `rotate_owner_pubkey`:

```cairo
// account.cairo line 665, before owners.add_owner(…)
let v_class = self.verifier_classes.read(kind);
assert(Into::<ClassHash, felt252>::into(v_class) != 0, 'SHHH: verifier missing');
let validator = ISignerLibraryDispatcher { class_hash: v_class };
assert(validator.validate_pubkey(pubkey_span), 'SHHH: invalid pubkey');
```

Each verifier implements `validate_pubkey`: raw-secp/p256 calls
`secp256_ec_new_syscall`, BLS calls `assert_in_subgroup_excluding_infinity`
inside a `Result`-wrapping helper and returns false on failure, Ed25519 /
STARK / WebAuthn / EIP-191 / EIP-712 do shape-only checks.

### Regression test

```cairo
#[test]
#[should_panic(expected: 'SHHH: invalid pubkey')]
fn test_add_owner_rejects_off_curve_bls_pubkey() {
    let addr = deploy_account_with_bls_verifier();
    let gov = IShhhGovDispatcher { contract_address: addr };
    let bad: Array<felt252> = array![1,0,0,0, 1,0,0,0, 1,0,0,0, 1,0,0,0];
    cheat_self(addr);
    let op = gov.propose_add_owner(0, 'BLS12_381', bad.clone(), ROLE_OWNER, 1, 'bad');
    advance_past_timelock();
    gov.execute_add_owner(op, 'BLS12_381', bad, ROLE_OWNER, 1, 'bad');
}
```

---

## M-2: Library-call verifier can re-enter `_assert_self_call`-gated mutators

Files:
- `src/account.cairo:444-446` (single-owner `dispatcher.verify` call)
- `src/account.cairo:1117-1119` (`_verify_sub_envelope` `dispatcher.verify` call)

Severity: **Medium**

### Vulnerability

Verifier classes are dispatched via `library_call_syscall`, which executes
in the account's storage *and* address context. Inside such a verifier,
`call_contract_syscall(self_addr, "propose_add_owner", …)` would re-enter
the account with `caller == self_addr`, satisfying `_assert_self_call`. The
`oe_in_progress` reentrancy guard prevents *recursing into another OE*, but
it does NOT block direct calls to `propose_add_owner`, `cancel_pending_op`,
`set_spending_policy`, `add_or_update_session_key`, etc. The trust model is
"governance-vetted verifier classes only" + 48h `TIMELOCK_ADD_VERIFIER`
window for owners to cancel — but a single malicious verifier installation
post-cancel-window grants the verifier permanent self-call privileges from
*every* `verify()`.

### Concrete exploit

```cairo
// Malicious verifier class — its verify() always returns true and also:
fn verify(...) -> bool {
    let self_addr = get_contract_address();
    let calldata = serialize![/* attacker-controlled add_owner args */];
    call_contract_syscall(self_addr, selector!("propose_add_owner"), calldata.span());
    true
}
// Once governance executes add_verifier_class for kind X with this class,
// EVERY future OE signed under kind X silently injects a propose_add_owner.
```

### Recommended fix

Add an `inside_verifier` storage flag + check it from `_assert_self_call`:

```cairo
// account.cairo storage
inside_verifier: bool,

// before dispatcher.verify(...) at line 445 and line 1118
self.inside_verifier.write(true);
let ok = dispatcher.verify(message_hash, pubkey.span(), verifier_payload);
self.inside_verifier.write(false);

// _assert_self_call:
fn _assert_self_call(self: @ContractState) {
    assert(get_caller_address() == get_contract_address(), 'SHHH: caller != self');
    assert(!self.inside_verifier.read(), 'SHHH: verifier reentry');
}
```

### Regression test

Declare a `MaliciousVerifier` class in `src/test_helpers/` whose `verify`
calls back into `propose_add_owner`. Register it via governance, submit an
OE that triggers it, and assert the OE reverts with `'SHHH: verifier
reentry'`.

---

## M-3: V8 audit-regression suite (`tests/audit_v8.cairo`) is missing M-4, H-2, I-3, L-1 mirrors

File: `tests/audit_v8.cairo` (compared against `tests/audit_2026_04_20.cairo`)

Severity: **Medium**

### Vulnerability

The 2026-04-20 audit is regression-tested against `ShhhWallet` (V7), but
mainnet has been declaring V8 (`ShhhAccount`) since 2026-04-28. The V8
mirror covers C-1, M-1, M-2, M-3 (signature-len only — not calls/calldata),
H-1, the V8 admin blocklist, and a timelock-boundary mutant. Missing
mirrors:

- **M-4** (signature envelope truncation + trailing-bytes check) — V8
  dispatches into the verifier class, so the V7 in-place check no longer
  applies; M-4 should be re-asserted *per verifier* in their own tests.
- **H-2** (canonical SRC9 ID registered + V7 wrong ID NOT registered) —
  `tests/audit_v8.cairo` doesn't probe `supports_interface(ISRC9_V2_ID)` on
  a deployed `ShhhAccount`.
- **I-3** (no `upgrade` selector exposed on V8). Trivial mirror.
- **L-1** (constructor pubkey range check) — V8 uses `Span<felt252>` so
  the V7 `u128::MAX` boundary doesn't apply directly, but the constructor's
  `assert(pubkey.len() > 0)` and `'L1: primary_kind is zero'` paths should
  be regression-tested.

The risk: a regression in V8 that re-introduces, e.g., a non-canonical SRC9
ID would not be caught by the existing suite. Mainnet truth is the V8
class, not V7.

### Recommended fix

Add four V8 mirrors to `tests/audit_v8.cairo` matching the V7 suite shape:

```cairo
#[test] fn test_v8_h2_registers_canonical_snip9_id() {
    let addr = deploy_account();
    assert(ISRC5Dispatcher { contract_address: addr }.supports_interface(ISRC9_V2_ID),
           'V8 H2: canonical id missing');
}
#[test] #[should_panic] fn test_v8_i3_no_upgrade_entrypoint() {
    let addr = deploy_account();
    IMaybeUpgradeableDispatcher { contract_address: addr }
        .upgrade(0xdead.try_into().unwrap());
}
#[test] #[should_panic(expected: 'L1: primary_kind is zero')]
fn test_v8_l1_constructor_rejects_zero_kind() {
    let v = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let cls = declare("ShhhAccount").unwrap().contract_class();
    let _ = cls.deploy(@array![0, v.into(), 1, 0xAAAA, 'x']);
}
#[test] #[should_panic /* per-verifier trailing-bytes felt */]
fn test_v8_m4_trailing_bytes_in_verifier_payload_reverts() {
    /* sign valid Ed25519 OE, append junk felt to envelope, submit */
}
```

---

## L-1: `OP_INITIATE_RECOVERY` / `OP_FINALIZE_RECOVERY` op-kind constants are dead code

File: `src/governance/pending_ops.cairo:27-28`

Severity: **Low**

The recovery flow uses its own substorage (`recovery.pending`) and does not
go through `governance.propose / assert_ready / mark_executed`. The two
op-kind constants are never referenced anywhere in `src/`. Dead constants
attract future "let's wire these up" diffs that would conflict with the
existing recovery state machine. Either delete them or wire
`initiate_recovery` to also stamp a `PendingOp` for indexer parity (the
indexer rule says every state change must emit a reconstructible event;
recovery uses its own `RecoveryInitiated` event so this is fine — just
delete).

### Recommended fix

Remove the two constants and add a CI check that every defined `OP_*` is
referenced under `src/`.

---

## I-1: `__execute__` is unreachable in practice; intent should be commented inline

File: `src/account.cairo:264-266` and `:277-285`

Severity: **Informational**

`__validate__` always reverts → the AA execution path can never reach
`__execute__`. The `caller.is_zero() || caller == self` gate inside
`__execute__` therefore only ever sees `caller != 0 && caller != self`
callers and reverts. The function is effectively unreachable for state
changes — which is the design intent, but worth documenting inline. Add a
one-line comment at line 277:

```cairo
// Unreachable in practice — __validate__ unconditionally reverts.
// Kept for ABI conformance and future protocol-path enablement.
```

---

## I-2: `_total_calldata_felts` re-iterates `Span<Call>` independently of the multicall executor

File: `src/account.cairo:1123-1133`

Severity: **Informational**

Counts felts via a fresh `pop_front` loop in addition to the executor's
loop. Two passes over the same span. For `MAX_CALLS = 16` this is
negligible but worth folding the bound check into `_execute_calls_atomic_span`
to eliminate the duplicated traversal.

---

## I-3: BLS12-381 verifier — subgroup ordering, pubkey negation, lines_len gate, byte order, DST

File: `src/signer/bls12_381/verifier.cairo`

Reviewed — **no findings.**

- Both `assert_in_subgroup_excluding_infinity` calls (lines 183-184) fire
  **before** `multi_pairing_check_bls12_381_2P_2F` (line 194). ✓
- `pubkey_g2.negate(BLS_CURVE_INDEX)` (line 193) negates on chain, matching
  the docstring guarantee that off-chain signers register the natural form. ✓
- `lines_len != BLS_2P_2F_LINES_LEN (136)` short-circuits before allocating
  `lines_arr` (lines 158-160). ✓
- `felt252_to_u32x8_be` produces the BE `[u32; 8]` shape Garaga's
  `hash_to_curve_bls12_381` consumes (drand-quicknet ciphersuite uses a
  32-byte digest split into eight BE u32 words). ✓
- DST string (`BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_+`) is the
  drand-quicknet variant Garaga's `apps::drand::hash_to_curve_bls12_381`
  hardcodes. Consistent with the docstring claim. ✓

The single related weakness is **M-1 above** (no subgroup check at
registration) — that is in `add_owner`, not in this verifier.

---

## I-4: EIP-712 verifier — domain binding

File: `src/signer/eip712_secp256k1/verifier.cairo`

Reviewed — **no findings.**

- `chain_id` read from `get_tx_info().unbox().chain_id` at verify time, not
  from the envelope (line 162). ✓
- `account_addr` from `get_contract_address()` carried in the EIP-712
  `salt` field (lines 163-165). The choice of `salt` over
  `verifyingContract` is documented as a deliberate workaround for ethers
  v6 ENS-resolution; functionally equivalent for replay-protection (different
  account → different domain separator → different EIP-712 hash → recovery
  fails). ✓
- Cross-account replay is therefore not possible.

---

## I-5: OE replay protection (SNIP-12 hash + nonce map)

Files: `src/outside_execution.cairo`, `src/account.cairo:319-321`

Reviewed — **no findings.**

`compute_snip12_hash` includes `chain_id` (via
`STARKNET_DOMAIN_TYPE_HASH_REV1`) and `contract_address` directly.
`oe_nonces` map is keyed on the bare `nonce` felt, but cross-chain replay
requires a hash collision (impossible — different chain_id → different hash
→ different signature would be required). Fork replay has the same property.
Class-upgrade replay would preserve the nonce map (storage is per-address),
so consumed nonces remain consumed across class upgrades. ✓

---

## I-6: Recovery cancel-window arithmetic

Files: `src/recovery/component.cairo`, `tests/account_recovery.cairo`

Reviewed — **no arithmetic findings** (modulo C-1 above).

- `valid_after = now + timelock_seconds`; `finalize` requires
  `now >= valid_after`. No off-by-one.
- `cancel` has no timestamp check, so cancellation is always allowed before
  finalize — the right safety property.
- `cancel_recovery` in the account asserts `owner.role == ROLE_OWNER`
  (line 800) — guardians cannot cancel, confirmed by
  `test_guardian_cannot_cancel`. ✓
- `test_revoked_guardian_cannot_initiate_recovery` confirms revoked-guardian
  initiate is blocked. ✓
- The remaining `cancel_recovery` concern is rolled into **C-1** — guardians
  can't *invoke* `cancel_recovery` directly, but with the role bypass they
  can sign an OE that calls `cancel_recovery` passing an active owner's
  `owner_id`, since `_assert_self_call` only gates *who originated the call*
  (the account itself, after OE auth). Fix C-1 closes this.

---

## Coverage gaps in `tests/audit_v8.cairo` and the fixture suite

Beyond M-3 above, the following negative test classes are absent and would
have caught the new findings:

1. **No test that a `ROLE_GUARDIAN` signer can sign an arbitrary OE.** The
   single recovery test `test_guardian_cannot_cancel` only checks the
   cancel path. There is no test asserting that a guardian's signature is
   **rejected** for non-recovery actions — and that's because the contract
   currently *accepts* it (C-1).
2. **No test that `bootstrap_from_sessions` is unreachable from non-self
   callers.** All four migration tests in `tests/account_migration.cairo`
   either hit `'MIG: already initialized'` (no caller variation) or call
   `bootstrap_from_sessions` after `reset_for_migration_simulation` *without*
   simulating a hostile front-runner.
3. **No "anchor" test for the JWT sub-bound verifier** —
   `tests/signer_jwt_es256_sub.cairo` checks wrong-sub and wrong-stored-hash,
   but does not check that `sub_offset` pointing into another claim
   (`email`, `name`) is rejected.
4. **No verifier-reentrancy test** for the M-2 library-call concern.
5. **No spending-policy update test** verifying `spent_in_window` semantics.

---

## Methodology

- Manual code reading of every file under `src/` (not just the diff against
  V7), with focus on the 7 attack surfaces listed in the review brief:
  BLS12-381 verifier internals, library_call dispatcher trust model,
  threshold envelope aggregation, JWT sub binding, EIP-712 domain binding,
  recovery cancel-window arithmetic, OE replay protection, and subgroup
  validation at owner registration.
- Cross-reading of `tests/audit_2026_04_20.cairo` and
  `tests/audit_v8.cairo` against the contract code to confirm each existing
  guard has an active regression test.
- Cross-reading of `docs/audit-response-omar.md` and
  `docs/audit-response-henri.md` to avoid re-litigating closed findings.
- No automated fuzzing or property testing was run for this self-review;
  all findings are from static reading.

## Out of scope

- Garaga internals (Ed25519 / BLS12-381 / pairing primitives)
- WebAuthn `clientDataJSON` parser correctness beyond the type-prefix and
  challenge-binding checks already enforced
- Off-chain TypeScript SDK (`scripts/ts/*`)
- Mainnet bytecode verification beyond declared class hashes
- Phase 13 audit firm selection
