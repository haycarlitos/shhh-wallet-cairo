# Shhh Wallet Cairo Security Audit

Date: 2026-04-20
Auditor: Codex / Cairo auditor workflow
Repository: https://github.com/haycarlitos/shhh-wallet-cairo
Commit: `70eeef3c9be06de9411f4e2906ecbba8f83ed1d4`

## Executive Summary

The wallet is **not safe to deploy or reuse as-is**.

The current implementation contains a confirmed **Critical** Starknet account vulnerability: public `__execute__` can be called directly and used to execute arbitrary calls from the wallet without Ed25519 authorization. This bypasses the wallet's core security model.

The audit also found a **High** atomicity issue in multicall execution and a **High** standards-compliance issue: the contract registers a SNIP-9 V2 SRC5 interface but does not implement SNIP-9 V2's required SNIP-12 typed-data signing semantics and uses the wrong published V2 interface ID.

The immediate release gate is:

- Fix `__execute__` caller/version validation.
- Make multicalls atomic.
- Decide whether this wallet is a custom Phantom outside-execution wallet or a real SNIP-9 V2 wallet. Do not advertise SNIP-9 V2 unless the SNIP-9 V2 semantics are implemented.
- Add regression tests proving the auth bypass and partial-execution bugs are fixed.

## Scope

In scope:

- `src/wallet.cairo`
- `src/outside_execution.cairo`
- `src/ed25519/component.cairo`
- `src/ed25519/interface.cairo`
- `src/lib.cairo`
- `tests/test_contract.cairo`
- `Scarb.toml`
- `Scarb.lock`

Out of scope:

- External audited guarantees of Garaga internals.
- Off-chain Phantom signing UI and relayer/paymaster backend.
- Deployed mainnet bytecode verification beyond this repository commit.
- Full formal verification of Ed25519 arithmetic.

## Commands Run

```bash
git clone https://github.com/haycarlitos/shhh-wallet-cairo /Users/espejelomar/StarkNet/security-audits/shhh-wallet-cairo-2026-04-20
git rev-parse HEAD
scarb build
scarb test
scarb fmt --check
python3.12 /Users/espejelomar/.codex/skills/cairo-auditor/scripts/quality/audit_local_repo.py \
  --repo-root /Users/espejelomar/StarkNet/security-audits/shhh-wallet-cairo-2026-04-20 \
  --scan-id shhh-preflight \
  --output-dir /tmp
```

Results:

- `scarb build`: passed.
- `scarb test`: passed, 9/9 existing tests.
- Audit-only PoC for the unsigned `__execute__` bypass: passed, proving exploitability.
- `scarb fmt --check`: failed due formatting drift under local Scarb 2.14.0 formatter.
- Cairo auditor deterministic preflight: 0 findings. The critical account issue required manual account-security reasoning.

Toolchain note:

- Local `snforge` was `0.56.0`.
- Project uses `snforge_std v0.54.1`.
- `snforge` warned that the package version does not meet recommended requirement `^0.56.0`.

## Findings Index

| ID | Severity | Title | Confidence |
| --- | --- | --- | --- |
| C-1 | Critical | Public `__execute__` allows unsigned arbitrary calls | 100 |
| H-1 | High | Subcall failures are silently swallowed, enabling partial execution | 95 |
| H-2 | High | Contract advertises SNIP-9 V2 but implements incompatible custom signing | 95 |
| M-1 | Medium | `caller == 0` is accepted as unrestricted despite SNIP-9 requiring `'ANY_CALLER'` | 90 |
| M-2 | Medium | No maximum validity window for bearer outside-execution signatures | 85 |
| M-3 | Medium | No bounds on call count, calldata length, or signature length | 85 |
| M-4 | Medium | Signature span bounds and trailing bytes are not fully validated | 85 |
| L-1 | Low | Constructor accepts pubkey halves that later panic on `u128` conversion | 75 |
| I-1 | Informational | Custom calls hash should be replaced by SNIP-12 or explicitly tagged | 70 |
| I-2 | Informational | Ed25519 negative test vectors are missing | 70 |
| I-3 | Informational | Upgradeable component is wired but no upgrade entrypoint exists | 80 |

## C-1: Public `__execute__` Allows Unsigned Arbitrary Calls

File: `src/wallet.cairo`
Lines: 73-92
Severity: Critical
Confidence: 100

### Impact

Anyone can call `__execute__` directly and make the wallet call arbitrary contracts without an Ed25519 signature.

This breaks the README security claim that Ed25519 signature verification is the sole authorization mechanism. In practice, a malicious caller can route the wallet into arbitrary token/NFT/protocol calls as the wallet contract address.

### Evidence

`__execute__` is public and has no caller or transaction-version guard:

```cairo
#[external(v0)]
fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
    let mut results: Array<Span<felt252>> = array![];
    for call in calls {
        match syscalls::call_contract_syscall(call.to, call.selector, call.calldata) {
            Result::Ok(ret) => results.append(ret),
            Result::Err(_) => results.append(array![].span()),
        }
    };
    results
}
```

Starknet's account documentation says two critical validations must happen in `__execute__` and that their absence can lead to draining the account's funds:

- `get_caller_address().is_zero()`
- valid transaction version, preventing deprecated invoke v0 validation bypass

This is also consistent with public Starknet security guidance:

- FuzzingLabs' Cairo/Starknet vulnerability writeup shows an Argent-style `__execute__` skeleton that starts the reentrancy guard, reads execution info, checks `assert_only_protocol(exec_info.caller_address)`, checks `assert_correct_invoke_version(tx_info.version)`, and then executes the multicall.
- Cairopractice's `get_caller_address` note explains the protocol rationale: for state-changing account execution, a zero caller indicates StarknetOS is invoking `__validate__` / `__execute__`; because these functions are public, a non-zero caller must not be treated as protocol execution.

### PoC

An audit-only test was run locally proving an arbitrary caller can make the wallet call a target contract:

```cairo
#[test]
fn audit_poc_external_execute_allows_unsigned_calls() {
    let wallet_class = declare("ShhhWallet").unwrap().contract_class();
    let wallet_calldata: Array<felt252> = array![AUDIT_PUBKEY_LOW, AUDIT_PUBKEY_HIGH];
    let (wallet_addr, _) = wallet_class.deploy(@wallet_calldata).unwrap();

    let target_class = declare("AuditTarget").unwrap().contract_class();
    let target_calldata: Array<felt252> = array![];
    let (target_addr, _) = target_class.deploy(@target_calldata).unwrap();

    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(wallet_addr, attacker);

    let account = IAccountExecuteDispatcher { contract_address: wallet_addr };
    let target = IAuditTargetDispatcher { contract_address: target_addr };

    assert(target.get_value() == 0, 'initial nonzero');
    account.__execute__(array![Call {
        to: target_addr,
        selector: selector!("set_value"),
        calldata: array![0xCAFE].span(),
    }]);
    assert(target.get_value() == 0xCAFE, 'execute not public');
}
```

Result:

```text
[PASS] shhh_wallet_integrationtest::audit_execute_poc::audit_poc_external_execute_allows_unsigned_calls
```

### Recommended Fix

If `__execute__` exists for standard account compatibility, harden it as a protocol-only path:

```diff
 #[external(v0)]
 fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
+    assert(get_caller_address().is_zero(), 'ACCOUNT: invalid caller');
+    let tx_info = get_tx_info().unbox();
+    assert(tx_info.version.into() >= 1_u32, 'ACCOUNT: invalid tx version');
     let mut results: Array<Span<felt252>> = array![];
     for call in calls {
         match syscalls::call_contract_syscall(call.to, call.selector, call.calldata) {
             Result::Ok(ret) => results.append(ret),
-            Result::Err(_) => results.append(array![].span()),
+            Result::Err(_) => core::panic_with_felt252('ACCOUNT: subcall failed'),
         }
     };
     results
 }
```

Prefer using the same explicit valid-version policy as OpenZeppelin/Argent-style account implementations, including supported estimate versions if relevant.

If the wallet is not intended to support normal account invokes, make `__execute__` revert after mandatory caller/version checks and route real execution exclusively through `execute_from_outside_v2`.

### Required Tests

- Direct external call to `__execute__` from non-zero caller must revert.
- Invoke-v0-style execution path must revert if the test framework can simulate it.
- Protocol/estimation path must still behave as intended if required.
- Attempted token transfer or arbitrary state write through unsigned `__execute__` must fail.

## H-1: Subcall Failures Are Silently Swallowed, Enabling Partial Execution

File: `src/wallet.cairo`
Lines: 82-92 and 305-321
Severity: High
Confidence: 95

### Impact

Both `__execute__` and `execute_from_outside_v2` convert failed subcalls into empty return spans instead of reverting. This creates non-atomic multicalls.

For a signed outside execution, the user may authorize a sequence such as approve -> deposit -> repay, expecting the sequence to be atomic. If a later subcall fails, earlier state changes remain committed and the nonce is consumed.

This can create fund loss, stuck approvals, failed-but-consumed orders, and inconsistent protocol state.

### Evidence

```cairo
match syscalls::call_contract_syscall(
    *call.to, *call.selector, *call.calldata,
) {
    Result::Ok(ret) => results.append(ret),
    Result::Err(_) => results.append(array![].span()),
}
```

The SNIP-9 reference outline calls `execute_multicall(calls)`, which propagates failures rather than treating them as successful empty responses.

### Recommended Fix

Revert the entire operation on any failed subcall:

```diff
 match syscalls::call_contract_syscall(
     *call.to, *call.selector, *call.calldata,
 ) {
     Result::Ok(ret) => results.append(ret),
-    Result::Err(_) => results.append(array![].span()),
+    Result::Err(_) => core::panic_with_felt252('SRC9: subcall failed'),
 }
```

Optional-call behavior should be a separate, explicit signed payload type. It should not be the default behavior of a wallet multicall.

### Required Tests

- Signed outside execution with two calls where call 1 succeeds and call 2 fails must revert all state.
- Nonce must remain reusable after reverted execution.
- Failed DeFi call must not leave token allowance or intermediate state behind.
- The same atomic behavior must apply to `__execute__`, if `__execute__` remains supported.

## H-2: Contract Advertises SNIP-9 V2 but Implements Incompatible Custom Signing

Files:

- `src/wallet.cairo`
- `src/outside_execution.cairo`

Severity: High
Confidence: 95

### Impact

The contract registers an SRC5 interface as if it implements SNIP-9 V2, but the signed payload and interface ID do not match SNIP-9 V2. Dapps and SDKs probing for SNIP-9 V2 support can get incorrect results or build signatures this contract will reject.

This is not merely cosmetic. Standards discovery is how wallets, relayers, SDKs, paymasters, and dapps decide what signing flow to use. Advertising a standard but accepting a different payload creates integration failures and dangerous false assumptions about the security model.

### Evidence

The constructor registers:

```cairo
self.src5.register_interface(ISRC9_V2_ID);
```

The contract's constant is:

```cairo
pub const ISRC9_V2_ID: felt252 =
    0x1d1144bb2138571a605b8b8eed8e4e9e04dc40fce40190a11af584935e0a04c;
```

The published SNIP-9 V2 / OpenZeppelin SRC9 V2 interface ID is:

```text
0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872
```

The contract signs/verifies custom bytes:

```text
SHHH_OE_V1 || chain_id || contract_address || caller || nonce || execute_after || execute_before || calls_hash
```

then hex-encodes those bytes for Phantom.

SNIP-9 V2 requires SNIP-12 typed-data signing of `OutsideExecution` with version `2` in the domain separator.

### Recommended Fix

Choose one of two designs.

Design A: custom Phantom-only outside execution.

- Rename the interface to project-specific semantics.
- Register a project-specific SRC5 interface ID, e.g. `ISHHH_OUTSIDE_EXECUTION_V1_ID`.
- Do not advertise SNIP-9 V2.
- Document that this is not general SNIP-9 V2 support.

Design B: real SNIP-9 V2 plus Phantom extension.

- Implement SNIP-12 typed-data hashing for true SNIP-9 V2.
- Use the published SNIP-9 V2 interface ID.
- Keep the Phantom hex-ASCII path as a separate function or versioned extension.
- Ensure SDKs can distinguish the two signing modes.

### Required Tests

- `supports_interface(0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872)` returns true only if true SNIP-9 V2 semantics are implemented.
- Standard SNIP-9 V2 typed-data signature succeeds if SNIP-9 V2 is advertised.
- Custom Phantom signature succeeds only on the custom interface/path.
- Standard SNIP-9 V2 dapp-generated signature does not accidentally route into the custom path.

## M-1: `caller == 0` Is Accepted as Unrestricted Despite SNIP-9 Requiring `'ANY_CALLER'`

File: `src/wallet.cairo`
Lines: 248-254
Severity: Medium
Confidence: 90

### Impact

The code treats both address zero and the felt value of shortstring `'ANY_CALLER'` as unrestricted caller sentinels:

```cairo
let caller_felt: felt252 = outside_execution.caller.into();
if caller_felt != 0 && caller_felt != 'ANY_CALLER' {
    assert(get_caller_address() == outside_execution.caller, 'SRC9: invalid caller');
}
```

If this contract claims SNIP-9 V2 support, this is a standards deviation. SNIP-9 defines the special unrestricted caller as `'ANY_CALLER'`.

Accepting zero as unrestricted can cause signatures intended for a zero-address sentinel to become universally executable.

### Recommended Fix

If the contract advertises SNIP-9 V2, use only the SNIP-9 sentinel:

```diff
 let caller_felt: felt252 = outside_execution.caller.into();
-if caller_felt != 0 && caller_felt != 'ANY_CALLER' {
+if caller_felt != 'ANY_CALLER' {
     assert(get_caller_address() == outside_execution.caller, 'SRC9: invalid caller');
 }
```

If the product wants `0` as a custom unrestricted sentinel for Phantom UX, do not advertise SNIP-9 V2 and document the custom convention.

### Required Tests

- `caller = 'ANY_CALLER'` permits any caller.
- `caller = expected_executor` permits only that executor.
- `caller = 0` behavior matches the selected standard/custom policy.
- If SNIP-9 V2 is advertised, `caller = 0` must not be treated as unrestricted unless the spec changes.

## M-2: No Maximum Validity Window for Bearer Outside-Execution Signatures

File: `src/wallet.cairo`
Lines: 256-259
Severity: Medium
Confidence: 85

### Impact

The contract validates lower and upper timestamp bounds but does not cap the length of the validity window:

```cairo
let now = get_block_timestamp();
assert(outside_execution.execute_after < now, 'SRC9: too early');
assert(now < outside_execution.execute_before, 'SRC9: too late');
```

A signature with `execute_after = 0` and `execute_before = u64::MAX` is valid indefinitely until its nonce is used. Combined with `ANY_CALLER`, this is a long-lived bearer instrument. If a relayer, paymaster, backend, browser extension, or log sink leaks the object, anyone can execute it.

### Recommended Fix

Add a maximum validity window, especially for unrestricted caller payloads:

```cairo
const MAX_ANY_CALLER_VALIDITY_SECONDS: u64 = 3600;

assert(outside_execution.execute_before > outside_execution.execute_after, 'SRC9: invalid window');
if outside_execution.caller.into() == 'ANY_CALLER' {
    assert(
        outside_execution.execute_before - outside_execution.execute_after <= MAX_ANY_CALLER_VALIDITY_SECONDS,
        'SRC9: validity too long',
    );
}
```

For restricted caller payloads, choose a documented policy. Longer windows may be acceptable when the caller is a trusted executor contract, but they should still have an explicit cap.

### Required Tests

- `ANY_CALLER` payload with validity window above the cap reverts.
- Restricted-caller payload follows the selected cap policy.
- Boundary tests cover `execute_after == now`, `execute_before == now`, and `execute_before <= execute_after`.

## M-3: No Bounds on Call Count, Calldata Length, or Signature Length

File: `src/wallet.cairo`
Lines: 94-120, 281-303, 305-321
Severity: Medium
Confidence: 85

### Impact

The wallet loops over:

- all calls;
- all calldata felts in `hash_calls_for_oe`;
- all message bytes in signature validation;
- the full Garaga signature/hint span during deserialization.

There are no explicit application-level limits.

For a paymaster-funded product, this is griefable. An attacker can submit oversized payloads that are expected to fail but still consume verification, hashing, memory, or relayer/paymaster resources.

### Recommended Fix

Add explicit bounds before expensive work:

```cairo
const MAX_CALLS: u32 = 16;
const MAX_TOTAL_CALLDATA_FELTS: u32 = 1024;
const MAX_SIGNATURE_FELTS: u32 = 512;

assert(outside_execution.calls.len() <= MAX_CALLS, 'SRC9: too many calls');
assert(signature.len() <= MAX_SIGNATURE_FELTS, 'SRC9: signature too long');
```

Compute and bound total calldata length once before hashing/execution.

Tune these values to product needs, but do not leave them unbounded.

### Required Tests

- `MAX_CALLS + 1` calls revert before signature verification.
- Total calldata above the cap reverts before signature verification.
- Signature length above cap reverts before deserialization.
- Valid expected flows remain below limits.

## M-4: Signature Span Bounds and Trailing Bytes Are Not Fully Validated

File: `src/wallet.cairo`
Lines: 281-303
Severity: Medium
Confidence: 85

### Impact

The contract reads `msg_len` from the signature and checks it equals the expected message length, but it does not check that the signature span actually contains `5 + msg_len` elements before indexing:

```cairo
assert(signature.len() >= 5, 'SRC9: sig too short');
let msg_len: u32 = (*signature.at(4)).try_into().expect('SRC9: bad msg len');
...
while i < msg_len {
    let msg_byte: u8 = (*signature.at(5 + i)).try_into().expect('SRC9: bad msg byte');
    ...
}
```

After deserializing `EdDSASignatureWithHint`, the code also does not verify that the deserializer consumed the entire signature span:

```cairo
let mut sig_span = signature;
let sig_with_hints = Serde::<EdDSASignatureWithHint>::deserialize(ref sig_span)
    .expect('SRC9: bad sig format');
```

Malformed signatures should fail with controlled errors, not generic bounds panics or trailing-data ambiguity.

### Recommended Fix

Add a length lower bound before byte indexing and reject trailing data after deserialization:

```diff
 assert(msg_len == expected_bytes.len(), 'SRC9: msg length mismatch');
+assert(signature.len() >= 5 + msg_len, 'SRC9: sig message truncated');
 let mut i: u32 = 0;
 while i < msg_len {
     let msg_byte: u8 = (*signature.at(5 + i)).try_into().expect('SRC9: bad msg byte');
     assert(msg_byte == *expected_bytes.at(i), 'SRC9: msg mismatch');
     i += 1;
 };

 let mut sig_span = signature;
 let sig_with_hints = Serde::<EdDSASignatureWithHint>::deserialize(ref sig_span)
     .expect('SRC9: bad sig format');
+assert(sig_span.is_empty(), 'SRC9: trailing sig bytes');
```

### Required Tests

- Signature with correct `msg_len` but truncated message bytes reverts with `SRC9: sig message truncated`.
- Signature with a non-byte message felt reverts with `SRC9: bad msg byte`.
- Signature with trailing felts after a valid serialized structure reverts.
- Oversized signature/hints are rejected or explicitly accepted under a documented maximum.

## L-1: Constructor Accepts Invalid Ed25519 Public-Key Halves and Can Deploy a Bricked Wallet

File: `src/ed25519/component.cairo`
Lines: 29-36
File: `src/wallet.cairo`
Lines: 267-272
Severity: Low
Confidence: 75

### Impact

The constructor accepts `felt252` values for `owner_pubkey_low` and `owner_pubkey_high`, stores them, and later converts them into `u128` halves:

```cairo
let owner_u256 = u256 {
    low: owner_low.try_into().unwrap(),
    high: owner_high.try_into().unwrap(),
};
```

If either value is greater than `u128::MAX`, future executions panic. This is mostly a deploy-time safety issue, but a wallet factory or deterministic deployment flow can accidentally deploy unusable accounts.

### Recommended Fix

Validate constructor inputs:

```diff
 fn constructor(ref self: ContractState, owner_pubkey_low: felt252, owner_pubkey_high: felt252) {
+    let _: u128 = owner_pubkey_low.try_into().expect('OWNER_LOW_OUT_OF_RANGE');
+    let _: u128 = owner_pubkey_high.try_into().expect('OWNER_HIGH_OUT_OF_RANGE');
     self.ed25519.initializer(owner_pubkey_low, owner_pubkey_high);
     self.src5.register_interface(ISRC9_V2_ID);
 }
```

Add non-zero / curve-validity checks if Garaga exposes a cheap validation helper for the expected Ed25519 point representation.

### Required Tests

- Constructor rejects `owner_pubkey_low > u128::MAX`.
- Constructor rejects `owner_pubkey_high > u128::MAX`.
- Valid fixture still deploys and verifies signatures.

## I-1: Custom Calls Hash Should Be Replaced by SNIP-12 or Explicitly Tagged

File: `src/wallet.cairo`
Lines: 94-120
Severity: Informational
Confidence: 70

### Assessment

The reviewed external audit suggested this encoding is ambiguous and rated it High. I do not consider that proven.

The construction:

```text
[to, selector, cd_len, calldata..., ...per call..., num_calls]
```

is custom and non-standard, but the provided ambiguity example does not produce the same felt sequence. Because each calldata segment is length-prefixed and the number of calls is appended, a concrete equal-encoding collision was not demonstrated.

The real issue is standards/design risk:

- If the contract claims SNIP-9 V2, this should use SNIP-12 typed data, not custom Poseidon packing.
- If the contract remains custom, the encoding should include explicit domain and field tags to reduce future parser/encoding mistakes.

### Recommended Fix

If SNIP-9 V2 is intended, replace the custom calls hash with SNIP-12-compliant hashing.

If custom signing remains, use explicit tags:

```text
[TAG_SHHH_OE_V1, TAG_NUM_CALLS, num_calls, TAG_CALL, to, selector, cd_len, calldata..., ...]
```

Add differential tests against the off-chain encoder.

## I-2: Ed25519 Negative Test Vectors Are Missing

File: `tests/test_contract.cairo`
Severity: Informational
Confidence: 70

### Assessment

The test suite checks:

- valid Ed25519 fixture;
- wrong owner;
- replay;
- time bounds;
- caller restriction.

It does not test Ed25519 edge cases such as:

- `s >= L`;
- small-subgroup / torsion `R`;
- non-canonical public key / encoded point;
- non-canonical `R`;
- zero scalar;
- malformed Garaga hints.

The wallet's security model depends almost entirely on Garaga Ed25519 verification, so upstream cryptographic assumptions should be pinned with negative fixtures.

### Recommended Fix

Add curated RFC 8032 / Ed25519 negative vectors and Garaga-specific malformed hint vectors to CI.

If any invalid vector verifies, treat it as a release-blocking upstream dependency issue.

## I-3: Upgradeable Component Is Wired But No Upgrade Entrypoint Exists

File: `src/wallet.cairo`
Lines: 10-45
Severity: Informational
Confidence: 80

### Assessment

The contract imports and wires OpenZeppelin's `UpgradeableComponent`:

```cairo
use openzeppelin::upgrades::UpgradeableComponent;

component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;
```

It also allocates upgradeable storage and emits upgradeable events. However, the contract does not expose an external `upgrade` function or any other authorized wrapper around the component's internal upgrade path.

This means the upgradeability feature is currently dead code. Maintainers or integrators may assume the wallet can be upgraded after deployment, but no callable upgrade path exists in the public ABI.

This is not a direct vulnerability by itself. In an account contract, an upgrade function is also dangerous if it is not authorization-hardened. The risk here is inaccurate operational assumptions and unnecessary attack surface from unused component wiring.

### Recommended Fix

If immutability is intended:

- remove `UpgradeableComponent`;
- remove its storage and event wiring;
- remove `UpgradeableInternalImpl`;
- document that deployed wallet classes are immutable.

If upgradeability is intended:

- add an explicit external upgrade entrypoint only after fixing `C-1`;
- require the same authorization model as critical wallet execution, either protocol account authorization or a signed outside-execution payload;
- add tests proving arbitrary callers cannot upgrade the account class;
- add tests proving valid owner-authorized upgrade payloads work.

## Tooling and Test Hardening Recommendations

### Immediate

- Pin a mutually compatible Starknet Foundry stack. Local `snforge 0.56.0` warns that `snforge_std v0.54.1` is below the recommended `^0.56.0`.
- Add CI for `scarb build`, `scarb test`, and formatter checks using pinned Scarb/Starknet Foundry versions.
- Add audit PoC regression tests for all confirmed vulnerabilities.
- Add negative tests for malformed signatures, long validity windows, oversize payloads, and all sentinel cases.

### Property/Fuzz Testing

Use Starknet Foundry fuzz tests first. They are maintained and support `#[fuzzer]`, fixed seeds, and configurable run counts.

Recommended invariants:

- Unauthorized callers can never cause a wallet subcall without a valid Ed25519 signature.
- Any invalid signature/caller/time window must leave `outside_nonces[nonce] == false`.
- A failed subcall must revert the entire outside execution and preserve nonce availability.
- For all fuzzed `execute_after` / `execute_before` windows, acceptance matches the intended boundary policy.
- For fuzzed signature spans, the function either succeeds with the exact valid fixture or reverts with controlled errors.
- SNIP-9/SRC5 support must match actual supported signing semantics.

Example fuzz targets:

- time window boundaries;
- random malformed signature spans;
- random caller values, including zero and `'ANY_CALLER'`;
- random call counts and calldata lengths around configured limits;
- replay attempts across random nonce values.

### Mutation Testing

There is no mature, maintained Cairo 2 mutation testing stack comparable to Solidity's mature ecosystems. Cairo-Fuzzer exists but is marked unmaintained and states it does not support Cairo 2.0 / pure Cairo contracts.

Recommended practical mutation approach:

- Build a small repo-local mutation script for critical guards.
- Mutate one guard at a time and require the suite to fail.
- Start with these mutants:
  - remove `get_caller_address().is_zero()` guard in `__execute__`;
  - remove tx-version guard in `__execute__`;
  - replace subcall revert with swallowed error;
  - remove nonce write;
  - remove nonce duplicate check;
  - flip time-bound inequalities;
  - treat zero as unrestricted if final policy says only `'ANY_CALLER'` is allowed;
  - remove signature message-byte comparison;
  - remove `signature.len() >= 5 + msg_len`;
  - remove trailing-byte rejection;
  - remove call/calldata/signature length bounds;
  - remove constructor u128 bounds.

This is high-value for this wallet because the core security properties are guard-heavy and cheap to mutate.

## Final Release Gate

Do not deploy or reuse the current mainnet class hash until:

- C-1 is fixed and regression-tested.
- H-1 is fixed and regression-tested.
- H-2 is resolved by either real SNIP-9 V2 implementation or a custom interface.
- M-1 is resolved consistently with the selected standard/custom path.
- M-2 and M-3 are bounded for paymaster safety.
- M-4 has controlled malformed-signature behavior.
- CI pins compatible Scarb/Starknet Foundry versions.

## References

- Starknet account docs: https://docs.starknet.io/learn/protocol/accounts
- FuzzingLabs Top 4 Cairo/Starknet vulnerabilities: https://fuzzinglabs.com/top-4-vulnerability-cairo-starknet-smart-contract/
- Cairopractice, "When is get_caller_address zero?": https://cairopractice.com/posts/get_caller_address_zero/
- SNIP-9 raw specification: https://raw.githubusercontent.com/starknet-io/SNIPs/main/SNIPS/snip-9.md
- OpenZeppelin Cairo account/SRC9 docs: https://docs.openzeppelin.com/contracts-cairo/0.19.0/api/account
- Starknet.js outside execution docs: https://starknetjs.com/docs/7.6.4/guides/outsideExecution/
- Starknet Foundry fuzzing docs: https://foundry-rs.github.io/starknet-foundry/snforge-advanced-features/fuzz-testing.html
- Cairo property-based testing guidance: https://www.starknet.io/cairo-book/zh-cn/ch104-02-03-fuzz-testing.html
- Cairo-Fuzzer repository and limitations: https://github.com/FuzzingLabs/cairo-fuzzer
- Consensys Diligence Argent Starknet audit: https://diligence.consensys.io/audits/2024/01/argent-account-argent-multisig-starknet-transaction-v3-updates/argent-audit-2024-01.pdf
