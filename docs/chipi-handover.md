# Chipi Pay handover — Shhh V8.3 integration

> **Audience**: Chipi Pay engineering. Everything the Chipi integration team needs to wire V8.3 ShhhAccount into the paymaster + the Chipi customer SDK.
>
> **Pin this commit**: `v8-robust @ af45e95` (or the squash-merge commit of [PR #6](https://github.com/haycarlitos/shhh-wallet-cairo/pull/6) once landed). Class hashes are deterministic functions of compiled Sierra at this commit; do not rebuild from a different toolchain.

---

## 1. What you're integrating with

V8.3 ShhhAccount is one Starknet account class that authenticates owners signing under any of ten cryptographic primitives via `library_call_syscall` dispatch to separately-declared verifier classes. The account exposes SNIP-9 V2 outside execution as the sole user-facing entry point (`__validate__` always reverts), which is what Chipi paymaster's `paymaster_executeSponsoredRaw` already routes to today.

What changed vs. V7 from a paymaster perspective:
- **Envelope format is no longer `[Ry_low, Ry_high, s_low, s_high, msg_len, msg_bytes…, hints…]`** (V7's Ed25519-only shape).
- **Envelope is now version-tagged**: `[V2_SNIP12, owner_id, kind_tag, …payload]` (single owner), `[V2_THRESHOLD, n, env_1_len, …, env_n_len, …]` (threshold), or the 4-felt session-key envelope from SNIP-163.
- **Verification cost is per-kind** (table in §4).
- **The dispatch path is the same**: `execute_from_outside_v2(oe, signature)` is still the only entry point.

## 2. Class hashes (mainnet, immutable)

Pin these in Chipi's V8 routing table. They are the deterministic outputs of `scarb build` at commit `af45e95` and have been verified byte-for-byte against the mainnet declares.

```
V8_SHHH_ACCOUNT_CLASS_HASH_V8_3 = 0x03bc539295abd3e59bd9ea799d12fe3331748d484bc77bff45b302b1636a87d9

V8_VERIFIER_CLASS_HASHES = {
  STARK:               0x00d09209b2da9d49fc805ba26380ba4ce25aa641116c10eb178e1051a71dbf68,
  ED25519:             0x030a7dfc03e59cef6e41699e734abd2df53ce393a052221c02c6e07665949f74,
  SECP256K1:           0x03e81667a46bd5287e09a9600fa98d28fdc477735f2689f5f4e8e95f37b67b74,
  EIP191_SECP256K1:    0x03a75997862059c36cb8e204fb3027eb6d1fdf933488d42c2db4528118d084e6,
  EIP712_SECP256K1:    0x072a3f77e8c28bfea2ade91ec3fb83b6290169d1ed8c1b2396704231841c6474,
  P256:                0x01b600709af54c8838e5f18ddad3a26feeb47cb124c239f55a0f1b7a780e2d8a,
  WEBAUTHN_P256:       0x074f6efd2af9025cd8cab41a4565bc73b6ef097214c31352838fcdbac0a44657,
  JWT_ES256:           0x002efce875fa3e73e04d825d8ebade53e188cc995dfe0c55a6a2f7fa6c59f497,
  JWT_ES256_APPLE_SUB: 0x06b67762218a25fdd28e25b063480893a5cef9cdeecbc663e32d444d5734c471,
  BLS12_381:           0x02623721e74a9ad3e0ba639065f5631a09bf900913de6ab21ea6984973cd2cd1,
}
```

Deprecated `ShhhAccount` classes (V8.0 / V8.1 / V8.2) remain declared but **must not** be routed by Chipi for new deploys. Existing instances at deprecated classes cannot self-upgrade (V8 ships without an `upgrade` selector) — they must redeploy at a fresh V8.3 address.

## 3. Required artifacts (the handover package)

Everything Chipi engineering needs lives in this repo at commit `af45e95`:

| Artifact | Path | Purpose |
|---|---|---|
| Full SDK spec | [`docs/v8-3-sdk-integration.md`](./v8-3-sdk-integration.md) | The canonical TypeScript integration spec — constants, envelope builders per kind, OE construction, paymaster routing, error mapping. **Start here.** |
| Class-hash table | [`docs/class-hashes.md`](./class-hashes.md) | Live mainnet class hashes + declare timeline + reproduction recipe. |
| SNIP draft | [`docs/snip-draft-pluggable-signer.md`](./snip-draft-pluggable-signer.md) | The standards-track spec under which Chipi can document "Chipi paymaster supports the Pluggable-Signer SNIP." |
| Audit responses | [`docs/audit-response-2026-05-10.md`](./audit-response-2026-05-10.md), [`audits/2026-05-10-claude-opus-v8-2-review.md`](../audits/2026-05-10-claude-opus-v8-2-review.md) | Latest audit cycle (V8.2 → V8.3 closeout). For partner due diligence. |
| Smoke-test status | [`docs/v8-3-smoke-tests.md`](./v8-3-smoke-tests.md) | What is and isn't proven on mainnet. |
| TS reference scripts | [`scripts/ts/*.mjs`](../scripts/ts/) | `snip12-hash.ts`, `compute-wallet-address.ts`, and per-kind fixture generators. Copy-paste-able into the Chipi SDK. |

Cairo source for spot-checks:
- Dispatch site: [`src/account.cairo` lines 463-473](../src/account.cairo) — the `library_call_syscall` to the registered verifier.
- ISigner trait: [`src/signer/interface.cairo`](../src/signer/interface.cairo) — three methods (`verify`, `kind`, `validate_pubkey`).
- Each verifier: [`src/signer/<kind>/verifier.cairo`](../src/signer/) — one file per kind.

## 4. Paymaster gas-overhead table

These are the upper-bound l2_gas amounts Chipi paymaster should reserve when sponsoring an OE per primary-owner kind. Numbers are from `snforge test` runs at commit `af45e95` (252-byte calls, single owner, no session key). Add ~5M l2_gas safety margin.

| Kind                  | Verifier l2_gas (upper bound) | Notes                                                   |
|-----------------------|-------------------------------|---------------------------------------------------------|
| `STARK`               |  ~2M                          | Native ECDSA syscall, cheapest                          |
| `SECP256K1`           |  ~5M                          | recover_public_key syscall                              |
| `EIP191_SECP256K1`    | ~10M                          | + keccak256 over `\x19Ethereum Signed Message:\n32` …   |
| `EIP712_SECP256K1`    | ~12M                          | + domain hash + struct hash                             |
| `P256`                | ~30M                          | secp256r1 syscall                                       |
| `ED25519`             | ~33M                          | Garaga v1.0.1 `is_valid_eddsa_signature`                |
| `WEBAUTHN_P256`       | ~35M                          | P-256 + sha256(authData ‖ sha256(clientData))           |
| `JWT_ES256`           | ~60M                          | P-256 + RFC 7515 header parsing + payload nonce scan    |
| `JWT_ES256_APPLE_SUB` | ~62M                          | Above + poseidon(sub_bytes) identity binding            |
| `BLS12_381`           | ~80M                          | Garaga pairing + on-chain G2 negation                   |

Threshold envelopes: sum the per-owner cost + ~3M aggregation overhead.

Session-key envelopes (SNIP-163 4-felt format): ~2M (STARK ECDSA over session pubkey) + the session-policy enforcement cost.

## 5. Envelope format (the part most likely to bite)

Inner-envelope routing per Part C of the SNIP draft:

```
[ signature[0] ]
  ├─ 'V2_SNIP12'    → [owner_id, kind_tag, ...payload]              (single-owner, most common)
  ├─ 'V2_THRESHOLD' → [n, env_1_len, ..., env_n_len, ...inner_n]    (multisig with mixed kinds)
  └─ (else, len==4) → SNIP-163 session-key envelope
```

Chipi paymaster does **not** need to parse the inner payload — the account class strips the version tag and library_calls the verifier. But Chipi DOES need to:

1. **Compute the SNIP-12 hash** correctly. The off-chain reference is `scripts/ts/snip12-hash.ts`. The domain separator binds `chainId` (mainnet `0x534e5f4d41494e`) and the account address — they MUST match.
2. **Pass the entire signature span verbatim** to `execute_from_outside_v2`. Do not unwrap the version tag.
3. **Reject signatures with `len == 0`** unless the caller is the account itself (self-call). Reject `caller == 0` per audit M-1 fix.

The OE call shape (`caller`, `nonce`, `execute_after`, `execute_before`, `calls`) is unchanged from SNIP-9 V2. Use `caller = 'ANY_CALLER' (0x414e595f43414c4c4552)` for paymaster-sponsored flows and a 2-hour validity window cap (audit M-2).

## 6. Recommended Chipi rollout sequence

Cycle 1 — restore parity with V7 + add the headline Ed25519 path:
- Wire `STARK` and `ED25519` envelope builders into the Chipi SDK
- Run mainnet smoke test for the `ED25519` deploy + OE end-to-end (the V7-equivalent path on V8.3)
- Update Chipi paymaster overhead table for `ED25519` to ~33M l2_gas

Cycle 2 — cross-ecosystem onboarding:
- Add `EIP191_SECP256K1` (MetaMask `personal_sign`) — biggest user base
- Add `JWT_ES256_APPLE_SUB` (Sign in with Apple, multi-tenant) — Chipi-default multi-user pattern
- Update paymaster routing to recognize the new kinds via SRC-5 probing on the registered verifier class hash

Cycle 3 — passkey + threshold:
- Add `WEBAUTHN_P256` (Face ID / Touch ID)
- Add threshold envelope handling for multi-device users
- Add the SNIP-163 session-key path coexistence test

Cycle 4 — recovery + governance:
- Wire the timelocked governance UI (`propose_op` + 48h wait + `execute_pending_op`)
- Wire the guardian recovery UI (initiate + 7-day window + finalize)

## 7. What Chipi doesn't need to do

Things the V8.3 account handles internally; Chipi paymaster should NOT replicate or work around:

- Signature verification (happens inside the account via library_call)
- Validate_pubkey at owner registration (happens inside the account, audit M-1)
- Reentrancy protection (`inside_verifier` flag, audit M-1 / M-2)
- Atomic multicall (audit H-1)
- Replay protection (`oe_nonces` map)
- Time-window bounds checks (audit M-2)
- Calls/calldata/signature bounds (audit M-3)

If a Chipi-side check exists for any of these, it's either redundant (and safe to remove) or contradicting the on-chain enforcement (and a bug).

## 8. Known gaps Chipi should track

- **`ShhhMigrationFromSessions` class is not declared.** Existing chipi-pay/sessions-smart-contract users cannot upgrade in place to V8.3 — they must deploy a fresh V8.3 account and transfer assets. If Chipi wants in-place migration, the migration class needs to be implemented and declared (~45 STRK).
- **Mainnet smoke tests beyond STARK are pending.** Until each kind is smoked end-to-end on production, treat them as "snforge-proven but not mainnet-proven."
- **External audit is pending.** V8.3 has internal self-reviews only. Chipi should communicate this honestly to downstream customers.
- **AVNU paymaster** also needs gas-overhead updates for the V8 kinds (PR previously opened by Chipi against AVNU `overhead.rs`).

## 9. Contact

For integration questions, file issues against `haycarlitos/shhh-wallet-cairo` with the `chipi-integration` label, or reach the maintainer (Carlos) directly. The audit response letter ([`docs/audit-response-2026-05-10.md`](./audit-response-2026-05-10.md)) is the canonical record of which audit findings are closed at which commit.
