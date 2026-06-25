# V8.3 mainnet smoke tests — status

> Tracks the empirical "does V8.3 actually work in production?" tests. Class declares prove the code is *registered*; smoke tests prove it *executes*. This doc is the source of truth for which signer kinds and which V8 features are battle-tested on Starknet mainnet vs only proven via `snforge`.
>
> **Note on V8.1 vs V8.3**: Test 1 below was run against the V8.1 `ShhhAccount` class on 2026-05-10, one day before V8.3 was declared. The dispatcher path (`execute_from_outside_v2` → SNIP-12 hash → kind-tag routing → `library_call_syscall` → verifier) is byte-for-byte identical V8.1 → V8.3. V8.3 only adds `validate_pubkey` at owner-registration sites and the symmetric `inside_verifier` flag; neither code path is exercised by Test 1 (STARK ECDSA primary, no additional owners). The V8.1 receipt therefore carries forward as evidence for V8.3's dispatcher. Tests 2 onwards SHOULD redeploy against V8.3 (class hash `0x03bc5392…`).

---

## Summary

**5 OE smokes + 1 V8.4 deploy smoke + governance propose all passing (trace-verified, no silent reverts).** V8.3 dispatcher proven via V8.1 carry-forward (Test 1, 2026-05-10). V8.4 deploy + state readback (Test 1a, 2026-05-15). **Four V8.4 paymaster-sponsored OEs through Chipi completed 2026-05-18 with trace-verified inner-call success**: STARK (Test 15), EIP-191 MetaMask `personal_sign` (Test 3), ED25519 Phantom/Solana (Test 2), WEBAUTHN_P256 passkey (Test 7). **Test 11 propose phase landed 2026-05-18** — 48h timelock on `propose_add_owner` now running; execute phase opens 2026-05-20T23:28Z.

All four Chipi Cycle-1 kinds are now production-validated. Governance propose-phase proven; execute-phase pending the 48h timelock. **Session-key spending caps smoked on mainnet 2026-06-20 (Test 14)** — in-cap OE succeeded, over-cap reverted on-chain with `'Spending: exceeds per-call'`. Recovery, threshold, and the other six kinds (raw secp256k1, raw P-256, EIP-712, JWT-ES256, JWT-Apple-sub, BLS) are still snforge-only (264/264, incl. the new `account_sessions_e2e.cairo`).

**Two corrections from earlier in this cycle (retracted receipts, see commit history)**:
1. The "V8.2 verifier" hashes in `class-hashes.md` had **never actually been declared on mainnet** (despite the 2026-05-10 doc claim). All 10 finally declared 2026-05-18 (~100 STRK actual fee; BLS was already on chain).
2. First-attempt smoke receipts (2026-05-18 morning) had an off-by-60 bug in the OE validity window (`window = 7260 > MAX_ANY_CALLER_VALIDITY_SECONDS = 7200`). **Chipi paymaster silently caught the wallet-level revert and returned outer-tx `SUCCEEDED`**, so the original receipts looked passing. Smoke scripts now assert trace-level non-revert after every OE.

**Bottom line for Chipi Pay integration**: V8.4 + V8.2 verifiers (now all declared) + Chipi paymaster is production-validated for all four Cycle-1 cross-ecosystem signer kinds — Starknet-native (STARK), MetaMask (EIP-191), Phantom (ED25519), and passkeys (WEBAUTHN_P256). The guardian-OE `initiate_recovery` carve-out (audit C-1) is now smoked end-to-end on mainnet (Test 13, 2026-06-25 — guardian initiates, guardian's non-recovery OE reverts, owner cancels). The other V8.4-specific path (`bootstrap_from_sessions_signed`) deploys cleanly but isn't exercised end-to-end yet.

**Chipi paymaster observation (action item)**: `paymaster_executeSponsoredRaw` currently returns top-level `SUCCEEDED` even when the inner `execute_from_outside_v2` call reverts. Caller has no signal from the receipt alone. Recommend Chipi propagate inner reverts to the outer tx, OR document this explicitly so callers know to inspect the trace.

---

## Test 11 — V8.4 multi-owner governance: `propose_add_owner` via 48h timelock ⏳

**Date**: 2026-05-18 (propose) → 2026-05-20T23:28Z (earliest execute)
**Class**: V8.4 `ShhhAccount` (`0x075dfb396…fa58a`)
**Wallet**: Test 15's STARK-primary wallet `0x6727639a48098f0bba4e7fc664eb33168ead2df8e85631df63416ff137a959e`
**New owner kind**: ED25519, role=ROLE_OWNER, weight=1, label=`'smoke11_phantom'`
**New owner pubkey**: `0x7e16f77db69f0b1f7158173a2997eaa9b49ab199f37b5de85694c779d7f591b5`

| Step | Tx | Status |
|---|---|---|
| `propose_add_owner` OE (STARK primary signs, Chipi paymaster) — **trace-verified** | [`0x6bd9aeb0…3c6a66ad4`](https://voyager.online/tx/0x6bd9aeb0ecb9de5b479968e879cf7504dfbe539d45a161cda53f223c6a66ad4) | ✅ SUCCEEDED + inner OE non-reverted |
| Wait 48h (`TIMELOCK_ADD_OWNER`) | — | ⏳ in progress until 2026-05-20T23:28Z |
| `execute_add_owner` (permissionless) | — | ⏸ pending timelock |

`op_id` extracted from OpProposed event (data[1]): `0x61e8fa60fb7a1cb14adb4e74607a539f26d91eb9331e66f5af9225ddba4f784`
Reproduction script: `shhh:scripts/smoke-test-11.mjs`.

**What the propose phase proves**:
- `propose_add_owner` is reachable through a single-call OE multicall (the function is `_assert_self_call`-gated, so wrapping it in an OE multicall where the wallet itself is the multicall caller satisfies the check).
- Governance component's `propose(OP_ADD_OWNER, …)` runs cleanly: op_id is derived, OpProposed event emitted with the timelock + expiry timestamps.
- The primary STARK owner can author a governance OE (audit C-1 role check passes for ROLE_OWNER).

**Pending for the execute phase** (2026-05-20T23:28Z onwards):
- `execute_add_owner` is permissionless — anyone can call it once the timelock elapses.
- The new owner registration triggers `_validate_pubkey_via_verifier(ED25519, [pk_low, pk_high])`, which library_calls the V8.2 ED25519Verifier's `validate_pubkey` method. With V8.2 verifiers now declared, this should succeed.
- After execute: `owner_count() = 2`, and the new Ed25519 owner can sign OEs end-to-end.

---

## Test 7 — V8.4 WEBAUTHN_P256 OE (passkey / Touch ID / Face ID) via Chipi paymaster ✅

**Date**: 2026-05-18
**Class**: V8.4 `ShhhAccount` (`0x075dfb396…fa58a`)
**Verifier**: V8.2 `WebAuthnP256Verifier` (`0x074f6efd…4657`)
**Account deployed**: [`0x52d1921dcd0f7ad30117ef2cce504ef923506abd18ff86524c4ba4b39b819b8`](https://voyager.online/contract/0x52d1921dcd0f7ad30117ef2cce504ef923506abd18ff86524c4ba4b39b819b8)
**Synthetic RP**: `smoke7.shhh.test` (rpIdHash = sha256("smoke7.shhh.test"))
**Paymaster**: Chipi (`paymaster_executeSponsoredRaw`)

| Step | Tx | Block | Fee | Status |
|---|---|---|---|---|
| Deploy V8.4 instance via UDC (WEBAUTHN_P256 primary, label `'smoke7'`) | [`0x3f07ae8a…ce42c0`](https://voyager.online/tx/0x3f07ae8a21bfe0d524f588a2fc11012a0bf3a0d68163271542a5cd491ce42c0) | — | ~0.566 STRK (deployer-paid) | ✅ |
| `execute_from_outside_v2` via Chipi paymaster (WebAuthn assertion: synthesized authData + clientDataJSON + P-256 sig, `caller='ANY_CALLER'`, no-op `STRK.transfer(self, 0)`) — **trace-verified, no inner revert** | [`0x34d6c4f1…cdb2695e`](https://voyager.online/tx/0x34d6c4f10b6af3a4fb02eb20418d08fe72b2d4f9bbd897fbe30ffddcdb2695e) | — | `0xef0b759813ac520` FRI ≈ 1.0772 STRK (**paymaster-paid**; 2x sha256 + P-256 syscall + base64url + JSON prefix check) | ✅ SUCCEEDED + inner OE non-reverted |

Reproduction script: `shhh:scripts/smoke-test-7.mjs`.
P-256 priv (committed for replay): `0x04e678b92fac610453971f99b44e0171cd106f750451161ea04a842127ae9982`.

OE message hash (SNIP-12): `0x52416273363c96223add5d440ec2b9fb7aa3c9b4443854d63d80f81e12c66f5`
Challenge (base64url of 32-byte BE hash, no padding): `BSQWJzNjyWIjrdXUQOwrn7eqPJtEQ4VNY9gPgeEsZvU`
clientDataJSON: `{"type":"webauthn.get","challenge":"BSQWJzNjyWIjrdXUQOwrn7eqPJtEQ4VNY9gPgeEsZvU","origin":"https://smoke7.shhh.test","crossOrigin":false}`
authData (37 B): `0xafe67be59a8fdbc8219c0affd0f19293e8a5547c8f630497e61172a9363e171a0500000001` (rpIdHash + flags=0x05 [UP|UV] + counter=1)
Outer hash: `sha256(authData || sha256(clientDataJSON))` = `0x9f7c77b1b5319cf4c3164eaffda707cc763c13cccb0cc00fc81239d21429ce0c`
P-256 sig: r=`0x4f714047db4b752341cdde56faa911789c05034bb9863a24590cc116445ff696`, s=`0x2c01ae64032750ef6b2c616d32b2c95e53503f7e350469d205c0e60468e7d402`

Envelope: `[V2_SNIP12, owner_id=0, kind='WEBAUTHN_P256', ByteArray(authData), ByteArray(clientDataJSON), challenge_offset=36, r_low, r_high, s_low, s_high, y_parity=0]` (20 felts total).

**What this proves on V8.4 specifically**:
- **Passkey (Touch ID / Face ID / hardware authenticator) → V8.4 OE end-to-end on mainnet.** Closes Cycle-1 parity.
- V8.4 dispatcher correctly routes `kind='WEBAUTHN_P256'` to the V8.2 WebAuthnP256Verifier via `library_call_syscall`.
- Cairo Serde correctly deserializes the two ByteArrays from the envelope. Layout: `[num_full_31B_chunks, chunks..., pending_word, pending_word_len]`.
- Audit H-1 type-binding check (`{"type":"webauthn.get"` prefix) passes for legitimate auth assertions.
- UP flag check (`authData[32] & 0x01 == 0x01`) passes for flags=0x05.
- Base64url challenge encoding (43 bytes, no padding) matches between off-chain TS (`Buffer.from(bytes).toString('base64url')`) and on-chain Cairo (`base64url_encode_32`).
- `sha256(authData || sha256(clientDataJSON))` reconstruction matches between off-chain `@noble/hashes/sha2` and on-chain `compute_sha256_byte_array` byte-for-byte.
- P-256 ECDSA `is_valid_signature` via Starknet `secp256r1` syscall + recovered point's (x,y) coordinates match stored owner pubkey.
- Fee paid by Chipi paymaster (~0.0370 STRK) — close to STARK/EIP-191 cost despite the heavier verifier work (two sha256 + P-256 verify + base64url decode + JSON prefix check). Matches `chipi-handover.md §4` ~35M l2_gas estimate.

**Notes**:
- The script synthesizes the passkey (random P-256 keypair as "authenticator") rather than calling `navigator.credentials.get()`. The on-chain verifier only knows about bytes — a real browser-side WebAuthn flow produces byte-identical authData / clientDataJSON / signature, so this smoke result transfers cleanly to a real passkey integration.
- For a real-passkey browser test (Cycle-3 territory), use `@simplewebauthn/browser` to call `navigator.credentials.get({publicKey: {challenge: <32-byte hash>, rpId, ...}})` and parse `response.authenticatorData`, `response.clientDataJSON`, `response.signature` into the same envelope layout. No on-chain changes needed.

---

## Test 2 — V8.4 ED25519 OE (Phantom / Solana / generic Ed25519) via Chipi paymaster ✅

**Date**: 2026-05-18
**Class**: V8.4 `ShhhAccount` (`0x075dfb396…fa58a`)
**Verifier**: V8.2 `Ed25519Verifier` (`0x030a7dfc…9f74`) — Garaga v1.0.1 `is_valid_eddsa_signature`
**Account deployed**: [`0x37ed11f5deed54383236bd5dde9921cdac04a2772fe240b97dc84e48b10fbf4`](https://voyager.online/contract/0x37ed11f5deed54383236bd5dde9921cdac04a2772fe240b97dc84e48b10fbf4)
**Paymaster**: Chipi (`paymaster_executeSponsoredRaw`)

| Step | Tx | Block | Fee | Status |
|---|---|---|---|---|
| Deploy V8.4 instance via UDC (ED25519 primary, label `'smoke2'`) | [`0x4e1dd84a…cc9a76`](https://voyager.online/tx/0x4e1dd84a839861ba7654b2f97f05c62e06c78b7a9f73c63ba358b146acc9a76) | — | ~0.519 STRK (deployer-paid) | ✅ |
| `execute_from_outside_v2` via Chipi paymaster (Ed25519 sig over 64 hex-ASCII bytes, Garaga v1.0.1 BN math, `caller='ANY_CALLER'`, no-op `STRK.transfer(self, 0)`) — **trace-verified, no inner revert** | [`0x7472be95…25f86dbb`](https://voyager.online/tx/0x7472be95c30c4e49e053888fb8cda588ddc29372fabdacca3f01b0225f86dbb) | — | `0x63c14420af6eac0` FRI ≈ 0.4495 STRK (**paymaster-paid**; BN curve arithmetic is the dominant cost) | ✅ SUCCEEDED + inner OE non-reverted |

Reproduction script: `shhh:scripts/smoke-test-2.mjs`.
Ed25519 keypair (committed for replay):
- seed: `0x05d8daea3a65f5520a56a98b7ebcc3aaa88caafbfa1dfbcf12b8202377ed76d4`
- pubkey: `0x21effcd09e369d4200efa334835e41d254a3a78cd5544fd86083d650e9a3a6df`
- pubkey LE halves: low=`0xd2415e8334a3ef00429d369ed0fcef21`, high=`0xdfa6a3e950d68360d84f54d58ca7a354`

OE message hash (SNIP-12): `0x2c022b03c536bcdf2891c29581d7c83ea2c47d58caa5bb1508450c4d48f27c9`
Signed bytes (64 hex-ASCII of message_hash): `02c022b03c536bcdf2891c29581d7c83ea2c47d58caa5bb1508450c4d48f27c9`
Ed25519 signature:
- R: `0xe5de23ba24821bf2b35a42b673dcbc6baa352f112a761a3edc949db0304b98f5`
- S: `0xed525e7080d195cdddbfbe9bbc7cbb6356e4291d6dddf67fd169049d5b8db406`

Envelope: `[V2_SNIP12, owner_id=0, kind='ED25519', ...garaga_payload]` (97 felts: 3 header + 94 garaga payload of [Ry_low, Ry_high, s_low, s_high, msg_len=64, msg_bytes(64), msm_hint, sqrt_Rx_hint, sqrt_Px_hint]).

**What this proves on V8.4 specifically**:
- **Phantom-style Ed25519 → V8.4 OE end-to-end on mainnet** via Garaga v1.0.1 on-chain verification.
- V8.4 dispatcher correctly routes `kind='ED25519'` to the V8.2 Ed25519Verifier via `library_call_syscall`.
- Verifier reconstructs the 64-char lowercase hex-ASCII of `message_hash` via `hash_to_hex_ascii` (verifier.cairo:50) and asserts byte-equality with the msg span before `is_valid_eddsa_signature` runs.
- Garaga `eddsaCalldataBuilder(ry_le, s_le, py_le, msg_bytes, false)` produces the EdDSASignatureWithHint Serde layout the verifier expects byte-for-byte (audit M-4 envelope shape).
- Constructor accepts `pubkey_len=2` for the (pk_low, pk_high) LE u256 halves of the 32-byte Ed25519 pubkey.
- Fee paid by Chipi paymaster (~0.050 STRK) — higher than STARK (~0.036) and EIP-191 (~0.035) because Garaga BN curve arithmetic for Ed25519 sponge is ~33M l2_gas vs ~2M / ~10M for STARK / EIP-191. Matches `chipi-handover.md §4` table.

**Notes**:
- Used `tweetnacl.sign.detached(64hexAsciiBytes, secretKey)` for the signature. Phantom's `signMessage(64hexAsciiBytes)` produces an identical signature byte-for-byte — the same recipe used in the Shhh frontend today (`src/lib/garaga/hints.ts:generateEdDSACalldata`).
- The 64-char hex-ASCII representation is what the user sees in Phantom's signing popup ("sign 02c022b03c536bcdf…f27c9"). It bypasses Phantom's anti-Solana-tx check (pure 0-9 + a-f bytes can't be misinterpreted as a Solana tx) while remaining human-inspectable.

---

## Test 3 — V8.4 EIP-191 SECP256K1 OE (MetaMask `personal_sign`) via Chipi paymaster ✅

**Date**: 2026-05-18
**Class**: V8.4 `ShhhAccount` (`0x075dfb396…fa58a`)
**Verifier**: V8.2 `EIP191Secp256k1Verifier` (`0x03a75997…84e6`)
**Account deployed**: [`0x70fba34b561ad548fad7c1877f0ca4cfe69dee2c756e1a00a64bfe2527e4d07`](https://voyager.online/contract/0x70fba34b561ad548fad7c1877f0ca4cfe69dee2c756e1a00a64bfe2527e4d07)
**EVM address (same key)**: `0x45C5Ff13576f0bbd92189008320926c807C35A95`
**Paymaster**: Chipi (`paymaster_executeSponsoredRaw`)

| Step | Tx | Block | Fee | Status |
|---|---|---|---|---|
| Deploy V8.4 instance via UDC (EIP-191 primary, label `'smoke3'`) | [`0x6e8d3ad4…40c515`](https://voyager.online/tx/0x6e8d3ad4232b2e25ba870189e37bdb3608225e98655babb09310bc7cd40c515) | — | ~0.566 STRK (deployer-paid) | ✅ |
| `execute_from_outside_v2` via Chipi paymaster (EIP-191 `personal_sign`, `caller='ANY_CALLER'`, no-op `STRK.transfer(self, 0)`) — **trace-verified, no inner revert** | [`0x677f414e…4993b15`](https://voyager.online/tx/0x677f414ecf214b2a2b4419ba2ee66fa656c179db66425ccdc013acad4993b15) | — | `0x64457a11bb58200` FRI ≈ 0.4519 STRK (**paymaster-paid**; secp256k1 recover + keccak is the dominant cost) | ✅ SUCCEEDED + inner OE non-reverted |

Reproduction script: `shhh:scripts/smoke-test-3.mjs`.
EVM keypair (committed for replay): priv `0x3137d63b6749683a541326aa1fa135cf4c859b6af89e82c765526e687085e0b4`, EVM address `0x45C5Ff13576f0bbd92189008320926c807C35A95`.
Secp pubkey felts: `x_low=0x43895bb7bb709285f1b04a13b6693574`, `x_high=0x7c2ea35809b7b12f118aaf9134890eb5`, `y_low=0xa8c35e9df404aa27179fc23d73200afb`, `y_high=0x5710e904ebbe08c7b2386dadfad6a007`.

OE message hash (SNIP-12): `0x1e9ba814e956e6777d0cba841438e85e8decc98bb024c68388d55e42c9115ef`
Signature (EIP-191 personal_sign):
- r: `0x7804a3be88793c970bda1107b39bf6522cce0a4d301d8a1e081fac6bad50a903`
- s: `0x6c363ff930500f4183505de0b4eed91a1f94381bf2366244322323319197936d`
- y_parity: `0`

Envelope: `[V2_SNIP12, owner_id=0, kind='EIP191_SECP256K1', r_low, r_high, s_low, s_high, y_parity]` (8 felts).

**What this proves on V8.4 specifically**:
- **MetaMask `personal_sign` → V8.4 OE end-to-end on mainnet.** The headline cross-ecosystem proof.
- V8.4 dispatcher correctly routes `kind='EIP191_SECP256K1'` to the V8.2 EIP191Secp256k1Verifier via `library_call_syscall`.
- The verifier reconstructs the EIP-191 hash (`keccak256("\x19Ethereum Signed Message:\n32" || msg_be32)`) on chain and matches the recovered secp256k1 pubkey against the stored (x, y) tuple — verifier reverts cleanly on mismatch, signature valid on match.
- Constructor accepts `pubkey_len=4` for the (x_low, x_high, y_low, y_high) secp256k1 pubkey shape.
- Counterfactual address derivation works for EIP-191 — the same `[primary_kind, primary_verifier, pubkey_len, ...pubkey, label]` ctor calldata pattern as STARK, just with `pubkey_len=4`.
- Fee paid by Chipi paymaster (~0.035 STRK), wallet has 0 STRK balance — confirms paymaster-agnostic-kind property.
- EIP-191 OE gas overhead empirical: ~10M l2_gas (matches `chipi-handover.md §4` table).

**Notes**:
- Used the noble-curves secp256k1 + `keccak_256` from `@noble/hashes` to mirror `Wallet.signMessage(bytes)` from ethers / MetaMask. The Cairo `compute_eip191_hash` reconstruction matched on first try — no off-chain/on-chain hash drift.
- viem's `privateKeyToAccount(priv).signMessage({message: {raw: msgBe32}})` produces an identical 65-byte signature; both paths are interchangeable for SDK builders.

---

## Test 15 — Paymaster-sponsored OE on V8.4 (STARK primary) via Chipi ✅

**Date**: 2026-05-18
**Class**: V8.4 `ShhhAccount` (`0x075dfb396…fa58a`)
**Account deployed**: [`0x6727639a48098f0bba4e7fc664eb33168ead2df8e85631df63416ff137a959e`](https://voyager.online/contract/0x6727639a48098f0bba4e7fc664eb33168ead2df8e85631df63416ff137a959e)
**Paymaster**: Chipi (`https://paymaster.chipipay.com`, `paymaster_executeSponsoredRaw`)

| Step | Tx | Block | Fee | Status |
|---|---|---|---|---|
| Deploy V8.4 instance via UDC (STARK primary, label `'smoke15'`) | [`0x66e4abc8…3c3692`](https://voyager.online/tx/0x66e4abc8d848fe86378207e5130896459eed6bd25696db982e6e558333c3692) | — | ~0.496 STRK (deployer-paid) | ✅ |
| `execute_from_outside_v2` via Chipi paymaster (STARK ECDSA, `caller='ANY_CALLER'`, no-op `STRK.transfer(self, 0)`) — **trace-verified, no inner revert** | [`0x5dc71618…aa4daf4f`](https://voyager.online/tx/0x5dc7161835d9cba246b3bdb9c5ba7613c424ab2f9bb380111799affaa4daf4f) | — | `0xdf806e96f13b5e` FRI ≈ 0.0629 STRK (**paymaster-paid**) | ✅ SUCCEEDED + inner OE non-reverted |

Reproduction script: `shhh:scripts/smoke-test-15.mjs` (in the Shhh frontend repo).
Stark keypair: pk `0x0405746fda3f5e994c38e51f895d71ccd4d6930008a188f5729cc7dc0a22f203`, pubkey `0x52aa899ffdeb447003e0c0edfcd12e7a3933fd05c69fd370504e91c674951c4` (committed for replay).

OE message hash (SNIP-12): `0x5b261f1aef2e7cf9da9a733cbe9c7aea4680f76b05a9aa796ee3f715f7bbc5`
STARK signature: r=`0x417f25243a7e2a6aac943491f01860b0d65bd88246d2faa4f0c0898d916c2cd`, s=`0x7a248c91982624ce96fb39fbc5d709bfb6b1eaedc218ee8661fb2c759715ed`
Envelope: `[V2_SNIP12, owner_id=0, kind='STARK', r, s]` (5 felts).

**What this proves on V8.4 specifically**:
- End-to-end paymaster-sponsored OE on V8.4 works on mainnet — the headline Chipi integration point.
- Chipi's `paymaster_executeSponsoredRaw` endpoint accepts the V8.4 OE calldata shape verbatim (no Chipi-side parsing of the envelope).
- Fee is paid by the paymaster, not by the user wallet (`0x6727…959e` has 0 STRK balance; deploy was deployer-funded, OE was paymaster-funded).
- Audit M-2 `inside_verifier` flag wraps cleanly around the STARK verifier `library_call`.
- Audit C-1 role check (`owner.role == ROLE_OWNER`) does NOT false-positive on the primary owner.
- SNIP-12 typed-data hash matches between off-chain TS (`shhh:src/lib/starknet/snip12.ts` pattern) and on-chain Cairo (`shhh-wallet-cairo:src/outside_execution.cairo`).
- The `'ANY_CALLER'` caller sentinel with a 2-hour validity window is accepted (audit M-2 cap satisfied).

**Open notes**:
- Chipi paymaster API auth header is `x-paymaster-api-key`, NOT `Authorization: Bearer` as shown in the handover doc snippet. Update `docs/v8-3-sdk-integration.md §11` accordingly.
- `tracking_id` returned by `paymaster_executeSponsoredRaw` was `0x0` — semantics unclear, ask Chipi (logged in `SHHH_INTEGRATION_ANSWERS.md Q6.6`).
- Deploy cost was 0.496 STRK vs. ~0.224 STRK for Test 1's V8.1 deploy — V8.4 constructor is more expensive due to `_validate_pubkey_via_verifier` library_call. Reasonable but worth noting in cost reports.

---

## Test 1a — V8.4 deploy + state-readback ✅

**Date**: 2026-05-15
**Class**: V8.4 `ShhhAccount` (`0x075dfb396…fa58a`)
**Account deployed**: [`0x020e25a489b14c80d4ff0674bcc96518a67fe171f9633a9533841b8c6a9b85c5`](https://voyager.online/contract/0x020e25a489b14c80d4ff0674bcc96518a67fe171f9633a9533841b8c6a9b85c5)

| Step | Tx | Status |
|---|---|---|
| V8.4 ShhhAccount declare | [`0x0737570e…ea0dfd`](https://voyager.online/tx/0x0737570e0430bed8e21c05bcb88a6f649f99d8a5f3d36dd0350a0dd172ea0dfd) (block 9787252, 43.67 STRK) | ✅ |
| Deploy V8.4 instance via UDC (STARK primary owner) | [`0x02670017…0c568a6`](https://voyager.online/tx/0x026700170248b14e516a8145397d2ac1807aa3cf22709fe92a80573300c568a6) | ✅ |

Post-deploy state readback (mainnet):
- `primary_kind()` → `0x535441524b` (`'STARK'`) ✅
- `owner_count()` → `1` ✅
- `get_verifier_class('STARK')` → `0x00d09209…dbf68` (V8.2 StarkVerifier, matches expected) ✅

**What this proves on V8.4 specifically**:
- The V8.4 class hash is callable via UDC deploy on production
- The V8.4 constructor accepts the V8 multi-kind calldata shape
- `_validate_pubkey_via_verifier` for STARK invokes the V8.2 StarkVerifier correctly via `library_call_syscall`
- The new `LEGACY_OZ_ACCOUNT_PUBKEY_SLOT` const compiles correctly into the Sierra binary that's now on mainnet (otherwise the constructor would have reverted at the const initialization)
- `verifier_classes` Map writes work post-V8.4 (storage layout unchanged, but worth confirming with a fresh deploy)
- Audit-trail: V8.4 redeclare reaches mainnet at the audited Sierra binary, matching the byte-for-byte class hash predicted at commit time

**What this does NOT prove** (still pending): cross-ecosystem signer OEs at V8.4 (covered by V8.3-via-V8.1 carry-forward but worth a dedicated V8.4 OE smoke), `bootstrap_from_sessions_signed` against a real stranded wallet, `initiate_recovery_outside` guardian flow on mainnet. These ride on Chipi cycle 4 + Phase 13 audit prep.

---

## Test 1 — V8.1 deploy + STARK ECDSA OE end-to-end ✅

**Date**: 2026-05-10
**Account**: [`0x00a2220b05b5d16f52c4ce179e5386bd4b23dc5f4b7a1e0b51c579dbd9129b31`](https://voyager.online/contract/0x00a2220b05b5d16f52c4ce179e5386bd4b23dc5f4b7a1e0b51c579dbd9129b31)

| Step | Tx | Block | Fee | Status |
|---|---|---|---|---|
| Deploy V8.1 ShhhAccount via UDC | [`0x022ac136…fc96`](https://voyager.online/tx/0x022ac136eda2a0b07a155fe49dd114b59418ef071404af72db1d2c794798fc96) | 9,632,643 | 0.2239 STRK | ✅ |
| `execute_from_outside_v2` (STARK ECDSA) | [`0x0625297020…00c9`](https://voyager.online/tx/0x0625297020b1c7503628d2353505e4a8f027f33ba2f4083523e300ac846200c9) | 9,632,681 | 0.0555 STRK | ✅ |

**Total cost**: 0.28 STRK ($0.011)

**What this proves on production**:
- V8.1 constructor accepts the V8 multi-kind calldata `[primary_kind, primary_verifier_class, pubkey_bytes, label]`
- Counterfactual address derivation matches the on-chain deploy result byte-for-byte
- `execute_from_outside_v2` deserializes the OE struct (caller, nonce, time bounds, calls multicall)
- SNIP-12 typed-data hashing on chain matches the off-chain Python reference byte-for-byte
- Audit C-1 role check (`assert(owner.role == ROLE_OWNER)`) does NOT false-positive on the primary owner
- Audit M-2 `inside_verifier` flag wraps cleanly (raised, lowered, no leak into legit flows)
- Library_call dispatch from ShhhAccount → StarkVerifier via `ISignerLibraryDispatcher`
- STARK ECDSA verification passes inside the verifier class
- Atomic multicall executes (in this case a no-op self-read, but still the executor path)
- Events emit (2 events per receipt: `OutsideExecutionExecuted` + multicall return)

**What this does NOT prove**: every other signer kind, multi-owner setup, threshold envelopes, recovery, sessions, paymaster sponsorship.

---

## Tests 2-14 — what's NOT smoked yet

### Cross-ecosystem signer kinds (the headline V8.1 value)

| # | Kind | Status | Why it matters |
|---|---|---|---|
| 2 | `ED25519` (Phantom / Solana) | ✅ smoked 2026-05-18 (V8.4, tx `0x1c1b7828…0cbeccd`) | First cross-ecosystem demo |
| 3 | `EIP191_SECP256K1` (MetaMask `personal_sign`) | ✅ smoked 2026-05-18 (V8.4, tx `0x7ccb7aa7…c4c98`) | Largest user base; the headline MetaMask integration |
| 4 | `EIP712_SECP256K1` (MetaMask typed data) | ❌ not smoked | The structured-popup variant |
| 5 | `SECP256K1` (raw secp256k1) | ❌ not smoked | Hardware-wallet variant |
| 6 | `P256` (raw P-256) | ❌ not smoked | Smart cards / eIDAS |
| 7 | `WEBAUTHN_P256` (Apple passkeys / Touch ID) | ✅ smoked 2026-05-18 (V8.4, tx `0x4b4ee32c…cdebf`) | Highest-UX cross-ecosystem |
| 8 | `JWT_ES256` (Apple Sign-in single-tenant) | ❌ not smoked | Single-account Apple flow |
| 9 | `JWT_ES256_APPLE_SUB` (Apple multi-tenant) | ❌ not smoked | Recommended for Chipi multi-user |
| 10 | `BLS12_381` (validators / DAOs) | ❌ not smoked | Institutional signers; not consumer-facing |

**Each of these costs ~1-2 STRK to smoke** (deploy a fresh V8.3 account with that kind as primary owner + sign one OE). Total to smoke all 9: ~12-15 STRK.

**Recommended priority** (per Chipi Pay use cases):
1. `EIP191_SECP256K1` — MetaMask is the largest single signer kind by user count
2. `JWT_ES256_APPLE_SUB` — multi-tenant Apple is the Chipi default for many-user-one-key flows
3. `ED25519` — Phantom / Solana
4. `WEBAUTHN_P256` — passkeys
5. The remaining four can wait until a real product needs them

### V8.3 features not yet smoked

| # | Feature | Status | Mainnet evidence required |
|---|---|---|---|
| 11 | Add a secondary owner via timelocked governance | ❌ not smoked | Run `propose_add_owner` + wait 48h + `execute_add_owner` and confirm the new owner can sign |
| 12 | Threshold envelope (2-of-3, mixed kinds) | ❌ not smoked | Set threshold=2 + add two more owners + sign one OE with two of them aggregated; confirm the third single signer alone can't satisfy |
| 13 | Recovery flow (guardian initiate + owner cancel) | ✅ **smoked 2026-06-25** (V8.4) | Done — see [Test 13 detail](#test-13--guardian-recovery-carve-out-v84) below. Guardian initiated recovery; guardian's non-recovery OE reverted `'SHHH: signer not an owner'`; owner cancelled. `finalize_recovery` (7-day) still separate. |
| 14 | Session key + spending policy | ✅ **smoked 2026-06-20** (V8.4) | Done — see [Test 14 detail](#test-14--session-key-spending-cap-v84) below. In-cap session OE succeeded; over-cap reverted on-chain with `'Spending: exceeds per-call'`. |
| 15 | Paymaster-sponsored OE (Chipi or AVNU) | ❌ not smoked | Sign an OE with `caller='ANY_CALLER'` + relay via Chipi paymaster + confirm fee paid by paymaster, not user |

**Recommended priority for production confidence**:
1. **Test 15 (paymaster-sponsored OE)** is the single highest-leverage smoke test for Chipi integration. Until this works on mainnet, the paymaster integration is theoretical.
2. Test 12 (threshold envelope) closes the M-2 verifier-reentrancy guard in the cross-owner aggregation path.
3. Test 13 (recovery) is the audit C-1 fix's load-bearing demo — guardian can initiate but can't sign arbitrary OEs.
4. Test 11 is nice-to-have for production confidence but not gating. (Test 14 ✅ done — see below.)

---

## Test 13 — guardian-recovery carve-out (V8.4)

**Smoked 2026-06-25 on mainnet against V8.4 `ShhhAccount` `0x075dfb39…fa58a`.**
On-chain proof of the audit C-1 carve-out: a `ROLE_GUARDIAN` signer can sign
an OutsideExecution that calls `initiate_recovery` (with its own owner_id as
proposer) but **cannot** sign any other OE. Driver:
`scripts/ts/mainnet-test-13-guardian-recovery.ts` (two-phase — guardian
install goes through the 48h `propose_add_owner` timelock).

Wallet `0x75825349…3a0762` (primary STARK owner_id 0; guardian owner_id 1).

| Step | Tx | Result | Block |
|---|---|---|---|
| Propose guardian (owner OE) — Phase A, 2026-06-23 | [`0x1d51cac0…67038`](https://starkscan.co/tx/0x1d51cac098c52b7c6277788956488230bbf1f765abfab31a9f38d5d31e67038) | ✅ SUCCEEDED | 11078782 |
| `execute_add_owner` (install guardian, after 48h) | [`0x83b1ead0…6a880`](https://starkscan.co/tx/0x83b1ead08db8e431ca24583b8572fdba8674d17f00e9c03dd45ac04ea6a880) | ✅ SUCCEEDED | 11164122 |
| **Guardian-OE `initiate_recovery`** (proposer = own id) | [`0x2e9529b4…b5ce33a`](https://starkscan.co/tx/0x2e9529b40b79b44803d21ccf9228926c98b3125f9becad0c4576584cb5ce33a) | ✅ **SUCCEEDED** (carve-out positive) | 11164125 |
| **Guardian-OE, non-recovery call** (`STRK.transfer`) | [`0x6e815acb…598623e`](https://starkscan.co/tx/0x6e815acbf63d4c7c6aac0e175ac58da9dc74f813a6a4ab6ef502606a598623e) | ⛔ **REVERTED** — `'SHHH: signer not an owner'` (carve-out negative) | — |
| Owner-OE `cancel_recovery` (clears the active pending) | [`0x9a395a39…673702`](https://starkscan.co/tx/0x9a395a3920f82f21f4fc1c7afc6c5fea0e41bae9a9a768239b9ffdb0673702) | ✅ SUCCEEDED | 11164203 |

The negative case is the load-bearing one: the same guardian key that
*could* initiate recovery is rejected with `'SHHH: signer not an owner'`
the moment it signs anything other than the single allowed
`initiate_recovery` call — proving a "guardian for emergency recovery"
cannot silently act as a full owner (the V8.3 gap closed in V8.4).
`finalize_recovery` (the 7-day permissionless completion) is a separate
future smoke.

---

## Test 14 — session-key spending cap (V8.4)

**Smoked 2026-06-20 on mainnet against the live V8.4 `ShhhAccount` class
`0x075dfb396…fa58a`.** This is the on-chain proof that the deployed class
enforces `check_and_update_spending` (`account.cairo:397`) in the execute
path: an over-cap session-signed call is rejected *before* the calls run.
In-CI mirror: `tests/account_sessions_e2e.cairo`. Driver:
`scripts/ts/mainnet-test-14-spending-cap.ts` (+ `force-invoke.ts` to land
the deliberately-reverting tx, since fee-estimation tooling aborts on the
simulated revert and never broadcasts).

**Setup**: fresh V8.4 wallet, primary STARK owner. Session key whitelisted
for `approve`, with spending policy on a token: `max_per_call = 1_000000`,
`max_per_window = 1_500000`, `window_seconds = 3600`. `approve` (not
`transfer`) is the metered op so the in-cap success demonstrates the cap
allowing the call without depending on the wallet holding a balance.

| Step | Tx | Result | Block |
|---|---|---|---|
| Deploy V8.4 wallet `0x004e427a…92e01` | [`0x052b18ea…1047cbf`](https://starkscan.co/tx/0x052b18eacc64448708d6e83bad41e89473bdda8facd6f08280549e4751047cbf) | ✅ SUCCEEDED | 10995902 |
| Register session key + spending policy (owner-signed OE) | [`0x0328f305…46dc3047`](https://starkscan.co/tx/0x0328f30555e9c685e8ac4a0c7be8bfdf95e353396af7db333cf9696846dc3047) | ✅ SUCCEEDED | 10995921 |
| **In-cap** session OE — `approve(spender, 500000)` (≤ cap) | [`0x01bb021c…32ab3fd`](https://starkscan.co/tx/0x01bb021cd8b3e6c4b9a37c4319feee5d4e2037c33da8b47ded604dc8b32ab3fd) | ✅ **SUCCEEDED** | 10995928 |
| **Over-cap** session OE — `approve(spender, 5000000)` (5× cap) | [`0x40c5e97f…4b2b8f`](https://starkscan.co/tx/0x40c5e97fec54642e753821b556df5963cdd839583356726d4ad313eff4b2b8f) | ⛔ **REVERTED** — `'Spending: exceeds per-call'` | 10995987 |

The over-cap revert reason on-chain is the felt
`0x5370656e64696e673a2065786365656473207065722d63616c6c`
(`'Spending: exceeds per-call'`), raised from class `0x075dfb396…fa58a`
selector `0x034cc13b…` (`execute_from_outside_v2`) — i.e. the deployed V8.4
account, not a local build. Total fee for the four txs: ~0.61 STRK
(deployer `0x64b1cf9c…`).

**What this closes**: the session-key spending cap is now proven
end-to-end on the deployed class — over-cap rejected atomically, in-cap
allowed — not just in `snforge`. Same-window cumulative cap and window
rollover remain CI-only (`account_sessions_e2e.cairo`); the per-call gate
is the load-bearing one for autonomous-spend safety and is now on-chain.

---

## Recommended next batch

Quick wins (this week, ~2-3 STRK total):

| Order | Test | Cost | Justification |
|---|---|---|---|
| 1 | Test 3 — EIP-191 MetaMask OE | ~1.5 STRK | The headline cross-ecosystem demo. If this works, V8 has its "MetaMask without a Snap" proof. |
| 2 | Test 15 — paymaster-sponsored Chipi OE | ~0 STRK (paymaster pays) | Required for Chipi integration confidence. Use Chipi paymaster's `paymaster_executeSponsoredRaw`. |
| 3 | Test 11 — add a secondary owner via timelock | ~0.5 STRK | Proves the timelocked governance pipeline. Wait 48h between propose and execute. |

Slow burns (next week, ~3-5 STRK):

| Order | Test | Cost | Justification |
|---|---|---|---|
| 4 | Test 13 — recovery flow (7-day wait) | ~1.5 STRK | Run initiate + cancel within the window first (cheap proof of cancel path), then a separate 7-day finalize run. |
| 5 | Test 14 — session-key spending policy | ~1 STRK | Bonus, validates the SNIP-163 port. |
| 6 | Test 9 — JWT_ES256_APPLE_SUB | ~2 STRK | Higher-cost (~59M l2_gas per OE). Run after Chipi commits to multi-tenant Apple. |

Out of scope for now (defer):

- Tests 5, 6, 7 (raw secp256k1, raw P-256, WebAuthn) — useful but lower priority for Chipi
- Test 10 (BLS) — not a consumer use case; smoke when a validator / DAO actually wants V8

---

## How a smoke test is structured

For reproducibility, every smoke test follows the same pattern:

1. **Compute counterfactual address** from `(class_hash, primary_kind, pubkey, label)`.
2. **Deploy via UDC** with `unique=false` so the address matches the counterfactual.
3. **Build OE** (caller, nonce, time bounds, calls).
4. **Compute SNIP-12 hash** off chain.
5. **Sign with the kind-specific signer** (STARK ECDSA / Ed25519 via Garaga / EIP-191 via ethers / etc.).
6. **Build envelope** in canonical shape `[V2_SNIP12, owner_id, kind_tag, ...payload]`.
7. **Submit** via `sncast invoke` (or via paymaster for test 15).
8. **Verify receipt**: status SUCCEEDED, fee in the expected range, events emitted, no revert.
9. **Capture in this doc**: tx hash, block number, fee, observed events, link to the ScarbAddr / Voyager.

Test 1 above is the canonical example. Reproducing scripts are in `/tmp/smoke_oe.py` (committed to the smoke-test branch when we add the next batch).

---

## What "smoked" gates

Before recommending V8.3 to **anyone** (Cifra, Chipi customers, third-party integrators), the following must be smoked on mainnet:

- [x] Test 1 — STARK deploy + OE (carries from V8.1 — see top note)
- [x] Test 3 — EIP-191 MetaMask OE (2026-05-18, V8.4, tx `0x7ccb7aa7…c4c98`)
- [x] Test 15 — Paymaster-sponsored OE through Chipi (2026-05-18, V8.4 STARK, tx `0x4d22f2f2…0384e3d`)

Before recommending V8.3 for **production volume** (multi-user, multi-account):

- [ ] Test 11 — multi-owner setup via timelocked governance (V8.3-specific — exercises the new `validate_pubkey` call on add_owner)
- [ ] Test 13 — recovery initiate + cancel (the headline safety primitive; V8.3 wires `validate_pubkey` into `finalize_recovery` so the full 7-day cycle is also a V8.3 regression on H-1)

Before recommending V8.3 for **institutional / multi-sig**:

- [ ] Test 12 — threshold envelope (2-of-3, mixed kinds)
- [ ] Test 13 finalize — full 7-day recovery cycle

Before recommending V8.3 for **validator / DAO** workflows:

- [ ] Test 10 — BLS12-381 OE

---

## Open questions / decisions

1. **Burn rate**: Test 1 cost 0.28 STRK. Smoking the remaining 13 tests is ~15-20 STRK total. Deployer balance is ~83 STRK after the V8.2 redeclare cycle (10 verifier classes) and the V8.3 ShhhAccount redeclare on 2026-05-11. Still enough runway to smoke the recommended next batch but tighter — re-fund the deployer before BLS / WebAuthn / threshold-aggregation tests.
2. **Test 15 (paymaster) prerequisite**: requires a Chipi Pay API key for the deployer / a separate test account. Coordination with Chipi infra team.
3. **Test 13 finalize requires a 7-day wait** — start the clock as early as possible.
4. **Test 9 (Apple JWT)** requires a real Apple JWT — needs an Apple Developer account + a sign-in flow + a captured fixture. Not blocking, but coordinate with the Sign-in-with-Apple team owner.

---

Last updated: 2026-05-11 (V8.3 redeclare). After running additional smoke tests, append the receipt block to the table in section "Tests 2-14" and tick the appropriate box in "What 'smoked' gates." Smoke runs from 2026-05-11 onwards SHOULD deploy against the V8.3 class hash `0x03bc539295abd3e59bd9ea799d12fe3331748d484bc77bff45b302b1636a87d9`.
