# V8.1 mainnet smoke tests — status

> Tracks the empirical "does V8.1 actually work in production?" tests. Class declares prove the code is *registered*; smoke tests prove it *executes*. This doc is the source of truth for which signer kinds and which V8 features are battle-tested on Starknet mainnet vs only proven via `snforge`.

---

## Summary

**1 of 14 smoke tests passing.** V8.1 is proven to deploy + sign OEs end-to-end on production for the simplest signer kind. Cross-ecosystem signers, governance, recovery, threshold, sessions, and paymaster-sponsored flows are all unproven on mainnet (only proven in `snforge`).

**Bottom line for Chipi Pay integration**: the dispatcher works. Everything else needs one mainnet OE to call "proven."

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
| 2 | `ED25519` (Phantom / Solana) | ❌ not smoked | First cross-ecosystem demo |
| 3 | `EIP191_SECP256K1` (MetaMask `personal_sign`) | ❌ not smoked | Largest user base; the headline MetaMask integration |
| 4 | `EIP712_SECP256K1` (MetaMask typed data) | ❌ not smoked | The structured-popup variant |
| 5 | `SECP256K1` (raw secp256k1) | ❌ not smoked | Hardware-wallet variant |
| 6 | `P256` (raw P-256) | ❌ not smoked | Smart cards / eIDAS |
| 7 | `WEBAUTHN_P256` (Apple passkeys / Touch ID) | ❌ not smoked | Highest-UX cross-ecosystem |
| 8 | `JWT_ES256` (Apple Sign-in single-tenant) | ❌ not smoked | Single-account Apple flow |
| 9 | `JWT_ES256_APPLE_SUB` (Apple multi-tenant) | ❌ not smoked | Recommended for Chipi multi-user |
| 10 | `BLS12_381` (validators / DAOs) | ❌ not smoked | Institutional signers; not consumer-facing |

**Each of these costs ~1-2 STRK to smoke** (deploy a fresh V8.1 account with that kind as primary owner + sign one OE). Total to smoke all 9: ~12-15 STRK.

**Recommended priority** (per Chipi Pay use cases):
1. `EIP191_SECP256K1` — MetaMask is the largest single signer kind by user count
2. `JWT_ES256_APPLE_SUB` — multi-tenant Apple is the Chipi default for many-user-one-key flows
3. `ED25519` — Phantom / Solana
4. `WEBAUTHN_P256` — passkeys
5. The remaining four can wait until a real product needs them

### V8.1 features not yet smoked

| # | Feature | Status | Mainnet evidence required |
|---|---|---|---|
| 11 | Add a secondary owner via timelocked governance | ❌ not smoked | Run `propose_add_owner` + wait 48h + `execute_add_owner` and confirm the new owner can sign |
| 12 | Threshold envelope (2-of-3, mixed kinds) | ❌ not smoked | Set threshold=2 + add two more owners + sign one OE with two of them aggregated; confirm the third single signer alone can't satisfy |
| 13 | Recovery flow (initiate + cancel + finalize) | ❌ not smoked | Add a `ROLE_GUARDIAN` + initiate recovery from guardian + confirm `cancel_recovery` works (single-owner cancel) AND that `finalize_recovery` works after 7 days |
| 14 | Session key + spending policy | ❌ not smoked | Add a session key + set spending policy + sign 4-element session OE + confirm spending cap fires when exceeded |
| 15 | Paymaster-sponsored OE (Chipi or AVNU) | ❌ not smoked | Sign an OE with `caller='ANY_CALLER'` + relay via Chipi paymaster + confirm fee paid by paymaster, not user |

**Recommended priority for production confidence**:
1. **Test 15 (paymaster-sponsored OE)** is the single highest-leverage smoke test for Chipi integration. Until this works on mainnet, the paymaster integration is theoretical.
2. Test 12 (threshold envelope) closes the M-2 verifier-reentrancy guard in the cross-owner aggregation path.
3. Test 13 (recovery) is the audit C-1 fix's load-bearing demo — guardian can initiate but can't sign arbitrary OEs.
4. Tests 11 + 14 are nice-to-have for production confidence but not gating.

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

Before recommending V8.1 to **anyone** (Cifra, Chipi customers, third-party integrators), the following must be smoked on mainnet:

- [x] Test 1 — STARK deploy + OE
- [ ] Test 3 — EIP-191 MetaMask OE
- [ ] Test 15 — Paymaster-sponsored OE through Chipi

Before recommending V8.1 for **production volume** (multi-user, multi-account):

- [ ] Test 11 — multi-owner setup via timelocked governance
- [ ] Test 13 — recovery initiate + cancel (the headline safety primitive)

Before recommending V8.1 for **institutional / multi-sig**:

- [ ] Test 12 — threshold envelope (2-of-3, mixed kinds)
- [ ] Test 13 finalize — full 7-day recovery cycle

Before recommending V8.1 for **validator / DAO** workflows:

- [ ] Test 10 — BLS12-381 OE

---

## Open questions / decisions

1. **Burn rate**: Test 1 cost 0.28 STRK. Smoking the remaining 13 tests is ~15-20 STRK total. Deployer balance is ~366 STRK after V8.1 declare. Plenty of runway, but worth tracking.
2. **Test 15 (paymaster) prerequisite**: requires a Chipi Pay API key for the deployer / a separate test account. Coordination with Chipi infra team.
3. **Test 13 finalize requires a 7-day wait** — start the clock as early as possible.
4. **Test 9 (Apple JWT)** requires a real Apple JWT — needs an Apple Developer account + a sign-in flow + a captured fixture. Not blocking, but coordinate with the Sign-in-with-Apple team owner.

---

Last updated: 2026-05-10. After running additional smoke tests, append the receipt block to the table in section "Tests 2-14" and tick the appropriate box in "What 'smoked' gates."
