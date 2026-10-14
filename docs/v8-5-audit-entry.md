# V8.5 — single-owner envelopes must carry the threshold

> **Status**: V8.5 `ShhhAccount` declared on Starknet mainnet 2026-10-14. It replaces V8.4 for new deploys. The finding it fixes had **no affected wallets on mainnet** (see §4).

---

## 1. Pinned reference

| Item | Value |
|---|---|
| Repo | `haycarlitos/shhh-wallet-cairo` |
| Branch | `v8-robust` (V8.5 lands on top of the `StarkSnip12Verifier` merge, `a576995`) |
| Toolchain | Scarb `2.14.0`, Cairo `2.14`, Sierra `1.7`, snforge `0.59.0` |
| `snforge test` baseline | **292 passed, 0 failed, 0 ignored** (281 before V8.5 + 11 new) |

**V8.5 class hash (mainnet)**: `0x067828c8b82ac723b4adb141f9aa8975e296d8c11179d22bb8d7203b32abd96a`. Declared 2026-10-14, declare tx [`0x06c6a955…f788`](https://voyager.online/tx/0x06c6a955a10e6970849305b5eb84bf015358078d50814944388e52842451f788), block 16,375,744, fee 24.26 STRK, declared by `0x2937e79f543da6a3a6594bf3c94f63a3f1ccb9edcec7de71cd9f98aafcfea86`.

Only the account class changed. Verifier class hashes are unchanged.

---

## 2. The finding

**Severity**: Critical for any `ShhhAccount` V8.0–V8.4 whose threshold is above 1. No effect on wallets with threshold 1, which is every wallet at deploy and, per §4, every wallet on mainnet.

**What happened.** `execute_from_outside_v2` accepts two owner envelope shapes, chosen by the first signature felt:

- `V2_THRESHOLD`: N inner envelopes. The account verifies each one, rejects duplicate `owner_id`s, sums their weights and requires `sum >= threshold`.
- `V2_SNIP12`: one owner. The account checks the owner exists, is not revoked, has `ROLE_OWNER` (or is a guardian calling only `initiate_recovery`), matches the kind, and that the verifier accepts the signature.

The single-owner path never read the threshold. The signer chooses the envelope, so on a 2-of-3 wallet any one owner could submit a `V2_SNIP12` envelope and execute alone. The threshold was enforced only for signers who chose to be checked against it.

The SNIP draft described the same behaviour: its threshold aggregation steps applied "only for `V2_THRESHOLD`". The code matched the spec; the spec was wrong.

**What one owner could do on a threshold-2+ V8.4 wallet**, with one valid `V2_SNIP12` envelope:

- Move any asset immediately (transfers have no timelock).
- Register session keys, propose owner removals or a lower threshold, cancel other owners' pending operations, cancel recoveries.

**A second consequence, for multisig coordinators.** An off-chain multisig flow that collects one `V2_SNIP12` envelope per approver over the same OE hash (the shape every inner envelope has before it is wrapped in `V2_THRESHOLD`) holds, after the first approval, a signature that executes the OE on its own. The OE allows any caller, so whoever can read that one stored approval can submit it on-chain within the OE's validity window. This is limited to the proposed calls, but it makes the remaining approvals meaningless.

**What was not affected**:

- Threshold-1 wallets: one owner acting alone is the intended behaviour.
- Guardians: the role check held. A guardian can still only sign a single `initiate_recovery` naming itself.
- Session keys and spending caps: verified on a separate path; unchanged.
- `V2_THRESHOLD` envelopes: they always enforced the threshold.

---

## 3. The fix

`src/account.cairo`, single-owner `V2_SNIP12` branch of `execute_from_outside_v2`, after the role check:

```cairo
if owner.role == ROLE_OWNER {
    assert(
        owner.weight >= self.owners.threshold_value()
            || _is_single_cancel_recovery_call(
                outside_execution.calls, get_contract_address(), owner_id,
            ),
        'SHHH: below threshold',
    );
}
```

An owner below the threshold now signs through `V2_THRESHOLD`. An owner whose weight alone meets the threshold (for example weight 2 on a threshold-2 wallet) still signs alone; that is what weights are for.

Two single-call shapes stay open below the threshold, because both exist for the case where the threshold cannot be met:

| Call | Who | Why it stays open |
|---|---|---|
| `initiate_recovery(proposer, …)` | A guardian, with `proposer` equal to its own `owner_id` (V8.4 carve-out, unchanged) | Recovery is for when owners can't sign. Guardian weight never counts toward the threshold. The 7-day timelock and the owner veto bound it. |
| `cancel_recovery(owner_id)` | An owner, with `owner_id` equal to its own `owner_id`, as the only call, with no other calldata | The owner veto over a recovery. A single owner held it before V8.5. Removing it would let a hostile guardian take a wallet whose other owners lost their keys, because one remaining owner could no longer stop the recovery. |

`_is_single_cancel_recovery_call` mirrors `_is_single_initiate_recovery_call`: exactly one call, to the account itself, selector `cancel_recovery`, calldata exactly `[owner_id]`, and that `owner_id` equals the signer's. Bundling it with any other call, naming another owner, or adding calldata makes it a normal call that must meet the threshold.

**Accepted trade-off.** A single compromised owner key on a threshold-2+ wallet can still cancel a recovery, repeatedly. It cannot move funds or change the owner set. The alternative (no veto) trades that denial of service for a takeover path, which is worse.

**Unchanged**: storage layout, ABI, constructor, envelope formats, verifier interface, governance timelocks, recovery timelock, session-key path. SDKs integrate V8.5 exactly as V8.4; only the class hash differs.

---

## 4. Exposure on mainnet

Checked 2026-10-12 against Starknet mainnet with `starknet_getEvents`, no address filter, from block 7,000,000 (before the first V8 declare) to the head at the time (16,292,740):

| Event | Meaning | Count |
|---|---|---|
| `ThresholdChanged` | Some SHHH wallet raised or lowered its threshold | **0** |
| `ThresholdOutsideExecutionExecuted` | A `V2_THRESHOLD` envelope executed | **0** |

The same scan over recent blocks returned thousands of other SHHH events (`OwnerAdded`, `OutsideExecutionExecuted`, `VerifierClassAdded`), so the filter works.

Every `ShhhAccount` starts at threshold 1, whether deployed (constructor) or bootstrapped from a sessions wallet: both go through `OwnerSet::initialize_primary`, which writes 1. The only other write is `set_threshold`, which emits `ThresholdChanged`. **No wallet on mainnet has ever had a threshold above 1**, so no wallet was exposed.

---

## 5. What V8.4 wallets should do

V8.x has no `upgrade` selector. A V8.4 wallet stays V8.4.

- **Keep the threshold at 1.** At threshold 1 the finding has no effect.
- **Don't treat a V8.4 threshold as a multisig.** If you need N-of-M, deploy a V8.5 account at a new address and move the assets.
- **Coordinators** that relay SHHH outside executions should refuse `propose_set_threshold` / `execute_set_threshold` above 1 for wallets whose class is not V8.5 or later. Chipi's relay does this.

---

## 6. Tests

`tests/account_threshold_v8_5.cairo`. Fixture: owner A (id 0, weight 1), owner B (id 1, weight 1 or 2), guardian G (id 2), threshold 2.

| Test | Expects |
|---|---|
| `test_v8_5_single_owner_below_threshold_reverts` | `SHHH: below threshold` |
| `test_v8_5_one_approval_of_a_proposal_cannot_execute` | `SHHH: below threshold` |
| `test_v8_5_single_owner_cannot_propose_lower_threshold` | `SHHH: below threshold` |
| `test_v8_5_threshold_envelope_executes` | executes |
| `test_v8_5_owner_with_threshold_weight_executes_alone` | executes (B weight 2) |
| `test_v8_5_light_owner_next_to_heavy_owner_reverts` | `SHHH: below threshold` (A weight 1) |
| `test_v8_5_guardian_still_initiates_recovery_alone` | recovery active |
| `test_v8_5_single_owner_cancels_recovery` | recovery cleared |
| `test_v8_5_cancel_recovery_naming_another_owner_reverts` | `SHHH: below threshold` |
| `test_v8_5_cancel_recovery_bundled_with_a_call_reverts` | `SHHH: below threshold` |
| `test_v8_5_cancel_recovery_with_extra_calldata_reverts` | `SHHH: below threshold` |

Run against the V8.4 code, the seven tests that expect `SHHH: below threshold` fail (the bypass executes) and the four others pass. With V8.5 all eleven pass, and the full suite is 292/292.

---

## 7. Timeline

| Date | Event |
|---|---|
| 2026-10-12 | Found while integrating threshold signing for external wallets (Bramble) into the Chipi SDK; confirmed with an snforge probe; mainnet exposure scan (§4) |
| 2026-10-13 | Fix and tests written; Chipi's relay starts refusing thresholds above 1 on classes that don't enforce them |
| 2026-10-14 | V8.5 declared on mainnet; Chipi's relay allows thresholds above 1 on V8.5; source and this record published |

Found by the maintainer with AI assistance (Claude). Like the earlier self-reviews in [`audits/`](../audits/), this is not a third-party audit.

---

## 8. Build and reproduce

```bash
git clone https://github.com/haycarlitos/shhh-wallet-cairo
cd shhh-wallet-cairo
git checkout v8-robust
scarb --version     # expect 2.14.0
snforge --version   # expect 0.59.0
scarb build
snforge test        # expect 292 passed, 0 failed
sncast utils class-hash --contract-name ShhhAccount
# expect 0x067828c8b82ac723b4adb141f9aa8975e296d8c11179d22bb8d7203b32abd96a
```

If the hash differs, the toolchain drifted from the pinned versions.

---

## 9. Contact

- Maintainer: Carlos Castillo — `carlos@chipipay.com`
- Issues: `haycarlitos/shhh-wallet-cairo`, label `audit`
