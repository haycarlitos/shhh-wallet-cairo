# V8.4 helper-side correctness — lessons learned

> **Purpose**: a one-page artifact for the Phase 13/14 external auditor (and any future SDK-mirror author — Rust, Go, Swift) that captures the helper-side discipline already exercised during the V8.4 Cycle-1 integration push. The on-chain dispatcher cannot defend against a smoke runner that doesn't actually inspect the chain. The four bugs below are different surfaces of the same root pattern, and each one almost shipped a false-PASS into the audit trail.
>
> **Why this lives in the auditor packet**: the strongest single property of the V8.4 receipt corpus is "every receipt is independently re-verifiable on chain right now." That property is only meaningful if the helpers that *captured* the receipts were actually checking what they claimed. The discipline below is what makes that property load-bearing.
>
> **Date written**: 2026-05-28. Locked alongside the audit-entry doc + the 2026-05-28 smoke-test receipts.

---

## Unifying principle

> **Check the semantic of the signal, not its shape.**

Every bug below is one of two failure modes against that principle:
- **Shape check that's always satisfied** — testing whether a field *exists* or *has a printable form*, never whether it carries the meaning you wanted.
- **Stringified-form check that drifts** — comparing against a literal that's wrong under a different language binding, RPC version, or enum-printer.

The four discovered surfaces in this cycle:

| # | Lang | Surface | Mechanism | Indexed |
|---|---|---|---|---|
| 1 | TS | `execution_status === "REVERTED"` only | Missed Infura RPC 0.9 `is_reverted: true` boolean + `result[]` felt | chipi-pay/sdks PR #271 (2026-05-27) |
| 2 | Python | `hasattr(inv, "revert_reason")` | starknet-py exposes `Optional[str]` field on BOTH success and reverted dataclasses; attribute identically True | chipi-pay/sdks PR #279 (2026-05-28) |
| 3 | Python | `str(enum)` vs `"SUCCEEDED"` literal | `str(TransactionExecutionStatus.SUCCEEDED)` returns `"TransactionExecutionStatus.SUCCEEDED"`, not `"SUCCEEDED"` | chipi-pay/sdks PR #281 (2026-05-28) |
| 4 | TS+Python | Raw `now` timestamp on OE `execute_after` | Operator wall-clock skew vs sequencer block-time triggers audit M-1 (`SRC9: too early`) | chipi-pay/sdks PR #281 (2026-05-28) + chipi-pay/sdks PR earlier on TS side |

Detail follows. Each item is structured **Symptom → Mechanism → Fix → Pinned test → Grep target**.

---

## Item 1 — TS hasattr-helper miss (Infura RPC 0.9 shape)

- **Symptom**: B9 smoke runner reported `PASS` for production OE tx `0x1d1ee02e…0a55` (2026-05-27). On-chain trace showed the wallet REVERTED with `"SHHH: bad owner_id"`. The Chipi paymaster's outer transaction was `SUCCEEDED` because the forwarder caught the inner revert; the helper checked the outer status and never walked deeper.
- **Mechanism**: The TS `assertWalletCallsSucceeded` helper checked `c.execution_status === "REVERTED"` (RPC 0.8 shape) and `c.revert_reason` (RPC 0.7 shape) but never `c.is_reverted === true` (Infura RPC 0.9 boolean). On RPC 0.9 receipts, neither condition fired even when the call had reverted — the boolean is the canonical signal there and the felt-encoded reason lives in `result[]`. The helper had two stale shape-checks and no semantic check.
- **Fix**: Walk the trace by `contract_address` match against the wallet, and check **all three provider shapes** at every node: the `is_reverted` boolean, the `execution_status` string, and the `revert_reason` field. Surface the felt-encoded `result[]` reason for diagnostics. Reference implementation: `shhh:scripts/smoke-test-15.mjs::assertWalletCallSucceeded`.
- **Pinned test**: `chipi-pay/sdks:backend/src/__tests__/shhh-helpers.test.ts` — fixture `Infura is_reverted + result decode (the 2026-05-27 miss)`. The exact failing tx hash is the test's fixture.
- **Grep target for future SDK ports**:
  ```
  grep -nE 'execution_status\s*===\s*"(REVERTED|SUCCEEDED)"' <new-sdk-tree>
  grep -nE '\bhasattr\(' <new-sdk-tree>      # see Item 2
  grep -nE '\.revert_reason\b' <new-sdk-tree>  # check whether truthiness or presence
  ```
  Any hit on the first or third pattern is suspect: it's likely checking shape, not semantic.

---

## Item 2 — Python hasattr-equivalent miss

- **Symptom**: After the 2026-05-23 Python "Wave A closure" smoke claimed three honest-PASSes (STARK / Ed25519 / EIP-191), the on-chain receipts were explicitly `REVERTED|ACCEPTED_ON_L2` — the wallets weren't deployed at OE submission time, and the runner reported PASS anyway. Same failure family as Item 1, different language.
- **Mechanism**: The Python `_walk` helper used `hasattr(inv, "revert_reason")` to decide whether an invocation had reverted. starknet-py exposes `revert_reason: Optional[str]` as a field on BOTH `FunctionInvocation` (success) AND `RevertedFunctionInvocation` (failure) dataclasses — `hasattr` returns identically True for both. The walk short-circuited at the top-level invocation, returned the `None` value (which is falsy but never compared as such), and reported "no revert detected." Three for three at consecutive blocks confirmed the runner was deterministically wrong.
- **Fix**: Check **truthiness** of `revert_reason`, not presence: `if inv.revert_reason is not None`. Or — better — branch on the dataclass type itself: `isinstance(inv, RevertedFunctionInvocation)`. Always recurse into the `.calls` sub-tree even when the current node is a success; nested reverts under a successful outer must propagate.
- **Pinned test**: `chipi-pay/sdks:python/tests/test_smoke_helpers.py` — three fixtures: `top-level REVERTED with actionable error`, `nested REVERTED under successful outer`, `success tree returns sentinel`. The third Python tx from the 2026-05-23 batch is the canonical failing fixture.
- **Grep target for future SDK ports**:
  ```
  grep -nE '\bhasattr\([^,]+,\s*["\047]revert_reason["\047]\)' <new-sdk-tree>
  grep -nE '\bgetattr\([^,]+,\s*["\047]revert_reason["\047],\s*None\)' <new-sdk-tree>
  ```
  Any hit needs replacing with truthiness or `isinstance` checks. The same pattern applies to ANY `Optional[T]` field exposed on both success and failure variants of a tagged union in a binding language without sum-type enforcement.

---

## Item 3 — Python enum-vs-string false rejection

- **Symptom**: First `--apply` run of the fixed PR #279 runner against three real on-chain SUCCESS results produced three apparent failures. The new `_assert_top_level_succeeded` gate (added by PR #279 specifically to defend against Item 2) was rejecting good receipts.
- **Mechanism**: starknet-py returns `execution_status` as a `TransactionExecutionStatus` enum value, not a bare string. PR #279's gate compared `str(receipt.execution_status).upper() == "SUCCEEDED"`. Python's `str(enum)` returns the fully-qualified form `"TransactionExecutionStatus.SUCCEEDED"`. The upper-cased whole-string compare against the bare-name literal never matched. The mock-dict tests in `test_smoke_helpers.py` used plain strings (`{"execution_status": "SUCCEEDED"}`) and missed the regression entirely because they never exercised the real enum-typed return.
- **Fix**: Compare against the **suffix after the last dot** so both the bare-name and the qualified-enum forms work: `str(receipt.execution_status).rsplit('.', 1)[-1] == "SUCCEEDED"`. Two new pinned tests use the qualified-enum form so a future regression can't sneak past.
- **Pinned test**: `chipi-pay/sdks:python/tests/test_smoke_helpers.py` — fixtures `enum-qualified SUCCEEDED accepted`, `enum-qualified REVERTED rejected`. Both use the real `TransactionExecutionStatus.X` form, not the mock dict.
- **Grep target for future SDK ports**:
  ```
  grep -nE 'str\([^)]*(?:status|state|kind)[^)]*\)\s*==\s*["\047][A-Z_]+["\047]' <new-sdk-tree>
  ```
  Any equality compare between a stringified enum-typed value and a bare-name literal is suspect — the binding language's enum-printer is the load-bearing assumption. Two safe patterns: (a) suffix-after-dot, or (b) compare the enum value to its sibling: `status == TransactionExecutionStatus.SUCCEEDED`.

---

## Item 4 — Clock-skew buffer on OE `execute_after` (M-1 / M-2 surface)

- **Symptom**: First `--apply` of the Python re-smoke produced two `SRC9: too early` reverts on STARK + Ed25519. EIP-191 happened to land late enough to pass without the buffer. The runner had been correct in shape (it set `execute_after < execute_before`) but wrong in semantic (it used the operator's wall-clock `now` as the lower bound, with no slack for the operator-vs-sequencer drift).
- **Mechanism**: V8.4's `execute_from_outside_v2` enforces two audit-driven constraints on OE timestamps (`src/account.cairo:356, 365`):
  - **M-1**: `execute_after < get_block_timestamp()` — the OE must be ALREADY valid when the block lands; an `execute_after` set to "now" on the operator's machine will routinely lose its race against the sequencer's block timestamp.
  - **M-2**: `window <= MAX_ANY_CALLER_VALIDITY_SECONDS` (7200) — the validity window can't exceed 2 hours when `caller='ANY_CALLER'`.
  Naïve OE construction trips at least one of these. A previous Shhh-side smoke (`shhh:scripts/smoke-test-11.mjs`, 2026-05-18) tripped M-2 with `window = 7260`; the Python re-smoke tripped M-1 with `execute_after = now`.
- **Fix**: Subtract a fixed buffer (60s in both TS and Python; matches `OE_CLOCK_SKEW_BUFFER_SECONDS = 60` in `chipi-pay/sdks:backend/src/shhh/execute-paymaster-raw.ts`) from `execute_after`. Cap the window at `MAX_ANY_CALLER_VALIDITY_SECONDS - buffer`. Both constraints must be encoded as named constants in the SDK port, not as inline arithmetic — the audit reviewer can grep for the constant to confirm both invariants hold.
- **Pinned test**: `chipi-pay/sdks:python/tests/test_smoke_helpers.py` — fixture `OE clock-skew buffer applied`. The original failing test transaction sequence is documented in PR #281's commit message.
- **Grep target for future SDK ports**:
  ```
  grep -nE 'execute_after\s*[:=]\s*(now|time\.time|Date\.now|datetime\.now)' <new-sdk-tree>
  grep -nE 'execute_before\s*[:=].*[0-9]{3,4}' <new-sdk-tree>  # bare numeric window
  ```
  Both patterns are suspect. The constants must be named, the buffer subtracted, the window capped — all three in named code, all three audit-grep-able.

---

## Why this matters for the audit

The Phase 13/14 audit scope is the on-chain V8.4 dispatcher + the 10 verifier classes. The helpers above are **off-chain** code, not in audit scope. So why surface them?

Because the **audit-packet receipt corpus** (the 13 confirmed mainnet executions through V8.4 dispatch documented in `docs/v8-3-smoke-tests.md`) is the strongest single evidence the auditor will use to validate that the on-chain dispatcher works under the SDK code paths customers will actually use. If the helpers that captured those receipts were broken in any of the four ways above, the receipts are not actually proof. They're paste-artifacts.

The discipline the four items above instill — and the cross-language regression tests that pin each fix — make the receipt corpus genuinely re-verifiable. Any third party can:
1. Take any of the 13 receipt tx hashes from `docs/v8-3-smoke-tests.md`.
2. Run `starknet_traceTransaction` against any compliant Starknet RPC.
3. Walk the trace by `contract_address` match against the documented wallet address.
4. Assert `is_reverted=false` AND `execution_status=SUCCEEDED` AND `revert_reason is None` at the wallet node.

That third-party-replayable property is what the helper discipline buys. The semantic-vs-shape principle is what made the discipline correct.

---

## Pattern signatures — consolidated grep list for any new SDK port

```bash
# Shape-check vs semantic-check (Items 1, 2)
grep -nE '\bhasattr\([^,]+,\s*["\047]revert_reason["\047]\)' <tree>
grep -nE '\bgetattr\([^,]+,\s*["\047]revert_reason["\047],\s*None\)' <tree>
grep -nE 'execution_status\s*===\s*"(REVERTED|SUCCEEDED)"' <tree>
grep -nE '\.revert_reason\b' <tree>  # verify truthiness check, not presence

# Stringified-enum drift (Item 3)
grep -nE 'str\([^)]*(?:status|state|kind)[^)]*\)\s*==\s*["\047][A-Z_]+["\047]' <tree>

# Clock-skew + window-cap (Item 4)
grep -nE 'execute_after\s*[:=]\s*(now|time\.time|Date\.now|datetime\.now)' <tree>
grep -nE 'execute_before\s*[:=].*[0-9]{3,4}' <tree>

# Receipt-status check at all
grep -nE '(receipt|tx).*\.execution_status' <tree>
```

A clean port will have:
- Named constants for both buffer (60s) and max-window (7200s).
- A typed `is_reverted_at_wallet(trace, wallet_address) -> bool` helper that walks the trace, matches by address, and checks both the boolean AND the string AND the truthy reason at the wallet node.
- A `assert_receipt_succeeded(receipt) -> None` helper that compares the enum-typed status to its sibling value, not to a string literal.
- Tests pinned with real-language enum forms (not mock dicts) for each.

---

## Cross-references

- **Audit entry doc**: [`docs/v8-4-audit-entry.md`](./v8-4-audit-entry.md) — pin commit `3975532` (tag `v8.4`), full scope + threat model.
- **Audit response letter**: [`docs/audit-response-2026-05-10.md`](./audit-response-2026-05-10.md) — canonical record of which audit findings closed at which commit, including M-1 (`SRC9: too early`) and M-2 (`window too long`) referenced by Item 4.
- **Mainnet smoke receipts**: [`docs/v8-3-smoke-tests.md`](./v8-3-smoke-tests.md) — the 13 confirmed mainnet executions whose helper-side discipline is documented here.
- **Reference implementations**:
  - TS `assertWalletCallSucceeded`: `shhh:scripts/smoke-test-15.mjs` (V8.4-tagged, mainnet-proven 2026-05-28).
  - Python `_walk` + `_assert_top_level_succeeded` (post-fix): chipi-pay/sdks PR #279 + PR #281.

---

## Contact

- Maintainer: Carlos Castillo — `carlos@chipipay.com`
- Audit packet bundling: when Phase 13/14 starts, this doc ships alongside the audit-entry doc as part of the auditor's day-zero artifact set.
