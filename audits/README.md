# Audits

Every external security review of this codebase — report alongside the
project's response — lives in this folder. New reports append to the
table below chronologically (oldest first).

| Date       | Auditor                                                       | Report                                                                   | Response                                                           | Findings                    |
|------------|---------------------------------------------------------------|--------------------------------------------------------------------------|--------------------------------------------------------------------|-----------------------------|
| 2026-04-13 | Henri ([@l-henri](https://github.com/l-henri)) — Shhh project collaborator, via Nethermind AuditAgent | [`2026-04-13-henri-nethermind-auditagent-scan.pdf`](./2026-04-13-henri-nethermind-auditagent-scan.pdf) | [`docs/audit-response-henri.md`](../docs/audit-response-henri.md) | 1 High + 1 Medium + 1 Info  |
| 2026-04-20 | Omar Espejel ([@omarespejel](https://github.com/omarespejel)) | [`2026-04-20-omar-espejel-codex-audit.md`](./2026-04-20-omar-espejel-codex-audit.md) | [`docs/audit-response-omar.md`](../docs/audit-response-omar.md)    | 1 Critical + 2 High + 4 Med + 1 Low + 3 Info |
| 2026-05-07 | Carlos Castillo ([@haycarlitos](https://github.com/haycarlitos)) — pre-Phase-13 self-review, AI-assisted (Claude Opus 4.7) | [`2026-05-07-claude-opus-pre-phase13-review.md`](./2026-05-07-claude-opus-pre-phase13-review.md) | All Critical/High/Medium closed in V8.1 (mainnet redeclare 2026-05-07) | 1 Critical + 3 High + 3 Med + 1 Low + 6 Info |
| 2026-05-10 | Carlos Castillo — V8.2 audit-readiness self-review, AI-assisted (Claude Opus 4.7) | [`2026-05-10-claude-opus-v8-2-review.md`](./2026-05-10-claude-opus-v8-2-review.md) | All findings closed in V8.3 (mainnet redeclare 2026-05-11; account-class only, verifier hashes unchanged from V8.2) | 1 High + 1 Medium full closure + 2 Medium + 1 Low |
| 2026-05-12 | Carlos Castillo — V8.4 pre-merge audit, AI-assisted (Claude Opus 4.7), adversarial independent pass after author self-review | [`2026-05-12-claude-opus-v8-4-review.md`](./2026-05-12-claude-opus-v8-4-review.md) | 1 Critical + 1 Low closed in subsequent commits on `feat/v8-4-bootstrap-safety-and-guardian-oe` (PR #10); 3 Informational acknowledged | 1 Critical + 1 Low + 3 Info |
| 2026-05-14 | Carlos Castillo — V8.4 pre-declare re-review, AI-assisted (Claude Opus 4.7), adversarial independent pass against the audit-response delta after the 2026-05-12 Critical fix | [`2026-05-14-claude-opus-v8-4-pre-declare-audit.md`](./2026-05-14-claude-opus-v8-4-pre-declare-audit.md) | **Verdict: READY TO DECLARE.** INFO-2 docstring mitigation applied; INFO-1 deferred (auditor judged non-exploitable, can land in V8.5 if desired) | 2 Info |

## Status of findings

All 12 findings from Omar's audit + all 3 findings from Henri's scan
are closed on branch `v8-robust` with named regression tests. See the
response letters for the per-finding resolution table.

Four subsequent internal self-reviews — 2026-05-07 (pre-Phase-13),
2026-05-10 (V8.2 audit-readiness), 2026-05-12 (V8.4 pre-merge),
2026-05-14 (V8.4 pre-declare) — together surfaced **2 Critical + 4
High + 4 Medium + 1 Low + 8 Informational** findings against the V8
code that landed after the Omar/Henri reviews. All Critical / High /
Medium / Low findings are closed in the V8.1 / V8.2 / V8.3 / V8.4
redeclare cycles. Informational findings are tracked as code comments
and/or doc clarifications.

The 2026-05-12 V8.4 review was the first pre-merge adversarial review
on this codebase: an independent Claude Opus pass against a
self-authored PR found a Critical (`bootstrap_from_sessions_signed`
missing pubkey-binding gate) that the author missed in self-review.
The PoC test from the audit was committed alongside the fix to lock in
the gate.

The 2026-05-14 V8.4 pre-declare review was the second pre-merge
adversarial pass — specifically a re-review of the audit-response
delta from the 2026-05-12 cycle, gating the V8.4 mainnet declare on a
fresh "find what the last audit missed" pass. Verdict:
**READY TO DECLARE**. Two Informational findings raised; INFO-2
docstring mitigation applied at the same commit as the audit doc.

## Chronology

Henri's AuditAgent scan came first (2026-04-13) and surfaced the three
structural findings (unrestricted `__execute__`, non-atomic multicall,
dead upgrade component). Omar's Codex/Cairo review landed a week later
(2026-04-20), corroborated all three, and added nine additional
findings covering envelope hygiene, bounds, key-validation, and an
SRC-5 / SNIP-9 interface mismatch.

Together the two reviews triggered the V8 rewrite: a patch on V7 would
have closed Omar's list but left the structural gap Henri identified
wide open. V8 addresses both by making the authentication layer
pluggable + by giving every guard a named regression test.

## License note

The Henri scan was produced using Nethermind's AuditAgent tool. Per the
tool's license, this repository **does not claim** to be "audited by
Nethermind" — the credit is to Henri as the contributor who ran and
triaged the scan. See `../docs/audit-response-henri.md` for the full
attribution wording.

## What's next

- **V8.4 declare** — after PR #10 merges (currently open on
  `feat/v8-4-bootstrap-safety-and-guardian-oe`), declare the V8.4
  `ShhhAccount` class on mainnet. Verifier hashes unchanged from V8.2 →
  account-class redeclare only (~46 STRK). Existing V8.3 mainnet
  instances keep working at their frozen class; new deploys + sessions
  migrations use V8.4 (the V8.4 changes are the migration safety fix +
  guardian-OE recovery entry).
- Phase 13 — independent human audit. Candidates: Omar (round 2),
  Zellic, Nethermind, or OpenZeppelin Security Services. Budget + scope
  TBD. Recommended scope: V8.3 ShhhAccount + V8.2 verifier classes +
  V8.4 delta (the migration safety + guardian-OE work). Starting punch
  list: the 2026-05-12 V8.4 pre-merge review.
- Phase 14 — second independent audit pass for recovery-math + session
  coexistence edge cases.
- Future reports will land here under the same filename pattern
  (`YYYY-MM-DD-<auditor>-<medium>.md|pdf`) next to a response letter
  in `../docs/`.
