# Audits

Every external security review of this codebase — report alongside the
project's response — lives in this folder. New reports append to the
table below chronologically (oldest first).

| Date       | Auditor                                                       | Report                                                                   | Response                                                           | Findings                    |
|------------|---------------------------------------------------------------|--------------------------------------------------------------------------|--------------------------------------------------------------------|-----------------------------|
| 2026-04-13 | Henri ([@l-henri](https://github.com/l-henri)) — Shhh project collaborator, via Nethermind AuditAgent | [`2026-04-13-henri-nethermind-auditagent-scan.pdf`](./2026-04-13-henri-nethermind-auditagent-scan.pdf) | [`docs/audit-response-henri.md`](../docs/audit-response-henri.md) | 1 High + 1 Medium + 1 Info  |
| 2026-04-20 | Omar Espejel ([@omarespejel](https://github.com/omarespejel)) | [`2026-04-20-omar-espejel-codex-audit.md`](./2026-04-20-omar-espejel-codex-audit.md) | [`docs/audit-response-omar.md`](../docs/audit-response-omar.md)    | 1 Critical + 2 High + 4 Med + 1 Low + 3 Info |

## Status of findings

All 12 findings from Omar's audit + all 3 findings from Henri's scan
are closed on branch `v8-robust` with named regression tests. See the
response letters for the per-finding resolution table.

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

- Phase 13 — independent human audit of the V8 scope (~10k new lines
  since the 2026-04 reviews). Candidates: Omar (round 2), Zellic,
  Nethermind, or OpenZeppelin. Budget + scope TBD.
- Phase 14 — second independent audit pass for recovery-math + session
  coexistence edge cases.
- Both future reports will land here under the same filename pattern
  (`YYYY-MM-DD-<auditor>-<medium>.md|pdf`) next to a response letter
  in `../docs/`.
