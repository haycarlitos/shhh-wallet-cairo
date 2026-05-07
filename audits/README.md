# Audits

Every external security review of this codebase — report alongside the
project's response — lives in this folder. New reports append to the
table below chronologically (oldest first).

| Date       | Auditor                                                       | Report                                                                   | Response                                                           | Findings                    |
|------------|---------------------------------------------------------------|--------------------------------------------------------------------------|--------------------------------------------------------------------|-----------------------------|
| 2026-04-13 | Henri ([@l-henri](https://github.com/l-henri)) — Shhh project collaborator, via Nethermind AuditAgent | [`2026-04-13-henri-nethermind-auditagent-scan.pdf`](./2026-04-13-henri-nethermind-auditagent-scan.pdf) | [`docs/audit-response-henri.md`](../docs/audit-response-henri.md) | 1 High + 1 Medium + 1 Info  |
| 2026-04-20 | Omar Espejel ([@omarespejel](https://github.com/omarespejel)) | [`2026-04-20-omar-espejel-codex-audit.md`](./2026-04-20-omar-espejel-codex-audit.md) | [`docs/audit-response-omar.md`](../docs/audit-response-omar.md)    | 1 Critical + 2 High + 4 Med + 1 Low + 3 Info |
| 2026-05-07 | Carlos Castillo ([@haycarlitos](https://github.com/haycarlitos)) — pre-Phase-13 self-review, AI-assisted (Claude Opus 4.7) | [`2026-05-07-claude-opus-pre-phase13-review.md`](./2026-05-07-claude-opus-pre-phase13-review.md) | TBD (see report's "Recommendations" — V8.1 declare planned)        | 1 Critical + 3 High + 3 Med + 1 Low + 6 Info |

## Status of findings

All 12 findings from Omar's audit + all 3 findings from Henri's scan
are closed on branch `v8-robust` with named regression tests. See the
response letters for the per-finding resolution table.

The 2026-05-07 self-review surfaced **8 new findings** against the V8 code
that landed after the Omar/Henri reviews (multi-role owner set, sessions-
wallet migration, BLS12-381 verifier, JWT sub-binding, library-call
dispatcher reentry surface). These are **open** as of 2026-05-07; they are
the gating list before Phase 13 firm sign-off. Tracking branch:
`audit/2026-05-07-pre-phase13-self-review`.

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

- **V8.1 declare** — close the 2026-05-07 self-review's Critical (C-1
  guardian role bypass) and Highs (H-1 migration front-running, H-2 JWT
  sub anchor, H-3 spending-policy reset) before handing the codebase to a
  Phase 13 firm. Existing V8.0 mainnet instances keep working; new deploys
  use V8.1.
- Phase 13 — independent human audit of the V8.1 scope. Candidates: Omar
  (round 2), Zellic, Nethermind, or OpenZeppelin. Budget + scope TBD. The
  2026-05-07 self-review is the recommended starting punch list.
- Phase 14 — second independent audit pass for recovery-math + session
  coexistence edge cases.
- Future reports will land here under the same filename pattern
  (`YYYY-MM-DD-<auditor>-<medium>.md|pdf`) next to a response letter
  in `../docs/`.
