# Response to Henri's 2026-04-13 Audit Scan

**To:** Henri (collaborator, `haycarlitos/shhh-wallet-cairo`)
**From:** Carlos Castillo (`@haycarlitos`)
**Re:** Nethermind AuditAgent scan report, 2026-04-13 ([archived in-repo](../audits/2026-04-13-henri-nethermind-auditagent-scan.pdf))
**Scanned commit range:** `70eeef3...f83ed1d4` (V7 pre-audit tree)

---

Hi Henri,

Thanks for running the AuditAgent scan on the V7 tree and surfacing the findings a week before Omar's deep review landed. Your scan came first chronologically and was the first external signal that the authorization layer had structural issues — that's a real contribution, not a tool output, because you reviewed the results, filtered the noise, and raised the ones worth acting on.

Per the Nethermind AuditAgent license I'm not claiming the repo is "audited by Nethermind"; the credit here is to you as the collaborator who ran the scan, reviewed the findings, and brought them to the project.

## Your findings → V8 resolutions

Your scan surfaced three findings. All three landed in the V8 remediation track (and all three were later corroborated by Omar's independent human review, which gave me strong confidence they were real rather than tooling artifacts).

| AuditAgent ID (2026-04-13) | Finding                                            | Overlap with Omar (2026-04-20) | V8 resolution                                                                                   | Status on `v8-robust` |
|----------------------------|----------------------------------------------------|--------------------------------|-------------------------------------------------------------------------------------------------|-----------------------|
| High                       | Unrestricted `__execute__` — anyone can call       | = Omar C-1                     | `__execute__` asserts `caller.is_zero() \|\| caller == self` and `tx_info.version >= 1`.         | **Fixed + tested**    |
| Medium                     | Non-atomic multicall — silent subcall failure      | = Omar H-1                     | `Err(_) => core::panic_with_felt252('H1: subcall failed')` in every multicall loop.             | **Fixed + tested**    |
| Info                       | Dead `UpgradeableComponent` (unused import)        | = Omar I-3                     | Fully removed from `src/wallet.cairo` imports, storage, events, and impls.                      | **Fixed + tested**    |

Every finding you raised has a named regression test on `v8-robust` at commit `6c30576`:
- `test_c1_external_execute_reverts`
- `test_h1_subcall_failure_reverts` (V8) + existing V7 reverting-call paths
- `test_i3_no_upgrade_entrypoint`

## Why your scan landing first mattered

Your three findings are a proper subset of Omar's twelve, and the overlap is the load-bearing part: C-1 / H-1 / I-3 are the findings that forced the V8 architectural rewrite rather than a V7 patch. The remaining nine findings Omar raised (H-2, M-1–M-4, L-1, I-1, I-2) are all refinements inside the same structural gap your scan pointed at: "the authorization layer isn't where it should be."

Chronologically:
- **2026-04-13** — Your AuditAgent scan lands. Three findings; the Critical-severity one (unrestricted `__execute__`) makes it clear a V7 patch alone isn't enough.
- **2026-04-20** — Omar's human review lands. Twelve findings, all consistent with yours, with the added depth on envelope/bounds/key-validation hygiene.
- **2026-04-21 → 2026-04-30** — V8 rewrite on `v8-robust`. All 12 (+ your 3) close with tested regressions.

Without your scan coming in first, I'd have waited on Omar's review and started V8 a week later. You compressed the timeline and gave me confidence the work was real before Omar's deeper review confirmed it.

## Credit in the V8 deliverables

You appear as a credited contributor in three places:

1. **V8 audit response** (`docs/audit-response-omar.md`) — the resolution table references your AuditAgent scan as the corroborating first signal for C-1 / H-1 / I-3.
2. **SNIP PR body** (`docs/snip-pr-body.md`) — Acknowledgments section credits you as first-scan contributor.
3. **OZ Cairo Contracts PR body** (`docs/oz-pr-body.md`) — Credits section.

If you want a different handle / name / wording in the credits, tell me and I'll update in the same PR before anything ships.

Thanks again for running the scan and flagging the structural issues early.

— Carlos
