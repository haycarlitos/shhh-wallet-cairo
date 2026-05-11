# SNIP-108 publication process

> The mechanical checklist for submitting `docs/snip-draft-pluggable-signer.md` to `starknet-io/SNIPs`. Compiled from the [SNIP-1 governance process](https://github.com/starknet-io/SNIPs/blob/main/SNIPS/snip-1.md) and the Session Keys SNIP precedent ([starknet-io/SNIPs#163](https://github.com/starknet-io/SNIPs/pull/163), merged 2026-03-03).

---

## 0. Prerequisites (do these once, before the first PR)

- [ ] GitHub account with a public SSH key on `github.com`.
- [ ] `community.starknet.io` forum account (used for the `discussions-to` thread).
- [ ] Read [SNIP-1](https://github.com/starknet-io/SNIPs/blob/main/SNIPS/snip-1.md) end-to-end. It's the meta-SNIP and the editors quote it back at you when reviewing.
- [ ] Read the merged session-keys SNIP PR ([#163](https://github.com/starknet-io/SNIPs/pull/163)) — the closest precedent for the kind of SNIP we're submitting (component-style account extension authored by Chipi + Omar).
- [ ] PR #6 merged into `v8-robust` so the `reference-impl` link in the SNIP draft front-matter resolves to a clean tree.

## 1. Open the forum discussion thread (REQUIRED before opening the PR)

SNIP-1 explicitly requires a `discussions-to` URL in the front-matter, and editors will close-on-sight a PR without one.

1. Go to https://community.starknet.io and sign in.
2. Create a new topic in the **"Core devs / Standards"** category (the same one the sessions SNIP used).
3. Title: `[SNIP discussion] Pluggable Signer Interface for Smart Accounts`.
4. Body (template):
   ```
   This thread is the discussion-to anchor for the upcoming SNIP that
   standardizes a curve-agnostic signer interface for Starknet smart
   accounts.

   - Draft text: <link to the SNIP draft on the v8-robust branch>
   - Reference implementation: haycarlitos/shhh-wallet-cairo @ af45e95
     (V8.3 ShhhAccount declared on mainnet 2026-05-11)
   - Companion SNIP: Session Keys SNIP (PR #163), merged Draft on 2026-03-03

   tl;dr — V7-style "one account class per curve" doesn't scale.
   This SNIP defines a single ISigner trait + canonical kind-tag
   registry + tagged signature envelope so one audited account class
   can verify signatures from Phantom, MetaMask, passkeys, hardware
   wallets, OAuth providers, and Starknet-native keys.

   Feedback welcome on:
   - The three-method trait shape (verify / kind / validate_pubkey)
   - Tier-2 envelope variants (especially JWT_ES256_APPLE_SUB)
   - Library-call dispatch vs. component embedding (Part F)
   - The verifier-class governance attack surface (Security Considerations #7, #8)
   ```
5. Save the topic URL — that's what goes into the SNIP front-matter `discussions-to` field.

The forum thread is permanent. Re-use the same thread for the entire SNIP lifecycle (Draft → Review → Final); don't open a new one per revision.

## 2. Fork and prepare the PR

```bash
# Fork starknet-io/SNIPs to haycarlitos/SNIPs via the GitHub UI, then:
git clone git@github.com:haycarlitos/SNIPs.git
cd SNIPs
git checkout -b snip-pluggable-signer

# Copy the draft from the wallet repo.
cp ~/Documents/shhh-wallet-cairo/docs/snip-draft-pluggable-signer.md SNIPS/snip-x.md

# Edit SNIPS/snip-x.md:
# - front-matter: status: Draft (keep as Draft until editor assigns a number)
# - front-matter: discussions-to: <forum URL from step 1>
# - confirm the reference-impl URL points to v8-robust @ <merge commit of PR #6>
```

Editor convention: name the file `snip-x.md` until they assign a number, then rename to `snip-NNN-pluggable-signer.md` in a follow-up commit. The session-keys SNIP currently sits at `snip-x.md` for the same reason — it's a pre-allocation, not a permanent name.

## 3. Open the PR against `starknet-io/SNIPs`

```bash
git add SNIPS/snip-x.md
git commit -m "Add SNIP draft: Pluggable Signer Interface for Smart Accounts"
git push origin snip-pluggable-signer
gh pr create \
  --repo starknet-io/SNIPs \
  --base main \
  --head haycarlitos:snip-pluggable-signer \
  --title "Add SNIP draft: Pluggable Signer Interface for Smart Accounts" \
  --body-file pr-body.md
```

PR body template (`pr-body.md`):

```markdown
## Summary

Proposes a curve-agnostic signer trait, a canonical kind-tag registry,
and a tagged signature envelope so one Starknet smart-account class can
verify signatures from Phantom (Ed25519), MetaMask (secp256k1 / EIP-191
/ EIP-712), passkeys (WebAuthn P-256), hardware wallets (P-256), OAuth
providers (JWT-ES256), email (DKIM-RSA), validator keys (BLS12-381),
and native STARK wallets — without forking the account contract per
curve.

## Motivation

This SNIP was motivated by the April 2026 security review of the Shhh
wallet (audit-2026-04-20, Omar Espejel / Codex), which found three
issues that converged on the same root cause: there is no standard way
to say "this account uses curve X for owner signatures." See the
Motivation section of the draft for the full chain.

## Reference implementation

- Repo: haycarlitos/shhh-wallet-cairo
- Branch: v8-robust
- Commit: af45e95 (V8.3, declared on Starknet mainnet 2026-05-11)
- Test suite: 242 passing, 0 failing, 0 ignored on snforge 0.59.0
- Mainnet classes: 14 V8.x classes declared, ~283 STRK cumulative cost

## Discussion

Forum thread: <URL from step 1>

## Authors

- Carlos Castillo (@haycarlitos) — Chipi Pay, Shhh wallet
- Omar Espejel (@omarespejel) — co-author, audit reviewer

## Status

Draft.
```

## 4. Iterate with editors

SNIP editors (currently Henri-Lieutaud, Joshc, glihm, Stranger6667 among others) will leave review comments. Common first-pass requests:

| Likely editor request | Pre-emptive fix |
|---|---|
| "Add a Specification section with explicit MUST/MAY language" | Already done — RFC 2119 paragraph + numbered MUSTs throughout Part A–F |
| "Define every kind tag's exact byte layout" | Already done — Part B Tier 1 + Tier 2 tables, Part C kind-specific payload layouts |
| "Reference the SRC-5 interface ID with derivation" | Already done — `starknet_keccak("ISigner_V1") = 0x94c5a76…` |
| "Backwards-compatibility statement" | Already done — Backwards Compatibility section |
| "Security considerations" | Already done — 8 numbered items |
| "Discussions-to thread URL" | Set during step 1 |
| "Reference implementation must be on a public repo with a stable commit" | Pinned at `af45e95` after PR #6 merges |
| "Test cases section" | Already done — Test Cases section |

Editors typically merge in `Draft` status once these are present. The session-keys SNIP went through ~3 review rounds in 4 weeks.

## 5. Lifecycle after merge

| Status | When it moves there | Gating |
|---|---|---|
| `Draft` | First merge | Editor approval on formatting + completeness |
| `Review` | After ≥ 1 external implementation exists OR ≥ 1 independent audit | Demonstrate adoption beyond the author's repo |
| `Last Call` | Author requests it | 14-day final comment window |
| `Final` | After Last Call closes with no blocking objections | Editor consensus |
| `Stagnant` | 6 months without author activity | Auto-marked by editors |
| `Withdrawn` | Author abandons it | Author request |

For this SNIP, the realistic path:
- **Now → +4 weeks**: Draft merge (this PR).
- **+4 → +12 weeks**: External implementation work (OZ Cairo Contracts PR — a separate workstream documented as Phase 12 in `docs/shhh-v8-build-track.md`).
- **+12 → +20 weeks**: Phase 13 external audit (Omar / Zellic / Nethermind).
- **+20 → +24 weeks**: Move to `Review`.
- **+24 → +26 weeks**: Last Call → `Final`.

## 6. After the SNIP merges in Draft

- [ ] Open the OpenZeppelin Cairo Contracts PR porting `ISigner` + the per-kind verifier classes as reusable components under `account/verifiers/`. This is the second-implementation gate for moving the SNIP to `Review`.
- [ ] Add the SNIP number (assigned by editors) into:
  - `docs/snip-draft-pluggable-signer.md` (rename the file too: `docs/snip-108-pluggable-signer.md`).
  - The `reference-impl` URL on the merged SNIP if it's a `Final` redeclare cycle.
  - All in-repo references (search for "this SNIP" / "SNIP-X" / "the pluggable-signer SNIP").
- [ ] Publish a 1-page case study on the Chipi Pay blog / Shhh blog: "From audit finding to ecosystem SNIP in N weeks."
- [ ] Add the SNIP number to the AVNU paymaster overhead PR.

## 7. Things that will close-the-PR on first read (avoid these)

- Missing `discussions-to` (close on sight).
- Reference implementation linked to an uncommitted branch or a 404.
- Front-matter `status: Final` on first submission (must be `Draft`).
- File name `snip-pluggable-signer.md` without the `snip-x.md` placeholder convention.
- Author email/handle missing from front-matter.
- Title doesn't start with the SNIP shape it advertises (e.g., calling it "Pluggable Signer Standard" when the front-matter says `category: SRC` — keep them consistent).
- Editorialising motivation. Stick to what's broken and what's proposed; the editors politely strip out marketing language.

The current draft passes all of these. The only step still to do is step 1 (forum thread) before the PR can be opened.
