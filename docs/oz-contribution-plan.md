# OpenZeppelin Cairo Contracts — V8 Contribution Plan

> Phase 12 of the V8 track. Upstreams the four verifier classes + three reusable components from `haycarlitos/shhh-wallet-cairo@6c30576` into `OpenZeppelin/cairo-contracts` so the whole Starknet account ecosystem gets pluggable signers, multi-owner storage, timelocked governance, and guardian recovery as drop-in OZ modules.

## Goal

Every Starknet account framework (Argent, Braavos, Cartridge, Clave, Chipi, Shhh) ends up implementing the same four signer kinds + three account extensions in their own style. Landing a canonical OZ module:

- Removes audit surface duplication across teams (one audited implementation, reused)
- Gives the Pluggable Signer SNIP a reference that pre-dates wallets needing to adopt it
- Positions V8 as the "standard-OZ-account-pattern" Cairo codebase rather than a bespoke fork

## Scope — what ships to OZ

### `src/account/verifiers/` — new directory

| V8 path | OZ target | Notes |
|---|---|---|
| `src/signer/interface.cairo` | `src/account/verifiers/interface.cairo` | `ISigner` trait + kind-tag registry (Tier 1 + Tier 2) |
| `src/signer/stark/verifier.cairo` | `src/account/verifiers/stark.cairo` | Wraps `core::ecdsa::check_ecdsa_signature` |
| `src/signer/ed25519/verifier.cairo` | `src/account/verifiers/ed25519.cairo` | Wraps Garaga `is_valid_eddsa_signature` — adds Garaga as optional feature dep |
| `src/signer/secp256k1/verifier.cairo` | `src/account/verifiers/secp256k1.cairo` | Wraps `starknet::secp256_trait::recover_public_key<Secp256k1Point>` |
| `src/signer/webauthn_p256/verifier.cairo` | `src/account/verifiers/webauthn_p256.cairo` | Wraps `is_valid_signature<Secp256r1Point>` |

Each verifier is a `#[starknet::contract]` implementing the shared `ISigner` trait. Intended usage: deploy once per kind as a library class, account contracts `library_call_syscall` into them by kind tag. OZ already has `account::AccountComponent` — these verifiers complement it rather than replace.

### `src/account/extensions/multi_owner/`

| V8 path | OZ target |
|---|---|
| `src/owner_set/interface.cairo` | `src/account/extensions/multi_owner/interface.cairo` |
| `src/owner_set/component.cairo` | `src/account/extensions/multi_owner/multi_owner.cairo` |

Provides: `OwnerRecord` struct, `IOwnerSet` trait, `OwnerSetComponent` with weighted threshold, role-based access (OWNER / GUARDIAN / RECOVERY_ONLY), tombstone-preserving removal. Same pattern as OZ's `AccessControlComponent` but account-scoped.

### `src/account/extensions/timelock/`

| V8 path | OZ target |
|---|---|
| `src/governance/pending_ops.cairo` | `src/account/extensions/timelock/pending_ops.cairo` |
| `src/governance/component.cairo` | `src/account/extensions/timelock/timelock.cairo` |

Provides: timelocked propose/execute/cancel state machine. Generic over op_kind + payload hash — any account can embed this for self-governance.

### `src/account/extensions/recovery/`

| V8 path | OZ target |
|---|---|
| `src/recovery/component.cairo` | `src/account/extensions/recovery/guardian_recovery.cairo` |

Provides: guardian-initiated recovery with owner-cancel window. Uses the timelock component as its state backend. Additive semantics (existing owners preserved).

### Session-key coexistence

V8's session_key + spending_policy components are ports of `chipi-pay/sessions-smart-contract` — OZ has a parallel SNIP-163 integration effort (Session Keys SNIP is already merged at [starknet-io/SNIPs#163](https://github.com/starknet-io/SNIPs/pull/163)). This PR does NOT duplicate that work; it references it in the extension docs and shows how pluggable-signer verifiers + session keys compose (signature-length routing in `execute_from_outside_v2`).

## What does NOT ship

- `src/account.cairo` (ShhhAccount) — Shhh-specific orchestration. OZ users compose the components themselves per their own account style.
- `src/wallet.cairo` (V7) — retained for reference in the Shhh repo.
- `src/migration/bootstrap_from_sessions.cairo` — Shhh/Chipi-specific migration path; not part of the general pattern.

## Style conversion required

OZ has specific conventions that the V8 code must match before upstreaming:

1. **Docstrings** — OZ uses full triple-slash docstrings with `# Arguments`, `# Returns`, `# Requirements` sections. V8 uses inline `//!` module docs. Needs rewrite.
2. **Event naming** — OZ uses snake_case_events with detailed key annotations. V8 matches; minor `#[key]` marker tweaks.
3. **Error prefixes** — OZ uses `Module::error_message` ASCII shortstrings. V8 uses `NAMESPACE: error` (e.g. `'M1: caller=0 rejected'`). Needs adapter.
4. **Test structure** — OZ splits tests per-file with explicit imports. V8 has fewer test files. Needs restructuring but no logic changes.
5. **Storage trait imports** — OZ uses `Map`, `Vec` helpers with specific import paths; V8 already uses these patterns correctly.
6. **Constructor vs Initializer** — OZ components expose `initializer()` instead of relying on constructor args. V8's components already use `initialize_primary` patterns; naming may need alignment.

Estimated style-conversion effort: **3–5 days** for an engineer familiar with OZ conventions.

## Deliverables per target file

For each file listed above, the PR must include:

- [x] Cairo source with OZ-style docstrings
- [x] Unit + integration tests under `tests/account/...`
- [x] Entry in `src/account/mod.cairo` module tree
- [x] Doc page under `docs/modules/pages/` (OZ uses AsciiDoc; needs conversion from markdown)
- [x] Example under `examples/` showing minimal embedding
- [x] CHANGELOG entry under `CHANGELOG.md`

## Test migration

V8 tests at `tests/` → OZ layout at `tests/account/verifiers/` and `tests/account/extensions/`. Fixture files (`tests/signer_*_fixture.cairo`) become snforge helpers under `tests/mocks/`. The mutation harness (`scripts/mutation-test.sh`) is Shhh-specific and stays in the Shhh repo — OZ has their own mutation approach via `cairo-fuzzer` in their CI.

## Dependencies to add to OZ

- `garaga = { git = "...", tag = "v1.0.1" }` — Ed25519 verifier. OZ might want this as an optional feature (the other verifiers have zero external crypto deps).

No other new deps — secp256k1 and P-256 verifiers use Starknet's built-in syscalls.

## Release path

1. Open draft PR with the file mapping + empty skeletons.
2. Port + style-convert one verifier at a time. Ed25519 first since it depends on Garaga which is the most controversial dep choice.
3. Port components (owner_set → multi_owner, governance → timelock, recovery → guardian_recovery).
4. Add examples showing a 4-verifier account using all four kinds.
5. CHANGELOG + docs pages.
6. Community review + revisions.
7. Merge into the next OZ cairo-contracts minor release.

Timeline: ~4–6 weeks elapsed (OZ review cadence is the long pole).

## PR relationship to the Pluggable Signer SNIP

This PR is the **reference implementation landing zone** for the [Pluggable Signer SNIP](../snip-draft-pluggable-signer.md). Order of operations:

1. Open SNIP PR on `starknet-io/SNIPs` → gathers community feedback on the interface.
2. Open OZ draft PR (this doc) → parallel so builders see "here's how to actually use it."
3. SNIP finalizes → OZ PR locks the trait shape + kind registry → merges.
4. Wallets adopt from OZ directly instead of forking Shhh.

## Authors

- Carlos Castillo ([@haycarlitos](https://github.com/haycarlitos)) — reference implementation, V8 track
- Omar Espejel ([@omarespejel](https://github.com/omarespejel)) — audit that catalyzed the SNIP + Session Keys SNIP co-author
