# V8 class hashes (live on Starknet mainnet)

V8 launched 2026-04-28 with six classes. As of 2026-05-15 there are
**15 V8.x classes** declared on mainnet:

- **11 active classes** for new deploys (V8.4 `ShhhAccount` + 10 V8.2 verifier classes).
- **4 deprecated `ShhhAccount` classes** (V8.0 / V8.1 / V8.2 / V8.3) retained for legacy recognition; they have unfixed audit findings or known limitations from earlier review cycles and must not be used for new deploys.

Hashes are deterministic functions of the compiled Sierra, so the
values in the tables below were known and published before declare
and verified byte-for-byte post-declare.

Build environment: Scarb 2.14.0 / Cairo 2.14 / Sierra 1.7. Branch
`v8-robust` at the most recent merge commit.

For declare-tx hashes, fees, and per-user cost estimates see
[`mainnet-deployment.md`](./mainnet-deployment.md). Audit-trail
docs: `audits/2026-05-07-claude-opus-pre-phase13-review.md`,
`audits/2026-05-10-claude-opus-v8-2-review.md`,
`audits/2026-05-12-claude-opus-v8-4-review.md`,
`audits/2026-05-14-claude-opus-v8-4-pre-declare-audit.md`,
`docs/audit-response-2026-05-10.md`.

## Production classes (V8.4 — current; declared 2026-05-15)

V8.4 closes two architectural gaps from the 2026-05-12 SDK-integration
review (stranded-bootstrap recovery + guardian-OE `initiate_recovery`)
plus the Critical from the 2026-05-12 V8.4 pre-merge audit
(`bootstrap_from_sessions_signed` missing pubkey-binding gate) and the
Low (calldata-length floor on `_is_single_initiate_recovery_call`).
The 2026-05-14 pre-declare re-review verdict was **READY TO DECLARE**.
Only the account contract changed — verifier class hashes stay at
V8.2 values.

| Contract                  | Class hash                                                                  | Role                                                     |
|---------------------------|-----------------------------------------------------------------------------|----------------------------------------------------------|
| `ShhhAccount` V8.4        | `0x075dfb396145926bffa6beb659897f46cc082a50b211d80871cff7f1038fa58a`        | V8 account — V8.3 + stranded-bootstrap recovery + guardian-OE `initiate_recovery` + 2026-05-12 audit C-1 closeout. **Use this for new deploys.** |
| `ShhhAccount` V8.3        | `0x03bc539295abd3e59bd9ea799d12fe3331748d484bc77bff45b302b1636a87d9`        | V8.3 (no stranded-bootstrap recovery primitive; no guardian-OE `initiate_recovery`). Deprecated 2026-05-15. |
| `ShhhAccount` V8.2        | `0x02a0b719d79b063cafd45a32d34c98b28f220baa678611db63790150a361a062`        | V8.2 (audit M-1 partial in OE paths only). Deprecated 2026-05-11. |
| `StarkVerifier`           | `0x00d09209b2da9d49fc805ba26380ba4ce25aa641116c10eb178e1051a71dbf68`        | STARK-curve owner signer (V8.2)                          |
| `Ed25519Verifier`         | `0x030a7dfc03e59cef6e41699e734abd2df53ce393a052221c02c6e07665949f74`        | Ed25519 owner signer (Phantom / Solana) (V8.2)           |
| `Secp256k1Verifier`       | `0x03e81667a46bd5287e09a9600fa98d28fdc477735f2689f5f4e8e95f37b67b74`        | Raw secp256k1 owner signer (V8.2)                        |
| `EIP191Secp256k1Verifier` | `0x03a75997862059c36cb8e204fb3027eb6d1fdf933488d42c2db4528118d084e6`        | EIP-191 `personal_sign` — MetaMask, Rabby (V8.2)         |
| `EIP712Secp256k1Verifier` | `0x072a3f77e8c28bfea2ade91ec3fb83b6290169d1ed8c1b2396704231841c6474`        | EIP-712 typed-data (V8.2)                                |
| `P256Verifier`            | `0x01b600709af54c8838e5f18ddad3a26feeb47cb124c239f55a0f1b7a780e2d8a`        | Raw P-256 owner signer (V8.2)                            |
| `WebAuthnP256Verifier`    | `0x074f6efd2af9025cd8cab41a4565bc73b6ef097214c31352838fcdbac0a44657`        | WebAuthn envelope (passkeys / Face ID) (V8.2)            |
| `JwtES256AppleVerifier`   | `0x002efce875fa3e73e04d825d8ebade53e188cc995dfe0c55a6a2f7fa6c59f497`        | Sign in with Apple — single-tenant (V8.2)                |
| `JwtES256AppleSubVerifier`| `0x06b67762218a25fdd28e25b063480893a5cef9cdeecbc663e32d444d5734c471`        | Sign in with Apple — multi-tenant (sub-bound) (V8.2)     |
| `Bls12_381MinSigVerifier` | `0x02623721e74a9ad3e0ba639065f5631a09bf900913de6ab21ea6984973cd2cd1`        | BLS12-381 min-sig-size (drand DST) (V8.2)                |

## Deprecated V8.0 / V8.1 classes (kept declared for legacy recognition)

V8.1 verifier classes lack `validate_pubkey` and are incompatible with
V8.2 ShhhAccount. The V8.0 / V8.1 ShhhAccount stay declared so legacy
instances remain readable; **new deploys MUST use V8.2.**

| Contract                  | V8.1 class hash (deprecated)                                                 |
|---------------------------|------------------------------------------------------------------------------|
| `ShhhAccount` V8.1        | `0x01e7f69e3c22c5a209c24fcd4c31683f7cf2f1850cd0037635bd582c93f363b5`         |
| `ShhhAccount` V8.0        | `0x01d6e475526c1f0dddafe47f944efa52cd1d8af273771c4bf171aeb65919eae3`         |
| `StarkVerifier` V8.1      | `0x06e671d2c70cf6d28ad18de864b82ffcbc60251b4dbcdb630ec17d4e1e43729b`         |
| `Ed25519Verifier` V8.1    | `0x004f075cb1dbbafde78faaa037824cc327e3a038ecd4ff7b8e2aa4ef039b1774`         |
| `Secp256k1Verifier` V8.1  | `0x0473d8215659c5e91a8431557618f6664f698d16ba300d8d626027011391d8c6`         |
| `EIP191Secp256k1Verifier` V8.1 | `0x025c6a15e84aae7a999b449b08dc37da5071319eb09eec935161090148821c7f`    |
| `EIP712Secp256k1Verifier` V8.1 | `0x0729a2303c20fb3ba8994809b9ae923301c7489a069ae7401fb13a55c9184b2b`    |
| `P256Verifier` V8.1       | `0x029693329bb6f061e15c470ce2b169120cacfab47af024897b5588026c857810`         |
| `WebAuthnP256Verifier` V8.1 | `0x078fd4ce33370699f44c221191ce0d8b7ccfccff77297f798dc7948b4201b9f4`       |
| `JwtES256AppleVerifier` V8.1 | `0x06da4abb7fec87a9844d4a128b40621f282f694f56b108de76137b5174266ef8`      |
| `JwtES256AppleSubVerifier` V8.1 | `0x034bfab90a072ea8717379ad50185692378a5048a2105c2928da3777ee09a316`   |
| `Bls12_381MinSigVerifier` V8.1 | `0x052a0625cffd197b6aeb0de4806e16605d95d6bf0229efbc45b96a38e41b513d`    |

## Legacy (V7, pre-patch — already on mainnet)

| Contract         | Class hash (mainnet, declared 2026-02)                                    | Notes                              |
|------------------|---------------------------------------------------------------------------|------------------------------------|
| `ShhhWallet` V7  | `0x2e599a0939f268c70acab242411225ddeefd7f3978e40dcb7c397ca39a9a13`         | Single-owner Ed25519-only. Retained on mainnet for existing users; superseded by V8 for new deploys. |
| `ShhhWallet` V7-patched | `0x0283ae3cf126c1423674298680ca3669949da935504ba78992fc6b32f000233c` | Audit-fix-in-place build in this branch. **Not declared on mainnet** — kept in-repo for regression tests and for audit cross-reference. |

## Deploy status

**15 V8.x classes declared on Starknet mainnet** by deployer
`0x64b1cf9c492b9ea333db7d4a2836feeee31cd1e2720f43b22732873122d433e`:

- 2026-04-28 — initial 6: V8.0 `ShhhAccount` + StarkVerifier +
  Ed25519Verifier + Secp256k1Verifier + P256Verifier +
  WebAuthnP256Verifier.
- 2026-05-05 — +4: `EIP191Secp256k1Verifier`,
  `EIP712Secp256k1Verifier`, `JwtES256AppleVerifier`,
  `JwtES256AppleSubVerifier`.
- 2026-05-06 — +1: `Bls12_381MinSigVerifier`.
- 2026-05-07 — V8.1 `ShhhAccount` redeclare (audit-closed against
  2026-05-07 self-review: C-1, H-1, H-2, H-3, M-1 partial, M-2,
  M-3, L-1).
- 2026-05-10 — V8.2 redeclare of ShhhAccount + all 10 verifier
  classes (full M-1 closure via `validate_pubkey` on the `ISigner`
  trait; trait shape changed → fresh hashes for every class).
- 2026-05-11 — V8.3 `ShhhAccount` redeclare (audit-closed against
  2026-05-10 V8.2 self-review: H-1 finalize_recovery, M-1
  inside_verifier symmetry, M-2 bootstrap_from_sessions, M-3 evil
  verifier negative tests). Verifier class hashes unchanged from
  V8.2.
- 2026-05-15 — V8.4 `ShhhAccount` redeclare (audit-closed against
  2026-05-12 V8.4 pre-merge review + 2026-05-14 pre-declare
  re-review). Adds `bootstrap_from_sessions_signed` for stranded-
  state recovery (audit C-1) + guardian-OE carve-out for
  `initiate_recovery` (V8.3 architectural gap) + L-1 calldata-
  length floor + `LEGACY_OZ_ACCOUNT_PUBKEY_SLOT` const. Verifier
  class hashes unchanged from V8.2. Declare tx
  `0x0737570e0430bed8e21c05bcb88a6f649f99d8a5f3d36dd0350a0dd172ea0dfd`
  in block 9787252, actual cost 43.67 STRK.

Total declare cost: ~327 STRK across the 15 classes (283 through V8.3 + 43.67 V8.4).

V8.0 / V8.1 / V8.2 / V8.3 `ShhhAccount` classes stay declared for
legacy recognition but are deprecated for new deploys. V8.1 verifier
class hashes are incompatible with V8.2+ ShhhAccount because they
lack `validate_pubkey`. Existing V8.x instances do not have a self-
upgrade path — the only path from V8.0 / V8.1 / V8.2 / V8.3 to V8.4
is to deploy a fresh V8.4 account at a new address and migrate funds
manually.

Phase 13 + 14 external audits are scheduled against the V8.4 commit
(post-merge `v8-robust` HEAD after PR #11). If an external audit
finding requires a redeploy, V8.5 = new class hash + opt-in new-
address deploy (existing V8.x wallets keep working at their current
class).

## How to reproduce

```bash
cd shhh-wallet-cairo
git checkout v8-robust
scarb build
for c in ShhhAccount StarkVerifier Ed25519Verifier Secp256k1Verifier \
         EIP191Secp256k1Verifier EIP712Secp256k1Verifier P256Verifier \
         WebAuthnP256Verifier JwtES256AppleVerifier \
         JwtES256AppleSubVerifier Bls12_381MinSigVerifier; do
  sncast utils class-hash --contract-name "$c"
done
```

The output MUST match the table above byte-for-byte; if it doesn't,
the local Scarb / Cairo / Sierra versions drifted from the pinned
values in `Scarb.toml` (`scarb 2.14.0` / `snforge_std v0.59.0`).

## Re-declare (only if a future V8.x is published)

The recipe used 2026-04-28:

```bash
sncast --account deployer_oz \
       declare --contract-name ShhhAccount \
       --url https://starknet-rpc.publicnode.com
```

(Run once per class. Each declare is a one-time tx per class hash —
subsequent accounts deploy *instances* via `deploy_syscall`, which does
not require re-declaring.)
