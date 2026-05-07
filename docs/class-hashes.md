# V8 class hashes (declared on mainnet 2026-04-28)

All six V8 classes are **live on Starknet mainnet**. Hashes are
deterministic functions of the compiled Sierra, so the values below
were known and published before declare and verified byte-for-byte
post-declare.

Build environment: Scarb 2.14.0 / Cairo 2.14 / Sierra 1.7. Branch
`v8-robust` at the declare commit.

For declare-tx hashes, fees, and per-user cost estimates see
[`mainnet-deployment.md`](./mainnet-deployment.md).

## Production classes (V8)

| Contract                  | Class hash                                                                  | Role                                                     |
|---------------------------|-----------------------------------------------------------------------------|----------------------------------------------------------|
| `ShhhAccount` V8.1        | `0x01e7f69e3c22c5a209c24fcd4c31683f7cf2f1850cd0037635bd582c93f363b5`        | V8 account, audit-closed (2026-05-07 self-review). **Use this for new deploys.** |
| `ShhhAccount` V8.0        | `0x01d6e475526c1f0dddafe47f944efa52cd1d8af273771c4bf171aeb65919eae3`        | V8.0 account (declared 2026-04-28). **Deprecated — vulnerable to C-1 + H-1, see audits/2026-05-07.** Existing instances should rotate to V8.1. |
| `StarkVerifier`           | `0x06e671d2c70cf6d28ad18de864b82ffcbc60251b4dbcdb630ec17d4e1e43729b`        | STARK-curve owner signer                                 |
| `Ed25519Verifier`         | `0x004f075cb1dbbafde78faaa037824cc327e3a038ecd4ff7b8e2aa4ef039b1774`        | Ed25519 owner signer (Phantom / Solana) via Garaga       |
| `Secp256k1Verifier`       | `0x0473d8215659c5e91a8431557618f6664f698d16ba300d8d626027011391d8c6`        | Raw secp256k1 owner signer (programmatic / hardware)     |
| `EIP191Secp256k1Verifier` | `0x025c6a15e84aae7a999b449b08dc37da5071319eb09eec935161090148821c7f`        | EIP-191 `personal_sign` — MetaMask, Rabby, every EVM wallet |
| `EIP712Secp256k1Verifier` | `0x0729a2303c20fb3ba8994809b9ae923301c7489a069ae7401fb13a55c9184b2b`        | EIP-712 typed-data — MetaMask `eth_signTypedData_v4` structured popup |
| `P256Verifier`            | `0x029693329bb6f061e15c470ce2b169120cacfab47af024897b5588026c857810`        | Raw P-256 owner signer (PIV / eIDAS / DeviceCheck)       |
| `WebAuthnP256Verifier`    | `0x078fd4ce33370699f44c221191ce0d8b7ccfccff77297f798dc7948b4201b9f4`        | Full WebAuthn envelope (passkeys / Face ID / Touch ID)   |
| `JwtES256AppleVerifier`   | `0x06da4abb7fec87a9844d4a128b40621f282f694f56b108de76137b5174266ef8`        | "Sign in with Apple" — single-tenant (Apple key per user) |
| `JwtES256AppleSubVerifier`| `0x034bfab90a072ea8717379ad50185692378a5048a2105c2928da3777ee09a316`        | "Sign in with Apple" — multi-tenant (one Apple key, many users; sub-bound) |
| `Bls12_381MinSigVerifier` | `0x052a0625cffd197b6aeb0de4806e16605d95d6bf0229efbc45b96a38e41b513d`        | BLS12-381 min-sig-size (drand DST) — validator multisigs, DAO keys, backend signers |

## Legacy (V7, pre-patch — already on mainnet)

| Contract         | Class hash (mainnet, declared 2026-02)                                    | Notes                              |
|------------------|---------------------------------------------------------------------------|------------------------------------|
| `ShhhWallet` V7  | `0x2e599a0939f268c70acab242411225ddeefd7f3978e40dcb7c397ca39a9a13`         | Single-owner Ed25519-only. Retained on mainnet for existing users; superseded by V8 for new deploys. |
| `ShhhWallet` V7-patched | `0x0283ae3cf126c1423674298680ca3669949da935504ba78992fc6b32f000233c` | Audit-fix-in-place build in this branch. **Not declared on mainnet** — kept in-repo for regression tests and for audit cross-reference. |

## Deploy status

**Twelve V8 classes declared on Starknet mainnet.** Six on 2026-04-28
(initial V8 set); on 2026-05-05: `EIP191Secp256k1Verifier`,
`EIP712Secp256k1Verifier` (MetaMask `personal_sign` and
`eth_signTypedData_v4`), `JwtES256AppleVerifier` (Sign in with Apple,
single-tenant), and `JwtES256AppleSubVerifier` (Sign in with Apple,
multi-tenant with sub binding); on 2026-05-06:
`Bls12_381MinSigVerifier` (BLS12-381 min-sig-size, drand DST); on
2026-05-07: `ShhhAccount` **V8.1** (audit-closed against the
2026-05-07 self-review — C-1, H-1, H-2, H-3, M-1 partial, M-2, M-3,
L-1). V8.0 stays declared for existing users but is deprecated for
new deploys and should be rotated to V8.1.
Declarer: `0x64b1cf9c492b9ea333db7d4a2836feeee31cd1e2720f43b22732873122d433e`.
Total declare cost: 236.47 STRK across the twelve classes.

Phase 13 + 14 audits are now post-launch hardening rather than
pre-launch gating. If a finding requires a redeploy, V8.1 = new class
hash + opt-in migration (existing V8 wallets keep working).

## How to reproduce

```bash
cd shhh-wallet-cairo
git checkout v8-robust
scarb build
for c in ShhhAccount StarkVerifier Ed25519Verifier Secp256k1Verifier \
         P256Verifier WebAuthnP256Verifier; do
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
