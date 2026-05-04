# V8 Mainnet Deployment

V8 ShhhAccount is **declared on Starknet mainnet**. Initial 6 classes
landed 2026-04-28; `EIP191Secp256k1Verifier` (MetaMask `personal_sign`)
followed 2026-05-05. This document records what was deployed, what it
cost, and what each user-facing operation will cost going forward.

## Class hashes (live on mainnet)

| Contract                  | Class hash                                                           | Voyager                                                                     |
|---------------------------|----------------------------------------------------------------------|-----------------------------------------------------------------------------|
| `ShhhAccount`             | `0x01d6e475526c1f0dddafe47f944efa52cd1d8af273771c4bf171aeb65919eae3` | [link](https://voyager.online/class/0x01d6e475526c1f0dddafe47f944efa52cd1d8af273771c4bf171aeb65919eae3) |
| `StarkVerifier`           | `0x06e671d2c70cf6d28ad18de864b82ffcbc60251b4dbcdb630ec17d4e1e43729b` | [link](https://voyager.online/class/0x06e671d2c70cf6d28ad18de864b82ffcbc60251b4dbcdb630ec17d4e1e43729b) |
| `Ed25519Verifier`         | `0x004f075cb1dbbafde78faaa037824cc327e3a038ecd4ff7b8e2aa4ef039b1774` | [link](https://voyager.online/class/0x004f075cb1dbbafde78faaa037824cc327e3a038ecd4ff7b8e2aa4ef039b1774) |
| `Secp256k1Verifier`       | `0x0473d8215659c5e91a8431557618f6664f698d16ba300d8d626027011391d8c6` | [link](https://voyager.online/class/0x0473d8215659c5e91a8431557618f6664f698d16ba300d8d626027011391d8c6) |
| `EIP191Secp256k1Verifier` | `0x025c6a15e84aae7a999b449b08dc37da5071319eb09eec935161090148821c7f` | [link](https://voyager.online/class/0x025c6a15e84aae7a999b449b08dc37da5071319eb09eec935161090148821c7f) |
| `P256Verifier`            | `0x029693329bb6f061e15c470ce2b169120cacfab47af024897b5588026c857810` | [link](https://voyager.online/class/0x029693329bb6f061e15c470ce2b169120cacfab47af024897b5588026c857810) |
| `WebAuthnP256Verifier`    | `0x078fd4ce33370699f44c221191ce0d8b7ccfccff77297f798dc7948b4201b9f4` | [link](https://voyager.online/class/0x078fd4ce33370699f44c221191ce0d8b7ccfccff77297f798dc7948b4201b9f4) |

Declared by: `0x64b1cf9c492b9ea333db7d4a2836feeee31cd1e2720f43b22732873122d433e`

## Declare-tx record (one-time costs, paid by maintainer)

STRK price reference: $0.038 / STRK (2026-04-28)

| Class                     | Sierra size | Tx hash                                                                | Fee paid    | USD     |
|---------------------------|------------:|------------------------------------------------------------------------|------------:|--------:|
| StarkVerifier             | 20 KB       | `0x2ba4610399325a32f12cfb33d3f20db2ecb7b696bbef0514fa8275310c7fc1a`     | 1.3622 STRK | $0.052  |
| P256Verifier              | 36 KB       | `0x7f2696cbe4d9835f4521fe25ef06fbade74ee2641d3dce23a225eff8355ce25`     | 2.9748 STRK | $0.114  |
| Secp256k1Verifier         | 40 KB       | `0x75690c0dd6203500e50461a5daa95e96998bd5662ec4b96f97f460f2c72407d`     | 3.1808 STRK | $0.122  |
| EIP191Secp256k1Verifier   | 97 KB       | `0x5e702a47debde19e7b913a1cabdf469888a8332b4f731ed4cf1f34507ce7683`     | 6.5362 STRK | $0.250  |
| WebAuthnP256Verifier      | 195 KB      | `0x126d8639de99ef821b0091a97f392e2f1234dbd7c4d0b58e3385cbdc3d12c62`     | 11.9532 STRK| $0.458  |
| Ed25519Verifier           | 543 KB      | `0x3c636c48f5f40cac5a5b38a8137d162c8826f17acd8dd5c73628dac9ff63aa0`     | 31.6190 STRK| $1.213  |
| ShhhAccount               | 831 KB      | `0x718b07da74315f9a418df8b32fb974deb584cf47296e28bb4c28a5554b0e64`      | 41.0650 STRK| $1.575  |
| **Total**                 |             |                                                                        | **98.692 STRK** | **$3.784** |

Cost scales roughly linearly with Sierra size — bigger class, more bytes
to upload + more validation work.

## Per-user costs (paid by user OR by paymaster like Chipi Pay)

These costs are estimates derived from `snforge test` gas measurements
under Cairo 2.14 / Sierra 1.7. Actual mainnet fees will be in the same
order of magnitude; mileage varies with `l2_gas_price` at the time.

### One-time per wallet

| Operation                                    | l2_gas         | STRK (est.) | USD (est.) | Notes |
|----------------------------------------------|---------------:|------------:|-----------:|-------|
| Deploy a wallet (any signer kind)            | ~3 M           | ~0.10       | ~$0.004    | Same `deploy_syscall` cost regardless of curve |
| Bootstrap migration from sessions wallet     | ~10 M          | ~0.32       | ~$0.012    | One-shot upgrade path for existing Chipi sessions users |

### Per transaction (typical user activity)

| Curve                     | l2_gas (snforge) | STRK (est.) | USD (est.) | Wallets that use this kind |
|---------------------------|-----------------:|------------:|-----------:|----------------------------|
| STARK ECDSA               | ~12 M            | ~0.38       | ~$0.014    | Argent, Braavos, native Starknet |
| Ed25519 (Garaga)          | ~28 M            | ~0.89       | ~$0.034    | Phantom, Solflare, every Solana wallet |
| Raw secp256k1 (recovery)  | ~15 M            | ~0.47       | ~$0.018    | Hardware wallets exposing low-level signing |
| EIP-191 secp256k1         | ~18 M            | ~0.57       | ~$0.022    | MetaMask, Rabby, WalletConnect, every EVM wallet |
| P-256 (raw)               | ~13 M            | ~0.41       | ~$0.016    | PIV smart cards, eIDAS IDs |
| WebAuthn P-256            | ~46 M            | ~1.46       | ~$0.056    | Apple passkeys, Touch ID, Face ID, YubiKey |
| Threshold 2-of-N (STARK)  | ~25 M            | ~0.79       | ~$0.030    | DAO multisig, corporate treasury |

### Account-management flows (timelocked, multi-step)

Each governance flow = **at least two user transactions** separated by a
timelock window. Costs sum.

| Flow                               | Steps                              | Total gas        | STRK   | USD     | Wall-clock |
|------------------------------------|------------------------------------|-----------------:|-------:|--------:|------------|
| Add a guardian                     | propose + execute (after 24h)      | ~24 M            | ~0.76  | ~$0.029 | 24 h       |
| Add a second owner key             | propose + execute (after 48h)      | ~24 M            | ~0.76  | ~$0.029 | 48 h       |
| Set threshold (e.g. 1 → 2-of-3)    | propose + execute (after 48h)      | ~22 M            | ~0.70  | ~$0.027 | 48 h       |
| Add a new verifier class kind      | propose + execute (after 48h)      | ~20 M            | ~0.63  | ~$0.024 | 48 h       |
| Guardian recovery                  | initiate + (cancel window) + finalize | ~30 M         | ~0.95  | ~$0.036 | 7 d        |
| Add session key + spending policy  | one OE with two inner calls        | ~18 M            | ~0.57  | ~$0.022 | instant    |

**Reading the table:** "USD" is what a sponsoring paymaster like Chipi
Pay would absorb per call, or what a user pays out-of-pocket if they
hold STRK. None of these operations exceed $0.06 in steady state at
2026-04-28 prices.

## Cost projection per active user (rough)

Assume a Cifra user signs up with Phantom, places 30 bets in their
first month (each = one OE with one inner `place_bet` call), and adds a
guardian:

| Item                    | Count |  STRK | USD    |
|-------------------------|------:|------:|-------:|
| Wallet deploy           |     1 |  0.10 | $0.004 |
| Place bet (Ed25519)     |    30 | 26.7  | $1.024 |
| Add guardian            |     1 |  0.76 | $0.029 |
| **Per-user month 1**    |       | **27.6** | **$1.057** |

**Take:** Chipi Pay can sponsor ~950 Cifra users per month for $1,000
of paymaster budget at current STRK prices. Drops to ~$0.50 per user
if STRK price halves.

## Where the deployer wallet stands

```
Pre-declare balance:  17.0164 STRK
Funded mid-process:  +600.0000 STRK
Total spent:         -98.6920 STRK (7 declares)
Final balance:       504.1457 STRK  ($19.30 USD)
```

The 504 STRK leftover sits with the deployer for any future class
declares (e.g. a V8.1 if Phase 13/14 audits surface a finding requiring
a redeploy, or new verifier kinds added per the roadmap such as
`EIP712Secp256k1Verifier` or BLS).

## Sources of variance

- **STRK price** — the dollar columns scale linearly with $/STRK
- **L2 gas price** — fluctuates per block; snforge measurements use a
  constant l2_gas_price for reproducibility. Mainnet fees will swing
  ±30% across the day depending on congestion.
- **Garaga hint complexity** — Ed25519 verification cost varies slightly
  with the signature's MSM hint shape (off-curve hints are cheaper than
  on-curve). The 28 M figure above is a typical happy-path value.
- **Calldata size** — every additional felt in a multicall adds
  ~0.05 M l2_gas. The estimates assume single-call OEs with ≤4 calldata
  felts, which covers `place_bet` / `transfer` / `approve` / `swap`.

## Reproduction

```bash
# Pre-declare class-hash check (deterministic)
sncast utils class-hash --contract-name ShhhAccount

# Declare
sncast --account deployer_oz declare \
  --contract-name ShhhAccount \
  --url https://starknet-rpc.publicnode.com

# Per-tx fee read-back
curl -s -X POST https://starknet-rpc.publicnode.com \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"starknet_getTransactionReceipt","params":["0x..."],"id":1}'
```
