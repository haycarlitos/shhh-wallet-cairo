# Shhh Wallet — Self-Custodial Starknet Account (Cairo)

A self-custodial Starknet smart wallet controlled by an **Ed25519 keypair** (e.g., a Solana/Phantom wallet). All operations are authorized via **SNIP-9 V2** (`execute_from_outside_v2`) with on-chain Ed25519 signature verification powered by [Garaga](https://github.com/keep-starknet-strange/garaga).

Designed to work with **Starknet paymasters** for gasless UX — users never need STRK/ETH.

## Use Case

Shhh enables Solana users to interact with Starknet DeFi protocols without ever managing Starknet keys or gas tokens:

1. **User connects Phantom wallet** (Solana)
2. **A Starknet smart wallet is deterministically derived** from their Ed25519 public key
3. **All wallet operations** (DeFi deposits, withdrawals, approvals) are signed with Phantom's `signMessage`
4. **On-chain verification**: The contract verifies Ed25519 signatures using Garaga's optimized elliptic curve operations
5. **Gas is abstracted**: A paymaster (e.g., [Chipi Pay](https://chipipay.com)) sponsors all transactions

The wallet has **no `execute()` entrypoint** — there is no server key, relayer, or admin that can authorize operations. The Ed25519 signature is the **sole authorization mechanism**, making this fully self-custodial.

## Architecture

### SNIP-9 V2 Flow

```
User (Phantom)                    Paymaster                    Starknet Contract
     |                               |                              |
     |-- signMessage(OE_hex) ------->|                              |
     |                               |-- invoke(execute_from_outside_v2)
     |                               |                              |
     |                               |   1. Validate caller         |
     |                               |   2. Check time bounds       |
     |                               |   3. Mark nonce used         |
     |                               |   4. Read owner pubkey       |
     |                               |   5. Verify OE encoding      |
     |                               |   6. Garaga Ed25519 verify   |
     |                               |   7. Execute calls           |
     |                               |                              |
```

### Canonical OE Byte Encoding (186 bytes)

The contract reconstructs the exact bytes the user signed and verifies them against the Ed25519 signature:

| Field | Size | Encoding |
|-------|------|----------|
| Domain separator (`SHHH_OE_V1`) | 10 bytes | ASCII |
| `chain_id` | 32 bytes | Big-endian felt252 |
| `contract_address` | 32 bytes | Big-endian felt252 |
| `caller` | 32 bytes | Big-endian felt252 |
| `nonce` | 32 bytes | Big-endian felt252 |
| `execute_after` | 8 bytes | Big-endian u64 |
| `execute_before` | 8 bytes | Big-endian u64 |
| `calls_hash` | 32 bytes | Poseidon hash, big-endian |

The 186 raw bytes are hex-encoded to 372 ASCII characters before Ed25519 verification. This allows Phantom to sign the message as a text string without triggering transaction detection.

## Contract Interface

```cairo
#[starknet::interface]
pub trait IShhhWallet<TContractState> {
    /// Returns the owner's Ed25519 public key as LE u256 halves (low, high)
    fn get_owner(self: @TContractState) -> (felt252, felt252);
}

// SNIP-9 V2 (SRC9)
fn execute_from_outside_v2(
    outside_execution: OutsideExecution,
    signature: Span<felt252>,
) -> Array<Span<felt252>>;

fn is_valid_outside_execution_nonce(nonce: felt252) -> bool;
```

### Constructor

```cairo
fn constructor(owner_pubkey_low: felt252, owner_pubkey_high: felt252)
```

Only two parameters — the Ed25519 public key split into little-endian u256 halves (matching Garaga's `Py_twisted` format).

### What's NOT in the contract

- No `execute()` entrypoint — no relayer, no admin key
- No sequential nonce — uses SNIP-9 V2 outside execution nonces (timestamp-based)
- No `__validate__` logic — always reverts (`NOT_SUPPORTED`). Actual validation happens inside `execute_from_outside_v2`

## Security Model

| Property | Mechanism |
|----------|-----------|
| **Authorization** | Ed25519 on-chain signature verification (Garaga v1.0.1) |
| **Replay protection** | Per-nonce mapping in contract storage |
| **Time bounds** | `execute_after` / `execute_before` window validation |
| **Caller restriction** | `caller: 0x0` (ANY_CALLER) — security is in the signature, not caller identity |
| **Self-custodial** | Only the holder of the Ed25519 private key can authorize operations |
| **Paymaster compatible** | `__execute__` exists for fee estimation; actual execution via SNIP-9 V2 |

### If the server is compromised

The attacker **cannot execute any wallet operation**. They can only pay gas (via paymaster), but without the user's Ed25519 private key (held in Phantom), no calls can be authorized.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `starknet` | 2.14.0 | Cairo core library |
| `openzeppelin` | v3.0.0 | SRC5 introspection, upgradeable component |
| `garaga` | v1.0.1 | On-chain Ed25519 signature verification |
| `snforge_std` | v0.54.1 | Testing framework (dev only) |

## Build & Test

```bash
# Build
scarb build

# Run tests (9/9 pass)
scarb test
```

### Test Coverage

| Test | What it verifies |
|------|-----------------|
| `test_initial_state` | Owner pubkey stored correctly |
| `test_nonce_availability` | Fresh nonce is available |
| `test_outside_execution_too_early` | Rejects if `block_timestamp < execute_after` |
| `test_outside_execution_too_late` | Rejects if `block_timestamp > execute_before` |
| `test_outside_execution_wrong_caller` | Rejects if caller doesn't match (non-ANY_CALLER) |
| `test_outside_execution_valid_ed25519` | Full Garaga Ed25519 verification with test fixtures |
| `test_outside_execution_wrong_owner` | Rejects signature from wrong key |
| `test_outside_execution_ed25519_replay` | Rejects replay (duplicate nonce) |
| `test_poseidon_hash_compatibility` | Poseidon hash matches starknet.js |

## Mainnet Deployment

- **Class hash**: `0x2e599a0939f268c70acab242411225ddeefd7f3978e40dcb7c397ca39a9a13`
- **Network**: Starknet Mainnet
- **Ed25519 verification cost**: ~33M L2 gas per call (Garaga v1.0.1)

## Project Structure

```
src/
├── lib.cairo              # Module declarations
├── wallet.cairo           # Main contract (SNIP-9 V2 + OE encoding)
├── outside_execution.cairo # OutsideExecution struct + ISRC9_V2 interface
└── ed25519/
    ├── interface.cairo    # IShhhWallet trait
    └── component.cairo    # Ed25519 owner storage component
tests/
└── test_contract.cairo    # 9 tests (SNIP-9 + Ed25519 + Poseidon)
```

## License

MIT
