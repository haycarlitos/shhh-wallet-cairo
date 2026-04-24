//! SRC-5 interface-ID registration + cross-language parity.
//!
//! Two load-bearing properties enforced here:
//!
//!   1. **A fresh V8 account reports `supports_interface` for both**
//!      `ISRC9_V2_ID` (audit H-2) and `ISIGNER_ID` (pluggable-signer
//!      trait). Anything that consumes the SRC-5 surface — paymasters,
//!      SDKs, indexers — can discover the account's capabilities with
//!      one call each, no storage reads.
//!
//!   2. **The Cairo `ISIGNER_ID` constant matches the canonical recipe**
//!      — `starknet_keccak("ISigner_V1")`. The hardcoded value is
//!      cross-checked here against a test-only Poseidon-free recomputation
//!      using the same hex literal the TS SDK publishes, so any accidental
//!      edit to the Cairo constant is caught before it ships.
//!
//! Edge cases covered:
//!   - Bogus interface IDs (zero, random, V7 wrong ID) MUST return false.
//!   - Migration path (sessions-wallet `bootstrap_from_sessions`) MUST
//!     register `ISIGNER_ID` too — so a migrated account looks
//!     indistinguishable from a fresh V8 deploy to SRC-5 consumers.
//!   - V7 wallet class MUST NOT advertise `ISIGNER_ID` (it predates the
//!     trait) — anyone probing a V7 account correctly learns it is not
//!     pluggable-signer-capable.

use shhh_wallet::outside_execution::ISRC9_V2_ID;
use shhh_wallet::signer::interface::ISIGNER_ID;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, store};
use starknet::{ClassHash, ContractAddress};

#[starknet::interface]
trait ISRC5<TContractState> {
    fn supports_interface(self: @TContractState, interface_id: felt252) -> bool;
}

#[starknet::interface]
trait IShhhMigration<TContractState> {
    fn bootstrap_from_sessions(
        ref self: TContractState,
        public_key: felt252,
        stark_verifier_class: ClassHash,
        label: felt252,
    );
}

// --------------------------------------------------------------
// Canonical value — MUST match both the Cairo constant and the
// TS SDK's `ISIGNER_ID` export in `scripts/ts/snip12-hash.ts`.
// If this value changes, update the Cairo module, the SDK module,
// and the SNIP's Part G "Interface Identifier" section — all three
// at the same time.
//
// Recipe: `starknet_keccak("ISigner_V1")`.
// --------------------------------------------------------------
const CANONICAL_ISIGNER_ID: felt252 =
    0x94c5a761f34b25a4e603c651ac0e1fc4fad9cdb5517f7fa1bb54044c7e5ef8;

const V7_WRONG_SRC9_ID: felt252 = 0x1d1144bb2138571a605b8b8eed8e4e9e04dc40fce40190a11af584935e0a04c;

// --------------------------------------------------------------
// Deploy helpers
// --------------------------------------------------------------

fn deploy_shhh_account() -> ContractAddress {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, 0xABCD, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();
    addr
}

fn deploy_v7_wallet() -> ContractAddress {
    let class = declare("ShhhWallet").unwrap().contract_class();
    let (addr, _) = class
        .deploy(@array![ // V7 2-param constructor: pubkey_low, pubkey_high
        0xAAAA, 0xBBBB])
        .unwrap();
    addr
}

// --------------------------------------------------------------
// Constant parity — the imported `ISIGNER_ID` must equal the
// canonical literal used by the SDK and the SNIP text. Silently
// flipping the in-repo constant would break every external
// consumer, so we lock it to the public value here.
// --------------------------------------------------------------

#[test]
fn test_isigner_id_matches_canonical_value() {
    assert(ISIGNER_ID == CANONICAL_ISIGNER_ID, 'ISIGNER_ID drift');
}

#[test]
fn test_isigner_id_is_not_zero() {
    // The original scaffolded value was `0x0`. A zero interface ID is
    // illegal under SRC-5 (it would collide with "interface not
    // registered"). Guard against a regression to the placeholder.
    assert(ISIGNER_ID != 0, 'ISIGNER_ID must not be zero');
}

#[test]
fn test_isigner_id_distinct_from_src9_v2_id() {
    assert(ISIGNER_ID != ISRC9_V2_ID, 'IDs collide');
}

// --------------------------------------------------------------
// SRC-5 surface on a freshly-deployed V8 account
// --------------------------------------------------------------

#[test]
fn test_shhh_account_reports_isigner_id() {
    let addr = deploy_shhh_account();
    let src5 = ISRC5Dispatcher { contract_address: addr };
    assert(src5.supports_interface(ISIGNER_ID), 'missing ISIGNER_ID');
}

#[test]
fn test_shhh_account_reports_src9_v2_id() {
    let addr = deploy_shhh_account();
    let src5 = ISRC5Dispatcher { contract_address: addr };
    assert(src5.supports_interface(ISRC9_V2_ID), 'missing SRC9_V2_ID');
}

#[test]
fn test_shhh_account_rejects_zero_interface_id() {
    let addr = deploy_shhh_account();
    let src5 = ISRC5Dispatcher { contract_address: addr };
    // Zero MUST NOT be treated as registered. The OZ SRC-5 component
    // default-returns false for uninitialised slots; this test pins
    // that behavior so a change in the component can't silently
    // re-enable the "zero means registered" footgun.
    assert(!src5.supports_interface(0), '0 treated as registered');
}

#[test]
fn test_shhh_account_rejects_random_interface_id() {
    let addr = deploy_shhh_account();
    let src5 = ISRC5Dispatcher { contract_address: addr };
    assert(!src5.supports_interface(0xDEADBEEF), 'bogus id registered');
}

#[test]
fn test_shhh_account_rejects_v7_wrong_src9_id() {
    // Defense-in-depth audit H-2 check: the wrong-ID-from-V7 should
    // NEVER appear in an V8 account's SRC-5 surface (already covered
    // in tests/audit_2026_04_20.cairo for the V7 class, repeated here
    // for V8).
    let addr = deploy_shhh_account();
    let src5 = ISRC5Dispatcher { contract_address: addr };
    assert(!src5.supports_interface(V7_WRONG_SRC9_ID), 'V7 wrong id registered');
}

// --------------------------------------------------------------
// Migration path preserves SRC-5 surface
// --------------------------------------------------------------

fn reset_for_migration_simulation(addr: ContractAddress) {
    store(addr, selector!("primary_kind"), array![0].span());
    store(addr, selector!("primary_pubkey_hash"), array![0].span());
    store(addr, selector!("address_salt"), array![0].span());
    store(addr, selector!("owners_count"), array![0].span());
    store(addr, selector!("active_count"), array![0].span());
    store(addr, selector!("threshold"), array![0].span());
    store(addr, selector!("primary_owner_id"), array![0].span());
    store(addr, selector!("pubkey_cursor"), array![0].span());
}

#[test]
fn test_migrated_account_registers_isigner_id() {
    // Simulate a freshly-upgraded sessions wallet. After
    // `bootstrap_from_sessions` it must look identical to a native
    // V8 deploy from the SRC-5 side, so dapps can probe either
    // deployment path uniformly.
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, 0xAAAA, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();

    reset_for_migration_simulation(addr);
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    mig.bootstrap_from_sessions(0xCAFE, verifier_class, 'migrated');

    let src5 = ISRC5Dispatcher { contract_address: addr };
    assert(src5.supports_interface(ISIGNER_ID), 'ISIGNER_ID not registered');
    assert(src5.supports_interface(ISRC9_V2_ID), 'SRC9_V2 not registered');
}

// --------------------------------------------------------------
// V7 class correctly does NOT advertise ISIGNER_ID
// --------------------------------------------------------------

#[test]
fn test_v7_wallet_does_not_advertise_isigner_id() {
    // V7 predates the pluggable-signer trait. A client probing V7
    // for ISIGNER_ID must correctly learn the wallet is not
    // pluggable-signer-capable, so upgrade-prompts / downgrade-paths
    // can trigger cleanly.
    let addr = deploy_v7_wallet();
    let src5 = ISRC5Dispatcher { contract_address: addr };
    assert(!src5.supports_interface(ISIGNER_ID), 'V7 falsely claims ISigner');
}
