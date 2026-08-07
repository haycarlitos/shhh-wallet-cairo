//! Audit V8.3 (2026-05-10) regression tests.
//!
//! Closes the four findings from
//! `audits/2026-05-10-claude-opus-v8-2-review.md`:
//!
//!   - H-1: `finalize_recovery` now calls `_validate_pubkey_via_verifier`.
//!     The negative test below proves a poison-pill pubkey reaching
//!     finalize is rejected with `'M1: invalid pubkey'`.
//!
//!   - M-1: `_validate_pubkey_via_verifier` now raises `inside_verifier`
//!     around the library_call, so a malicious verifier class
//!     re-entering via `propose_*` is rejected with
//!     `'SHHH: verifier reentry'`.
//!
//!   - M-2: `bootstrap_from_sessions` now calls
//!     `_validate_pubkey_via_verifier`. With the kind hardcoded to
//!     STARK and a non-zero check upstream the path was already
//!     correct-by-coincidence; this test pins that the helper is
//!     wired in (a regression to the V8.2 shape would surface as a
//!     missing 'M1: invalid pubkey' panic on a deliberately-zero
//!     pubkey path).
//!
//!   - M-3: per-finding negative test exists and runs in CI.
//!
//! All three test verifier helpers live in
//! `src/test_helpers/evil_verifier.cairo`.

use shhh_wallet::owner_set::interface::{ROLE_GUARDIAN, ROLE_OWNER};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_caller_address, stop_cheat_caller_address, store,
};
use starknet::{ClassHash, ContractAddress};

const TIMELOCK_ADD_OWNER: u64 = 172_800; // 48h
const TIMELOCK_ADD_VERIFIER: u64 = 172_800; // 48h
const TIMELOCK_RECOVERY: u64 = 604_800; // 7d
const SIG_VERSION_V2_SNIP12: felt252 = 'V2_SNIP12';

// --------------------------------------------------------------
// Account / Gov / Recovery dispatchers
// --------------------------------------------------------------

#[starknet::interface]
trait IShhhGov<TContractState> {
    fn propose_add_owner(
        ref self: TContractState,
        proposer: u32,
        kind: felt252,
        pubkey_bytes: Array<felt252>,
        role: felt252,
        weight: u8,
        label: felt252,
    ) -> felt252;
    fn execute_add_owner(
        ref self: TContractState,
        op_id: felt252,
        kind: felt252,
        pubkey_bytes: Array<felt252>,
        role: felt252,
        weight: u8,
        label: felt252,
    ) -> u32;
    fn propose_add_verifier_class(
        ref self: TContractState, proposer: u32, kind: felt252, class_hash: ClassHash,
    ) -> felt252;
    fn execute_add_verifier_class(
        ref self: TContractState, op_id: felt252, kind: felt252, class_hash: ClassHash,
    );
}

#[starknet::interface]
trait IShhhRecovery<TContractState> {
    fn initiate_recovery(
        ref self: TContractState,
        proposer: u32,
        new_owner_kind: felt252,
        new_pubkey_bytes: Array<felt252>,
        new_role: felt252,
        new_weight: u8,
        new_label: felt252,
    );
    fn finalize_recovery(
        ref self: TContractState,
        new_owner_kind: felt252,
        new_pubkey_bytes: Array<felt252>,
        new_role: felt252,
        new_weight: u8,
        new_label: felt252,
    ) -> u32;
}

// --------------------------------------------------------------
// Fixture helpers
// --------------------------------------------------------------

fn declare_v8_account_and_stark() -> (ContractAddress, ClassHash) {
    let stark_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', stark_class.into(), 1, 0xAAAA, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();
    (addr, stark_class)
}

fn add_guardian(addr: ContractAddress, t0: u64) -> u32 {
    // Self-call propose + execute pattern.
    start_cheat_block_timestamp_global(t0);
    start_cheat_caller_address(addr, addr);
    let gov = IShhhGovDispatcher { contract_address: addr };
    let op_id = gov
        .propose_add_owner(0_u32, 'STARK', array![0xCCCC], ROLE_GUARDIAN, 1_u8, 'guardian');
    start_cheat_block_timestamp_global(t0 + TIMELOCK_ADD_OWNER + 1);
    let gid = gov
        .execute_add_owner(op_id, 'STARK', array![0xCCCC], ROLE_GUARDIAN, 1_u8, 'guardian');
    gid
}

fn register_secp256k1_verifier_via_governance(addr: ContractAddress, t0: u64) {
    // Register Secp256k1Verifier under kind 'SECP256K1' through the
    // 48h ADD_VERIFIER timelock so the recovery test below can
    // actually exercise the verifier (rather than being short-
    // circuited by 'SHHH: verifier missing').
    let secp_class = *declare("Secp256k1Verifier").unwrap().contract_class().class_hash;
    start_cheat_block_timestamp_global(t0);
    start_cheat_caller_address(addr, addr);
    let gov = IShhhGovDispatcher { contract_address: addr };
    let op_id = gov.propose_add_verifier_class(0_u32, 'SECP256K1', secp_class);
    start_cheat_block_timestamp_global(t0 + TIMELOCK_ADD_VERIFIER + 1);
    gov.execute_add_verifier_class(op_id, 'SECP256K1', secp_class);
}

// =====================================================================
//  H-1 negative — finalize_recovery rejects off-curve pubkey
// =====================================================================

#[test]
#[should_panic(expected: 'M1: invalid pubkey')]
fn test_v8_3_h1_finalize_recovery_rejects_off_curve_secp256k1() {
    let (addr, _) = declare_v8_account_and_stark();
    let _gid = add_guardian(addr, 1_000_000);

    // Register secp256k1 verifier under SECP256K1 kind.
    register_secp256k1_verifier_via_governance(addr, 1_000_000 + TIMELOCK_ADD_OWNER + 100);

    // Guardian initiates recovery with a deliberately off-curve secp256k1
    // pubkey. (4 felts, right shape, but `(x,y) = (DEAD, BABE)` is not
    // on the secp256k1 curve.)
    let t_init = 1_000_000 + TIMELOCK_ADD_OWNER + TIMELOCK_ADD_VERIFIER + 200;
    start_cheat_block_timestamp_global(t_init);
    start_cheat_caller_address(addr, addr);
    let rec = IShhhRecoveryDispatcher { contract_address: addr };
    let bad: Array<felt252> = array![0xDEAD, 0xBEEF, 0xCAFE, 0xBABE];
    rec.initiate_recovery(1_u32, 'SECP256K1', bad.clone(), ROLE_OWNER, 1_u8, 'evil');

    // Wait out the 7-day window.
    let t_finalize = t_init + TIMELOCK_RECOVERY + 1;
    start_cheat_block_timestamp_global(t_finalize);

    // finalize_recovery is permissionless — anyone can trigger.
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    let _ = rec.finalize_recovery('SECP256K1', bad, ROLE_OWNER, 1_u8, 'evil');
    // EXPECTED: revert with 'M1: invalid pubkey' before the off-curve
// pubkey lands in `owner_set`. Pre-V8.3 this would have succeeded.
}

// =====================================================================
//  M-1 negative — malicious verifier class cannot re-enter into
//  propose_set_threshold from inside validate_pubkey
// =====================================================================

#[test]
#[should_panic(expected: 'SHHH: verifier reentry')]
fn test_v8_3_m1_validate_pubkey_blocks_reentry_into_self_call_mutator() {
    let (addr, _) = declare_v8_account_and_stark();

    // Register the EvilReentrantVerifier under kind 'TEST' via the
    // 48h ADD_VERIFIER timelock (mirrors the trust assumption that
    // gates verifier class additions in production).
    let evil_class = *declare("EvilReentrantVerifier").unwrap().contract_class().class_hash;
    let t0: u64 = 1_000_000;
    start_cheat_block_timestamp_global(t0);
    start_cheat_caller_address(addr, addr);
    let gov = IShhhGovDispatcher { contract_address: addr };
    let v_op = gov.propose_add_verifier_class(0_u32, 'TEST', evil_class);
    start_cheat_block_timestamp_global(t0 + TIMELOCK_ADD_VERIFIER + 1);
    gov.execute_add_verifier_class(v_op, 'TEST', evil_class);

    // Now schedule an add_owner with kind='TEST' so the account
    // dispatches validate_pubkey to the EvilReentrantVerifier.
    let t1 = t0 + TIMELOCK_ADD_VERIFIER + 100;
    start_cheat_block_timestamp_global(t1);
    let pk: Array<felt252> = array![0xFEED];
    let owner_op = gov.propose_add_owner(0_u32, 'TEST', pk.clone(), ROLE_OWNER, 1_u8, 'evil');
    start_cheat_block_timestamp_global(t1 + TIMELOCK_ADD_OWNER + 1);
    // execute_add_owner is permissionless; STOP the self-call cheat so
    // the inner `call_contract_syscall(addr, 'propose_set_threshold')`
    // from the EvilReentrantVerifier sees the natural Starknet caller
    // (= addr itself) rather than the cheated value. snforge's
    // start_cheat_caller_address overrides ALL get_caller_address
    // observations inside the target contract — including ones from
    // inner syscalls — which would shadow the test of `_assert_self_call`'s
    // first check before reaching `inside_verifier`.
    stop_cheat_caller_address(addr);
    // EXPECTED: inside the EvilReentrantVerifier::validate_pubkey
    // library_call, an attempted call back into propose_set_threshold
    // passes the `caller == self` first check (caller = addr) and
    // hits the second check `!inside_verifier` which reverts with
    // 'SHHH: verifier reentry'. Pre-V8.3 the flag wasn't raised on
    // the validate_pubkey path so the syscall would have succeeded
    // and the malicious verifier could escalate privilege.
    let _ = gov.execute_add_owner(owner_op, 'TEST', pk, ROLE_OWNER, 1_u8, 'evil');
}

// =====================================================================
//  M-2 negative — bootstrap_from_sessions actually invokes
//  validate_pubkey on the registered verifier class.
//
//  Audit C-1 (2026-05-11): the prior smoke test only proved the
//  helper module compiles — a future maintainer removing
//  `_validate_pubkey_via_verifier(ref self, kind, pubkey_span);`
//  from bootstrap_from_sessions could ship the regression with CI
//  still green. This test injects the EvilPanicVerifier as the
//  STARK verifier class; if bootstrap calls validate_pubkey the
//  test panics with 'EVIL: validate panicked'. If a regression
//  removes the validate call the test fails-open with a
//  PrimaryOwnerInitialized event and no panic — which would fail
//  the should_panic expectation.
// =====================================================================

#[test]
#[should_panic(expected: 'EVIL: validate panicked')]
fn test_v8_3_m2_bootstrap_panics_when_validate_panics() {
    // Deploy ShhhAccount with a normal STARK primary so the
    // constructor's own validate_pubkey lookup hits a real verifier.
    // (Constructor validates the primary pubkey via the legitimate
    // StarkVerifier — we can't put EvilPanicVerifier in the
    // constructor without breaking the deploy.)
    let stark_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let evil_class = *declare("EvilPanicVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', stark_class.into(), 1, 0xAAAA, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();

    // Simulate a freshly-upgraded sessions wallet: wipe the V8
    // primary scalars + owner_set so `bootstrap_from_sessions` can
    // re-initialise. Match `tests/account_migration.cairo::reset_for_migration_simulation`.
    store(addr, selector!("primary_kind"), array![0].span());
    store(addr, selector!("primary_pubkey_hash"), array![0].span());
    store(addr, selector!("address_salt"), array![0].span());
    store(addr, selector!("owners_count"), array![0].span());
    store(addr, selector!("active_count"), array![0].span());
    store(addr, selector!("threshold"), array![0].span());
    store(addr, selector!("primary_owner_id"), array![0].span());
    store(addr, selector!("pubkey_cursor"), array![0].span());

    // Bootstrap with EvilPanicVerifier as the STARK verifier class.
    // The account's `_validate_pubkey_via_verifier(ref self, kind,
    // pubkey_span)` dispatches via library_call into
    // EvilPanicVerifier::validate_pubkey, which panics with
    // 'EVIL: validate panicked'. Pre-V8.3 the helper wasn't called
    // and the test would fail-open with no panic.
    start_cheat_caller_address(addr, addr);
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    mig.bootstrap_from_sessions(0xCAFE, evil_class.try_into().unwrap(), 'evil-migration');
    stop_cheat_caller_address(addr);
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
