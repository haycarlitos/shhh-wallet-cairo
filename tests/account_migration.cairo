//! Phase 6.5 — sessions-wallet migration into V8.
//!
//! Two flows exercised:
//!   1. Already-initialized account rejects `bootstrap_from_sessions`
//!      ('MIG: already initialized') — guards fresh V8 deployments.
//!   2. Simulated post-upgrade state (primary_kind reset to 0 + owners
//!      wiped via snforge `store`) accepts `bootstrap_from_sessions`
//!      and lands in a valid V8 state matching a native constructor
//!      deployment.
//!
//! The `store()` cheat is the standard snforge way to simulate the
//! storage layout an account would have *right after* a sessions
//! wallet called `upgrade(SHHH_ACCOUNT_CLASS_HASH)` without yet
//! running `bootstrap_from_sessions`.

use shhh_wallet::owner_set::interface::ROLE_OWNER;
use snforge_std::signature::SignerTrait;
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
    stop_cheat_caller_address, store,
};
use starknet::{ClassHash, ContractAddress};

/// Audit H-1 follow-up (2026-05-07): the migration entrypoint now
/// gates on `_assert_self_call`, so test fixtures must simulate the
/// legitimate path where the OLD class's multicall executes
/// `[upgrade, bootstrap_from_sessions]` in one OE — call 2's caller
/// is the account itself. This helper stamps that caller for one
/// invocation.
fn cheat_self_call(addr: ContractAddress) {
    start_cheat_caller_address(addr, addr);
}

#[starknet::interface]
trait IShhhReads<TContractState> {
    fn primary_kind(self: @TContractState) -> felt252;
    fn primary_pubkey_hash(self: @TContractState) -> felt252;
    fn address_salt(self: @TContractState) -> felt252;
    fn get_verifier_class(self: @TContractState, kind: felt252) -> ClassHash;
    fn owner_count(self: @TContractState) -> u32;
    fn active_owner_count(self: @TContractState) -> u32;
    fn threshold(self: @TContractState) -> u8;
    fn get_owner(
        self: @TContractState, owner_id: u32,
    ) -> shhh_wallet::owner_set::interface::OwnerRecord;
}

#[starknet::interface]
trait IShhhMigration<TContractState> {
    fn bootstrap_from_sessions(
        ref self: TContractState,
        public_key: felt252,
        stark_verifier_class: ClassHash,
        label: felt252,
    );
    fn bootstrap_from_sessions_signed(
        ref self: TContractState,
        public_key: felt252,
        stark_verifier_class: ClassHash,
        label: felt252,
        signature_r: felt252,
        signature_s: felt252,
    );
}

fn declare_and_deploy() -> (ContractAddress, ClassHash) {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, 0xAAAA, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();
    (addr, verifier_class)
}

/// snforge `store` by raw storage-variable selector. For a top-level
/// scalar Cairo storage field `foo`, the slot selector is
/// `selector!("foo")`. For the OwnerSetComponent sub-fields we use the
/// component-prefixed name.
fn reset_for_migration_simulation(addr: ContractAddress) {
    // Wipe the V8 primary-owner scalars.
    store(addr, selector!("primary_kind"), array![0].span());
    store(addr, selector!("primary_pubkey_hash"), array![0].span());
    store(addr, selector!("address_salt"), array![0].span());
    // OwnerSetComponent scalars (substorage prefix + component field).
    store(addr, selector!("owners_count"), array![0].span());
    store(addr, selector!("active_count"), array![0].span());
    store(addr, selector!("threshold"), array![0].span());
    store(addr, selector!("primary_owner_id"), array![0].span());
    store(addr, selector!("pubkey_cursor"), array![0].span());
}

#[test]
#[should_panic(expected: 'MIG: already initialized')]
fn test_cannot_rebootstrap_an_initialized_account() {
    let (addr, verifier) = declare_and_deploy();
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    // primary_kind already 'STARK' from the constructor.
    cheat_self_call(addr);
    mig.bootstrap_from_sessions(0xCAFE, verifier, 'secondary');
}

#[test]
#[should_panic(expected: 'MIG: public_key is zero')]
fn test_bootstrap_rejects_zero_public_key() {
    let (addr, verifier) = declare_and_deploy();
    reset_for_migration_simulation(addr);
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    cheat_self_call(addr);
    mig.bootstrap_from_sessions(0, verifier, 'x');
}

#[test]
#[should_panic(expected: 'MIG: verifier class zero')]
fn test_bootstrap_rejects_zero_verifier_class() {
    let (addr, _) = declare_and_deploy();
    reset_for_migration_simulation(addr);
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    let zero_class: ClassHash = 0.try_into().unwrap();
    cheat_self_call(addr);
    mig.bootstrap_from_sessions(0xCAFE, zero_class, 'x');
}

#[test]
fn test_bootstrap_initializes_v8_state() {
    let (addr, verifier) = declare_and_deploy();
    reset_for_migration_simulation(addr);
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    cheat_self_call(addr);
    mig.bootstrap_from_sessions(0xCAFE, verifier, 'migrated');

    let reads = IShhhReadsDispatcher { contract_address: addr };
    assert(reads.primary_kind() == 'STARK', 'primary_kind');
    assert(reads.owner_count() == 1_u32, 'owner_count');
    assert(reads.active_owner_count() == 1_u32, 'active_owner_count');
    assert(reads.threshold() == 1_u8, 'threshold');
    assert(
        Into::<
            ClassHash, felt252,
            >::into(reads.get_verifier_class('STARK')) == Into::<
            ClassHash, felt252,
        >::into(verifier),
        'verifier not registered',
    );

    let owner_0 = reads.get_owner(0);
    assert(owner_0.kind == 'STARK', 'owner_0 kind');
    assert(owner_0.role == ROLE_OWNER, 'owner_0 role');
    assert(owner_0.label == 'migrated', 'owner_0 label');

    // Address salt and pubkey hash are set to non-zero values derived
    // from the sessions public key — indexer-visible via the events
    // emitted by bootstrap_from_sessions.
    assert(reads.primary_pubkey_hash() != 0, 'pubkey_hash empty');
    assert(reads.address_salt() != 0, 'address_salt empty');
}

#[test]
#[should_panic(expected: 'MIG: already initialized')]
fn test_double_bootstrap_reverts_even_after_reset() {
    let (addr, verifier) = declare_and_deploy();
    reset_for_migration_simulation(addr);
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    cheat_self_call(addr);
    mig.bootstrap_from_sessions(0xCAFE, verifier, 'migrated');
    // Second call must revert — primary_kind is now nonzero.
    mig.bootstrap_from_sessions(0xDEAD, verifier, 'attacker');
}

/// Audit H-1 regression (2026-05-07): direct external invocation of
/// `bootstrap_from_sessions` from any non-self caller MUST revert with
/// 'SHHH: caller != self'. The legitimate path bundles
/// `[upgrade, bootstrap_from_sessions]` in a single OE multicall so
/// call 2 sees the account as caller. Without this guard, a mempool
/// watcher could race the upgrade tx and seize the migrating account
/// (the test fixture in this file used to do exactly that — it is now
/// scoped to the self-call cheat).
#[test]
#[should_panic(expected: 'SHHH: caller != self')]
fn test_audit_h1_bootstrap_rejects_external_caller() {
    let (addr, verifier) = declare_and_deploy();
    reset_for_migration_simulation(addr);
    // Cheat as a hostile address — NOT the account itself.
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    mig.bootstrap_from_sessions(0xCAFE, verifier, 'pwned');
    stop_cheat_caller_address(addr);
}

// ==========================================================
// V8.4 — stranded-state recovery via bootstrap_from_sessions_signed
//
// The chipi-pay/sessions-smart-contract OE multicall is non-atomic:
// `_execute_calls` silently swallows subcall errors. If the migration
// OE [upgrade(V8.3), bootstrap_from_sessions(...)] hits a bootstrap
// revert (bad calldata, validate_pubkey panic, gas), the upgrade syscall
// has already queued the class swap and takes effect at end-of-tx — the
// wallet lands at V8.3 with primary_kind == 0 and no owners. The
// self-call gate on bootstrap_from_sessions makes that state
// unrecoverable on its own. bootstrap_from_sessions_signed accepts a
// STARK signature from the legacy pubkey over a canonical bootstrap
// message bound to the account's address, so any caller can re-trigger
// initialization with proof that they hold the legacy key.
// ==========================================================

/// Compute the canonical bootstrap message hash the contract checks.
/// Mirrors `_initialize_v8_from_sessions`'s signature gate exactly.
fn compute_bootstrap_message(
    account: ContractAddress, public_key: felt252, verifier_class: ClassHash, label: felt252,
) -> felt252 {
    let verifier_felt: felt252 = verifier_class.into();
    core::poseidon::poseidon_hash_span(
        array!['SHHH_BOOTSTRAP_V8_4', account.into(), public_key, verifier_felt, label].span(),
    )
}

#[test]
fn test_v8_4_signed_bootstrap_recovers_stranded_wallet() {
    let (addr, verifier) = declare_and_deploy();
    // Simulate the stranded state: upgrade succeeded but bootstrap reverted
    // silently inside the OLD class's non-atomic _execute_calls. After the
    // tx end-of-block, the class is V8.3 but storage is zeroed.
    reset_for_migration_simulation(addr);

    let kp = StarkCurveKeyPairImpl::from_secret_key(0xC0FFEE_BEEF);
    let label = 'recovered';
    let msg = compute_bootstrap_message(addr, kp.public_key, verifier, label);
    let (r, s) = kp.sign(msg).unwrap();

    // Recovery is callable from ANY address — not the account itself,
    // not the original owner's EOA. The signature is the authorization.
    let relay: ContractAddress = 0xBEEF_C0DE.try_into().unwrap();
    start_cheat_caller_address(addr, relay);
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    mig.bootstrap_from_sessions_signed(kp.public_key, verifier, label, r, s);
    stop_cheat_caller_address(addr);

    // Post-state must match what bootstrap_from_sessions produces.
    let reads = IShhhReadsDispatcher { contract_address: addr };
    assert(reads.primary_kind() == 'STARK', 'primary_kind');
    assert(reads.owner_count() == 1_u32, 'owner_count');
    assert(reads.active_owner_count() == 1_u32, 'active_count');
    assert(reads.threshold() == 1_u8, 'threshold');
    let owner_0 = reads.get_owner(0);
    assert(owner_0.kind == 'STARK', 'owner_0 kind');
    assert(owner_0.role == ROLE_OWNER, 'owner_0 role');
    assert(owner_0.label == label, 'owner_0 label');
    assert(reads.primary_pubkey_hash() != 0, 'pubkey_hash empty');
    assert(reads.address_salt() != 0, 'address_salt empty');
}

#[test]
#[should_panic(expected: 'MIG: bad bootstrap signature')]
fn test_v8_4_signed_bootstrap_rejects_invalid_signature() {
    let (addr, verifier) = declare_and_deploy();
    reset_for_migration_simulation(addr);
    let kp = StarkCurveKeyPairImpl::from_secret_key(0xDEAD_BEEF);
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    // Garbage signature — not a valid ECDSA pair under any private key.
    mig.bootstrap_from_sessions_signed(kp.public_key, verifier, 'x', 0x1, 0x2);
}

#[test]
#[should_panic(expected: 'MIG: bad bootstrap signature')]
fn test_v8_4_signed_bootstrap_rejects_wrong_signer() {
    let (addr, verifier) = declare_and_deploy();
    reset_for_migration_simulation(addr);
    let legitimate = StarkCurveKeyPairImpl::from_secret_key(0xC0FFEE_BEEF);
    let attacker = StarkCurveKeyPairImpl::from_secret_key(0xBAD_DEED);
    // Attacker signs the canonical message with their own key, then
    // submits it claiming to be the legitimate pubkey. Signature is valid
    // under the attacker's pubkey, NOT under the claimed `legitimate.public_key`,
    // so check_ecdsa_signature returns false.
    let msg = compute_bootstrap_message(addr, legitimate.public_key, verifier, 'pwned');
    let (r, s) = attacker.sign(msg).unwrap();
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    mig.bootstrap_from_sessions_signed(legitimate.public_key, verifier, 'pwned', r, s);
}

#[test]
#[should_panic(expected: 'MIG: bad bootstrap signature')]
fn test_v8_4_signed_bootstrap_rejects_cross_account_replay() {
    // Threat model: attacker captures a valid signed-bootstrap signature
    // for account A and tries to re-broadcast on a different stranded
    // account B. Canonical message commits to get_contract_address(), so
    // the same (msg_hash, r, s) tuple fails check_ecdsa_signature at B
    // (B's message hash differs).
    let (addr_a, verifier) = declare_and_deploy();
    let (addr_b, _) = declare_and_deploy();
    reset_for_migration_simulation(addr_b);

    let kp = StarkCurveKeyPairImpl::from_secret_key(0xC0FFEE_BEEF);
    // Sign FOR account A.
    let msg_a = compute_bootstrap_message(addr_a, kp.public_key, verifier, 'orig');
    let (r, s) = kp.sign(msg_a).unwrap();
    // Try to replay on account B — the contract recomputes the canonical
    // message with B's address so the signature check fails.
    let mig_b = IShhhMigrationDispatcher { contract_address: addr_b };
    mig_b.bootstrap_from_sessions_signed(kp.public_key, verifier, 'orig', r, s);
}

#[test]
#[should_panic(expected: 'MIG: bad bootstrap signature')]
fn test_v8_4_signed_bootstrap_rejects_pubkey_substitution() {
    // Threat model: frontrunner captures the user's signed bootstrap tx
    // from the mempool and substitutes their own pubkey before submission.
    // Canonical message commits to public_key, so the verification fails
    // when the contract recomputes the hash with the attacker's pubkey.
    let (addr, verifier) = declare_and_deploy();
    reset_for_migration_simulation(addr);

    let legitimate = StarkCurveKeyPairImpl::from_secret_key(0xC0FFEE_BEEF);
    let attacker = StarkCurveKeyPairImpl::from_secret_key(0xBAD_DEED);
    // User signs the canonical message for THEIR pubkey.
    let msg = compute_bootstrap_message(addr, legitimate.public_key, verifier, 'orig');
    let (r, s) = legitimate.sign(msg).unwrap();
    // Frontrunner substitutes attacker.public_key while reusing (r, s).
    // Contract recomputes the canonical hash with attacker.public_key,
    // gets a different msg_hash, signature check fails.
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    mig.bootstrap_from_sessions_signed(attacker.public_key, verifier, 'orig', r, s);
}

#[test]
#[should_panic(expected: 'MIG: already initialized')]
fn test_v8_4_signed_bootstrap_one_shot_gate() {
    let (addr, verifier) = declare_and_deploy();
    // Account already initialized by the constructor — primary_kind != 0.
    // bootstrap_from_sessions_signed must reject regardless of signature.
    let kp = StarkCurveKeyPairImpl::from_secret_key(0xC0FFEE_BEEF);
    let msg = compute_bootstrap_message(addr, kp.public_key, verifier, 'pwned');
    let (r, s) = kp.sign(msg).unwrap();
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    mig.bootstrap_from_sessions_signed(kp.public_key, verifier, 'pwned', r, s);
}

#[test]
#[should_panic(expected: 'MIG: public_key is zero')]
fn test_v8_4_signed_bootstrap_rejects_zero_pubkey() {
    let (addr, verifier) = declare_and_deploy();
    reset_for_migration_simulation(addr);
    // Caller provides zero pubkey; signature check would never pass even
    // with a "valid" sig under pubkey=0 (ECDSA rejects), but the explicit
    // zero check fires first for a cleaner revert string.
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    mig.bootstrap_from_sessions_signed(0, verifier, 'x', 0x1, 0x2);
}

#[test]
#[should_panic(expected: 'MIG: verifier class zero')]
fn test_v8_4_signed_bootstrap_rejects_zero_verifier() {
    let (addr, _) = declare_and_deploy();
    reset_for_migration_simulation(addr);
    let zero_class: ClassHash = 0.try_into().unwrap();
    let kp = StarkCurveKeyPairImpl::from_secret_key(0xC0FFEE_BEEF);
    let mig = IShhhMigrationDispatcher { contract_address: addr };
    mig.bootstrap_from_sessions_signed(kp.public_key, zero_class, 'x', 0x1, 0x2);
}
