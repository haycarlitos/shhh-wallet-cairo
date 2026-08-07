//! V8 ShhhAccount mirror of the audit-regression suite.
//!
//! The Phase 0 tests in `tests/audit_2026_04_20.cairo` target V7
//! `ShhhWallet` (the audited mainnet contract). V8's `ShhhAccount`
//! implements the same guards in different code paths — the mutation
//! harness (scripts/mutation-test.sh) surfaced that those V8 paths
//! weren't covered. These tests close that gap.

use shhh_wallet::outside_execution::{ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution};
use shhh_wallet::owner_set::interface::ROLE_GUARDIAN;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_caller_address, stop_cheat_caller_address,
};
use starknet::ContractAddress;
use starknet::account::Call;

const SIG_VERSION_V2_SNIP12: felt252 = 'V2_SNIP12';
const TIMELOCK_ADD_OWNER: u64 = 172_800; // 48h — must match account.cairo

// IShhhGov is declared once below (line ~150), with both add-owner and
// set-threshold ops. Tests that need add_owner share the same
// dispatcher.

#[starknet::interface]
trait IAccountExec<TContractState> {
    fn __execute__(ref self: TContractState, calls: Array<Call>) -> Array<Span<felt252>>;
}

fn deploy_account() -> ContractAddress {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, 0xAAAA, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();
    addr
}

// ============================================================
// C-1 on V8 — external __execute__ from a non-zero, non-self caller
// must revert.
// ============================================================

#[test]
#[should_panic(expected: 'C1: unauthorized caller')]
fn test_v8_c1_external_execute_reverts() {
    let addr = deploy_account();
    let attacker: ContractAddress = 0xBAD.try_into().unwrap();
    start_cheat_caller_address(addr, attacker);
    let dispatcher = IAccountExecDispatcher { contract_address: addr };
    let target: ContractAddress = 0xBEEF.try_into().unwrap();
    dispatcher
        .__execute__(
            array![Call { to: target, selector: selector!("noop"), calldata: array![].span() }],
        );
}

// ============================================================
// M-1 on V8 — OE with caller == 0 must revert.
// ============================================================

#[test]
#[should_panic(expected: 'M1: caller=0 rejected')]
fn test_v8_m1_caller_zero_rejected() {
    let addr = deploy_account();
    start_cheat_block_timestamp_global(500);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    let oe = OutsideExecution {
        caller: 0.try_into().unwrap(),
        nonce: 1,
        execute_after: 0,
        execute_before: 1000,
        calls: array![].span(),
    };
    src9.execute_from_outside_v2(oe, array![0, 0, 0].span());
}

// ============================================================
// M-2 on V8 — ANY_CALLER validity window cap.
// ============================================================

#[test]
#[should_panic(expected: 'M2: window too long')]
fn test_v8_m2_window_cap() {
    let addr = deploy_account();
    start_cheat_block_timestamp_global(500);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    // MAX_ANY_CALLER_VALIDITY_SECONDS = 7200.
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 2,
        execute_after: 0,
        execute_before: 7201, // one second past the cap
        calls: array![].span(),
    };
    src9.execute_from_outside_v2(oe, array![0, 0, 0].span());
}

// ============================================================
// M-3 on V8 — signature length > MAX_SIGNATURE_FELTS fires early.
// ============================================================

#[test]
#[should_panic(expected: 'M3: signature too long')]
fn test_v8_m3_signature_too_long() {
    let addr = deploy_account();
    start_cheat_block_timestamp_global(500);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 3,
        execute_after: 0,
        execute_before: 1000,
        calls: array![].span(),
    };
    let mut sig: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < 1025_u32 {
        sig.append(0);
        i += 1;
    }
    src9.execute_from_outside_v2(oe, sig.span());
}
// ============================================================
// Timelock boundary — execution at EXACTLY `valid_after` must succeed.
// Kills the `>=` → `>` off-by-one mutant.
// ============================================================

#[starknet::interface]
trait IShhhGov<TContractState> {
    fn propose_set_threshold(ref self: TContractState, proposer: u32, new: u8) -> felt252;
    fn execute_set_threshold(ref self: TContractState, op_id: felt252, new: u8);
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
}

const TIMELOCK_SET_THRESHOLD: u64 = 172_800; // 48h — mirrors pending_ops.cairo

#[test]
#[should_panic(expected: 'OWNERS: threshold == 0')]
fn test_v8_timelock_boundary_accepts_at_valid_after() {
    // The op's valid_after = propose_ts + TIMELOCK. Advancing to
    // EXACTLY that timestamp must let execute() proceed past the
    // timelock check — it then fails on the threshold==0 invariant
    // inside OwnerSetComponent::set_threshold, which is what the
    // should_panic matches. If the mutant flips `>=` to `>`, the
    // timelock check rejects this timestamp and the panic class
    // changes → mutant killed.
    let addr = deploy_account();
    let gov = IShhhGovDispatcher { contract_address: addr };
    let propose_ts: u64 = 1_000_000;

    start_cheat_block_timestamp_global(propose_ts);
    start_cheat_caller_address(addr, addr);
    let op_id = gov.propose_set_threshold(0_u32, 0_u8);

    // Exactly at valid_after — passes `now >= valid_after`,
    // fails `now > valid_after`.
    start_cheat_block_timestamp_global(propose_ts + TIMELOCK_SET_THRESHOLD);
    gov.execute_set_threshold(op_id, 0_u8);
}

// ============================================================
// H-1 atomic multicall — sub-call failure inside a self-invoked
// multicall (via __execute__) must revert the whole batch with
// 'H1: subcall failed'. Uses the Target helper's known panicking
// selector (selector!("noop") is not exported → dispatch fails).
// ============================================================

#[test]
#[should_panic(expected: 'H1: subcall failed')]
fn test_v8_h1_atomic_multicall_propagates_failure() {
    let addr = deploy_account();
    // Deploy a real target so dispatch reaches the callee; a bogus
    // selector there makes the subcall fail. The H-1 guard must
    // propagate the failure as 'H1: subcall failed'. If the mutant
    // swallows it, the multicall returns normally and the test fails.
    let target_class = declare("Target").unwrap().contract_class();
    let (target, _) = target_class.deploy(@array![]).unwrap();
    start_cheat_caller_address(addr, addr);
    let dispatcher = IAccountExecDispatcher { contract_address: addr };
    dispatcher
        .__execute__(
            array![
                Call {
                    to: target,
                    selector: selector!("this_selector_does_not_exist"),
                    calldata: array![].span(),
                },
            ],
        );
}
// ============================================================
// V8 blocklist — session keys can't reach governance / recovery /
// migration selectors even if the whitelist allows them.
//
// Setup:
//   1. Add a session key with whitelist = [selector("initiate_recovery")]
//   2. Submit a 4-element session sig OE that calls
//      self.initiate_recovery(...). is_session_allowed_for_calls
//      accepts (selector is in whitelist, caller is self-call... but
//      empty-whitelist self-call block doesn't apply because the
//      whitelist is non-empty).
//   3. V8 blocklist (_v8_blocklist_ok) MUST fire with
//      'SESSION: V8-blocked selector'. If the mutant drops the
//      initiate_recovery entry, the call slips to the ECDSA verify
//      stage → different panic class → mutant killed.
// ============================================================

#[starknet::interface]
trait IShhhSessions<TContractState> {
    fn add_or_update_session_key(
        ref self: TContractState,
        session_key: felt252,
        valid_until: u64,
        max_calls: u32,
        allowed_entrypoints: Array<felt252>,
    );
}

#[test]
#[should_panic(expected: 'SESSION: V8-blocked selector')]
fn test_v8_blocklist_rejects_session_initiate_recovery() {
    let addr = deploy_account();
    let sessions = IShhhSessionsDispatcher { contract_address: addr };
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };

    // Add a session key with an explicit whitelist permitting
    // initiate_recovery — this bypasses the ported SNIPs#163 empty-
    // whitelist self-call block, forcing the flow to reach the V8
    // blocklist check next.
    start_cheat_caller_address(addr, addr);
    sessions
        .add_or_update_session_key(
            0xDEAD, 10_000_u64, 10_u32, array![selector!("initiate_recovery")],
        );

    // Submit a 4-element session signature. r, s, valid_until are
    // placeholder — the V8 blocklist fires BEFORE ECDSA verify.
    start_cheat_block_timestamp_global(500);
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 0x1234,
        execute_after: 0,
        execute_before: 1000,
        calls: array![
            Call {
                to: addr, // self-call to initiate_recovery
                selector: selector!("initiate_recovery"),
                calldata: array![].span(),
            },
        ]
            .span(),
    };
    // [session_pubkey, r, s, valid_until]
    let sig = array![0xDEAD, 0xAA, 0xBB, 10_000].span();
    src9.execute_from_outside_v2(oe, sig);
}
// ============================================================
// Audit C-1 (2026-05-07 self-review) — guardian role MUST NOT be able
// to sign an arbitrary OE. Without `assert(owner.role == ROLE_OWNER)`
// in the OE verify path, a non-revoked GUARDIAN was indistinguishable
// from a primary owner and could drain the account. The role check
// fires BEFORE the verifier dispatch, so even an envelope with a
// junk signature payload reverts with 'SHHH: signer not an owner'.
// ============================================================

fn deploy_account_with_guardian() -> (ContractAddress, u32) {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let calldata: Array<felt252> = array!['STARK', verifier_class.into(), 1, 0xAAAA, 'primary'];
    let (addr, _) = account_class.deploy(@calldata).unwrap();

    // Add a guardian via the timelocked propose/execute flow (self-call).
    let gov = IShhhGovDispatcher { contract_address: addr };
    start_cheat_block_timestamp_global(100);
    start_cheat_caller_address(addr, addr);
    let op_id = gov
        .propose_add_owner(0_u32, 'STARK', array![0xCCCC], ROLE_GUARDIAN, 1_u8, 'guardian');
    start_cheat_block_timestamp_global(100 + TIMELOCK_ADD_OWNER + 1);
    let guardian_id = gov
        .execute_add_owner(op_id, 'STARK', array![0xCCCC], ROLE_GUARDIAN, 1_u8, 'guardian');
    (addr, guardian_id)
}

#[test]
#[should_panic(expected: 'SHHH: signer not an owner')]
fn test_v8_audit_c1_guardian_cannot_sign_oe() {
    let (addr, guardian_id) = deploy_account_with_guardian();
    // The fixture left `start_cheat_caller_address(addr, addr)` active for
    // the propose/execute self-call. Drop it so the OE submission below
    // doesn't appear to come from the account itself.
    stop_cheat_caller_address(addr);
    let now: u64 = 100 + TIMELOCK_ADD_OWNER + 100;
    start_cheat_block_timestamp_global(now);
    let src9 = ISRC9_V2Dispatcher { contract_address: addr };
    // ANY_CALLER caps the validity window at 7200s (M-2); keep ours
    // well inside that. execute_after < now < execute_before.
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 0xC1,
        execute_after: now - 10,
        execute_before: now + 10,
        calls: array![].span(),
    };
    // Envelope shape: [version, owner_id, kind_tag, ...verifier_payload].
    // The role check fires before the verifier runs, so a junk payload
    // is fine — the panic must come from the role assertion, not from
    // signature validation.
    let envelope: Array<felt252> = array![SIG_VERSION_V2_SNIP12, guardian_id.into(), 'STARK', 0, 0];
    src9.execute_from_outside_v2(oe, envelope.span());
}
// ============================================================
// Audit M-3 (2026-05-07 self-review) — V8 mirrors of the V7
// audit-regression suite. The 2026-04-20 audit was tested against
// V7 (`ShhhWallet`); mainnet has been declaring V8 (`ShhhAccount`)
// since 2026-04-28, so the same guards need V8-specific covers.
//
//   M-3a: H-2 — canonical SRC9_V2 interface ID is registered on a
//         freshly-deployed V8 account.
//   M-3b: I-3 — V8 has no `upgrade` selector; calling it must
//         revert (entrypoint not found / unimplemented).
//   M-3c: L-1 — V8 constructor refuses a primary kind of zero.
//   M-4 (per-verifier trailing-bytes) is regression-tested inside
//         each verifier's own test suite (e.g.
//         `tests/signer_jwt_es256.cairo::test_rejects_extra_trailing_bytes`).
// ============================================================

#[starknet::interface]
trait ISRC5<TContractState> {
    fn supports_interface(self: @TContractState, interface_id: felt252) -> bool;
}

const ISRC9_V2_ID: felt252 = 0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872;

#[test]
fn test_v8_audit_m3_h2_registers_canonical_snip9_id() {
    let addr = deploy_account();
    let src5 = ISRC5Dispatcher { contract_address: addr };
    assert(src5.supports_interface(ISRC9_V2_ID), 'V8 H2: canonical id missing');
}

#[starknet::interface]
trait IMaybeUpgradeable<TContractState> {
    fn upgrade(ref self: TContractState, new_class_hash: starknet::ClassHash);
}

#[test]
#[should_panic]
fn test_v8_audit_m3_i3_no_upgrade_entrypoint() {
    // Audit I-3: V8 deliberately ships without an `upgrade` selector
    // (only the one-shot `bootstrap_from_sessions` migration path
    // exists). A direct call to `upgrade(...)` MUST revert because
    // the selector is not exported. snforge's dispatcher panics on
    // entrypoint-not-found.
    let addr = deploy_account();
    let dispatcher = IMaybeUpgradeableDispatcher { contract_address: addr };
    dispatcher.upgrade(0xdead.try_into().unwrap());
}

#[test]
#[should_panic]
fn test_v8_audit_m3_l1_constructor_rejects_zero_kind() {
    // Audit L-1 (V7) on V8: deploying with `primary_kind == 0`
    // would leave the dispatcher unable to resolve the verifier
    // class for its own primary owner. The constructor's
    // `'L1: primary_kind is zero'` assertion blocks this.
    let v = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let cls = declare("ShhhAccount").unwrap().contract_class();
    // [primary_kind=0, verifier_class, pubkey_len=1, pubkey, label]
    let calldata: Array<felt252> = array![0, v.into(), 1, 0xAAAA, 'x'];
    cls.deploy(@calldata).unwrap();
}

// ============================================================
// Audit M-2 (2026-05-07 self-review) — verifier reentrancy guard.
// A library-call'd verifier MUST NOT be able to recurse into a
// `_assert_self_call`-gated mutator: with the `inside_verifier`
// flag held high during `dispatcher.verify(...)`, any self-call to
// `propose_add_owner` / `set_spending_policy` / `cancel_recovery`
// reverts with 'SHHH: verifier reentry'.
//
// Direct positive test would require a malicious verifier helper
// class. The flag's effect is observable indirectly: a regular
// owner-self-call to `propose_set_threshold` (NOT inside a verifier)
// must still succeed — confirming the flag does not leak into
// legitimate flows. This complements the negative case which is
// expressed by inspection of the storage-flag invariant.
// ============================================================

#[test]
fn test_v8_audit_m2_self_call_outside_verifier_succeeds() {
    let addr = deploy_account();
    let gov = IShhhGovDispatcher { contract_address: addr };
    start_cheat_block_timestamp_global(1_000_000);
    start_cheat_caller_address(addr, addr);
    // Should NOT panic: inside_verifier is false here, so
    // _assert_self_call passes both checks.
    let _op_id = gov.propose_set_threshold(0_u32, 1_u8);
}
// ============================================================
// Nonce replay on V8 — handled by the Phase 11 STARK-signed e2e test.
//
// Within a single failing tx the nonce write is rolled back with the
// rest of the state, so a "consume then fail" scenario is not
// expressible in snforge unit tests. A fixture-driven OE that
// succeeds on first submission and reverts with 'SRC9: duplicate
// nonce' on the second is the correct covering test and lands
// alongside the Phase 11 STARK-session-signed fixture.
// ============================================================


