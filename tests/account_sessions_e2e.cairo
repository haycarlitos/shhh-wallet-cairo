//! Phase 11 E2E — session-key spending caps through the real 4-element
//! outside-execution path.
//!
//! `tests/account_sessions.cairo` proves the *management* surface
//! (set/remove policy, the H-3 window-preservation fix) but stops short
//! of driving a spend through a session signature, because that needs a
//! STARK session-signer fixture + a token to spend against. This file
//! closes that gap. It is the in-CI mirror of mainnet smoke "Test 14".
//!
//! The account under test is the V8.4 `ShhhAccount` source (class
//! `0x075dfb39…fa58a` on mainnet). The enforcement lives at
//! `account.cairo:397` — `check_and_update_spending` runs *before*
//! `_execute_calls_atomic_span`, so an over-cap call is rejected at the
//! policy gate and never reaches the token.
//!
//! Scenarios:
//!   1. In-cap spend SUCCEEDS — the transfer reaches the token, the
//!      session call counter and `spent_in_window` both advance, and the
//!      window anchors at the first spend.
//!   2. Over-`max_per_call` spend REVERTS (`'Spending: exceeds per-call'`)
//!      and the token is never touched.
//!   3. Cumulative over-`max_per_window` spend REVERTS
//!      (`'Spending: exceeds window limit'`) — first spend lands, the
//!      second tips the rolling total over and is rejected.
//!   4. Window rollover — after `window_seconds` elapses the budget
//!      resets and a fresh in-cap spend SUCCEEDS again.

#[feature("safe_dispatcher")]
use shhh_wallet::outside_execution::{
    ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, ISRC9_V2SafeDispatcher,
    ISRC9_V2SafeDispatcherTrait, OutsideExecution, compute_snip12_hash,
};
use shhh_wallet::session_key::interface::SessionData;
use shhh_wallet::spending_policy::interface::SpendingPolicy;
use shhh_wallet::test_helpers::mock_erc20::{IMockErc20Dispatcher, IMockErc20DispatcherTrait};
use snforge_std::signature::SignerTrait;
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp_global,
    start_cheat_caller_address, start_cheat_chain_id_global, stop_cheat_caller_address,
};
use starknet::ContractAddress;
use starknet::account::Call;

// --------------------------------------------------------------
// Account ABI — session + spending-policy management reads/writes.
// --------------------------------------------------------------

#[starknet::interface]
trait IShhhSessions<TContractState> {
    fn add_or_update_session_key(
        ref self: TContractState,
        session_key: felt252,
        valid_until: u64,
        max_calls: u32,
        allowed_entrypoints: Array<felt252>,
    );
    fn get_session_data(self: @TContractState, session_key: felt252) -> SessionData;
    fn set_spending_policy(
        ref self: TContractState,
        session_key: felt252,
        token: ContractAddress,
        max_per_call: u256,
        max_per_window: u256,
        window_seconds: u64,
    );
    fn get_spending_policy(
        self: @TContractState, session_key: felt252, token: ContractAddress,
    ) -> SpendingPolicy;
}

const OWNER_SECRET: felt252 = 0xA11CE_A11CE_BEEF;
const SESSION_SECRET: felt252 = 0x5E5510_05E55_BEEF;
const RECIPIENT: felt252 = 0x111;

// Policy: 100 per call, 150 per rolling window, 1h window.
const MAX_PER_CALL: u256 = 100;
const MAX_PER_WINDOW: u256 = 150;
const WINDOW_SECONDS: u64 = 3_600;
const SESSION_VALID_UNTIL: u64 = 2_000_000;

// --------------------------------------------------------------
// Fixture: deploy a STARK-owner V8.4 account + a mock ERC-20, then
// register a session key (whitelisted for `transfer`) and a spending
// policy on that token. Returns (account, token, session_key).
// --------------------------------------------------------------

fn setup() -> (ContractAddress, ContractAddress, felt252) {
    let verifier_class = *declare("StarkVerifier").unwrap().contract_class().class_hash;
    let account_class = declare("ShhhAccount").unwrap().contract_class();
    let owner_kp = StarkCurveKeyPairImpl::from_secret_key(OWNER_SECRET);
    let calldata: Array<felt252> = array![
        'STARK', verifier_class.into(), 1, owner_kp.public_key, 'primary',
    ];
    let (account, _) = account_class.deploy(@calldata).unwrap();

    let token_class = declare("MockErc20").unwrap().contract_class();
    let (token, _) = token_class.deploy(@array![]).unwrap();

    let session_kp = StarkCurveKeyPairImpl::from_secret_key(SESSION_SECRET);
    let session_key = session_kp.public_key;

    // Owner registers the session key + spending policy via self-call.
    start_cheat_block_timestamp_global(1_000);
    start_cheat_caller_address(account, account);
    let s = IShhhSessionsDispatcher { contract_address: account };
    s.add_or_update_session_key(session_key, SESSION_VALID_UNTIL, 10_u32, array![selector!("transfer")]);
    s.set_spending_policy(session_key, token, MAX_PER_CALL, MAX_PER_WINDOW, WINDOW_SECONDS);
    stop_cheat_caller_address(account);

    (account, token, session_key)
}

/// Build a `transfer(recipient, amount)` OE and sign it with the session
/// key. The 4-element session envelope is `[session_pubkey, r, s,
/// valid_until]`; the account routes on `signature.len() == 4`.
fn build_session_spend(
    account: ContractAddress,
    token: ContractAddress,
    amount: u256,
    nonce: felt252,
    exec_after: u64,
    exec_before: u64,
) -> (OutsideExecution, Array<felt252>) {
    // ERC-20 `transfer` calldata = [recipient, amount.low, amount.high] —
    // exactly the slots `check_and_update_spending` reads for the amount.
    let calldata: Array<felt252> = array![RECIPIENT, amount.low.into(), amount.high.into()];
    let call = Call {
        to: token, selector: selector!("transfer"), calldata: calldata.span(),
    };
    let oe = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce,
        execute_after: exec_after,
        execute_before: exec_before,
        calls: array![call].span(),
    };

    let hash = compute_snip12_hash(@oe, account.into(), 'SN_MAIN');
    let session_kp = StarkCurveKeyPairImpl::from_secret_key(SESSION_SECRET);
    let (r, s) = session_kp.sign(hash).unwrap();
    let envelope: Array<felt252> = array![
        session_kp.public_key, r, s, SESSION_VALID_UNTIL.into(),
    ];
    (oe, envelope)
}

// ==========================================================
// 1. In-cap spend succeeds end-to-end.
// ==========================================================

#[test]
fn test_e2e_in_cap_spend_succeeds() {
    let (account, token, session_key) = setup();
    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_block_timestamp_global(1_000_001);

    let (oe, envelope) = build_session_spend(
        account, token, 100_u256, 'spend-1', 1_000_000, 1_003_600,
    );
    let src9 = ISRC9_V2Dispatcher { contract_address: account };
    src9.execute_from_outside_v2(oe, envelope.span());

    // The transfer actually reached the token.
    let erc20 = IMockErc20Dispatcher { contract_address: token };
    assert(erc20.transfer_count() == 1_u32, 'transfer did not run');
    assert(erc20.total_transferred() == 100_u256, 'wrong amount moved');

    // Session call budget consumed.
    let sess = IShhhSessionsDispatcher { contract_address: account };
    let d = sess.get_session_data(session_key);
    assert(d.calls_used == 1_u32, 'session call not consumed');

    // Spend recorded; window anchored at the first spend (not setup time).
    let p = sess.get_spending_policy(session_key, token);
    assert(p.spent_in_window == 100_u256, 'spent_in_window wrong');
    assert(p.window_start == 1_000_001_u64, 'window not anchored at spend');
}

// ==========================================================
// 2. Over-per-call spend reverts at the policy gate, and the token is
//    never touched — proving the cap check runs BEFORE the call loop.
//    Uses the safe dispatcher so we can assert the side effect survives
//    the revert (a `should_panic` test can't observe post-revert state).
// ==========================================================

#[test]
fn test_e2e_over_per_call_reverts_before_token_called() {
    let (account, token, _) = setup();
    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_block_timestamp_global(1_000_001);

    // 101 > max_per_call (100) → rejected at the policy gate.
    let (oe, envelope) = build_session_spend(
        account, token, 101_u256, 'spend-over-call', 1_000_000, 1_003_600,
    );
    let src9 = ISRC9_V2SafeDispatcher { contract_address: account };
    match src9.execute_from_outside_v2(oe, envelope.span()) {
        Result::Ok(_) => core::panic_with_felt252('over-cap call should revert'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'Spending: exceeds per-call', 'wrong revert reason');
        },
    }

    // The transfer never reached the token — the gate fires first.
    let erc20 = IMockErc20Dispatcher { contract_address: token };
    assert(erc20.transfer_count() == 0_u32, 'token must be untouched');
    assert(erc20.total_transferred() == 0_u256, 'no amount should move');
}

// ==========================================================
// 3. Cumulative over-window spend reverts; first spend stands.
// ==========================================================

#[test]
#[should_panic(expected: 'Spending: exceeds window limit')]
fn test_e2e_over_window_cumulative_reverts() {
    let (account, token, _) = setup();
    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_block_timestamp_global(1_000_001);
    let src9 = ISRC9_V2Dispatcher { contract_address: account };

    // First in-cap spend: 100 ≤ 150 → lands. spent_in_window = 100.
    let (oe1, env1) = build_session_spend(
        account, token, 100_u256, 'win-1', 1_000_000, 1_003_600,
    );
    src9.execute_from_outside_v2(oe1, env1.span());

    // Second spend 100: cumulative 200 > max_per_window (150) → revert.
    let (oe2, env2) = build_session_spend(
        account, token, 100_u256, 'win-2', 1_000_000, 1_003_600,
    );
    src9.execute_from_outside_v2(oe2, env2.span());
}

// ==========================================================
// 4. Window rollover — budget resets after window_seconds.
// ==========================================================

#[test]
fn test_e2e_window_rollover_resets_budget() {
    let (account, token, session_key) = setup();
    start_cheat_chain_id_global('SN_MAIN');
    let src9 = ISRC9_V2Dispatcher { contract_address: account };

    // First spend at t=1_000_001 → window anchors here, spent = 100.
    start_cheat_block_timestamp_global(1_000_001);
    let (oe1, env1) = build_session_spend(
        account, token, 100_u256, 'roll-1', 1_000_000, 1_003_600,
    );
    src9.execute_from_outside_v2(oe1, env1.span());

    // Advance exactly one window: now = window_start + window_seconds.
    // The next spend must auto-reset spent_in_window to 0 then add 100.
    let rolled = 1_000_001 + WINDOW_SECONDS; // 1_003_601
    start_cheat_block_timestamp_global(rolled);
    let (oe2, env2) = build_session_spend(
        account, token, 100_u256, 'roll-2', rolled - 1, rolled + WINDOW_SECONDS,
    );
    src9.execute_from_outside_v2(oe2, env2.span());

    // Both spends landed on the token...
    let erc20 = IMockErc20Dispatcher { contract_address: token };
    assert(erc20.transfer_count() == 2_u32, 'both spends should run');
    assert(erc20.total_transferred() == 200_u256, 'total moved wrong');

    // ...but the window budget shows only the post-rollover spend.
    let sess = IShhhSessionsDispatcher { contract_address: account };
    let p = sess.get_spending_policy(session_key, token);
    assert(p.spent_in_window == 100_u256, 'window did not reset');
    assert(p.window_start == rolled, 'window_start not re-anchored');
}
