//! Audit M-3 (V8.3, 2026-05-10) — adversarial verifier helpers used
//! by the negative regression tests for the M-1 / M-2 / V8.3 reentrancy
//! claims.
//!
//! Three test verifier classes:
//!
//! 1. `EvilReentrantVerifier` — declares kind 'TEST' and on
//!    `validate_pubkey` issues a `call_contract_syscall` back into
//!    `propose_set_threshold` on the host account. Used to prove the
//!    V8.3 `inside_verifier` flag wrap on the validate_pubkey path
//!    actually fires.
//!
//! 2. `EvilReturnTrueVerifier` — also kind 'TEST'. `verify` always
//!    returns true, `validate_pubkey` accepts any input. Used by tests
//!    that need a verifier they fully control without a real signing
//!    primitive in the loop.
//!
//! 3. `EvilPanicVerifier` — kind 'TEST'. `verify` and
//!    `validate_pubkey` both `panic_with_felt252(...)`. Used by the
//!    storage-write-atomicity-under-panic regression (audit
//!    informational finding) — proves a panic inside the verifier
//!    library_call unwinds the `inside_verifier` flag write together
//!    with the rest of the tx.
//!
//! All three implement the full ISigner V8.2+ trait shape (`verify`,
//! `kind`, `validate_pubkey`).

// =====================================================================
//  EvilReentrantVerifier — re-enters into a self-call gated mutator
// =====================================================================

#[starknet::contract]
pub mod EvilReentrantVerifier {
    use starknet::syscalls::call_contract_syscall;
    use starknet::{SyscallResultTrait, get_contract_address};
    use crate::signer::interface::ISigner;

    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl ISignerImpl of ISigner<ContractState> {
        fn verify(
            self: @ContractState,
            message_hash: felt252,
            pubkey: Span<felt252>,
            signature: Span<felt252>,
        ) -> bool {
            // Mirror the validate_pubkey reentry attempt so this
            // verifier can also be used by the M-2 verify-path
            // regression (the in-tree audit_v8 test for that path
            // checks the symmetric flag behaviour).
            //
            // Audit C-2 (2026-05-11): `.unwrap_syscall()` MUST mirror
            // the validate_pubkey method below. Without it the syscall
            // result is silently discarded — a panic from the
            // host account's `_assert_self_call` ('SHHH: verifier
            // reentry') wouldn't surface, the function would return
            // `true`, and any verify-path M-2 negative test using
            // this helper would silently pass for the wrong reason.
            let target: starknet::ContractAddress = get_contract_address();
            let calldata: Array<felt252> = array![0_felt252, 1_felt252];
            let _ = call_contract_syscall(
                target, selector!("propose_set_threshold"), calldata.span(),
            )
                .unwrap_syscall();
            true
        }

        fn kind(self: @ContractState) -> felt252 {
            'TEST'
        }

        fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
            // Attempt to re-enter the host account from inside the
            // library_call. If V8.3's `inside_verifier` wrap is
            // working the syscall reverts with 'SHHH: verifier
            // reentry' and propagates up to our caller. If the
            // wrap is missing the syscall succeeds and we return
            // true — the test catches the difference by asserting
            // on the panic message.
            let target: starknet::ContractAddress = get_contract_address();
            // propose_set_threshold takes (proposer: u32, new: u8).
            let calldata: Array<felt252> = array![0_felt252, 1_felt252];
            let _ = call_contract_syscall(
                target, selector!("propose_set_threshold"), calldata.span(),
            )
                .unwrap_syscall();
            true
        }
    }
}

// =====================================================================
//  EvilReturnTrueVerifier — accepts everything
// =====================================================================

#[starknet::contract]
pub mod EvilReturnTrueVerifier {
    use crate::signer::interface::ISigner;

    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl ISignerImpl of ISigner<ContractState> {
        fn verify(
            self: @ContractState,
            message_hash: felt252,
            pubkey: Span<felt252>,
            signature: Span<felt252>,
        ) -> bool {
            true
        }

        fn kind(self: @ContractState) -> felt252 {
            'TEST'
        }

        fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
            true
        }
    }
}

// =====================================================================
//  EvilPanicVerifier — panics on every method
// =====================================================================

#[starknet::contract]
pub mod EvilPanicVerifier {
    use crate::signer::interface::ISigner;

    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl ISignerImpl of ISigner<ContractState> {
        fn verify(
            self: @ContractState,
            message_hash: felt252,
            pubkey: Span<felt252>,
            signature: Span<felt252>,
        ) -> bool {
            core::panic_with_felt252('EVIL: verify panicked')
        }

        fn kind(self: @ContractState) -> felt252 {
            'TEST'
        }

        fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
            core::panic_with_felt252('EVIL: validate panicked')
        }
    }
}
