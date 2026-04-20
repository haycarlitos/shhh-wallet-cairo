//! ShhhAccount — the single V8 account class.
//!
//! This file is the *skeleton* — it pins the ABI, wires every component,
//! and documents every audit-required guard. Bodies marked `TODO(v8)`
//! will be filled during the week-by-week implementation track in
//! `docs/shhh-v8-robust-plan.md` §9.
//!
//! Mapping from audit findings (2026-04-20) to guards in this file:
//!
//!   C-1 → `__execute__` asserts `caller.is_zero() || caller == self`
//!         + tx_info.version >= 1 before touching any storage.
//!   H-1 → `_execute_calls` panics on any subcall `Err(_)`.
//!   H-2 → `execute_from_outside_v2` hashes via SNIP-12 typed data and
//!         registers the canonical `ISRC9_V2_ID`.
//!   M-1 → Outside-execution caller check rejects `caller == 0`;
//!         only `'ANY_CALLER'` unlocks the unrestricted path.
//!   M-2 → `MAX_ANY_CALLER_VALIDITY_SECONDS = 7200` cap on the
//!         (execute_before - execute_after) window for ANY_CALLER ops.
//!   M-3 → `MAX_CALLS`, `MAX_TOTAL_CALLDATA_FELTS`, `MAX_SIGNATURE_FELTS`
//!         enforced before hashing / library_call.
//!   M-4 → Envelope parsers assert `signature.len() >= 5 + msg_len` and
//!         `sig_span.is_empty()` after Serde deserialize.
//!   L-1 → Constructor delegates key-material validation to the
//!         primary-kind verifier via `library_call`.
//!   I-1 → No custom calls-hash. SNIP-12 typed data is the sole
//!         primary hashing path.
//!   I-3 → No `UpgradeableComponent`. This class is immutable by design;
//!         operational changes route through recovery + redeploy.

#[starknet::contract(account)]
pub mod ShhhAccount {
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_contract_address,
        get_block_timestamp, get_tx_info,
    };
    use starknet::storage::{
        Map, StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
    };
    use starknet::account::Call;

    use crate::owner_set::component::OwnerSetComponent;
    use crate::governance::component::GovernanceComponent;
    use crate::recovery::component::RecoveryComponent;
    use crate::session_key::component::SessionKeyComponent;
    use crate::spending_policy::component::SpendingPolicyComponent;

    use crate::signer::interface::{
        ISIGNER_ID,
        parse_owner_envelope_header,
    };

    // ------------------------------------------------------------------
    // Audit-driven bounds (M-2, M-3).
    // Values chosen to cover Cifra / Shhh worst-case flows:
    //   - 3-call bet flow (approve / shield / place_bet) ≪ MAX_CALLS.
    //   - Ed25519 + Garaga hints ≈ 700 felts ≪ MAX_SIGNATURE_FELTS per envelope.
    //   - CCTP pre-sign OE finishes in 20–30 min ≪ 2h cap.
    // ------------------------------------------------------------------
    pub const MAX_CALLS:                       u32 = 16;
    pub const MAX_TOTAL_CALLDATA_FELTS:        u32 = 1024;
    pub const MAX_SIGNATURE_FELTS:             u32 = 1024;
    pub const MAX_ANY_CALLER_VALIDITY_SECONDS: u64 = 7_200;

    // ------------------------------------------------------------------
    // Component wiring
    // ------------------------------------------------------------------

    component!(path: OwnerSetComponent,       storage: owners,          event: OwnerSetEvent);
    component!(path: GovernanceComponent,     storage: governance,      event: GovernanceEvent);
    component!(path: RecoveryComponent,       storage: recovery,        event: RecoveryEvent);
    component!(path: SessionKeyComponent,     storage: session_key,     event: SessionKeyEvent);
    component!(path: SpendingPolicyComponent, storage: spending_policy, event: SpendingPolicyEvent);

    impl OwnerSetInternal       = OwnerSetComponent::InternalImpl<ContractState>;
    impl GovernanceInternal     = GovernanceComponent::InternalImpl<ContractState>;
    impl RecoveryInternal       = RecoveryComponent::InternalImpl<ContractState>;
    impl SessionKeyInternal     = SessionKeyComponent::InternalImpl<ContractState>;
    impl SpendingPolicyInternal = SpendingPolicyComponent::InternalImpl<ContractState>;

    // HasAccountOwner plumbing — session_key + spending_policy components
    // need an owner-only self-call gate. We satisfy it by asserting
    // `caller == self`, which is the contract calling itself via
    // __execute__ after a verified owner-threshold signature.
    impl SessionKeyHasOwnerImpl of SessionKeyComponent::HasAccountOwner<ContractState> {
        fn assert_only_self(self: @ContractState) {
            assert(get_caller_address() == get_contract_address(), 'SHHH: caller != self');
        }
    }
    impl SpendingPolicyHasOwnerImpl of SpendingPolicyComponent::HasAccountOwner<ContractState> {
        fn assert_only_self(self: @ContractState) {
            assert(get_caller_address() == get_contract_address(), 'SHHH: caller != self');
        }
    }

    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------

    #[storage]
    struct Storage {
        // Verifier class registry — kind_tag → library-call target.
        // Governed by unanimous existing owners (see plan §3.3).
        verifier_classes: Map<felt252, ClassHash>,

        // SNIP-9 V2 nonce replay protection.
        oe_nonces: Map<felt252, bool>,

        // Primary-owner binding, captured at deploy. Fixes the address
        // salt so adding/removing owners later does not mutate the
        // address. (§3.8 deterministic addresses.)
        primary_kind:        felt252,
        primary_pubkey_hash: felt252,

        #[substorage(v0)] owners:          OwnerSetComponent::Storage,
        #[substorage(v0)] governance:      GovernanceComponent::Storage,
        #[substorage(v0)] recovery:        RecoveryComponent::Storage,
        #[substorage(v0)] session_key:     SessionKeyComponent::Storage,
        #[substorage(v0)] spending_policy: SpendingPolicyComponent::Storage,
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat] OwnerSetEvent:       OwnerSetComponent::Event,
        #[flat] GovernanceEvent:     GovernanceComponent::Event,
        #[flat] RecoveryEvent:       RecoveryComponent::Event,
        #[flat] SessionKeyEvent:     SessionKeyComponent::Event,
        #[flat] SpendingPolicyEvent: SpendingPolicyComponent::Event,
        VerifierClassAdded:          VerifierClassAdded,
        VerifierClassRemoved:        VerifierClassRemoved,
    }

    #[derive(Drop, starknet::Event)]
    struct VerifierClassAdded {
        #[key] kind: felt252,
        class_hash: ClassHash,
    }
    #[derive(Drop, starknet::Event)]
    struct VerifierClassRemoved {
        #[key] kind: felt252,
    }

    // ------------------------------------------------------------------
    // Constructor
    //
    // Deploy calldata (audit L-1: primary verifier validates key material):
    //   [ primary_kind,
    //     primary_verifier_class_hash,
    //     pubkey_len, pubkey_0, ..., pubkey_n,
    //     label ]
    // ------------------------------------------------------------------

    #[constructor]
    fn constructor(
        ref self: ContractState,
        primary_kind: felt252,
        primary_verifier: ClassHash,
        pubkey: Span<felt252>,
        label: felt252,
    ) {
        self.primary_kind.write(primary_kind);

        // TODO(v8, L-1): library_call into primary_verifier's
        // `validate_pubkey(pubkey)` helper before storing it. Reject
        // malformed / out-of-range key material with a controlled revert
        // so factories cannot deploy bricked accounts.

        let pubkey_hash = crate::signer::interface::owner_commitment(primary_kind, pubkey);
        self.primary_pubkey_hash.write(pubkey_hash);
        self.verifier_classes.write(primary_kind, primary_verifier);
        self.owners.initialize_primary(primary_kind, pubkey_hash, pubkey, label);
    }

    // ------------------------------------------------------------------
    // __validate__ — always reverts.
    //
    // Design decision: all owner-authorized action in V8 goes through
    // `execute_from_outside_v2`. `__validate__` exists only to satisfy
    // SNIP-6 / account-contract probing, and it MUST refuse every call
    // so that stray invoke transactions cannot reach `__execute__`.
    // ------------------------------------------------------------------

    #[external(v0)]
    fn __validate__(ref self: ContractState, _calls: Array<Call>) -> felt252 {
        core::panic_with_felt252('SHHH: __validate__ disabled')
    }

    #[external(v0)]
    fn __validate_declare__(self: @ContractState, _class_hash: felt252) -> felt252 {
        core::panic_with_felt252('SHHH: declare disabled')
    }

    #[external(v0)]
    fn __validate_deploy__(
        self: @ContractState,
        _class_hash: felt252,
        _salt: felt252,
        _primary_kind: felt252,
        _primary_verifier: ClassHash,
        _pubkey: Span<felt252>,
        _label: felt252,
    ) -> felt252 {
        // Deploy is sponsored by a paymaster; no owner signature verified here.
        // The address-salt binding in §3.8 is the integrity guarantee.
        starknet::VALIDATED
    }

    // ------------------------------------------------------------------
    // __execute__ — protocol / paymaster-estimation path ONLY.
    //
    // Audit C-1 guard: must reject non-protocol, non-self callers.
    // ------------------------------------------------------------------

    #[external(v0)]
    fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
        let caller = get_caller_address();
        assert(
            caller.is_zero() || caller == get_contract_address(),
            'SHHH: C-1 unauthorized caller',
        );
        let tx_info = get_tx_info().unbox();
        let v: u32 = tx_info.version.try_into().unwrap_or(0_u32);
        assert(v >= 1_u32, 'SHHH: C-1 bad tx version');

        _execute_calls_atomic(calls)
    }

    // ------------------------------------------------------------------
    // execute_from_outside_v2 — the SINGLE real execution path.
    // ------------------------------------------------------------------

    #[external(v0)]
    fn execute_from_outside_v2(
        ref self: ContractState,
        // TODO(v8): replace with the official `OutsideExecution` struct
        // from OZ's SRC9 once the typed-data adapter is wired.
        _outside_execution: Span<felt252>,
        _signature: Span<felt252>,
    ) -> Array<Span<felt252>> {
        // Skeleton body — the real flow is:
        //   1. caller check (M-1)
        //   2. time-window bounds + ANY_CALLER cap (M-2)
        //   3. nonce replay check
        //   4. size bounds (M-3)
        //   5. SNIP-12 typed-data hash (H-2, I-1)
        //   6. parse signature envelope(s); library_call verifier(s); sum weights
        //   7. atomic multicall (H-1)
        core::panic_with_felt252('SHHH: OE path not yet wired')
    }

    // ------------------------------------------------------------------
    // Verifier registry — governance-gated.
    // ------------------------------------------------------------------

    #[external(v0)]
    fn add_verifier_class(ref self: ContractState, kind: felt252, class_hash: ClassHash) {
        // Must be called through __execute__ after a unanimous owner
        // threshold + 48h timelock (see pending_ops OP_ADD_VERIFIER_CLASS).
        assert(get_caller_address() == get_contract_address(), 'SHHH: caller != self');
        self.verifier_classes.write(kind, class_hash);
        self.emit(VerifierClassAdded { kind, class_hash });
    }

    #[external(v0)]
    fn remove_verifier_class(ref self: ContractState, kind: felt252) {
        assert(get_caller_address() == get_contract_address(), 'SHHH: caller != self');
        // Invariant: primary kind MUST remain verifiable.
        assert(kind != self.primary_kind.read(), 'SHHH: cant remove primary kind');
        self.verifier_classes.write(kind, 0.try_into().unwrap());
        self.emit(VerifierClassRemoved { kind });
    }

    #[external(v0)]
    fn get_verifier_class(self: @ContractState, kind: felt252) -> ClassHash {
        self.verifier_classes.read(kind)
    }

    // ------------------------------------------------------------------
    // Read-only introspection
    // ------------------------------------------------------------------

    #[external(v0)]
    fn primary_kind(self: @ContractState) -> felt252 { self.primary_kind.read() }

    #[external(v0)]
    fn primary_pubkey_hash(self: @ContractState) -> felt252 { self.primary_pubkey_hash.read() }

    #[external(v0)]
    fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
        interface_id == ISIGNER_ID
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn _execute_calls_atomic(mut calls: Array<Call>) -> Array<Span<felt252>> {
        let mut results: Array<Span<felt252>> = array![];
        loop {
            match calls.pop_front() {
                Option::Some(call) => {
                    match starknet::syscalls::call_contract_syscall(
                        call.to, call.selector, call.calldata,
                    ) {
                        Result::Ok(ret) => results.append(ret),
                        // Audit H-1 fix: subcall failures revert the whole
                        // multicall. NO silent empty-span fallback.
                        Result::Err(_) => core::panic_with_felt252('SHHH: subcall failed'),
                    }
                },
                Option::None => { break; },
            };
        };
        results
    }

    // Touch imports we haven't wired yet to avoid dead-warning noise
    // during the skeleton phase.
    fn _touch_imports_for_skeleton() {
        let _ = parse_owner_envelope_header;
    }
}
