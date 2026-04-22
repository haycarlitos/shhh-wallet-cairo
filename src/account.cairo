//! ShhhAccount — V8 account class, Phases 3 + 4 scope.
//!
//! - Phase 3: single-entry dispatcher + pluggable verifier via
//!   `library_call_syscall`.
//! - Phase 4: multi-owner storage (up to N owners with weight + role),
//!   self-gated `add_owner` / `remove_owner` / `rotate_owner_pubkey` /
//!   `set_threshold`. Deterministic address derivation via
//!   `salt = poseidon(primary_kind, primary_pubkey_hash)` is computed
//!   off-chain (see `scripts/ts/compute-wallet-address.ts`).
//!
//! Governance timelocks (Phase 5) and recovery (Phase 6) will replace
//! the `caller == self` gate on mutators. Sessions (Phase 7), secp256k1
//! (Phase 8), and WebAuthn (Phase 9) bolt on without storage changes.
//!
//! Every audit finding (2026-04-20) has its guard inline with its
//! audit-id error prefix (`C1:`, `M1:`..). See tests/audit_2026_04_20.cairo.
//!
//! Events-for-indexer rule: every state change emits an event with
//! enough data for an indexer to reconstruct the new state without
//! re-reading storage.

#[starknet::contract(account)]
pub mod ShhhAccount {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use openzeppelin::introspection::src5::SRC5Component;
    use starknet::account::Call;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{
        ClassHash, get_block_timestamp, get_caller_address, get_contract_address, get_tx_info,
        syscalls,
    };
    use crate::governance::component::GovernanceComponent;
    use crate::governance::pending_ops::{
        DEFAULT_OP_EXPIRY_SECONDS, OP_ADD_OWNER, OP_ADD_VERIFIER_CLASS, OP_REMOVE_OWNER,
        OP_REMOVE_VERIFIER_CLASS, OP_ROTATE_OWNER, OP_SET_THRESHOLD, PendingOp, TIMELOCK_ADD_OWNER,
        TIMELOCK_ADD_VERIFIER, TIMELOCK_REMOVE_OWNER, TIMELOCK_REMOVE_VERIFIER,
        TIMELOCK_ROTATE_OWNER, TIMELOCK_SET_THRESHOLD,
    };
    use crate::outside_execution::{
        ISRC9_V2, ISRC9_V2_ID, OutsideExecution, SIG_VERSION_V2_SNIP12, compute_snip12_hash,
    };
    use crate::owner_set::component::OwnerSetComponent;
    use crate::owner_set::interface::OwnerRecord;
    use crate::signer::interface::{ISignerDispatcherTrait, ISignerLibraryDispatcher};

    // ------------------------------------------------------------------
    // Audit-driven bounds (M-2, M-3). Same values as the V7 in-place fix.
    // ------------------------------------------------------------------
    pub const MAX_CALLS: u32 = 16;
    pub const MAX_TOTAL_CALLDATA_FELTS: u32 = 1024;
    pub const MAX_SIGNATURE_FELTS: u32 = 1024;
    pub const MAX_ANY_CALLER_VALIDITY_SECONDS: u64 = 7_200;

    /// Owner-envelope header min length: [version_tag, owner_id, kind_tag].
    pub const OE_OWNER_ENVELOPE_HEADER_LEN: u32 = 3;

    component!(path: SRC5Component, storage: src5, event: SRC5Event);
    component!(path: OwnerSetComponent, storage: owners, event: OwnerSetEvent);
    component!(path: GovernanceComponent, storage: governance, event: GovernanceEvent);

    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;
    impl SRC5InternalImpl = SRC5Component::InternalImpl<ContractState>;
    impl OwnerSetInternal = OwnerSetComponent::InternalImpl<ContractState>;
    impl GovernanceInternal = GovernanceComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        // Primary-owner binding (frozen at deploy). Used by address salt
        // and by paymasters deciding signer routing.
        primary_kind: felt252,
        primary_pubkey_hash: felt252,
        address_salt: felt252,
        // Kind → verifier class hash. Mutating this is restricted to
        // `caller == self` until Phase 5 wires timelocked governance.
        verifier_classes: Map<felt252, ClassHash>,
        // SRC9 nonces.
        oe_nonces: Map<felt252, bool>,
        // Components.
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        owners: OwnerSetComponent::Storage,
        #[substorage(v0)]
        governance: GovernanceComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        SRC5Event: SRC5Component::Event,
        #[flat]
        OwnerSetEvent: OwnerSetComponent::Event,
        #[flat]
        GovernanceEvent: GovernanceComponent::Event,
        PrimaryOwnerInitialized: PrimaryOwnerInitialized,
        VerifierClassAdded: VerifierClassAdded,
        VerifierClassRemoved: VerifierClassRemoved,
        OutsideExecutionExecuted: OutsideExecutionExecuted,
    }

    /// Fired once in the constructor. Carries the primary owner's salt
    /// inputs so an indexer can precompute / reconcile the deterministic
    /// address without reading storage.
    #[derive(Drop, starknet::Event)]
    struct PrimaryOwnerInitialized {
        #[key]
        kind: felt252,
        #[key]
        pubkey_hash: felt252,
        verifier_class: ClassHash,
        salt: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct VerifierClassAdded {
        #[key]
        kind: felt252,
        class_hash: ClassHash,
    }

    #[derive(Drop, starknet::Event)]
    struct VerifierClassRemoved {
        #[key]
        kind: felt252,
    }

    /// Emitted after a successful `execute_from_outside_v2`. Enough data
    /// for an indexer to match the tx to a known OE and link the signer.
    #[derive(Drop, starknet::Event)]
    struct OutsideExecutionExecuted {
        #[key]
        owner_id: u32,
        #[key]
        nonce: felt252,
        kind: felt252,
        message_hash: felt252,
        calls_count: u32,
    }

    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------

    #[constructor]
    fn constructor(
        ref self: ContractState,
        primary_kind: felt252,
        primary_verifier: ClassHash,
        pubkey: Span<felt252>,
        label: felt252,
    ) {
        assert(primary_kind != 0, 'L1: primary_kind is zero');
        assert(pubkey.len() > 0_u32, 'L1: pubkey empty');
        let verifier_felt: felt252 = primary_verifier.into();
        assert(verifier_felt != 0, 'L1: verifier class zero');

        let commitment = crate::signer::interface::owner_commitment(primary_kind, pubkey);
        self.primary_kind.write(primary_kind);
        self.primary_pubkey_hash.write(commitment);
        let salt = poseidon_hash_span(array![primary_kind, commitment].span());
        self.address_salt.write(salt);

        // Store primary owner at owner_id 0 via the component.
        self.owners.initialize_primary(primary_kind, commitment, pubkey, label);

        // Register verifier class for the primary kind.
        self.verifier_classes.write(primary_kind, primary_verifier);

        // SRC5: canonical SNIP-9 V2 interface (audit H-2).
        self.src5.register_interface(ISRC9_V2_ID);

        // Events (indexer rule: emit full state for the primary owner).
        self
            .emit(
                PrimaryOwnerInitialized {
                    kind: primary_kind,
                    pubkey_hash: commitment,
                    verifier_class: primary_verifier,
                    salt,
                },
            );
        self.emit(VerifierClassAdded { kind: primary_kind, class_hash: primary_verifier });
    }

    // ------------------------------------------------------------------
    // __validate__ always reverts. __validate_deploy__ omitted.
    // ------------------------------------------------------------------

    #[external(v0)]
    fn __validate__(ref self: ContractState, _calls: Array<Call>) -> felt252 {
        core::panic_with_felt252('SHHH: __validate__ disabled')
    }

    #[external(v0)]
    fn __validate_declare__(self: @ContractState, _class_hash: felt252) -> felt252 {
        core::panic_with_felt252('SHHH: declare disabled')
    }

    // ------------------------------------------------------------------
    // __execute__ — protocol/paymaster path. Audit C-1 gated.
    // ------------------------------------------------------------------

    #[external(v0)]
    fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
        let caller = get_caller_address();
        assert(caller.is_zero() || caller == get_contract_address(), 'C1: unauthorized caller');
        let tx_info = get_tx_info().unbox();
        let v: u32 = tx_info.version.try_into().unwrap_or(0_u32);
        assert(v >= 1_u32, 'C1: invalid tx version');
        _execute_calls_atomic(calls)
    }

    // ------------------------------------------------------------------
    // SRC9 V2 — the sole authorized-execution path.
    // ------------------------------------------------------------------

    #[abi(embed_v0)]
    impl SRC9V2Impl of ISRC9_V2<ContractState> {
        fn execute_from_outside_v2(
            ref self: ContractState, outside_execution: OutsideExecution, signature: Span<felt252>,
        ) -> Array<Span<felt252>> {
            // 1. Caller check (M-1).
            let caller_felt: felt252 = outside_execution.caller.into();
            if caller_felt == 'ANY_CALLER' {
                let window = outside_execution.execute_before - outside_execution.execute_after;
                assert(window <= MAX_ANY_CALLER_VALIDITY_SECONDS, 'M2: window too long');
            } else {
                assert(caller_felt != 0, 'M1: caller=0 rejected');
                assert(get_caller_address() == outside_execution.caller, 'SRC9: invalid caller');
            }

            // 2. Time bounds.
            let now = get_block_timestamp();
            assert(outside_execution.execute_after < now, 'SRC9: too early');
            assert(now < outside_execution.execute_before, 'SRC9: too late');

            // 3. Nonce replay.
            assert(!self.oe_nonces.read(outside_execution.nonce), 'SRC9: duplicate nonce');
            self.oe_nonces.write(outside_execution.nonce, true);

            // 4. Bounds (M-3).
            let calls_count = outside_execution.calls.len();
            assert(calls_count <= MAX_CALLS, 'M3: too many calls');
            assert(
                _total_calldata_felts(outside_execution.calls) <= MAX_TOTAL_CALLDATA_FELTS,
                'M3: calldata too large',
            );
            assert(signature.len() <= MAX_SIGNATURE_FELTS, 'M3: signature too long');

            // 5. Owner-envelope header.
            assert(signature.len() >= OE_OWNER_ENVELOPE_HEADER_LEN, 'SRC9: sig too short');
            let version_tag = *signature.at(0);
            assert(version_tag == SIG_VERSION_V2_SNIP12, 'SHHH: unsupported sig version');

            let owner_id: u32 = (*signature.at(1)).try_into().expect('SHHH: bad owner_id');
            assert(owner_id < self.owners.owner_count(), 'SHHH: unknown owner_id');
            let owner: OwnerRecord = self.owners.get_owner(owner_id);
            assert(!owner.revoked, 'SHHH: owner revoked');

            let kind_tag = *signature.at(2);
            assert(kind_tag == owner.kind, 'SHHH: kind mismatch');

            // 6. SNIP-12 hash + library_call dispatch.
            let chain_id = get_tx_info().unbox().chain_id;
            let message_hash = compute_snip12_hash(
                @outside_execution, get_contract_address(), chain_id,
            );
            let verifier_class = self.verifier_classes.read(owner.kind);
            assert(Into::<ClassHash, felt252>::into(verifier_class) != 0, 'SHHH: verifier missing');

            let pubkey = self.owners.read_pubkey_bytes(owner);
            let verifier_payload = _slice_from(signature, OE_OWNER_ENVELOPE_HEADER_LEN);
            let dispatcher = ISignerLibraryDispatcher { class_hash: verifier_class };
            let ok = dispatcher.verify(message_hash, pubkey.span(), verifier_payload);
            assert(ok, 'SHHH: signature invalid');

            // 7. Atomic multicall (H-1).
            let results = _execute_calls_atomic_span(outside_execution.calls);

            // 8. Indexer event — full identifying info.
            self
                .emit(
                    OutsideExecutionExecuted {
                        owner_id,
                        nonce: outside_execution.nonce,
                        kind: owner.kind,
                        message_hash,
                        calls_count,
                    },
                );

            results
        }

        fn is_valid_outside_execution_nonce(self: @ContractState, nonce: felt252) -> bool {
            !self.oe_nonces.read(nonce)
        }
    }

    // ------------------------------------------------------------------
    // Phase 5 — timelocked governance.
    //
    // Every structural mutation (add_owner / remove_owner / rotate /
    // threshold / verifier-class) goes through propose → wait-timelock →
    // execute. During the window any single owner can cancel via OE.
    // All propose_* + cancel_pending_op are caller==self gated so they
    // can only be invoked as a sub-call of a verified OE multicall.
    // execute_pending_* is PERMISSIONLESS after the timelock — the user
    // has already had the window to cancel.
    // ------------------------------------------------------------------

    #[derive(Drop, starknet::Event)]
    struct GovernanceProposeSummary {
        #[key]
        op_id: felt252,
        #[key]
        op_kind: felt252,
    }

    // -----------------------------------------------------------------
    // Payload hash helpers — MUST match between propose_* and
    // execute_* so the stored commitment verifies against the execute
    // args. Keep these in sync whenever an op's argument shape changes.
    // -----------------------------------------------------------------

    fn _payload_add_owner(
        kind: felt252, pubkey_hash: felt252, role: felt252, weight: u8, label: felt252,
    ) -> felt252 {
        let weight_felt: felt252 = weight.into();
        core::poseidon::poseidon_hash_span(
            array![kind, pubkey_hash, role, weight_felt, label].span(),
        )
    }

    fn _payload_remove_owner(owner_id: u32) -> felt252 {
        let id_felt: felt252 = owner_id.into();
        core::poseidon::poseidon_hash_span(array![id_felt].span())
    }

    fn _payload_rotate_owner(owner_id: u32, new_pubkey_hash: felt252) -> felt252 {
        let id_felt: felt252 = owner_id.into();
        core::poseidon::poseidon_hash_span(array![id_felt, new_pubkey_hash].span())
    }

    fn _payload_set_threshold(new: u8) -> felt252 {
        let new_felt: felt252 = new.into();
        core::poseidon::poseidon_hash_span(array![new_felt].span())
    }

    fn _payload_add_verifier(kind: felt252, class_hash: ClassHash) -> felt252 {
        core::poseidon::poseidon_hash_span(array![kind, class_hash.into()].span())
    }

    fn _payload_remove_verifier(kind: felt252) -> felt252 {
        core::poseidon::poseidon_hash_span(array![kind].span())
    }

    // -----------------------------------------------------------------
    // Propose entrypoints (caller == self).
    // Each returns the generated op_id so the OE caller / frontend can
    // watch for its OpProposed event and schedule execute/cancel.
    // -----------------------------------------------------------------

    #[external(v0)]
    fn propose_add_owner(
        ref self: ContractState,
        proposer: u32,
        kind: felt252,
        pubkey_bytes: Array<felt252>,
        role: felt252,
        weight: u8,
        label: felt252,
    ) -> felt252 {
        _assert_self_call();
        let commitment = crate::signer::interface::owner_commitment(kind, pubkey_bytes.span());
        let payload = _payload_add_owner(kind, commitment, role, weight, label);
        self
            .governance
            .propose(OP_ADD_OWNER, proposer, payload, TIMELOCK_ADD_OWNER, DEFAULT_OP_EXPIRY_SECONDS)
    }

    #[external(v0)]
    fn propose_remove_owner(ref self: ContractState, proposer: u32, owner_id: u32) -> felt252 {
        _assert_self_call();
        let payload = _payload_remove_owner(owner_id);
        self
            .governance
            .propose(
                OP_REMOVE_OWNER,
                proposer,
                payload,
                TIMELOCK_REMOVE_OWNER,
                DEFAULT_OP_EXPIRY_SECONDS,
            )
    }

    #[external(v0)]
    fn propose_rotate_owner(
        ref self: ContractState, proposer: u32, owner_id: u32, new_pubkey_bytes: Array<felt252>,
    ) -> felt252 {
        _assert_self_call();
        let owner = self.owners.get_owner(owner_id);
        let new_hash = crate::signer::interface::owner_commitment(
            owner.kind, new_pubkey_bytes.span(),
        );
        let payload = _payload_rotate_owner(owner_id, new_hash);
        self
            .governance
            .propose(
                OP_ROTATE_OWNER,
                proposer,
                payload,
                TIMELOCK_ROTATE_OWNER,
                DEFAULT_OP_EXPIRY_SECONDS,
            )
    }

    #[external(v0)]
    fn propose_set_threshold(ref self: ContractState, proposer: u32, new: u8) -> felt252 {
        _assert_self_call();
        let payload = _payload_set_threshold(new);
        self
            .governance
            .propose(
                OP_SET_THRESHOLD,
                proposer,
                payload,
                TIMELOCK_SET_THRESHOLD,
                DEFAULT_OP_EXPIRY_SECONDS,
            )
    }

    #[external(v0)]
    fn propose_add_verifier_class(
        ref self: ContractState, proposer: u32, kind: felt252, class_hash: ClassHash,
    ) -> felt252 {
        _assert_self_call();
        assert(
            Into::<ClassHash, felt252>::into(self.verifier_classes.read(kind)) == 0,
            'SHHH: verifier already set',
        );
        let payload = _payload_add_verifier(kind, class_hash);
        self
            .governance
            .propose(
                OP_ADD_VERIFIER_CLASS,
                proposer,
                payload,
                TIMELOCK_ADD_VERIFIER,
                DEFAULT_OP_EXPIRY_SECONDS,
            )
    }

    #[external(v0)]
    fn propose_remove_verifier_class(
        ref self: ContractState, proposer: u32, kind: felt252,
    ) -> felt252 {
        _assert_self_call();
        assert(kind != self.primary_kind.read(), 'SHHH: cant remove primary kind');
        let payload = _payload_remove_verifier(kind);
        self
            .governance
            .propose(
                OP_REMOVE_VERIFIER_CLASS,
                proposer,
                payload,
                TIMELOCK_REMOVE_VERIFIER,
                DEFAULT_OP_EXPIRY_SECONDS,
            )
    }

    // -----------------------------------------------------------------
    // Execute entrypoints (permissionless, post-timelock).
    // Caller re-provides the op arguments. The account recomputes the
    // payload hash and asserts it matches the stored commitment; then
    // runs the side effect and marks the op executed.
    // -----------------------------------------------------------------

    #[external(v0)]
    fn execute_add_owner(
        ref self: ContractState,
        op_id: felt252,
        kind: felt252,
        pubkey_bytes: Array<felt252>,
        role: felt252,
        weight: u8,
        label: felt252,
    ) -> u32 {
        let pubkey_span = pubkey_bytes.span();
        let commitment = crate::signer::interface::owner_commitment(kind, pubkey_span);
        let expected = _payload_add_owner(kind, commitment, role, weight, label);
        let op = self.governance.assert_ready(op_id, expected);
        assert(op.op_kind == OP_ADD_OWNER, 'OP: wrong op_kind');
        let new_id = self.owners.add_owner(kind, commitment, pubkey_span, role, weight, label);
        self.governance.mark_executed(op_id);
        new_id
    }

    #[external(v0)]
    fn execute_remove_owner(ref self: ContractState, op_id: felt252, owner_id: u32) {
        let expected = _payload_remove_owner(owner_id);
        let op = self.governance.assert_ready(op_id, expected);
        assert(op.op_kind == OP_REMOVE_OWNER, 'OP: wrong op_kind');
        self.owners.remove_owner(owner_id);
        self.governance.mark_executed(op_id);
    }

    #[external(v0)]
    fn execute_rotate_owner(
        ref self: ContractState, op_id: felt252, owner_id: u32, new_pubkey_bytes: Array<felt252>,
    ) {
        let owner = self.owners.get_owner(owner_id);
        let new_span = new_pubkey_bytes.span();
        let new_hash = crate::signer::interface::owner_commitment(owner.kind, new_span);
        let expected = _payload_rotate_owner(owner_id, new_hash);
        let op = self.governance.assert_ready(op_id, expected);
        assert(op.op_kind == OP_ROTATE_OWNER, 'OP: wrong op_kind');
        self.owners.rotate_owner_pubkey(owner_id, new_hash, new_span);
        self.governance.mark_executed(op_id);
    }

    #[external(v0)]
    fn execute_set_threshold(ref self: ContractState, op_id: felt252, new: u8) {
        let expected = _payload_set_threshold(new);
        let op = self.governance.assert_ready(op_id, expected);
        assert(op.op_kind == OP_SET_THRESHOLD, 'OP: wrong op_kind');
        self.owners.set_threshold(new);
        self.governance.mark_executed(op_id);
    }

    #[external(v0)]
    fn execute_add_verifier_class(
        ref self: ContractState, op_id: felt252, kind: felt252, class_hash: ClassHash,
    ) {
        let expected = _payload_add_verifier(kind, class_hash);
        let op = self.governance.assert_ready(op_id, expected);
        assert(op.op_kind == OP_ADD_VERIFIER_CLASS, 'OP: wrong op_kind');
        // Re-check the not-already-set invariant at execute time in case a
        // concurrent op slotted a verifier in between propose and execute.
        assert(
            Into::<ClassHash, felt252>::into(self.verifier_classes.read(kind)) == 0,
            'SHHH: verifier already set',
        );
        self.verifier_classes.write(kind, class_hash);
        self.governance.mark_executed(op_id);
        self.emit(VerifierClassAdded { kind, class_hash });
    }

    #[external(v0)]
    fn execute_remove_verifier_class(ref self: ContractState, op_id: felt252, kind: felt252) {
        let expected = _payload_remove_verifier(kind);
        let op = self.governance.assert_ready(op_id, expected);
        assert(op.op_kind == OP_REMOVE_VERIFIER_CLASS, 'OP: wrong op_kind');
        assert(kind != self.primary_kind.read(), 'SHHH: cant remove primary kind');
        self.verifier_classes.write(kind, 0.try_into().unwrap());
        self.governance.mark_executed(op_id);
        self.emit(VerifierClassRemoved { kind });
    }

    // -----------------------------------------------------------------
    // Cancel — caller==self, valid any time until the op is executed.
    // -----------------------------------------------------------------

    #[external(v0)]
    fn cancel_pending_op(ref self: ContractState, op_id: felt252) {
        _assert_self_call();
        self.governance.cancel(op_id);
    }

    #[external(v0)]
    fn get_pending_op(self: @ContractState, op_id: felt252) -> PendingOp {
        self.governance.get_op(op_id)
    }

    // ------------------------------------------------------------------
    // Read-only introspection
    // ------------------------------------------------------------------

    #[external(v0)]
    fn primary_kind(self: @ContractState) -> felt252 {
        self.primary_kind.read()
    }

    #[external(v0)]
    fn primary_pubkey_hash(self: @ContractState) -> felt252 {
        self.primary_pubkey_hash.read()
    }

    #[external(v0)]
    fn address_salt(self: @ContractState) -> felt252 {
        self.address_salt.read()
    }

    #[external(v0)]
    fn get_verifier_class(self: @ContractState, kind: felt252) -> ClassHash {
        self.verifier_classes.read(kind)
    }

    #[external(v0)]
    fn get_owner(self: @ContractState, owner_id: u32) -> OwnerRecord {
        self.owners.get_owner(owner_id)
    }

    #[external(v0)]
    fn owner_count(self: @ContractState) -> u32 {
        self.owners.owner_count()
    }

    #[external(v0)]
    fn active_owner_count(self: @ContractState) -> u32 {
        self.owners.active_owner_count()
    }

    #[external(v0)]
    fn threshold(self: @ContractState) -> u8 {
        self.owners.threshold_value()
    }

    #[external(v0)]
    fn total_weight(self: @ContractState) -> u32 {
        self.owners.total_weight()
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn _assert_self_call() {
        assert(get_caller_address() == get_contract_address(), 'SHHH: caller != self');
    }

    fn _slice_from(span: Span<felt252>, start: u32) -> Span<felt252> {
        let mut out: Array<felt252> = array![];
        let mut i: u32 = start;
        while i < span.len() {
            out.append(*span.at(i));
            i += 1;
        }
        out.span()
    }

    fn _total_calldata_felts(calls: Span<Call>) -> u32 {
        let mut total: u32 = 0;
        let mut cursor = calls;
        loop {
            match cursor.pop_front() {
                Option::Some(call) => { total += (*call.calldata).len(); },
                Option::None => { break; },
            }
        }
        total
    }

    fn _execute_calls_atomic(mut calls: Array<Call>) -> Array<Span<felt252>> {
        let mut results: Array<Span<felt252>> = array![];
        loop {
            match calls.pop_front() {
                Option::Some(call) => {
                    match syscalls::call_contract_syscall(call.to, call.selector, call.calldata) {
                        Result::Ok(ret) => results.append(ret),
                        Result::Err(_) => core::panic_with_felt252('H1: subcall failed'),
                    }
                },
                Option::None => { break; },
            }
        }
        results
    }

    fn _execute_calls_atomic_span(mut calls: Span<Call>) -> Array<Span<felt252>> {
        let mut results: Array<Span<felt252>> = array![];
        loop {
            match calls.pop_front() {
                Option::Some(call) => {
                    match syscalls::call_contract_syscall(
                        *call.to, *call.selector, *call.calldata,
                    ) {
                        Result::Ok(ret) => results.append(ret),
                        Result::Err(_) => core::panic_with_felt252('H1: subcall failed'),
                    }
                },
                Option::None => { break; },
            }
        }
        results
    }
}
