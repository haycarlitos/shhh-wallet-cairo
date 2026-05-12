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
    use core::ecdsa::check_ecdsa_signature;
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use openzeppelin::introspection::src5::SRC5Component;
    use starknet::account::Call;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{
        ClassHash, ContractAddress, get_block_timestamp, get_caller_address, get_contract_address,
        get_tx_info, syscalls,
    };
    use crate::governance::component::GovernanceComponent;
    use crate::governance::pending_ops::{
        DEFAULT_OP_EXPIRY_SECONDS, OP_ADD_OWNER, OP_ADD_VERIFIER_CLASS, OP_REMOVE_OWNER,
        OP_REMOVE_VERIFIER_CLASS, OP_ROTATE_OWNER, OP_SET_THRESHOLD, PendingOp, TIMELOCK_ADD_OWNER,
        TIMELOCK_ADD_VERIFIER, TIMELOCK_RECOVERY, TIMELOCK_REMOVE_OWNER, TIMELOCK_REMOVE_VERIFIER,
        TIMELOCK_ROTATE_OWNER, TIMELOCK_SET_THRESHOLD,
    };
    use crate::outside_execution::{
        ISRC9_V2, ISRC9_V2_ID, OutsideExecution, SIG_VERSION_V2_SNIP12, SIG_VERSION_V2_THRESHOLD,
        compute_snip12_hash,
    };
    use crate::owner_set::component::OwnerSetComponent;
    use crate::owner_set::interface::{OwnerRecord, ROLE_GUARDIAN, ROLE_OWNER};
    use crate::recovery::component::RecoveryComponent;
    use crate::session_key::component::SessionKeyComponent;
    use crate::session_key::interface::SessionData;
    use crate::signer::interface::{ISIGNER_ID, ISignerDispatcherTrait, ISignerLibraryDispatcher};
    use crate::spending_policy::component::SpendingPolicyComponent;
    use crate::spending_policy::interface::SpendingPolicy;

    // ------------------------------------------------------------------
    // Audit-driven bounds (M-2, M-3). Same values as the V7 in-place fix.
    // ------------------------------------------------------------------
    pub const MAX_CALLS: u32 = 16;
    pub const MAX_TOTAL_CALLDATA_FELTS: u32 = 1024;
    pub const MAX_SIGNATURE_FELTS: u32 = 1024;
    pub const MAX_ANY_CALLER_VALIDITY_SECONDS: u64 = 7_200;

    /// Owner-envelope header min length: [version_tag, owner_id, kind_tag].
    pub const OE_OWNER_ENVELOPE_HEADER_LEN: u32 = 3;

    /// Storage slot of the OZ AccountComponent's `Account_public_key`
    /// field on the legacy sessions-smart-contract class. Read by
    /// `bootstrap_from_sessions_signed` (V8.4, audit C-1 fix) to bind
    /// the supplied `public_key` to the preserved sessions owner.
    ///
    /// **ABI-tied to OZ AccountComponent v3.0.0** — verified against
    /// `github.com/OpenZeppelin/cairo-contracts` tag `v3.0.0`,
    /// `packages/account/src/account.cairo`, which declares
    /// `pub Account_public_key: felt252` inside `AccountComponent::Storage`.
    /// Substorage v0 places this field at the top-level slot keyed by
    /// `selector!("Account_public_key")`.
    ///
    /// **Maintenance contract**: if `Scarb.toml`'s `openzeppelin` git
    /// tag is bumped past `v3.0.0`, the OZ source MUST be re-verified
    /// against this constant before merge. A rename in OZ (e.g., to
    /// `public_key` without the `Account_` prefix, or to a different
    /// substorage layout in v4.0.0+) silently breaks
    /// `bootstrap_from_sessions_signed` for any sessions wallet minted
    /// off the newer OZ class — the slot read returns zero, the
    /// 'MIG: no legacy pk' branch fires, and stranded-state recovery
    /// is permanently unreachable for those wallets. The error fail-
    /// closes safely (no takeover surface), but legitimate users
    /// cannot recover. Treat any OZ bump as gated on re-verifying
    /// this slot.
    pub const LEGACY_OZ_ACCOUNT_PUBKEY_SLOT: felt252 = selector!("Account_public_key");

    component!(path: SRC5Component, storage: src5, event: SRC5Event);
    component!(path: OwnerSetComponent, storage: owners, event: OwnerSetEvent);
    component!(path: GovernanceComponent, storage: governance, event: GovernanceEvent);
    component!(path: RecoveryComponent, storage: recovery, event: RecoveryEvent);
    component!(path: SessionKeyComponent, storage: session_key, event: SessionKeyEvent);
    component!(path: SpendingPolicyComponent, storage: spending_policy, event: SpendingPolicyEvent);

    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;
    impl SRC5InternalImpl = SRC5Component::InternalImpl<ContractState>;
    impl OwnerSetInternal = OwnerSetComponent::InternalImpl<ContractState>;
    impl GovernanceInternal = GovernanceComponent::InternalImpl<ContractState>;
    impl RecoveryInternal = RecoveryComponent::InternalImpl<ContractState>;
    impl SessionKeyInternal = SessionKeyComponent::InternalImpl<ContractState>;
    impl SpendingPolicyInternal = SpendingPolicyComponent::InternalImpl<ContractState>;

    // Both components require a `HasAccountOwner` seam — we supply it
    // by asserting `caller == self`, which is the standard V8 convention
    // for protected entrypoints.
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
        // Reentrancy guard — set for the duration of
        // `execute_from_outside_v2`. Any subcall that tries to re-enter
        // the OE path reverts with 'SHHH: reentrant'. Defense-in-depth
        // against attacker-controlled target contracts that have a
        // session-key envelope in hand and try to stack a second
        // execution on top of the first.
        oe_in_progress: bool,
        // Audit M-2 (2026-05-07 self-review): library-call verifiers run
        // in the account's storage AND address context, so a malicious
        // verifier could `call_contract_syscall(self_addr, ...)` back
        // into a `_assert_self_call`-gated mutator (propose_add_owner,
        // set_spending_policy, …) and trivially satisfy the self-call
        // assertion. We set this flag for the duration of every
        // `dispatcher.verify(...)` library_call and refuse self-calls
        // while it's set. Trust model is governance-vetted verifier
        // classes; this is defense-in-depth in case a malicious class
        // makes it through the 48h ADD_VERIFIER timelock unanimously.
        inside_verifier: bool,
        // Components.
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        owners: OwnerSetComponent::Storage,
        #[substorage(v0)]
        governance: GovernanceComponent::Storage,
        // `recovery.pending` and `governance.pending` namespaced under
        // their own substorage prefixes — physically distinct slots.
        #[allow(starknet::colliding_storage_paths)]
        #[substorage(v0)]
        recovery: RecoveryComponent::Storage,
        #[substorage(v0)]
        session_key: SessionKeyComponent::Storage,
        #[substorage(v0)]
        spending_policy: SpendingPolicyComponent::Storage,
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
        #[flat]
        RecoveryEvent: RecoveryComponent::Event,
        #[flat]
        SessionKeyEvent: SessionKeyComponent::Event,
        #[flat]
        SpendingPolicyEvent: SpendingPolicyComponent::Event,
        PrimaryOwnerInitialized: PrimaryOwnerInitialized,
        VerifierClassAdded: VerifierClassAdded,
        VerifierClassRemoved: VerifierClassRemoved,
        OutsideExecutionExecuted: OutsideExecutionExecuted,
        ThresholdOutsideExecutionExecuted: ThresholdOutsideExecutionExecuted,
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

    /// Emitted after a successful threshold-signed `execute_from_outside_v2`.
    /// Indexers key on `nonce` and can reconstruct which owners signed
    /// by replaying the inner envelopes from the tx calldata.
    #[derive(Drop, starknet::Event)]
    struct ThresholdOutsideExecutionExecuted {
        #[key]
        nonce: felt252,
        n_signers: u32,
        total_weight: u32,
        threshold: u8,
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

        // SRC5: canonical SNIP-9 V2 interface (audit H-2) + ISigner_V1
        // trait surface so paymasters / SDKs can discover that this
        // account exposes the pluggable-signer interface without having
        // to infer it from the kind registry.
        self.src5.register_interface(ISRC9_V2_ID);
        self.src5.register_interface(ISIGNER_ID);

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
            // 0. Reentrancy guard — set before any state mutation; cleared
            // at every return path. A subcall that re-enters via any OE
            // surface reverts. Nonce dedup already prevents same-nonce
            // replay; this adds defense-in-depth for a malicious target
            // that holds independent signatures and tries to interleave.
            assert(!self.oe_in_progress.read(), 'SHHH: reentrant');
            self.oe_in_progress.write(true);

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

            // 5. Route by signature shape (SNIPs#163 convention):
            //    - 4-element  → session key [session_pubkey, r, s, valid_until]
            //    - variable   → owner envelope [V2_SNIP12, owner_id, kind, payload...]
            let chain_id = get_tx_info().unbox().chain_id;
            let message_hash = compute_snip12_hash(
                @outside_execution, get_contract_address(), chain_id,
            );

            if signature.len() == 4_u32 {
                _verify_session_sig_and_consume(
                    ref self, outside_execution.calls, signature, message_hash,
                );
                let session_pubkey = *signature.at(0);
                // Spending caps enforce at execute time, not validate.
                self
                    .spending_policy
                    .check_and_update_spending(session_pubkey, outside_execution.calls);

                let results = _execute_calls_atomic_span(outside_execution.calls);
                self
                    .emit(
                        OutsideExecutionExecuted {
                            owner_id: 0, // sessions don't map to an owner_id
                            nonce: outside_execution.nonce,
                            kind: 'SESSION',
                            message_hash,
                            calls_count,
                        },
                    );
                self.oe_in_progress.write(false);
                return results;
            }

            // Owner-envelope header — version tag selects single vs threshold.
            assert(signature.len() >= 2_u32, 'SRC9: sig too short');
            let version_tag = *signature.at(0);

            if version_tag == SIG_VERSION_V2_THRESHOLD {
                // Threshold envelope: [V2_THRESHOLD, n, env_1_len, env_1..., env_2_len, env_2...]
                let n_felt = *signature.at(1);
                let n: u32 = n_felt.try_into().expect('THRESH: bad n');
                assert(n >= 2_u32, 'THRESH: need >= 2 envelopes');
                assert(n <= self.owners.owner_count(), 'THRESH: n > owner_count');

                let mut cursor: u32 = 2;
                let mut total_weight: u32 = 0;
                let mut seen_ids: Array<u32> = array![];
                let threshold: u8 = self.owners.threshold_value();
                let mut i: u32 = 0;
                while i < n {
                    assert(cursor < signature.len(), 'THRESH: truncated');
                    let env_len: u32 = (*signature.at(cursor))
                        .try_into()
                        .expect('THRESH: bad env_len');
                    cursor += 1;
                    assert(env_len >= 2_u32, 'THRESH: inner too short');
                    assert(cursor + env_len <= signature.len(), 'THRESH: env overflow');
                    let sub = _slice_range(signature, cursor, cursor + env_len);
                    let (owner_id, _kind, weight) = _verify_sub_envelope(
                        ref self, sub, message_hash,
                    );
                    // Duplicate owner_id rejection.
                    let mut k: u32 = 0;
                    while k < seen_ids.len() {
                        assert(*seen_ids.at(k) != owner_id, 'THRESH: duplicate owner_id');
                        k += 1;
                    }
                    seen_ids.append(owner_id);
                    let w_u32: u32 = weight.into();
                    total_weight += w_u32;
                    cursor += env_len;
                    i += 1;
                }
                assert(cursor == signature.len(), 'THRESH: trailing bytes');
                let thr_u32: u32 = threshold.into();
                assert(total_weight >= thr_u32, 'THRESH: below threshold');

                let results = _execute_calls_atomic_span(outside_execution.calls);

                self
                    .emit(
                        ThresholdOutsideExecutionExecuted {
                            nonce: outside_execution.nonce,
                            n_signers: n,
                            total_weight,
                            threshold,
                            message_hash,
                            calls_count,
                        },
                    );

                self.oe_in_progress.write(false);
                return results;
            }

            // Single-owner V2 envelope.
            assert(version_tag == SIG_VERSION_V2_SNIP12, 'SHHH: unsupported sig version');
            assert(signature.len() >= OE_OWNER_ENVELOPE_HEADER_LEN, 'SRC9: sig too short');

            let owner_id: u32 = (*signature.at(1)).try_into().expect('SHHH: bad owner_id');
            assert(owner_id < self.owners.owner_count(), 'SHHH: unknown owner_id');
            let owner: OwnerRecord = self.owners.get_owner(owner_id);
            assert(!owner.revoked, 'SHHH: owner revoked');
            // Audit C-1 (2026-05-07 self-review): only `ROLE_OWNER` may
            // sign arbitrary OEs. `ROLE_GUARDIAN` is recovery-only;
            // `ROLE_RECOVERY_ONLY` never signs. Without this check, a
            // guardian added "for emergency recovery" silently became a
            // co-owner with full drain authority — the role distinction
            // was enforced only at `initiate_recovery` / `cancel_recovery`,
            // not on the OE verify path.
            //
            // V8.4 guardian-OE carve-out: ROLE_GUARDIAN envelopes are
            // accepted iff the OE's calls are exactly one call to
            // `initiate_recovery` on this account AND the `proposer` arg
            // (calldata[0]) equals the signer's owner_id. This closes the
            // V8.3 gap where guardians could never directly trigger
            // recovery (the only valid path required an owner OE, which
            // defeats the "I lost my owner key" use case). Cancel and
            // finalize stay owner-only / permissionless respectively.
            assert(
                owner.role == ROLE_OWNER
                    || (owner.role == ROLE_GUARDIAN
                        && _is_single_initiate_recovery_call(
                            outside_execution.calls, get_contract_address(), owner_id,
                        )),
                'SHHH: signer not an owner',
            );

            let kind_tag = *signature.at(2);
            assert(kind_tag == owner.kind, 'SHHH: kind mismatch');

            let verifier_class = self.verifier_classes.read(owner.kind);
            assert(Into::<ClassHash, felt252>::into(verifier_class) != 0, 'SHHH: verifier missing');

            let pubkey = self.owners.read_pubkey_bytes(owner);
            let verifier_payload = _slice_from(signature, OE_OWNER_ENVELOPE_HEADER_LEN);
            let dispatcher = ISignerLibraryDispatcher { class_hash: verifier_class };
            // Audit M-2 (2026-05-07): raise the inside_verifier flag so a
            // malicious verifier class can't recurse into a
            // `_assert_self_call`-gated mutator while we hold an open
            // library_call. Lower it before assert(ok) so the
            // signature-invalid revert path doesn't leak the flag.
            self.inside_verifier.write(true);
            let ok = dispatcher.verify(message_hash, pubkey.span(), verifier_payload);
            self.inside_verifier.write(false);
            assert(ok, 'SHHH: signature invalid');

            // 6. Atomic multicall (H-1).
            let results = _execute_calls_atomic_span(outside_execution.calls);

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

            self.oe_in_progress.write(false);
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
        _assert_self_call(@self);
        let commitment = crate::signer::interface::owner_commitment(kind, pubkey_bytes.span());
        let payload = _payload_add_owner(kind, commitment, role, weight, label);
        self
            .governance
            .propose(OP_ADD_OWNER, proposer, payload, TIMELOCK_ADD_OWNER, DEFAULT_OP_EXPIRY_SECONDS)
    }

    #[external(v0)]
    fn propose_remove_owner(ref self: ContractState, proposer: u32, owner_id: u32) -> felt252 {
        _assert_self_call(@self);
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
        _assert_self_call(@self);
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
        _assert_self_call(@self);
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
        _assert_self_call(@self);
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
        _assert_self_call(@self);
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
        // Audit M-1 (V8.2, full): delegate per-kind validation to the
        // verifier class via library_call. Runs AFTER the governance
        // gate so a malformed pubkey can never sneak past timelocks
        // BUT the cheap timelock / op-kind checks fire first. Each
        // verifier validates shape AND curve membership; secp/p256
        // gracefully via `secp256_ec_new_syscall`, BLS by propagating
        // Garaga's panic on non-r-torsion. Replaces V8.1's
        // `_assert_pubkey_shape` length-only stopgap.
        _validate_pubkey_via_verifier(ref self, kind, pubkey_span);
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
        // Audit M-1 (V8.2, full): same per-verifier validation on
        // rotation as on registration. Runs after governance gate.
        _validate_pubkey_via_verifier(ref self, owner.kind, new_span);
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
        _assert_self_call(@self);
        self.governance.cancel(op_id);
    }

    #[external(v0)]
    fn get_pending_op(self: @ContractState, op_id: felt252) -> PendingOp {
        self.governance.get_op(op_id)
    }

    // ------------------------------------------------------------------
    // Phase 6 — guardian-initiated recovery.
    //
    // Recovery flow:
    //   1. `initiate_recovery` — self-call; proposer MUST have role=GUARDIAN.
    //      Stores the new-owner commitment with a 7-day timelock.
    //   2. `cancel_recovery` — self-call, any ROLE_OWNER. Clears the pending
    //      state instantly. Recommended to wire into an auto-watcher.
    //   3. `finalize_recovery` — PERMISSIONLESS after the timelock elapses.
    //      Caller re-provides the full new-owner args; we recompute the
    //      commitment and assert equality before adding to the owner set.
    //
    // Recovery is ADDITIVE: existing owners stay. The user is expected
    // to follow up with `remove_owner` governance proposals for the
    // devices they actually lost.
    // ------------------------------------------------------------------

    fn _recovery_new_owner_commitment(
        kind: felt252, pubkey_hash: felt252, role: felt252, weight: u8, label: felt252,
    ) -> felt252 {
        // Reuses the payload_add_owner shape — a recovery is, structurally,
        // an `add_owner` with a longer timelock and a guardian-authored proposal.
        _payload_add_owner(kind, pubkey_hash, role, weight, label)
    }

    #[external(v0)]
    fn initiate_recovery(
        ref self: ContractState,
        proposer: u32,
        new_owner_kind: felt252,
        new_pubkey_bytes: Array<felt252>,
        new_role: felt252,
        new_weight: u8,
        new_label: felt252,
    ) {
        _assert_self_call(@self);
        let proposer_record = self.owners.get_owner(proposer);
        assert(!proposer_record.revoked, 'RECOVERY: proposer revoked');
        assert(proposer_record.role == ROLE_GUARDIAN, 'RECOVERY: not a guardian');

        let pubkey_hash = crate::signer::interface::owner_commitment(
            new_owner_kind, new_pubkey_bytes.span(),
        );
        let commitment = _recovery_new_owner_commitment(
            new_owner_kind, pubkey_hash, new_role, new_weight, new_label,
        );
        self.recovery.initiate(commitment, TIMELOCK_RECOVERY);
    }

    #[external(v0)]
    fn cancel_recovery(ref self: ContractState, owner_id: u32) {
        _assert_self_call(@self);
        let owner = self.owners.get_owner(owner_id);
        assert(!owner.revoked, 'RECOVERY: canceler revoked');
        assert(owner.role == ROLE_OWNER, 'RECOVERY: not an owner');
        self.recovery.cancel();
    }

    #[external(v0)]
    fn finalize_recovery(
        ref self: ContractState,
        new_owner_kind: felt252,
        new_pubkey_bytes: Array<felt252>,
        new_role: felt252,
        new_weight: u8,
        new_label: felt252,
    ) -> u32 {
        // Permissionless — the 7-day window is the security property.
        let pubkey_span = new_pubkey_bytes.span();
        let pubkey_hash = crate::signer::interface::owner_commitment(new_owner_kind, pubkey_span);
        let expected = _recovery_new_owner_commitment(
            new_owner_kind, pubkey_hash, new_role, new_weight, new_label,
        );
        let stored = self.recovery.finalize();
        assert(stored == expected, 'RECOVERY: args mismatch');
        // Audit H-1 (V8.3, 2026-05-10): the third owner-mutation entry
        // point — was bypassing per-kind validation. A compromised
        // guardian could `initiate_recovery` with a poison-pill pubkey,
        // sit through the 7-day window, and `finalize_recovery` would
        // add the malformed owner to `owner_set` with role ROLE_OWNER,
        // contributing to total_weight even though it can never sign.
        // Same `_validate_pubkey_via_verifier` library_call as
        // `execute_add_owner` / `execute_rotate_owner`.
        _validate_pubkey_via_verifier(ref self, new_owner_kind, pubkey_span);
        self
            .owners
            .add_owner(new_owner_kind, pubkey_hash, pubkey_span, new_role, new_weight, new_label)
    }

    #[external(v0)]
    fn get_pending_recovery(
        self: @ContractState,
    ) -> crate::recovery::component::RecoveryComponent::PendingRecovery {
        self.recovery.read_pending()
    }

    // ------------------------------------------------------------------
    // Phase 7 — session keys + spending policy.
    //
    // Session management is owner-gated via `caller == self` (the
    // components' HasAccountOwner seam). Session signatures verify via
    // the 4-element path in execute_from_outside_v2. Spending caps
    // enforce per-token limits with rolling windows.
    // ------------------------------------------------------------------

    #[external(v0)]
    fn add_or_update_session_key(
        ref self: ContractState,
        session_key: felt252,
        valid_until: u64,
        max_calls: u32,
        allowed_entrypoints: Array<felt252>,
    ) {
        self
            .session_key
            .add_or_update_session_key(session_key, valid_until, max_calls, allowed_entrypoints)
    }

    #[external(v0)]
    fn revoke_session_key(ref self: ContractState, session_key: felt252) {
        self.session_key.revoke_session_key(session_key)
    }

    #[external(v0)]
    fn get_session_data(self: @ContractState, session_key: felt252) -> SessionData {
        self.session_key.get_session_data(session_key)
    }

    #[external(v0)]
    fn set_spending_policy(
        ref self: ContractState,
        session_key: felt252,
        token: ContractAddress,
        max_per_call: u256,
        max_per_window: u256,
        window_seconds: u64,
    ) {
        self
            .spending_policy
            .set_spending_policy(session_key, token, max_per_call, max_per_window, window_seconds)
    }

    #[external(v0)]
    fn remove_spending_policy(
        ref self: ContractState, session_key: felt252, token: ContractAddress,
    ) {
        self.spending_policy.remove_spending_policy(session_key, token)
    }

    #[external(v0)]
    fn get_spending_policy(
        self: @ContractState, session_key: felt252, token: ContractAddress,
    ) -> SpendingPolicy {
        self.spending_policy.get_spending_policy(session_key, token)
    }

    // ------------------------------------------------------------------
    // Phase 6.5 — sessions-wallet migration (chipi-pay/sessions-smart-contract).
    //
    // A `chipi-pay/sessions-smart-contract` wallet (`starknet-io/SNIPs#163`
    // reference impl) can migrate into V8 via two atomic steps bundled in
    // one OE signed by the current sessions owner:
    //
    //   1. `upgrade(SHHH_ACCOUNT_CLASS_HASH)` — OZ UpgradeableComponent
    //      swaps the class to ShhhAccount; sessions substorage is
    //      preserved.
    //   2. `bootstrap_from_sessions(public_key, verifier_class, label)` —
    //      this entrypoint, run against the new ShhhAccount class. Sets
    //      V8 primary-owner storage, registers the STARK verifier, emits
    //      indexer events.
    //
    // Atomicity requirement: the two calls MUST be part of the same OE
    // multicall. If called as separate txs, a front-runner could steal
    // the account between upgrade and bootstrap. The migration SDK
    // (scripts/ts/migrate-sessions-wallet.ts) bundles them by default.
    //
    // Gate: `primary_kind == 0` means "V8 not initialized yet". Both
    // fresh constructor-deployed accounts and already-bootstrapped
    // sessions upgrades land with primary_kind != 0, so the function
    // only succeeds once per account lifetime.
    //
    // Recovery, session keys, and spending policies in the OLD
    // substorage layout are preserved but NOT re-wired into V8 by this
    // bootstrap. Phase 7 adds a second-step migration that lifts
    // session data into the V8 session-key component.
    // ------------------------------------------------------------------

    #[external(v0)]
    fn bootstrap_from_sessions(
        ref self: ContractState,
        public_key: felt252,
        stark_verifier_class: ClassHash,
        label: felt252,
    ) {
        // Audit H-1 (2026-05-07 self-review): force atomic bundling with
        // `upgrade(...)`. The legitimate migration path is the OLD class's
        // multicall executing `[upgrade, bootstrap_from_sessions]` in one
        // OE — call 2's caller is the account itself. Without this gate,
        // any address watching the mempool could race the upgrade tx and
        // call `bootstrap_from_sessions(attacker_pk, …)` first, seizing
        // the account before the legitimate owner's bootstrap arrives.
        //
        // Stranded-state recovery (V8.4): if the OLD class's multicall is
        // non-atomic (chipi-pay/sessions-smart-contract is — see
        // `_execute_calls` in that repo, which swallows subcall errors at
        // a `Result::Err(_) => res.append(array![].span())` site), the
        // upgrade syscall can take effect while this call silently reverts
        // and leaves the account stranded at V8.3 with primary_kind == 0.
        // In that case use `bootstrap_from_sessions_signed` below — it
        // accepts a STARK signature from `public_key` over a canonical
        // bootstrap message bound to this account's address, so anyone
        // can re-trigger initialization (typically the original owner
        // themselves via a non-self relay or sponsor) without needing
        // a self-call channel.
        _assert_self_call(@self);
        _initialize_v8_from_sessions(ref self, public_key, stark_verifier_class, label);
    }

    /// Stranded-state recovery for the V8.0/V8.1/V8.2/V8.3 migration path
    /// (V8.4, audit-trail item from the 2026-05-12 review).
    ///
    /// Used ONLY when the sessions-contract upgrade tx left the account at
    /// the V8.3 class with `primary_kind == 0` — i.e., the upgrade syscall
    /// succeeded but the bundled bootstrap call reverted silently because
    /// the OLD class's OE multicall is non-atomic. The wallet at that
    /// point has no owners and no signature path to recover via
    /// `bootstrap_from_sessions` (which requires `_assert_self_call`).
    ///
    /// This entry point requires TWO independent authorization checks:
    ///
    /// 1. **Preserved-pubkey match** (audit C-1, 2026-05-12). The caller
    ///    supplies `public_key`, and we cross-reference it against the
    ///    OZ AccountComponent's `Account_public_key` storage slot that
    ///    the sessions-smart-contract class wrote at constructor time
    ///    (sessions-smart-contract `src/account.cairo:158` —
    ///    `self.account.initializer(public_key)`). The slot survives
    ///    `replace_class_syscall` losslessly (same property V8.x relies
    ///    on for `oe_nonces`). Without this check, anyone with a fresh
    ///    STARK keypair could sign the canonical msg below and seize
    ///    any stranded wallet — the 2026-05-12 V8.4 pre-merge audit's
    ///    Critical finding. The PoC test
    ///    `audit_poc_attacker_can_seize_any_stranded_wallet` in
    ///    `tests/account_migration.cairo` is the regression that
    ///    proves the gate fires.
    ///
    /// 2. **STARK ECDSA signature under `public_key`** over
    ///    `bootstrap_recovery_hash(public_key, stark_verifier_class,
    ///    label)`. The canonical hash binds:
    ///      - A domain-separator tag ('SHHH_BOOTSTRAP_V8_4') so the
    ///        signature cannot be reused across protocols.
    ///      - The account's own `get_contract_address()` so the
    ///        signature cannot be replayed on a different stranded
    ///        V8.x wallet.
    ///      - `public_key` so a frontrunner cannot substitute their
    ///        own key and re-broadcast the same signature.
    ///      - `stark_verifier_class` so a frontrunner cannot point
    ///        the kind dispatch at a malicious verifier.
    ///      - `label` so storage layout matches the original bootstrap
    ///        intent.
    ///
    /// Together: only an actor who (a) knew the legacy sessions owner's
    /// private key and (b) wants to bootstrap with that exact public_key
    /// + verifier + label tuple can pass both gates. A frontrunner who
    /// captures the legitimate signed tx and re-broadcasts it with the
    /// same parameters simply relays the intended bootstrap — not an
    /// attack. A frontrunner with a fresh keypair fails gate (1).
    ///
    /// Residual surface: a legitimate user whose private key is
    /// genuinely lost has no recovery path through this entry point.
    /// They must use guardian recovery (if previously set up) or the
    /// wallet is lost — no different from any other self-custodial
    /// wallet without a guardian. This is the correct security
    /// property for a recovery primitive.
    ///
    /// One-shot: same `primary_kind == 0` gate as the happy path.
    #[external(v0)]
    fn bootstrap_from_sessions_signed(
        ref self: ContractState,
        public_key: felt252,
        stark_verifier_class: ClassHash,
        label: felt252,
        signature_r: felt252,
        signature_s: felt252,
    ) {
        // No _assert_self_call — the whole point of this entry point is to
        // be usable from a non-self caller when the wallet is stranded.
        // Authorization is the TWO independent checks below.
        assert(self.primary_kind.read() == 0, 'MIG: already initialized');
        assert(public_key != 0, 'MIG: public_key is zero');
        let verifier_felt: felt252 = stark_verifier_class.into();
        assert(verifier_felt != 0, 'MIG: verifier class zero');

        // (1) Bind to the preserved sessions-smart-contract owner pubkey.
        //
        // The slot we read (`LEGACY_OZ_ACCOUNT_PUBKEY_SLOT`) is the
        // top-level storage address of OZ AccountComponent v3.0.0's
        // `Account_public_key` field. It's defined as a module-level
        // const above (search for `LEGACY_OZ_ACCOUNT_PUBKEY_SLOT`) so
        // the OZ-version dependency is named, documented, and
        // single-point-of-update. See the const's docstring for the
        // maintenance contract on OZ version bumps.
        //
        // The sessions class writes this slot at constructor time. After
        // `replace_class_syscall` to V8.4, storage persists; the slot
        // remains the legacy pubkey. We read it via `storage_read_syscall`
        // (domain 0) and require equality with the supplied `public_key`.
        //
        // Edge cases:
        //   - slot is 0 (legacy class didn't use OZ AccountComponent at
        //     this slot, OR OZ renamed the field in a future version and
        //     the const is stale): revert with 'MIG: no legacy pk' —
        //     recovery via this entry point is unreachable for such
        //     wallets, which fails closed safely (no takeover surface)
        //     but means legitimate users of newer OZ versions cannot
        //     recover via this path until the const is re-verified.
        //   - slot is non-zero but != public_key: revert with
        //     'MIG: pk mismatch' — the supplied pubkey doesn't match the
        //     preserved legacy owner; either the caller is an attacker
        //     with a fresh keypair (audit C-1) or the wallet's legacy
        //     class used a different slot for the owner key.
        let slot_address: starknet::storage_access::StorageAddress = LEGACY_OZ_ACCOUNT_PUBKEY_SLOT
            .try_into()
            .expect('MIG: bad slot address');
        let preserved_slot = starknet::syscalls::storage_read_syscall(0, slot_address).unwrap();
        assert(preserved_slot != 0, 'MIG: no legacy pk');
        assert(public_key == preserved_slot, 'MIG: pk mismatch');

        // (2) Verify the STARK ECDSA signature under `public_key`.
        let bootstrap_msg = core::poseidon::poseidon_hash_span(
            array![
                'SHHH_BOOTSTRAP_V8_4', starknet::get_contract_address().into(), public_key,
                verifier_felt, label,
            ]
                .span(),
        );
        assert(
            core::ecdsa::check_ecdsa_signature(bootstrap_msg, public_key, signature_r, signature_s),
            'MIG: bad bootstrap signature',
        );

        _initialize_v8_from_sessions(ref self, public_key, stark_verifier_class, label);
    }

    /// Shared initialization between `bootstrap_from_sessions` (self-call
    /// happy path) and `bootstrap_from_sessions_signed` (stranded-state
    /// recovery).
    ///
    /// **INVARIANT — CALLER MUST AUTHORIZE BEFORE INVOKING.** This helper
    /// does NOT perform any caller-identity check. The two current
    /// callers each handle authorization themselves:
    ///   - `bootstrap_from_sessions` gates on `_assert_self_call` (only
    ///     the account itself, called inside an atomic OE multicall).
    ///   - `bootstrap_from_sessions_signed` gates on the preserved-pubkey
    ///     match (audit C-1) plus a STARK ECDSA signature under that
    ///     pubkey over the canonical bootstrap message.
    ///
    /// The defensive re-checks below (`primary_kind == 0`,
    /// `public_key != 0`, `verifier_felt != 0`) verify PARAMETER VALIDITY
    /// only — they do NOT replace authorization. If a future entry point
    /// is added that calls this helper, that entry point MUST install its
    /// own authorization gate before delegating. The audit-2026-05-12
    /// Informational finding on this helper recommended an enum-based
    /// `AuthProof` pattern; the comment here is the lighter-weight
    /// equivalent until a third caller exists.
    fn _initialize_v8_from_sessions(
        ref self: ContractState,
        public_key: felt252,
        stark_verifier_class: ClassHash,
        label: felt252,
    ) {
        // Defensive: re-assert the one-shot gate. Both callers also assert
        // this earlier so they get a distinct revert string, but if a
        // future entry point forgets the assertion this catches it.
        assert(self.primary_kind.read() == 0, 'MIG: already initialized');
        assert(public_key != 0, 'MIG: public_key is zero');
        let verifier_felt: felt252 = stark_verifier_class.into();
        assert(verifier_felt != 0, 'MIG: verifier class zero');

        // Same derivations the constructor uses.
        let kind = 'STARK';
        let pubkey_span = array![public_key].span();
        let commitment = crate::signer::interface::owner_commitment(kind, pubkey_span);
        let salt = core::poseidon::poseidon_hash_span(array![kind, commitment].span());

        self.primary_kind.write(kind);
        self.primary_pubkey_hash.write(commitment);
        self.address_salt.write(salt);
        self.owners.initialize_primary(kind, commitment, pubkey_span, label);
        self.verifier_classes.write(kind, stark_verifier_class);
        self.src5.register_interface(ISRC9_V2_ID);
        self.src5.register_interface(ISIGNER_ID);
        // Audit M-2 (V8.3, 2026-05-10): the third owner-mutation entry
        // point — was bypassing per-kind validation. Today benign
        // (kind hardcoded to STARK and `assert(public_key != 0)`
        // coincides with `StarkVerifier::validate_pubkey`'s shape-only
        // check) but the V8.2 invariant is "always delegate to
        // verifier"; this path used to silently break it. Placed
        // AFTER the verifier_classes.write so the lookup hits.
        _validate_pubkey_via_verifier(ref self, kind, pubkey_span);

        self
            .emit(
                PrimaryOwnerInitialized {
                    kind, pubkey_hash: commitment, verifier_class: stark_verifier_class, salt,
                },
            );
        self.emit(VerifierClassAdded { kind, class_hash: stark_verifier_class });
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

    fn _assert_self_call(self: @ContractState) {
        assert(get_caller_address() == get_contract_address(), 'SHHH: caller != self');
        // Audit M-2 (2026-05-07): refuse self-calls that originate from
        // inside a library_call'd verifier. A malicious verifier class
        // running in the account's storage + address context could
        // otherwise loop back into any `_assert_self_call`-gated mutator
        // and effectively be a co-owner. The `inside_verifier` flag is
        // raised around every `dispatcher.verify(...)` and lowered after
        // it returns; legitimate self-call mutators are issued from the
        // multicall executor where this flag is never set.
        assert(!self.inside_verifier.read(), 'SHHH: verifier reentry');
    }

    /// Audit M-1 (V8.2 full + V8.3 reentrancy) — delegate per-kind
    /// pubkey validation to the registered verifier class via
    /// `library_call`, with the M-2 `inside_verifier` flag raised
    /// for the duration of the call.
    ///
    /// Behavior:
    ///   - For curves with a non-panicking on-curve syscall (secp256k1,
    ///     P-256 family) the verifier returns `false` on a bad pubkey;
    ///     the assert here re-raises as a clean revert.
    ///   - For BLS12-381 the verifier MAY panic (Garaga's
    ///     `assert_in_subgroup_excluding_infinity` panics on
    ///     non-r-torsion / off-curve / infinity). The panic propagates
    ///     and reverts the registration tx — same security outcome as
    ///     returning false.
    ///   - For an unknown kind the verifier_classes lookup returns
    ///     a zero ClassHash, and we revert with `'SHHH: verifier
    ///     missing'`.
    ///
    /// V8.3 (audit 2026-05-10) — `inside_verifier` is now raised
    /// AROUND the library_call so a malicious verifier class
    /// (governance-vetted but rogue) cannot
    /// `call_contract_syscall(self, "propose_*")` back into a
    /// `_assert_self_call`-gated mutator from inside its
    /// validate_pubkey. The execute_add_owner / execute_rotate_owner
    /// paths are PERMISSIONLESS post-timelock, so this flag is the
    /// load-bearing reentrancy block for those paths — same trust
    /// boundary the verify-path M-2 fix already enforces.
    fn _validate_pubkey_via_verifier(
        ref self: ContractState, kind: felt252, pubkey: Span<felt252>,
    ) {
        let v_class = self.verifier_classes.read(kind);
        assert(Into::<ClassHash, felt252>::into(v_class) != 0, 'SHHH: verifier missing');
        let dispatcher = ISignerLibraryDispatcher { class_hash: v_class };
        // V8.3 — raise inside_verifier, dispatch, lower, then check
        // the result. Identical control flow to the verify path
        // (single-owner OE at line 469-472 and threshold inner at
        // 1257-1259) so a panic in dispatcher.validate_pubkey unwinds
        // the storage write atomically along with the rest of the tx.
        self.inside_verifier.write(true);
        let ok = dispatcher.validate_pubkey(pubkey);
        self.inside_verifier.write(false);
        assert(ok, 'M1: invalid pubkey');
    }

    /// Session-sig validation (SNIPs#163 base blocklist + V8 extension).
    fn _verify_session_sig_and_consume(
        ref self: ContractState, calls: Span<Call>, signature: Span<felt252>, message_hash: felt252,
    ) {
        let session_pubkey = *signature.at(0);
        let r = *signature.at(1);
        let s = *signature.at(2);
        let valid_until: u64 = (*signature.at(3)).try_into().expect('SESSION: bad valid_until');

        assert(get_block_timestamp() <= valid_until, 'SESSION: expired');

        // Ported SNIPs#163 guard chain: session exists, expiry, call count,
        // admin blocklist (base), self-call block if whitelist empty,
        // selector whitelist.
        assert(
            self.session_key.is_session_allowed_for_calls(session_pubkey, calls),
            'SESSION: call not allowed',
        );

        // V8-specific blocklist — reject any call targeting our governance,
        // recovery, migration, or verifier-class mutators.
        assert(_v8_blocklist_ok(calls, get_contract_address()), 'SESSION: V8-blocked selector');

        assert(check_ecdsa_signature(message_hash, session_pubkey, r, s), 'SESSION: bad signature');

        self.session_key.consume_session_call(session_pubkey);
    }

    /// V8.4 guardian-OE carve-out check. Returns true iff `calls` is
    /// exactly one call to `initiate_recovery` on the account itself AND
    /// the first calldata felt (the `proposer` arg) equals
    /// `signer_owner_id`. Used by `execute_from_outside_v2` to allow
    /// ROLE_GUARDIAN signers exclusively for the recovery-initiation
    /// path; every other selector still requires ROLE_OWNER.
    ///
    /// The `proposer == signer_owner_id` clause prevents a guardian from
    /// signing an OE that names a different owner_id as proposer (the
    /// proposer arg ends up in the event log + the recovery payload
    /// commitment, so binding it to the signer keeps the audit trail
    /// honest). The recovery flow's own role check on the proposer
    /// (`proposer_record.role == ROLE_GUARDIAN` at `initiate_recovery`)
    /// remains as defense-in-depth.
    fn _is_single_initiate_recovery_call(
        calls: Span<Call>, self_addr: ContractAddress, signer_owner_id: u32,
    ) -> bool {
        if calls.len() != 1_u32 {
            return false;
        }
        let call = calls.at(0);
        if *call.to != self_addr {
            return false;
        }
        if *call.selector != selector!("initiate_recovery") {
            return false;
        }
        // initiate_recovery(proposer, new_kind, new_pubkey_bytes,
        //                   new_role, new_weight, new_label)
        // — `proposer` is the first felt of calldata. Require it match
        // the OE signer's owner_id so a guardian can only initiate on
        // their own behalf.
        //
        // V8.4 audit L-1 (2026-05-12): require the well-formed Serde
        // minimum (7 felts: proposer + kind + pubkey_bytes_len + ≥1
        // pubkey felt + role + weight + label). Without this floor the
        // helper would accept truncated calldata; the OE then proceeds
        // to call_contract_syscall, and safety relies on
        // _execute_calls_atomic_span panicking with 'H1: subcall
        // failed' when Serde deserialization fails inside
        // initiate_recovery. The coupling is fragile — a future
        // change that catches Serde errors more leniently would let
        // a malformed initiate_recovery reach the recovery component
        // with default-zero fields. Defense-in-depth check here.
        let calldata: Span<felt252> = *call.calldata;
        if calldata.len() < 7_u32 {
            return false;
        }
        let proposer_felt: felt252 = (*calldata.at(0));
        let proposer_id: u32 = match proposer_felt.try_into() {
            Option::Some(v) => v,
            Option::None => { return false; },
        };
        proposer_id == signer_owner_id
    }

    /// V8-specific admin selectors that sessions must never reach.
    fn _v8_blocklist_ok(calls: Span<Call>, self_addr: ContractAddress) -> bool {
        let mut i: u32 = 0;
        while i < calls.len() {
            let call = calls.at(i);
            if *call.to == self_addr {
                let sel = *call.selector;
                if sel == selector!("propose_add_owner")
                    || sel == selector!("propose_remove_owner")
                    || sel == selector!("propose_rotate_owner")
                    || sel == selector!("propose_set_threshold")
                    || sel == selector!("propose_add_verifier_class")
                    || sel == selector!("propose_remove_verifier_class")
                    || sel == selector!("execute_add_owner")
                    || sel == selector!("execute_remove_owner")
                    || sel == selector!("execute_rotate_owner")
                    || sel == selector!("execute_set_threshold")
                    || sel == selector!("execute_add_verifier_class")
                    || sel == selector!("execute_remove_verifier_class")
                    || sel == selector!("cancel_pending_op")
                    || sel == selector!("initiate_recovery")
                    || sel == selector!("cancel_recovery")
                    || sel == selector!("finalize_recovery")
                    || sel == selector!("bootstrap_from_sessions")
                    || sel == selector!("bootstrap_from_sessions_signed") {
                    return false;
                }
            }
            i += 1;
        }
        true
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

    fn _slice_range(span: Span<felt252>, start: u32, end: u32) -> Span<felt252> {
        let mut out: Array<felt252> = array![];
        let mut i: u32 = start;
        while i < end {
            out.append(*span.at(i));
            i += 1;
        }
        out.span()
    }

    /// Verifies one inner envelope shaped `[owner_id, kind_tag, payload...]`
    /// (no version tag — that's handled once by the outer threshold frame).
    /// Reverts on any integrity failure. Returns (owner_id, owner.kind, owner.weight).
    fn _verify_sub_envelope(
        ref self: ContractState, sub: Span<felt252>, message_hash: felt252,
    ) -> (u32, felt252, u8) {
        assert(sub.len() >= 2_u32, 'THRESH: inner too short');
        let owner_id: u32 = (*sub.at(0)).try_into().expect('THRESH: bad owner_id');
        assert(owner_id < self.owners.owner_count(), 'THRESH: unknown owner_id');
        let owner: OwnerRecord = self.owners.get_owner(owner_id);
        assert(!owner.revoked, 'THRESH: owner revoked');
        // Audit C-1 (2026-05-07): guardians MUST NOT contribute weight to a
        // threshold envelope. Same rationale as the single-owner OE path —
        // a non-revoked GUARDIAN is otherwise indistinguishable from a
        // primary owner and would silently satisfy the threshold.
        assert(owner.role == ROLE_OWNER, 'THRESH: signer not an owner');
        let kind_tag = *sub.at(1);
        assert(kind_tag == owner.kind, 'THRESH: kind mismatch');
        let verifier_class = self.verifier_classes.read(owner.kind);
        assert(Into::<ClassHash, felt252>::into(verifier_class) != 0, 'THRESH: verifier missing');
        let pubkey = self.owners.read_pubkey_bytes(owner);
        let payload = _slice_from(sub, 2);
        let dispatcher = ISignerLibraryDispatcher { class_hash: verifier_class };
        // Audit M-2 (2026-05-07): same flag wrapping as the single-owner
        // path — block re-entry into self-call-gated mutators while a
        // library_call'd verifier holds the floor.
        self.inside_verifier.write(true);
        let ok = dispatcher.verify(message_hash, pubkey.span(), payload);
        self.inside_verifier.write(false);
        assert(ok, 'THRESH: inner sig invalid');
        (owner_id, owner.kind, owner.weight)
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
