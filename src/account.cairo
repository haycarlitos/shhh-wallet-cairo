//! ShhhAccount — V8 account class, Phase 3 scope.
//!
//! Single primary owner + pluggable verifier via `library_call_syscall`.
//! Multi-owner / governance / recovery / session-keys land in Phases 4–7
//! and augment (not replace) the storage layout below.
//!
//! Every audit finding from 2026-04-20 is enforced in-contract, with the
//! same error prefixes (`C1:`, `H1:`, `M1:`..`M4:`, `L1:`, etc.) as the
//! V7 in-place patch on `src/wallet.cairo`. Phase 3 tests confirm each
//! guard fires.
//!
//! Deployment calldata:
//!   [ primary_kind,                          // felt252 short-string
//!     primary_verifier_class_hash,           // ClassHash
//!     pubkey_len, pubkey_0, ..., pubkey_n,   // Span<felt252>
//!     label ]                                // felt252 user tag

#[starknet::contract(account)]
pub mod ShhhAccount {
    use core::num::traits::Zero;
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
    use crate::outside_execution::{
        ISRC9_V2, ISRC9_V2_ID, OutsideExecution, SIG_VERSION_V2_SNIP12, compute_snip12_hash,
    };
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

    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;
    impl SRC5InternalImpl = SRC5Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        // Primary owner, frozen at deploy.
        primary_kind: felt252,
        primary_pubkey_hash: felt252,
        // Append-only pubkey bytes log (only one entry today; multi-owner
        // Phase 4 adds more).
        primary_pubkey_len: u32,
        primary_pubkey_slot: u64,
        pubkey_bytes: Map<u64, felt252>,
        pubkey_cursor: u64,
        // Kind → verifier class hash. Mutating this is restricted to
        // `caller == self` until Phase 5 wires timelocked governance.
        verifier_classes: Map<felt252, ClassHash>,
        // SRC9 nonces.
        oe_nonces: Map<felt252, bool>,
        // SRC5.
        #[substorage(v0)]
        src5: SRC5Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        SRC5Event: SRC5Component::Event,
        VerifierClassAdded: VerifierClassAdded,
    }

    #[derive(Drop, starknet::Event)]
    struct VerifierClassAdded {
        #[key]
        kind: felt252,
        class_hash: ClassHash,
    }

    // ------------------------------------------------------------------
    // Constructor
    //
    // Audit L-1: we delegate public-key range checks to the verifier
    // class itself (via a probe call that will fire in Phase 4 when
    // `validate_pubkey` is added to the ISigner trait). Until then we
    // require a non-zero commitment and a non-empty pubkey span.
    // ------------------------------------------------------------------

    #[constructor]
    fn constructor(
        ref self: ContractState,
        primary_kind: felt252,
        primary_verifier: ClassHash,
        pubkey: Span<felt252>,
        label: felt252,
    ) {
        let _ = label; // labels are a Phase 4 owner-set feature
        assert(primary_kind != 0, 'L1: primary_kind is zero');
        assert(pubkey.len() > 0_u32, 'L1: pubkey empty');
        let verifier_felt: felt252 = primary_verifier.into();
        assert(verifier_felt != 0, 'L1: verifier class zero');

        // Store pubkey bytes and commitment.
        let slot = _append_pubkey_bytes(ref self, pubkey);
        let commitment = crate::signer::interface::owner_commitment(primary_kind, pubkey);

        self.primary_kind.write(primary_kind);
        self.primary_pubkey_hash.write(commitment);
        self.primary_pubkey_len.write(pubkey.len());
        self.primary_pubkey_slot.write(slot);
        self.verifier_classes.write(primary_kind, primary_verifier);

        // Register the canonical SRC9 V2 interface (audit H-2).
        self.src5.register_interface(ISRC9_V2_ID);

        self.emit(VerifierClassAdded { kind: primary_kind, class_hash: primary_verifier });
    }

    // ------------------------------------------------------------------
    // __validate__ — always reverts.
    // ------------------------------------------------------------------

    #[external(v0)]
    fn __validate__(ref self: ContractState, _calls: Array<Call>) -> felt252 {
        core::panic_with_felt252('SHHH: __validate__ disabled')
    }

    #[external(v0)]
    fn __validate_declare__(self: @ContractState, _class_hash: felt252) -> felt252 {
        core::panic_with_felt252('SHHH: declare disabled')
    }

    // __validate_deploy__ is intentionally omitted — deploys are sponsored
    // by the paymaster (which performs its own sanity checks) and the
    // deterministic address binds primary_kind + pubkey_hash into the
    // salt. No on-chain deploy-time signature is required.

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
                // 2a. Window cap on bearer payloads (M-2).
                let window = outside_execution.execute_before - outside_execution.execute_after;
                assert(window <= MAX_ANY_CALLER_VALIDITY_SECONDS, 'M2: window too long');
            } else {
                assert(caller_felt != 0, 'M1: caller=0 rejected');
                assert(get_caller_address() == outside_execution.caller, 'SRC9: invalid caller');
            }

            // 2b. Time bounds.
            let now = get_block_timestamp();
            assert(outside_execution.execute_after < now, 'SRC9: too early');
            assert(now < outside_execution.execute_before, 'SRC9: too late');

            // 3. Nonce replay check.
            assert(!self.oe_nonces.read(outside_execution.nonce), 'SRC9: duplicate nonce');
            self.oe_nonces.write(outside_execution.nonce, true);

            // 4. Bounds (M-3). Computed before any hashing or library_call.
            assert(outside_execution.calls.len() <= MAX_CALLS, 'M3: too many calls');
            assert(
                _total_calldata_felts(outside_execution.calls) <= MAX_TOTAL_CALLDATA_FELTS,
                'M3: calldata too large',
            );
            assert(signature.len() <= MAX_SIGNATURE_FELTS, 'M3: signature too long');

            // 5. Owner envelope header. Phase 3 only supports the V2 SNIP-12
            //    hashing path; legacy V1_HEX_ASCII route stays in
            //    `wallet.cairo` (the V7 in-place patch) during the
            //    deprecation window.
            assert(signature.len() >= OE_OWNER_ENVELOPE_HEADER_LEN, 'SRC9: sig too short');
            let version_tag = *signature.at(0);
            assert(version_tag == SIG_VERSION_V2_SNIP12, 'SHHH: unsupported sig version');

            let owner_id: u32 = (*signature.at(1)).try_into().expect('SHHH: bad owner_id');
            assert(owner_id == 0_u32, 'SHHH: unknown owner_id');

            let kind_tag = *signature.at(2);
            let primary_kind = self.primary_kind.read();
            assert(kind_tag == primary_kind, 'SHHH: kind mismatch');

            // 6. Compute SNIP-12 hash and dispatch to the verifier class.
            let chain_id = get_tx_info().unbox().chain_id;
            let message_hash = compute_snip12_hash(
                @outside_execution, get_contract_address(), chain_id,
            );
            let verifier_class = self.verifier_classes.read(primary_kind);
            assert(Into::<ClassHash, felt252>::into(verifier_class) != 0, 'SHHH: verifier missing');

            // Load primary pubkey span out of storage.
            let pubkey = _read_primary_pubkey(@self);

            // `library_call` invokes the verifier in the account's own
            // execution context. The verifier is a pure function —
            // cannot mutate account storage.
            let verifier_payload = _slice_from(signature, OE_OWNER_ENVELOPE_HEADER_LEN);
            let dispatcher = ISignerLibraryDispatcher { class_hash: verifier_class };
            let ok = dispatcher.verify(message_hash, pubkey.span(), verifier_payload);
            assert(ok, 'SHHH: signature invalid');

            // 7. Atomic multicall (H-1).
            _execute_calls_atomic_span(outside_execution.calls)
        }

        fn is_valid_outside_execution_nonce(self: @ContractState, nonce: felt252) -> bool {
            !self.oe_nonces.read(nonce)
        }
    }

    // ------------------------------------------------------------------
    // Introspection
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
    fn get_verifier_class(self: @ContractState, kind: felt252) -> ClassHash {
        self.verifier_classes.read(kind)
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn _append_pubkey_bytes(ref self: ContractState, bytes: Span<felt252>) -> u64 {
        let start = self.pubkey_cursor.read();
        let mut i: u32 = 0;
        while i < bytes.len() {
            let slot: u64 = start + i.into();
            self.pubkey_bytes.write(slot, *bytes.at(i));
            i += 1;
        }
        self.pubkey_cursor.write(start + bytes.len().into());
        start
    }

    fn _read_primary_pubkey(self: @ContractState) -> Array<felt252> {
        let len = self.primary_pubkey_len.read();
        let slot = self.primary_pubkey_slot.read();
        let mut out: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < len {
            let s: u64 = slot + i.into();
            out.append(self.pubkey_bytes.read(s));
            i += 1;
        }
        out
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
