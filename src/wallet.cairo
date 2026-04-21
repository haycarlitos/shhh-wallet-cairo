//! Shhh Wallet V8 — audit-closed core.
//!
//! This is the in-place V7 patch that closes every finding from the
//! 2026-04-20 Codex/Cairo audit (Omar Espejel). The code structure and
//! ABI are unchanged so existing Phantom flows keep working; each
//! guard below is annotated with the finding it closes.
//!
//! Finding index:
//!   C-1 → `__execute__` caller + tx-version gate
//!   H-1 → atomic multicall (panic on any subcall failure)
//!   H-2 → corrected ISRC9_V2 interface ID registration
//!         (see `outside_execution.cairo`)
//!   M-1 → `caller == 0` rejected; only 'ANY_CALLER' is the sentinel
//!   M-2 → 2h cap on 'ANY_CALLER' validity window
//!   M-3 → MAX_CALLS / MAX_TOTAL_CALLDATA / MAX_SIGNATURE bounds
//!   M-4 → `signature.len() >= 5 + msg_len` + trailing-bytes rejection
//!   L-1 → constructor validates u128 range of both pubkey halves
//!   I-1 → custom calls hash retained behind an explicit tagged encoding
//!         (documented as project-specific; see `hash_calls_for_oe`)
//!   I-3 → UpgradeableComponent removed; account is immutable

#[starknet::contract(account)]
pub mod ShhhWallet {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use garaga::signatures::eddsa_25519::{EdDSASignatureWithHint, is_valid_eddsa_signature};
    use openzeppelin::introspection::src5::SRC5Component;
    use starknet::account::Call;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use starknet::{
        ContractAddress, get_block_timestamp, get_caller_address, get_contract_address, get_tx_info,
        syscalls,
    };
    use crate::ed25519::component::{Ed25519WalletComponent, HasOwner};
    use crate::ed25519::interface::IShhhWallet;
    use crate::outside_execution::{ISRC9_V2, ISRC9_V2_ID, OutsideExecution};

    // ------------------------------------------------------------------
    // Audit M-2 / M-3 — explicit bounds.
    // ------------------------------------------------------------------
    /// Max number of calls per outside-execution. Real flows use 3–5.
    pub const MAX_CALLS: u32 = 16;
    /// Max sum of calldata felts across all calls. Guards paymaster resources.
    pub const MAX_TOTAL_CALLDATA_FELTS: u32 = 1024;
    /// Max signature envelope length (felts).
    pub const MAX_SIGNATURE_FELTS: u32 = 1024;
    /// Max validity window for an 'ANY_CALLER' payload (seconds).
    /// Sized to cover Solana→Starknet CCTP pre-sign finality (~20–30 min)
    /// with comfortable headroom.
    pub const MAX_ANY_CALLER_VALIDITY_SECONDS: u64 = 7_200;

    // Owner signature envelope prefix that must match the msg bytes layout
    // (5 felts: Ry_low, Ry_high, s_low, s_high, msg_len).
    const SIG_PREFIX_LEN: u32 = 5;

    component!(path: Ed25519WalletComponent, storage: ed25519, event: Ed25519Event);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;

    impl Ed25519InternalImpl = Ed25519WalletComponent::InternalImpl<ContractState>;
    impl SRC5InternalImpl = SRC5Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        ed25519: Ed25519WalletComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        outside_nonces: Map<felt252, bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        Ed25519Event: Ed25519WalletComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
    }

    impl HasOwnerImpl of HasOwner<ContractState> {
        fn get_owner_keys(self: @ContractState) -> (felt252, felt252) {
            self.ed25519._get_owner()
        }
    }

    // ------------------------------------------------------------------
    // Constructor.
    //
    // Audit L-1: both pubkey halves MUST be u128-range. If either exceeds
    // u128::MAX the wallet would deploy but panic on every future tx —
    // creating a bricked account. We reject up front with a controlled
    // error so factories cannot ship unusable wallets.
    // ------------------------------------------------------------------
    #[constructor]
    fn constructor(ref self: ContractState, owner_pubkey_low: felt252, owner_pubkey_high: felt252) {
        let _: u128 = owner_pubkey_low.try_into().expect('L1: owner_low OOR');
        let _: u128 = owner_pubkey_high.try_into().expect('L1: owner_high OOR');
        self.ed25519.initializer(owner_pubkey_low, owner_pubkey_high);
        self.src5.register_interface(ISRC9_V2_ID);
    }

    #[abi(embed_v0)]
    impl ShhhWalletImpl of IShhhWallet<ContractState> {
        fn get_owner(self: @ContractState) -> (felt252, felt252) {
            self.ed25519._get_owner()
        }
    }

    // ------------------------------------------------------------------
    // __validate__ — always reverts. Owner-authorized action MUST use
    // `execute_from_outside_v2`. This entrypoint exists only to satisfy
    // the standard account ABI so sequencers can probe it.
    // ------------------------------------------------------------------
    #[external(v0)]
    fn __validate__(self: @ContractState, _calls: Array<Call>) -> felt252 {
        core::panic_with_felt252('SHHH: __validate__ disabled')
    }

    // ------------------------------------------------------------------
    // __execute__ — protocol / paymaster-estimation path ONLY.
    //
    // Audit C-1: must reject non-zero, non-self callers and require a
    // non-deprecated transaction version. This entrypoint previously
    // allowed arbitrary callers to execute arbitrary calls.
    //
    // Audit H-1: subcall failures revert the whole multicall.
    // ------------------------------------------------------------------
    #[external(v0)]
    fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
        let caller = get_caller_address();
        let is_sequencer_or_self = caller.is_zero() || caller == get_contract_address();
        assert(is_sequencer_or_self, 'C1: unauthorized caller');

        let tx_info = get_tx_info().unbox();
        let v: u32 = tx_info.version.try_into().unwrap_or(0_u32);
        assert(v >= 1_u32, 'C1: invalid tx version');

        _execute_calls_atomic(calls)
    }

    /// Atomic multicall. Audit H-1: any subcall failure reverts the whole
    /// transaction — NO silent empty-span fallback.
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

    /// Audit I-1 hardening — explicit tag bytes. The encoding is now
    ///     [CALLS_TAG, num_calls, CALL_TAG, to, selector, cd_len, cd..., ...]
    /// which prevents any future change to the calls array from producing
    /// a colliding pre-image with a different-shape payload.
    const CALLS_TAG: felt252 = 'SHHH_CALLS_V1';
    const CALL_TAG: felt252 = 'SHHH_CALL_V1';

    fn hash_calls_for_oe(calls: Span<Call>) -> felt252 {
        let mut data: Array<felt252> = array![];
        data.append(CALLS_TAG);
        data.append(calls.len().into());
        let mut calls_copy = calls;
        loop {
            match calls_copy.pop_front() {
                Option::Some(call) => {
                    data.append(CALL_TAG);
                    data.append((*call.to).into());
                    data.append(*call.selector);
                    let cd_len: felt252 = (*call.calldata).len().into();
                    data.append(cd_len);
                    let mut calldata = *call.calldata;
                    loop {
                        match calldata.pop_front() {
                            Option::Some(cd) => data.append(*cd),
                            Option::None => { break; },
                        }
                    };
                },
                Option::None => { break; },
            }
        }
        poseidon_hash_span(data.span())
    }

    fn bytes_to_hex_ascii(bytes: @Array<u8>) -> Array<u8> {
        let hex_chars: [u8; 16] = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66,
        ];
        let hex_span = hex_chars.span();
        let mut result: Array<u8> = array![];
        let mut i: u32 = 0;
        while i < bytes.len() {
            let b: u16 = (*bytes.at(i)).into();
            result.append(*hex_span.at((b / 16).try_into().unwrap()));
            result.append(*hex_span.at((b % 16).try_into().unwrap()));
            i += 1;
        }
        result
    }

    fn append_felt252_be(ref bytes: Array<u8>, value: felt252) {
        let v: u256 = value.into();
        append_u128_be(ref bytes, v.high);
        append_u128_be(ref bytes, v.low);
    }

    fn append_u128_be(ref bytes: Array<u8>, value: u128) {
        let mut temp: Array<u8> = array![];
        let mut remaining = value;
        let mut i: u32 = 0;
        while i < 16 {
            let byte: u8 = (remaining % 256).try_into().unwrap();
            temp.append(byte);
            remaining = remaining / 256;
            i += 1;
        }
        let mut j: u32 = 16;
        while j > 0 {
            j -= 1;
            bytes.append(*temp.at(j));
        };
    }

    fn append_u64_be(ref bytes: Array<u8>, value: u64) {
        let mut temp: Array<u8> = array![];
        let mut remaining = value;
        let mut i: u32 = 0;
        while i < 8 {
            let byte: u8 = (remaining % 256).try_into().unwrap();
            temp.append(byte);
            remaining = remaining / 256;
            i += 1;
        }
        let mut j: u32 = 8;
        while j > 0 {
            j -= 1;
            bytes.append(*temp.at(j));
        };
    }

    fn encode_outside_execution_bytes(
        outside_execution: @OutsideExecution, contract_address: ContractAddress, chain_id: felt252,
    ) -> Array<u8> {
        let mut bytes: Array<u8> = array![];
        // Domain separator "SHHH_OE_V1" (10 ASCII bytes)
        bytes.append(0x53);
        bytes.append(0x48);
        bytes.append(0x48);
        bytes.append(0x48);
        bytes.append(0x5f);
        bytes.append(0x4f);
        bytes.append(0x45);
        bytes.append(0x5f);
        bytes.append(0x56);
        bytes.append(0x31);
        append_felt252_be(ref bytes, chain_id);
        append_felt252_be(ref bytes, contract_address.into());
        let caller_felt: felt252 = (*outside_execution.caller).into();
        append_felt252_be(ref bytes, caller_felt);
        append_felt252_be(ref bytes, *outside_execution.nonce);
        append_u64_be(ref bytes, *outside_execution.execute_after);
        append_u64_be(ref bytes, *outside_execution.execute_before);
        let calls_hash = hash_calls_for_oe(*outside_execution.calls);
        append_felt252_be(ref bytes, calls_hash);
        bytes
    }

    fn total_calldata_felts(calls: Span<Call>) -> u32 {
        let mut total: u32 = 0;
        let mut calls_copy = calls;
        loop {
            match calls_copy.pop_front() {
                Option::Some(call) => { total += (*call.calldata).len(); },
                Option::None => { break; },
            }
        }
        total
    }

    // ------------------------------------------------------------------
    // execute_from_outside_v2 — the SINGLE real execution path.
    //
    // Step order mirrors the audit-response plan:
    //   1. caller check (M-1)
    //   2. time window + ANY_CALLER cap (M-2)
    //   3. nonce replay
    //   4. bounds (M-3)
    //   5. verify msg bytes against canonical OE encoding, verify
    //      Ed25519 signature via Garaga (M-4, I-1)
    //   6. atomic multicall (H-1)
    // ------------------------------------------------------------------

    #[abi(embed_v0)]
    impl SRC9V2Impl of ISRC9_V2<ContractState> {
        fn execute_from_outside_v2(
            ref self: ContractState, outside_execution: OutsideExecution, signature: Span<felt252>,
        ) -> Array<Span<felt252>> {
            // 1. Caller check.
            //    Audit M-1: `caller == 0` is NOT a valid unrestricted sentinel.
            //    Only the short-string `'ANY_CALLER'` unlocks the
            //    unrestricted-submitter path.
            let caller_felt: felt252 = outside_execution.caller.into();
            if caller_felt == 'ANY_CALLER' {
                // 2a. ANY_CALLER payloads are bearer credentials — cap their
                //     validity window (audit M-2).
                let window = outside_execution.execute_before - outside_execution.execute_after;
                assert(window <= MAX_ANY_CALLER_VALIDITY_SECONDS, 'M2: window too long');
            } else {
                assert(caller_felt != 0, 'M1: caller=0 rejected');
                assert(get_caller_address() == outside_execution.caller, 'SRC9: invalid caller');
            }

            // 2b. Standard time-window bounds.
            let now = get_block_timestamp();
            assert(outside_execution.execute_after < now, 'SRC9: too early');
            assert(now < outside_execution.execute_before, 'SRC9: too late');

            // 3. Nonce replay.
            assert(!self.outside_nonces.read(outside_execution.nonce), 'SRC9: duplicate nonce');
            self.outside_nonces.write(outside_execution.nonce, true);

            // 4. Bounds (audit M-3). Enforced BEFORE any hashing or signature
            //    work so grief attempts are cheap to reject.
            assert(outside_execution.calls.len() <= MAX_CALLS, 'M3: too many calls');
            assert(
                total_calldata_felts(outside_execution.calls) <= MAX_TOTAL_CALLDATA_FELTS,
                'M3: calldata too large',
            );
            assert(signature.len() <= MAX_SIGNATURE_FELTS, 'M3: signature too long');

            // 5. Read owner pubkey.
            let (owner_low, owner_high) = self.ed25519._get_owner();
            let owner_u256 = u256 {
                low: owner_low.try_into().unwrap(), high: owner_high.try_into().unwrap(),
            };

            // 5a. Extract signed msg bytes and verify against canonical OE encoding.
            //     Audit M-4: minimum envelope length, msg-byte range, and
            //     emptiness after Serde are all explicitly asserted.
            assert(signature.len() >= SIG_PREFIX_LEN, 'SRC9: sig too short');
            let msg_len: u32 = (*signature.at(4)).try_into().expect('SRC9: bad msg len');
            assert(signature.len() >= SIG_PREFIX_LEN + msg_len, 'M4: sig message truncated');
            let chain_id = get_tx_info().unbox().chain_id;
            let contract_address = get_contract_address();
            let raw_bytes = encode_outside_execution_bytes(
                @outside_execution, contract_address, chain_id,
            );
            let expected_bytes = bytes_to_hex_ascii(@raw_bytes);
            assert(msg_len == expected_bytes.len(), 'SRC9: msg length mismatch');
            let mut i: u32 = 0;
            while i < msg_len {
                let msg_byte: u8 = (*signature.at(SIG_PREFIX_LEN + i))
                    .try_into()
                    .expect('M4: bad msg byte');
                assert(msg_byte == *expected_bytes.at(i), 'SRC9: msg mismatch');
                i += 1;
            }

            // 5b. Garaga Ed25519 verification.
            let mut sig_span = signature;
            let sig_with_hints = Serde::<EdDSASignatureWithHint>::deserialize(ref sig_span)
                .expect('SRC9: bad sig format');
            assert(sig_span.is_empty(), 'M4: trailing sig bytes');
            assert(is_valid_eddsa_signature(sig_with_hints, owner_u256), 'SRC9: invalid signature');

            // 6. Atomic multicall (audit H-1).
            _execute_calls_atomic_span(outside_execution.calls)
        }

        fn is_valid_outside_execution_nonce(self: @ContractState, nonce: felt252) -> bool {
            !self.outside_nonces.read(nonce)
        }
    }

    /// Atomic multicall for a Span<Call>. Same semantics as
    /// `_execute_calls_atomic` — Audit H-1 panic on any subcall failure.
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
