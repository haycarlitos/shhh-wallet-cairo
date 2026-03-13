#[starknet::contract(account)]
pub mod ShhhWallet {
    use starknet::account::Call;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use starknet::{
        ContractAddress, get_block_timestamp, get_caller_address, get_contract_address,
        get_tx_info, syscalls,
    };
    use core::poseidon::poseidon_hash_span;
    use openzeppelin::upgrades::UpgradeableComponent;
    use openzeppelin::introspection::src5::SRC5Component;
    use crate::ed25519::component::{Ed25519WalletComponent, HasOwner};
    use crate::ed25519::interface::IShhhWallet;
    use crate::outside_execution::{OutsideExecution, ISRC9_V2, ISRC9_V2_ID};
    use garaga::signatures::eddsa_25519::{EdDSASignatureWithHint, is_valid_eddsa_signature};

    component!(path: Ed25519WalletComponent, storage: ed25519, event: Ed25519Event);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;

    impl Ed25519InternalImpl = Ed25519WalletComponent::InternalImpl<ContractState>;
    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;
    impl SRC5InternalImpl = SRC5Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        ed25519: Ed25519WalletComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
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
        UpgradeableEvent: UpgradeableComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
    }

    impl HasOwnerImpl of HasOwner<ContractState> {
        fn get_owner_keys(self: @ContractState) -> (felt252, felt252) {
            self.ed25519._get_owner()
        }
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner_pubkey_low: felt252,
        owner_pubkey_high: felt252,
    ) {
        self.ed25519.initializer(owner_pubkey_low, owner_pubkey_high);
        self.src5.register_interface(ISRC9_V2_ID);
    }

    #[abi(embed_v0)]
    impl ShhhWalletImpl of IShhhWallet<ContractState> {
        fn get_owner(self: @ContractState) -> (felt252, felt252) {
            self.ed25519._get_owner()
        }
    }

    // Standard Starknet account entrypoints — needed for paymaster fee estimation.
    // __validate__ always reverts to prevent unauthorized direct invokes.
    // __execute__ provides a standard multicall for estimation (SkipValidate is used).
    // Actual sponsored execution goes through execute_from_outside_v2.
    #[external(v0)]
    fn __validate__(self: @ContractState, calls: Array<Call>) -> felt252 {
        core::panic_with_felt252('NOT_SUPPORTED')
    }

    #[external(v0)]
    fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
        let mut results: Array<Span<felt252>> = array![];
        for call in calls {
            match syscalls::call_contract_syscall(call.to, call.selector, call.calldata) {
                Result::Ok(ret) => results.append(ret),
                Result::Err(_) => results.append(array![].span()),
            }
        };
        results
    }

    /// Hash the calls array using Poseidon for the canonical OE message.
    /// Format: [to, selector, cd_len, calldata..., ...per call..., num_calls]
    fn hash_calls_for_oe(calls: Span<Call>) -> felt252 {
        let mut data: Array<felt252> = array![];
        let num_calls: felt252 = calls.len().into();
        let mut calls_copy = calls;
        loop {
            match calls_copy.pop_front() {
                Option::Some(call) => {
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
        };
        data.append(num_calls);
        poseidon_hash_span(data.span())
    }

    /// Convert raw bytes to lowercase hex ASCII bytes.
    /// Each input byte becomes two ASCII hex chars (e.g. 0x5f -> '5','f').
    /// Used because Phantom signs hex-encoded messages to bypass tx detection.
    fn bytes_to_hex_ascii(bytes: @Array<u8>) -> Array<u8> {
        let hex_chars: [u8; 16] = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, // '0'-'7'
            0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, // '8'-'9','a'-'f'
        ];
        let hex_span = hex_chars.span();
        let mut result: Array<u8> = array![];
        let mut i: u32 = 0;
        while i < bytes.len() {
            let b: u16 = (*bytes.at(i)).into();
            result.append(*hex_span.at((b / 16).try_into().unwrap()));
            result.append(*hex_span.at((b % 16).try_into().unwrap()));
            i += 1;
        };
        result
    }

    /// Append felt252 as 32 big-endian bytes
    fn append_felt252_be(ref bytes: Array<u8>, value: felt252) {
        let v: u256 = value.into();
        append_u128_be(ref bytes, v.high);
        append_u128_be(ref bytes, v.low);
    }

    /// Append u128 as 16 big-endian bytes
    fn append_u128_be(ref bytes: Array<u8>, value: u128) {
        let mut temp: Array<u8> = array![];
        let mut remaining = value;
        let mut i: u32 = 0;
        while i < 16 {
            let byte: u8 = (remaining % 256).try_into().unwrap();
            temp.append(byte);
            remaining = remaining / 256;
            i += 1;
        };
        let mut j: u32 = 16;
        while j > 0 {
            j -= 1;
            bytes.append(*temp.at(j));
        };
    }

    /// Append u64 as 8 big-endian bytes
    fn append_u64_be(ref bytes: Array<u8>, value: u64) {
        let mut temp: Array<u8> = array![];
        let mut remaining = value;
        let mut i: u32 = 0;
        while i < 8 {
            let byte: u8 = (remaining % 256).try_into().unwrap();
            temp.append(byte);
            remaining = remaining / 256;
            i += 1;
        };
        let mut j: u32 = 8;
        while j > 0 {
            j -= 1;
            bytes.append(*temp.at(j));
        };
    }

    /// Encode OutsideExecution as canonical bytes for Ed25519 signature verification.
    ///
    /// Format (186 bytes total):
    ///   "SHHH_OE_V1"     (10 bytes, ASCII domain separator)
    ///   chain_id          (32 bytes, big-endian felt252)
    ///   contract_address  (32 bytes, big-endian felt252)
    ///   caller            (32 bytes, big-endian felt252)
    ///   nonce             (32 bytes, big-endian felt252)
    ///   execute_after     (8 bytes, big-endian u64)
    ///   execute_before    (8 bytes, big-endian u64)
    ///   calls_hash        (32 bytes, Poseidon hash of calls, big-endian)
    fn encode_outside_execution_bytes(
        outside_execution: @OutsideExecution,
        contract_address: ContractAddress,
        chain_id: felt252,
    ) -> Array<u8> {
        let mut bytes: Array<u8> = array![];

        // Domain separator: "SHHH_OE_V1" (10 bytes ASCII)
        bytes.append(0x53); // S
        bytes.append(0x48); // H
        bytes.append(0x48); // H
        bytes.append(0x48); // H
        bytes.append(0x5f); // _
        bytes.append(0x4f); // O
        bytes.append(0x45); // E
        bytes.append(0x5f); // _
        bytes.append(0x56); // V
        bytes.append(0x31); // 1

        // chain_id (32 bytes BE)
        append_felt252_be(ref bytes, chain_id);

        // contract_address (32 bytes BE)
        append_felt252_be(ref bytes, contract_address.into());

        // caller (32 bytes BE)
        let caller_felt: felt252 = (*outside_execution.caller).into();
        append_felt252_be(ref bytes, caller_felt);

        // nonce (32 bytes BE)
        append_felt252_be(ref bytes, *outside_execution.nonce);

        // execute_after (8 bytes BE)
        append_u64_be(ref bytes, *outside_execution.execute_after);

        // execute_before (8 bytes BE)
        append_u64_be(ref bytes, *outside_execution.execute_before);

        // calls_hash (32 bytes BE)
        let calls_hash = hash_calls_for_oe(*outside_execution.calls);
        append_felt252_be(ref bytes, calls_hash);

        bytes
    }

    #[abi(embed_v0)]
    impl SRC9V2Impl of ISRC9_V2<ContractState> {
        fn execute_from_outside_v2(
            ref self: ContractState,
            outside_execution: OutsideExecution,
            signature: Span<felt252>,
        ) -> Array<Span<felt252>> {
            // 1. Validate caller (ANY_CALLER = address 0 or shortstring 'ANY_CALLER')
            let caller_felt: felt252 = outside_execution.caller.into();
            if caller_felt != 0 && caller_felt != 'ANY_CALLER' {
                assert(
                    get_caller_address() == outside_execution.caller, 'SRC9: invalid caller',
                );
            }

            // 2. Validate time bounds
            let now = get_block_timestamp();
            assert(outside_execution.execute_after < now, 'SRC9: too early');
            assert(now < outside_execution.execute_before, 'SRC9: too late');

            // 3. Validate + mark nonce as used
            assert(
                !self.outside_nonces.read(outside_execution.nonce), 'SRC9: duplicate nonce',
            );
            self.outside_nonces.write(outside_execution.nonce, true);

            // 4. Read owner pubkey from storage (garaga v1.0+ takes Py as separate param)
            let (owner_low, owner_high) = self.ed25519._get_owner();
            let owner_u256 = u256 {
                low: owner_low.try_into().unwrap(),
                high: owner_high.try_into().unwrap(),
            };

            // 5. Extract message bytes from raw span and verify against expected OE encoding.
            // EdDSASignatureWithHint Serde layout (garaga v1.0+):
            //   [0-1] Ry_twisted (u256: low, high)
            //   [2-3] s          (u256: low, high)
            //   [4]   msg_len
            //   [5..5+msg_len] msg bytes (one felt252 per byte)
            //   [...] msm_hint, sqrt hints
            assert(signature.len() >= 5, 'SRC9: sig too short');
            let msg_len: u32 = (*signature.at(4)).try_into().expect('SRC9: bad msg len');
            let chain_id = get_tx_info().unbox().chain_id;
            let contract_address = get_contract_address();
            let raw_bytes = encode_outside_execution_bytes(
                @outside_execution, contract_address, chain_id,
            );
            // Phantom signs hex-encoded bytes (ASCII) to bypass transaction detection.
            // The Ed25519 msg field contains hex chars, so we hex-encode expected bytes.
            let expected_bytes = bytes_to_hex_ascii(@raw_bytes);
            assert(msg_len == expected_bytes.len(), 'SRC9: msg length mismatch');
            let mut i: u32 = 0;
            while i < msg_len {
                let msg_byte: u8 = (*signature.at(5 + i)).try_into().expect('SRC9: bad msg byte');
                assert(msg_byte == *expected_bytes.at(i), 'SRC9: msg mismatch');
                i += 1;
            };

            // 6. Full Ed25519 signature verification via Garaga (v1.0+: Py is separate param)
            let mut sig_span = signature;
            let sig_with_hints = Serde::<EdDSASignatureWithHint>::deserialize(ref sig_span)
                .expect('SRC9: bad sig format');
            assert(is_valid_eddsa_signature(sig_with_hints, owner_u256), 'SRC9: invalid signature');

            // 7. Execute calls (non-atomic — failed subcalls return empty spans)
            let mut calls = outside_execution.calls;
            let mut results: Array<Span<felt252>> = array![];
            loop {
                match calls.pop_front() {
                    Option::Some(call) => {
                        match syscalls::call_contract_syscall(
                            *call.to, *call.selector, *call.calldata,
                        ) {
                            Result::Ok(ret) => results.append(ret),
                            Result::Err(_) => results.append(array![].span()),
                        }
                    },
                    Option::None => { break; },
                }
            };
            results
        }

        fn is_valid_outside_execution_nonce(
            self: @ContractState, nonce: felt252,
        ) -> bool {
            !self.outside_nonces.read(nonce)
        }
    }
}
