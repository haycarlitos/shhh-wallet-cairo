//! Test-only target that re-enters its caller via
//! `execute_from_outside_v2` during its `ping()` call. Used by
//! `tests/account_reentrancy.cairo` to prove the reentrancy guard
//! fires when a malicious subcall target tries to stack a second OE
//! on top of a still-executing first one.

use shhh_wallet::outside_execution::OutsideExecution;

#[starknet::interface]
pub trait IReentrantTarget<TContractState> {
    fn set_victim(ref self: TContractState, account: starknet::ContractAddress);
    fn set_payload(ref self: TContractState, oe: OutsideExecution, envelope: Array<felt252>);
    fn ping(ref self: TContractState);
}

#[starknet::contract]
pub mod ReentrantTarget {
    use shhh_wallet::outside_execution::{
        ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution,
    };
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };

    #[storage]
    struct Storage {
        victim: ContractAddress,
        // Serialized OE + envelope — reconstructed inside ping().
        oe_caller: ContractAddress,
        oe_nonce: felt252,
        oe_execute_after: u64,
        oe_execute_before: u64,
        // Envelope felts as a Map<u32, felt252>, len-prefixed.
        envelope_len: u32,
        envelope: Map<u32, felt252>,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl IReentrantTargetImpl of super::IReentrantTarget<ContractState> {
        fn set_victim(ref self: ContractState, account: ContractAddress) {
            self.victim.write(account);
        }

        fn set_payload(ref self: ContractState, oe: OutsideExecution, envelope: Array<felt252>) {
            self.oe_caller.write(oe.caller);
            self.oe_nonce.write(oe.nonce);
            self.oe_execute_after.write(oe.execute_after);
            self.oe_execute_before.write(oe.execute_before);
            // Calls are always empty in the reentrancy test — we call
            // `ping` on ourselves via the outer OE, never through this
            // serialized inner OE.
            self.envelope_len.write(envelope.len());
            let mut i: u32 = 0;
            while i < envelope.len() {
                self.envelope.write(i, *envelope.at(i));
                i += 1;
            }
        }

        fn ping(ref self: ContractState) {
            // Reconstruct the stored OE + envelope and replay via
            // execute_from_outside_v2 on the victim. With the
            // reentrancy guard in place this MUST panic with
            // 'SHHH: reentrant'. Without the guard the nonce replay
            // check catches it ('SRC9: duplicate nonce') — but that
            // check already runs on the OUTER call, so reaching this
            // path means the outer OE already cleared dedup but
            // left the guard unset.
            let oe = OutsideExecution {
                caller: self.oe_caller.read(),
                nonce: self.oe_nonce.read(),
                execute_after: self.oe_execute_after.read(),
                execute_before: self.oe_execute_before.read(),
                calls: array![].span(),
            };
            let mut env: Array<felt252> = array![];
            let len = self.envelope_len.read();
            let mut i: u32 = 0;
            while i < len {
                env.append(self.envelope.read(i));
                i += 1;
            }
            let victim = self.victim.read();
            let src9 = ISRC9_V2Dispatcher { contract_address: victim };
            src9.execute_from_outside_v2(oe, env.span());
        }
    }
}
