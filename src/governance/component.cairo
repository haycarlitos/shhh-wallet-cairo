//! Governance component — pending-op storage + propose/execute/cancel
//! state machine. The main contract wires these into its external ABI
//! and each op's auth policy (single-owner via OE in Phase 5;
//! threshold/unanimous in Phase 5.5 and beyond) is enforced at the call
//! site before `propose` is invoked.
//!
//! Events are indexer-first: every state change carries the full op
//! record so a downstream indexer never needs to read storage.

#[starknet::component]
pub mod GovernanceComponent {
    use core::poseidon::poseidon_hash_span;
    use starknet::get_block_timestamp;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use crate::governance::pending_ops::{
        ERR_OP_CANCELLED, ERR_OP_EXECUTED, ERR_OP_EXPIRED, ERR_OP_NOT_READY, ERR_OP_PAYLOAD,
        ERR_OP_UNKNOWN, PendingOp,
    };

    #[storage]
    pub struct Storage {
        /// op_id → PendingOp. op_id values are generated inside `propose`.
        pub pending: Map<felt252, PendingOp>,
        /// Monotonic counter folded into op_id derivation to guarantee
        /// uniqueness even when two identical proposals land in the
        /// same block.
        pub pending_count: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        OpProposed: OpProposed,
        OpExecuted: OpExecuted,
        OpCancelled: OpCancelled,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OpProposed {
        #[key]
        pub op_id: felt252,
        #[key]
        pub op_kind: felt252,
        pub proposer: u32,
        pub payload: felt252,
        pub valid_after: u64,
        pub expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OpExecuted {
        #[key]
        pub op_id: felt252,
        #[key]
        pub op_kind: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OpCancelled {
        #[key]
        pub op_id: felt252,
        #[key]
        pub op_kind: felt252,
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of InternalTrait<TContractState> {
        /// Proposes a new timelocked op. Returns the derived op_id. The
        /// caller (main contract) authenticates the proposer BEFORE
        /// invoking this — typically via `caller == self` during an OE
        /// multicall.
        fn propose(
            ref self: ComponentState<TContractState>,
            op_kind: felt252,
            proposer: u32,
            payload: felt252,
            timelock_seconds: u64,
            expiry_seconds: u64,
        ) -> felt252 {
            let now = get_block_timestamp();
            let counter = self.pending_count.read();
            self.pending_count.write(counter + 1_u64);

            let op_id = poseidon_hash_span(
                array![op_kind, payload, proposer.into(), now.into(), counter.into()].span(),
            );

            let op = PendingOp {
                op_kind,
                proposer,
                proposed_at: now,
                valid_after: now + timelock_seconds,
                expires_at: now + timelock_seconds + expiry_seconds,
                payload,
                executed: false,
                cancelled: false,
            };
            self.pending.write(op_id, op);

            self
                .emit(
                    OpProposed {
                        op_id,
                        op_kind,
                        proposer,
                        payload,
                        valid_after: op.valid_after,
                        expires_at: op.expires_at,
                    },
                );
            op_id
        }

        /// Asserts the op is ready to execute and the caller-provided
        /// payload commitment matches what was stored at propose time.
        /// Does NOT write state — `mark_executed` does that after the
        /// op's side effect lands.
        fn assert_ready(
            self: @ComponentState<TContractState>, op_id: felt252, expected_payload: felt252,
        ) -> PendingOp {
            let op = self.pending.read(op_id);
            assert(op.proposed_at != 0_u64, ERR_OP_UNKNOWN);
            assert(!op.executed, ERR_OP_EXECUTED);
            assert(!op.cancelled, ERR_OP_CANCELLED);
            let now = get_block_timestamp();
            assert(now >= op.valid_after, ERR_OP_NOT_READY);
            assert(now <= op.expires_at, ERR_OP_EXPIRED);
            assert(op.payload == expected_payload, ERR_OP_PAYLOAD);
            op
        }

        fn mark_executed(ref self: ComponentState<TContractState>, op_id: felt252) {
            let mut op = self.pending.read(op_id);
            op.executed = true;
            self.pending.write(op_id, op);
            self.emit(OpExecuted { op_id, op_kind: op.op_kind });
        }

        /// Cancellation. Caller (main contract) authenticates the canceller
        /// as a valid owner BEFORE invoking — during the window, any
        /// single owner's OE can cancel.
        fn cancel(ref self: ComponentState<TContractState>, op_id: felt252) {
            let mut op = self.pending.read(op_id);
            assert(op.proposed_at != 0_u64, ERR_OP_UNKNOWN);
            assert(!op.executed, ERR_OP_EXECUTED);
            op.cancelled = true;
            self.pending.write(op_id, op);
            self.emit(OpCancelled { op_id, op_kind: op.op_kind });
        }

        /// Read-only — useful for the account's ABI / indexer reconciliation.
        fn get_op(self: @ComponentState<TContractState>, op_id: felt252) -> PendingOp {
            self.pending.read(op_id)
        }

        fn get_pending_count(self: @ComponentState<TContractState>) -> u64 {
            self.pending_count.read()
        }
    }
}
