//! Governance component — owns the `pending_ops` map and exposes
//! helpers for propose / execute / cancel. The main contract wires
//! these into its external ABI and each op's policy (threshold vs
//! unanimous vs guardian-threshold) is enforced at the call site.

#[starknet::component]
pub mod GovernanceComponent {
    use starknet::get_block_timestamp;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use crate::governance::pending_ops::{
        ERR_OP_CANCELLED, ERR_OP_EXECUTED, ERR_OP_EXPIRED, ERR_OP_NOT_READY, ERR_OP_PAYLOAD,
        ERR_OP_UNKNOWN, PendingOp,
    };

    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------

    #[storage]
    pub struct Storage {
        pub pending: Map<felt252, PendingOp>, // op_id -> op
        pub pending_count: u64 // monotonic for op_id generation
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

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
        pub op_kind: felt252,
        pub proposer: u32,
        pub valid_after: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OpExecuted {
        #[key]
        pub op_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OpCancelled {
        #[key]
        pub op_id: felt252,
    }

    // ------------------------------------------------------------------
    // Internal API
    // ------------------------------------------------------------------

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of InternalTrait<TContractState> {
        /// Proposes a new timelocked op. Caller (the account) is responsible
        /// for enforcing the correct threshold BEFORE calling this.
        fn propose(
            ref self: ComponentState<TContractState>,
            op_id: felt252,
            op_kind: felt252,
            proposer: u32,
            payload: felt252,
            timelock_seconds: u64,
            expiry_seconds: u64,
        ) {
            let existing = self.pending.read(op_id);
            assert(existing.proposed_at == 0_u64, 'OP: op_id in use');

            let now = get_block_timestamp();
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
            self.emit(OpProposed { op_id, op_kind, proposer, valid_after: op.valid_after });
        }

        /// Validates an op is ready for execution and returns the stored
        /// record. Does NOT mark it executed — the caller does that after
        /// the op's side effect succeeds.
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
            self.emit(OpExecuted { op_id });
        }

        /// Owner-threshold cancellation. The main contract authenticates the
        /// caller as a valid owner-quorum signature BEFORE calling this.
        fn cancel(ref self: ComponentState<TContractState>, op_id: felt252) {
            let mut op = self.pending.read(op_id);
            assert(op.proposed_at != 0_u64, ERR_OP_UNKNOWN);
            assert(!op.executed, ERR_OP_EXECUTED);
            op.cancelled = true;
            self.pending.write(op_id, op);
            self.emit(OpCancelled { op_id });
        }
    }
}
