//! Recovery component — guardians can initiate a timelocked recovery.
//! Until the window elapses, any single owner can cancel. After the
//! window, anyone can finalize and the new owner is added.
//!
//! This is explicitly *additive*: `finalize_recovery` does not remove
//! existing owners. The user is expected to follow up with explicit
//! `remove_owner` calls for the devices they actually lost.

#[starknet::component]
pub mod RecoveryComponent {
    use starknet::get_block_timestamp;
    use starknet::storage::{StorageMapReadAccess, StorageMapWriteAccess};

    // ------------------------------------------------------------------
    // Pending recovery record
    // ------------------------------------------------------------------

    #[derive(Drop, Copy, Serde, starknet::Store)]
    pub struct PendingRecovery {
        pub initiated_at: u64,
        pub valid_after: u64,
        pub new_owner_hash: felt252, // poseidon commitment of new owner record
        pub is_active: bool,
    }

    pub const ERR_NO_PENDING: felt252 = 'RECOVERY: no pending op';
    pub const ERR_PENDING_EXISTS: felt252 = 'RECOVERY: already pending';
    pub const ERR_TIMELOCK_NOT_MET: felt252 = 'RECOVERY: timelock not met';

    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------

    #[storage]
    pub struct Storage {
        pub pending: PendingRecovery,
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        RecoveryInitiated: RecoveryInitiated,
        RecoveryCancelled: RecoveryCancelled,
        RecoveryFinalized: RecoveryFinalized,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RecoveryInitiated {
        pub new_owner_hash: felt252,
        pub valid_after: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RecoveryCancelled {}

    #[derive(Drop, starknet::Event)]
    pub struct RecoveryFinalized {
        pub new_owner_hash: felt252,
    }

    // ------------------------------------------------------------------
    // Internal API
    // ------------------------------------------------------------------

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of InternalTrait<TContractState> {
        /// Called after guardian-threshold authentication.
        fn initiate(
            ref self: ComponentState<TContractState>,
            new_owner_hash: felt252,
            timelock_seconds: u64,
        ) {
            let existing = self.pending.read();
            assert(!existing.is_active, ERR_PENDING_EXISTS);
            let now = get_block_timestamp();
            let rec = PendingRecovery {
                initiated_at: now,
                valid_after: now + timelock_seconds,
                new_owner_hash,
                is_active: true,
            };
            self.pending.write(rec);
            self.emit(RecoveryInitiated { new_owner_hash, valid_after: rec.valid_after });
        }

        /// Called after single-owner authentication during the window.
        fn cancel(ref self: ComponentState<TContractState>) {
            let existing = self.pending.read();
            assert(existing.is_active, ERR_NO_PENDING);
            let cleared = PendingRecovery {
                initiated_at: 0_u64, valid_after: 0_u64, new_owner_hash: 0, is_active: false,
            };
            self.pending.write(cleared);
            self.emit(RecoveryCancelled {});
        }

        /// Permissionless after timelock. Returns the new_owner_hash so the
        /// main contract can add the owner.
        fn finalize(ref self: ComponentState<TContractState>) -> felt252 {
            let existing = self.pending.read();
            assert(existing.is_active, ERR_NO_PENDING);
            assert(get_block_timestamp() >= existing.valid_after, ERR_TIMELOCK_NOT_MET);
            let new_owner_hash = existing.new_owner_hash;
            let cleared = PendingRecovery {
                initiated_at: 0_u64, valid_after: 0_u64, new_owner_hash: 0, is_active: false,
            };
            self.pending.write(cleared);
            self.emit(RecoveryFinalized { new_owner_hash });
            new_owner_hash
        }

        fn read_pending(self: @ComponentState<TContractState>) -> PendingRecovery {
            self.pending.read()
        }
    }
}
