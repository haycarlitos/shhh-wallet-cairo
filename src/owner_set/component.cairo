//! Owner-set component. Reusable storage + invariants for a multi-owner
//! Starknet account. Mutations go through `HasGovernance` so that the
//! embedding contract's timelock + threshold policy is always enforced.

#[starknet::component]
pub mod OwnerSetComponent {
    use starknet::get_block_timestamp;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use crate::owner_set::interface::{
        ERR_DUPLICATE_HASH, ERR_ROLE_INVALID, ERR_THRESHOLD_TOO_HIGH, ERR_THRESHOLD_ZERO,
        ERR_UNKNOWN_OWNER, ERR_WEIGHT_ZERO, ERR_ZERO_OWNERS, OwnerRecord, ROLE_GUARDIAN, ROLE_OWNER,
        ROLE_RECOVERY_ONLY,
    };

    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------

    #[storage]
    pub struct Storage {
        pub owners: Map<u32, OwnerRecord>,
        pub owner_by_hash: Map<felt252, u32>, // 0 = absent, otherwise owner_id + 1
        pub owners_count: u32,
        pub active_count: u32,
        pub threshold: u8,
        pub primary_owner_id: u32,
        // Append-only pubkey bytes log. Each owner's pubkey bytes live at
        // slots [pubkey_slot .. pubkey_slot + pubkey_len).
        pub pubkey_bytes: Map<u64, felt252>,
        pub pubkey_cursor: u64,
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        OwnerAdded: OwnerAdded,
        OwnerRemoved: OwnerRemoved,
        OwnerRotated: OwnerRotated,
        ThresholdChanged: ThresholdChanged,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OwnerAdded {
        #[key]
        pub owner_id: u32,
        pub kind: felt252,
        pub pubkey_hash: felt252,
        pub role: felt252,
        pub weight: u8,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OwnerRemoved {
        #[key]
        pub owner_id: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OwnerRotated {
        #[key]
        pub owner_id: u32,
        pub new_pubkey_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ThresholdChanged {
        pub old: u8,
        pub new: u8,
    }

    // ------------------------------------------------------------------
    // Internal impl — called by the governance path in the main contract.
    //
    // TODO(v8): every public mutator must be invoked only after the
    //           governance component confirms the timelocked op has
    //           reached `valid_after`.
    // ------------------------------------------------------------------

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of InternalTrait<TContractState> {
        fn initialize_primary(
            ref self: ComponentState<TContractState>,
            kind: felt252,
            pubkey_hash: felt252,
            pubkey_bytes: Span<felt252>,
            label: felt252,
        ) {
            assert(self.owners_count.read() == 0, 'OWNERS: already initialized');
            let slot = self._append_pubkey_bytes(pubkey_bytes);
            let record = OwnerRecord {
                kind,
                pubkey_hash,
                pubkey_len: pubkey_bytes.len(),
                pubkey_slot: slot,
                role: ROLE_OWNER,
                weight: 1_u8,
                added_at: get_block_timestamp(),
                label,
                revoked: false,
            };
            self.owners.write(0_u32, record);
            self.owner_by_hash.write(pubkey_hash, 1_u32);
            self.owners_count.write(1_u32);
            self.active_count.write(1_u32);
            self.threshold.write(1_u8);
            self.primary_owner_id.write(0_u32);

            self
                .emit(
                    OwnerAdded {
                        owner_id: 0_u32, kind, pubkey_hash, role: ROLE_OWNER, weight: 1_u8,
                    },
                );
        }

        fn add_owner(
            ref self: ComponentState<TContractState>,
            kind: felt252,
            pubkey_hash: felt252,
            pubkey_bytes: Span<felt252>,
            role: felt252,
            weight: u8,
            label: felt252,
        ) -> u32 {
            // role sanity
            assert(
                role == ROLE_OWNER || role == ROLE_GUARDIAN || role == ROLE_RECOVERY_ONLY,
                ERR_ROLE_INVALID,
            );
            assert(weight > 0_u8, ERR_WEIGHT_ZERO);
            // dedupe
            let existing = self.owner_by_hash.read(pubkey_hash);
            assert(existing == 0_u32, ERR_DUPLICATE_HASH);

            let slot = self._append_pubkey_bytes(pubkey_bytes);
            let next_id = self.owners_count.read();
            let record = OwnerRecord {
                kind,
                pubkey_hash,
                pubkey_len: pubkey_bytes.len(),
                pubkey_slot: slot,
                role,
                weight,
                added_at: get_block_timestamp(),
                label,
                revoked: false,
            };
            self.owners.write(next_id, record);
            self.owner_by_hash.write(pubkey_hash, next_id + 1_u32);
            self.owners_count.write(next_id + 1_u32);
            self.active_count.write(self.active_count.read() + 1_u32);

            self.emit(OwnerAdded { owner_id: next_id, kind, pubkey_hash, role, weight });
            next_id
        }

        fn remove_owner(ref self: ComponentState<TContractState>, owner_id: u32) {
            let mut record = self.owners.read(owner_id);
            assert(!record.revoked, ERR_UNKNOWN_OWNER);
            assert(owner_id < self.owners_count.read(), ERR_UNKNOWN_OWNER);

            // invariant: primary owner cannot be removed unilaterally
            // (the account's governance policy enforces stronger auth for this)
            // invariant: at least one active OWNER must remain
            let still_active = self._count_remaining_owner_role(owner_id);
            assert(still_active >= 1_u32, ERR_ZERO_OWNERS);

            record.revoked = true;
            self.owners.write(owner_id, record);
            self.owner_by_hash.write(record.pubkey_hash, 0_u32);
            self.active_count.write(self.active_count.read() - 1_u32);

            // re-check threshold ≤ total_weight
            let total = self._recompute_total_weight();
            let t: u8 = self.threshold.read();
            let t_u32: u32 = t.into();
            assert(t_u32 <= total, ERR_THRESHOLD_TOO_HIGH);

            self.emit(OwnerRemoved { owner_id });
        }

        fn rotate_owner_pubkey(
            ref self: ComponentState<TContractState>,
            owner_id: u32,
            new_pubkey_hash: felt252,
            new_pubkey_bytes: Span<felt252>,
        ) {
            let existing = self.owner_by_hash.read(new_pubkey_hash);
            assert(existing == 0_u32, ERR_DUPLICATE_HASH);
            let mut record = self.owners.read(owner_id);
            assert(!record.revoked, ERR_UNKNOWN_OWNER);

            self.owner_by_hash.write(record.pubkey_hash, 0_u32);
            let slot = self._append_pubkey_bytes(new_pubkey_bytes);
            record.pubkey_hash = new_pubkey_hash;
            record.pubkey_len = new_pubkey_bytes.len();
            record.pubkey_slot = slot;
            record.added_at = get_block_timestamp();
            self.owners.write(owner_id, record);
            self.owner_by_hash.write(new_pubkey_hash, owner_id + 1_u32);

            self.emit(OwnerRotated { owner_id, new_pubkey_hash });
        }

        fn set_threshold(ref self: ComponentState<TContractState>, new: u8) {
            assert(new > 0_u8, ERR_THRESHOLD_ZERO);
            let total = self._recompute_total_weight();
            let new_u32: u32 = new.into();
            assert(new_u32 <= total, ERR_THRESHOLD_TOO_HIGH);
            let old = self.threshold.read();
            self.threshold.write(new);
            self.emit(ThresholdChanged { old, new });
        }

        // ---------- read helpers ----------

        fn read_pubkey_bytes(
            self: @ComponentState<TContractState>, record: OwnerRecord,
        ) -> Array<felt252> {
            let mut out: Array<felt252> = array![];
            let mut i: u32 = 0;
            loop {
                if i >= record.pubkey_len {
                    break;
                }
                let slot: u64 = record.pubkey_slot + i.into();
                out.append(self.pubkey_bytes.read(slot));
                i += 1;
            }
            out
        }

        fn find_by_hash(
            self: @ComponentState<TContractState>, pubkey_hash: felt252,
        ) -> Option<u32> {
            let v = self.owner_by_hash.read(pubkey_hash);
            if v == 0_u32 {
                Option::None
            } else {
                Option::Some(v - 1_u32)
            }
        }

        // ---------- internals ----------

        fn _append_pubkey_bytes(
            ref self: ComponentState<TContractState>, bytes: Span<felt252>,
        ) -> u64 {
            let start = self.pubkey_cursor.read();
            let mut i: u32 = 0;
            loop {
                if i >= bytes.len() {
                    break;
                }
                let slot: u64 = start + i.into();
                self.pubkey_bytes.write(slot, *bytes.at(i));
                i += 1;
            }
            self.pubkey_cursor.write(start + bytes.len().into());
            start
        }

        fn _count_remaining_owner_role(
            self: @ComponentState<TContractState>, excluding: u32,
        ) -> u32 {
            let mut i: u32 = 0;
            let mut count: u32 = 0;
            let n = self.owners_count.read();
            loop {
                if i >= n {
                    break;
                }
                if i != excluding {
                    let r = self.owners.read(i);
                    if !r.revoked && r.role == ROLE_OWNER {
                        count += 1_u32;
                    }
                }
                i += 1;
            }
            count
        }

        fn _recompute_total_weight(self: @ComponentState<TContractState>) -> u32 {
            let mut i: u32 = 0;
            let mut total: u32 = 0;
            let n = self.owners_count.read();
            loop {
                if i >= n {
                    break;
                }
                let r = self.owners.read(i);
                if !r.revoked && r.role == ROLE_OWNER {
                    total += r.weight.into();
                }
                i += 1;
            }
            total
        }
    }
}
