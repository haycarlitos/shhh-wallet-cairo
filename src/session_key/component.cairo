/// Reusable session key component.
///
/// Provides session key storage, validation, and management that any
/// Starknet account contract can embed.  The embedding contract must
/// implement `HasAccountOwner` so the component can enforce owner-only
/// access on mutating session management functions.

#[starknet::component]
pub mod SessionKeyComponent {
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use starknet::account::Call;
    use starknet::get_block_timestamp;
    use starknet::get_contract_address;
    use core::poseidon::poseidon_hash_span;
    use core::array::ArrayTrait;
    use core::array::SpanTrait;
    use core::traits::Into;
    use starknet::get_tx_info;
    use crate::session_key::interface::SessionData;

    // ----------------------------------------------------------------
    // Storage
    // ----------------------------------------------------------------

    #[storage]
    pub struct Storage {
        pub session_keys: Map<felt252, SessionData>,
        pub session_entrypoints: Map<(felt252, u32), felt252>,
    }

    // ----------------------------------------------------------------
    // Events
    // ----------------------------------------------------------------

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        SessionKeyAdded: SessionKeyAdded,
        SessionKeyRevoked: SessionKeyRevoked,
    }

    #[derive(Drop, starknet::Event)]
    pub struct SessionKeyAdded {
        #[key]
        pub session_key: felt252,
        pub valid_until: u64,
        pub max_calls: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct SessionKeyRevoked {
        #[key]
        pub session_key: felt252,
    }

    // ----------------------------------------------------------------
    // Trait bound: embedding contract must provide an owner check
    // ----------------------------------------------------------------

    pub trait HasAccountOwner<TContractState> {
        fn assert_only_self(self: @TContractState);
    }

    // ----------------------------------------------------------------
    // Internal implementation — called by the embedding contract
    // ----------------------------------------------------------------

    #[generate_trait]
    pub impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +HasAccountOwner<TContractState>,
        +Drop<TContractState>,
    > of InternalTrait<TContractState> {

        // ---------- session management (owner-gated) ----------

        /// Adds a new session key or updates an existing one.
        /// Clears stale entrypoints before writing new ones (audit 1 fix #10).
        /// Resets calls_used to 0 on update.
        fn add_or_update_session_key(
            ref self: ComponentState<TContractState>,
            session_key: felt252,
            valid_until: u64,
            max_calls: u32,
            allowed_entrypoints: Array<felt252>,
        ) {
            let contract_state = self.get_contract();
            HasAccountOwner::assert_only_self(contract_state);

            // SECURITY: Clear stale entrypoints first (audit fix #10)
            let old_session = self.session_keys.read(session_key);
            let mut i: u32 = 0;
            loop {
                if i >= old_session.allowed_entrypoints_len {
                    break;
                }
                self.session_entrypoints.write((session_key, i), 0);
                i += 1;
            };

            let sess = SessionData {
                valid_until,
                max_calls,
                calls_used: 0,
                allowed_entrypoints_len: allowed_entrypoints.len(),
            };
            self.session_keys.write(session_key, sess);

            // Store new allowed entrypoints
            let mut i: u32 = 0;
            loop {
                if i >= allowed_entrypoints.len() {
                    break;
                }
                self.session_entrypoints.write((session_key, i), *allowed_entrypoints.at(i));
                i += 1;
            };

            self.emit(SessionKeyAdded { session_key, valid_until, max_calls });
        }

        /// Revokes a session key. Clears all stored entrypoints and zeroes SessionData.
        fn revoke_session_key(
            ref self: ComponentState<TContractState>,
            session_key: felt252,
        ) {
            let contract_state = self.get_contract();
            HasAccountOwner::assert_only_self(contract_state);

            let current_session = self.session_keys.read(session_key);
            let entrypoints_to_clear = current_session.allowed_entrypoints_len;

            let mut i: u32 = 0;
            loop {
                if i >= entrypoints_to_clear {
                    break;
                }
                self.session_entrypoints.write((session_key, i), 0);
                i += 1;
            };

            let sess = SessionData {
                valid_until: 0,
                max_calls: 0,
                calls_used: 0,
                allowed_entrypoints_len: 0,
            };
            self.session_keys.write(session_key, sess);

            self.emit(SessionKeyRevoked { session_key });
        }

        fn get_session_data(
            self: @ComponentState<TContractState>,
            session_key: felt252,
        ) -> SessionData {
            self.session_keys.read(session_key)
        }

        // ---------- entrypoint helpers ----------

        fn get_session_allowed_entrypoints_len(
            self: @ComponentState<TContractState>,
            session_key: felt252,
        ) -> u32 {
            let s = self.session_keys.read(session_key);
            s.allowed_entrypoints_len
        }

        fn get_session_allowed_entrypoint_at(
            self: @ComponentState<TContractState>,
            session_key: felt252,
            index: u32,
        ) -> felt252 {
            self.session_entrypoints.read((session_key, index))
        }

        // ---------- validation helpers ----------

        /// Pure session validation check (no mutations).
        ///
        /// SECURITY: Enforces two layers of protection against privilege escalation:
        ///
        /// Layer 1 -- Admin selector blocklist (defense-in-depth):
        ///   Blocks 9 specific selectors that grant privileged access regardless of
        ///   whitelist configuration.
        ///
        /// Layer 2 -- Self-call block for empty whitelist (primary protection):
        ///   When allowed_entrypoints_len == 0 (open whitelist), sessions CANNOT target
        ///   the account contract itself.
        fn is_session_allowed_for_calls(
            self: @ComponentState<TContractState>,
            session_key: felt252,
            calls: Span<Call>,
        ) -> bool {
            let session = self.session_keys.read(session_key);
            if session.valid_until == 0 { return false; }
            if get_block_timestamp() > session.valid_until { return false; }
            if session.calls_used >= session.max_calls { return false; }

            // SECURITY Layer 1: Admin selector blocklist
            let UPGRADE_SELECTOR: felt252 = selector!("upgrade");
            let ADD_SESSION_SELECTOR: felt252 = selector!("add_or_update_session_key");
            let REVOKE_SESSION_SELECTOR: felt252 = selector!("revoke_session_key");
            let EXECUTE_SELECTOR: felt252 = selector!("__execute__");
            let SET_PUBLIC_KEY_SELECTOR: felt252 = selector!("set_public_key");
            let SET_PUBLIC_KEY_CAMEL_SELECTOR: felt252 = selector!("setPublicKey");
            let EXECUTE_FROM_OUTSIDE_V2_SELECTOR: felt252 = selector!("execute_from_outside_v2");
            let SET_SPENDING_POLICY_SELECTOR: felt252 = selector!("set_spending_policy");
            let REMOVE_SPENDING_POLICY_SELECTOR: felt252 = selector!("remove_spending_policy");

            let mut i: u32 = 0;
            loop {
                if i >= calls.len() { break; }
                let call = calls.at(i);
                let sel = *call.selector;

                if sel == UPGRADE_SELECTOR
                    || sel == ADD_SESSION_SELECTOR
                    || sel == REVOKE_SESSION_SELECTOR
                    || sel == EXECUTE_SELECTOR
                    || sel == SET_PUBLIC_KEY_SELECTOR
                    || sel == SET_PUBLIC_KEY_CAMEL_SELECTOR
                    || sel == EXECUTE_FROM_OUTSIDE_V2_SELECTOR
                    || sel == SET_SPENDING_POLICY_SELECTOR
                    || sel == REMOVE_SPENDING_POLICY_SELECTOR {
                    return false;
                }
                i += 1;
            };

            // SECURITY Layer 2: Self-call block for empty whitelist
            if session.allowed_entrypoints_len == 0 {
                let account_address = get_contract_address();
                let mut i: u32 = 0;
                loop {
                    if i >= calls.len() { break; }
                    let call = calls.at(i);
                    if *call.to == account_address {
                        return false;
                    }
                    i += 1;
                };
                return true;
            }

            // Second pass: verify all selectors are in the explicit whitelist
            let mut i: u32 = 0;
            loop {
                if i >= calls.len() { break; }
                let call = calls.at(i);
                let selector = *call.selector;

                let mut j: u32 = 0;
                let mut found = false;
                loop {
                    if j >= session.allowed_entrypoints_len { break; }
                    let allowed = self.session_entrypoints.read((session_key, j));
                    if allowed == selector { found = true; break; }
                    j += 1;
                };
                if !found { return false; }
                i += 1;
            };
            true
        }

        /// Consume one session call (increment counter).
        fn consume_session_call(
            ref self: ComponentState<TContractState>,
            session_key: felt252,
        ) {
            let mut session = self.session_keys.read(session_key);
            session.calls_used += 1;
            self.session_keys.write(session_key, session);
        }

        /// Compute Poseidon message hash for session signature verification.
        ///
        /// Binds: account address, chain_id, nonce, valid_until, and all call data.
        fn session_message_hash(
            self: @ComponentState<TContractState>,
            calls: Span<Call>,
            valid_until: u64,
        ) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let mut hash_data = array![];

            hash_data.append(get_contract_address().into());
            hash_data.append(tx_info.chain_id.into());
            hash_data.append(tx_info.nonce.into());
            hash_data.append(valid_until.into());

            let mut i: u32 = 0;
            loop {
                if i >= calls.len() {
                    break;
                }
                let call = calls.at(i);

                hash_data.append((*call.to).into());
                hash_data.append((*call.selector).into());
                hash_data.append(call.calldata.len().into());

                let mut j: u32 = 0;
                loop {
                    if j >= call.calldata.len() {
                        break;
                    }
                    hash_data.append((*call.calldata.at(j)).into());
                    j += 1;
                };

                i += 1;
            };

            poseidon_hash_span(hash_data.span())
        }
    }
}
