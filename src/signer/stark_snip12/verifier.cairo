//! STARK SNIP-12 typed-data verifier — Starknet browser wallets
//! (Bramble, Braavos, Ready/Argent, OpenZeppelin accounts) via
//! `wallet_signTypedData`.
//!
//! Why a second STARK verifier (in addition to raw `StarkVerifier`):
//! a Starknet browser wallet never signs a raw hash. Its only signing
//! method, `wallet_signTypedData`, signs the SNIP-12 message hash, and
//! SNIP-12 always folds the SIGNING wallet's own account address into
//! that hash. So the signature is over a hash the ShhhAccount never
//! computes, and `StarkVerifier` (which checks the OE hash directly)
//! rejects it. This is the Starknet twin of `EIP712Secp256k1Verifier`:
//! the OE hash is wrapped in the wallet's native typed data and the
//! STARK ECDSA is checked over the wrapper.
//!
//! Recipe (SNIP-12 revision 1, starknet.js `typedData.getMessageHash`):
//!
//!     domain_hash = poseidon(
//!         STARKNET_DOMAIN_TYPE_HASH_REV1, 'Shhh', 1, chain_id, 1)
//!     struct_hash = poseidon(APPROVAL_TYPE_HASH, wallet, message_hash)
//!     final_hash  = poseidon(
//!         'StarkNet Message', domain_hash, signer_account, struct_hash)
//!     sig         = stark_ecdsa_sign(final_hash, priv_key)
//!
//! Typed data the wallet shows:
//!
//!     StarknetDomain { name: 'Shhh', version: '1', chainId, revision: '1' }
//!     Approval { Wallet: ContractAddress, Hash: felt }
//!
//! `Wallet` is the ShhhAccount the approval is for. The verifier reads it
//! from `get_contract_address()` (it runs inside the account through
//! `library_call_syscall`), so a signature only works on that wallet.
//! `chain_id` comes from the tx, so it only works on that chain. `Hash`
//! is the SNIP-12 OE hash the account passed to `verify()`.
//!
//! Pubkey layout:
//!   [ stark_pubkey, signer_account_address ]   // 2 felts
//! The account address is what the wallet folds into the hash. The
//! signer is bound to the KEY: if the user rotates the key inside their
//! wallet, they register the new one. The verifier never calls the
//! signer's account, so it stays pure and works for accounts that are
//! not deployed yet (counterfactual Bramble/Ready accounts).
//!
//! Envelope layout:
//!   [ r, s ]   // 2 felts
//! Off-chain callers normalize wallet-specific shapes first (Argent and
//! Ready return [1, 0, pubkey, r, s]).

#[starknet::contract]
pub mod StarkSnip12Verifier {
    use core::ecdsa::check_ecdsa_signature;
    use core::poseidon::poseidon_hash_span;
    use starknet::{get_contract_address, get_tx_info};
    use crate::outside_execution::{STARKNET_DOMAIN_TYPE_HASH_REV1, STARKNET_MESSAGE_PREFIX};
    use crate::signer::interface::{ISigner, KIND_STARK_SNIP12};

    // ------------------------------------------------------------------
    // Pinned SNIP-12 values. Computed off-chain with starknet.js
    // (`scripts/ts/gen-stark-snip12-fixture.mjs`). Any edit to the domain
    // or struct shape MUST update these — silent drift would produce
    // hashes that no wallet signs.
    // ------------------------------------------------------------------

    /// `typedData.getTypeHash(types, 'Approval', revision 1)` of
    /// `"Approval"("Wallet":"ContractAddress","Hash":"felt")`.
    pub const APPROVAL_TYPE_HASH: felt252 =
        0x19ab981aa7f552862f5b614248684a1e633f8749ad277aab3c8871a65db9b3b;

    /// Domain `name` (shortstring).
    pub const DOMAIN_NAME: felt252 = 'Shhh';

    /// Domain `version` '1' and `revision` '1' (starknet.js encodes the
    /// numeric shortstrings as the felt 1).
    pub const DOMAIN_VERSION: felt252 = 1;
    pub const DOMAIN_REVISION: felt252 = 1;

    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl ISignerImpl of ISigner<ContractState> {
        fn verify(
            self: @ContractState,
            message_hash: felt252,
            pubkey: Span<felt252>,
            signature: Span<felt252>,
        ) -> bool {
            if pubkey.len() != 2_u32 {
                return false;
            }
            if signature.len() != 2_u32 {
                return false;
            }
            let stark_pubkey = *pubkey.at(0);
            let signer_account = *pubkey.at(1);

            let chain_id = get_tx_info().unbox().chain_id;
            let wallet: felt252 = get_contract_address().into();
            let final_hash = approval_hash(chain_id, wallet, signer_account, message_hash);

            check_ecdsa_signature(final_hash, stark_pubkey, *signature.at(0), *signature.at(1))
        }

        fn kind(self: @ContractState) -> felt252 {
            KIND_STARK_SNIP12
        }

        /// `[stark_pubkey, signer_account]`, both non-zero. The account is
        /// NOT required to be deployed (no syscall): new Bramble and Ready
        /// accounts are counterfactual until their first transaction.
        fn validate_pubkey(self: @ContractState, pubkey: Span<felt252>) -> bool {
            if pubkey.len() != 2_u32 {
                return false;
            }
            let stark_pubkey: felt252 = *pubkey.at(0);
            let signer_account: felt252 = *pubkey.at(1);
            stark_pubkey != 0 && signer_account != 0
        }
    }

    /// SNIP-12 rev 1 message hash of `Approval { Wallet, Hash }` as signed
    /// by `signer_account`. Public so tests and tooling can recompute it.
    pub fn approval_hash(
        chain_id: felt252, wallet: felt252, signer_account: felt252, message_hash: felt252,
    ) -> felt252 {
        let domain_hash = poseidon_hash_span(
            array![
                STARKNET_DOMAIN_TYPE_HASH_REV1, DOMAIN_NAME, DOMAIN_VERSION, chain_id,
                DOMAIN_REVISION,
            ]
                .span(),
        );
        let struct_hash = poseidon_hash_span(
            array![APPROVAL_TYPE_HASH, wallet, message_hash].span(),
        );
        poseidon_hash_span(
            array![STARKNET_MESSAGE_PREFIX, domain_hash, signer_account, struct_hash].span(),
        )
    }
}
