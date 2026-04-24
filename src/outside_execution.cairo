use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;
use starknet::account::Call;

#[derive(Drop, Copy, Serde)]
pub struct OutsideExecution {
    pub caller: ContractAddress,
    pub nonce: felt252,
    pub execute_after: u64,
    pub execute_before: u64,
    pub calls: Span<Call>,
}

#[starknet::interface]
pub trait ISRC9_V2<TContractState> {
    fn execute_from_outside_v2(
        ref self: TContractState, outside_execution: OutsideExecution, signature: Span<felt252>,
    ) -> Array<Span<felt252>>;

    fn is_valid_outside_execution_nonce(self: @TContractState, nonce: felt252) -> bool;
}

// SNIP-9 v2 SRC5 interface ID.
//
// Audit H-2: the V7 value (`0x1d1144bb2138571a605b8b8eed8e4e9e04dc40fce40190a11af584935e0a04c`)
// did not match the canonical OZ / SNIP-9 V2 identifier. V8 registers the
// published value. Any dapp that probes SRC-5 for SNIP-9 V2 support now
// gets the correct answer.
pub const ISRC9_V2_ID: felt252 = 0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872;

// ================================================================
// SNIP-12 typed-data hashing for OutsideExecution (audit H-2 closeout).
// ================================================================
//
// Primary hashing path for `execute_from_outside_v2` signatures. Matches the
// "felt-timestamp" variant used by `chipi-pay/sessions-smart-contract`
// (starknet-io/SNIPs#163) — our `OutsideExecution` already stores u64
// timestamps which convert losslessly to felt.
//
// The OZ SRC9 u128-timestamp variant stays as a follow-up (non-blocking for
// V8 since our struct doesn't use u128). When OZ ships u128 OutsideExecution
// as default, we'll add a second `compute_snip12_hash_u128` alongside.
//
// Hash derivation (RFC 2119 MUST):
//   domain_hash = poseidon([
//     STARKNET_DOMAIN_TYPE_HASH_REV1,
//     'Account.execute_from_outside',  // name
//     2,                                // version
//     chain_id,
//     1                                 // revision
//   ])
//
//   for each call:
//     calldata_hash = poseidon_hash_span(calldata)
//     call_hash = poseidon([CALL_TYPE_HASH_REV1, to, selector, calldata_hash])
//
//   calls_array_hash = poseidon_hash_span([call_hash_0, call_hash_1, ...])
//
//   struct_hash = poseidon([
//     OUTSIDE_EXECUTION_TYPE_HASH_REV1,
//     caller, nonce,
//     execute_after, execute_before,
//     calls_array_hash,
//   ])
//
//   message_hash = poseidon([
//     STARKNET_MESSAGE_PREFIX,
//     domain_hash,
//     contract_address,
//     struct_hash,
//   ])

/// starknetKeccak("OutsideExecution"("Caller":"ContractAddress","Nonce":"felt","Execute
/// After":"felt","Execute Before":"felt","Calls":"Call*")"Call"(...))
pub const OUTSIDE_EXECUTION_TYPE_HASH_REV1: felt252 =
    0x5a4b49e17039355cd95d1f0981d75901191d1319b1f4b05a9a791d218d7e0c;

/// starknetKeccak("Call"("To":"ContractAddress","Selector":"selector","Calldata":"felt*"))
pub const CALL_TYPE_HASH_REV1: felt252 =
    0x3635c7f2a7ba93844c0d064e18e487f35ab90f7c39d00f186a781fc3f0c2ca9;

/// starknetKeccak("StarknetDomain"("name":"shortstring","version":"shortstring","chainId":"shortstring","revision":"shortstring"))
pub const STARKNET_DOMAIN_TYPE_HASH_REV1: felt252 =
    0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210;

/// SNIP-12 message prefix.
pub const STARKNET_MESSAGE_PREFIX: felt252 = 'StarkNet Message';

/// SNIP-12 domain name used by `execute_from_outside_v2` messages.
/// Matches the sessions-contract convention.
pub const OE_DOMAIN_NAME: felt252 = 'Account.execute_from_outside';
pub const OE_DOMAIN_VERSION: felt252 = 2;
pub const OE_DOMAIN_REVISION: felt252 = 1;

/// Signature envelope version tags. The first felt of the signature
/// selects the hashing path so paymasters can route correctly during
/// the V1 → V2 deprecation window.
pub const SIG_VERSION_V1_HEX_ASCII: felt252 = 'V1_HEX_ASCII';
pub const SIG_VERSION_V2_SNIP12: felt252 = 'V2_SNIP12';
/// Threshold-signature envelope. Wraps N inner single-owner envelopes
/// over the same SNIP-12 hash, each shaped `[owner_id, kind, payload...]`
/// (no inner version tag). The account verifies each, rejects duplicate
/// owner_ids, and requires `sum(weight_i) >= owner_set.threshold`.
pub const SIG_VERSION_V2_THRESHOLD: felt252 = 'V2_THRESHOLD';

/// Hash one `Call` per the SNIP-12 `Call` type.
fn hash_call(call: @Call) -> felt252 {
    let mut cd = *call.calldata;
    let mut calldata_items: Array<felt252> = array![];
    loop {
        match cd.pop_front() {
            Option::Some(item) => calldata_items.append(*item),
            Option::None => { break; },
        }
    }
    let calldata_hash = poseidon_hash_span(calldata_items.span());
    poseidon_hash_span(
        array![CALL_TYPE_HASH_REV1, (*call.to).into(), *call.selector, calldata_hash].span(),
    )
}

/// Hash the SNIP-12 `StarknetDomain` struct for this account.
fn hash_starknet_domain(chain_id: felt252) -> felt252 {
    poseidon_hash_span(
        array![
            STARKNET_DOMAIN_TYPE_HASH_REV1, OE_DOMAIN_NAME, OE_DOMAIN_VERSION, chain_id,
            OE_DOMAIN_REVISION,
        ]
            .span(),
    )
}

/// Hash an array of `Call` structs into a single calls-array hash.
fn hash_calls_span(calls: Span<Call>) -> felt252 {
    let mut calls_copy = calls;
    let mut hashes: Array<felt252> = array![];
    loop {
        match calls_copy.pop_front() {
            Option::Some(call) => { hashes.append(hash_call(call)); },
            Option::None => { break; },
        }
    }
    poseidon_hash_span(hashes.span())
}

/// Hash the `OutsideExecution` struct itself.
fn hash_outside_execution_struct(oe: @OutsideExecution) -> felt252 {
    let calls_array_hash = hash_calls_span(*oe.calls);
    poseidon_hash_span(
        array![
            OUTSIDE_EXECUTION_TYPE_HASH_REV1, (*oe.caller).into(), *oe.nonce,
            (*oe.execute_after).into(), (*oe.execute_before).into(), calls_array_hash,
        ]
            .span(),
    )
}

/// Compute the SNIP-12 message hash for an `OutsideExecution` payload.
/// This is the felt252 that signers MUST sign over when using the
/// V2 hashing path (`SIG_VERSION_V2_SNIP12`).
///
/// MUST match the TypeScript reference at `scripts/ts/snip12-hash.ts`.
pub fn compute_snip12_hash(
    oe: @OutsideExecution, contract_address: ContractAddress, chain_id: felt252,
) -> felt252 {
    let domain_hash = hash_starknet_domain(chain_id);
    let struct_hash = hash_outside_execution_struct(oe);
    poseidon_hash_span(
        array![STARKNET_MESSAGE_PREFIX, domain_hash, contract_address.into(), struct_hash].span(),
    )
}
