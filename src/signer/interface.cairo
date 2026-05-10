//! Pluggable signer interface — reference implementation for the proposed
//! Starknet pluggable-signer SNIP. A `ShhhAccount` dispatches owner-signature
//! verification to a separately-declared verifier class via `library_call`.
//!
//! Kind tags are ASCII short-strings (fit in a `felt252`) so they are
//! human-readable in explorers and logs and impossible to collide with a
//! raw public key value.

// ------------------------------------------------------------------
// SRC-5 interface IDs
// ------------------------------------------------------------------

/// SRC-5 interface ID for the pluggable-signer trait.
///
/// Canonical recipe: `starknet_keccak("ISigner_V1")`.
///
///   - `ISigner` is the trait name defined in this module.
///   - `_V1` is a version tag; a breaking-trait-shape change (e.g. adding
///     a new required method) MUST bump to `ISigner_V2` + register both.
///
/// The value MUST match any off-chain code that probes via
/// `supports_interface(ISIGNER_ID)`. The TypeScript SDK exposes the
/// same hex string from `scripts/ts/snip12-hash.ts`, and two parity
/// checks wire the three sources shut so a silent edit to any one
/// fails CI:
///   - `tests/interface_ids.cairo` — Cairo ↔ canonical-literal guard
///   - `scripts/ts/check-interface-ids.mjs` — TS ↔ starknet_keccak
///     recomputation + TS ↔ Cairo constant equality
///
/// Final value (starknet.js v9 `hash.starknetKeccak("ISigner_V1")`):
pub const ISIGNER_ID: felt252 = 0x94c5a761f34b25a4e603c651ac0e1fc4fad9cdb5517f7fa1bb54044c7e5ef8;

// ------------------------------------------------------------------
// Kind tag registry — MUST match SNIP Part B
// ------------------------------------------------------------------

// Tier 1 — primitive curves
pub const KIND_STARK: felt252 = 'STARK';
pub const KIND_SECP256K1: felt252 = 'SECP256K1';
pub const KIND_ED25519: felt252 = 'ED25519';
pub const KIND_P256: felt252 = 'P256';
pub const KIND_RSA_2048: felt252 = 'RSA_2048';
pub const KIND_BLS12_381: felt252 = 'BLS12_381';

// Tier 2 — envelope variants
pub const KIND_WEBAUTHN_P256: felt252 = 'WEBAUTHN_P256';
pub const KIND_EIP191_SECP256K1: felt252 = 'EIP191_SECP256K1';
pub const KIND_EIP712_SECP256K1: felt252 = 'EIP712_SECP256K1';
pub const KIND_DKIM_RSA: felt252 = 'DKIM_RSA';
pub const KIND_JWT_RS256: felt252 = 'JWT_RS256';
pub const KIND_JWT_ES256: felt252 = 'JWT_ES256';
/// Sub-bound variant of JWT_ES256 — verifier additionally checks the
/// `sub` claim against a stored identity hash, so a single IdP signing
/// key can authenticate distinct end users on different accounts.
pub const KIND_JWT_ES256_APPLE_SUB: felt252 = 'JWT_ES256_APPLE_SUB';

// Tier 3 — reserved, verifier circuits in future SNIP amendments
pub const KIND_MULTISIG_K_OF_N: felt252 = 'MULTISIG_K_OF_N';
pub const KIND_GUARDIAN: felt252 = 'GUARDIAN';
pub const KIND_ZK_JWT: felt252 = 'ZK_JWT';
pub const KIND_ZK_EMAIL: felt252 = 'ZK_EMAIL';
pub const KIND_ZK_TLS: felt252 = 'ZK_TLS';
pub const KIND_ZK_TOTP: felt252 = 'ZK_TOTP';

// ------------------------------------------------------------------
// Canonical signer trait
// ------------------------------------------------------------------

/// Implemented by a separately-declared verifier class.
///
/// The ShhhAccount stores a mapping `kind_tag -> ClassHash` and dispatches
/// to the matching verifier via `library_call_syscall`. Because it is a
/// library call, the verifier runs in the account's execution context and
/// MUST NOT touch storage. The verifier is a pure computation.
#[starknet::interface]
pub trait ISigner<TContractState> {
    /// Verifies that `signature` authorizes `message_hash` under the
    /// provided owner public-key bytes.
    ///
    /// MUST be pure. MUST NOT write storage.
    /// MUST return `true` only when the signature is cryptographically valid
    /// and its envelope has been fully consumed (audit M-4).
    fn verify(
        self: @TContractState,
        message_hash: felt252,
        pubkey: Span<felt252>,
        signature: Span<felt252>,
    ) -> bool;

    /// Returns the canonical kind tag this verifier implements.
    fn kind(self: @TContractState) -> felt252;

    /// Audit M-1 (full, V8.2) — returns true iff `pubkey` is a
    /// structurally valid public key for this verifier's kind.
    ///
    /// Called by `ShhhAccount::execute_add_owner`,
    /// `execute_rotate_owner`, and `bootstrap_from_sessions` BEFORE
    /// any owner-set mutation, so a malformed pubkey can never land
    /// in storage and poison subsequent multisig flows.
    ///
    /// Contract:
    ///   - MUST be pure (no storage writes).
    ///   - MUST validate per-kind length (the V8.1 `_assert_pubkey_shape`
    ///     stopgap is removed; verifiers own this now).
    ///   - SHOULD validate curve membership / subgroup where the
    ///     primitive supports a non-panicking check
    ///     (`secp256_ec_new_syscall` for secp/p256 families; shape-only
    ///     for STARK / Ed25519 / EIP-191 / EIP-712).
    ///   - MAY panic on malformed BLS pubkeys: Garaga's
    ///     `assert_in_subgroup_excluding_infinity` panics by design,
    ///     and the registration tx reverting is the same outcome as
    ///     returning false. Document this behavior in the verifier's
    ///     module-level comment.
    fn validate_pubkey(self: @TContractState, pubkey: Span<felt252>) -> bool;
}

// ------------------------------------------------------------------
// Signature envelope helpers
// ------------------------------------------------------------------

/// Owner envelope layout at the account level:
///
///     [owner_id, kind_tag, payload_0, payload_1, ..., payload_n]
///
/// `owner_id` selects which registered owner signed. `kind_tag` disambiguates
/// the curve at the account level (the account verifies it matches
/// `owners[owner_id].kind`). The rest is kind-specific and passed to the
/// verifier class.
///
/// Threshold layout wraps one or more envelopes:
///
///     [n_envelopes, envelope_1_len, envelope_1..., envelope_2_len, envelope_2...]
pub const OWNER_ENVELOPE_MIN_LEN: u32 = 3;

/// Helper — parses the owner_id and kind tag from an owner envelope without
/// touching the payload. Returns `None` if the envelope is too short.
pub fn parse_owner_envelope_header(envelope: Span<felt252>) -> Option<(u32, felt252)> {
    if envelope.len() < OWNER_ENVELOPE_MIN_LEN {
        return Option::None;
    }
    let owner_id_felt = *envelope.at(0);
    let owner_id: u32 = match owner_id_felt.try_into() {
        Option::Some(v) => v,
        Option::None => { return Option::None; },
    };
    let kind_tag: felt252 = *envelope.at(1);
    Option::Some((owner_id, kind_tag))
}

// ------------------------------------------------------------------
// Pubkey commitment helper
// ------------------------------------------------------------------

/// Canonical pubkey commitment for address-salt derivation.
/// `poseidon_hash_span([kind_tag, pubkey_0, pubkey_1, ..., pubkey_n])`.
///
/// Implementations MUST use this to derive the salt used in
/// `compute_address(class_hash, salt, calldata)` so that the same raw key
/// material encoded under two different kinds yields two distinct addresses
/// (audit E-1 equivalent, address-salt binding).
pub fn owner_commitment(kind_tag: felt252, pubkey: Span<felt252>) -> felt252 {
    let mut data: Array<felt252> = array![kind_tag];
    let mut i: u32 = 0;
    loop {
        if i >= pubkey.len() {
            break;
        }
        data.append(*pubkey.at(i));
        i += 1;
    }
    core::poseidon::poseidon_hash_span(data.span())
}
