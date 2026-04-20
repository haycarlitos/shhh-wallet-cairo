//! I-1 (Informational): custom Poseidon calls-hash must be replaced by
//! SNIP-12 typed data on the primary path. Keeping it as a guard rail.

#[test]
fn primary_hashing_path_is_snip12_only() {
    // TODO(v8): inspect the compiled ABI — no function exposes the
    // V7 custom `_compute_custom_calls_hash` symbol.
    assert(true, 'TODO(v8)');
}

#[test]
fn snip12_hash_is_call_count_sensitive() {
    // TODO(v8): adding a call to the multicall MUST change the hash,
    // proving there's no length-prefix ambiguity in the primary encoding.
    assert(true, 'TODO(v8)');
}
