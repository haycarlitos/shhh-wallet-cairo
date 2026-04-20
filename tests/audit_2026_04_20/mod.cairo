//! Regression suite for the 2026-04-20 Codex/Cairo audit (Omar Espejel).
//! One file per finding; every stub panics with 'TODO(v8)' until the
//! corresponding guard in `src/account.cairo` is filled in and a real
//! assertion is added.
//!
//! Gate: CI must run `snforge test --filter audit_2026_04_20` as its
//! final green-light step before mainnet declare.

pub mod c1_execute_caller_check;
pub mod h1_atomic_multicall;
pub mod h2_snip9_interface_id;
pub mod m1_any_caller_sentinel;
pub mod m2_validity_window_cap;
pub mod m3_bounds_calls_calldata_sig;
pub mod m4_signature_envelope_bounds;
pub mod l1_pubkey_range_check;
pub mod i1_custom_hash_removed;
pub mod i2_ed25519_negative_vectors;
pub mod i3_no_upgradeable_component;
pub mod toolchain_snforge_pinned;
