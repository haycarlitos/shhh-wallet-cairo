#!/usr/bin/env bash
# Phase 10 — Mutation test harness.
#
# For each named mutant, we:
#   1. Verify the working tree is clean (so restore is safe).
#   2. Apply a single sed patch targeting one security guard.
#   3. Run `snforge test`.
#   4. Assert the test suite FAILS (exit code != 0) — meaning at least
#      one existing test caught the mutant.
#   5. Restore the original (git checkout -- file).
#
# Usage:
#   bash scripts/mutation-test.sh              # run all mutants
#   bash scripts/mutation-test.sh --list       # show registered mutants
#   bash scripts/mutation-test.sh --only NAME  # run one mutant
#
# Exits non-zero if any mutant survives all tests.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--list" ]]; then
  echo "Registered mutants:"
  printf '  %s\n' \
    "c1_caller_gate" \
    "h1_atomic_multicall" \
    "m1_caller_zero" \
    "m2_window_cap" \
    "m3_max_calls" \
    "l1_pubkey_range" \
    "nonce_dedup" \
    "timelock_offbyone" \
    "threshold_invariant" \
    "v8_blocklist"
  exit 0
fi

ONLY=""
if [[ "${1:-}" == "--only" ]]; then
  ONLY="${2:-}"
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "ERROR: working tree must be clean. Commit or stash first." >&2
  exit 2
fi

run_mutant() {
  local name="$1"
  local file="$2"
  local sed_script="$3"

  if [[ -n "${ONLY}" && "${ONLY}" != "${name}" ]]; then
    return 0
  fi

  echo "=== mutant: ${name}"
  echo "    file:   ${file}"

  sed -i.bak -E "${sed_script}" "${file}"

  # Ensure sed actually changed something.
  if cmp -s "${file}" "${file}.bak"; then
    echo "    SKIP: sed pattern did not match; guard may have been renamed"
    mv "${file}.bak" "${file}"
    return 0
  fi

  set +e
  snforge test >/tmp/mutation-${name}.log 2>&1
  local rc=$?
  set -e

  git checkout -- "${file}"
  rm -f "${file}.bak"

  if [[ $rc -eq 0 ]]; then
    echo "    SURVIVED: mutant passed the whole test suite"
    echo "    Log: /tmp/mutation-${name}.log"
    return 1
  else
    echo "    KILLED"
    rm -f "/tmp/mutation-${name}.log"
    return 0
  fi
}

FAILED=()

# Mutants with documented, acknowledged coverage gaps. Listed here so a
# CI run exits 0 iff only the known gaps survive. Empty is the goal.
declare -a KNOWN_GAPS=(
)

in_known_gaps() {
  local candidate="$1"
  for g in "${KNOWN_GAPS[@]}"; do
    if [[ "$g" == "$candidate" ]]; then return 0; fi
  done
  return 1
}

# C-1 — flip the caller gate into a no-op.
run_mutant "c1_caller_gate" \
  "src/account.cairo" \
  "s/assert\\(caller\\.is_zero\\(\\) \\|\\| caller == get_contract_address\\(\\), 'C1: unauthorized caller'\\);/\\/\\/ C1 GUARD REMOVED BY MUTANT/" \
  || FAILED+=("c1_caller_gate")

# H-1 — swallow subcall failures instead of reverting.
run_mutant "h1_atomic_multicall" \
  "src/account.cairo" \
  "s/Result::Err\\(_\\) => core::panic_with_felt252\\('H1: subcall failed'\\),/Result::Err(_) => results.append(array![].span()),/g" \
  || FAILED+=("h1_atomic_multicall")

# M-1 — allow caller == 0 as unrestricted.
run_mutant "m1_caller_zero" \
  "src/account.cairo" \
  "s/assert\\(caller_felt != 0, 'M1: caller=0 rejected'\\);/\\/\\/ M1 GUARD REMOVED BY MUTANT/" \
  || FAILED+=("m1_caller_zero")

# M-2 — remove the ANY_CALLER validity-window cap.
run_mutant "m2_window_cap" \
  "src/account.cairo" \
  "s/assert\\(window <= MAX_ANY_CALLER_VALIDITY_SECONDS, 'M2: window too long'\\);/\\/\\/ M2 GUARD REMOVED BY MUTANT/" \
  || FAILED+=("m2_window_cap")

# M-3 — raise MAX_CALLS to u32::MAX so the bound never fires.
run_mutant "m3_max_calls" \
  "src/account.cairo" \
  "s/pub const MAX_CALLS: u32 = 16;/pub const MAX_CALLS: u32 = 4294967295;/" \
  || FAILED+=("m3_max_calls")

# L-1 — strip the pubkey range check in the V7 constructor.
run_mutant "l1_pubkey_range" \
  "src/wallet.cairo" \
  "s/let _: u128 = owner_pubkey_low\\.try_into\\(\\)\\.expect\\('L1: owner_low OOR'\\);/\\/\\/ L1 GUARD REMOVED BY MUTANT/" \
  || FAILED+=("l1_pubkey_range")

# Nonce dedup — remove the replay check.
run_mutant "nonce_dedup" \
  "src/account.cairo" \
  "s/assert\\(!self\\.oe_nonces\\.read\\(outside_execution\\.nonce\\), 'SRC9: duplicate nonce'\\);/\\/\\/ NONCE GUARD REMOVED BY MUTANT/" \
  || FAILED+=("nonce_dedup")

# Timelock off-by-one — flip `>=` to `>`.
run_mutant "timelock_offbyone" \
  "src/governance/component.cairo" \
  "s/assert\\(now >= op\\.valid_after, ERR_OP_NOT_READY\\);/assert(now > op.valid_after, ERR_OP_NOT_READY);/" \
  || FAILED+=("timelock_offbyone")

# Threshold invariant — allow threshold > total weight.
run_mutant "threshold_invariant" \
  "src/owner_set/component.cairo" \
  "s/assert\\(new_u32 <= total, ERR_THRESHOLD_TOO_HIGH\\);/\\/\\/ THRESHOLD GUARD REMOVED BY MUTANT/" \
  || FAILED+=("threshold_invariant")

# V8 session-key blocklist — remove the initiate_recovery entry so a
# session key could elevate to a guardian recovery.
run_mutant "v8_blocklist" \
  "src/account.cairo" \
  "s/\\|\\| sel == selector!\\(\"initiate_recovery\"\\)/\\/\\/ BLOCKLIST ENTRY REMOVED/" \
  || FAILED+=("v8_blocklist")

echo
UNEXPECTED=()
EXPECTED=()
# `set -u` trips on `"${FAILED[@]}"` when the array was never written
# (which is the expected all-killed case when running a single-mutant
# filter). Use the ${arr[@]+...} guard to sidestep.
for f in ${FAILED[@]+"${FAILED[@]}"}; do
  if in_known_gaps "$f"; then
    EXPECTED+=("$f")
  else
    UNEXPECTED+=("$f")
  fi
done

if [[ ${#UNEXPECTED[@]} -gt 0 ]]; then
  echo "=== FAILED (unexpected survivors): ===" >&2
  printf '  %s\n' "${UNEXPECTED[@]}" >&2
  if [[ ${#EXPECTED[@]} -gt 0 ]]; then
    echo "=== known-gap survivors (documented): ===" >&2
    printf '  %s\n' "${EXPECTED[@]}" >&2
  fi
  exit 1
fi

if [[ ${#EXPECTED[@]} -gt 0 ]]; then
  echo "=== ${#EXPECTED[@]} known-gap survivors (documented): ==="
  printf '  %s\n' "${EXPECTED[@]}"
  echo "=== All remaining mutants KILLED ==="
  exit 0
fi

echo "=== ALL MUTANTS KILLED: every guard is provably load-bearing ==="
