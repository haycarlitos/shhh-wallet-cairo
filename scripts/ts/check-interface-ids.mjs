#!/usr/bin/env node
/**
 * Cross-language parity check for the V8 SRC-5 interface IDs.
 *
 * Asserts that:
 *   - `starknet_keccak("ISigner_V1")` matches the hardcoded
 *     `ISIGNER_ID` in `scripts/ts/snip12-hash.ts`
 *   - the same value matches the Cairo `ISIGNER_ID` constant in
 *     `src/signer/interface.cairo`
 *   - the SRC-9 V2 canonical ID hardcoded in the TS SDK matches the
 *     one the Cairo `src/outside_execution.cairo` module advertises.
 *
 * Run from the repo root:
 *   node scripts/ts/check-interface-ids.mjs
 *
 * Exits 0 on parity. Nonzero + prints the two values on drift, so a
 * CI smoke (`npm run check:interface-ids`) can catch any future edit
 * to one side that doesn't update the other.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hash } from 'starknet';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../..');

function loadExportedConstant(filePath, name) {
  const src = readFileSync(resolve(repoRoot, filePath), 'utf8');
  // Spans across lines — BigInt('...') call may be on its own line.
  const pattern = new RegExp(
    `export\\s+const\\s+${name}\\s*=\\s*BigInt\\(\\s*['\"]0x([0-9a-fA-F]+)['\"]`,
    's',
  );
  const match = src.match(pattern);
  if (!match) throw new Error(`Could not find exported BigInt \`${name}\` in ${filePath}`);
  return BigInt('0x' + match[1]);
}

function loadCairoConstant(filePath, name) {
  const src = readFileSync(resolve(repoRoot, filePath), 'utf8');
  // Matches e.g.:  pub const ISIGNER_ID: felt252 =\n    0x94c5...;
  const pattern = new RegExp(
    `pub\\s+const\\s+${name}\\s*:\\s*felt252\\s*=\\s*\\n?\\s*0x([0-9a-fA-F]+)\\s*;`,
  );
  const match = src.match(pattern);
  if (!match) throw new Error(`Could not find \`${name}\` in ${filePath}`);
  return BigInt('0x' + match[1]);
}

const SOURCES = {
  cairoISignerId: ['src/signer/interface.cairo', 'ISIGNER_ID'],
  cairoSrc9Id: ['src/outside_execution.cairo', 'ISRC9_V2_ID'],
  tsISignerId: ['scripts/ts/snip12-hash.ts', 'ISIGNER_ID'],
  tsSrc9Id: ['scripts/ts/snip12-hash.ts', 'ISRC9_V2_ID'],
};

const cairoISignerId = loadCairoConstant(...SOURCES.cairoISignerId);
const cairoSrc9Id = loadCairoConstant(...SOURCES.cairoSrc9Id);
const tsISignerId = loadExportedConstant(...SOURCES.tsISignerId);
const tsSrc9Id = loadExportedConstant(...SOURCES.tsSrc9Id);

const canonicalISignerId = BigInt(hash.starknetKeccak('ISigner_V1'));

const checks = [
  {
    name: 'TS ISIGNER_ID == starknet_keccak("ISigner_V1")',
    a: tsISignerId,
    b: canonicalISignerId,
  },
  {
    name: 'Cairo ISIGNER_ID == TS ISIGNER_ID',
    a: cairoISignerId,
    b: tsISignerId,
  },
  {
    name: 'Cairo ISIGNER_ID != 0 (placeholder)',
    a: cairoISignerId !== 0n ? 1n : 0n,
    b: 1n,
  },
  {
    name: 'TS ISRC9_V2_ID == Cairo ISRC9_V2_ID',
    a: tsSrc9Id,
    b: cairoSrc9Id,
  },
  {
    name: 'ISIGNER_ID != ISRC9_V2_ID (distinct interfaces)',
    a: cairoISignerId !== cairoSrc9Id ? 1n : 0n,
    b: 1n,
  },
];

let failed = 0;
for (const c of checks) {
  const ok = c.a === c.b;
  if (ok) {
    console.log(`✔ ${c.name}`);
  } else {
    failed += 1;
    console.error(`✘ ${c.name}`);
    console.error(`    got      = 0x${c.a.toString(16)}`);
    console.error(`    expected = 0x${c.b.toString(16)}`);
  }
}

if (failed > 0) {
  console.error(`\n${failed} parity check(s) failed — update all three sources together.`);
  process.exit(1);
}

console.log('\nInterface-ID parity verified.');
console.log(`  ISIGNER_ID  = 0x${canonicalISignerId.toString(16)}`);
console.log(`  ISRC9_V2_ID = 0x${tsSrc9Id.toString(16)}`);
