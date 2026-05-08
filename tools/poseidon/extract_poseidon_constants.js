#!/usr/bin/env node
// extract_poseidon_constants.js
//
// Reads circomlibjs's poseidon_constants.js (UNOPTIMIZED version) and emits
// a drop-in replacement for src/libxrpl/zkp/rollup/PoseidonConstants.cpp.
//
// We want the UNOPTIMIZED constants (poseidon_constants.js, NOT _opt.js)
// because our Phase 2a gadget uses the textbook permutation, not the
// Hadeshash partial-round optimization. The optimized constants are
// mathematically equivalent across the WHOLE permutation but produce
// different intermediate state values, which would break our gadget-vs-
// off-circuit equality check.
//
// circomlibjs ships params indexed by t-1:
//   C[0], M[0]  → t=2  (1-input hash, e.g., for SMT)
//   C[1], M[1]  → t=2  (??? in some versions; depends on exporter)
//   C[2], M[2]  → t=3  (2-input hash, our case)
//   C[3], M[3]  → t=4
//   ...
//
// We default to t=3 (which is index 2 in iden3's t=2..17 export). If your
// version's index layout differs, override via --t-index=N on the cli.
//
// Usage:
//   cd ~/Sainath
//   node extract_poseidon_constants.js > rippled_zkp/src/libxrpl/zkp/rollup/PoseidonConstants.cpp
//
//   # If the t=3 entry is at a different index in your version:
//   node extract_poseidon_constants.js --t-index=1 > ...
//
//   # If you accidentally want the OPT version (don't, unless you know why):
//   node extract_poseidon_constants.js --opt > ...

import fs from 'fs';
import path from 'path';

// ------- Argument parsing (very basic) -------
const args = process.argv.slice(2);
let useOpt = false;
let tIndex = null;            // null => auto-detect by row length
let inputFile = null;

for (const a of args) {
    if (a === '--opt')              useOpt = true;
    else if (a.startsWith('--t-index=')) tIndex = parseInt(a.split('=')[1], 10);
    else if (a.startsWith('--file='))    inputFile = a.split('=')[1];
}

if (!inputFile) {
    inputFile = useOpt
        ? path.resolve(process.env.HOME || '.', 'Sainath/circomlibjs/src/poseidon_constants_opt.js')
        : path.resolve(process.env.HOME || '.', 'Sainath/circomlibjs/src/poseidon_constants.js');
}

if (!fs.existsSync(inputFile)) {
    console.error(`ERROR: cannot find ${inputFile}`);
    console.error(`       Override with --file=/path/to/poseidon_constants.js`);
    process.exit(2);
}

// ------- Load the JS module via dynamic import -------
// circomlibjs ships ESM. Convert path to file:// URL for import().
const fileUrl = new URL('file://' + inputFile).href;
const mod = await import(fileUrl);
const data = mod.default || mod;

if (!data.C || !data.M) {
    console.error('ERROR: loaded module has no .C or .M arrays.');
    console.error('       Keys present:', Object.keys(data));
    process.exit(3);
}

const C = data.C;
const M = data.M;

// ------- Auto-detect t=3 row -------
// Round-constant rows for t=3 with R_F=8, R_P=57 have length (8+57)*3 = 195.
// MDS rows for t=3 are length 9 (3x3 matrix flattened).
// We pick the row whose lengths match exactly. If multiple match, the user
// must pass --t-index=N.
const T = 3;
const EXPECTED_RC = (8 + 57) * T;   // 195
const EXPECTED_MDS = T * T;          // 9

let chosenIndex = tIndex;
if (chosenIndex === null) {
    const candidates = [];
    for (let i = 0; i < C.length; ++i) {
        if (Array.isArray(C[i]) && C[i].length === EXPECTED_RC
            && Array.isArray(M[i]) && M[i].length === T
            && Array.isArray(M[i][0]) && M[i][0].length === T)
        {
            candidates.push(i);
        }
    }
    if (candidates.length === 0) {
        console.error('ERROR: no row matched the expected t=3 dimensions.');
        console.error(`       Wanted C[i].length=${EXPECTED_RC}, M[i] = 3×3.`);
        console.error('       Row lengths in C:', C.map(r => Array.isArray(r) ? r.length : '<not-array>'));
        process.exit(4);
    }
    if (candidates.length > 1) {
        console.error(`ERROR: ${candidates.length} rows matched. Specify --t-index=N.`);
        console.error('       Candidates:', candidates);
        process.exit(5);
    }
    chosenIndex = candidates[0];
}

const arc = C[chosenIndex];
const mdsRows = M[chosenIndex];

// Flatten the 3x3 MDS into a 9-element row-major array of strings.
const mds = [];
for (let i = 0; i < T; ++i)
    for (let j = 0; j < T; ++j)
        mds.push(mdsRows[i][j]);

// ------- Convert hex (or decimal) strings → decimal strings -------
// Our C++ parser uses libff::bigint(const char*) which assumes BASE 10.
// circomlibjs entries are typically "0x..."; convert via BigInt for safety.
function toDecimalString(s) {
    if (typeof s !== 'string')
        s = String(s);
    s = s.trim();
    // BigInt accepts "0x..." and decimal directly.
    const big = BigInt(s);
    return big.toString(10);
}

const arcDec = arc.map(toDecimalString);
const mdsDec = mds.map(toDecimalString);

if (arcDec.length !== EXPECTED_RC) {
    console.error(`ERROR: ARC length ${arcDec.length} ≠ expected ${EXPECTED_RC}`);
    process.exit(6);
}
if (mdsDec.length !== EXPECTED_MDS) {
    console.error(`ERROR: MDS length ${mdsDec.length} ≠ expected ${EXPECTED_MDS}`);
    process.exit(7);
}

// ------- Emit the .cpp file -------
const lines = [];
lines.push('// Copyright 2026 Sainath, Trinity College Dublin');
lines.push('// SPDX-License-Identifier: ISC');
lines.push('//');
lines.push('// Auto-generated from iden3/circomlibjs/src/poseidon_constants.js by');
lines.push('// extract_poseidon_constants.js. DO NOT EDIT BY HAND. To regenerate:');
lines.push('//');
lines.push('//   cd ~/Sainath');
lines.push('//   node extract_poseidon_constants.js > \\');
lines.push('//     rippled_zkp/src/libxrpl/zkp/rollup/PoseidonConstants.cpp');
lines.push('//');
lines.push(`// Source row index: ${chosenIndex}  (auto-detected to match t=3)`);
lines.push(`// Parameters: t=${T}, R_F=8, R_P=57, x^5 S-box, BN-254 (Fr).`);
lines.push(`// ARC entries: ${arcDec.length}, MDS entries: ${mdsDec.length}`);
lines.push('');
lines.push('#include "PoseidonConstants.h"');
lines.push('');
lines.push('namespace ripple {');
lines.push('namespace zkp {');
lines.push('namespace rollup {');
lines.push('namespace poseidon_params {');
lines.push('');

// ARC
lines.push('std::array<std::string_view, kArcCount> const kArcDecimal = {{');
for (let i = 0; i < arcDec.length; ++i) {
    const sep = i + 1 === arcDec.length ? '' : ',';
    lines.push(`    "${arcDec[i]}"${sep}`);
}
lines.push('}};');
lines.push('');

// MDS
lines.push('std::array<std::string_view, kT * kT> const kMdsDecimal = {{');
for (let i = 0; i < mdsDec.length; ++i) {
    const sep = i + 1 === mdsDec.length ? '' : ',';
    lines.push(`    "${mdsDec[i]}"${sep}`);
}
lines.push('}};');
lines.push('');

lines.push('}  // namespace poseidon_params');
lines.push('}  // namespace rollup');
lines.push('}  // namespace zkp');
lines.push('}  // namespace ripple');

process.stdout.write(lines.join('\n') + '\n');