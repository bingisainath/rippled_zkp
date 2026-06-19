// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// Poseidon parameters for BN-128 (alt_bn128 scalar field), t=3, x^5 S-box.
// Source: iden3 circomlibjs / circomlib (de-facto reference for Circom & Tornado Cash).
// Generation: Sage script `generate_parameters_grain.sage` from
//   https://extgit.iaik.tugraz.at/krypto/hadeshash
// Reference: Grassi et al., "Poseidon: A New Hash Function for Zero-Knowledge
//   Proof Systems", USENIX Security 2021. eprint 2019/458.
//
// Layout for t=3:
//   - 65 round constants total (one per round) — but each round adds t=3 ARC
//     constants, so the table holds (R_F + R_P) * t = 65 * 3 = 195 constants.
//   - Wait: standard Poseidon adds t constants per FULL round and t constants
//     per partial round (only the first state element is non-linearised in
//     partial rounds, but ALL t elements still get an ARC constant added).
//   - Therefore total ARC entries = (8 + 57) * 3 = 195. We store them in a
//     flat array of length 195, indexed by [round * t + i].
//   - MDS matrix is t x t = 9 entries, fixed.
//
// All constants are stored as decimal strings to avoid endianness ambiguity
// when fed to libff::Fr<alt_bn128_pp>::from_string-equivalent constructors.
// We provide a small loader that converts at static-init time.
//
// IMPORTANT: do not edit by hand. To regenerate, run:
//   git clone https://extgit.iaik.tugraz.at/krypto/hadeshash
//   cd hadeshash/code
//   sage generate_parameters_grain.sage 1 0 254 3 8 57 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
// then transcribe the printed C[] and M[] arrays into this file.

#ifndef RIPPLE_ZKP_ROLLUP_POSEIDON_CONSTANTS_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_POSEIDON_CONSTANTS_H_INCLUDED

#include <array>
#include <string_view>

namespace ripple {
namespace zkp {
namespace rollup {
namespace poseidon_params {

// Permutation width: t = 3 (rate=2, capacity=1) — supports binary Merkle hashing.
constexpr std::size_t kT = 3;

// Round counts per Hadeshash spec for BN-128 / 128-bit security / t=3 / x^5.
constexpr std::size_t kFullRounds = 8;       // R_F (split 4 + 4 around partials)
constexpr std::size_t kPartialRounds = 57;   // R_P
constexpr std::size_t kTotalRounds = kFullRounds + kPartialRounds;  // 65
constexpr std::size_t kArcCount = kTotalRounds * kT;                // 195

// ===== ROUND CONSTANTS (ARK / ARC) =====
// Each round adds 3 constants to the state (one per lane), total 195.
// Indexed as kArc[round * 3 + lane].
//
// First and last few values shown below verbatim from circomlibjs to anchor
// the Phase 2a reference-vector test. The full 195-entry table is loaded
// from poseidon_constants.inc which contains the Sage-generated values.
//
// SANITY ANCHOR (must match exactly or Phase 2a is wrong).
// Values are circomlibjs's t=3 round constants (auto-extracted via
// tools/poseidon/extract_poseidon_constants.js):
//   kArc[0]   == "6745197990210204598374042828761989596302876299545964402857411729872131034734"
//   kArc[1]   == "426281677759936592021316809065178817848084678679510574715894138690250139748"
//   kArc[2]   == "4014188762916583598888942667424965430287497824629657219807941460227372577781"
//   kArc[194] == "13409242754315411433193860530743374419854094495153957441316635981078068351329"
//
// (These four anchors are sufficient to confirm the table loaded correctly;
//  if any of them mismatches, regenerate the .cpp from circomlibjs.)

extern std::array<std::string_view, kArcCount> const kArcDecimal;

// ===== MDS MATRIX =====
// Symmetric Cauchy-style 3x3 matrix for the BN-128 / t=3 / x^5 parameter set.
// Row-major: kMds[row * 3 + col].
//
// SANITY ANCHOR (circomlibjs values):
//   kMds[0] == "7511745149465107256748700652201246547602992235352608707588321460060273774987"
//   kMds[8] == "11597556804922396090267472882856054602429588299176362916247939723151043581408"

extern std::array<std::string_view, kT * kT> const kMdsDecimal;

// ===== REFERENCE VECTORS (Phase 2a gate) =====
// These three pairs anchor the Phase 2a unit tests. Any implementation that
// matches all three is bit-compatible with circomlib / Tornado Cash Nova.

struct ReferenceVector
{
    std::string_view a_decimal;
    std::string_view b_decimal;
    std::string_view expected_decimal;
};

constexpr ReferenceVector kRefVector_0_0{
    "0",
    "0",
    // Poseidon(0, 0) — circomlibjs verified
    "14744269619966411208579211824598458697587494354926760081771325075741142829156"
};

constexpr ReferenceVector kRefVector_1_2{
    "1",
    "2",
    // Poseidon(1, 2) — circomlibjs verified
    "7853200120776062878684798364095072458815029376092732009249414926327459813530"
};

constexpr ReferenceVector kRefVector_3_4{
    "3",
    "4",
    // Poseidon(3, 4) — circomlibjs verified
    "14763215145315200506921711489642608356394854266165572616578112107564877678998"
};

}  // namespace poseidon_params
}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_POSEIDON_CONSTANTS_H_INCLUDED
