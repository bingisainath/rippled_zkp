// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// ProofAggregator: SnarkPack-style aggregation of Track 1's 8 independent
// per-user Groth16 proofs into ONE aggregate proof, verified with O(log N)
// pairings instead of N separate verifications — while users keep proving
// locally (Track 1's privacy property; contrast Track 2, where the
// sequencer proves and therefore sees every transaction's contents).
//
// Construction: the TIPP (target inner pairing product) half of SnarkPack's
// merged MT-IPP scheme [BMMTV21 / eprint 2021/529, FC22 "SnarkPack: Practical
// SNARK Aggregation"], applied to N=8 Groth16 proofs sharing one
// verification key (RollupProver's). Two deliberate scope simplifications
// relative to the full paper, both justified ONLY because N=8 is tiny — see
// the `track1-aggregation-snarkpack` note for the full derivation:
//
//   1. MIPP is not implemented. MIPP exists purely to avoid O(N) verifier
//      work when combining the C_i proof elements and the per-proof public
//      inputs (vk_x_i) under a random linear combination. At N=8 that O(N)
//      work is 8 scalar multiplications — cheaper than running a second
//      GIPA recursion for it — so verifyAggregate() computes
//      Z_C = sum(r^i * C_i) and vk_x_agg = sum(r^i * vk_x_i) directly.
//   2. The final commitment key's KZG opening proof (paper Appendix E) is
//      not implemented. The paper's own formula shows the final key is
//      v = g^f(alpha) for a PUBLIC polynomial f (coefficients depend only on
//      the Fiat-Shamir challenges), so it can be recomputed directly via an
//      O(N) multi-exponentiation over the original public SRS elements —
//      exactly the value a KZG opening would certify, just computed
//      directly rather than via a log(N)-time evaluation proof. KZG only
//      matters when N is large enough that O(N) is worse than O(log N); at
//      N=8 it isn't.
//
// Neither simplification weakens soundness — both recompute the same public
// values a full implementation would, just via O(N) direct computation
// instead of an O(log N) sub-protocol that isn't needed at this batch size.
//
// What's NOT simplified: the TIPP GIPA recursion itself, which compresses
// Z_AB = PROD e(A_i, B_i^(r^i)) from N pairings/final-exponentiations down to
// O(log N) — this is the one thing that can't be computed directly at any N
// without paying the cost aggregation exists to remove.
//
// HONEST EXPECTATION, per the SnarkPack paper's own published benchmarks:
// "batching is more efficient when verifying fewer than 32 Groth16 proofs...
// the break-even point where aggregation takes less space than batching
// occurs around 150 proofs" (FC22 paper). At N=8 this implementation is
// expected to be SLOWER and LARGER than Track 1's existing 8-independent-
// proof verification — that is not a bug. The point of building and
// measuring it here is to produce a real N=8 data point and demonstrate the
// O(log N) vs O(N) shape experimentally, projecting to the N where it wins,
// exactly like phase6/phase7 projected Track 2's numbers to larger N.

#ifndef RIPPLE_ZKP_ROLLUP_PROOF_AGGREGATOR_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_PROOF_AGGREGATOR_H_INCLUDED

#include "PoseidonHash.h"
#include "RollupProver.h"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <array>
#include <cstddef>
#include <string>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {

// Fixed batch size, matching Track 1/2's existing N=8 convention.
constexpr std::size_t kAggN = 8;
// log2(kAggN) — GIPA halves the vector length every round.
constexpr std::size_t kAggRounds = 3;

using AggG1 = libff::alt_bn128_G1;
using AggG2 = libff::alt_bn128_G2;
using AggGT = libff::alt_bn128_GT;  // = libff::alt_bn128_Fq12
using AggFr = libff::alt_bn128_Fr;

// Structured reference string for the TIPP commitment scheme (paper Section
// 3, "Double group version CMd"). Independent of the PoseidonCircuit's
// Groth16 SRS — this is a SEPARATE local toxic-waste setup: two trapdoors
// a, b are sampled, used to derive the four vectors below, and discarded on
// return. Same trust model as the existing Groth16 trusted setup
// (RollupProver::initialize's r1cs_gg_ppzksnark_generator step) — documented
// identically as a prototype simplification (a real deployment would run an
// MPC ceremony, or reuse two independent existing Groth16 SRS transcripts as
// the original SnarkPack implementation does).
struct AggSRS
{
    std::array<AggG2, kAggN> v1;  // h^(a^i),       i = 0..N-1
    std::array<AggG2, kAggN> v2;  // h^(b^i),       i = 0..N-1
    std::array<AggG1, kAggN> w1;  // g^(a^(N+i)),   i = 0..N-1
    std::array<AggG1, kAggN> w2;  // g^(b^(N+i)),   i = 0..N-1

    static AggSRS
    generate();

    void
    save(std::string const& path) const;

    static AggSRS
    load(std::string const& path);
};

// One GIPA round's prover-to-verifier message.
struct TippRound
{
    AggGT zL, zR;
    AggGT tL, uL;
    AggGT tR, uR;
};

// The aggregate proof for kAggN Groth16 proofs sharing one verification key.
struct AggregateProof
{
    // Initial CMd(v1,v2,w1,w2; A,B) commitment, computed on the ORIGINAL
    // (unscaled) A,B — this is what bootstraps the Fiat-Shamir challenge r
    // before any rescaling happens, and is also the GIPA recursion's
    // starting (T_0, U_0). Identical whether computed on (A,B) or the
    // r-rescaled (A,B',w'1,w'2) — see the memory note for why.
    AggGT T_AB, U_AB;

    // Claimed value of the inner pairing product PROD e(A_i, B_i^(r^i)).
    // The GIPA rounds below are the proof that this value is correct.
    AggGT Z_AB;

    std::array<TippRound, kAggRounds> rounds;

    // Fully-folded (length-1) A and B' after all kAggRounds rounds.
    AggG1 finalA;
    AggG2 finalB;

    std::vector<unsigned char>
    serialize() const;

    static AggregateProof
    deserialize(std::vector<unsigned char> const& bytes);
};

class ProofAggregator
{
public:
    // Aggregate kAggN already-produced, individually-valid Track 1 Groth16
    // proofs (from RollupProver::createProof) into one AggregateProof.
    // Operates purely on the raw Groth16 (A, B, C) elements pulled out of
    // each proof's serialised bytes — never touches any circuit witness, so
    // this step (and verifyAggregate below) genuinely cannot see anything
    // the individual users didn't already make public by producing their
    // proofs. That is the whole privacy argument for this design.
    static AggregateProof
    aggregate(
        AggSRS const& srs,
        std::array<RollupProofData, kAggN> const& proofs);

    // Verify an AggregateProof against the same kAggN proofs' PUBLIC INPUTS
    // (anchor, new_anchor, nullifier, value_pub, is_withdraw — exactly what
    // RollupProofData already carries publicly) and RollupProver's already-
    // loaded verification key (RollupProver::verificationKey()). Requires
    // RollupProver to be initialised first (verifier-only load is enough —
    // this never touches the large proving key).
    static bool
    verifyAggregate(
        AggSRS const& srs,
        AggregateProof const& agg,
        std::array<RollupProofData, kAggN> const& publicInputs);

private:
    // Fiat-Shamir over the existing libsnark stream serialisation of
    // G1/G2/GT elements (SHA-256, reduced mod Fr) — this transcript hashing
    // is native C++, never inside a circuit, so there is no reason to pay
    // Poseidon's cost/complexity here (contrast PoseidonHash, used only for
    // in-circuit hashing).
    static AggFr
    hashToFr(std::vector<unsigned char> const& transcript);

    template <typename T>
    static void
    appendSerialized(std::vector<unsigned char>& out, T const& elt);
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif
