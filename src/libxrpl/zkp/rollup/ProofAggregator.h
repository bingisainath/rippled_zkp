// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// ProofAggregator: SnarkPack-style aggregation of Track 1's N independent
// per-user Groth16 proofs into ONE aggregate proof, verified with O(log N)
// pairings for the recursion itself instead of N separate verifications —
// while users keep proving locally (Track 1's privacy property; contrast
// Track 2, where the sequencer proves and therefore sees every
// transaction's contents).
//
// Construction: the TIPP (target inner pairing product) half of SnarkPack's
// merged MT-IPP scheme [BMMTV21 / eprint 2021/529, FC22 "SnarkPack: Practical
// SNARK Aggregation"], applied to N Groth16 proofs sharing one verification
// key (RollupProver's). N is a runtime parameter (must be a power of two —
// GIPA halves the vector every round), not a fixed constant: this generality
// is what let us actually MEASURE N=8/16/32/64/128 rather than project them
// analytically — see the track1-aggregation-snarkpack memory note.
//
// Two deliberate scope simplifications relative to the full paper — see the
// memory note for the full derivation:
//
//   1. MIPP is not implemented. MIPP exists purely to avoid O(N) verifier
//      work when combining the C_i proof elements and the per-proof public
//      inputs (vk_x_i) under a random linear combination. verifyAggregate()
//      always computes Z_C = sum(r^i * C_i) and vk_x_agg = sum(r^i * vk_x_i)
//      directly (O(N) scalar multiplications, no pairings) rather than
//      running a second GIPA recursion for it. Cheap at small N; means
//      overall verifier time stays O(N) (dominated by this term) even
//      though the TIPP recursion itself is O(log N) — see the measured
//      N=8/16/32/64/128 table in memory for how this actually plays out.
//   2. The final commitment key's KZG opening proof (paper Appendix E) is
//      not implemented. The paper's own formula shows the final key is
//      v = g^f(alpha) for a PUBLIC polynomial f (coefficients depend only on
//      the Fiat-Shamir challenges), so it can be recomputed directly via an
//      O(N) multi-exponentiation over the original public SRS elements —
//      exactly the value a KZG opening would certify, just computed
//      directly rather than via a log(N)-time evaluation proof.
//
// Neither simplification weakens soundness — both recompute the same public
// values a full implementation would, just via O(N) direct computation
// instead of an O(log N) sub-protocol. Implementing both would be needed to
// get genuinely O(log N) verifier time at large N; not done here — see
// memory for the honest cost/benefit of that follow-up.
//
// What's NOT simplified: the TIPP GIPA recursion itself, which compresses
// Z_AB = PROD e(A_i, B_i^(r^i)) from N pairings/final-exponentiations down to
// O(log N) — this is the one thing that can't be computed directly at any N
// without paying the cost aggregation exists to remove.
//
// PERFORMANCE NOTE: verifyAggregate() also does NOT batch its ~7 separate
// reduced_pairing calls into one combined final exponentiation, unlike
// SnarkPack's own reference implementation (which explicitly does this to
// avoid paying final-exponentiation cost repeatedly). This is a real,
// identified, unclaimed optimization opportunity, not a fundamental limit —
// left for a follow-up since Stage A's priority was a correct, real number.

#ifndef RIPPLE_ZKP_ROLLUP_PROOF_AGGREGATOR_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_PROOF_AGGREGATOR_H_INCLUDED

#include "PoseidonHash.h"
#include "RollupProver.h"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {

using AggG1 = libff::alt_bn128_G1;
using AggG2 = libff::alt_bn128_G2;
using AggGT = libff::alt_bn128_GT;  // = libff::alt_bn128_Fq12
using AggFr = libff::alt_bn128_Fr;

// Structured reference string for the TIPP commitment scheme (paper Section
// 3, "Double group version CMd"), sized for a given N. Independent of the
// PoseidonCircuit's Groth16 SRS — this is a SEPARATE local toxic-waste
// setup: two trapdoors a, b are sampled, used to derive the four vectors
// below, and discarded on return. Same trust model as the existing Groth16
// trusted setup (RollupProver::initialize's r1cs_gg_ppzksnark_generator
// step) — documented identically as a prototype simplification (a real
// deployment would run an MPC ceremony, or reuse two independent existing
// Groth16 SRS transcripts as the original SnarkPack implementation does).
struct AggSRS
{
    std::vector<AggG2> v1;  // h^(a^i),       i = 0..N-1
    std::vector<AggG2> v2;  // h^(b^i),       i = 0..N-1
    std::vector<AggG1> w1;  // g^(a^(N+i)),   i = 0..N-1
    std::vector<AggG1> w2;  // g^(b^(N+i)),   i = 0..N-1

    std::size_t
    n() const
    {
        return v1.size();
    }

    static AggSRS
    generate(std::size_t n);

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

// The aggregate proof for N Groth16 proofs sharing one verification key.
struct AggregateProof
{
    // Initial CMd(v1,v2,w1,w2; A,B) commitment, computed on the ORIGINAL
    // (unscaled) A,B — this is what bootstraps the Fiat-Shamir challenge r
    // before any rescaling happens, and is also the GIPA recursion's
    // starting (T_0, U_0). Identical whether computed on (A,B) or the
    // r-rescaled (A,B',w'1,w'2). See the memory note for why.
    AggGT T_AB, U_AB;

    // Claimed value of the inner pairing product PROD e(A_i, B_i^(r^i)).
    // The GIPA rounds below are the proof that this value is correct.
    AggGT Z_AB;

    std::vector<TippRound> rounds;  // length log2(N)

    // Fully-folded (length-1) A and B' after all rounds.
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
    // Aggregate N already-produced, individually-valid Track 1 Groth16
    // proofs (from RollupProver::createProof) into one AggregateProof. N
    // (proofs.size()) must be a power of two. Operates purely on the raw
    // Groth16 (A, B, C) elements pulled out of each proof's serialised
    // bytes — never touches any circuit witness, so this step (and
    // verifyAggregate below) genuinely cannot see anything the individual
    // users didn't already make public by producing their proofs. That is
    // the whole privacy argument for this design.
    static AggregateProof
    aggregate(AggSRS const& srs, std::vector<RollupProofData> const& proofs);

    // Verify an AggregateProof against the same N proofs' PUBLIC INPUTS
    // (anchor, new_anchor, nullifier, value_pub, is_withdraw — exactly what
    // RollupProofData already carries publicly) and RollupProver's already-
    // loaded verification key (RollupProver::verificationKey()). Requires
    // RollupProver to be initialised first (verifier-only load is enough —
    // this never touches the large proving key).
    static bool
    verifyAggregate(
        AggSRS const& srs,
        AggregateProof const& agg,
        std::vector<RollupProofData> const& publicInputs);

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
