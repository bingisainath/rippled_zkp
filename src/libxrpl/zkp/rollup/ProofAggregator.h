// ProofAggregator: SnarkPack-style aggregation of Track 1's N independent
// per-user Groth16 proofs into ONE aggregate proof, verified with O(log N)
// pairings for the recursion instead of N separate verifications — while
// users keep proving locally, so the sequencer never sees a transaction's
// contents (contrast Track 2, where the sequencer proves).
//
// Construction: the merged MT-IPP scheme of SnarkPack [BMMTV21, eprint
// 2021/529; FC22], over N Groth16 proofs sharing one verification key
// (RollupProver's). TIPP (Z_AB = PROD e(A_i, B_i^(r^i))) and MIPP
// (Z_C = <C, r>) share one GIPA recursion and one Fiat-Shamir transcript.
// N is a runtime parameter and must be a power of two, since GIPA halves
// the vector every round.
//
// Aggregating the public inputs (vk_x_agg = sum r^i * vk_x_i) stays a direct
// O(N) computation, matching SnarkPack's own design: MIPP aggregates group
// elements, not public-input scalars, and verification is linear in the
// public inputs by construction.
//
// KZG final-key openings (paper Appendix E) cover all four folded keys, so
// the verifier checks them with a fixed number of pairings rather than an
// N-term multi-exponentiation:
//   - v1/v2 commit in G2, so their openings use the flipped variant with the
//     opening proof also in G2, checked as
//       e(g, v1f - y*h) =? e(vkA - z*g, pi_v1)
//     against a single new G1 element vkA = g^a (vkB = g^b for v2).
//   - w1/w2 commit in G1 over the shifted SRS range n..2n-1, but the
//     quotient generically has nonzero coefficients across the full
//     0..2n-2 range, so they need w1Low/w2Low = {g^(a^i)} for i=0..n-1
//     prepended to cover 0..2n-1. Checked normally as
//       e(w1f - y*g, h) =? e(pi_w1, v1[1] - z*h)
//     reusing v1[1] = h^a as the opposite-group verification key.
//
// verifyAggregate() folds every pairing check into one shared final
// exponentiation (BatchedPairingCheck, ProofAggregator.cpp).

#ifndef RIPPLE_ZKP_ROLLUP_PROOF_AGGREGATOR_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_PROOF_AGGREGATOR_H_INCLUDED

#include "PoseidonHash.h"
#include "RollupProver.h"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <cstddef>
#include <memory>
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
    std::vector<AggG2> v1;     // h^(a^i),       i = 0..N-1
    std::vector<AggG2> v2;     // h^(b^i),       i = 0..N-1
    std::vector<AggG1> w1Low;  // g^(a^i),       i = 0..N-1   (KZG opening range for w1)
    std::vector<AggG1> w1;     // g^(a^(N+i)),   i = 0..N-1
    std::vector<AggG1> w2Low;  // g^(b^i),       i = 0..N-1   (KZG opening range for w2)
    std::vector<AggG1> w2;     // g^(b^(N+i)),   i = 0..N-1
    AggG1 vkA;                 // g^a — verification key point for v1's KZG opening
    AggG1 vkB;                 // g^b — verification key point for v2's KZG opening
    // v1[1] = h^a and v2[1] = h^b serve as the verification key points for
    // w1's / w2's KZG openings — no separate G2 elements needed for those.

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

// One GIPA round's prover-to-verifier message — TIPP's (A,B') cross terms
// AND MIPP's (C,r) cross terms together, sharing one Fiat-Shamir challenge
// per round (the "merged" in MT-IPP). Note the MIPP cross terms (zL_C,
// zR_C) are G1 multi-exponentiation results, NOT pairings — <C,r> is a
// group multiexp, not a pairing product, so it folds with plain G1 scalar
// multiplication where TIPP's zL/zR fold with GT exponentiation. tL_C/uL_C/
// tR_C/uR_C ARE pairing-valued (they come from CMs(v1,v2;C), which commits
// via pairings the same way TIPP's CMd does) — same fold pattern as TIPP's
// tL/uL/tR/uR.
struct MtRound
{
    // TIPP
    AggGT zL, zR;
    AggGT tL, uL;
    AggGT tR, uR;
    // MIPP
    AggG1 zL_C, zR_C;
    AggGT tL_C, uL_C;
    AggGT tR_C, uR_C;
};

// The aggregate proof for N Groth16 proofs sharing one verification key.
struct AggregateProof
{
    // Initial CMd(v1,v2,w1,w2; A,B) commitment, computed on the ORIGINAL
    // (unscaled) A,B — this is what bootstraps the Fiat-Shamir challenge r
    // before any rescaling happens, and is also the GIPA recursion's
    // starting (T_0, U_0). Identical whether computed on (A,B) or the
    // r-rescaled (A,B',w'1,w'2).
    AggGT T_AB, U_AB;

    // Claimed value of the inner pairing product PROD e(A_i, B_i^(r^i)).
    // The GIPA rounds below are the proof that this value is correct.
    AggGT Z_AB;

    // MIPP: initial CMs(v1,v2;C) commitment (on the ORIGINAL, unfolded C —
    // same bootstrapping role as T_AB/U_AB) and the claimed multi-
    // exponentiation value Z_C = <C,r> = sum(r^i * C_i). Z_C is a G1
    // element (a multiexp result), NOT a GT/pairing value like Z_AB.
    AggGT T_C, U_C;
    AggG1 Z_C;

    std::vector<MtRound> rounds;  // length log2(N)

    // Fully-folded (length-1) A, B', and C after all rounds.
    AggG1 finalA;
    AggG2 finalB;
    AggG1 finalC;

    // Final commitment keys — sent directly by the prover (free, already
    // computed while folding) — plus their KZG opening proofs certifying
    // each is the correct fold of the SRS under the announced challenges.
    // v1f/v2f live in G2 (v1/v2's own group); w1f/w2f live in G1. Opening
    // proofs live in the SAME group as the thing they open (piV1/piV2 in
    // G2, piW1/piW2 in G1) — see the header's KZG section for why.
    AggG2 v1f, v2f;
    AggG1 w1f, w2f;
    AggG2 piV1, piV2;
    AggG1 piW1, piW2;

    std::vector<unsigned char>
    serialize() const;

    static AggregateProof
    deserialize(std::vector<unsigned char> const& bytes);
};

class ProofAggregator
{
public:
    // Default AggSRS cache path — distinct from RollupProver's and
    // BatchCircuitProver's key paths on purpose (same discipline as those
    // two: never share files across independent trusted setups).
    static std::string const&
    defaultSrsPath();

    // Load a cached AggSRS from disk, or generate-and-save one (local
    // toxic-waste setup, same trust model as the Groth16 trusted setup) if
    // none exists yet. Idempotent — a node calls this once at startup
    // (RollupModule::onStart), the same way it loads RollupProver's and
    // BatchCircuitProver's keys.
    static void
    initialize(std::string const& srsPath = defaultSrsPath(), std::size_t n = 8);

    static bool
    isInitialized();

    // Read-only access to the loaded SRS — throws if not yet initialised.
    static AggSRS const&
    srs();

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

    static std::shared_ptr<AggSRS> srs_;
    static bool initialised_;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif
