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
// STATUS (see track1-aggregation-snarkpack memory for the full history):
// this now implements the MERGED MT-IPP scheme — TIPP (proves Z_AB =
// PROD e(A_i, B_i^(r^i))) AND MIPP (proves Z_C = <C, r>, the multi-
// exponentiation aggregating each proof's C element) share one GIPA
// recursion and one Fiat-Shamir transcript, per the paper's Section 4 "our
// MT-IPP makes black-box use of the two Pair Group Commitments ... and
// fuses together proofs for MIPP and TIPP relations." This makes the
// C-element aggregation genuinely O(log N) instead of the O(N) direct
// multi-scalar-mult an earlier version of this file used.
//
// One deliberate scope simplification remains, matching real SnarkPack's
// OWN design choice (not a corner we cut): the per-proof PUBLIC INPUT
// aggregation (vk_x_agg = sum r^i * vk_x_i, from each proof's 5 public
// field elements) stays a direct O(N) computation. The paper's own FC22
// text says exactly this is fine: "the verification algorithm is linear in
// terms of the public inputs... small enough to barely count for the total
// verification time" — MIPP exists for aggregating GROUP elements (C_i),
// not the public-input scalars, and real implementations don't try to make
// this part logarithmic either.
//
// KZG final-key opening (paper Appendix E) is now implemented for all four
// keys (v1, v2, w1, w2). v1f/v2f/w1f/w2f are no longer recomputed by the
// verifier via an O(N) multi-exponentiation — the PROVER sends them
// directly (free — it already has them from folding) plus a KZG opening
// proof per key, and the verifier checks each via a small, FIXED number of
// pairings (folded into the same BatchedPairingCheck as everything else)
// instead of an N-term multi-exponentiation.
//
// v1/v2 commit IN G2 (v1f = h^f_v(a)), so their openings use the "flipped"
// KZG variant: opening proof pi ALSO in G2 (computed via v1/v2's own SRS,
// since the quotient q_v has degree <= n-2, well within v1/v2's existing
// 0..n-1 range — no SRS expansion needed here), verified via
//   e(g, v1f - y*h) =? e(vkA - z*g, pi_v1)
// using a NEW single G1 element vkA = g^a (vkB = g^b for v2's check).
//
// w1/w2 commit IN G1 (w1f = g^f_w(a)) using the SHIFTED SRS range n..2n-1 —
// but the QUOTIENT (f_w(X)-y)/(X-z) generically has NONZERO coefficients
// across the FULL 0..2n-2 range (polynomial division mixes degrees even
// though f_w's own low-degree coefficients are all zero), so w1/w2's
// openings DO need an expanded SRS: w1Low/w2Low = {g^(a^i)}/{g^(b^i)} for
// i=0..n-1, concatenated with the existing w1/w2 (n..2n-1) to cover the
// full 0..2n-1 range. Verified via the standard (non-flipped) KZG check
//   e(w1f - y*g, h) =? e(pi_w1, v1[1] - z*h)
// reusing v1[1]=h^a / v2[1]=h^b as the "opposite-group" verification key —
// no new G2 elements needed for this side.
//
// PERFORMANCE NOTE: verifyAggregate() batches its pairing checks into one
// shared final exponentiation (BatchedPairingCheck, ProofAggregator.cpp) —
// this on its own turned out NOT to be the dominant cost (see memory).
// MIPP's real-world payoff was a genuine surprise (it made things SLOWER
// at every N tested up to 128 — the O(N) computation it replaces was cheap
// pairing-free scalar math, while MIPP's own per-round overhead roughly
// doubles the pairing-heavy GIPA fold; the crossover is projected around
// N~256-512, not measured). KZG's cost/benefit is measured separately —
// see memory for the honest comparison once both are in.

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
    // r-rescaled (A,B',w'1,w'2). See the memory note for why.
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
