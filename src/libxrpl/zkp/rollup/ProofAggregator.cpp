// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC

#include "ProofAggregator.h"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/fields/bigint.hpp>

#include <gmp.h>
#include <openssl/sha.h>

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace ripple {
namespace zkp {
namespace rollup {

using Curve = libff::alt_bn128_pp;

namespace {

// Reduce a big-endian byte digest mod Fr — same idea as
// PoseidonHash::uint256ToField, just via mpz_import instead of a hex
// round-trip since the input here is already raw bytes, not a uint256.
AggFr
bytesToFr(unsigned char const* digest, std::size_t len)
{
    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, len, 1, 1, 1, 0, digest);

    mpz_t r;
    mpz_init(r);
    AggFr::field_char().to_mpz(r);
    mpz_mod(tmp, tmp, r);

    libff::bigint<libff::alt_bn128_r_limbs> n(tmp);
    mpz_clear(tmp);
    mpz_clear(r);
    return AggFr(n);
}

// Inner pairing product PROD e(A_i, B_i). Requires A.size() == B.size().
AggGT
ipp(std::vector<AggG1> const& A, std::vector<AggG2> const& B)
{
    AggGT acc = AggGT::one();
    for (std::size_t i = 0; i < A.size(); ++i)
        acc = acc * Curve::reduced_pairing(A[i], B[i]);
    return acc;
}

AggG1
multiExpG1(
    std::array<AggG1, kAggN> const& base,
    std::vector<AggFr> const& coeffs)
{
    AggG1 acc = AggG1::zero();
    for (std::size_t i = 0; i < kAggN; ++i)
        acc = acc + coeffs[i] * base[i];
    return acc;
}

AggG2
multiExpG2(
    std::array<AggG2, kAggN> const& base,
    std::vector<AggFr> const& coeffs)
{
    AggG2 acc = AggG2::zero();
    for (std::size_t i = 0; i < kAggN; ++i)
        acc = acc + coeffs[i] * base[i];
    return acc;
}

// Dense coefficients (length kAggN) of PROD_{j=0}^{rounds-1} (1 + factor[j] *
// X^(2^j)), built by iterative in-place polynomial multiplication by each
// binomial factor (safe done high-to-low since poly[k-shift] hasn't been
// touched yet in the current pass).
std::vector<AggFr>
expandBinomialProduct(std::vector<AggFr> const& factors)
{
    std::vector<AggFr> poly(kAggN, AggFr::zero());
    poly[0] = AggFr::one();
    for (std::size_t j = 0; j < factors.size(); ++j)
    {
        std::size_t const shift = std::size_t(1) << j;
        AggFr const coeff = factors[j];
        for (std::size_t k = kAggN; k-- > shift;)
            poly[k] = poly[k] + coeff * poly[k - shift];
    }
    return poly;
}

}  // namespace

// ---------------------------------------------------------------------------
// AggSRS
// ---------------------------------------------------------------------------

AggSRS
AggSRS::generate()
{
    AggFr const a = AggFr::random_element();
    AggFr const b = AggFr::random_element();

    AggSRS srs;
    AggFr aPow = AggFr::one();
    AggFr bPow = AggFr::one();
    for (std::size_t i = 0; i < kAggN; ++i)
    {
        srs.v1[i] = aPow * AggG2::one();
        srs.v2[i] = bPow * AggG2::one();
        aPow = aPow * a;
        bPow = bPow * b;
    }
    // aPow == a^kAggN, bPow == b^kAggN at this point.
    AggFr aShift = aPow;
    AggFr bShift = bPow;
    for (std::size_t i = 0; i < kAggN; ++i)
    {
        srs.w1[i] = aShift * AggG1::one();
        srs.w2[i] = bShift * AggG1::one();
        aShift = aShift * a;
        bShift = bShift * b;
    }
    return srs;
}

void
AggSRS::save(std::string const& path) const
{
    std::ofstream f(path, std::ios::binary);
    if (!f.good())
        throw std::runtime_error("AggSRS::save: cannot open " + path);
    std::vector<AggG2> v1v(v1.begin(), v1.end());
    std::vector<AggG2> v2v(v2.begin(), v2.end());
    std::vector<AggG1> w1v(w1.begin(), w1.end());
    std::vector<AggG1> w2v(w2.begin(), w2.end());
    f << v1v << v2v << w1v << w2v;
}

AggSRS
AggSRS::load(std::string const& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.good())
        throw std::runtime_error("AggSRS::load: cannot open " + path);
    std::vector<AggG2> v1v, v2v;
    std::vector<AggG1> w1v, w2v;
    f >> v1v >> v2v >> w1v >> w2v;
    if (v1v.size() != kAggN || v2v.size() != kAggN || w1v.size() != kAggN ||
        w2v.size() != kAggN)
        throw std::runtime_error("AggSRS::load: size mismatch in " + path);

    AggSRS srs;
    std::copy(v1v.begin(), v1v.end(), srs.v1.begin());
    std::copy(v2v.begin(), v2v.end(), srs.v2.begin());
    std::copy(w1v.begin(), w1v.end(), srs.w1.begin());
    std::copy(w2v.begin(), w2v.end(), srs.w2.begin());
    return srs;
}

// ---------------------------------------------------------------------------
// AggregateProof (de)serialisation
// ---------------------------------------------------------------------------

std::vector<unsigned char>
AggregateProof::serialize() const
{
    std::stringstream ss(std::ios::binary | std::ios::out);
    ss << T_AB << U_AB << Z_AB;
    for (auto const& r : rounds)
        ss << r.zL << r.zR << r.tL << r.uL << r.tR << r.uR;
    ss << finalA << finalB;
    auto s = ss.str();
    return std::vector<unsigned char>(s.begin(), s.end());
}

AggregateProof
AggregateProof::deserialize(std::vector<unsigned char> const& bytes)
{
    std::stringstream ss(
        std::string(bytes.begin(), bytes.end()),
        std::ios::binary | std::ios::in);
    AggregateProof p;
    ss >> p.T_AB >> p.U_AB >> p.Z_AB;
    for (auto& r : p.rounds)
        ss >> r.zL >> r.zR >> r.tL >> r.uL >> r.tR >> r.uR;
    ss >> p.finalA >> p.finalB;
    return p;
}

// ---------------------------------------------------------------------------
// ProofAggregator
// ---------------------------------------------------------------------------

template <typename T>
void
ProofAggregator::appendSerialized(std::vector<unsigned char>& out, T const& elt)
{
    std::stringstream ss(std::ios::binary | std::ios::out);
    ss << elt;
    auto s = ss.str();
    out.insert(out.end(), s.begin(), s.end());
}

AggFr
ProofAggregator::hashToFr(std::vector<unsigned char> const& transcript)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(transcript.data(), transcript.size(), digest);
    return bytesToFr(digest, SHA256_DIGEST_LENGTH);
}

AggregateProof
ProofAggregator::aggregate(
    AggSRS const& srs,
    std::array<RollupProofData, kAggN> const& proofs)
{
    std::vector<AggG1> A(kAggN);
    std::vector<AggG2> B(kAggN);
    for (std::size_t i = 0; i < kAggN; ++i)
    {
        auto proof = RollupProver::deserializeProofPublic(proofs[i].proof_bytes);
        A[i] = proof.g_A;
        B[i] = proof.g_B;
    }

    std::vector<AggG2> v1(srs.v1.begin(), srs.v1.end());
    std::vector<AggG2> v2(srs.v2.begin(), srs.v2.end());
    std::vector<AggG1> w1(srs.w1.begin(), srs.w1.end());
    std::vector<AggG1> w2(srs.w2.begin(), srs.w2.end());

    // Initial commitment on the ORIGINAL (unscaled) A, B — bootstraps r via
    // Fiat-Shamir before any rescaling. See the memory note: this value is
    // identical whether computed on (A,B,w1,w2) or the later-rescaled
    // (A,B',w'1,w'2), because the r and r^-1 factors cancel inside each
    // pairing — that identity is exactly what makes the rescaling trick sound.
    AggGT const T_AB = ipp(A, v1) * ipp(w1, B);
    AggGT const U_AB = ipp(A, v2) * ipp(w2, B);

    std::vector<unsigned char> hcomBytes;
    appendSerialized(hcomBytes, T_AB);
    appendSerialized(hcomBytes, U_AB);
    AggFr const hcom = hashToFr(hcomBytes);

    std::vector<unsigned char> x0Bytes;
    appendSerialized(x0Bytes, hcom);
    AggFr const r = hashToFr(x0Bytes);

    std::vector<AggFr> rPow(kAggN);
    rPow[0] = AggFr::one();
    for (std::size_t i = 1; i < kAggN; ++i)
        rPow[i] = rPow[i - 1] * r;

    // Rescale B -> B' = B^r and w1,w2 -> w'1,w'2 = w1^(1/r), w2^(1/r),
    // component-wise, once.
    std::vector<AggG2> Bp(kAggN);
    std::vector<AggG1> w1p(kAggN), w2p(kAggN);
    for (std::size_t i = 0; i < kAggN; ++i)
    {
        Bp[i] = rPow[i] * B[i];
        AggFr const rInv = rPow[i].inverse();
        w1p[i] = rInv * w1[i];
        w2p[i] = rInv * w2[i];
    }

    AggGT const Z_AB = ipp(A, Bp);

    std::array<TippRound, kAggRounds> rounds;
    std::vector<AggG1> curA = A;
    std::vector<AggG2> curB = Bp;
    std::vector<AggG2> curV1 = v1, curV2 = v2;
    std::vector<AggG1> curW1 = w1p, curW2 = w2p;
    AggFr xPrev = hcom;

    std::size_t m = kAggN;
    for (std::size_t round = 0; round < kAggRounds; ++round)
    {
        std::size_t const mp = m / 2;

        std::vector<AggG1> A_lo(curA.begin(), curA.begin() + mp);
        std::vector<AggG1> A_hi(curA.begin() + mp, curA.begin() + m);
        std::vector<AggG2> B_lo(curB.begin(), curB.begin() + mp);
        std::vector<AggG2> B_hi(curB.begin() + mp, curB.begin() + m);
        std::vector<AggG2> V1_lo(curV1.begin(), curV1.begin() + mp);
        std::vector<AggG2> V1_hi(curV1.begin() + mp, curV1.begin() + m);
        std::vector<AggG2> V2_lo(curV2.begin(), curV2.begin() + mp);
        std::vector<AggG2> V2_hi(curV2.begin() + mp, curV2.begin() + m);
        std::vector<AggG1> W1_lo(curW1.begin(), curW1.begin() + mp);
        std::vector<AggG1> W1_hi(curW1.begin() + mp, curW1.begin() + m);
        std::vector<AggG1> W2_lo(curW2.begin(), curW2.begin() + mp);
        std::vector<AggG1> W2_hi(curW2.begin() + mp, curW2.begin() + m);

        // Cross terms — see the memory note for the index derivation
        // (zero-padded CMd expands to cross pairings between the "hi" half
        // of one vector and the "lo" half of the OTHER).
        AggGT const zL = ipp(A_hi, B_lo);
        AggGT const zR = ipp(A_lo, B_hi);
        AggGT const tL = ipp(A_hi, V1_lo) * ipp(W1_hi, B_lo);
        AggGT const uL = ipp(A_hi, V2_lo) * ipp(W2_hi, B_lo);
        AggGT const tR = ipp(A_lo, V1_hi) * ipp(W1_lo, B_hi);
        AggGT const uR = ipp(A_lo, V2_hi) * ipp(W2_lo, B_hi);

        std::vector<unsigned char> xb;
        appendSerialized(xb, xPrev);
        appendSerialized(xb, zL);
        appendSerialized(xb, zR);
        appendSerialized(xb, tL);
        appendSerialized(xb, uL);
        appendSerialized(xb, tR);
        appendSerialized(xb, uR);
        AggFr const x = hashToFr(xb);
        AggFr const xInv = x.inverse();

        std::vector<AggG1> newA(mp);
        std::vector<AggG2> newB(mp);
        std::vector<AggG2> newV1(mp), newV2(mp);
        std::vector<AggG1> newW1(mp), newW2(mp);
        for (std::size_t k = 0; k < mp; ++k)
        {
            newA[k] = A_lo[k] + x * A_hi[k];
            newB[k] = B_lo[k] + xInv * B_hi[k];
            newV1[k] = V1_lo[k] + xInv * V1_hi[k];
            newV2[k] = V2_lo[k] + xInv * V2_hi[k];
            newW1[k] = W1_lo[k] + x * W1_hi[k];
            newW2[k] = W2_lo[k] + x * W2_hi[k];
        }

        rounds[round] = TippRound{zL, zR, tL, uL, tR, uR};
        curA = std::move(newA);
        curB = std::move(newB);
        curV1 = std::move(newV1);
        curV2 = std::move(newV2);
        curW1 = std::move(newW1);
        curW2 = std::move(newW2);
        xPrev = x;
        m = mp;
    }

    AggregateProof out;
    out.T_AB = T_AB;
    out.U_AB = U_AB;
    out.Z_AB = Z_AB;
    out.rounds = rounds;
    out.finalA = curA[0];
    out.finalB = curB[0];
    return out;
}

bool
ProofAggregator::verifyAggregate(
    AggSRS const& srs,
    AggregateProof const& agg,
    std::array<RollupProofData, kAggN> const& proofs)
{
    auto const& vk = RollupProver::verificationKey();

    // Reconstruct r exactly as aggregate() derived it.
    std::vector<unsigned char> hcomBytes;
    appendSerialized(hcomBytes, agg.T_AB);
    appendSerialized(hcomBytes, agg.U_AB);
    AggFr const hcom = hashToFr(hcomBytes);

    std::vector<unsigned char> x0Bytes;
    appendSerialized(x0Bytes, hcom);
    AggFr const r = hashToFr(x0Bytes);

    std::vector<AggFr> rPow(kAggN);
    rPow[0] = AggFr::one();
    for (std::size_t i = 1; i < kAggN; ++i)
        rPow[i] = rPow[i - 1] * r;

    // Reconstruct round challenges and fold (Z,T,U) alongside them.
    AggGT Zc = agg.Z_AB, Tc = agg.T_AB, Uc = agg.U_AB;
    AggFr xPrev = hcom;
    std::vector<AggFr> xs(kAggRounds);
    for (std::size_t round = 0; round < kAggRounds; ++round)
    {
        auto const& rd = agg.rounds[round];
        std::vector<unsigned char> xb;
        appendSerialized(xb, xPrev);
        appendSerialized(xb, rd.zL);
        appendSerialized(xb, rd.zR);
        appendSerialized(xb, rd.tL);
        appendSerialized(xb, rd.uL);
        appendSerialized(xb, rd.tR);
        appendSerialized(xb, rd.uR);
        AggFr const x = hashToFr(xb);
        AggFr const xInv = x.inverse();
        xs[round] = x;

        Zc = (rd.zL ^ x.as_bigint()) * Zc * (rd.zR ^ xInv.as_bigint());
        Tc = (rd.tL ^ x.as_bigint()) * Tc * (rd.tR ^ xInv.as_bigint());
        Uc = (rd.uL ^ x.as_bigint()) * Uc * (rd.uR ^ xInv.as_bigint());

        xPrev = x;
    }

    // Base case: the fully-folded values must equal the direct pairings on
    // the transmitted finalA, finalB.
    if (Zc != Curve::reduced_pairing(agg.finalA, agg.finalB))
        return false;

    // Recompute the final commitment keys directly (skip-KZG simplification
    // — see header/memory doc). f_v(X) = PROD_{j=0}^{l-1}(1 + x_(l-j)^-1 *
    // X^(2^j)); f_w uses x_(l-j) (not inverted) times r^(-2^j), and its
    // coefficients pair directly against w1/w2 since those SRS elements
    // already represent the X^(n+i) monomials.
    std::vector<AggFr> fvFactors(kAggRounds);
    for (std::size_t j = 0; j < kAggRounds; ++j)
        fvFactors[j] = xs[kAggRounds - 1 - j].inverse();
    std::vector<AggFr> const fvCoeffs = expandBinomialProduct(fvFactors);

    std::vector<AggFr> fwFactors(kAggRounds);
    AggFr const rInv = r.inverse();
    AggFr rInvPow = rInv;
    for (std::size_t j = 0; j < kAggRounds; ++j)
    {
        fwFactors[j] = xs[kAggRounds - 1 - j] * rInvPow;
        rInvPow = rInvPow * rInvPow;
    }
    std::vector<AggFr> const fwCoeffs = expandBinomialProduct(fwFactors);

    AggG2 const v1f = multiExpG2(srs.v1, fvCoeffs);
    AggG2 const v2f = multiExpG2(srs.v2, fvCoeffs);
    AggG1 const w1f = multiExpG1(srs.w1, fwCoeffs);
    AggG1 const w2f = multiExpG1(srs.w2, fwCoeffs);

    if (Tc != Curve::reduced_pairing(agg.finalA, v1f) *
                  Curve::reduced_pairing(w1f, agg.finalB))
        return false;
    if (Uc != Curve::reduced_pairing(agg.finalA, v2f) *
                  Curve::reduced_pairing(w2f, agg.finalB))
        return false;

    // Direct (non-GIPA) aggregation of C_i and the per-entry public-input
    // accumulation vk_x_i — justified at N=8, see header doc. Both are O(N)
    // multi-scalar sums a verifier can just compute rather than compressing
    // via a second (MIPP) GIPA recursion.
    AggG1 Z_C = AggG1::zero();
    AggG1 vkXAgg = AggG1::zero();
    for (std::size_t i = 0; i < kAggN; ++i)
    {
        auto proof = RollupProver::deserializeProofPublic(proofs[i].proof_bytes);
        Z_C = Z_C + rPow[i] * proof.g_C;

        libsnark::r1cs_primary_input<FieldT> primary;
        primary.push_back(proofs[i].anchor);
        primary.push_back(proofs[i].new_anchor);
        primary.push_back(proofs[i].nullifier);
        primary.push_back(proofs[i].value_pub);
        primary.push_back(proofs[i].is_withdraw ? FieldT::one() : FieldT::zero());
        auto const accI = vk.gamma_ABC_g1
                               .template accumulate_chunk<FieldT>(
                                   primary.begin(), primary.end(), 0)
                               .first;
        vkXAgg = vkXAgg + rPow[i] * accI;
    }

    AggFr sumR = AggFr::zero();
    for (std::size_t i = 0; i < kAggN; ++i)
        sumR = sumR + rPow[i];

    AggGT const rhs = (vk.alpha_g1_beta_g2 ^ sumR.as_bigint()) *
        Curve::reduced_pairing(vkXAgg, vk.gamma_g2) *
        Curve::reduced_pairing(Z_C, vk.delta_g2);

    return agg.Z_AB == rhs;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
