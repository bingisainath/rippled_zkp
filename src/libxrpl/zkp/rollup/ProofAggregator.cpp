// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC

#include "ProofAggregator.h"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/fields/bigint.hpp>
#include <libff/common/serialization.hpp>

#include <gmp.h>
#include <openssl/sha.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
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

// Accumulates PROD e(P_i, Q_i)^(rho_i) as ONE unreduced Miller-loop product
// across many terms drawn from several logically-separate pairing
// equations, deferring the expensive final exponentiation to a single call
// at the very end — "batch pairing checks, pay for one FinalExponentiation
// instead of N", the specific optimization identified as missing from the
// original implementation (see ProofAggregator.h's PERFORMANCE NOTE).
//
// Soundness: the rho_i are fresh, LOCAL, non-Fiat-Shamir randomness (sampled
// after every value being checked is already fixed) — same technique
// SnarkPack's own reference implementation uses ("the verifier samples from
// /dev/urandom"). A proof that fails any individual equation only survives
// the combined check with probability ~1/|Fr|, because the prover cannot
// have anticipated these weights when producing the proof.
class BatchedPairingCheck
{
public:
    // Accumulate e(weight*P, Q) into the running Miller-loop product.
    void
    addTerm(AggG1 const& P, AggG2 const& Q, AggFr const& weight)
    {
        AggG1 const scaledP = weight * P;
        millerAccum_ = millerAccum_ *
            Curve::miller_loop(
                Curve::precompute_G1(scaledP), Curve::precompute_G2(Q));
    }

    // Multiply the running target product by target^weight — a plain GT
    // exponentiation, cheap relative to a pairing.
    void
    addTarget(AggGT const& target, AggFr const& weight)
    {
        targetAccum_ = targetAccum_ * (target ^ weight.as_bigint());
    }

    // ONE final exponentiation over every accumulated Miller-loop term,
    // compared against the accumulated target product.
    bool
    verify() const
    {
        return Curve::final_exponentiation(millerAccum_) == targetAccum_;
    }

private:
    AggGT millerAccum_ = AggGT::one();
    AggGT targetAccum_ = AggGT::one();
};

AggG1
multiExpG1(std::vector<AggG1> const& base, std::vector<AggFr> const& coeffs)
{
    AggG1 acc = AggG1::zero();
    for (std::size_t i = 0; i < base.size(); ++i)
        acc = acc + coeffs[i] * base[i];
    return acc;
}

AggG2
multiExpG2(std::vector<AggG2> const& base, std::vector<AggFr> const& coeffs)
{
    AggG2 acc = AggG2::zero();
    for (std::size_t i = 0; i < base.size(); ++i)
        acc = acc + coeffs[i] * base[i];
    return acc;
}

// n must be a power of two; returns log2(n).
std::size_t
log2Exact(std::size_t n)
{
    if (n == 0 || (n & (n - 1)) != 0)
        throw std::runtime_error("ProofAggregator: N must be a power of two");
    std::size_t rounds = 0;
    while ((std::size_t(1) << rounds) < n)
        ++rounds;
    return rounds;
}

// Dense coefficients (length n) of PROD_{j=0}^{rounds-1} (1 + factor[j] *
// X^(2^j)), built by iterative in-place polynomial multiplication by each
// binomial factor (safe done high-to-low since poly[k-shift] hasn't been
// touched yet in the current pass).
std::vector<AggFr>
expandBinomialProduct(std::vector<AggFr> const& factors, std::size_t n)
{
    std::vector<AggFr> poly(n, AggFr::zero());
    poly[0] = AggFr::one();
    for (std::size_t j = 0; j < factors.size(); ++j)
    {
        std::size_t const shift = std::size_t(1) << j;
        AggFr const coeff = factors[j];
        for (std::size_t k = n; k-- > shift;)
            poly[k] = poly[k] + coeff * poly[k - shift];
    }
    return poly;
}

// Evaluates PROD_{j=0}^{rounds-1} (1 + factor[j] * z^(2^j)) directly at a
// point z, in O(rounds) = O(log N) field operations — used at verify time
// instead of expandBinomialProduct's O(N) coefficient expansion, since the
// verifier only ever needs f(z) (a single scalar), not f's full coefficient
// vector (that's only needed prover-side, to build a KZG opening).
AggFr
evalBinomialProduct(std::vector<AggFr> const& factors, AggFr const& z)
{
    AggFr result = AggFr::one();
    AggFr zPow2j = z;
    for (std::size_t j = 0; j < factors.size(); ++j)
    {
        result = result * (AggFr::one() + factors[j] * zPow2j);
        zPow2j = zPow2j * zPow2j;
    }
    return result;
}

// Synthetic division: given dense coefficients c[0..n-1] of f(X) (degree
// n-1) and a point z, returns the coefficients of q(X) = (f(X) - f(z)) /
// (X - z), a degree n-2 polynomial (length n-1). Standard technique since
// z is a root of f(X)-f(z) by construction.
std::vector<AggFr>
syntheticDivide(std::vector<AggFr> const& c, AggFr const& z)
{
    std::size_t const n = c.size();
    std::vector<AggFr> q(n - 1);
    q[n - 2] = c[n - 1];
    for (std::size_t i = n - 2; i-- > 0;)
        q[i] = c[i + 1] + z * q[i + 1];
    return q;
}

}  // namespace

// ---------------------------------------------------------------------------
// AggSRS
// ---------------------------------------------------------------------------

AggSRS
AggSRS::generate(std::size_t n)
{
    log2Exact(n);  // validates n is a power of two; throws otherwise

    AggFr const a = AggFr::random_element();
    AggFr const b = AggFr::random_element();

    AggSRS srs;
    srs.v1.resize(n);
    srs.v2.resize(n);
    srs.w1Low.resize(n);
    srs.w1.resize(n);
    srs.w2Low.resize(n);
    srs.w2.resize(n);

    AggFr aPow = AggFr::one();
    AggFr bPow = AggFr::one();
    for (std::size_t i = 0; i < n; ++i)
    {
        srs.v1[i] = aPow * AggG2::one();
        srs.v2[i] = bPow * AggG2::one();
        // w1Low/w2Low cover the SAME power range as v1/v2 (0..n-1), just in
        // G1 instead of G2 — needed for w1/w2's KZG opening quotient, which
        // (unlike w1/w2 themselves) is NOT confined to the shifted n..2n-1
        // range. Free to capture here since aPow/bPow already pass through
        // exactly these powers.
        srs.w1Low[i] = aPow * AggG1::one();
        srs.w2Low[i] = bPow * AggG1::one();
        aPow = aPow * a;
        bPow = bPow * b;
    }
    // aPow == a^n, bPow == b^n at this point.
    srs.vkA = a * AggG1::one();
    srs.vkB = b * AggG1::one();

    AggFr aShift = aPow;
    AggFr bShift = bPow;
    for (std::size_t i = 0; i < n; ++i)
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
    f << v1 << v2 << w1Low << w1 << w2Low << w2 << vkA << vkB;
}

AggSRS
AggSRS::load(std::string const& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.good())
        throw std::runtime_error("AggSRS::load: cannot open " + path);
    AggSRS srs;
    f >> srs.v1 >> srs.v2 >> srs.w1Low >> srs.w1 >> srs.w2Low >> srs.w2 >>
        srs.vkA >> srs.vkB;
    if (srs.v1.size() != srs.v2.size() || srs.v1.size() != srs.w1.size() ||
        srs.v1.size() != srs.w2.size() || srs.v1.size() != srs.w1Low.size() ||
        srs.v1.size() != srs.w2Low.size())
        throw std::runtime_error("AggSRS::load: size mismatch in " + path);
    log2Exact(srs.v1.size());
    return srs;
}

// ---------------------------------------------------------------------------
// AggregateProof (de)serialisation
//
// Custom fixed-width BINARY encoding — not libff's text-mode operator<</>>.
// Text mode writes every field element (Fq/Fq2/Fq6/Fq12 component) as an
// ASCII decimal string of the underlying ~254-bit integer (~77 characters),
// which is why the old format ran ~33KB for N=8: a GT (Fq12) element alone
// is 12 of those base-field components, and the proof carries 35 of them
// (5 top-level + 10 per GIPA round × log2(8)=3 rounds). Writing each base
// field element as its raw 32-byte limb representation instead — same
// value, no ASCII — cuts every element to well under half its text size
// (Fq: ~77 chars -> 32 bytes; GT: ~940 chars -> 384 bytes) with zero change
// to the cryptography. G1/G2 points are written with both affine
// coordinates (not compressed) to avoid re-deriving Y via sqrt() on
// read — the extra bytes that costs are negligible next to the GT savings,
// which is where nearly all the size lives.
// ---------------------------------------------------------------------------

namespace {

constexpr std::size_t kFqLimbs = libff::alt_bn128_Fq::num_limbs;
constexpr std::size_t kFqBytes = kFqLimbs * sizeof(mp_limb_t);

void
writeFq(std::vector<unsigned char>& out, libff::alt_bn128_Fq const& f)
{
    auto const b = f.as_bigint();
    auto const* p = reinterpret_cast<unsigned char const*>(b.data);
    out.insert(out.end(), p, p + kFqBytes);
}

libff::alt_bn128_Fq
readFq(unsigned char const*& p, unsigned char const* end)
{
    if (static_cast<std::size_t>(end - p) < kFqBytes)
        throw std::runtime_error("AggregateProof::deserialize: truncated Fq");
    libff::bigint<kFqLimbs> b;
    std::memcpy(b.data, p, kFqBytes);
    p += kFqBytes;
    return libff::alt_bn128_Fq(b);
}

void
writeFq2(std::vector<unsigned char>& out, libff::alt_bn128_Fq2 const& f)
{
    writeFq(out, f.c0);
    writeFq(out, f.c1);
}

libff::alt_bn128_Fq2
readFq2(unsigned char const*& p, unsigned char const* end)
{
    libff::alt_bn128_Fq2 r;
    r.c0 = readFq(p, end);
    r.c1 = readFq(p, end);
    return r;
}

void
writeFq6(std::vector<unsigned char>& out, libff::alt_bn128_Fq6 const& f)
{
    writeFq2(out, f.c0);
    writeFq2(out, f.c1);
    writeFq2(out, f.c2);
}

libff::alt_bn128_Fq6
readFq6(unsigned char const*& p, unsigned char const* end)
{
    libff::alt_bn128_Fq6 r;
    r.c0 = readFq2(p, end);
    r.c1 = readFq2(p, end);
    r.c2 = readFq2(p, end);
    return r;
}

void
writeGT(std::vector<unsigned char>& out, AggGT const& f)
{
    writeFq6(out, f.c0);
    writeFq6(out, f.c1);
}

AggGT
readGT(unsigned char const*& p, unsigned char const* end)
{
    AggGT r;
    r.c0 = readFq6(p, end);
    r.c1 = readFq6(p, end);
    return r;
}

void
writeG1(std::vector<unsigned char>& out, AggG1 const& g)
{
    AggG1 a(g);
    a.to_affine_coordinates();
    out.push_back(a.is_zero() ? 1 : 0);
    writeFq(out, a.X);
    writeFq(out, a.Y);
}

AggG1
readG1(unsigned char const*& p, unsigned char const* end)
{
    if (p >= end)
        throw std::runtime_error("AggregateProof::deserialize: truncated G1 flag");
    bool const isZero = (*p++ != 0);
    auto const x = readFq(p, end);
    auto const y = readFq(p, end);
    if (isZero)
        return AggG1::zero();
    AggG1 r;
    r.X = x;
    r.Y = y;
    r.Z = libff::alt_bn128_Fq::one();
    return r;
}

void
writeG2(std::vector<unsigned char>& out, AggG2 const& g)
{
    AggG2 a(g);
    a.to_affine_coordinates();
    out.push_back(a.is_zero() ? 1 : 0);
    writeFq2(out, a.X);
    writeFq2(out, a.Y);
}

AggG2
readG2(unsigned char const*& p, unsigned char const* end)
{
    if (p >= end)
        throw std::runtime_error("AggregateProof::deserialize: truncated G2 flag");
    bool const isZero = (*p++ != 0);
    auto const x = readFq2(p, end);
    auto const y = readFq2(p, end);
    if (isZero)
        return AggG2::zero();
    AggG2 r;
    r.X = x;
    r.Y = y;
    r.Z = libff::alt_bn128_Fq2::one();
    return r;
}

}  // namespace

std::vector<unsigned char>
AggregateProof::serialize() const
{
    std::vector<unsigned char> out;
    std::uint64_t const nRounds = rounds.size();
    auto const* np = reinterpret_cast<unsigned char const*>(&nRounds);
    out.insert(out.end(), np, np + sizeof(nRounds));

    writeGT(out, T_AB);
    writeGT(out, U_AB);
    writeGT(out, Z_AB);
    writeGT(out, T_C);
    writeGT(out, U_C);
    writeG1(out, Z_C);
    for (auto const& r : rounds)
    {
        writeGT(out, r.zL);
        writeGT(out, r.zR);
        writeGT(out, r.tL);
        writeGT(out, r.uL);
        writeGT(out, r.tR);
        writeGT(out, r.uR);
        writeG1(out, r.zL_C);
        writeG1(out, r.zR_C);
        writeGT(out, r.tL_C);
        writeGT(out, r.uL_C);
        writeGT(out, r.tR_C);
        writeGT(out, r.uR_C);
    }
    writeG1(out, finalA);
    writeG2(out, finalB);
    writeG1(out, finalC);
    writeG2(out, v1f);
    writeG2(out, v2f);
    writeG1(out, w1f);
    writeG1(out, w2f);
    writeG2(out, piV1);
    writeG2(out, piV2);
    writeG1(out, piW1);
    writeG1(out, piW2);
    return out;
}

AggregateProof
AggregateProof::deserialize(std::vector<unsigned char> const& bytes)
{
    unsigned char const* p = bytes.data();
    unsigned char const* const end = bytes.data() + bytes.size();

    if (static_cast<std::size_t>(end - p) < sizeof(std::uint64_t))
        throw std::runtime_error("AggregateProof::deserialize: truncated header");
    std::uint64_t nRounds = 0;
    std::memcpy(&nRounds, p, sizeof(nRounds));
    p += sizeof(nRounds);

    AggregateProof out;
    out.T_AB = readGT(p, end);
    out.U_AB = readGT(p, end);
    out.Z_AB = readGT(p, end);
    out.T_C = readGT(p, end);
    out.U_C = readGT(p, end);
    out.Z_C = readG1(p, end);
    out.rounds.resize(nRounds);
    for (auto& r : out.rounds)
    {
        r.zL = readGT(p, end);
        r.zR = readGT(p, end);
        r.tL = readGT(p, end);
        r.uL = readGT(p, end);
        r.tR = readGT(p, end);
        r.uR = readGT(p, end);
        r.zL_C = readG1(p, end);
        r.zR_C = readG1(p, end);
        r.tL_C = readGT(p, end);
        r.uL_C = readGT(p, end);
        r.tR_C = readGT(p, end);
        r.uR_C = readGT(p, end);
    }
    out.finalA = readG1(p, end);
    out.finalB = readG2(p, end);
    out.finalC = readG1(p, end);
    out.v1f = readG2(p, end);
    out.v2f = readG2(p, end);
    out.w1f = readG1(p, end);
    out.w2f = readG1(p, end);
    out.piV1 = readG2(p, end);
    out.piV2 = readG2(p, end);
    out.piW1 = readG1(p, end);
    out.piW2 = readG1(p, end);
    return out;
}

// ---------------------------------------------------------------------------
// ProofAggregator — SRS lifecycle
// ---------------------------------------------------------------------------

std::shared_ptr<AggSRS> ProofAggregator::srs_;
bool ProofAggregator::initialised_ = false;

std::string const&
ProofAggregator::defaultSrsPath()
{
    static std::string const path = "/tmp/rippled_rollup_agg_srs";
    return path;
}

void
ProofAggregator::initialize(std::string const& srsPath, std::size_t n)
{
    if (initialised_)
        return;

    std::ifstream probe(srsPath, std::ios::binary);
    if (probe.good())
    {
        probe.close();
        srs_ = std::make_shared<AggSRS>(AggSRS::load(srsPath));
        std::cout << "[ProofAggregator] Loaded aggregation SRS from "
                  << srsPath << " (N=" << srs_->n() << ")" << std::endl;
    }
    else
    {
        std::cout << "[ProofAggregator] No cached SRS at " << srsPath
                  << "; generating one (local toxic-waste setup, N=" << n
                  << ")..." << std::endl;
        srs_ = std::make_shared<AggSRS>(AggSRS::generate(n));
        srs_->save(srsPath);
        std::cout << "[ProofAggregator] Generated and saved aggregation SRS"
                  << std::endl;
    }
    initialised_ = true;
}

bool
ProofAggregator::isInitialized()
{
    return initialised_;
}

AggSRS const&
ProofAggregator::srs()
{
    if (!srs_)
        throw std::runtime_error(
            "ProofAggregator::srs: not initialised — call initialize() first");
    return *srs_;
}

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
    std::vector<RollupProofData> const& proofs)
{
    std::size_t const n = proofs.size();
    std::size_t const rounds_n = log2Exact(n);
    if (srs.n() != n)
        throw std::runtime_error("ProofAggregator::aggregate: SRS size != N");

    std::vector<AggG1> A(n), C(n);
    std::vector<AggG2> B(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        auto proof = RollupProver::deserializeProofPublic(proofs[i].proof_bytes);
        A[i] = proof.g_A;
        B[i] = proof.g_B;
        C[i] = proof.g_C;
    }

    std::vector<AggG2> const& v1 = srs.v1;
    std::vector<AggG2> const& v2 = srs.v2;
    std::vector<AggG1> const& w1 = srs.w1;
    std::vector<AggG1> const& w2 = srs.w2;

    // Initial commitments on the ORIGINAL (unscaled) A, B, C — bootstraps r
    // via Fiat-Shamir before any rescaling. T_AB/U_AB stay identical whether
    // computed pre- or post-rescaling (see memory note); T_C/U_C = CMs(v1,v2;C)
    // is MIPP's equivalent initial commitment.
    AggGT const T_AB = ipp(A, v1) * ipp(w1, B);
    AggGT const U_AB = ipp(A, v2) * ipp(w2, B);
    AggGT const T_C = ipp(C, v1);
    AggGT const U_C = ipp(C, v2);

    std::vector<unsigned char> hcomBytes;
    appendSerialized(hcomBytes, T_AB);
    appendSerialized(hcomBytes, U_AB);
    appendSerialized(hcomBytes, T_C);
    appendSerialized(hcomBytes, U_C);
    AggFr const hcom = hashToFr(hcomBytes);

    std::vector<unsigned char> rBytes;
    appendSerialized(rBytes, hcom);
    AggFr const r = hashToFr(rBytes);

    std::vector<AggFr> rPow(n);
    rPow[0] = AggFr::one();
    for (std::size_t i = 1; i < n; ++i)
        rPow[i] = rPow[i - 1] * r;

    // Rescale B -> B' = B^r and w1,w2 -> w'1,w'2 = w1^(1/r), w2^(1/r),
    // component-wise, once.
    std::vector<AggG2> Bp(n);
    std::vector<AggG1> w1p(n), w2p(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        Bp[i] = rPow[i] * B[i];
        AggFr const rInv = rPow[i].inverse();
        w1p[i] = rInv * w1[i];
        w2p[i] = rInv * w2[i];
    }

    AggGT const Z_AB = ipp(A, Bp);

    // MIPP's claimed value: Z_C = <C, r> = sum(r^i * C_i) — a G1
    // multi-exponentiation (NOT a pairing product like Z_AB). Computing
    // this here (prover side, O(N), paid once) and proving it via the
    // shared GIPA recursion below is what makes the VERIFIER's equivalent
    // check O(log N) instead of redoing this multiexp itself.
    AggG1 Z_C = AggG1::zero();
    for (std::size_t i = 0; i < n; ++i)
        Z_C = Z_C + rPow[i] * C[i];

    // x0 binds the first round's challenge to r and the claimed (Z_AB,Z_C)
    // values, so neither can be adjusted after the recursion begins.
    std::vector<unsigned char> x0Bytes;
    appendSerialized(x0Bytes, hcom);
    appendSerialized(x0Bytes, Z_AB);
    appendSerialized(x0Bytes, Z_C);
    AggFr const x0 = hashToFr(x0Bytes);

    std::vector<MtRound> rounds(rounds_n);
    std::vector<AggG1> curA = A, curC = C;
    std::vector<AggG2> curB = Bp;
    std::vector<AggG2> curV1 = v1, curV2 = v2;
    std::vector<AggG1> curW1 = w1p, curW2 = w2p;
    // r's own fold vector — starts as the full [r^0..r^(n-1)] and folds
    // with x^-1 each round (the same "opposite side" pattern B' uses,
    // since <C,r> plays the same structural role as <A,B'>). The verifier
    // never needs to track this explicitly — it recovers the final folded
    // scalar via a closed-form O(log N) product instead (see
    // verifyAggregate).
    std::vector<AggFr> curR = rPow;
    AggFr xPrev = x0;
    std::vector<AggFr> xs(rounds_n);

    std::size_t m = n;
    for (std::size_t round = 0; round < rounds_n; ++round)
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
        std::vector<AggG1> C_lo(curC.begin(), curC.begin() + mp);
        std::vector<AggG1> C_hi(curC.begin() + mp, curC.begin() + m);
        std::vector<AggFr> R_lo(curR.begin(), curR.begin() + mp);
        std::vector<AggFr> R_hi(curR.begin() + mp, curR.begin() + m);

        // TIPP cross terms — see the memory note for the index derivation
        // (zero-padded CMd expands to cross pairings between the "hi" half
        // of one vector and the "lo" half of the OTHER).
        AggGT const zL = ipp(A_hi, B_lo);
        AggGT const zR = ipp(A_lo, B_hi);
        AggGT const tL = ipp(A_hi, V1_lo) * ipp(W1_hi, B_lo);
        AggGT const uL = ipp(A_hi, V2_lo) * ipp(W2_hi, B_lo);
        AggGT const tR = ipp(A_lo, V1_hi) * ipp(W1_lo, B_hi);
        AggGT const uR = ipp(A_lo, V2_hi) * ipp(W2_lo, B_hi);

        // MIPP cross terms. zL_C/zR_C are G1 multiexps (<C,r> is a
        // multiexp, not a pairing product) — same hi/lo cross pattern as
        // TIPP's zL/zR. tL_C/uL_C/tR_C/uR_C ARE pairing-valued (CMs(v1,v2;C)
        // commits via pairings), same padding derivation as TIPP's
        // tL/uL/tR/uR with C standing in for A (and no B-side term, since
        // MIPP only commits one vector).
        AggG1 zL_C = AggG1::zero();
        for (std::size_t k = 0; k < mp; ++k)
            zL_C = zL_C + R_lo[k] * C_hi[k];
        AggG1 zR_C = AggG1::zero();
        for (std::size_t k = 0; k < mp; ++k)
            zR_C = zR_C + R_hi[k] * C_lo[k];
        AggGT const tL_C = ipp(C_hi, V1_lo);
        AggGT const uL_C = ipp(C_hi, V2_lo);
        AggGT const tR_C = ipp(C_lo, V1_hi);
        AggGT const uR_C = ipp(C_lo, V2_hi);

        std::vector<unsigned char> xb;
        appendSerialized(xb, xPrev);
        appendSerialized(xb, zL);
        appendSerialized(xb, zR);
        appendSerialized(xb, tL);
        appendSerialized(xb, uL);
        appendSerialized(xb, tR);
        appendSerialized(xb, uR);
        appendSerialized(xb, zL_C);
        appendSerialized(xb, zR_C);
        appendSerialized(xb, tL_C);
        appendSerialized(xb, uL_C);
        appendSerialized(xb, tR_C);
        appendSerialized(xb, uR_C);
        AggFr const x = hashToFr(xb);
        AggFr const xInv = x.inverse();
        xs[round] = x;

        std::vector<AggG1> newA(mp), newC(mp);
        std::vector<AggG2> newB(mp);
        std::vector<AggG2> newV1(mp), newV2(mp);
        std::vector<AggG1> newW1(mp), newW2(mp);
        std::vector<AggFr> newR(mp);
        for (std::size_t k = 0; k < mp; ++k)
        {
            newA[k] = A_lo[k] + x * A_hi[k];
            newC[k] = C_lo[k] + x * C_hi[k];
            newB[k] = B_lo[k] + xInv * B_hi[k];
            newV1[k] = V1_lo[k] + xInv * V1_hi[k];
            newV2[k] = V2_lo[k] + xInv * V2_hi[k];
            newW1[k] = W1_lo[k] + x * W1_hi[k];
            newW2[k] = W2_lo[k] + x * W2_hi[k];
            newR[k] = R_lo[k] + xInv * R_hi[k];
        }

        rounds[round] =
            MtRound{zL, zR, tL, uL, tR, uR, zL_C, zR_C, tL_C, uL_C, tR_C, uR_C};
        curA = std::move(newA);
        curC = std::move(newC);
        curB = std::move(newB);
        curV1 = std::move(newV1);
        curV2 = std::move(newV2);
        curW1 = std::move(newW1);
        curW2 = std::move(newW2);
        curR = std::move(newR);
        xPrev = x;
        m = mp;
    }

    // ---- KZG openings for the final commitment keys --------------------
    // v1f/v2f/w1f/w2f are free — already computed by the fold loop above.
    // Opening proofs certify each is correctly derived, so the verifier
    // trusts them via O(1)-ish pairing checks instead of an O(N) SRS
    // multiexp. See the header's KZG section for the group/verification-key
    // layout this follows.
    AggG2 const v1f = curV1[0];
    AggG2 const v2f = curV2[0];
    AggG1 const w1f = curW1[0];
    AggG1 const w2f = curW2[0];

    std::vector<unsigned char> zBytes;
    appendSerialized(zBytes, xs[rounds_n - 1]);
    appendSerialized(zBytes, v1f);
    appendSerialized(zBytes, v2f);
    appendSerialized(zBytes, w1f);
    appendSerialized(zBytes, w2f);
    AggFr const z = hashToFr(zBytes);

    // f_v's dense coefficients (length n; degree n-1) — same construction
    // used for the base-case check, now also feeding a KZG opening. q_v has
    // degree n-2, fitting entirely within v1/v2's own 0..n-1 SRS range.
    std::vector<AggFr> fvFactors(rounds_n);
    for (std::size_t j = 0; j < rounds_n; ++j)
        fvFactors[j] = xs[rounds_n - 1 - j].inverse();
    std::vector<AggFr> const fvCoeffs = expandBinomialProduct(fvFactors, n);
    std::vector<AggFr> const qV = syntheticDivide(fvCoeffs, z);
    AggG2 const piV1 = multiExpG2(
        std::vector<AggG2>(v1.begin(), v1.begin() + qV.size()), qV);
    AggG2 const piV2 = multiExpG2(
        std::vector<AggG2>(v2.begin(), v2.begin() + qV.size()), qV);

    // f_w's dense coefficients span the FULL 0..2n-1 range (low half all
    // zero — f_w(X) = X^n * g(X)). The quotient (f_w(X)-y)/(X-z) generally
    // has nonzero coefficients across that whole range even though f_w's
    // own low coefficients are zero, so it needs w1Low/w1 (resp. w2Low/w2)
    // concatenated together as its commitment key.
    std::vector<AggFr> fwFactors(rounds_n);
    AggFr const rInv = r.inverse();
    AggFr rInvPow = rInv;
    for (std::size_t j = 0; j < rounds_n; ++j)
    {
        fwFactors[j] = xs[rounds_n - 1 - j] * rInvPow;
        rInvPow = rInvPow * rInvPow;
    }
    std::vector<AggFr> const fwCoeffsHigh = expandBinomialProduct(fwFactors, n);
    std::vector<AggFr> fwCoeffsFull(2 * n, AggFr::zero());
    for (std::size_t i = 0; i < n; ++i)
        fwCoeffsFull[n + i] = fwCoeffsHigh[i];
    std::vector<AggFr> const qW = syntheticDivide(fwCoeffsFull, z);

    std::vector<AggG1> fullW1SRS(srs.w1Low);
    fullW1SRS.insert(fullW1SRS.end(), srs.w1.begin(), srs.w1.end());
    fullW1SRS.resize(qW.size());
    AggG1 const piW1 = multiExpG1(fullW1SRS, qW);

    std::vector<AggG1> fullW2SRS(srs.w2Low);
    fullW2SRS.insert(fullW2SRS.end(), srs.w2.begin(), srs.w2.end());
    fullW2SRS.resize(qW.size());
    AggG1 const piW2 = multiExpG1(fullW2SRS, qW);

    AggregateProof out;
    out.T_AB = T_AB;
    out.U_AB = U_AB;
    out.Z_AB = Z_AB;
    out.T_C = T_C;
    out.U_C = U_C;
    out.Z_C = Z_C;
    out.rounds = std::move(rounds);
    out.finalA = curA[0];
    out.finalB = curB[0];
    out.finalC = curC[0];
    out.v1f = v1f;
    out.v2f = v2f;
    out.w1f = w1f;
    out.w2f = w2f;
    out.piV1 = piV1;
    out.piV2 = piV2;
    out.piW1 = piW1;
    out.piW2 = piW2;
    return out;
}

bool
ProofAggregator::verifyAggregate(
    AggSRS const& srs,
    AggregateProof const& agg,
    std::vector<RollupProofData> const& proofs)
{
    bool const timing = std::getenv("PROOF_AGGREGATOR_TIMING") != nullptr;
    auto const t0 = std::chrono::steady_clock::now();

    std::size_t const n = proofs.size();
    std::size_t const rounds_n = log2Exact(n);
    if (srs.n() != n)
        throw std::runtime_error(
            "ProofAggregator::verifyAggregate: SRS size != N");
    if (agg.rounds.size() != rounds_n)
        return false;

    auto const& vk = RollupProver::verificationKey();

    // Reconstruct r and x0 exactly as aggregate() derived them.
    std::vector<unsigned char> hcomBytes;
    appendSerialized(hcomBytes, agg.T_AB);
    appendSerialized(hcomBytes, agg.U_AB);
    appendSerialized(hcomBytes, agg.T_C);
    appendSerialized(hcomBytes, agg.U_C);
    AggFr const hcom = hashToFr(hcomBytes);

    std::vector<unsigned char> rBytes;
    appendSerialized(rBytes, hcom);
    AggFr const r = hashToFr(rBytes);

    std::vector<AggFr> rPow(n);
    rPow[0] = AggFr::one();
    for (std::size_t i = 1; i < n; ++i)
        rPow[i] = rPow[i - 1] * r;

    std::vector<unsigned char> x0Bytes;
    appendSerialized(x0Bytes, hcom);
    appendSerialized(x0Bytes, agg.Z_AB);
    appendSerialized(x0Bytes, agg.Z_C);
    AggFr const x0 = hashToFr(x0Bytes);

    // Reconstruct round challenges and fold (Z,T,U) for BOTH TIPP and MIPP
    // alongside them — one shared challenge per round. Zc_C folds with G1
    // scalar multiplication (it's a multiexp result, not a pairing value);
    // Tc_C/Uc_C fold with GT exponentiation exactly like TIPP's Tc/Uc.
    AggGT Zc = agg.Z_AB, Tc = agg.T_AB, Uc = agg.U_AB;
    AggG1 Zc_C = agg.Z_C;
    AggGT Tc_C = agg.T_C, Uc_C = agg.U_C;
    AggFr xPrev = x0;
    std::vector<AggFr> xs(rounds_n);
    for (std::size_t round = 0; round < rounds_n; ++round)
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
        appendSerialized(xb, rd.zL_C);
        appendSerialized(xb, rd.zR_C);
        appendSerialized(xb, rd.tL_C);
        appendSerialized(xb, rd.uL_C);
        appendSerialized(xb, rd.tR_C);
        appendSerialized(xb, rd.uR_C);
        AggFr const x = hashToFr(xb);
        AggFr const xInv = x.inverse();
        xs[round] = x;

        Zc = (rd.zL ^ x.as_bigint()) * Zc * (rd.zR ^ xInv.as_bigint());
        Tc = (rd.tL ^ x.as_bigint()) * Tc * (rd.tR ^ xInv.as_bigint());
        Uc = (rd.uL ^ x.as_bigint()) * Uc * (rd.uR ^ xInv.as_bigint());

        Zc_C = x * rd.zL_C + Zc_C + xInv * rd.zR_C;
        Tc_C = (rd.tL_C ^ x.as_bigint()) * Tc_C * (rd.tR_C ^ xInv.as_bigint());
        Uc_C = (rd.uL_C ^ x.as_bigint()) * Uc_C * (rd.uR_C ^ xInv.as_bigint());

        xPrev = x;
    }

    auto const t1 = std::chrono::steady_clock::now();

    // All remaining pairing checks (TIPP base case, TIPP final-key checks,
    // MIPP final-key checks, final combined Groth16-style equation) are
    // batched into ONE combined pairing check below instead of being
    // verified with individual reduced_pairing calls — see
    // BatchedPairingCheck's doc comment.
    BatchedPairingCheck batch;

    // TIPP base case: Zc must equal the direct pairing on finalA, finalB.
    AggFr const rho1 = AggFr::random_element();
    batch.addTerm(agg.finalA, agg.finalB, rho1);
    batch.addTarget(Zc, rho1);

    // MIPP base case: Zc_C must equal finalC scaled by the closed-form
    // folded r value r' = f_v(r) — a DIRECT G1 comparison, no pairing at
    // all, computed by evaluating the SAME product-form polynomial that
    // governs v1/v2's folding (see below) at the point X=r, in O(log N)
    // scalar multiplications instead of the O(N) direct multiexp an
    // earlier version of this file used for Z_C entirely.
    AggFr rPrime = AggFr::one();
    {
        AggFr rPow2j = r;
        for (std::size_t j = 0; j < rounds_n; ++j)
        {
            AggFr const xInvHere = xs[rounds_n - 1 - j].inverse();
            rPrime = rPrime * (AggFr::one() + xInvHere * rPow2j);
            rPow2j = rPow2j * rPow2j;
        }
    }
    if (Zc_C != rPrime * agg.finalC)
        return false;

    // Final commitment keys come DIRECTLY from the proof now (agg.v1f etc)
    // instead of an O(N) SRS multiexp — KZG opening proofs (below) are what
    // let the verifier trust them anyway. f_v/f_w's FACTOR lists (not their
    // expanded coefficients — no O(N) expansion needed at verify time) are
    // still needed to evaluate y_v=f_v(z), y_w=f_w(z) via evalBinomialProduct,
    // O(log N). Note r' above (the MIPP base case) is exactly f_v(r), the
    // same polynomial evaluated at a different point.
    std::vector<AggFr> fvFactors(rounds_n);
    for (std::size_t j = 0; j < rounds_n; ++j)
        fvFactors[j] = xs[rounds_n - 1 - j].inverse();

    std::vector<AggFr> fwFactors(rounds_n);
    AggFr const rInv = r.inverse();
    AggFr rInvPow = rInv;
    for (std::size_t j = 0; j < rounds_n; ++j)
    {
        fwFactors[j] = xs[rounds_n - 1 - j] * rInvPow;
        rInvPow = rInvPow * rInvPow;
    }

    AggG2 const v1f = agg.v1f;
    AggG2 const v2f = agg.v2f;
    AggG1 const w1f = agg.w1f;
    AggG1 const w2f = agg.w2f;

    AggFr const rho2 = AggFr::random_element();
    batch.addTerm(agg.finalA, v1f, rho2);
    batch.addTerm(w1f, agg.finalB, rho2);
    batch.addTarget(Tc, rho2);

    AggFr const rho3 = AggFr::random_element();
    batch.addTerm(agg.finalA, v2f, rho3);
    batch.addTerm(w2f, agg.finalB, rho3);
    batch.addTarget(Uc, rho3);

    // MIPP final-key checks: Tc_C =? e(finalC,v1f), Uc_C =? e(finalC,v2f) —
    // reuse the SAME v1f/v2f (MIPP shares TIPP's v1,v2 keys).
    AggFr const rho5 = AggFr::random_element();
    batch.addTerm(agg.finalC, v1f, rho5);
    batch.addTarget(Tc_C, rho5);

    AggFr const rho6 = AggFr::random_element();
    batch.addTerm(agg.finalC, v2f, rho6);
    batch.addTarget(Uc_C, rho6);

    // ---- KZG opening checks for v1f, v2f, w1f, w2f ---------------------
    // Recompute the KZG challenge z exactly as aggregate() derived it, and
    // y_v=f_v(z), y_w=f_w(z) — O(log N) via evalBinomialProduct, not the
    // O(N) expandBinomialProduct used to actually BUILD the polynomial
    // (prover-side only, in aggregate()).
    std::vector<unsigned char> zBytes;
    appendSerialized(zBytes, xs[rounds_n - 1]);
    appendSerialized(zBytes, v1f);
    appendSerialized(zBytes, v2f);
    appendSerialized(zBytes, w1f);
    appendSerialized(zBytes, w2f);
    AggFr const z = hashToFr(zBytes);

    AggFr const yV = evalBinomialProduct(fvFactors, z);
    AggFr zPowN = z;
    for (std::size_t j = 0; j < rounds_n; ++j)
        zPowN = zPowN * zPowN;
    AggFr const yW = zPowN * evalBinomialProduct(fwFactors, z);

    AggG1 const g = AggG1::one();
    AggG2 const h = AggG2::one();

    // v1: e(g, v1f - yV*h) =? e(vkA - z*g, piV1)
    AggFr const rhoKzgV1 = AggFr::random_element();
    batch.addTerm(g, v1f - yV * h, rhoKzgV1);
    batch.addTerm(srs.vkA - z * g, agg.piV1, AggFr::zero() - rhoKzgV1);

    // v2: e(g, v2f - yV*h) =? e(vkB - z*g, piV2)
    AggFr const rhoKzgV2 = AggFr::random_element();
    batch.addTerm(g, v2f - yV * h, rhoKzgV2);
    batch.addTerm(srs.vkB - z * g, agg.piV2, AggFr::zero() - rhoKzgV2);

    // w1: e(w1f - yW*g, h) =? e(piW1, v1[1] - z*h)   [v1[1] = h^a]
    AggFr const rhoKzgW1 = AggFr::random_element();
    batch.addTerm(w1f - yW * g, h, rhoKzgW1);
    batch.addTerm(agg.piW1, srs.v1[1] - z * h, AggFr::zero() - rhoKzgW1);

    // w2: e(w2f - yW*g, h) =? e(piW2, v2[1] - z*h)   [v2[1] = h^b]
    AggFr const rhoKzgW2 = AggFr::random_element();
    batch.addTerm(w2f - yW * g, h, rhoKzgW2);
    batch.addTerm(agg.piW2, srs.v2[1] - z * h, AggFr::zero() - rhoKzgW2);

    auto const t2 = std::chrono::steady_clock::now();

    // Public-input accumulation vk_x_agg = sum(r^i * vk_x_i) stays a direct
    // O(N) computation by DESIGN, matching real SnarkPack (see header doc)
    // — it's cheap (no pairings, no proof deserialisation: just each
    // proof's 5 already-public FieldT inputs and a small IC accumulation).
    // Z_C is no longer computed here at all — MIPP above proves it.
    AggG1 vkXAgg = AggG1::zero();
    for (std::size_t i = 0; i < n; ++i)
    {
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
    for (std::size_t i = 0; i < n; ++i)
        sumR = sumR + rPow[i];

    // Z_AB = alpha_beta^sumR * e(vkXAgg,gamma) * e(Z_C,delta) — the
    // aggregated Groth16 verification equation — rearranged so the pairing
    // terms equal Z_AB * (alpha_beta^sumR)^-1. Uses agg.Z_C (MIPP-verified
    // above), not a directly recomputed value.
    AggFr const rho4 = AggFr::random_element();
    batch.addTerm(vkXAgg, vk.gamma_g2, rho4);
    batch.addTerm(agg.Z_C, vk.delta_g2, rho4);
    batch.addTarget(agg.Z_AB, rho4);
    batch.addTarget((vk.alpha_g1_beta_g2 ^ sumR.as_bigint()).inverse(), rho4);

    auto const t3 = std::chrono::steady_clock::now();

    // All equations above collapse into ONE combined Miller-loop product
    // and ONE final exponentiation here.
    bool const ok = batch.verify();

    if (timing)
    {
        auto const t4 = std::chrono::steady_clock::now();
        auto ms = [](auto a, auto b) {
            return std::chrono::duration_cast<std::chrono::microseconds>(b - a)
                .count();
        };
        std::cerr << "[ProofAggregator::verifyAggregate timing] n=" << n
                  << " round_fold=" << ms(t0, t1) << "us"
                  << " final_key_setup=" << ms(t1, t2) << "us"
                  << " vkX_loop=" << ms(t2, t3) << "us"
                  << " batch.verify=" << ms(t3, t4) << "us"
                  << " total=" << ms(t0, t4) << "us\n";
    }

    return ok;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
