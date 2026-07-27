// bench_proof_aggregator — Stage A benchmark for Track 1 proof aggregation.
//
// Generates N REAL Track 1 Groth16 proofs (same PoseidonCircuit, same
// RollupProver::createProof path gen_batch_blob uses for a genesis deposit
// batch), aggregates them via ProofAggregator (SnarkPack-style TIPP/GIPA —
// see ProofAggregator.h for the exact construction and its N=8-era scoping
// simplifications, which now apply at any N), verifies the aggregate, and
// times every step. N is a runtime CLI argument specifically so the real
// crossover-vs-Track-1 point can be MEASURED at N=16/32/64/128 rather than
// projected analytically — see the track1-aggregation-snarkpack memory note
// for why a naive O(log N) projection was not trustworthy enough to report
// without measuring (the implementation's deliberate MIPP/KZG-opening
// simplifications mean verify time is NOT actually O(log N) end-to-end).
//
// Usage: bench_proof_aggregator [N] [--tamper]
//   N          batch size, must be a power of two (default 8)
//   --tamper   after producing a valid aggregate proof, corrupt one field
//              and confirm verifyAggregate correctly rejects it.
//
// NOTE: N here is independent of Track 1's on-chain kRollupBatchSize=8
// convention — this tool tests the aggregation SCHEME at various N,
// simulating "what if a sequencer aggregated N off-chain proofs before
// touching L1" rather than today's fixed 8-proof blob.

#include <libxrpl/zkp/rollup/PoseidonHash.h>
#include <libxrpl/zkp/rollup/ProofAggregator.h>
#include <libxrpl/zkp/rollup/RollupMerkleTree.h>
#include <libxrpl/zkp/rollup/RollupNote.h>
#include <libxrpl/zkp/rollup/RollupProver.h>
#include <libxrpl/zkp/rollup/RollupState.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace ripple;
using namespace ripple::zkp;
using namespace ripple::zkp::rollup;

namespace {

std::vector<FieldT>
toFieldVec(std::vector<uint256> const& v)
{
    std::vector<FieldT> out;
    out.reserve(v.size());
    for (auto const& u : v)
        out.push_back(PoseidonHash::uint256ToField(u));
    return out;
}

std::vector<bool>
leafPosBits(std::size_t pos, std::size_t depth)
{
    std::vector<bool> bits(depth, false);
    for (std::size_t b = 0; b < depth; ++b)
        bits[b] = (pos >> b) & 1u;
    return bits;
}

std::vector<RollupNote>
buildGenesisNotes(std::size_t n)
{
    std::vector<RollupNote> notes(n);
    for (std::size_t i = 0; i < n; ++i)
        notes[i] = RollupNote::createRandom(0, static_cast<std::uint64_t>(i));
    return notes;
}

std::vector<RollupNote>
buildBatchNotes(
    std::uint32_t batchId,
    std::uint64_t valueBase,
    std::vector<RollupNote> const& genesisNotes)
{
    std::size_t const n = genesisNotes.size();
    std::vector<RollupNote> notes(n);
    std::uint64_t const seedBase = static_cast<std::uint64_t>(batchId) *
        static_cast<std::uint64_t>(n) * 2;
    for (std::size_t i = 0; i < n; ++i)
    {
        notes[i] = RollupNote::createRandom(valueBase, seedBase + i);
        notes[i].ask = genesisNotes[i].ask;
        notes[i].apk = genesisNotes[i].apk;
    }
    return notes;
}

template <typename Fn>
long long
timeMs(Fn&& fn)
{
    auto const start = std::chrono::steady_clock::now();
    fn();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start)
        .count();
}

bool
isPowerOfTwo(std::size_t n)
{
    return n != 0 && (n & (n - 1)) == 0;
}

}  // namespace

int
main(int argc, char** argv)
{
    std::size_t n = 8;
    bool tamper = false;
    for (int i = 1; i < argc; ++i)
    {
        if (std::strcmp(argv[i], "--tamper") == 0)
            tamper = true;
        else
            n = static_cast<std::size_t>(std::stoul(argv[i]));
    }
    if (!isPowerOfTwo(n))
    {
        std::cerr << "N must be a power of two, got " << n << "\n";
        return 1;
    }
    if (n > (std::size_t(1) << kRollupTreeDepth))
    {
        std::cerr << "N exceeds tree capacity (depth " << (int)kRollupTreeDepth
                  << ")\n";
        return 1;
    }

    std::cerr << "[bench_proof_aggregator] N=" << n
              << " initialising RollupProver (loading keys)...\n";
    RollupProver::initialize();
    std::cerr << "[bench_proof_aggregator] keys loaded ("
              << RollupProver::constraintCount() << " constraints)\n";

    // Build a genesis deposit batch of size N.
    auto const genesisNotes = buildGenesisNotes(n);
    auto const oldNotes = genesisNotes;
    auto const newNotes = buildBatchNotes(1, 20'000'000ull, genesisNotes);

    RollupMerkleTree oldTree(kRollupTreeDepth);
    for (std::size_t i = 0; i < n; ++i)
        oldTree.append(PoseidonHash::fieldToUint256(genesisNotes[i].commitment()));
    uint256 const prevRoot = oldTree.root();

    RollupMerkleTree newTree(kRollupTreeDepth);
    for (std::size_t i = 0; i < n; ++i)
        newTree.append(PoseidonHash::fieldToUint256(genesisNotes[i].commitment()));
    for (std::size_t i = 0; i < n; ++i)
        newTree.update_leaf(i, PoseidonHash::fieldToUint256(newNotes[i].commitment()));

    FieldT const prevRootF = PoseidonHash::uint256ToField(prevRoot);
    FieldT const newRootF = PoseidonHash::uint256ToField(newTree.root());

    std::cerr << "[bench_proof_aggregator] generating " << n
              << " real Track 1 Groth16 proofs...\n";
    std::vector<RollupProofData> proofs(n);
    long long totalProveMs = 0;
    for (std::size_t i = 0; i < n; ++i)
    {
        auto const leafBits = leafPosBits(i, kRollupTreeDepth);
        auto const authOld = toFieldVec(oldTree.authPath(i));
        auto const authNew = toFieldVec(newTree.authPath(i));

        long long ms = timeMs([&] {
            proofs[i] = RollupProver::createProof(
                oldNotes[i],
                newNotes[i],
                leafBits,
                authOld,
                authNew,
                prevRootF,
                newRootF,
                false);
        });
        totalProveMs += ms;
    }
    std::cerr << "[bench_proof_aggregator] total per-user proving: "
              << totalProveMs << " ms (sum of " << n
              << " independent, parallelisable proofs; mean "
              << (totalProveMs / static_cast<long long>(n)) << " ms/proof)\n";

    // ── SRS setup (one-time, not part of the per-batch latency figure) ────
    AggSRS srs;
    long long const srsGenMs = timeMs([&] { srs = AggSRS::generate(n); });
    std::cerr << "[bench_proof_aggregator] AggSRS::generate: " << srsGenMs
              << " ms (one-time, analogous to Groth16 trusted setup)\n";

    // ── Aggregate ───────────────────────────────────────────────────────
    AggregateProof agg;
    long long const aggMs = timeMs([&] { agg = ProofAggregator::aggregate(srs, proofs); });
    std::cerr << "[bench_proof_aggregator] ProofAggregator::aggregate: "
              << aggMs << " ms (N=" << n << ")\n";

    auto const wireBytes = agg.serialize();
    std::cerr << "[bench_proof_aggregator] aggregate proof size: "
              << wireBytes.size() << " bytes (vs Track 1 today: "
              << (n * 192) << " B padded on-chain slots, "
              << "~" << (n * 137) << " B raw Groth16 proof bytes)\n";

    // ── Verify ──────────────────────────────────────────────────────────
    bool verifyOk = false;
    long long const verifyMs = timeMs([&] {
        verifyOk = ProofAggregator::verifyAggregate(srs, agg, proofs);
    });
    std::cerr << "[bench_proof_aggregator] ProofAggregator::verifyAggregate: "
              << verifyMs << " ms -> " << (verifyOk ? "PASS" : "FAIL") << "\n";

    if (!verifyOk)
    {
        std::cerr << "[bench_proof_aggregator] FATAL: valid aggregate proof "
                     "failed to verify\n";
        return 1;
    }

    if (tamper)
    {
        AggregateProof bad = agg;
        bad.Z_AB = bad.Z_AB * bad.Z_AB;
        bool const badOk = ProofAggregator::verifyAggregate(srs, bad, proofs);
        std::cerr << "[bench_proof_aggregator] tamper test (corrupted Z_AB): "
                  << (badOk ? "FAIL (accepted a bad proof!)" : "PASS (rejected)")
                  << "\n";
        if (badOk)
            return 1;

        std::vector<RollupProofData> badProofs = proofs;
        badProofs[0].value_pub = badProofs[0].value_pub + FieldT::one();
        bool const badPub = ProofAggregator::verifyAggregate(srs, agg, badProofs);
        std::cerr << "[bench_proof_aggregator] tamper test (corrupted public "
                     "input): "
                  << (badPub ? "FAIL (accepted a bad proof!)" : "PASS (rejected)")
                  << "\n";
        if (badPub)
            return 1;
    }

    // Machine-parseable summary line for scripted sweeps across N.
    std::cout << "RESULT n=" << n << " prove_sum_ms=" << totalProveMs
              << " prove_mean_ms=" << (totalProveMs / static_cast<long long>(n))
              << " aggregate_ms=" << aggMs << " verify_ms=" << verifyMs
              << " proof_bytes=" << wireBytes.size()
              << " track1_raw_bytes=" << (n * 137)
              << " track1_padded_bytes=" << (n * 192) << "\n";
    return 0;
}
