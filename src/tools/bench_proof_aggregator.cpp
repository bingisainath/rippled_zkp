// bench_proof_aggregator — Stage A benchmark for Track 1 proof aggregation.
//
// Generates kBatchSize=8 REAL Track 1 Groth16 proofs (same PoseidonCircuit,
// same RollupProver::createProof path gen_batch_blob uses for a genesis
// deposit batch), aggregates them via ProofAggregator (SnarkPack-style
// TIPP/GIPA — see ProofAggregator.h for the exact construction and the
// N=8-specific simplifications), verifies the aggregate, and times every
// step. This is the tool that produces the real N=8 latency/size numbers
// for the dissertation — see the track1-aggregation-snarkpack memory note
// for why full aggregation is expected to lose to today's Track 1 at N=8
// (SnarkPack's own published crossover is ~32 proofs for verify time, ~150
// for proof size) and why building/measuring it here is still the right
// call (a real N=8 data point to project the curve from).
//
// Usage: bench_proof_aggregator [--tamper]
//   --tamper   after producing a valid aggregate proof, corrupt one field
//              and confirm verifyAggregate correctly rejects it.

#include <libxrpl/zkp/rollup/PoseidonHash.h>
#include <libxrpl/zkp/rollup/ProofAggregator.h>
#include <libxrpl/zkp/rollup/RollupMerkleTree.h>
#include <libxrpl/zkp/rollup/RollupNote.h>
#include <libxrpl/zkp/rollup/RollupProver.h>
#include <libxrpl/zkp/rollup/RollupState.h>

#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>

using namespace ripple;
using namespace ripple::zkp;
using namespace ripple::zkp::rollup;

namespace {

constexpr std::size_t kBatchSize = kRollupBatchSize;

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

std::array<RollupNote, kBatchSize>
buildGenesisNotes()
{
    std::array<RollupNote, kBatchSize> notes;
    for (std::size_t i = 0; i < kBatchSize; ++i)
        notes[i] = RollupNote::createRandom(0, static_cast<std::uint64_t>(i));
    return notes;
}

std::array<RollupNote, kBatchSize>
buildBatchNotes(
    std::uint32_t batchId,
    std::uint64_t valueBase,
    std::array<RollupNote, kBatchSize> const& genesisNotes)
{
    std::array<RollupNote, kBatchSize> notes;
    std::uint64_t const seedBase = static_cast<std::uint64_t>(batchId) * 200;
    for (std::size_t i = 0; i < kBatchSize; ++i)
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

}  // namespace

int
main(int argc, char** argv)
{
    bool tamper = false;
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], "--tamper") == 0)
            tamper = true;

    std::cerr << "[bench_proof_aggregator] initialising RollupProver "
                 "(loading keys)...\n";
    RollupProver::initialize();
    std::cerr << "[bench_proof_aggregator] keys loaded ("
              << RollupProver::constraintCount() << " constraints)\n";

    // Build a genesis deposit batch (batchId=1, all 8 deposits) — same
    // convention as gen_batch_blob's default path.
    auto const genesisNotes = buildGenesisNotes();
    auto const oldNotes = genesisNotes;
    auto const newNotes = buildBatchNotes(1, 20'000'000ull, genesisNotes);

    RollupMerkleTree oldTree(kRollupTreeDepth);
    for (std::size_t i = 0; i < kBatchSize; ++i)
        oldTree.append(PoseidonHash::fieldToUint256(genesisNotes[i].commitment()));
    uint256 const prevRoot = oldTree.root();

    RollupMerkleTree newTree(kRollupTreeDepth);
    for (std::size_t i = 0; i < kBatchSize; ++i)
        newTree.append(PoseidonHash::fieldToUint256(genesisNotes[i].commitment()));
    for (std::size_t i = 0; i < kBatchSize; ++i)
        newTree.update_leaf(i, PoseidonHash::fieldToUint256(newNotes[i].commitment()));

    FieldT const prevRootF = PoseidonHash::uint256ToField(prevRoot);
    FieldT const newRootF = PoseidonHash::uint256ToField(newTree.root());

    std::cerr << "[bench_proof_aggregator] generating " << kBatchSize
              << " real Track 1 Groth16 proofs...\n";
    std::array<RollupProofData, kBatchSize> proofs;
    long long totalProveMs = 0;
    for (std::size_t i = 0; i < kBatchSize; ++i)
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
        std::cerr << "  entry " << i << " createProof: " << ms << " ms\n";
    }
    std::cerr << "[bench_proof_aggregator] total per-user proving: "
              << totalProveMs << " ms (sum of " << kBatchSize
              << " independent, parallelisable proofs)\n";

    // ── SRS setup (one-time, not part of the per-batch latency figure) ────
    AggSRS srs;
    long long const srsGenMs = timeMs([&] { srs = AggSRS::generate(); });
    std::cerr << "[bench_proof_aggregator] AggSRS::generate: " << srsGenMs
              << " ms (one-time, analogous to Groth16 trusted setup)\n";

    // ── Aggregate ───────────────────────────────────────────────────────
    AggregateProof agg;
    long long const aggMs = timeMs([&] { agg = ProofAggregator::aggregate(srs, proofs); });
    std::cerr << "[bench_proof_aggregator] ProofAggregator::aggregate: "
              << aggMs << " ms (N=" << kBatchSize << ")\n";

    auto const wireBytes = agg.serialize();
    std::cerr << "[bench_proof_aggregator] aggregate proof size: "
              << wireBytes.size() << " bytes (vs Track 1 today: "
              << (kBatchSize * 192) << " B padded on-chain slots, "
              << "~" << (kBatchSize * 137) << " B raw Groth16 proof bytes)\n";

    // ── Verify ──────────────────────────────────────────────────────────
    bool verifyOk = false;
    long long const verifyMs = timeMs([&] {
        verifyOk = ProofAggregator::verifyAggregate(srs, agg, proofs);
    });
    std::cerr << "[bench_proof_aggregator] ProofAggregator::verifyAggregate: "
              << verifyMs << " ms -> " << (verifyOk ? "PASS" : "FAIL")
              << " (vs Track 1 today: ~" << (kBatchSize) << " x per-proof "
              << "verify, measured separately via gen_batch_blob)\n";

    if (!verifyOk)
    {
        std::cerr << "[bench_proof_aggregator] FATAL: valid aggregate proof "
                     "failed to verify\n";
        return 1;
    }

    if (tamper)
    {
        AggregateProof bad = agg;
        bad.Z_AB = bad.Z_AB * bad.Z_AB;  // corrupt the claimed inner pairing product
        bool const badOk = ProofAggregator::verifyAggregate(srs, bad, proofs);
        std::cerr << "[bench_proof_aggregator] tamper test (corrupted Z_AB): "
                  << (badOk ? "FAIL (accepted a bad proof!)" : "PASS (rejected)")
                  << "\n";
        if (badOk)
            return 1;

        std::array<RollupProofData, kBatchSize> badProofs = proofs;
        badProofs[0].value_pub = badProofs[0].value_pub + FieldT::one();
        bool const badPub = ProofAggregator::verifyAggregate(srs, agg, badProofs);
        std::cerr << "[bench_proof_aggregator] tamper test (corrupted public "
                     "input): "
                  << (badPub ? "FAIL (accepted a bad proof!)" : "PASS (rejected)")
                  << "\n";
        if (badPub)
            return 1;
    }

    std::cerr << "[bench_proof_aggregator] SUMMARY (N=" << kBatchSize << "):\n"
              << "  per-user prove (sum, parallelisable): " << totalProveMs
              << " ms\n"
              << "  aggregate (sequencer-side, one-time SRS excluded): "
              << aggMs << " ms\n"
              << "  aggregate verify (L1-side): " << verifyMs << " ms\n"
              << "  aggregate proof bytes: " << wireBytes.size() << " B\n";
    return 0;
}
