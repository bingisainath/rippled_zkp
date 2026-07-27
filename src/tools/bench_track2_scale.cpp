// bench_track2_scale — Track 2 (monolithic batch circuit) at N != 8.
//
// BatchCircuitProver/BatchCircuit already take batch_size as a runtime
// constructor parameter (BatchCircuitProver.h) — RollupSequencer2 is what
// hardcodes BATCH2_SIZE=8, not the circuit/prover themselves. This tool
// bypasses RollupSequencer2 and drives BatchCircuitProver directly with an
// arbitrary N, building an all-NoOp batch (same construction
// RollupSequencer2::buildBatch uses for its NoOp padding — see
// RollupSequencer2.cpp:161,313-333) against a fresh AccountTree. Per
// [[phase7-benchmarks]], prove time is content-independent (a NoOp-only
// batch costs the same as a full deposit batch of the same N), so this is a
// legitimate way to measure the circuit's N-scaling without needing N real
// signed deposits.
//
// Each N needs its OWN Groth16 trusted setup (constraint count scales with
// N) — this tool always keygens fresh at a per-N key path
// (/tmp/bench_track2_keys_n<N>_*) rather than touching the production
// /tmp/rippled_rollup_batch_keys_* keys gen_batch_blob2 uses.
//
// Usage: bench_track2_scale N   (N a positive integer, not required to be a
//                                 power of two — BatchCircuit has no such
//                                 constraint, unlike ProofAggregator's GIPA)

#include <libxrpl/zkp/rollup/AccountLeaf.h>
#include <libxrpl/zkp/rollup/AccountTree.h>
#include <libxrpl/zkp/rollup/BabyJubjub.h>
#include <libxrpl/zkp/rollup/BatchCircuitProver.h>
#include <libxrpl/zkp/rollup/PoseidonHash.h>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using namespace ripple;
using namespace ripple::zkp;
using namespace ripple::zkp::rollup;

namespace {

constexpr std::size_t kDepth = 16;

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
    if (argc < 2)
    {
        std::cerr << "usage: bench_track2_scale N\n";
        return 1;
    }
    libff::alt_bn128_pp::init_public_params();
    BabyJubjub::initialize();
    PoseidonHash::initialize();

    std::size_t const n = static_cast<std::size_t>(std::stoul(argv[1]));
    std::size_t const padIndexBase = std::size_t{1} << (kDepth - 1);
    if (padIndexBase + n > (std::size_t{1} << kDepth))
    {
        std::cerr << "N too large for tree depth " << kDepth << "\n";
        return 1;
    }

    AccountTree tree(kDepth);
    FieldT const prevRootF = tree.root();

    std::vector<BatchEntryWitness> entries;
    entries.reserve(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        std::size_t const padIndex = padIndexBase + i;
        FieldT const padAsk =
            FieldT("31337") + FieldT(static_cast<std::uint64_t>(i));
        auto padReq = SignedRequest::make(
            padAsk, FieldT::zero(), 0, 0, RequestType::NoOp);

        BatchEntryWitness ew;
        ew.req = padReq;
        ew.old_balance = 0;
        ew.is_create = true;
        ew.leaf_pos = tree.posBits(padIndex);
        ew.auth_path = tree.authPath(padIndex);
        entries.push_back(ew);
    }

    std::string const keyPath =
        "/tmp/bench_track2_keys_n" + std::to_string(n);

    std::cerr << "[bench_track2_scale] N=" << n
              << " initialising BatchCircuitProver (key path " << keyPath
              << ")...\n";
    long long const initMs = timeMs([&] {
        BatchCircuitProver::initialize(keyPath, n, kDepth);
    });
    std::cerr << "[bench_track2_scale] initialize (keygen if first run): "
              << initMs << " ms, " << BatchCircuitProver::constraintCount()
              << " constraints\n";

    BatchProofData pd;
    long long const proveMs = timeMs([&] {
        pd = BatchCircuitProver::createBatchProof(prevRootF, entries);
    });
    if (pd.empty())
    {
        std::cerr << "[bench_track2_scale] FATAL: createBatchProof failed\n";
        return 1;
    }
    std::cerr << "[bench_track2_scale] createBatchProof: " << proveMs
              << " ms, proof " << pd.proof_bytes.size() << " bytes\n";

    bool verifyOk = false;
    long long const verifyMs = timeMs([&] {
        verifyOk = BatchCircuitProver::verifyBatch(
            pd.prev_root, pd.new_root, pd.entries_hash, pd.proof_bytes);
    });
    std::cerr << "[bench_track2_scale] verifyBatch: " << verifyMs << " ms -> "
              << (verifyOk ? "PASS" : "FAIL") << "\n";

    if (!verifyOk)
        return 1;

    std::cout << "RESULT n=" << n
              << " constraints=" << BatchCircuitProver::constraintCount()
              << " init_ms=" << initMs << " prove_ms=" << proveMs
              << " verify_ms=" << verifyMs
              << " proof_bytes=" << pd.proof_bytes.size() << "\n";
    return 0;
}
