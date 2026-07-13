// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// gen_batch_blob2 — off-node generator for a Track 2 (Option A) ttBATCH_ROLLUP2
// sfBatchProof blob. Mirrors gen_batch_blob.cpp (Track 1) but builds ONE
// monolithic proof via RollupSequencer2 instead of N per-entry proofs.
//
// Emits KEY=value lines on stdout for a demo shell script to parse:
//   BLOB=<hex>        the sfBatchProof blob
//   PUB=<hex>         33-byte sequencer Ed25519 public key
//   PREV_ROOT=<hex>   prevRoot (uint256)
//   NEW_ROOT=<hex>    newRoot  (uint256)
//   BATCH_ID=<n>
//   TX_COUNT=<n>
//
// Options:
//   --gen-keys              Initialise/generate the BatchCircuit Groth16 keys
//                           at the default path, then exit (one-time setup).
//   --genesis-root          Print the empty-tree genesis root and exit.
//   --deposits N            Number of deposit entries (1..8, default 8).
//   --batch-id N            Batch id (default 1). NOTE: this tool is stateless
//                           and always builds from the GENESIS root, so only
//                           batch-id 1 will apply on a fresh node.
//   --deposit-value-base V  First deposit's drops (default 1000000); entry i
//                           deposits V + i.
//
// Key path: /tmp/rippled_rollup_batch_keys (the node's default — so the tool
// and node share keys; the node's onStart generates them if absent).

#include <libxrpl/zkp/rollup/BatchCircuitProver.h>
#include <libxrpl/zkp/rollup/BatchProof2.h>
#include <libxrpl/zkp/rollup/RollupSequencer2.h>
#include <libxrpl/zkp/rollup/RollupState2.h>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace ripple::zkp::rollup;

namespace {

constexpr std::size_t kDepth = 16;  // matches the node's default prover shape

std::string
toHex(std::vector<std::uint8_t> const& v)
{
    std::ostringstream ss;
    for (auto b : v)
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(b);
    return ss.str();
}

std::string
toHex(ripple::uint256 const& u)
{
    std::vector<std::uint8_t> v(u.begin(), u.end());
    return toHex(v);
}

void
initCrypto()
{
    libff::alt_bn128_pp::init_public_params();
    BabyJubjub::initialize();
    PoseidonHash::initialize();
}

// Deterministic demo user keys.
FieldT
userKey(std::size_t i)
{
    return FieldT("770000110022003300") + FieldT(i);
}

}  // namespace

int
main(int argc, char** argv)
{
    initCrypto();

    if (argc >= 2 && std::string(argv[1]) == "--genesis-root")
    {
        std::cout << toHex(emptyAccountTreeRoot(kDepth)) << "\n";
        return 0;
    }

    if (argc >= 2 && std::string(argv[1]) == "--gen-keys")
    {
        std::cerr << "[gen_batch_blob2] initialising BatchCircuit keys "
                     "(one-time, ~35s if absent)…\n";
        BatchCircuitProver::initialize(
            BatchCircuitProver::defaultKeyPath(), 8, kDepth);
        std::cerr << "[gen_batch_blob2] keys ready ("
                  << BatchCircuitProver::constraintCount()
                  << " constraints).\n";
        return 0;
    }

    std::uint32_t batchId = 1;
    std::uint32_t deposits = 8;
    std::uint64_t depositValueBase = 1'000'000;

    for (int a = 1; a < argc; ++a)
    {
        std::string arg = argv[a];
        if (arg == "--batch-id" && a + 1 < argc)
            batchId = static_cast<std::uint32_t>(std::stoul(argv[++a]));
        else if (arg == "--deposits" && a + 1 < argc)
            deposits = static_cast<std::uint32_t>(std::stoul(argv[++a]));
        else if (arg == "--deposit-value-base" && a + 1 < argc)
            depositValueBase = std::stoull(argv[++a]);
        else
        {
            std::cerr << "[gen_batch_blob2] unknown/incomplete arg: " << arg
                      << "\n";
            return 2;
        }
    }

    if (deposits < 1 || deposits > BATCH2_SIZE)
    {
        std::cerr << "[gen_batch_blob2] --deposits must be in [1, "
                  << BATCH2_SIZE << "]\n";
        return 2;
    }

    // Load (or generate) keys and build the batch.
    BatchCircuitProver::initialize(
        BatchCircuitProver::defaultKeyPath(), 8, kDepth);

    RollupSequencer2 seq(kDepth);
    std::vector<SequencerRequest> reqs;
    for (std::uint32_t i = 0; i < deposits; ++i)
    {
        SequencerRequest sr;
        BjjPoint apk = EdDSA::derivePublicKey(userKey(i));
        sr.req = SignedRequest::make(
            userKey(i), apk.x, depositValueBase + i, 0,
            RequestType::Deposit);
        reqs.push_back(sr);
    }

    std::cerr << "[gen_batch_blob2] building batch " << batchId << " with "
              << deposits << " deposit(s) + " << (BATCH2_SIZE - deposits)
              << " NoOp pad(s); proving (~38s at depth " << kDepth << ")…\n";

    auto bp = seq.buildBatch(reqs, batchId);
    if (!bp)
    {
        std::cerr << "[gen_batch_blob2] ERROR: buildBatch failed\n";
        return 1;
    }

    auto const blob = bp->serialize();

    std::cout << "BLOB=" << toHex(blob) << "\n";
    std::cout << "PUB=" << toHex(seq.publicKey()) << "\n";
    std::cout << "PREV_ROOT=" << toHex(bp->prevRoot) << "\n";
    std::cout << "NEW_ROOT=" << toHex(bp->newRoot) << "\n";
    std::cout << "BATCH_ID=" << bp->batchId << "\n";
    std::cout << "TX_COUNT=" << bp->txCount << "\n";

    std::cerr << "[gen_batch_blob2] blob=" << blob.size()
              << " bytes (proof=" << bp->proof.size() << "B). Done.\n";
    return 0;
}
