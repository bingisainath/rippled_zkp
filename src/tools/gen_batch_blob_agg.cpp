// gen_batch_blob_agg — Generate a valid BatchRollupAgg sfBatchProof blob.
//
// Track 3 (aggregation), wired onto a live on-chain transactor
// (ttBATCH_ROLLUP_AGG=64). Reuses gen_batch_blob's exact genesis/note/tree
// conventions (SAME RollupState tree — this is an alternative proof path
// for Track 1's existing rollup, not a new one) so a chain of BatchRollup
// (tt=61) and BatchRollupAgg (tt=64) batches can interleave freely against
// the same on-chain root. Each of the 8 users proves locally
// (RollupProver::createProof, real, ~0.5s each); this tool then aggregates
// the 8 proofs (ProofAggregator::aggregate) instead of submitting them as
// 8 padded proof slots.
//
// Usage:
//   gen_batch_blob_agg [batch_id]        -- default batch_id=1
//   gen_batch_blob_agg --chain <batch_id> [--deposit-value-base N]
//
// Output (stdout, one line each):
//   BLOB=<hex>
//   PUB=<hex>
//   PREV_ROOT=<hex>
//   NEW_ROOT=<hex>
//   BATCH_ID=<n>
//   TX_COUNT=8

#include <libxrpl/zkp/rollup/BabyJubjub.h>
#include <libxrpl/zkp/rollup/BatchProof.h>
#include <libxrpl/zkp/rollup/PoseidonHash.h>
#include <libxrpl/zkp/rollup/ProofAggregator.h>
#include <libxrpl/zkp/rollup/RollupMerkleTree.h>
#include <libxrpl/zkp/rollup/RollupNote.h>
#include <libxrpl/zkp/rollup/RollupProver.h>
#include <libxrpl/zkp/rollup/RollupState.h>

#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/KeyType.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/SecretKey.h>
#include <xrpl/protocol/Seed.h>

#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace ripple;
using namespace ripple::zkp;
using namespace ripple::zkp::rollup;

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

std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>
signBatch(uint256 const& batchHash)
{
    std::string const seedStr = "sequencer-seed-phase1";
    auto const seed = generateSeed(seedStr);
    auto const kp = generateKeyPair(KeyType::ed25519, seed);
    auto const& pk = kp.first;
    auto const& sk = kp.second;
    auto const sig = sign(pk, sk, Slice(batchHash.data(), batchHash.size()));
    std::vector<std::uint8_t> pubBytes(pk.data(), pk.data() + pk.size());
    std::vector<std::uint8_t> sigBytes(sig.data(), sig.data() + sig.size());
    return {pubBytes, sigBytes};
}

std::string
toHex(std::vector<std::uint8_t> const& v)
{
    std::ostringstream ss;
    for (auto b : v)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return ss.str();
}

std::string
toHex(uint256 const& u)
{
    std::vector<std::uint8_t> v(u.begin(), u.end());
    return toHex(v);
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

void
buildChainTree(
    RollupMerkleTree& tree,
    std::uint32_t upToBatch,
    std::uint64_t valueBase,
    std::array<RollupNote, kBatchSize> const& genesisNotes)
{
    for (std::size_t i = 0; i < kBatchSize; ++i)
        tree.append(PoseidonHash::fieldToUint256(genesisNotes[i].commitment()));
    for (std::uint32_t k = 1; k <= upToBatch; ++k)
    {
        auto const bNotes = buildBatchNotes(k, valueBase, genesisNotes);
        for (std::size_t i = 0; i < kBatchSize; ++i)
            tree.update_leaf(i, PoseidonHash::fieldToUint256(bNotes[i].commitment()));
    }
}

}  // namespace

int
main(int argc, char** argv)
{
    std::uint32_t batchId = 1;
    bool chainMode = false;
    std::uint64_t depositValueBase = 20'000'000ULL;
    std::uint32_t numWithdrawals = 0;
    std::vector<std::string> destStrs;

    for (int a = 1; a < argc; ++a)
    {
        std::string arg = argv[a];
        if (arg == "--chain")
            chainMode = true;
        else if (arg == "--deposit-value-base" && a + 1 < argc)
            depositValueBase = std::stoull(argv[++a]);
        else if (arg == "--withdrawals" && a + 1 < argc)
            numWithdrawals = static_cast<std::uint32_t>(std::stoul(argv[++a]));
        else if (arg == "--dest" && a + 1 < argc)
        {
            std::istringstream ss(argv[++a]);
            std::string tok;
            while (std::getline(ss, tok, ','))
                if (!tok.empty())
                    destStrs.push_back(tok);
        }
        else if (arg[0] != '-')
            batchId = static_cast<std::uint32_t>(std::stoul(arg));
    }
    if (batchId > 1 && !chainMode)
    {
        std::cerr << "FATAL: batch_id=" << batchId << " requires --chain\n";
        return 1;
    }
    if (numWithdrawals > kBatchSize)
    {
        std::cerr << "FATAL: --withdrawals " << numWithdrawals
                   << " > batch size " << kBatchSize << "\n";
        return 1;
    }
    if (numWithdrawals > 0 && destStrs.size() != numWithdrawals)
    {
        std::cerr << "FATAL: --withdrawals " << numWithdrawals
                   << " but --dest has " << destStrs.size() << " addresses\n";
        return 1;
    }
    std::array<AccountID, kBatchSize> dests{};
    for (std::size_t i = 0; i < numWithdrawals; ++i)
    {
        auto opt = ripple::parseBase58<AccountID>(destStrs[i]);
        if (!opt)
        {
            std::cerr << "FATAL: invalid XRPL address: " << destStrs[i] << "\n";
            return 1;
        }
        dests[i] = *opt;
    }

    DefaultCurve::init_public_params();
    PoseidonHash::initialize();
    BabyJubjub::initialize();

    auto const genesisNotes = buildGenesisNotes();

    std::array<RollupNote, kBatchSize> oldNotes;
    if (batchId == 1)
    {
        oldNotes = genesisNotes;
    }
    else
    {
        std::uint64_t const prevSeedBase =
            static_cast<std::uint64_t>(batchId - 1) * 200;
        for (std::size_t i = 0; i < kBatchSize; ++i)
        {
            oldNotes[i] = RollupNote::createRandom(depositValueBase, prevSeedBase + i);
            oldNotes[i].ask = genesisNotes[i].ask;
            oldNotes[i].apk = genesisNotes[i].apk;
        }
    }

    std::cerr << "[gen_batch_blob_agg] initialising RollupProver + "
                 "ProofAggregator (loading keys + SRS)...\n";
    RollupProver::initialize();
    ProofAggregator::initialize();
    std::cerr << "[gen_batch_blob_agg] ready ("
              << RollupProver::constraintCount() << " constraints, SRS N="
              << ProofAggregator::srs().n() << ")\n";

    auto const newNotes = buildBatchNotes(batchId, depositValueBase, genesisNotes);

    RollupMerkleTree oldTree(kRollupTreeDepth);
    buildChainTree(oldTree, batchId - 1, depositValueBase, genesisNotes);
    uint256 const prevRoot = oldTree.root();
    if (batchId == 1 && prevRoot != kGenesisRollupRoot())
    {
        std::cerr << "[gen_batch_blob_agg] FATAL: batch 1 prevRoot != "
                     "kGenesisRollupRoot()\n";
        return 1;
    }
    std::cerr << "[gen_batch_blob_agg] batchId=" << batchId << "  prevRoot="
              << toHex(prevRoot).substr(0, 16) << "...\n";

    RollupMerkleTree newTree(kRollupTreeDepth);
    buildChainTree(newTree, batchId - 1, depositValueBase, genesisNotes);
    for (std::size_t i = 0; i < kBatchSize; ++i)
        newTree.update_leaf(i, PoseidonHash::fieldToUint256(newNotes[i].commitment()));
    uint256 const newRoot = newTree.root();

    BatchProof bp;
    bp.batchId = batchId;
    bp.prevRoot = prevRoot;
    bp.newRoot = newRoot;
    bp.txCount = static_cast<std::uint32_t>(kBatchSize);
    bp.entries.reserve(kBatchSize);

    std::cerr << "[gen_batch_blob_agg] generating " << kBatchSize
              << " real Track 1 Groth16 proofs (batchId=" << batchId
              << ", " << numWithdrawals << " withdrawal(s))...\n";
    std::vector<RollupProofData> proofs(kBatchSize);
    for (std::size_t i = 0; i < kBatchSize; ++i)
    {
        auto const leafBits = leafPosBits(i, kRollupTreeDepth);
        auto const authOld = toFieldVec(oldTree.authPath(i));
        auto const authNew = toFieldVec(newTree.authPath(i));
        FieldT const prevRootF = PoseidonHash::uint256ToField(prevRoot);
        FieldT const newRootF = PoseidonHash::uint256ToField(newRoot);

        // Entries [0, numWithdrawals) are withdrawals — same note-rotation
        // chain as a deposit (spend batch K-1's note, create batch K's), just
        // tagged with is_withdraw so the circuit enforces value-conservation
        // instead of minting, and doApply() pays the pool out to destination
        // instead of crediting it. Mirrors gen_batch_blob.cpp exactly.
        bool const isWithdraw = (i < numWithdrawals);

        auto const t0 = std::chrono::steady_clock::now();
        proofs[i] = RollupProver::createProof(
            oldNotes[i], newNotes[i], leafBits, authOld, authNew, prevRootF,
            newRootF, isWithdraw);
        auto const ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - t0)
                             .count();
        std::cerr << "  entry " << i << " (" << (isWithdraw ? "WITHDRAW" : "DEPOSIT")
                  << ")... ok (" << ms << " ms)\n";

        RollupTxEntry entry;
        entry.commitment = PoseidonHash::fieldToUint256(newNotes[i].commitment());
        entry.nullifier = PoseidonHash::fieldToUint256(oldNotes[i].nullifier());
        entry.value = newNotes[i].value;
        entry.txType = isWithdraw ? RollupTxType::Withdraw : RollupTxType::Deposit;
        entry.destination = isWithdraw ? dests[i] : AccountID{};
        bp.entries.push_back(entry);
    }

    std::cerr << "[gen_batch_blob_agg] aggregating " << kBatchSize
              << " proofs into one (TIPP/MIPP/KZG)...\n";
    auto const t0 = std::chrono::steady_clock::now();
    auto const agg = ProofAggregator::aggregate(ProofAggregator::srs(), proofs);
    auto const aggMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
    bp.proof = agg.serialize();
    std::cerr << "[gen_batch_blob_agg] aggregate proof: " << aggMs << " ms, "
              << bp.proof.size() << " bytes\n";

    auto const tv0 = std::chrono::steady_clock::now();
    bool const verifyOk =
        ProofAggregator::verifyAggregate(ProofAggregator::srs(), agg, proofs);
    auto const verifyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - tv0)
                               .count();
    std::cerr << "[gen_batch_blob_agg] local verify: "
              << (verifyOk ? "PASS" : "FAIL") << " (" << verifyMs << " ms)\n";
    if (!verifyOk)
    {
        std::cerr << "FATAL: aggregate proof failed local verification\n";
        return 1;
    }

    uint256 const batchHash = bp.computeBatchHash();
    auto [pubBytes, sigBytes] = signBatch(batchHash);
    std::copy(sigBytes.begin(), sigBytes.end(), bp.sequencerSig.begin());

    auto const blob = bp.serialize();
    if (blob.empty())
    {
        std::cerr << "FATAL: BatchProof::serialize() failed\n";
        return 1;
    }

    std::cout << "BLOB=" << toHex(blob) << "\n"
              << "PUB=" << toHex(pubBytes) << "\n"
              << "PREV_ROOT=" << toHex(prevRoot) << "\n"
              << "NEW_ROOT=" << toHex(newRoot) << "\n"
              << "BATCH_ID=" << batchId << "\n"
              << "TX_COUNT=" << kBatchSize << "\n";
    std::cerr << "[gen_batch_blob_agg] blob=" << blob.size() << " bytes. Done.\n";
    return 0;
}
