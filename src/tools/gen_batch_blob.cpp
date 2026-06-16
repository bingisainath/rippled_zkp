// gen_batch_blob — Generate a valid BatchRollup sfBatchProof blob for the
// live-node demonstration (Option B).
//
// Usage:
//   gen_batch_blob [batch_id]        -- defaults to batch_id=1
//
// Output (stdout, one line each):
//   BLOB=<hex>          full sfBatchProof field (2420 bytes)
//   PUB=<hex>           sequencer public key (33 bytes, XRPL ed25519 format)
//   PREV_ROOT=<hex>     sfPrevRoot (32 bytes)
//   NEW_ROOT=<hex>      sfRollupRoot (32 bytes)
//   BATCH_ID=<n>
//   TX_COUNT=8
//
// The genesis null-notes (seeds 0..7) are the "old notes" for batch 1.
// Each deposit creates a new note with value = 1_000_000 drops × (i+1).
//
// Sequencer key: Ed25519 keypair derived from "sequencer-seed-phase1"
// (same as BatchVerifier_test / RollupBench_test — reproducible).

#include <libxrpl/zkp/ZKProver.h>
#include <libxrpl/zkp/rollup/BatchProof.h>
#include <libxrpl/zkp/rollup/BabyJubjub.h>
#include <libxrpl/zkp/rollup/PoseidonHash.h>
#include <libxrpl/zkp/rollup/RollupMerkleTree.h>
#include <libxrpl/zkp/rollup/RollupNote.h>
#include <libxrpl/zkp/rollup/RollupProver.h>
#include <libxrpl/zkp/rollup/RollupState.h>
#include <libxrpl/zkp/circuits/MerkleCircuit.h>

#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/KeyType.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/SecretKey.h>
#include <xrpl/protocol/Seed.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ripple;
using namespace ripple::zkp;
using namespace ripple::zkp::rollup;

constexpr std::size_t kBatchSize         = kRollupBatchSize;
constexpr std::size_t kEntryProofSlot    = 192;
constexpr std::size_t kTotalProofBytes   = kBatchSize * kEntryProofSlot;

// Convert uint256 auth-path vector to FieldT vector for the prover.
std::vector<FieldT>
toFieldVec(std::vector<uint256> const& v)
{
    std::vector<FieldT> out;
    out.reserve(v.size());
    for (auto const& u : v)
        out.push_back(PoseidonHash::uint256ToField(u));
    return out;
}

// Decompose leaf index into a bool vector (LSB first, length = tree depth).
std::vector<bool>
leafPosBits(std::size_t pos, std::size_t depth)
{
    std::vector<bool> bits(depth, false);
    for (std::size_t b = 0; b < depth; ++b)
        bits[b] = (pos >> b) & 1u;
    return bits;
}

// Sign batch hash with the test sequencer key.
// Returns: (pubKeyBytes33, sigBytes64)
std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>
signBatch(uint256 const& batchHash)
{
    // Same seed string as BatchVerifier_test::signWithTestSequencer.
    std::string const seedStr = "sequencer-seed-phase1";
    auto const seed = generateSeed(seedStr);
    auto const kp   = generateKeyPair(KeyType::ed25519, seed);
    auto const& pk  = kp.first;
    auto const& sk  = kp.second;

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
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(b);
    return ss.str();
}

std::string
toHex(uint256 const& u)
{
    std::vector<std::uint8_t> v(u.begin(), u.end());
    return toHex(v);
}

}  // namespace

int
main(int argc, char** argv)
{
    // Fast path: just print the genesis rollup root (no key loading).
    if (argc >= 2 && std::string(argv[1]) == "--genesis-root")
    {
        DefaultCurve::init_public_params();
        PoseidonHash::initialize();
        BabyJubjub::initialize();
        std::cout << toHex(kGenesisRollupRoot()) << "\n";
        return 0;
    }

    // Fast path: generate (or load) Groth16 keys and exit — no proof generation.
    // Used by the demo script to pre-warm keys before starting rippled.
    if (argc >= 2 && std::string(argv[1]) == "--gen-keys")
    {
        std::cerr << "[gen_batch_blob] loading/generating Groth16 keys...\n";
        RollupProver::initialize();
        std::cerr << "[gen_batch_blob] keys ready ("
                  << RollupProver::constraintCount() << " constraints)\n";
        return 0;
    }

    std::uint32_t const batchId =
        (argc >= 2) ? static_cast<std::uint32_t>(std::stoul(argv[1])) : 1u;

    std::cerr << "[gen_batch_blob] initialising RollupProver (loading keys)...\n";
    RollupProver::initialize();
    std::cerr << "[gen_batch_blob] keys loaded ("
              << RollupProver::constraintCount() << " constraints)\n";

    // ── 1. Build genesis tree (8 null-note commitments, seeds 0..7) ───────────
    RollupMerkleTree genesisTree(kRollupTreeDepth);
    std::array<RollupNote, kBatchSize> oldNotes;
    for (std::size_t i = 0; i < kBatchSize; ++i)
    {
        oldNotes[i] = RollupNote::createRandom(0, static_cast<std::uint64_t>(i));
        genesisTree.append(
            PoseidonHash::fieldToUint256(oldNotes[i].commitment()));
    }
    uint256 const prevRoot = genesisTree.root();

    // Sanity: must match the on-chain kGenesisRollupRoot().
    if (prevRoot != kGenesisRollupRoot())
    {
        std::cerr << "[gen_batch_blob] FATAL: computed prevRoot != "
                     "kGenesisRollupRoot(). Rebuild required.\n";
        return 1;
    }
    std::cerr << "[gen_batch_blob] genesis prevRoot confirmed\n";

    // ── 2. Create 8 deposit new-notes (same spending key as old, new value) ──
    std::array<RollupNote, kBatchSize> newNotes;
    for (std::size_t i = 0; i < kBatchSize; ++i)
    {
        std::uint64_t const seed = 200 + static_cast<std::uint64_t>(i);
        newNotes[i] = RollupNote::createRandom(
            1'000'000ULL * (i + 1), seed);
        // Keep the same spending key so the nullifier derivation is consistent.
        newNotes[i].ask = oldNotes[i].ask;
        newNotes[i].apk = oldNotes[i].apk;
    }

    // ── 3. Build the new tree by updating leaf i with newNote[i].commitment() ─
    RollupMerkleTree newTree(kRollupTreeDepth);
    // Copy genesis tree contents by re-appending, then update in place.
    for (std::size_t i = 0; i < kBatchSize; ++i)
        newTree.append(
            PoseidonHash::fieldToUint256(oldNotes[i].commitment()));
    for (std::size_t i = 0; i < kBatchSize; ++i)
        newTree.update_leaf(
            i, PoseidonHash::fieldToUint256(newNotes[i].commitment()));
    uint256 const newRoot = newTree.root();

    // ── 4. Assemble BatchProof skeleton ──────────────────────────────────────
    BatchProof bp;
    bp.batchId  = batchId;
    bp.prevRoot = prevRoot;
    bp.newRoot  = newRoot;
    bp.txCount  = static_cast<std::uint32_t>(kBatchSize);
    bp.proof.assign(kTotalProofBytes, 0);
    bp.entries.reserve(kBatchSize);

    // ── 5. Generate one Groth16 proof per entry ───────────────────────────────
    std::cerr << "[gen_batch_blob] generating " << kBatchSize
              << " Groth16 proofs...\n";

    for (std::size_t i = 0; i < kBatchSize; ++i)
    {
        std::cerr << "  entry " << i << "... " << std::flush;

        auto const leafBits = leafPosBits(i, kRollupTreeDepth);

        // Auth paths from the two trees.
        auto authOld = toFieldVec(genesisTree.authPath(i));
        auto authNew = toFieldVec(newTree.authPath(i));

        FieldT const prevRootF = PoseidonHash::uint256ToField(prevRoot);
        FieldT const newRootF  = PoseidonHash::uint256ToField(newRoot);

        RollupProofData pd = RollupProver::createProof(
            oldNotes[i], newNotes[i],
            leafBits, authOld, authNew,
            prevRootF, newRootF);

        if (pd.proof_bytes.size() > kEntryProofSlot)
        {
            std::cerr << "FATAL: proof_bytes.size()=" << pd.proof_bytes.size()
                      << " exceeds slot " << kEntryProofSlot << "\n";
            return 1;
        }
        std::memcpy(
            bp.proof.data() + i * kEntryProofSlot,
            pd.proof_bytes.data(),
            pd.proof_bytes.size());

        RollupTxEntry entry;
        entry.commitment =
            PoseidonHash::fieldToUint256(newNotes[i].commitment());
        entry.nullifier  =
            PoseidonHash::fieldToUint256(oldNotes[i].nullifier());
        entry.value      = newNotes[i].value;
        entry.txType     = RollupTxType::Deposit;
        entry.destination = AccountID{};
        bp.entries.push_back(entry);

        // Local proof verification — catches conversion bugs before the node.
        std::vector<unsigned char> entryProofVec(
            bp.proof.data() + i * kEntryProofSlot,
            bp.proof.data() + i * kEntryProofSlot + kEntryProofSlot);
        if (!RollupProver::verifyEntry(bp, i, entryProofVec))
        {
            std::cerr << "FATAL: local verify FAILED for entry " << i << "\n";
            return 1;
        }

        std::cerr << "ok\n";
    }

    // ── 6. Sign ───────────────────────────────────────────────────────────────
    uint256 const batchHash = bp.computeBatchHash();
    auto [pubBytes, sigBytes] = signBatch(batchHash);

    std::copy(sigBytes.begin(), sigBytes.end(), bp.sequencerSig.begin());

    // ── 7. Serialise ──────────────────────────────────────────────────────────
    auto const blob = bp.serialize();

    // ── 8. Print results ──────────────────────────────────────────────────────
    std::cout << "BLOB="      << toHex(blob)    << "\n";
    std::cout << "PUB="       << toHex(pubBytes) << "\n";
    std::cout << "PREV_ROOT=" << toHex(prevRoot) << "\n";
    std::cout << "NEW_ROOT="  << toHex(newRoot)  << "\n";
    std::cout << "BATCH_ID="  << batchId         << "\n";
    std::cout << "TX_COUNT="  << kBatchSize       << "\n";

    std::cerr << "[gen_batch_blob] blob=" << blob.size() << " bytes. Done.\n";
    return 0;
}
