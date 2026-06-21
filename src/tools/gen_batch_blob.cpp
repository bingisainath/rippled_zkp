// gen_batch_blob — Generate a valid BatchRollup sfBatchProof blob.
//
// Usage:
//   gen_batch_blob [flags] [batch_id]        -- default batch_id=1
//
// Flags:
//   --genesis-root          Print genesis rollup root (Poseidon init only) and exit
//   --gen-keys              Load/generate Groth16 keys and exit
//   --chain                 Compute prevRoot from genesis using seed convention
//                           (required for batch_id > 1)
//   --withdrawals K         First K entries are withdrawals (0=all deposit)
//   --dest A0,A1,...,AK-1   XRPL account addresses for withdrawal entries
//   --print-nullifiers      Print NULLIFIER_i=hex for old notes then exit (no Groth16)
//   --deposit-value-base N  Drops per note for batch_id > 1 (default 20_000_000 = 20 XRP)
//
// Output (stdout, one line each):
//   BLOB=<hex>
//   PUB=<hex>
//   PREV_ROOT=<hex>
//   NEW_ROOT=<hex>
//   BATCH_ID=<n>
//   TX_COUNT=8
//   NULLIFIER_0..7=<hex>    (old-note nullifiers, always printed)
//
// Seed / chaining convention (must be consistent across all batches in a chain):
//   genesis notes : createRandom(0, i)                         for i=0..7
//   batch K notes : createRandom(depositValueBase, K*200+i),
//                   ask/apk = genesis note i's ask/apk
//
//   Old notes for batch K = new notes from batch K-1 (same value, next seed base).
//   With a uniform depositValueBase, the full chain is determined by batch_id alone,
//   so --chain can reconstruct prevRoot without storing external state.

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
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/KeyType.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/SecretKey.h>
#include <xrpl/protocol/Seed.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ripple;
using namespace ripple::zkp;
using namespace ripple::zkp::rollup;

constexpr std::size_t kBatchSize       = kRollupBatchSize;
constexpr std::size_t kEntryProofSlot  = 192;
constexpr std::size_t kTotalProofBytes = kBatchSize * kEntryProofSlot;

// ── Helpers ──────────────────────────────────────────────────────────────────

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
    auto const kp   = generateKeyPair(KeyType::ed25519, seed);
    auto const& pk  = kp.first;
    auto const& sk  = kp.second;
    auto const sig  = sign(pk, sk, Slice(batchHash.data(), batchHash.size()));
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

// ── Note construction helpers ─────────────────────────────────────────────────

// Genesis null-notes: createRandom(0, 0..7). Provides ask/apk for all batches.
std::array<RollupNote, kBatchSize>
buildGenesisNotes()
{
    std::array<RollupNote, kBatchSize> notes;
    for (std::size_t i = 0; i < kBatchSize; ++i)
        notes[i] = RollupNote::createRandom(0, static_cast<std::uint64_t>(i));
    return notes;
}

// New notes for batch K: createRandom(valueBase, K*200+i) with genesis ask/apk.
// value_pub = new_note.value (circuit constraint), so entry.value = valueBase
// for both deposit and withdrawal entries. Withdrawal entries point to L1 dests.
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

// Build a Merkle tree after genesis and then applying batches 1..upToBatch.
// Uses the same seed convention as buildBatchNotes. O(upToBatch * 8) Poseidon hashes.
void
buildChainTree(
    RollupMerkleTree& tree,
    std::uint32_t upToBatch,
    std::uint64_t valueBase,
    std::array<RollupNote, kBatchSize> const& genesisNotes)
{
    // Append genesis null-note commitments
    for (std::size_t i = 0; i < kBatchSize; ++i)
        tree.append(PoseidonHash::fieldToUint256(genesisNotes[i].commitment()));

    // Apply each simulated batch in order
    for (std::uint32_t k = 1; k <= upToBatch; ++k)
    {
        auto const bNotes = buildBatchNotes(k, valueBase, genesisNotes);
        for (std::size_t i = 0; i < kBatchSize; ++i)
        {
            tree.update_leaf(
                i, PoseidonHash::fieldToUint256(bNotes[i].commitment()));
        }
    }
}

}  // namespace

int
main(int argc, char** argv)
{
    // ── Fast path: genesis root (no key loading) ─────────────────────────────
    if (argc >= 2 && std::string(argv[1]) == "--genesis-root")
    {
        DefaultCurve::init_public_params();
        PoseidonHash::initialize();
        BabyJubjub::initialize();
        std::cout << toHex(kGenesisRollupRoot()) << "\n";
        return 0;
    }

    // ── Fast path: generate / load Groth16 keys ──────────────────────────────
    if (argc >= 2 && std::string(argv[1]) == "--gen-keys")
    {
        std::cerr << "[gen_batch_blob] loading/generating Groth16 keys...\n";
        RollupProver::initialize();
        std::cerr << "[gen_batch_blob] keys ready ("
                  << RollupProver::constraintCount() << " constraints)\n";
        return 0;
    }

    // ── Parse flags ──────────────────────────────────────────────────────────
    std::uint32_t batchId          = 1;
    bool          chainMode        = false;
    bool          printNullifiers  = false;
    std::uint32_t numWithdrawals   = 0;
    std::vector<std::string> destStrs;
    std::uint64_t depositValueBase = 20'000'000ULL;  // 20 XRP default

    for (int a = 1; a < argc; ++a)
    {
        std::string arg = argv[a];
        if (arg == "--chain")
        {
            chainMode = true;
        }
        else if (arg == "--print-nullifiers")
        {
            printNullifiers = true;
        }
        else if (arg == "--withdrawals" && a + 1 < argc)
        {
            numWithdrawals = static_cast<std::uint32_t>(std::stoul(argv[++a]));
        }
        else if (arg == "--dest" && a + 1 < argc)
        {
            std::string ds = argv[++a];
            std::istringstream ss(ds);
            std::string tok;
            while (std::getline(ss, tok, ','))
                if (!tok.empty())
                    destStrs.push_back(tok);
        }
        else if (arg == "--deposit-value-base" && a + 1 < argc)
        {
            depositValueBase = std::stoull(argv[++a]);
        }
        else if (arg[0] != '-')
        {
            batchId = static_cast<std::uint32_t>(std::stoul(arg));
        }
    }

    // Validate
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
    if (batchId > 1 && !chainMode)
    {
        std::cerr << "FATAL: batch_id=" << batchId
                  << " requires --chain (to compute prevRoot from seed convention)\n";
        return 1;
    }

    // ── Initialise crypto primitives ─────────────────────────────────────────
    DefaultCurve::init_public_params();
    PoseidonHash::initialize();
    BabyJubjub::initialize();

    // ── Build genesis notes (provides ask/apk for all batches) ───────────────
    auto const genesisNotes = buildGenesisNotes();

    // Sanity: confirm genesis tree root matches kGenesisRollupRoot().
    {
        RollupMerkleTree gTree(kRollupTreeDepth);
        for (std::size_t i = 0; i < kBatchSize; ++i)
            gTree.append(PoseidonHash::fieldToUint256(genesisNotes[i].commitment()));
        if (gTree.root() != kGenesisRollupRoot())
        {
            std::cerr << "[gen_batch_blob] FATAL: computed genesis root != "
                         "kGenesisRollupRoot(). Rebuild required.\n";
            return 1;
        }
    }

    // ── Build old notes for this batch ───────────────────────────────────────
    // batch 1  → genesis null notes (seed 0..7, value 0)
    // batch K  → previous batch's new notes (seed (K-1)*200+i, value depositValueBase)
    std::array<RollupNote, kBatchSize> oldNotes;
    if (batchId == 1)
    {
        oldNotes = genesisNotes;
    }
    else
    {
        std::uint64_t const prevSeedBase = static_cast<std::uint64_t>(batchId - 1) * 200;
        for (std::size_t i = 0; i < kBatchSize; ++i)
        {
            oldNotes[i] = RollupNote::createRandom(
                depositValueBase, prevSeedBase + i);
            oldNotes[i].ask = genesisNotes[i].ask;
            oldNotes[i].apk = genesisNotes[i].apk;
        }
    }

    // ── Parse withdrawal destination addresses (before key loading for fast fail) ─
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

    // ── Print nullifiers and exit (no Groth16) ───────────────────────────────
    if (printNullifiers)
    {
        for (std::size_t i = 0; i < kBatchSize; ++i)
            std::cout << "NULLIFIER_" << i << "="
                      << toHex(PoseidonHash::fieldToUint256(oldNotes[i].nullifier()))
                      << "\n";
        return 0;
    }

    // ── Load Groth16 keys ────────────────────────────────────────────────────
    std::cerr << "[gen_batch_blob] initialising RollupProver (loading keys)...\n";
    RollupProver::initialize();
    std::cerr << "[gen_batch_blob] keys loaded ("
              << RollupProver::constraintCount() << " constraints)\n";

    // ── Build new notes for this batch ───────────────────────────────────────
    // Both deposit and withdrawal replacement notes use the same seed convention
    // and value (depositValueBase). For withdrawals: value_pub = new_note.value,
    // so entry.value = depositValueBase = the amount transferred from pool to L1.
    auto const newNotes = buildBatchNotes(batchId, depositValueBase, genesisNotes);

    // ── Build old tree (for auth paths) ──────────────────────────────────────
    // Reconstructs tree state after genesis + batches 1..batchId-1.
    RollupMerkleTree oldTree(kRollupTreeDepth);
    buildChainTree(oldTree, batchId - 1, depositValueBase, genesisNotes);

    uint256 const prevRoot = oldTree.root();
    if (batchId == 1 && prevRoot != kGenesisRollupRoot())
    {
        std::cerr << "[gen_batch_blob] FATAL: batch 1 prevRoot != kGenesisRollupRoot()\n";
        return 1;
    }
    std::cerr << "[gen_batch_blob] batchId=" << batchId
              << "  prevRoot=" << toHex(prevRoot).substr(0, 16) << "…\n";

    // ── Build new tree (apply current batch's note transitions) ──────────────
    // Start from old tree state, re-initialise as a fresh tree with identical leaves.
    RollupMerkleTree newTree(kRollupTreeDepth);
    buildChainTree(newTree, batchId - 1, depositValueBase, genesisNotes);
    for (std::size_t i = 0; i < kBatchSize; ++i)
        newTree.update_leaf(i, PoseidonHash::fieldToUint256(newNotes[i].commitment()));
    uint256 const newRoot = newTree.root();

    // ── Assemble BatchProof skeleton ─────────────────────────────────────────
    BatchProof bp;
    bp.batchId  = batchId;
    bp.prevRoot = prevRoot;
    bp.newRoot  = newRoot;
    bp.txCount  = static_cast<std::uint32_t>(kBatchSize);
    bp.proof.assign(kTotalProofBytes, 0);
    bp.entries.reserve(kBatchSize);

    // ── Generate one Groth16 proof per entry ─────────────────────────────────
    std::cerr << "[gen_batch_blob] generating " << kBatchSize
              << " Groth16 proofs (batchId=" << batchId << ")...\n";

    for (std::size_t i = 0; i < kBatchSize; ++i)
    {
        std::cerr << "  entry " << i << "... " << std::flush;

        auto const leafBits = leafPosBits(i, kRollupTreeDepth);
        auto authOld = toFieldVec(oldTree.authPath(i));
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
                      << " > slot " << kEntryProofSlot << "\n";
            return 1;
        }
        std::memcpy(
            bp.proof.data() + i * kEntryProofSlot,
            pd.proof_bytes.data(),
            pd.proof_bytes.size());

        RollupTxEntry entry;
        entry.commitment  = PoseidonHash::fieldToUint256(newNotes[i].commitment());
        entry.nullifier   = PoseidonHash::fieldToUint256(oldNotes[i].nullifier());
        entry.value       = newNotes[i].value;  // = depositValueBase
        entry.txType      = (i < numWithdrawals) ? RollupTxType::Withdraw
                                                  : RollupTxType::Deposit;
        entry.destination = (i < numWithdrawals) ? dests[i] : AccountID{};
        bp.entries.push_back(entry);

        // Local verification against the assembled BatchProof.
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

    // ── Sign ──────────────────────────────────────────────────────────────────
    uint256 const batchHash = bp.computeBatchHash();
    auto [pubBytes, sigBytes] = signBatch(batchHash);
    std::copy(sigBytes.begin(), sigBytes.end(), bp.sequencerSig.begin());

    // ── Serialise ─────────────────────────────────────────────────────────────
    auto const blob = bp.serialize();

    // ── Print results ─────────────────────────────────────────────────────────
    std::cout << "BLOB="      << toHex(blob)    << "\n";
    std::cout << "PUB="       << toHex(pubBytes) << "\n";
    std::cout << "PREV_ROOT=" << toHex(prevRoot) << "\n";
    std::cout << "NEW_ROOT="  << toHex(newRoot)  << "\n";
    std::cout << "BATCH_ID="  << batchId         << "\n";
    std::cout << "TX_COUNT="  << kBatchSize       << "\n";
    for (std::size_t i = 0; i < kBatchSize; ++i)
        std::cout << "NULLIFIER_" << i << "="
                  << toHex(PoseidonHash::fieldToUint256(oldNotes[i].nullifier()))
                  << "\n";

    std::cerr << "[gen_batch_blob] blob=" << blob.size() << " bytes. Done.\n";
    return 0;
}
