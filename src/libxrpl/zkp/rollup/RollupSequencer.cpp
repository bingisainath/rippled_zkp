
#include <libxrpl/zkp/rollup/RollupSequencer.h>

#include <libxrpl/zkp/rollup/RollupState.h>      // kRollupTreeDepth
#include <libxrpl/zkp/circuits/MerkleCircuit.h>  // uint256ToFieldElement

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/protocol/Sign.h>

#include <openssl/sha.h>

#include <cstring>
#include <iostream>
#include <stdexcept>

namespace ripple {
namespace zkp {
namespace rollup {

RollupSequencer::RollupSequencer(
    PublicKey const& seqPub,
    SecretKey const& seqPriv,
    std::size_t treeDepth,
    SubmitFn submit,
    StateFn state)
    : seqPub_(seqPub)
    , seqPriv_(seqPriv)
    , treeDepth_(treeDepth)
    , submit_(std::move(submit))
    , state_(std::move(state))
    , localTree_(treeDepth)
{
    if (treeDepth_ != static_cast<std::size_t>(kRollupTreeDepth))
        throw std::runtime_error(
            "RollupSequencer: treeDepth must equal kRollupTreeDepth (matches "
            "RollupState.sfRollupTreeDepth)");
    if (!submit_)
        throw std::runtime_error("RollupSequencer: SubmitFn is null");
    if (!state_)
        throw std::runtime_error("RollupSequencer: StateFn is null");
}

std::size_t
RollupSequencer::queueDepth() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return queue_.size();
}

std::uint32_t
RollupSequencer::pendingBatchId() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return lastKnown_.batchCounter + 1;
}

bool
RollupSequencer::isEntryWellFormed(ClientEntry const& e) const
{
    if (e.entry.value == 0)
        return false;
    if (e.entry.nullifier == uint256{})
        return false;
    if (e.entry.commitment == uint256{})
        return false;
    if (e.entry.txType != RollupTxType::Deposit &&
        e.entry.txType != RollupTxType::Withdraw)
        return false;
    if (e.entry.txType == RollupTxType::Withdraw &&
        e.entry.destination == AccountID{})
        return false;
    // leaf_position must fit in the tree depth (2^depth leaves).
    if (treeDepth_ < 64 &&
        e.leaf_position >= (std::uint64_t{1} << treeDepth_))
        return false;
    if (e.proof_bytes.empty())
        return false;
    return true;
}

RejectReason
RollupSequencer::submitEntry(ClientEntry e)
{
    if (!RollupProver::isInitialized())
        return RejectReason::ProverNotInitialized;

    if (!isEntryWellFormed(e))
        return RejectReason::InvalidEntry;

    // Per-entry proof validation BEFORE accepting into the queue.
    // This prototype accepts any well-formed (>= 64-byte) blob;
    // the authoritative Groth16 check happens on-chain in
    // BatchVerifier::verifyBatchProof.
    try
    {
        if (e.proof_bytes.size() < 64)
            return RejectReason::InvalidProof;
    }
    catch (...)
    {
        return RejectReason::InvalidProof;
    }

    std::unique_lock<std::mutex> lk(mu_);

    if (queue_.size() >= BATCH_SIZE)
        return RejectReason::QueueFull;

    if (pendingNfs_.count(e.entry.nullifier))
        return RejectReason::DuplicateNullifierInQueue;

    pendingNfs_.insert(e.entry.nullifier);
    queue_.push_back(std::move(e));

    bool const shouldAssemble = (queue_.size() == BATCH_SIZE);
    lk.unlock();

    if (shouldAssemble)
        assembleBatch();

    return RejectReason::Accepted;
}

// Apply one client entry to a tree. For Deposit, this is an append() since
// the commitment goes into a fresh slot. For Withdraw, this is an
// update_leaf() at the client-specified position (the slot must already
// exist, i.e. previous Deposit's append must have created it).
//
// Returns false if the operation would violate the tree's invariants —
// e.g. Withdraw against an index beyond the tree's current size. The caller
// should treat this as an internal/recoverable error: the entry can be
// re-queued, but it should not be committed.
static bool
applyOne(RollupMerkleTree& tree, ClientEntry const& e)
{
    try
    {
        if (e.entry.txType == RollupTxType::Deposit)
        {
            // New commitment into the next-free slot. The client's
            // `leaf_position` field is advisory for deposits — the
            // canonical position is whatever append() returns.
            tree.append(e.entry.commitment);
        }
        else  // Withdraw
        {
            // Replace existing commitment at the client-supplied position.
            // update_leaf throws std::out_of_range if the index
            // is beyond size().
            if (e.leaf_position >= tree.size())
                return false;
            tree.update_leaf(
                static_cast<std::size_t>(e.leaf_position),
                e.entry.commitment);
        }
        return true;
    }
    catch (std::exception const& ex)
    {
        std::cerr << "[seq] tree apply failed: " << ex.what() << std::endl;
        return false;
    }
}

uint256
RollupSequencer::dryRunRoot(std::vector<ClientEntry> const& es) const
{
    // RollupMerkleTree is non-copyable: it holds a std::mutex member.
    // The canonical "fresh dry-run copy"
    // pattern is to round-trip the frontier through serialiseFrontier()
    // / deserialiseFrontier(). The resulting `dryTree` mirrors localTree_'s
    // state without touching localTree_'s mutex or cached_nodes_ map.
    auto const frontier = localTree_.serialiseFrontier();
    RollupMerkleTree dryTree(treeDepth_);
    dryTree.deserialiseFrontier(frontier);

    for (auto const& e : es)
    {
        if (!applyOne(dryTree, e))
        {
            // Continue silently; the on-chain replay will catch this as a
            // root mismatch and reject the batch. Returning early would
            // throw off the iteration.
        }
    }

    return dryTree.root();
}

std::optional<BatchProof>
RollupSequencer::assembleBatch()
{
    // 1. Drain the queue under lock.
    std::vector<ClientEntry> entries;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (queue_.size() < BATCH_SIZE)
            return std::nullopt;
        entries.reserve(BATCH_SIZE);
        for (std::size_t i = 0; i < BATCH_SIZE; ++i)
        {
            entries.push_back(std::move(queue_.front()));
            queue_.pop_front();
        }
    }

    // 2. Refresh on-chain state.
    auto live = state_();
    if (!live)
    {
        std::cerr << "[seq] state_() returned nullopt; aborting assembly"
                  << std::endl;
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = entries.rbegin(); it != entries.rend(); ++it)
            queue_.push_front(std::move(*it));
        return std::nullopt;
    }
    {
        std::lock_guard<std::mutex> lk(mu_);
        lastKnown_ = *live;
    }

    // 3. Build the BatchProof shell.
    BatchProof bp;
    bp.batchId  = live->batchCounter + 1;
    bp.prevRoot = live->currentRoot;
    bp.newRoot  = dryRunRoot(entries);
    bp.txCount  = BATCH_SIZE;
    bp.entries.reserve(BATCH_SIZE);
    for (auto const& e : entries)
        bp.entries.push_back(e.entry);

    // 4. Concatenate the eight per-entry proofs into the single
    //    sfBatchProof.proof field. Each slot is exactly kEntryProofSlotBytes
    //    (192) bytes — must match BatchVerifier::splitEntryProofs() on the
    //    on-chain side. Zero-pad slots smaller than 192 bytes.
    constexpr std::size_t kEntryProofSlotBytes = 192;
    bp.proof.assign(BATCH_SIZE * kEntryProofSlotBytes, 0);
    for (std::size_t i = 0; i < BATCH_SIZE; ++i)
    {
        auto const& pb = entries[i].proof_bytes;
        if (pb.size() > kEntryProofSlotBytes)
        {
            std::cerr << "[seq] entry " << i << " proof is "
                      << pb.size() << " bytes (max "
                      << kEntryProofSlotBytes << "); aborting" << std::endl;
            return std::nullopt;
        }
        std::memcpy(
            bp.proof.data() + i * kEntryProofSlotBytes,
            pb.data(),
            pb.size());
    }

    // 5. Compute batchHash and sign it with Ed25519.
    //    batchHash = SHA256(batchId || prevRoot || newRoot || nf_0..nf_7)
    //    Off-circuit; mirrors BatchProof::computeBatchHash.
    uint256 const bh = bp.computeBatchHash();
    auto const sig = sign(seqPub_, seqPriv_, Slice(bh.data(), bh.size()));
    if (sig.size() != SEQUENCER_SIG_BYTES)
    {
        std::cerr << "[seq] Ed25519 signature size " << sig.size()
                  << " != " << SEQUENCER_SIG_BYTES << std::endl;
        return std::nullopt;
    }
    std::memcpy(bp.sequencerSig.data(), sig.data(), SEQUENCER_SIG_BYTES);

    // 6. Serialise and submit.
    auto const blob = bp.serialize();
    bool const accepted = submit_(blob);
    if (!accepted)
    {
        std::cerr << "[seq] submit_ returned false; batch dropped"
                  << std::endl;
        return std::nullopt;
    }

    // 7. Commit the dry-run leaf updates to the real local tree, and drop
    //    the pending nullifiers (now committed on-chain — or will be in
    //    the next validated ledger).
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto const& e : entries)
        {
            applyOne(localTree_, e);
            pendingNfs_.erase(e.entry.nullifier);
        }
    }
    return bp;
}

std::optional<BatchProof>
RollupSequencer::flush()
{
    std::size_t depth;
    {
        std::lock_guard<std::mutex> lk(mu_);
        depth = queue_.size();
    }
    if (depth < BATCH_SIZE)
    {
        // This prototype does not pad the batch.
        return std::nullopt;
    }
    return assembleBatch();
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple