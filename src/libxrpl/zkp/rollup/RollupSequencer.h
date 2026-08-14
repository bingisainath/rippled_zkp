// RollupSequencer: Track 1's off-chain batch assembly service.
//
//   1. Accepts ClientEntry submissions, each a per-entry Groth16 proof plus
//      the private witness needed for tree placement.
//   2. Validates each entry's standalone proof on receipt, so a batch is
//      never submitted containing a known-invalid entry.
//   3. Rejects duplicate nullifiers within the pending queue.
//   4. On reaching BATCH_SIZE (8), assembles a BatchProof, computes newRoot
//      by a dry-run update_leaf() against a temporary clone of the local
//      tree, signs batchHash with Ed25519 and submits via the SubmitFn
//      callback (in production, a POST to rippled's JSON-RPC `submit`).
//   5. Commits the dry-run leaf updates to the real tree once the
//      submission is accepted.
//
// Acknowledged limitation: this is a single-process sequencer. Distributed
// operation is out of scope.

#ifndef RIPPLE_ZKP_ROLLUP_ROLLUP_SEQUENCER_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ROLLUP_SEQUENCER_H_INCLUDED

#include <libxrpl/zkp/rollup/BatchProof.h>
#include <libxrpl/zkp/rollup/RollupMerkleTree.h>
#include <libxrpl/zkp/rollup/RollupNote.h>
#include <libxrpl/zkp/rollup/RollupProver.h>

#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/SecretKey.h>

#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {

// Reason a sequencer-side submission was accepted or rejected.
// Sequencer-internal only; never reaches TER.
enum class RejectReason
{
    Accepted,
    QueueFull,
    DuplicateNullifierInQueue,
    InvalidProof,
    InvalidEntry,
    ProverNotInitialized,
};

inline char const*
toString(RejectReason r)
{
    switch (r)
    {
        case RejectReason::Accepted: return "Accepted";
        case RejectReason::QueueFull: return "QueueFull";
        case RejectReason::DuplicateNullifierInQueue:
            return "DuplicateNullifierInQueue";
        case RejectReason::InvalidProof: return "InvalidProof";
        case RejectReason::InvalidEntry: return "InvalidEntry";
        case RejectReason::ProverNotInitialized:
            return "ProverNotInitialized";
    }
    return "Unknown";
}

// One client submission: wire-format entry + the per-entry Groth16 proof
// + the private witness fields the sequencer needs to compute newRoot.
struct ClientEntry
{
    RollupTxEntry entry;                     // public, on-the-wire portion
    std::vector<unsigned char> proof_bytes;  // per-entry Groth16 proof
    std::uint64_t leaf_position;             // position in the Poseidon IMT
    // The sequencer doesn't need ask / rho / r — those stay client-side.
    // newRoot is computed purely from (leaf_position, entry.commitment).
};

// Current on-chain RollupState SLE snapshot. Sequencer fetches this before
// every assembly to bind the next batch's prevRoot and batchId correctly.
struct LiveState
{
    uint256 currentRoot;
    std::uint32_t batchCounter;
};

// Sequencer callbacks.
//
// SubmitFn: production = hex-encode the wire blob and POST to rippled
//   /v1/submit. Tests = lambda that captures the blob.
//   Returns true on rippled-accepted-into-mempool (preflight passed).
using SubmitFn =
    std::function<bool(std::vector<std::uint8_t> const& txBlob)>;

// StateFn: production = JSON-RPC `account_objects` filtered to
//   ltROLLUP_STATE; tests = stub.
using StateFn = std::function<std::optional<LiveState>()>;

class RollupSequencer
{
public:
    // The sequencer key pair MUST match sfSequencerKey anchored at genesis
    // treeDepth MUST equal kRollupTreeDepth, to match the on-chain
    // RollupState.sfRollupTreeDepth. The constructor enforces this.
    RollupSequencer(
        PublicKey const& seqPub,
        SecretKey const& seqPriv,
        std::size_t treeDepth,
        SubmitFn submit,
        StateFn state);

    // Submit a single client entry. Validates the per-entry proof and
    // enqueues. When the queue reaches BATCH_SIZE, triggers assembleBatch()
    // synchronously (single-process L4 limitation).
    RejectReason
    submitEntry(ClientEntry e);

    // Force assembly of whatever is in the queue. Returns the submitted
    // BatchProof on success. Returns std::nullopt if the queue is not yet
    // full; this prototype does not pad and has no timed flush.
    std::optional<BatchProof>
    flush();

    // Diagnostics.
    std::size_t
    queueDepth() const;
    std::uint32_t
    pendingBatchId() const;

private:
    std::optional<BatchProof>
    assembleBatch();

    // Compute newRoot by applying update_leaf() to a CLONE of localTree_.
    // The clone is discarded. localTree_ is mutated only after submit
    // succeeds (see assembleBatch).
    uint256
    dryRunRoot(std::vector<ClientEntry> const& es) const;

    bool
    isEntryWellFormed(ClientEntry const& e) const;

    PublicKey seqPub_;
    SecretKey seqPriv_;
    std::size_t treeDepth_;
    SubmitFn submit_;
    StateFn state_;

    mutable std::mutex mu_;
    std::deque<ClientEntry> queue_;
    std::unordered_set<uint256> pendingNfs_;
    RollupMerkleTree localTree_;
    LiveState lastKnown_{uint256{}, 0};
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ROLLUP_SEQUENCER_H_INCLUDED