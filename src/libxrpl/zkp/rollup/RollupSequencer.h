// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// RollupSequencer: off-chain batch assembly service (v2.2 Figure 6).
//
// Responsibilities:
//   1. Accept ClientEntry submissions (per-entry Groth16 proof + private
//      witness for tree placement).
//   2. Validate each entry's standalone Poseidon proof on receipt
//      (RollupProver::verifyProof) so we never submit a batch containing
//      a known-invalid entry.
//   3. Reject duplicate nullifiers within the pending queue.
//   4. When the queue reaches BATCH_SIZE (= 8): assemble a BatchProof,
//      perform a dry-run update_leaf() on a temporary clone of the local
//      Merkle tree to compute newRoot, sign batchHash with Ed25519, and
//      submit via the SubmitFn callback (production: libcurl POST to
//      rippled's JSON-RPC `submit` with hex-encoded tx_blob).
//   5. After submission acceptance, commit the dry-run leaf updates to
//      the real local tree.
//
// L4 limitation acknowledged (v2.2 §2.3): single-process sequencer.
// Distributed operation is outside Phase 4b's scope.

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
    // (Phase 1 §5.3.1). Tree depth MUST be 32 to match the on-chain
    // RollupState.sfRollupTreeDepth.
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
    // full (Phase 4b prototype does not pad; Phase 5 may add timed flushes).
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