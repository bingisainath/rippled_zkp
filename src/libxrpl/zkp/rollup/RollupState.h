//------------------------------------------------------------------------------
/*
    This file is part of rippled_zkp: ZK-Rollup extension for XRPL.
    Copyright (c) 2026 Trinity College Dublin (MSc dissertation).

    Phase 1 — Foundation: RollupState SLE access helpers.
    See v2.2 §5.1 for the field specification.
*/
//==============================================================================

#ifndef RIPPLE_ZKP_ROLLUP_ROLLUPSTATE_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ROLLUPSTATE_H_INCLUDED

#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>

#include <cstdint>
#include <memory>

namespace ripple {

// Forward declarations so we don't transitively include heavy headers.
class ApplyView;
class ReadView;

namespace zkp {
namespace rollup {

// =============================================================================
// RollupState — the singleton on-chain state SLE (ltROLLUP_STATE = 0x0084)
//
// Fields (v2.2 §5.1 confirmed codes):
//   sfBatchCounter     UInt32  / 78   — monotonic sequence, replay prevention
//   sfRollupRoot       Hash256 / 34   — Poseidon root after last committed batch
//   sfSequencerKey     Blob    / 36   — Ed25519 public key of authorised sequencer
//   sfRollupTreeDepth  UInt8   /  6   — circuit tree depth (= 32 for prototype)
//   sfOwnerCount       UInt32 existing — required by XRPL SLE framework
//
// Phase 1 only writes sfBatchCounter and sfRollupRoot in doApply().
// sfSequencerKey and sfRollupTreeDepth are set once at genesis (first batch)
// and never mutated again (immutable across the dissertation lifetime).
// =============================================================================

/** Fixed circuit depth for the prototype — v2.2 Table 6. */
constexpr std::uint8_t kRollupTreeDepth = 32;

/** The Poseidon empty-tree root is not computable in Phase 1 (Phase 2 deliverable).
 *  Until Poseidon lands we use the all-zero sentinel: callers submitting the
 *  first batch set sfPrevRoot = uint256{} and the preclaim check uses the same
 *  sentinel. When Phase 2 lands, replace uses of kGenesisRollupRoot with the
 *  Poseidon empty-tree root computed from PoseidonCircuit::empty_tree_root(). */
inline uint256 const&
kGenesisRollupRoot()
{
    static uint256 const sentinel{};  // all zeros
    return sentinel;
}

/**
 * Thin RAII accessor around the RollupState SLE. Not a subclass of SLE —
 * just a typed facade that keeps the SField names in one place and makes
 * preclaim/doApply call-sites readable.
 *
 * Usage pattern:
 *   auto sle = RollupState::peek(view);
 *   if (!sle) { ... genesis path ... }
 *   auto counter = RollupState::batchCounter(*sle);
 */
class RollupState
{
public:
    // ---- Read helpers (work on any STLedgerEntry of type ltROLLUP_STATE) ----

    static std::uint32_t batchCounter(STLedgerEntry const& sle);
    static uint256       rollupRoot  (STLedgerEntry const& sle);
    static std::uint8_t  treeDepth   (STLedgerEntry const& sle);

    // ---- Write helpers ----

    static void setBatchCounter(STLedgerEntry& sle, std::uint32_t v);
    static void setRollupRoot  (STLedgerEntry& sle, uint256 const& r);

    // ---- Lookup ----

    /** Read-only lookup. Returns nullptr if the SLE does not yet exist
     *  (first batch scenario — valid state). */
    static std::shared_ptr<STLedgerEntry const>
    read(ReadView const& view);

    /** Mutable lookup (for doApply). Returns nullptr if the SLE does not
     *  yet exist. */
    static std::shared_ptr<STLedgerEntry>
    peek(ApplyView& view);

    /**
     * Create the genesis RollupState SLE. Called by doApply() when the
     * first batch commits and no SLE exists yet.
     *
     * Initial values:
     *   batchCounter    = 0 (before the batch commit; doApply bumps to 1)
     *   rollupRoot      = kGenesisRollupRoot()
     *   sequencerKey    = provided (copied from sfSequencerPubKey on the tx)
     *   rollupTreeDepth = kRollupTreeDepth
     *   ownerCount      = 0
     *
     * Returns the newly inserted SLE. Caller is responsible for setting
     * the mutable fields (counter, root) and calling view.update().
     */
    static std::shared_ptr<STLedgerEntry>
    createGenesis(ApplyView& view, std::vector<std::uint8_t> const& sequencerPubKey);
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ROLLUPSTATE_H_INCLUDED