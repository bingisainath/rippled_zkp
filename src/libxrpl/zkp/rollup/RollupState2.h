//------------------------------------------------------------------------------
/*
    This file is part of rippled_zkp: ZK-Rollup extension for XRPL.
    Copyright (c) 2026 Trinity College Dublin (MSc dissertation).

    Phase 6 — Track 2 (Option A) rollup state SLE.

    Independent of Track 1's RollupState: separate keylet (rollup_state2),
    an ACCOUNT-leaf tree that starts EMPTY and grows (leaves created on
    demand), and the batch counter / root for the single-proof batches.
*/
//==============================================================================

#ifndef RIPPLE_ZKP_ROLLUP_ROLLUPSTATE2_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ROLLUPSTATE2_H_INCLUDED

#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/STLedgerEntry.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace ripple {

class ApplyView;
class ReadView;

namespace zkp {
namespace rollup {

class RollupMerkleTree;

// The genesis root of an EMPTY account tree at the given depth (all leaves
// unoccupied). This is the prevRoot the sequencer must use for batch 1, and
// what preclaim checks when no RollupState2 SLE exists yet. Derived from an
// empty RollupMerkleTree so it stays consistent with doApply's replay.
uint256 const&
kGenesisRollup2Root();

class RollupState2
{
public:
    static std::uint32_t batchCounter(STLedgerEntry const& sle);
    static uint256       rollupRoot  (STLedgerEntry const& sle);
    static std::uint8_t  treeDepth   (STLedgerEntry const& sle);

    static void setBatchCounter(STLedgerEntry& sle, std::uint32_t v);
    static void setRollupRoot  (STLedgerEntry& sle, uint256 const& r);

    static std::shared_ptr<STLedgerEntry const>
    read(ReadView const& view);

    static std::shared_ptr<STLedgerEntry>
    peek(ApplyView& view);

    // Creates the Track 2 state SLE with an EMPTY account tree (no
    // pre-loaded leaves — Track 2 leaves are created on demand). Runs once
    // in a network's lifetime.
    static std::shared_ptr<STLedgerEntry>
    createGenesis(ApplyView& view,
                  std::vector<std::uint8_t> const& sequencerPubKey);

    static std::unique_ptr<RollupMerkleTree>
    loadTree(STLedgerEntry const& sle);

    static void
    storeTree(STLedgerEntry& sle, RollupMerkleTree const& tree);
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ROLLUPSTATE2_H_INCLUDED
