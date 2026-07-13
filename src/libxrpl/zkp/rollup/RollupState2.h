//------------------------------------------------------------------------------
/*
    This file is part of rippled_zkp: ZK-Rollup extension for XRPL.
    Copyright (c) 2026 Trinity College Dublin (MSc dissertation).

    Phase 6 — Track 2 (Option A) rollup state SLE.

    Independent of Track 1's RollupState: separate keylet (rollup_state2) and
    a batch counter / account-tree root. The account tree lives OFF-CHAIN with
    the sequencer (rebuildable from published entries); L1 stores only the
    root and counter, so there is no on-chain tree/frontier here.

    Empty-leaf convention: leaf = FieldT(0), so the empty-tree root is Poseidon
    applied `depth` times to zero (P^depth(0)) — matching BatchCircuit. This is
    deliberately DIFFERENT from Track 1's RollupMerkleTree, which uses empty
    leaf = Poseidon(0,0). Keeping Track 2 on the circuit's convention is what
    makes genesis / sequencer / circuit roots agree.
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

// Empty account-tree root at the given depth under the leaf-0 convention:
// P^depth(0). Matches BatchCircuit; used for genesis and by the sequencer.
uint256
emptyAccountTreeRoot(std::size_t depth);

// The genesis prevRoot for batch 1 (empty tree at kRollupTreeDepth).
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

    // Creates the Track 2 state SLE with the empty-tree genesis root. Runs
    // once in a network's lifetime. No tree/frontier is stored (Track 2
    // keeps the tree off-chain).
    static std::shared_ptr<STLedgerEntry>
    createGenesis(ApplyView& view,
                  std::vector<std::uint8_t> const& sequencerPubKey);
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ROLLUPSTATE2_H_INCLUDED
