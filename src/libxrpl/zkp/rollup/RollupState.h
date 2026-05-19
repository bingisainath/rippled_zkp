//------------------------------------------------------------------------------
/*
    This file is part of rippled_zkp: ZK-Rollup extension for XRPL.
    Phase 1 — Foundation; Phase 4a — frontier persistence.
*/
//==============================================================================

#ifndef RIPPLE_ZKP_ROLLUP_ROLLUPSTATE_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ROLLUPSTATE_H_INCLUDED

#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/SField.h>
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

constexpr std::uint8_t kRollupTreeDepth = 32;

inline uint256 const&
kGenesisRollupRoot()
{
    static uint256 const sentinel{};  // all zeros
    return sentinel;
}

class RollupState
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

    static std::shared_ptr<STLedgerEntry>
    createGenesis(ApplyView& view,
                  std::vector<std::uint8_t> const& sequencerPubKey);

    // Phase 4a: tree-frontier persistence.
    // RollupMerkleTree has a std::mutex (non-movable, non-copyable), so we
    // must return it by unique_ptr rather than by value.
    static std::unique_ptr<RollupMerkleTree>
    loadTree(STLedgerEntry const& sle);

    static void
    storeTree(STLedgerEntry& sle, RollupMerkleTree const& tree);
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif