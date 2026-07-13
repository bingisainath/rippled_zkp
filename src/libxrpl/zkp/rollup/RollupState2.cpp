//------------------------------------------------------------------------------
/*
    Phase 6 — Track 2 rollup state SLE helpers.
*/
//==============================================================================

#include <libxrpl/zkp/rollup/RollupState2.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>
#include <libxrpl/zkp/rollup/RollupMerkleTree.h>
#include <libxrpl/zkp/rollup/RollupState.h>  // kRollupTreeDepth
#include <libxrpl/zkp/rollup/BabyJubjub.h>
#include <libxrpl/zkp/rollup/PoseidonHash.h>

#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpld/ledger/ApplyView.h>
#include <xrpld/ledger/ReadView.h>

namespace ripple {
namespace zkp {
namespace rollup {

uint256 const&
kGenesisRollup2Root()
{
    // Root of an EMPTY account tree — Track 2 leaves are created on demand,
    // so batch 1's prevRoot is the all-unoccupied root. Derived from the
    // same RollupMerkleTree doApply replays, so the two always agree.
    static uint256 const root = []() {
        PoseidonHash::initialize();
        BabyJubjub::initialize();
        RollupMerkleTree tree(kRollupTreeDepth);
        return tree.root();
    }();
    return root;
}

std::uint32_t
RollupState2::batchCounter(STLedgerEntry const& sle)
{
    return sle.getFieldU32(sfBatchCounter);
}

uint256
RollupState2::rollupRoot(STLedgerEntry const& sle)
{
    return sle.getFieldH256(sfRollupRoot);
}

std::uint8_t
RollupState2::treeDepth(STLedgerEntry const& sle)
{
    return sle.getFieldU8(sfRollupTreeDepth);
}

void
RollupState2::setBatchCounter(STLedgerEntry& sle, std::uint32_t v)
{
    sle.setFieldU32(sfBatchCounter, v);
}

void
RollupState2::setRollupRoot(STLedgerEntry& sle, uint256 const& r)
{
    sle.setFieldH256(sfRollupRoot, r);
}

std::shared_ptr<STLedgerEntry const>
RollupState2::read(ReadView const& view)
{
    return view.read(keylet::rollup_state2());
}

std::shared_ptr<STLedgerEntry>
RollupState2::peek(ApplyView& view)
{
    return view.peek(keylet::rollup_state2());
}

std::shared_ptr<STLedgerEntry>
RollupState2::createGenesis(
    ApplyView& view,
    std::vector<std::uint8_t> const& sequencerPubKey)
{
    auto const k = keylet::rollup_state2();
    auto sle = std::make_shared<STLedgerEntry>(k);

    sle->setFieldU32(sfBatchCounter, 0);
    sle->setFieldH256(sfRollupRoot, kGenesisRollup2Root());
    sle->setFieldVL(sfSequencerKey, sequencerPubKey);
    sle->setFieldU8(sfRollupTreeDepth, kRollupTreeDepth);
    sle->setFieldU32(sfOwnerCount, 0);

    // EMPTY tree — no pre-loaded leaves (the Track 2 growable-tree property).
    RollupMerkleTree tree(kRollupTreeDepth);
    storeTree(*sle, tree);

    view.insert(sle);
    return sle;
}

std::unique_ptr<RollupMerkleTree>
RollupState2::loadTree(STLedgerEntry const& sle)
{
    auto const depth = sle.getFieldU8(sfRollupTreeDepth);
    auto tree = std::make_unique<RollupMerkleTree>(depth);

    if (sle.isFieldPresent(sfTreeFrontier))
    {
        auto const blob = sle.getFieldVL(sfTreeFrontier);
        if (!blob.empty())
            tree->deserialiseFrontier(blob);
    }
    return tree;
}

void
RollupState2::storeTree(STLedgerEntry& sle, RollupMerkleTree const& tree)
{
    sle.setFieldVL(sfTreeFrontier, tree.serialiseFrontier());
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
