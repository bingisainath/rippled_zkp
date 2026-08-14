/*
    RollupState SLE helpers.
*/

#include <libxrpl/zkp/rollup/RollupState.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>
#include <libxrpl/zkp/rollup/RollupMerkleTree.h>
#include <libxrpl/zkp/rollup/RollupNote.h>
#include <libxrpl/zkp/rollup/BabyJubjub.h>
#include <libxrpl/zkp/rollup/PoseidonHash.h>
#include <libxrpl/zkp/circuits/MerkleCircuit.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpld/ledger/ApplyView.h>
#include <xrpld/ledger/ReadView.h>

namespace ripple {
namespace zkp {
namespace rollup {

// Genesis root: root of a depth-32 Poseidon tree pre-seeded with 8 null-note
// commitments (one per genesis leaf slot). Seeds 0..7 produce deterministic,
// distinct notes so their nullifiers are all unique (avoiding in-batch
// duplicate rejection on the first real batch).
uint256 const&
kGenesisRollupRoot()
{
    static uint256 const root = []() {
        PoseidonHash::initialize();
        BabyJubjub::initialize();
        RollupMerkleTree tree(kRollupTreeDepth);
        for (std::uint64_t i = 0; i < kRollupBatchSize; ++i)
        {
            RollupNote n = RollupNote::createRandom(0, i);
            tree.append(PoseidonHash::fieldToUint256(n.commitment()));
        }
        return tree.root();
    }();
    return root;
}

std::uint32_t
RollupState::batchCounter(STLedgerEntry const& sle)
{
    return sle.getFieldU32(sfBatchCounter);
}

uint256
RollupState::rollupRoot(STLedgerEntry const& sle)
{
    return sle.getFieldH256(sfRollupRoot);
}

std::uint8_t
RollupState::treeDepth(STLedgerEntry const& sle)
{
    return sle.getFieldU8(sfRollupTreeDepth);
}

void
RollupState::setBatchCounter(STLedgerEntry& sle, std::uint32_t v)
{
    sle.setFieldU32(sfBatchCounter, v);
}

void
RollupState::setRollupRoot(STLedgerEntry& sle, uint256 const& r)
{
    sle.setFieldH256(sfRollupRoot, r);
}

std::shared_ptr<STLedgerEntry const>
RollupState::read(ReadView const& view)
{
    return view.read(keylet::rollup_state());
}

std::shared_ptr<STLedgerEntry>
RollupState::peek(ApplyView& view)
{
    return view.peek(keylet::rollup_state());
}

std::shared_ptr<STLedgerEntry>
RollupState::createGenesis(
    ApplyView& view,
    std::vector<std::uint8_t> const& sequencerPubKey)
{
    auto const k = keylet::rollup_state();
    auto sle = std::make_shared<STLedgerEntry>(k);

    sle->setFieldU32(sfBatchCounter, 0);
    sle->setFieldH256(sfRollupRoot, kGenesisRollupRoot());
    sle->setFieldVL(sfSequencerKey, sequencerPubKey);
    sle->setFieldU8(sfRollupTreeDepth, kRollupTreeDepth);
    sle->setFieldU32(sfOwnerCount, 0);

    // Pre-load the Merkle tree with the 8 genesis null-note commitments so
    // that doApply()'s update_leaf(0..7) finds existing leaves to update.
    RollupMerkleTree tree(kRollupTreeDepth);
    for (std::uint64_t i = 0; i < kRollupBatchSize; ++i)
    {
        RollupNote n = RollupNote::createRandom(0, i);
        tree.append(PoseidonHash::fieldToUint256(n.commitment()));
    }
    storeTree(*sle, tree);

    view.insert(sle);
    return sle;
}

std::unique_ptr<RollupMerkleTree>
RollupState::loadTree(STLedgerEntry const& sle)
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
RollupState::storeTree(STLedgerEntry& sle, RollupMerkleTree const& tree)
{
    auto const blob = tree.serialiseFrontier();
    sle.setFieldVL(sfTreeFrontier, blob);
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple