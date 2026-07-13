//------------------------------------------------------------------------------
/*
    Phase 6 — Track 2 rollup state SLE helpers.
*/
//==============================================================================

#include <libxrpl/zkp/rollup/RollupState2.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>
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

uint256
emptyAccountTreeRoot(std::size_t depth)
{
    PoseidonHash::initialize();
    // Leaf-0 convention: an empty leaf is FieldT(0); fold Poseidon up `depth`
    // levels over an all-empty tree. Matches BatchCircuit / the test trees.
    FieldT cur = FieldT::zero();
    for (std::size_t i = 0; i < depth; ++i)
        cur = PoseidonHash::hash(cur, cur);
    return PoseidonHash::fieldToUint256(cur);
}

uint256 const&
kGenesisRollup2Root()
{
    static uint256 const root = []() {
        PoseidonHash::initialize();
        BabyJubjub::initialize();
        return emptyAccountTreeRoot(kRollupTreeDepth);
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

    view.insert(sle);
    return sle;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
