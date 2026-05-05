//------------------------------------------------------------------------------
/*
    Phase 1 — Foundation: RollupState SLE helper implementation.
*/
//==============================================================================

#include <libxrpl/zkp/rollup/RollupState.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpld/ledger/ApplyView.h>
#include <xrpld/ledger/ReadView.h>

namespace ripple {
namespace zkp {
namespace rollup {

// =============================================================================
// Read helpers
// =============================================================================

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

// =============================================================================
// Write helpers
// =============================================================================

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

// =============================================================================
// Lookup
// =============================================================================

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

// =============================================================================
// Genesis creation
// =============================================================================
// Called exactly once — the first time any BatchRollup transaction reaches
// doApply() and finds no RollupState SLE. Subsequent batches update the
// existing SLE; they never call this path.
// =============================================================================

std::shared_ptr<STLedgerEntry>
RollupState::createGenesis(
    ApplyView& view,
    std::vector<std::uint8_t> const& sequencerPubKey)
{
    auto const k = keylet::rollup_state();
    auto sle = std::make_shared<STLedgerEntry>(k);

    // Invariants at genesis (before the first batch commit bumps the counter).
    sle->setFieldU32(sfBatchCounter, 0);
    sle->setFieldH256(sfRollupRoot, kGenesisRollupRoot());
    sle->setFieldVL(sfSequencerKey, sequencerPubKey);
    sle->setFieldU8(sfRollupTreeDepth, kRollupTreeDepth);
    sle->setFieldU32(sfOwnerCount, 0);

    view.insert(sle);
    return sle;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple