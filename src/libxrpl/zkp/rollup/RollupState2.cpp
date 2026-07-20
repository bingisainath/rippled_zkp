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
#include <xrpl/protocol/STArray.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STObject.h>
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

std::vector<RollupState2::DepositClaim>
RollupState2::depositClaims(STLedgerEntry const& sle)
{
    std::vector<DepositClaim> out;
    if (!sle.isFieldPresent(sfDepositClaims))
        return out;  // pre-queue state SLE: no outstanding claims

    auto const& arr = sle.getFieldArray(sfDepositClaims);
    out.reserve(arr.size());
    for (auto const& o : arr)
        out.push_back({o.getFieldH256(sfDepositApk),
                       o.getFieldU64(sfClaimDrops)});
    return out;
}

void
RollupState2::setDepositClaims(
    STLedgerEntry& sle,
    std::vector<DepositClaim> const& claims)
{
    STArray arr(sfDepositClaims, claims.size());
    for (auto const& c : claims)
    {
        auto o = STObject::makeInnerObject(sfDepositClaim);
        o.setFieldH256(sfDepositApk, c.apk);
        o.setFieldU64(sfClaimDrops, c.drops);
        arr.push_back(std::move(o));
    }
    sle.setFieldArray(sfDepositClaims, arr);

    // Keep the aggregate in step: it is a cache of this array, and preclaim's
    // fast path trusts it.
    std::uint64_t total = 0;
    for (auto const& c : claims)
        total += c.drops;
    sle.setFieldU64(sfPendingDeposits, total);
}

std::uint64_t
RollupState2::pendingDeposits(STLedgerEntry const& sle)
{
    // soeOPTIONAL: a state SLE created before backed deposits existed has no
    // such field, and "no escrowed drops" is the correct reading.
    return sle.isFieldPresent(sfPendingDeposits)
        ? sle.getFieldU64(sfPendingDeposits)
        : 0;
}

AccountID
RollupState2::escrowAccount(STLedgerEntry const& sle)
{
    return sle.isFieldPresent(sfEscrowAccount)
        ? sle.getAccountID(sfEscrowAccount)
        : AccountID{};
}

void
RollupState2::setBatchCounter(STLedgerEntry& sle, std::uint32_t v)
{
    sle.setFieldU32(sfBatchCounter, v);
}

void
RollupState2::setPendingDeposits(STLedgerEntry& sle, std::uint64_t v)
{
    sle.setFieldU64(sfPendingDeposits, v);
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
    std::vector<std::uint8_t> const& sequencerPubKey,
    AccountID const& escrow)
{
    auto const k = keylet::rollup_state2();
    auto sle = std::make_shared<STLedgerEntry>(k);

    sle->setFieldU32(sfBatchCounter, 0);
    sle->setFieldH256(sfRollupRoot, kGenesisRollup2Root());
    sle->setFieldVL(sfSequencerKey, sequencerPubKey);
    sle->setFieldU8(sfRollupTreeDepth, kRollupTreeDepth);
    sle->setFieldU32(sfOwnerCount, 0);
    sle->setFieldU64(sfPendingDeposits, 0);
    sle->setAccountID(sfEscrowAccount, escrow);

    view.insert(sle);
    return sle;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
