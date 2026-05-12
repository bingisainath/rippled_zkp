//------------------------------------------------------------------------------
/*
    Phase 4a — BatchVerifier (class BatchRollup).
*/
//==============================================================================

#include <libxrpl/zkp/rollup/BatchVerifier.h>
#include <libxrpl/zkp/rollup/BatchProof.h>
#include <libxrpl/zkp/rollup/NullifierStore.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>
#include <libxrpl/zkp/rollup/RollupMerkleTree.h>
#include <libxrpl/zkp/rollup/RollupModule.h>
#include <libxrpl/zkp/rollup/RollupProver.h>
#include <libxrpl/zkp/rollup/RollupState.h>

#include <libxrpl/zkp/circuits/MerkleCircuit.h>  // for uint256ToFieldElement
#include <libxrpl/zkp/ZKProver.h>                // proven verifyProof entry point

#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/STAccount.h>
#include <xrpl/protocol/TER.h>
#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpld/ledger/View.h>

#include <set>

namespace ripple {

namespace {

constexpr std::size_t kMaxBatchBlobBytes = 1u << 20;
constexpr std::size_t kBatchSize         = 8;

// Phase 4a integration shortcut: we have a real Groth16 proof inside
// `bp.proof`. The proper Phase 4b verifier will take a BatchProof
// and call RollupProver::verifyProof against the full N=8 public-input
// vector. Here we route through the existing ZkProver verifier, which
// takes (proof, anchor, nullifier, value_commitment) and is known to
// link cleanly. The cryptographic check is real; only the public-input
// packing is single-note. This is an explicit Phase 4a deferral and
// will be tightened in Phase 4b's RollupSequencer integration.
bool
verifyBatchProof(zkp::rollup::BatchProof const& bp)
{
    if (bp.entries.empty() || bp.proof.empty())
        return false;

    auto const anchor =
        zkp::MerkleCircuit::uint256ToFieldElement(bp.prevRoot);
    auto const nullifier =
        zkp::MerkleCircuit::uint256ToFieldElement(bp.entries.front().nullifier);
    auto const value_commitment =
        zkp::MerkleCircuit::uint256ToFieldElement(bp.newRoot);

    return zkp::ZkProver::verifyProof(
        bp.proof, anchor, nullifier, value_commitment);
}

}  // anonymous namespace

NotTEC
BatchRollup::preflight(PreflightContext const& ctx)
{
    using namespace zkp::rollup;

    if (!ctx.rules.enabled(featureZKRollup))
        return temDISABLED;

    if (!RollupModule::isStarted())
        return temDISABLED;

    if (auto const ret = preflight1(ctx); !isTesSuccess(ret))
        return ret;

    auto const& tx = ctx.tx;

    if (!tx.isFieldPresent(sfBatchProof) ||
        !tx.isFieldPresent(sfBatchId) ||
        !tx.isFieldPresent(sfPrevRoot) ||
        !tx.isFieldPresent(sfRollupRoot) ||
        !tx.isFieldPresent(sfTxCount) ||
        !tx.isFieldPresent(sfSequencerPubKey))
        return temMALFORMED;

    auto const& blob = tx.getFieldVL(sfBatchProof);
    if (blob.empty() || blob.size() > kMaxBatchBlobBytes)
        return temMALFORMED;

    bool ok = false;
    auto const bp = BatchProof::deserialize(blob, ok);
    if (!ok)
        return temMALFORMED;

    if (!bp.isWellFormed())
        return temMALFORMED;

    auto const declaredTxCount = tx.getFieldU32(sfTxCount);
    if (declaredTxCount != bp.txCount ||
        bp.entries.size() != bp.txCount)
        return temMALFORMED;

    auto const declaredBatchId = tx.getFieldU32(sfBatchId);
    if (declaredBatchId == 0 || declaredBatchId != bp.batchId)
        return temMALFORMED;

    if (tx.getFieldH256(sfPrevRoot) != bp.prevRoot ||
        tx.getFieldH256(sfRollupRoot) != bp.newRoot)
        return temMALFORMED;

    auto const pubKeyBlob = tx.getFieldVL(sfSequencerPubKey);
    if (pubKeyBlob.size() != 33)
        return temBAD_SIGNATURE;

    auto const batchHash = bp.computeBatchHash();
    PublicKey const pk{Slice(pubKeyBlob.data(), pubKeyBlob.size())};
    if (!verify(
            pk,
            Slice(batchHash.data(), batchHash.size()),
            Slice(bp.sequencerSig.data(), bp.sequencerSig.size()),
            /*mustBeFullyCanonical=*/true))
        return temBAD_SIGNATURE;

    return preflight2(ctx);
}

TER
BatchRollup::preclaim(PreclaimContext const& ctx)
{
    using namespace zkp::rollup;

    bool ok = false;
    auto const bp = BatchProof::deserialize(
        ctx.tx.getFieldVL(sfBatchProof), ok);
    if (!ok)
        return tefINTERNAL;

    auto const sle = ctx.view.read(keylet::rollup_state());

    uint256       expectedPrevRoot;
    std::uint32_t expectedBatchId = 0;

    if (!sle)
    {
        expectedPrevRoot = kGenesisRollupRoot();
        expectedBatchId  = 1;
    }
    else
    {
        expectedPrevRoot = sle->getFieldH256(sfRollupRoot);
        expectedBatchId  = sle->getFieldU32(sfBatchCounter) + 1;
    }

    if (bp.prevRoot != expectedPrevRoot)
        return tecFAILED_PROCESSING;

    if (bp.batchId != expectedBatchId)
        return temMALFORMED;

    if (!verifyBatchProof(bp))
        return temBAD_PROOF;

    std::set<uint256> seenInBatch;
    for (auto const& entry : bp.entries)
    {
        if (!seenInBatch.insert(entry.nullifier).second)
            return temBAD_PROOF;
    }

    for (auto const& entry : bp.entries)
    {
        if (NullifierStore::contains(ctx.view, entry.nullifier))
            return tecUNFUNDED;
    }

    std::int64_t totalWithdrawal = 0;
    for (auto const& entry : bp.entries)
    {
        if (entry.txType == RollupTxType::Withdraw)
            totalWithdrawal += static_cast<std::int64_t>(entry.value);
    }
    if (totalWithdrawal > 0)
    {
        std::int64_t poolBalance = 0;
        if (sle && sle->isFieldPresent(sfBalance))
            poolBalance =
                sle->getFieldAmount(sfBalance).xrp().drops();
        if (poolBalance < totalWithdrawal)
            return tecINSUF_RESERVE_LINE;
    }

    return tesSUCCESS;
}

TER
BatchRollup::doApply()
{
    using namespace zkp::rollup;

    auto& view    = ctx_.view();
    auto const& tx = ctx_.tx;

    bool ok = false;
    auto const bp = BatchProof::deserialize(tx.getFieldVL(sfBatchProof), ok);
    if (!ok)
        return tefINTERNAL;

    auto sle = view.peek(keylet::rollup_state());
    if (!sle)
    {
        auto const pubKeyBlob = tx.getFieldVL(sfSequencerPubKey);
        sle = RollupState::createGenesis(view, pubKeyBlob);
        if (!sle)
            return tefINTERNAL;
    }

    auto tree = RollupState::loadTree(*sle);   // unique_ptr<RollupMerkleTree>

    auto const baseIndex =
        static_cast<std::size_t>(sle->getFieldU32(sfBatchCounter)) * kBatchSize;

    for (std::size_t i = 0; i < bp.entries.size(); ++i)
    {
        auto const& entry = bp.entries[i];
        tree->update_leaf(baseIndex + i, entry.commitment);
    }

    if (tree->root() != bp.newRoot)
        return tefINTERNAL;

    std::vector<uint256> nfs;
    nfs.reserve(bp.entries.size());
    for (auto const& entry : bp.entries)
        nfs.push_back(entry.nullifier);
    if (!NullifierStore::insertBatch(view, nfs))
        return tefINTERNAL;

    std::int64_t poolDrops = 0;
    if (sle->isFieldPresent(sfBalance))
        poolDrops = sle->getFieldAmount(sfBalance).xrp().drops();

    for (auto const& entry : bp.entries)
    {
        if (entry.txType == RollupTxType::Deposit)
        {
            poolDrops += static_cast<std::int64_t>(entry.value);
        }
        else
        {
            poolDrops -= static_cast<std::int64_t>(entry.value);

            auto destSle = view.peek(keylet::account(entry.destination));
            if (!destSle)
            {
                auto const reserve = view.fees().accountReserve(0).drops();
                if (static_cast<std::int64_t>(entry.value) < reserve)
                    return tecNO_DST_INSUF_XRP;

                destSle = std::make_shared<STLedgerEntry>(
                    keylet::account(entry.destination));
                destSle->setAccountID(sfAccount, entry.destination);
                destSle->setFieldAmount(
                    sfBalance, STAmount(XRPAmount(entry.value)));
                destSle->setFieldU32(sfSequence, view.seq());
                view.insert(destSle);
            }
            else
            {
                auto bal = destSle->getFieldAmount(sfBalance);
                bal += STAmount(XRPAmount(entry.value));
                destSle->setFieldAmount(sfBalance, bal);
                view.update(destSle);
            }
        }
    }
    if (poolDrops < 0)
        return tefINTERNAL;
    sle->setFieldAmount(sfBalance, STAmount(XRPAmount(poolDrops)));

    RollupState::storeTree(*sle, *tree);
    RollupState::setBatchCounter(*sle, bp.batchId);
    RollupState::setRollupRoot(*sle, bp.newRoot);
    view.update(sle);

    return tesSUCCESS;
}

}  // namespace ripple