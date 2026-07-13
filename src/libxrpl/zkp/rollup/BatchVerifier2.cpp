//------------------------------------------------------------------------------
/*
    Phase 6 — Track 2 transactor (ttBATCH_ROLLUP2 = 62). See BatchVerifier2.h.
*/
//==============================================================================

#include <libxrpl/zkp/rollup/BatchVerifier2.h>
#include <libxrpl/zkp/rollup/BatchCircuitProver.h>
#include <libxrpl/zkp/rollup/BatchProof2.h>
#include <libxrpl/zkp/rollup/PoseidonHash.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>
#include <libxrpl/zkp/rollup/RollupModule.h>
#include <libxrpl/zkp/rollup/RollupState2.h>

#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpld/ledger/ApplyView.h>
#include <xrpld/ledger/View.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/TxFlags.h>

namespace ripple {

using namespace zkp::rollup;

NotTEC
BatchRollup2::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureZKRollup2))
        return temDISABLED;

    if (!RollupModule::isStarted())
        return temDISABLED;
    if (!BatchCircuitProver::isInitialized())
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
    if (blob.empty() || blob.size() > MAX_BATCH2_BLOB_BYTES)
        return temMALFORMED;

    bool ok = false;
    auto const bp = BatchProof2::deserialize(blob, ok);
    if (!ok || !bp.isWellFormed())
        return temMALFORMED;

    if (tx.getFieldU32(sfTxCount) != bp.txCount ||
        bp.entries.size() != bp.txCount)
        return temMALFORMED;

    auto const declaredBatchId = tx.getFieldU32(sfBatchId);
    if (declaredBatchId == 0 || declaredBatchId != bp.batchId)
        return temMALFORMED;

    if (tx.getFieldH256(sfPrevRoot) != bp.prevRoot ||
        tx.getFieldH256(sfRollupRoot) != bp.newRoot)
        return temMALFORMED;

    // ONE Groth16 proof — reject an implausibly sized blob before preclaim
    // spends any pairing cycles (also the malformed-proof DoS guard).
    if (bp.proof.size() < 64 || bp.proof.size() > 256)
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
BatchRollup2::preclaim(PreclaimContext const& ctx)
{
    bool ok = false;
    auto const bp =
        BatchProof2::deserialize(ctx.tx.getFieldVL(sfBatchProof), ok);
    if (!ok)
        return tefINTERNAL;

    auto const sle = ctx.view.read(keylet::rollup_state2());

    uint256 expectedPrevRoot;
    std::uint32_t expectedBatchId = 0;
    if (!sle)
    {
        expectedPrevRoot = kGenesisRollup2Root();
        expectedBatchId = 1;
    }
    else
    {
        expectedPrevRoot = sle->getFieldH256(sfRollupRoot);
        expectedBatchId = sle->getFieldU32(sfBatchCounter) + 1;
    }

    // Root-chain: this batch must start where the last one ended.
    if (bp.prevRoot != expectedPrevRoot)
        return tecFAILED_PROCESSING;
    // Strictly the next batch id.
    if (bp.batchId != expectedBatchId)
        return temMALFORMED;

    // Pool solvency for withdrawals (fail fast before the pairing check).
    std::int64_t totalWithdrawal = 0;
    for (auto const& e : bp.entries)
    {
        if (e.txType == RequestType::Withdraw)
            totalWithdrawal += static_cast<std::int64_t>(e.value);
    }
    if (totalWithdrawal > 0)
    {
        std::int64_t poolBalance = 0;
        if (sle && sle->isFieldPresent(sfBalance))
            poolBalance = sle->getFieldAmount(sfBalance).xrp().drops();
        if (poolBalance < totalWithdrawal)
            return tecINSUF_RESERVE_LINE;
    }

    // THE Track 2 win: ONE Groth16 verify binds the whole batch. entriesHash
    // is recomputed natively from the blob entries, tying the published data
    // to the proven statement.
    FieldT const prevF = PoseidonHash::uint256ToField(bp.prevRoot);
    FieldT const newF = PoseidonHash::uint256ToField(bp.newRoot);
    FieldT const ehF = bp.computeEntriesHash();

    JLOG(ctx.j.info())
        << "BatchRollup2: preclaim running ONE Groth16 verify (batch of "
        << bp.txCount << ")";
    if (!BatchCircuitProver::verifyBatch(prevF, newF, ehF, bp.proof))
    {
        JLOG(ctx.j.warn()) << "BatchRollup2: verifyBatch FAILED → temBAD_PROOF";
        return temBAD_PROOF;
    }
    JLOG(ctx.j.info()) << "BatchRollup2: batch proof VERIFIED";
    return tesSUCCESS;
}

TER
BatchRollup2::doApply()
{
    auto& view = ctx_.view();
    auto const& tx = ctx_.tx;

    bool ok = false;
    auto const bp =
        BatchProof2::deserialize(tx.getFieldVL(sfBatchProof), ok);
    if (!ok)
        return tefINTERNAL;

    auto sle = view.peek(keylet::rollup_state2());
    if (!sle)
    {
        sle = RollupState2::createGenesis(
            view, tx.getFieldVL(sfSequencerPubKey));
        if (!sle)
            return tefINTERNAL;
    }

    // No on-chain tree replay: the proof (verified in preclaim) already
    // binds prevRoot -> newRoot, so L1 commits newRoot directly. The
    // account tree lives off-chain with the sequencer, rebuildable from the
    // entries published in this and prior batch blobs (data availability).

    // Escrow bridge (prototype pattern shared with Track 1): the submitter's
    // AccountRoot backs the pool so rippled's XRP-supply invariant sees a
    // balanced transfer. Deposits raise the virtual pool; withdrawals debit
    // the submitter and credit the destination AccountRoot.
    std::int64_t poolDrops = 0;
    if (sle->isFieldPresent(sfBalance))
        poolDrops = sle->getFieldAmount(sfBalance).xrp().drops();

    auto submitterSle =
        view.peek(keylet::account(tx.getAccountID(sfAccount)));
    if (!submitterSle)
        return tefINTERNAL;

    for (auto const& e : bp.entries)
    {
        if (e.txType == RequestType::Deposit)
        {
            poolDrops += static_cast<std::int64_t>(e.value);
        }
        else if (e.txType == RequestType::Withdraw)
        {
            poolDrops -= static_cast<std::int64_t>(e.value);

            auto subBal = submitterSle->getFieldAmount(sfBalance);
            subBal -= STAmount(XRPAmount(e.value));
            submitterSle->setFieldAmount(sfBalance, subBal);
            view.update(submitterSle);

            auto destSle = view.peek(keylet::account(e.destination));
            if (!destSle)
            {
                auto const reserve = view.fees().accountReserve(0).drops();
                if (static_cast<std::int64_t>(e.value) < reserve)
                    return tecNO_DST_INSUF_XRP;
                destSle = std::make_shared<STLedgerEntry>(
                    keylet::account(e.destination));
                destSle->setAccountID(sfAccount, e.destination);
                destSle->setFieldAmount(
                    sfBalance, STAmount(XRPAmount(e.value)));
                destSle->setFieldU32(sfSequence, view.seq());
                view.insert(destSle);
            }
            else
            {
                auto bal = destSle->getFieldAmount(sfBalance);
                bal += STAmount(XRPAmount(e.value));
                destSle->setFieldAmount(sfBalance, bal);
                view.update(destSle);
            }
        }
        // Transfer / NoOp: no L1 XRP movement.
    }
    if (poolDrops < 0)
        return tefINTERNAL;
    sle->setFieldAmount(sfBalance, STAmount(XRPAmount(poolDrops)));

    RollupState2::setBatchCounter(*sle, bp.batchId);
    RollupState2::setRollupRoot(*sle, bp.newRoot);
    view.update(sle);

    JLOG(ctx_.journal.info())
        << "BatchRollup2: applied batch " << bp.batchId << " ("
        << bp.txCount << " entries); root advanced, pool=" << poolDrops
        << " drops";
    return tesSUCCESS;
}

}  // namespace ripple
