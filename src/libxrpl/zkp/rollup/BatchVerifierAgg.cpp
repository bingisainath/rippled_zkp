//------------------------------------------------------------------------------
/*
    Phase 8 — BatchVerifierAgg (class BatchRollupAgg).

    preflight and doApply are structurally identical to BatchVerifier.cpp's
    BatchRollup — same field set, same wire struct (BatchProof), same
    RollupState tree, same nullifier/root-replay logic. preclaim's proof
    check is the one place this genuinely differs: ONE
    ProofAggregator::verifyAggregate() call instead of BatchRollup's 8x
    RollupProver::verifyEntry loop.
*/
//==============================================================================

#include <libxrpl/zkp/rollup/BatchVerifierAgg.h>
#include <libxrpl/zkp/rollup/BatchProof.h>
#include <libxrpl/zkp/rollup/NullifierStore.h>
#include <libxrpl/zkp/rollup/PoseidonHash.h>
#include <libxrpl/zkp/rollup/ProofAggregator.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>
#include <libxrpl/zkp/rollup/RollupMerkleTree.h>
#include <libxrpl/zkp/rollup/RollupModule.h>
#include <libxrpl/zkp/rollup/RollupState.h>

#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpld/ledger/View.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/Sign.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/digest.h>

#include <xrpl/basics/Log.h>

#include <cstdlib>
#include <set>
#include <vector>

namespace ripple {

namespace {

constexpr std::size_t kMaxBatchBlobBytes = 1u << 20;  // 1 MiB
constexpr std::size_t kBatchSize         = 8;

inline bool
walkthroughOn()
{
    static bool const on = (std::getenv("ZKR_WALKTHROUGH") != nullptr);
    return on;
}

// Build the N RollupProofData "public inputs only" entries verifyAggregate
// needs from a deserialised BatchProof — anchor is the SAME prevRoot for
// every entry (matching PoseidonCircuit's convention, see BatchVerifier.cpp
// / RollupProver::verifyEntry), the rest come straight off each entry.
// proof_bytes is left empty — verifyAggregate never reads it (MIPP proves
// the C-element aggregation; only the 5 public field elements are used).
std::vector<zkp::rollup::RollupProofData>
buildPublicInputs(zkp::rollup::BatchProof const& bp)
{
    using namespace zkp::rollup;
    std::vector<RollupProofData> out;
    out.reserve(bp.entries.size());
    FieldT const anchorF = PoseidonHash::uint256ToField(bp.prevRoot);
    for (auto const& e : bp.entries)
    {
        RollupProofData pd;
        pd.anchor = anchorF;
        pd.new_anchor = PoseidonHash::uint256ToField(e.commitment);
        pd.nullifier = PoseidonHash::uint256ToField(e.nullifier);
        pd.value_pub = FieldT(e.value);
        pd.is_withdraw = (e.txType == RollupTxType::Withdraw);
        out.push_back(std::move(pd));
    }
    return out;
}

// The one step that differs from BatchRollup::preclaim: verify ONE
// aggregate proof instead of looping over 8 independent Groth16 proofs.
// Wrapped in try/catch because AggregateProof::deserialize (like
// RollupProver::deserializeProof — see RollupProver::verifyProof's own
// try/catch) can throw on structurally-corrupted curve-point encodings;
// treat that identically to "verification failed", not a crash.
bool
verifyAggregateBatchProof(zkp::rollup::BatchProof const& bp)
{
    using namespace zkp::rollup;

    if (!ProofAggregator::isInitialized())
        return false;
    if (bp.entries.size() != kBatchSize)
        return false;

    try
    {
        auto const agg = AggregateProof::deserialize(bp.proof);
        auto const publicInputs = buildPublicInputs(bp);
        return ProofAggregator::verifyAggregate(
            ProofAggregator::srs(), agg, publicInputs);
    }
    catch (std::exception const& e)
    {
        JLOG(debugLog().warn())
            << "BatchRollupAgg: verifyAggregateBatchProof threw: " << e.what();
        return false;
    }
}

}  // anonymous namespace

NotTEC
BatchRollupAgg::preflight(PreflightContext const& ctx)
{
    using namespace zkp::rollup;

    if (!ctx.rules.enabled(featureZKRollupAgg))
        return temDISABLED;

    if (!RollupModule::isStarted())
        return temDISABLED;

    if (!ProofAggregator::isInitialized())
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

    // Structural-only check that bp.proof parses as an AggregateProof — the
    // cryptographic check itself is a preclaim concern (needs the SRS,
    // shouldn't run on the preflight fast path). A malformed/truncated blob
    // is rejected here without ever reaching the pairing-heavy verifier.
    try
    {
        (void)AggregateProof::deserialize(bp.proof);
    }
    catch (std::exception const&)
    {
        return temMALFORMED;
    }

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

    if (walkthroughOn())
        JLOG(ctx.j.info())
            << "[L1-WALKTHROUGH][AGG-STEP] preflight OK: blob " << blob.size()
            << "B deserialised; batchId=" << bp.batchId
            << " txCount=" << bp.txCount
            << "; prevRoot/newRoot match tx fields; AggregateProof parses; "
            << "Ed25519 sequencer signature VERIFIED";

    return preflight2(ctx);
}

TER
BatchRollupAgg::preclaim(PreclaimContext const& ctx)
{
    using namespace zkp::rollup;

    bool ok = false;
    auto const bp = BatchProof::deserialize(
        ctx.tx.getFieldVL(sfBatchProof), ok);
    if (!ok)
        return tefINTERNAL;

    // Same RollupState tree BatchRollup (tt=61) reads/writes — aggregation
    // is an alternative proof path for the SAME rollup, not a new one.
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

    std::set<uint256> seenInBatch;
    for (auto const& entry : bp.entries)
    {
        if (!seenInBatch.insert(entry.nullifier).second)
        {
            JLOG(ctx.j.warn())
                << "BatchRollupAgg: duplicate nullifier in batch → temBAD_PROOF";
            return temBAD_PROOF;
        }
    }

    for (auto const& entry : bp.entries)
    {
        if (NullifierStore::contains(ctx.view, entry.nullifier))
        {
            JLOG(ctx.j.warn())
                << "BatchRollupAgg: nullifier already spent → tecUNFUNDED";
            return tecUNFUNDED;
        }
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
            poolBalance = sle->getFieldAmount(sfBalance).xrp().drops();
        if (poolBalance < totalWithdrawal)
            return tecINSUF_RESERVE_LINE;
    }

    // The one step that differs from BatchRollup: ONE aggregate check
    // instead of 8 independent Groth16 verifications.
    if (walkthroughOn())
        JLOG(ctx.j.info())
            << "[L1-WALKTHROUGH][AGG-STEP] preclaim verifying ONE aggregate "
               "proof (TIPP/MIPP/KZG) covering all " << kBatchSize
            << " entries…";
    JLOG(ctx.j.info())
        << "BatchRollupAgg: preclaim running aggregate proof verification";
    if (!verifyAggregateBatchProof(bp))
    {
        JLOG(ctx.j.warn())
            << "BatchRollupAgg: verifyAggregateBatchProof FAILED → temBAD_PROOF";
        return temBAD_PROOF;
    }
    JLOG(ctx.j.info()) << "BatchRollupAgg: aggregate proof verified";
    if (walkthroughOn())
        JLOG(ctx.j.info())
            << "[L1-WALKTHROUGH][AGG-STEP] preclaim OK: aggregate proof "
               "VERIFIED (1 check covers all " << kBatchSize
            << " entries) → preclaim returns tesSUCCESS";

    return tesSUCCESS;
}

TER
BatchRollupAgg::doApply()
{
    // Byte-for-byte the same state mutation as BatchRollup::doApply
    // (BatchVerifier.cpp) — aggregation only changes how the proof was
    // checked in preclaim, never what an accepted batch does to the ledger.
    using namespace zkp::rollup;

    auto& view     = ctx_.view();
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

    auto tree = RollupState::loadTree(*sle);

    constexpr std::size_t baseIndex = 0;
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

    auto submitterSle = view.peek(keylet::account(tx.getAccountID(sfAccount)));
    if (!submitterSle)
        return tefINTERNAL;

    for (auto const& entry : bp.entries)
    {
        if (entry.txType == RollupTxType::Deposit)
        {
            poolDrops += static_cast<std::int64_t>(entry.value);
        }
        else
        {
            poolDrops -= static_cast<std::int64_t>(entry.value);

            auto subBal = submitterSle->getFieldAmount(sfBalance);
            subBal -= STAmount(XRPAmount(entry.value));
            submitterSle->setFieldAmount(sfBalance, subBal);
            view.update(submitterSle);

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

    if (walkthroughOn())
        JLOG(ctx_.journal.info())
            << "[L1-WALKTHROUGH][AGG-STEP] doApply DONE → tesSUCCESS ("
            << bp.entries.size()
            << " L2 txs settled in 1 L1 transaction via aggregate proof)";

    return tesSUCCESS;
}

}  // namespace ripple
