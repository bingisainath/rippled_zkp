//------------------------------------------------------------------------------
/*
    Phase 4b — BatchVerifier (class BatchRollup).

    Changes from Phase 4a:
      1. verifyBatchProof() now calls RollupProver::verifyEntry against the
         PoseidonCircuit verification key, eight times — once per entry.
         Phase 4a's ZkProver::verifyProof shortcut is removed; ZKProver.h
         is no longer included from this translation unit.
      2. The eight per-entry Groth16 proofs are unpacked from the
         sfBatchProof blob's `proof` field via fixed-size 192-byte slots
         (kEntryProofSlotBytes). No wire-format change vs Phase 1/4a; the
         split is internal to this file and to RollupSequencer.
      3. Preflight gains an explicit RollupProver::isInitialized() guard
         alongside the existing RollupModule::isStarted() guard.
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

#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpld/ledger/View.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/STVector256.h>
#include <xrpl/protocol/Sign.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/digest.h>

#include <xrpl/basics/Log.h>

#include <cstdlib>
#include <set>
#include <vector>

namespace ripple {

namespace {

constexpr std::size_t kMaxBatchBlobBytes  = 1u << 20;  // 1 MiB
constexpr std::size_t kBatchSize          = 8;

// L1-side walkthrough narration (sequence-diagram steps 10-22). Opt-in via the
// ZKR_WALKTHROUGH environment variable so production runs stay silent and the
// consensus hot path is unaffected by default. When set, each preflight/
// preclaim/doApply stage logs a "[L1-WALKTHROUGH][STEP N]" line at info level,
// greppable from debug.log. DEBUG/DEMO ONLY — do not enable in production.
inline bool
walkthroughOn()
{
    static bool const on = (std::getenv("ZKR_WALKTHROUGH") != nullptr);
    return on;
}

// Fixed slot size for each per-entry Groth16 proof inside sfBatchProof.proof.
// Phase 2 measured the serialised proof at ~137 bytes; 192 gives headroom
// for libsnark version drift without changing the slot layout. MUST match
// RollupSequencer::assembleBatch()'s slot size.
constexpr std::size_t kEntryProofSlotBytes = 192;
constexpr std::size_t kTotalProofBytes     = kBatchSize * kEntryProofSlotBytes;

// Split the concatenated sfBatchProof.proof field into the eight per-entry
// proof byte vectors. Returns false on size mismatch.
//
// Each slot is zero-padded at the end. libsnark's r1cs_gg_ppzksnark_proof
// serializer reads a fixed structure of three group elements, so trailing
// zeros in the slot are ignored by the deserializer.
bool
splitEntryProofs(
    zkp::rollup::BatchProof const& bp,
    std::vector<std::vector<unsigned char>>& out)
{
    out.clear();
    if (bp.proof.size() != kTotalProofBytes)
        return false;
    out.reserve(kBatchSize);
    auto it = bp.proof.begin();
    for (std::size_t i = 0; i < kBatchSize; ++i)
    {
        out.emplace_back(it, it + kEntryProofSlotBytes);
        it += kEntryProofSlotBytes;
    }
    return true;
}

// Phase 4b: verify all eight per-entry Poseidon proofs against the
// PoseidonCircuit verification key. Returns true iff every entry's proof
// satisfies its (prevRoot, newRoot, nullifier, value) public-input vector.
// Short-circuits on the first failure.
bool
verifyBatchProof(zkp::rollup::BatchProof const& bp)
{
    using namespace zkp::rollup;

    if (!RollupProver::isInitialized())
        return false;
    if (bp.entries.size() != kBatchSize)
        return false;

    std::vector<std::vector<unsigned char>> perEntryProofs;
    if (!splitEntryProofs(bp, perEntryProofs))
        return false;

    for (std::size_t i = 0; i < kBatchSize; ++i)
    {
        if (!RollupProver::verifyEntry(bp, i, perEntryProofs[i]))
            return false;
    }
    return true;
}

}  // anonymous namespace

NotTEC
BatchRollup::preflight(PreflightContext const& ctx)
{
    using namespace zkp::rollup;

    if (!ctx.rules.enabled(featureZKRollup))
        return temDISABLED;

    // Phase 4a: module bootstrap guard.
    if (!RollupModule::isStarted())
        return temDISABLED;

    // Phase 4b: explicit prover-keys guard. Should always agree with
    // RollupModule::isStarted() but check both for defence in depth — a
    // shutdown race between the two flags is otherwise possible.
    if (!RollupProver::isInitialized())
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

    // Phase 4b: enforce the fixed 8 * 192-byte proof layout at preflight
    // so a malformed-size blob fails fast (before preclaim spends pairing
    // cycles). Tampered byte content is caught in preclaim by the
    // per-entry Groth16 check.
    if (bp.proof.size() != kTotalProofBytes)
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

    if (walkthroughOn())
        JLOG(ctx.j.info())
            << "[L1-WALKTHROUGH][STEP 10] preflight OK: blob " << blob.size()
            << "B deserialised; batchId=" << bp.batchId
            << " txCount=" << bp.txCount
            << "; prevRoot/newRoot match tx fields; proof layout "
            << bp.proof.size() << "B (8x192); Ed25519 sequencer signature VERIFIED";

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

    // Root-chain invariant: this batch must start where the last one ended.
    if (bp.prevRoot != expectedPrevRoot)
        return tecFAILED_PROCESSING;

    // batchId must be strictly the next one.
    if (bp.batchId != expectedBatchId)
        return temMALFORMED;

    if (walkthroughOn())
        JLOG(ctx.j.info())
            << "[L1-WALKTHROUGH][STEP 11] preclaim chain OK: prevRoot matches"
            << " on-chain root; batchId=" << bp.batchId
            << " is strictly next (append-only invariant holds)";

    // In-batch nullifier uniqueness — cheap O(n log n); runs before Groth16
    // so a tampered batch with duplicate nullifiers fails fast.
    std::set<uint256> seenInBatch;
    for (auto const& entry : bp.entries)
    {
        if (!seenInBatch.insert(entry.nullifier).second)
        {
            JLOG(ctx.j.warn())
                << "BatchRollup: duplicate nullifier in batch → temBAD_PROOF";
            return temBAD_PROOF;
        }
    }

    // Chain-level nullifier uniqueness — prevents cross-batch double-spend.
    // Runs before Groth16 so a replay attempt is rejected without pairing cost.
    for (auto const& entry : bp.entries)
    {
        if (NullifierStore::contains(ctx.view, entry.nullifier))
        {
            JLOG(ctx.j.warn())
                << "BatchRollup: nullifier already spent → tecUNFUNDED";
            return tecUNFUNDED;
        }
    }

    if (walkthroughOn())
        JLOG(ctx.j.info())
            << "[L1-WALKTHROUGH][STEP 12] preclaim nullifiers OK: all "
            << bp.entries.size() << " unique in-batch and unspent on-chain"
            << " (no double-spend)";

    // Pool solvency check for withdrawals — runs before Groth16 for fail-fast.
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

    if (walkthroughOn())
        JLOG(ctx.j.info())
            << "[L1-WALKTHROUGH][STEP 13] preclaim solvency OK: totalWithdrawal="
            << totalWithdrawal << " drops within pool balance";

    // Phase 4b: real PoseidonCircuit Groth16 verification, 8x.
    // This is the most expensive check (~pairing per entry); all cheap policy
    // checks above must pass first.
    if (walkthroughOn())
        JLOG(ctx.j.info())
            << "[L1-WALKTHROUGH][STEP 14] preclaim verifying " << kBatchSize
            << " Groth16 proofs (one pairing check per entry, shared prevRoot)…";
    JLOG(ctx.j.info()) << "BatchRollup: preclaim running Groth16 verification ("
                       << kBatchSize << " entries)";
    if (!verifyBatchProof(bp))
    {
        JLOG(ctx.j.warn()) << "BatchRollup: verifyBatchProof FAILED → temBAD_PROOF";
        return temBAD_PROOF;
    }
    JLOG(ctx.j.info()) << "BatchRollup: all " << kBatchSize
                       << " Groth16 proofs verified";
    if (walkthroughOn())
        JLOG(ctx.j.info())
            << "[L1-WALKTHROUGH][STEP 14] preclaim OK: all " << kBatchSize
            << " Groth16 proofs VERIFIED → preclaim returns tesSUCCESS";

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

    if (walkthroughOn())
        JLOG(ctx_.journal.info())
            << "[L1-WALKTHROUGH][STEP 15] doApply: loaded L2 Poseidon tree from"
            << " RollupState SLE (deserialised frontier)";

    // All batches update the same 8 fixed leaf slots (0..7). The PoseidonCircuit
    // proves old→new at a fixed leaf_pos; it does not encode a batch-offset.
    // Using BatchCounter*kBatchSize would send batch 2 to positions 8..15,
    // exceeding tree.size()=8 and throwing std::out_of_range in update_leaf.
    constexpr std::size_t baseIndex = 0;

    for (std::size_t i = 0; i < bp.entries.size(); ++i)
    {
        auto const& entry = bp.entries[i];
        tree->update_leaf(baseIndex + i, entry.commitment);
    }

    if (walkthroughOn())
        JLOG(ctx_.journal.info())
            << "[L1-WALKTHROUGH][STEP 16] doApply: replayed " << bp.entries.size()
            << " update_leaf() insertions into the L2 tree (in memory)";

    // Phase 4a root-replay cross-check: the sequencer's declared newRoot
    // must equal what the on-chain replay computes. This is what lets the
    // eight per-entry Phase 4b proofs share (prevRoot, newRoot) anchors
    // without an in-circuit aggregation step.
    if (tree->root() != bp.newRoot)
        return tefINTERNAL;

    if (walkthroughOn())
        JLOG(ctx_.journal.info())
            << "[L1-WALKTHROUGH][STEP 17] doApply: ROOT-REPLAY BIND OK —"
            << " recomputed Poseidon root == sequencer's declared newRoot"
            << " (this binds all " << bp.entries.size()
            << " proofs to one root; no aggregation needed)";

    std::vector<uint256> nfs;
    nfs.reserve(bp.entries.size());
    for (auto const& entry : bp.entries)
        nfs.push_back(entry.nullifier);
    if (!NullifierStore::insertBatch(view, nfs))
        return tefINTERNAL;

    if (walkthroughOn())
        JLOG(ctx_.journal.info())
            << "[L1-WALKTHROUGH][STEP 18] doApply: inserted " << nfs.size()
            << " nullifiers into NullifierStore (spent markers persisted)";

    std::int64_t poolDrops = 0;
    if (sle->isFieldPresent(sfBalance))
        poolDrops = sle->getFieldAmount(sfBalance).xrp().drops();

    // The rollup pool balance is stored in a custom SLE, invisible to
    // rippled's XRP supply invariant. For withdrawals, we must debit an
    // actual AccountRoot so the invariant sees a balanced XRP transfer.
    // The TX submitter's account acts as the bridge pool in this prototype.
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

            // Debit the submitter's account to balance the XRP supply invariant.
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

    if (walkthroughOn())
    {
        std::size_t nDep = 0, nWdr = 0;
        for (auto const& entry : bp.entries)
            (entry.txType == RollupTxType::Deposit ? nDep : nWdr)++;
        JLOG(ctx_.journal.info())
            << "[L1-WALKTHROUGH][STEP 19] doApply: moved XRP — " << nDep
            << " deposit(s) raised the virtual pool, " << nWdr
            << " withdrawal(s) debited submitter (bridge) + credited"
            << " destination AccountRoot(s); new pool balance=" << poolDrops
            << " drops";
    }

    RollupState::storeTree(*sle, *tree);
    RollupState::setBatchCounter(*sle, bp.batchId);
    RollupState::setRollupRoot(*sle, bp.newRoot);
    view.update(sle);

    if (walkthroughOn())
    {
        JLOG(ctx_.journal.info())
            << "[L1-WALKTHROUGH][STEP 20-21] doApply: persisted RollupState SLE"
            << " (serialised tree + newRoot + batchCounter=" << bp.batchId
            << "); rippled re-hashes the SLE with SHA-512Half into the L1 SHAMap";
        JLOG(ctx_.journal.info())
            << "[L1-WALKTHROUGH][STEP 22] doApply DONE → tesSUCCESS ("
            << bp.entries.size() << " L2 txs settled in 1 L1 transaction)";
    }

    return tesSUCCESS;
}

}  // namespace ripple