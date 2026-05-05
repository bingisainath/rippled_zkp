//------------------------------------------------------------------------------
/*
    Phase 1 — Foundation: BatchVerifier transactor skeleton.

    Three-phase pipeline (v2.2 Fig 5):
        preflight  — stateless
        preclaim   — read-only ledger + mock proof verify
        doApply    — atomic state mutation (counter + root only in Phase 1)

    Models the structure of ZkDeposit::preflight/preclaim/doApply exactly,
    but with the v2.2 corrections applied (§10.1–§10.9):
      - gates on featureZKRollup (NOT featureZeroKnowledgePrivacy)
      - uses STI_VL for sfBatchProof (NOT STI_ZKPROOF)
      - key loading is out-of-scope here (fail-fast at preflight; Phase 4a
        hooks RollupProver::isInitialized into a startup module, not lazy
        init inside preclaim)
      - keylets via shared header RollupKeylets.h (NOT per-file inline)
*/
//==============================================================================

#include <libxrpl/zkp/rollup/BatchVerifier.h>
#include <libxrpl/zkp/rollup/BatchProof.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>
#include <libxrpl/zkp/rollup/RollupState.h>

#include <xrpl/basics/Log.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>
#include <xrpld/ledger/ApplyView.h>

namespace ripple {

using zkp::rollup::BatchProof;
using zkp::rollup::MAX_BATCH_BLOB_BYTES;
using zkp::rollup::kGenesisRollupRoot;

// =============================================================================
// preflight  (stateless — no ledger access)
// =============================================================================

NotTEC
BatchRollup::preflight(PreflightContext const& ctx)
{
    // ---- 1. Feature gate ------------------------------------------------
    // v2.2 §10.4: MUST be featureZKRollup, NOT featureZeroKnowledgePrivacy.
    // If you accidentally gate on the wrong flag every batch returns
    // temDISABLED with no diagnostic — one of the most insidious bugs.
    if (!ctx.rules.enabled(featureZKRollup))
    {
        JLOG(ctx.j.debug()) << "BatchVerifier: featureZKRollup not enabled";
        return temDISABLED;
    }

    // ---- 2. Standard rippled preflight prerequisites --------------------
    if (auto const ret = preflight1(ctx); !isTesSuccess(ret))
        return ret;

    // ---- 3. Required fields present -------------------------------------
    auto const& tx = ctx.tx;

    auto requireField = [&](SField const& f, char const* name) -> bool {
        if (!tx.isFieldPresent(f))
        {
            JLOG(ctx.j.debug()) << "BatchVerifier: missing field " << name;
            return false;
        }
        return true;
    };
    if (!requireField(sfBatchProof,       "sfBatchProof"))       return temMALFORMED;
    if (!requireField(sfBatchId,          "sfBatchId"))          return temMALFORMED;
    if (!requireField(sfPrevRoot,         "sfPrevRoot"))         return temMALFORMED;
    if (!requireField(sfRollupRoot,       "sfRollupRoot"))       return temMALFORMED;
    if (!requireField(sfTxCount,          "sfTxCount"))          return temMALFORMED;
    if (!requireField(sfSequencerPubKey,  "sfSequencerPubKey"))  return temMALFORMED;

    // ---- 4. Blob size guard (v2.2 §10.2) --------------------------------
    // Model exactly on ZkDeposit.cpp's sfZKProof size check, but with the
    // 1 MB rollup cap.
    auto const blob = tx.getFieldVL(sfBatchProof);
    if (blob.empty() || blob.size() > MAX_BATCH_BLOB_BYTES)
    {
        JLOG(ctx.j.debug())
            << "BatchVerifier: invalid sfBatchProof size " << blob.size();
        return temMALFORMED;
    }

    // ---- 5. Deserialize -------------------------------------------------
    bool ok = false;
    BatchProof bp = BatchProof::deserialize(
        std::vector<std::uint8_t>(blob.begin(), blob.end()), ok);
    if (!ok)
    {
        JLOG(ctx.j.debug()) << "BatchVerifier: BatchProof deserialize failed";
        return temMALFORMED;
    }

    // ---- 6. Structural wellformedness -----------------------------------
    if (!bp.isWellFormed())
    {
        JLOG(ctx.j.debug()) << "BatchVerifier: BatchProof not well-formed";
        return temMALFORMED;
    }

    // ---- 7. sfTxCount consistency (NEW check in v2.1, §Fig 5) -----------
    // Security: prevents a batch that declares N=8 but only carries 5
    // entries (or vice versa) from ever reaching preclaim.
    auto const declaredTxCount = tx.getFieldU32(sfTxCount);
    if (declaredTxCount != bp.txCount
        || declaredTxCount != bp.entries.size())
    {
        JLOG(ctx.j.debug())
            << "BatchVerifier: sfTxCount mismatch (tx=" << declaredTxCount
            << " blob.txCount=" << bp.txCount
            << " entries=" << bp.entries.size() << ')';
        return temMALFORMED;
    }

    // ---- 8. batchId > 0 and matches blob --------------------------------
    auto const declaredBatchId = tx.getFieldU32(sfBatchId);
    if (declaredBatchId == 0 || declaredBatchId != bp.batchId)
    {
        JLOG(ctx.j.debug()) << "BatchVerifier: invalid sfBatchId";
        return temMALFORMED;
    }

    // ---- 9/10. prevRoot / newRoot consistency between STTx and blob -----
    if (tx.getFieldH256(sfPrevRoot) != bp.prevRoot)
    {
        JLOG(ctx.j.debug()) << "BatchVerifier: sfPrevRoot mismatch (STTx vs blob)";
        return temMALFORMED;
    }
    if (tx.getFieldH256(sfRollupRoot) != bp.newRoot)
    {
        JLOG(ctx.j.debug()) << "BatchVerifier: sfRollupRoot mismatch (STTx vs blob)";
        return temMALFORMED;
    }

    // ---- 11. Ed25519 signature verification over batchHash --------------
    // The sequencer Ed25519-signs batchHash (off-chain SHA-256). The public
    // key travels on the STTx in sfSequencerPubKey; the signature travels
    // inside the blob in sequencerSig.
    try
    {
        auto const pubKeyBlob = tx.getFieldVL(sfSequencerPubKey);
        if (pubKeyBlob.empty())
            return temMALFORMED;

        Slice const pkSlice(pubKeyBlob.data(), pubKeyBlob.size());
        auto const pkType = publicKeyType(pkSlice);
        if (!pkType || *pkType != KeyType::ed25519)
        {
            JLOG(ctx.j.debug())
                << "BatchVerifier: sfSequencerPubKey not Ed25519";
            return temMALFORMED;
        }

        PublicKey const pk(pkSlice);

        uint256 const batchHash = bp.computeBatchHash();
        Slice const msg(batchHash.data(), batchHash.size());
        Slice const sig(bp.sequencerSig.data(), bp.sequencerSig.size());

        if (!verify(pk, msg, sig, /*mustBeFullyCanonical=*/false))
        {
            JLOG(ctx.j.debug())
                << "BatchVerifier: sequencer signature verification failed";
            return temBAD_SIGNATURE;
        }
    }
    catch (std::exception const& e)
    {
        JLOG(ctx.j.warn())
            << "BatchVerifier: exception during sig verify: " << e.what();
        return temMALFORMED;
    }

    // ---- 12. Standard rippled sig / structure trailer -------------------
    return preflight2(ctx);
}

// =============================================================================
// preclaim  (read-only ledger access; proof-verify stubbed via mock)
// =============================================================================

TER
BatchRollup::preclaim(PreclaimContext const& ctx)
{
    auto const& tx = ctx.tx;

    auto const declaredPrevRoot = tx.getFieldH256(sfPrevRoot);
    auto const declaredBatchId  = tx.getFieldU32(sfBatchId);

    auto const sle = ctx.view.read(keylet::rollup_state());

    uint256 expectedPrevRoot;
    std::uint32_t expectedBatchId = 0;

    if (!sle)
    {
        // First-ever batch on this network. The RollupState SLE doesn't
        // exist yet — doApply() will create it. Genesis invariants:
        expectedPrevRoot = kGenesisRollupRoot();   // all-zero sentinel
        expectedBatchId  = 1;                       // first batch
    }
    else
    {
        expectedPrevRoot = sle->getFieldH256(sfRollupRoot);
        expectedBatchId  = sle->getFieldU32(sfBatchCounter) + 1;
    }

    if (declaredPrevRoot != expectedPrevRoot)
    {
        JLOG(ctx.j.warn())
            << "BatchVerifier: prevRoot mismatch — sequencer must re-fetch "
               "currentRoot and resubmit";
        // Recoverable error — v2.2 §Fig 11 / Fig 7 "Rejection Scenario 5".
        return tecFAILED_PROCESSING;
    }

    if (declaredBatchId != expectedBatchId)
    {
        JLOG(ctx.j.warn())
            << "BatchVerifier: non-monotonic batchId (got " << declaredBatchId
            << ", expected " << expectedBatchId << ')';
        return temMALFORMED;
    }

    // --------- MOCK PROOF VERIFICATION (Phase 1 only) ---------------------
    // In Phase 4a this is replaced with:
    //     if (!zkp::rollup::RollupProver::verifyProof(bp))
    //         return temBAD_PROOF;
    //
    // We do a defensive redeserialize here so the mock sees the same blob
    // the real verifier will see — catches any discrepancy early.
    auto const blob = tx.getFieldVL(sfBatchProof);
    bool ok = false;
    BatchProof const bp = BatchProof::deserialize(
        std::vector<std::uint8_t>(blob.begin(), blob.end()), ok);
    if (!ok)
        return temMALFORMED;  // defensive — preflight should have caught this

    if (!verifyProofMock(bp))
    {
        JLOG(ctx.j.warn()) << "BatchVerifier: mock proof verifier rejected";
        return temBAD_PROOF;
    }

    return tesSUCCESS;
}

// =============================================================================
// doApply  (atomic state mutation — counter + root ONLY in Phase 1)
// =============================================================================

TER
BatchRollup::doApply()
{
    auto const& tx = ctx_.tx;

    auto const newBatchId   = tx.getFieldU32(sfBatchId);
    auto const declaredRoot = tx.getFieldH256(sfRollupRoot);

    auto sle = view().peek(keylet::rollup_state());

    if (!sle)
    {
        // Genesis path: create the SLE and set the initial sequencer key.
        // preclaim already verified that declaredBatchId == 1 and that
        // prevRoot == kGenesisRollupRoot().
        auto const pubKeyBlob = tx.getFieldVL(sfSequencerPubKey);
        sle = zkp::rollup::RollupState::createGenesis(view(), pubKeyBlob);
        if (!sle)
        {
            JLOG(j_.error())
                << "BatchVerifier: failed to create genesis RollupState SLE";
            return tecINTERNAL;
        }
    }

    // Update counter + root. Phase 4a will also:
    //   - call RollupMerkleTree::update_leaf() for each entry
    //   - recompute the Poseidon root and verify against declaredRoot
    //   - append nullifiers to NullifierPage chain
    //   - update sfBalance (pool balance) and transfer XRP for withdrawals
    zkp::rollup::RollupState::setBatchCounter(*sle, newBatchId);
    zkp::rollup::RollupState::setRollupRoot(*sle, declaredRoot);

    view().update(sle);

    JLOG(j_.info())
        << "BatchVerifier: committed batch " << newBatchId
        << " — root now " << declaredRoot;

    return tesSUCCESS;
}

// =============================================================================
// verifyProofMock  (Phase 1 only — REMOVE in Phase 4a)
// =============================================================================

bool
BatchRollup::verifyProofMock(zkp::rollup::BatchProof const& bp)
{
    // Phase 1 scaffolding. We do a minimum sanity check so that totally
    // absurd proofs (zero length, wrong txCount) still get rejected even
    // without real cryptography — makes the mock path useful for wiring
    // tests without giving the illusion of security.
    if (bp.proof.empty())          return false;
    if (bp.txCount == 0)           return false;
    if (bp.txCount > zkp::rollup::BATCH_SIZE) return false;
    if (bp.entries.size() != bp.txCount)      return false;
    return true;
}

}  // namespace ripple