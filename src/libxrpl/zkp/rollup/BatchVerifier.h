//------------------------------------------------------------------------------
/*
    This file is part of rippled_zkp: ZK-Rollup extension for XRPL.
    Copyright (c) 2026 Trinity College Dublin (MSc dissertation).

    Phase 1 — Foundation: BatchVerifier transactor declaration.

    This is the SKELETON version for Phase 1 — the real Groth16
    verification is stubbed by verifyProofMock() (always true). Phase 4a
    replaces it with RollupProver::verifyProof() (Phase 2 deliverable) and
    adds the real preclaim nullifier-chain walk and doApply tree/pool
    mutation.

    v2.2 state machine (Fig 11):
       PREFLIGHT  →  feature flag / fields / sig / txCount / batchId > 0
       PRECLAIM   →  SLE read / prevRoot check / batchId monotonicity /
                     verifyProofMock()
       DO_APPLY   →  update RollupState SLE (counter, root)
*/
//==============================================================================

#ifndef RIPPLE_ZKP_ROLLUP_BATCHVERIFIER_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_BATCHVERIFIER_H_INCLUDED

#include <libxrpl/zkp/rollup/BatchProof.h>

#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpl/protocol/TER.h>

namespace ripple {

class PreflightContext;
class PreclaimContext;
class ApplyContext;

/**
 * BatchVerifier — the on-chain transactor for ttBATCH_ROLLUP = 61.
 *
 * Inherits from Transactor in exactly the same way as CredentialCreate,
 * ZkDeposit, and ZkWithdraw — the canonical XRPL transactor pattern.
 *
 * ConsequencesFactory is Normal: no unusual fee/sequence semantics; the
 * batch pays a single XRPL transaction fee regardless of N.
 */
class BatchRollup : public Transactor
{
public:
    static constexpr ConsequencesFactoryType ConsequencesFactory{Normal};

    explicit BatchRollup(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    /**
     * Phase 1 preflight — stateless checks only. No ledger access.
     *
     *   1. featureZKRollup enabled?
     *   2. preflight1(ctx) — standard rippled prerequisites (fee, sequence).
     *   3. Required fields present: sfBatchProof, sfBatchId, sfPrevRoot,
     *      sfRollupRoot, sfTxCount, sfSequencerPubKey
     *   4. sfBatchProof blob size in (0, MAX_BATCH_BLOB_BYTES]
     *   5. BatchProof::deserialize() succeeds
     *   6. Deserialized BatchProof::isWellFormed() returns true
     *   7. sfTxCount (on STTx) == deserialized txCount (in blob) == entries.size()
     *   8. sfBatchId matches blob batchId and is > 0
     *   9. sfPrevRoot on STTx matches blob prevRoot
     *  10. sfRollupRoot on STTx matches blob newRoot
     *  11. Ed25519(sfSequencerPubKey, computeBatchHash(), blob.sequencerSig) verifies
     *  12. preflight2(ctx) — standard rippled signature / structure checks.
     */
    static NotTEC
    preflight(PreflightContext const& ctx);

    /**
     * Phase 1 preclaim — read-only ledger access.
     *
     *   1. Read RollupState SLE.
     *      - Exists: check sfPrevRoot == sle[sfRollupRoot]
     *                check sfBatchId == sle[sfBatchCounter] + 1
     *      - Missing (first-ever batch):
     *                check sfPrevRoot == kGenesisRollupRoot() (zeros)
     *                check sfBatchId == 1
     *   2. verifyProofMock() — ALWAYS returns true in Phase 1.
     *      (Phase 4a replaces with RollupProver::verifyProof().)
     *
     * Returns tecFAILED_PROCESSING on prevRoot mismatch (recoverable: the
     * sequencer re-fetches currentRoot and resubmits), temMALFORMED on
     * non-monotonic batchId.
     *
     * Deliberately NOT implemented here in Phase 1:
     *   - Nullifier chain walking (needs NullifierPage — Phase 4a)
     *   - Intra-batch nullifier uniqueness (Phase 4a)
     *   - Pool balance sufficiency (Phase 4a)
     */
    static TER
    preclaim(PreclaimContext const& ctx);

    /**
     * Phase 1 doApply — atomic state mutation.
     *
     *   1. RollupState::peek(view).
     *   2. If nullptr: RollupState::createGenesis(view, sfSequencerPubKey).
     *      This path only runs ONCE in the lifetime of a network.
     *   3. Set sfBatchCounter = sfBatchId (the just-validated-monotonic value).
     *   4. Set sfRollupRoot = sfRollupRoot (the post-batch Poseidon root,
     *      accepted on trust in Phase 1; integrity verified in Phase 4a).
     *   5. view.update(sle).
     *
     * Deliberately NOT implemented here in Phase 1:
     *   - update_leaf() on RollupMerkleTree (Phase 3)
     *   - Poseidon root recomputation and verify (Phase 4a)
     *   - Nullifier insertion into NullifierPage chain (Phase 4a)
     *   - Pool balance delta and XRP transfer to destination (Phase 4a)
     */
    TER
    doApply() override;

private:
    /**
     * Phase-1-only mock. Always returns true — deliberately.
     *
     * Centralised in one place so that when Phase 4a replaces it with
     * RollupProver::verifyProof(batchProof), there is a single call-site
     * to update. DO NOT call this from anywhere else.
     */
    static bool
    verifyProofMock(zkp::rollup::BatchProof const& bp);
};

}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_BATCHVERIFIER_H_INCLUDED