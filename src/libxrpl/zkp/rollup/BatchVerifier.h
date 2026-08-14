/*
    This file is part of rippled_zkp: ZK-Rollup extension for XRPL.

    BatchRollup: on-chain transactor for ttBATCH_ROLLUP, Track 1's proof
    path. A batch carries N per-entry Groth16 proofs, each verified
    independently, and the tree transition is replayed on-chain.

       preflight  feature flag, field presence, sequencer signature,
                  txCount, batchId > 0, and prover/module readiness
       preclaim   read the RollupState SLE; check prevRoot chains from the
                  last batch and batchId is strictly next; reject duplicate
                  nullifiers within the batch and any already spent on
                  chain; check pool solvency for withdrawals; then verify
                  the N Groth16 proofs. The cheap policy checks run first
                  so a bad batch fails before any pairing cost.
       doApply    replay update_leaf() over the batch entries, require the
                  recomputed root to equal the declared newRoot, insert the
                  nullifiers, and update the RollupState counter and root
*/

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
     * Stateless checks only; no ledger access.
     *
     * Requires featureZKRollup, the standard rippled prerequisites, and all
     * of sfBatchProof, sfBatchId, sfPrevRoot, sfRollupRoot, sfTxCount and
     * sfSequencerPubKey. The blob must be within MAX_BATCH_BLOB_BYTES,
     * deserialize, and be well-formed. Every field duplicated between the
     * STTx and the blob must agree — txCount against entries.size(),
     * batchId (which must be > 0), prevRoot, and newRoot against
     * sfRollupRoot — and the sequencer's Ed25519 signature over
     * computeBatchHash() must verify.
     */
    static NotTEC
    preflight(PreflightContext const& ctx);

    /**
     * Read-only ledger access. Checks run cheapest-first, so a bad batch is
     * rejected before any pairing cost is paid.
     *
     *   1. Read the RollupState SLE. If it exists, sfPrevRoot must equal
     *      sle[sfRollupRoot] and sfBatchId must be sle[sfBatchCounter] + 1;
     *      for the first-ever batch, sfPrevRoot must be kGenesisRollupRoot()
     *      and sfBatchId must be 1.
     *   2. Reject duplicate nullifiers within the batch.
     *   3. Reject any nullifier already spent on chain (NullifierStore).
     *   4. Require the pool balance to cover the batch's total withdrawals.
     *   5. Verify the per-entry Groth16 proofs against PoseidonCircuit's
     *      verification key, one per entry.
     *
     * Returns tecFAILED_PROCESSING on prevRoot mismatch, which is
     * recoverable — the sequencer re-fetches currentRoot and resubmits;
     * temMALFORMED on non-monotonic batchId; temBAD_PROOF on a duplicate
     * nullifier or failed verification; tecUNFUNDED on a spent nullifier;
     * tecINSUF_RESERVE_LINE on insufficient pool balance.
     */
    static TER
    preclaim(PreclaimContext const& ctx);

    /**
     * Atomic state mutation.
     *
     *   1. Peek the RollupState SLE, creating genesis on the first batch —
     *      a path that runs once in the lifetime of a network.
     *   2. Load the tree and replay update_leaf() over the batch entries.
     *   3. Require the recomputed root to equal the declared newRoot. This
     *      cross-check is what lets the per-entry proofs share one
     *      (prevRoot, newRoot) anchor without in-circuit aggregation.
     *   4. Insert the batch's nullifiers into the NullifierStore.
     *   5. Settle withdrawals against a real AccountRoot, so rippled's XRP
     *      supply invariant sees a balanced transfer, and update the
     *      RollupState counter and root.
     */
    TER
    doApply() override;
};

}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_BATCHVERIFIER_H_INCLUDED