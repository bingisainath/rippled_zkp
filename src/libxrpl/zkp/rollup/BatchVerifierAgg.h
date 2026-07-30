//------------------------------------------------------------------------------
/*
    This file is part of rippled_zkp: ZK-Rollup extension for XRPL.
    Copyright (c) 2026 Trinity College Dublin (MSc dissertation).

    Phase 8 — BatchVerifierAgg: on-chain transactor for ttBATCH_ROLLUP_AGG.

    This is Track 1's EXISTING RollupState tree (same keylet::rollup_state(),
    same nullifier/commitment model, same genesis) reached via an
    ALTERNATIVE proof path: one SnarkPack-style aggregate proof (TIPP/MIPP/
    KZG, see ProofAggregator.h) instead of 8 independent Groth16 proofs
    checked in a loop (BatchVerifier.cpp / ttBATCH_ROLLUP=61).

    Everything about doApply's STATE MUTATION is identical to BatchRollup —
    the aggregate proof only changes HOW the batch is cryptographically
    verified, not what changes on the ledger once it's accepted. Only
    preclaim's verification step differs from BatchRollup.
*/
//==============================================================================

#ifndef RIPPLE_ZKP_ROLLUP_BATCHVERIFIERAGG_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_BATCHVERIFIERAGG_H_INCLUDED

#include <libxrpl/zkp/rollup/BatchProof.h>

#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpl/protocol/TER.h>

namespace ripple {

class PreflightContext;
class PreclaimContext;
class ApplyContext;

/**
 * BatchRollupAgg — the on-chain transactor for ttBATCH_ROLLUP_AGG = 64.
 *
 * Same Transactor pattern as BatchRollup/BatchRollup2. sfBatchProof carries
 * a serialised BatchProof (Track 1's existing wire struct — its `proof`
 * field is already variable-length, so no new wire format is needed) whose
 * `proof` bytes are an AggregateProof::serialize() blob rather than
 * 8x192B padded individual Groth16 proofs.
 */
class BatchRollupAgg : public Transactor
{
public:
    static constexpr ConsequencesFactoryType ConsequencesFactory{Normal};

    explicit BatchRollupAgg(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    /**
     * Stateless checks only, no ledger access:
     *   1. featureZKRollupAgg enabled, RollupModule + ProofAggregator ready.
     *   2. preflight1(ctx).
     *   3. Required fields present (same set as BatchRollup).
     *   4. sfBatchProof deserialises to a well-formed BatchProof.
     *   5. sfTxCount/sfBatchId/sfPrevRoot/sfRollupRoot match the blob.
     *   6. Ed25519(sfSequencerPubKey, computeBatchHash(), sequencerSig) verifies.
     *   7. AggregateProof::deserialize() succeeds on bp.proof (structural
     *      only — cryptographic validity is a preclaim concern).
     *   8. preflight2(ctx).
     */
    static NotTEC
    preflight(PreflightContext const& ctx);

    /**
     * Read-only ledger access:
     *   1. Read RollupState SLE (SAME keylet as BatchRollup) — root-chain
     *      and batchId monotonicity checks, identical to BatchRollup.
     *   2. In-batch and chain-level nullifier uniqueness — identical.
     *   3. Pool solvency for withdrawals — identical.
     *   4. ProofAggregator::verifyAggregate() — ONE aggregate check instead
     *      of BatchRollup's 8x RollupProver::verifyEntry loop. This is the
     *      only step that differs from BatchRollup::preclaim.
     */
    static TER
    preclaim(PreclaimContext const& ctx);

    /**
     * Atomic state mutation — byte-for-byte the same logic as
     * BatchRollup::doApply (tree replay, root-replay bind check, nullifier
     * insertion, XRP movement for withdrawals). Aggregation changes how the
     * proof was checked, never what doApply does with an accepted batch.
     */
    TER
    doApply() override;
};

}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_BATCHVERIFIERAGG_H_INCLUDED
