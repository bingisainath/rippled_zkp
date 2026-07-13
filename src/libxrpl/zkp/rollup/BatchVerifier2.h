//------------------------------------------------------------------------------
/*
    This file is part of rippled_zkp: ZK-Rollup extension for XRPL.
    Copyright (c) 2026 Trinity College Dublin (MSc dissertation).

    Phase 6 — Track 2 (Option A) transactor: ttBATCH_ROLLUP2 = 62.

    The head-to-head counterpart of BatchRollup (Track 1). Where Track 1
    verifies N independent proofs and replays the tree on-chain, Track 2
    verifies ONE monolithic proof whose statement already binds the whole
    prevRoot -> newRoot transition — so preclaim is O(1) in batch size and
    doApply does NOT replay the tree (the tree lives off-chain with the
    sequencer, rebuildable from the published entries).
*/
//==============================================================================

#ifndef RIPPLE_ZKP_ROLLUP_BATCHVERIFIER2_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_BATCHVERIFIER2_H_INCLUDED

#include <libxrpl/zkp/rollup/BatchProof2.h>

#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpl/protocol/TER.h>

namespace ripple {

class PreflightContext;
class PreclaimContext;
class ApplyContext;

/**
 * BatchRollup2 — the on-chain transactor for ttBATCH_ROLLUP2 = 62 (Track 2).
 *
 * Same STTx field set as ttBATCH_ROLLUP (sfBatchProof carries a BatchProof2
 * blob instead of a BatchProof blob). Independent amendment (featureZKRollup2)
 * and state SLE (keylet::rollup_state2).
 */
class BatchRollup2 : public Transactor
{
public:
    static constexpr ConsequencesFactoryType ConsequencesFactory{Normal};

    explicit BatchRollup2(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    // Stateless: feature/module/keys guards, field presence, blob parse,
    // BatchProof2 well-formedness, tx-field vs blob agreement, single-proof
    // size sanity, Ed25519 sequencer signature over computeBatchHash().
    static NotTEC
    preflight(PreflightContext const& ctx);

    // Read-only: RollupState2 root-chain + batchId monotonicity, then ONE
    // BatchCircuitProver::verifyBatch over (prevRoot, newRoot, entriesHash)
    // — entriesHash recomputed natively from the blob entries.
    static TER
    preclaim(PreclaimContext const& ctx);

    // Mutating: update RollupState2 (counter, root) and move escrowed XRP
    // for deposit/withdraw entries. No on-chain tree replay (the proof binds
    // the root chain).
    TER
    doApply() override;
};

}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_BATCHVERIFIER2_H_INCLUDED
