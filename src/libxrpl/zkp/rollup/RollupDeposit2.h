//------------------------------------------------------------------------------
/*
    This file is part of rippled_zkp: ZK-Rollup extension for XRPL.
    Copyright (c) 2026 Trinity College Dublin (MSc dissertation).

    Phase 6 — Track 2 backed deposit: ttROLLUP_DEPOSIT2 = 63.

    Phase 1 of the two-phase deposit. A Deposit entry inside a batch credits an
    L2 leaf, but the depositor holds only a Baby Jubjub key and never signs an
    XRPL transaction — so nothing on L1 is debited and the sequencer can credit
    balance nobody paid for. (The gap is invisible to XRPNotCreated, which sums
    only ltACCOUNT_ROOT / ltPAYCHAN / ltESCROW, never ltROLLUP_STATE.)

    This transactor is the missing L1 leg: the depositor signs with their
    ordinary XRPL key, real XRP moves from their AccountRoot into the anchored
    escrow account, and sfPendingDeposits records the claim. A batch may then
    credit L2 leaves only by DECREMENTING that counter, which enforces

        total L2 credits  <=  total L1 payments

    with a single uint64 and no change to the circuit.

    What this does NOT enforce: that the credited leaf belongs to the depositor.
    A sequencer can consume the counter while crediting its own apk_x — funds
    are misattributed, not minted. Closing that needs a per-claim queue keyed on
    apk_x (see the "B-full" design note); it is a theft bound, not a supply bug.
*/
//==============================================================================

#ifndef RIPPLE_ZKP_ROLLUP_ROLLUPDEPOSIT2_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ROLLUPDEPOSIT2_H_INCLUDED

#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpl/protocol/TER.h>

namespace ripple {

class PreflightContext;
class PreclaimContext;
class ApplyContext;

/**
 * RollupDeposit2 — the on-chain transactor for ttROLLUP_DEPOSIT2 = 63.
 *
 * Guarded by the same amendment as the batch transactor (featureZKRollup2):
 * a backed deposit is meaningless without a batch transactor to consume it.
 */
class RollupDeposit2 : public Transactor
{
public:
    static constexpr ConsequencesFactoryType ConsequencesFactory{Normal};

    explicit RollupDeposit2(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    // Stateless: amendment guard, field presence, XRP-only positive amount,
    // non-zero apk_x, destination is not the depositor.
    static NotTEC
    preflight(PreflightContext const& ctx);

    // Read-only: the rollup state SLE must already exist (deposits are only
    // accepted once a bootstrap batch has anchored the escrow account), the
    // named destination must equal that anchored escrow, the depositor must
    // stay above reserve, and the counter must not overflow.
    static TER
    preclaim(PreclaimContext const& ctx);

    // Mutating: debit the depositor, credit the escrow AccountRoot, and add
    // the amount to sfPendingDeposits.
    TER
    doApply() override;
};

}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ROLLUPDEPOSIT2_H_INCLUDED
