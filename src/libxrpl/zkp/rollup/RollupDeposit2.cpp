//------------------------------------------------------------------------------
/*
    Phase 6 — Track 2 backed deposit transactor (ttROLLUP_DEPOSIT2 = 63).
    See RollupDeposit2.h for why this transaction exists.
*/
//==============================================================================

#include <libxrpl/zkp/rollup/RollupDeposit2.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>
#include <libxrpl/zkp/rollup/RollupState2.h>

#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpld/ledger/ApplyView.h>
#include <xrpld/ledger/View.h>

#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/TxFlags.h>

#include <limits>

namespace ripple {

using namespace zkp::rollup;

NotTEC
RollupDeposit2::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureZKRollup2))
        return temDISABLED;

    if (auto const ret = preflight1(ctx); !isTesSuccess(ret))
        return ret;

    auto const& tx = ctx.tx;

    if (!tx.isFieldPresent(sfAmount) ||
        !tx.isFieldPresent(sfDepositApk) ||
        !tx.isFieldPresent(sfDestination))
        return temMALFORMED;

    // XRP only. The rollup pool is denominated in drops and AccountLeaf packs
    // the balance into 64 bits; an IOU here would have no meaning downstream.
    auto const amount = tx.getFieldAmount(sfAmount);
    if (!isXRP(amount))
        return temBAD_AMOUNT;
    if (amount.xrp().drops() <= 0)
        return temBAD_AMOUNT;

    // apk_x = 0 is the empty-leaf sentinel in the account tree (leaf = 0), so
    // crediting it would be indistinguishable from crediting nothing.
    if (tx.getFieldH256(sfDepositApk) == uint256{})
        return temMALFORMED;

    // Paying escrow from escrow would net to zero while still inflating the
    // pending counter — free L2 balance for whoever controls the escrow.
    if (tx.getAccountID(sfDestination) == tx.getAccountID(sfAccount))
        return temREDUNDANT;

    return preflight2(ctx);
}

TER
RollupDeposit2::preclaim(PreclaimContext const& ctx)
{
    auto const sle = ctx.view.read(keylet::rollup_state2());

    // Deposits are only accepted once a bootstrap batch has anchored the
    // escrow account. Allowing a deposit to create the state SLE would let the
    // FIRST depositor nominate an escrow they control, which is precisely the
    // attack anchoring is meant to prevent.
    if (!sle)
    {
        JLOG(ctx.j.warn())
            << "RollupDeposit2: no rollup state — submit a bootstrap batch "
               "before depositing → tecNO_ENTRY";
        return tecNO_ENTRY;
    }

    auto const escrow = RollupState2::escrowAccount(*sle);
    if (escrow == AccountID{})
        return tecNO_ENTRY;

    if (ctx.tx.getAccountID(sfDestination) != escrow)
    {
        JLOG(ctx.j.warn())
            << "RollupDeposit2: destination is not the anchored escrow "
               "→ tecNO_PERMISSION";
        return tecNO_PERMISSION;
    }

    if (!ctx.view.exists(keylet::account(escrow)))
        return tecNO_DST;

    auto const amount = ctx.tx.getFieldAmount(sfAmount).xrp();

    // The counter is the whole soundness argument, so it must never wrap.
    auto const pending = RollupState2::pendingDeposits(*sle);
    if (pending >
        std::numeric_limits<std::uint64_t>::max() -
            static_cast<std::uint64_t>(amount.drops()))
        return tecOVERSIZE;

    return tesSUCCESS;
}

TER
RollupDeposit2::doApply()
{
    auto& view = ctx_.view();
    auto const& tx = ctx_.tx;

    auto sle = view.peek(keylet::rollup_state2());
    if (!sle)
        return tefINTERNAL;

    auto const account = tx.getAccountID(sfAccount);
    auto depositorSle = view.peek(keylet::account(account));
    if (!depositorSle)
        return tefINTERNAL;

    auto const amount = tx.getFieldAmount(sfAmount).xrp();

    // Reserve and funds. preclaim cannot do this: the fee has not been drawn
    // from mSourceBalance yet at that point.
    {
        auto const balance = STAmount((*depositorSle)[sfBalance]).xrp();
        auto const reserve =
            view.fees().accountReserve((*depositorSle)[sfOwnerCount]);

        if (balance < reserve)
            return tecINSUFFICIENT_RESERVE;
        if (balance < reserve + amount)
            return tecUNFUNDED;
    }

    auto const escrow = RollupState2::escrowAccount(*sle);
    auto escrowSle = view.peek(keylet::account(escrow));
    if (!escrowSle)
        return tecNO_DST;

    // Real XRP: depositor -> escrow. Both are AccountRoots, so XRPNotCreated
    // sees a balanced transfer. This is the leg that was missing entirely.
    depositorSle->setFieldAmount(
        sfBalance, (*depositorSle)[sfBalance] - STAmount(amount));
    view.update(depositorSle);

    escrowSle->setFieldAmount(
        sfBalance, (*escrowSle)[sfBalance] + STAmount(amount));
    view.update(escrowSle);

    // Record the claim. A batch Deposit entry may now consume up to this much.
    RollupState2::setPendingDeposits(
        *sle,
        RollupState2::pendingDeposits(*sle) +
            static_cast<std::uint64_t>(amount.drops()));
    view.update(sle);

    JLOG(j_.info()) << "RollupDeposit2: escrowed " << amount.drops()
                    << " drops from " << toBase58(account) << " for apk_x "
                    << tx.getFieldH256(sfDepositApk)
                    << "; pending now "
                    << RollupState2::pendingDeposits(*sle);

    return tesSUCCESS;
}

}  // namespace ripple
