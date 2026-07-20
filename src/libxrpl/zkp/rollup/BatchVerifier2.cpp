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

namespace {

// Match a batch's Deposit entries against the outstanding deposit claims.
//
// Each Deposit entry must consume a DISTINCT claim whose apk_x and drops both
// match exactly. Matching on apk_x is what closes the misattribution hole: the
// scalar total alone proves a batch credits no more than was escrowed, but not
// that it credits the depositor who paid. Exact-match on drops (rather than
// <=) keeps a claim indivisible — partial consumption would leave ambiguity
// about what remains owed to whom.
//
// Deliberately NOT strict FIFO. A Deposit entry carries the depositor's
// in-circuit EdDSA signature, so the sequencer cannot construct one without
// that depositor's cooperation. Under FIFO a single depositor who escrows and
// then never submits the matching L2 request would stall the queue head
// permanently and block deposits for everyone. Order-independent matching
// gives the same attribution guarantee with no head-of-line blocking; the
// censorship property FIFO would have added needs a reclaim path instead.
//
// On success `consumed` is filled with the index of the claim each Deposit
// entry matched, so doApply can erase exactly those.
bool
matchDepositClaims(
    std::vector<BatchProof2Entry> const& entries,
    std::vector<RollupState2::DepositClaim> const& claims,
    std::vector<std::size_t>& consumed)
{
    std::vector<bool> used(claims.size(), false);
    consumed.clear();

    for (auto const& e : entries)
    {
        if (e.txType != RequestType::Deposit)
            continue;

        bool found = false;
        for (std::size_t i = 0; i < claims.size(); ++i)
        {
            if (used[i] || claims[i].apk != e.fromApkX ||
                claims[i].drops != e.value)
                continue;
            used[i] = true;
            consumed.push_back(i);
            found = true;
            break;
        }
        if (!found)
            return false;
    }
    return true;
}

}  // namespace

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

    // Per-entry policy. All stateless, so it runs here rather than in preclaim
    // — an entry that fails any of these costs the node no pairing cycles.
    for (auto const& e : bp.entries)
    {
        // Transfer moves value between two L2 leaves and touches NO L1
        // account: it consumes no deposit claim, pays out of no escrow, and
        // leaves the pool total unchanged. Every guard below and in preclaim
        // is therefore correctly a no-op for it — the whole statement is
        // carried by the circuit's recipient leg (BatchCircuit.h §8).
        if (e.txType == RequestType::Withdraw)
        {
            // Bind the L1 payout target to the field the USER signed. The
            // user's EdDSA covers `dest` (inside msg) but NOT `destination`
            // — without this check a malicious sequencer could prove a
            // withdrawal to one AccountID and pay out to another.
            if (e.destination == AccountID{})
                return temMALFORMED;
            if (PoseidonHash::uint256ToField(e.dest) !=
                accountIdToField(e.destination))
                return temMALFORMED;
        }
        else
        {
            // Canonical form: destination is meaningful only for withdrawals.
            // computeBatchHash() covers every entry byte, so leaving junk here
            // would let two distinct blobs carry the same proof.
            if (e.destination != AccountID{})
                return temMALFORMED;
        }
    }

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

        // Permissioned sequencer: the submitter must be the key anchored at
        // genesis. preflight already proved they HOLD this key (Ed25519 over
        // computeBatchHash); this proves it is the RIGHT key.
        //
        // Track 2 keeps the account tree off-chain in the sequencer's memory,
        // so a second party submitting a valid batch would advance the on-chain
        // root out from under the legitimate sequencer and brick every
        // subsequent batch it builds (its prevRoot would no longer match).
        // The proof guarantees correctness, but not liveness — hence the gate.
        if (sle->isFieldPresent(sfSequencerKey) &&
            sle->getFieldVL(sfSequencerKey) !=
                ctx.tx.getFieldVL(sfSequencerPubKey))
        {
            JLOG(ctx.j.warn())
                << "BatchRollup2: submitter is not the anchored sequencer "
                   "→ tecNO_PERMISSION";
            return tecNO_PERMISSION;
        }
    }

    // Root-chain: this batch must start where the last one ended.
    if (bp.prevRoot != expectedPrevRoot)
        return tecFAILED_PROCESSING;
    // Strictly the next batch id.
    if (bp.batchId != expectedBatchId)
        return temMALFORMED;

    // Pool solvency for withdrawals (fail fast before the pairing check).
    std::int64_t totalWithdrawal = 0;
    std::uint64_t totalDeposit = 0;
    for (auto const& e : bp.entries)
    {
        if (e.txType == RequestType::Withdraw)
            totalWithdrawal += static_cast<std::int64_t>(e.value);
        else if (e.txType == RequestType::Deposit)
            totalDeposit += e.value;
    }
    if (totalWithdrawal > 0)
    {
        std::int64_t poolBalance = 0;
        if (sle && sle->isFieldPresent(sfBalance))
            poolBalance = sle->getFieldAmount(sfBalance).xrp().drops();
        if (poolBalance < totalWithdrawal)
        {
            JLOG(ctx.j.warn())
                << "BatchRollup2: pool holds " << poolBalance
                << " drops, batch withdraws " << totalWithdrawal
                << " → tecINSUF_RESERVE_LINE";
            return tecINSUF_RESERVE_LINE;
        }

        // The escrow account funds withdrawal payouts, so it must cover them
        // without dropping below its own reserve. doApply used to subtract
        // unconditionally, which could drive the balance negative. Mirror
        // doApply's fallback: before genesis the submitter IS the escrow.
        auto const escrow = sle ? RollupState2::escrowAccount(*sle)
                                : AccountID{};
        auto const escrowSle = ctx.view.read(keylet::account(
            escrow != AccountID{} ? escrow
                                  : ctx.tx.getAccountID(sfAccount)));
        if (!escrowSle)
            return terNO_ACCOUNT;
        auto const balance = STAmount((*escrowSle)[sfBalance]).xrp();
        auto const reserve =
            ctx.view.fees().accountReserve((*escrowSle)[sfOwnerCount]);
        if (balance < reserve + XRPAmount(totalWithdrawal))
        {
            JLOG(ctx.j.warn())
                << "BatchRollup2: escrow holds " << balance.drops()
                << " drops against reserve " << reserve.drops()
                << " and payouts " << totalWithdrawal
                << " → tecINSUF_RESERVE_LINE";
            return tecINSUF_RESERVE_LINE;
        }
    }

    // Backed deposits: a batch may credit L2 leaves only up to what
    // ttROLLUP_DEPOSIT2 has actually escrowed. Without this, a Deposit entry
    // raises the pool with no L1 debit anywhere — L2 balance minted from
    // nothing, invisible to XRPNotCreated (it ignores ltROLLUP_STATE).
    if (totalDeposit > 0)
    {
        // Fast path: the retained aggregate rules out an over-credit without
        // walking the claim array.
        std::uint64_t const pending =
            sle ? RollupState2::pendingDeposits(*sle) : 0;
        if (pending < totalDeposit)
        {
            JLOG(ctx.j.warn())
                << "BatchRollup2: batch credits " << totalDeposit
                << " drops of deposits but only " << pending
                << " are escrowed → tecINSUF_RESERVE_LINE";
            return tecINSUF_RESERVE_LINE;
        }

        // Attribution: every Deposit entry must consume a distinct claim
        // matching on BOTH apk_x and drops. entriesHash is already a public
        // input recomputed natively below, so these same entries are bound
        // into the proven statement — checking them here makes a
        // misattributed deposit unprovable, not merely rejected.
        std::vector<std::size_t> consumed;
        auto const claims = sle ? RollupState2::depositClaims(*sle)
                                : std::vector<RollupState2::DepositClaim>{};
        if (!matchDepositClaims(bp.entries, claims, consumed))
        {
            JLOG(ctx.j.warn())
                << "BatchRollup2: a Deposit entry does not match any "
                   "outstanding claim on (apk_x, drops) → "
                   "tecFAILED_PROCESSING";
            return tecFAILED_PROCESSING;
        }
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
        // Bootstrap batch: this submitter becomes the escrow account that
        // deposits pay into and withdrawals pay out of, for the life of the
        // rollup. Anchoring it here — rather than letting each deposit name
        // its own target — is what stops a depositor nominating an escrow
        // they control.
        sle = RollupState2::createGenesis(
            view, tx.getFieldVL(sfSequencerPubKey), tx.getAccountID(sfAccount));
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

    // Withdrawals pay OUT of the same account deposits pay INTO. Using the
    // submitter here instead would break that symmetry: preclaim pins the
    // submitter by sequencer KEY, not by account, so a second account holding
    // the same key would fund payouts from its own balance while the escrow
    // kept the depositors' XRP. In the normal case (the bootstrap submitter
    // keeps submitting) escrow and submitter are the same account.
    auto const escrow = RollupState2::escrowAccount(*sle);
    auto escrowSle = view.peek(
        keylet::account(escrow != AccountID{} ? escrow
                                              : tx.getAccountID(sfAccount)));
    if (!escrowSle)
        return tefINTERNAL;

    // Backed deposits: every drop credited to an L2 leaf must already have
    // been paid into escrow by a ttROLLUP_DEPOSIT2 the depositor signed, AND
    // must credit the leaf that depositor named. preclaim proved both; re-run
    // the match here so the mutation below cannot diverge from what was
    // checked (belt and braces — this is the code that actually erases).
    auto claims = RollupState2::depositClaims(*sle);
    std::vector<std::size_t> consumed;
    if (!matchDepositClaims(bp.entries, claims, consumed))
        return tecFAILED_PROCESSING;

    std::uint64_t pending = RollupState2::pendingDeposits(*sle);

    for (auto const& e : bp.entries)
    {
        if (e.txType == RequestType::Deposit)
        {
            if (pending < e.value)
                return tecINSUF_RESERVE_LINE;
            pending -= e.value;
            poolDrops += static_cast<std::int64_t>(e.value);
        }
        else if (e.txType == RequestType::Withdraw)
        {
            poolDrops -= static_cast<std::int64_t>(e.value);

            // Defence in depth: preclaim already checked the batch total
            // against the escrow balance, but this loop is what actually
            // subtracts. Without a per-entry check a change to preclaim (or a
            // path that reaches doApply another way) could drive the escrow
            // below its reserve, or negative — STAmount would happily hold a
            // negative XRP balance here.
            auto const escrowBal =
                escrowSle->getFieldAmount(sfBalance).xrp();
            auto const escrowReserve = view.fees().accountReserve(
                escrowSle->getFieldU32(sfOwnerCount));
            if (escrowBal < escrowReserve + XRPAmount(e.value))
            {
                JLOG(j_.warn())
                    << "BatchRollup2: escrow cannot fund withdrawal of "
                    << e.value << " drops without breaching its reserve "
                    << "→ tecINSUF_RESERVE_LINE";
                return tecINSUF_RESERVE_LINE;
            }

            auto subBal = escrowSle->getFieldAmount(sfBalance);
            subBal -= STAmount(XRPAmount(e.value));
            escrowSle->setFieldAmount(sfBalance, subBal);
            view.update(escrowSle);

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

    // Erase exactly the claims this batch consumed. setDepositClaims also
    // rewrites the aggregate, so it stays consistent with the array; `pending`
    // is recomputed from the survivors rather than trusted.
    if (!consumed.empty())
    {
        std::vector<bool> drop(claims.size(), false);
        for (auto i : consumed)
            drop[i] = true;

        std::vector<RollupState2::DepositClaim> remaining;
        remaining.reserve(claims.size() - consumed.size());
        for (std::size_t i = 0; i < claims.size(); ++i)
            if (!drop[i])
                remaining.push_back(claims[i]);

        RollupState2::setDepositClaims(*sle, remaining);
    }

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
