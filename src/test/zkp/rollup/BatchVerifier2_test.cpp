// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// Phase 6 gate — Track 2 transactor (ttBATCH_ROLLUP2) driven on a real
// jtx::Env ledger: preflight -> preclaim -> doApply. Complements
// RollupSequencer2_test (which validates the crypto but bypasses the
// transactor). MANUAL: Env construction triggers onStart (both provers'
// keygen) and the success path builds a real depth-16 proof (~38 s).
//
// Run: ./rippled --unittest=ripple.zkp_rollup.BatchVerifier2

#include <libxrpl/zkp/rollup/AccountLeaf.h>
#include <libxrpl/zkp/rollup/BatchProof2.h>
#include <libxrpl/zkp/rollup/BatchVerifier2.h>
#include <libxrpl/zkp/rollup/PoseidonHash.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>
#include <libxrpl/zkp/rollup/RollupSequencer2.h>
#include <libxrpl/zkp/rollup/RollupState2.h>

#include <test/jtx.h>
#include <test/jtx/Env.h>

#include <xrpl/basics/StringUtilities.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/jss.h>

namespace ripple {
namespace test {

using namespace zkp::rollup;

class BatchVerifier2_test : public beast::unit_test::suite
{
    // Env's BatchCircuitProver comes up at the production shape (8, 16).
    static constexpr std::size_t kDepth = 16;

    std::size_t submitterIdx_ = 0;

    jtx::Account
    freshSubmitter(jtx::Env& env)
    {
        jtx::Account a("submitter2_" + std::to_string(++submitterIdx_));
        env.fund(jtx::XRP(100000), a);
        env.close();
        return a;
    }

    static FieldT
    userKey(std::size_t i)
    {
        return FieldT("660000110022003300") + FieldT(i);
    }

    // Build a deposit batch via the sequencer. Returns (blob, pubKey, bp).
    struct BuiltBatch
    {
        BatchProof2 bp;
        std::vector<std::uint8_t> pubKey;
        std::vector<std::uint8_t> blob;
    };

    // Total drops a buildDepositBatch(_, n) will credit to L2. The escrow must
    // hold at least this much before the batch can be applied.
    static std::uint64_t
    depositBatchDrops(std::size_t nDeposits)
    {
        std::uint64_t t = 0;
        for (std::size_t i = 0; i < nDeposits; ++i)
            t += 1000 + i;
        return t;
    }

    // One sequencer building successive batches, so prevRoot/newRoot chain the
    // way they do in production. Tests that want a DELIBERATE chain break just
    // use a second Chain instance.
    struct Chain
    {
        RollupSequencer2 seq{kDepth};

        BuiltBatch
        build(std::vector<SequencerRequest> const& reqs, std::uint32_t batchId)
        {
            auto bp = seq.buildBatch(reqs, batchId);
            if (!bp)
                Throw<std::runtime_error>("sequencer failed to build batch");
            BuiltBatch bb;
            bb.bp = *bp;
            bb.pubKey = seq.publicKey();
            bb.blob = bp->serialize();
            return bb;
        }

        // Bootstrap batch: anchors the sequencer key and the escrow account
        // without crediting any L2 balance. It cannot be empty — isWellFormed
        // rejects txCount == 0 — so it carries a single NoOp, which admit()
        // accepts unconditionally.
        BuiltBatch
        bootstrap(std::uint32_t batchId)
        {
            SequencerRequest sr;
            // dest = 0, matching the sequencer's own NoOp pad slots.
            sr.req = SignedRequest::make(
                userKey(99), FieldT::zero(), 0, 0, RequestType::NoOp);
            return build({sr}, batchId);
        }

        // A batch containing one real withdrawal. `dest` must be an EXISTING
        // funded account: doApply creates a missing destination only if the
        // withdrawn value clears the account reserve, and these test values
        // are drops, not XRP.
        //
        // The signed `dest` field must encode the L1 payout target, or both
        // the sequencer and BatchRollup2::preflight reject the batch.
        BuiltBatch
        withdraw(
            std::uint32_t batchId,
            std::size_t user,
            std::uint64_t value,
            std::uint64_t nonce,
            AccountID const& dest)
        {
            SequencerRequest sr;
            sr.destination = dest;
            sr.req = SignedRequest::make(
                userKey(user),
                accountIdToField(dest),
                value,
                nonce,
                RequestType::Withdraw);
            return build({sr}, batchId);
        }

        BuiltBatch
        deposits(std::uint32_t batchId, std::size_t nDeposits)
        {
            std::vector<SequencerRequest> reqs;
            for (std::size_t i = 0; i < nDeposits; ++i)
            {
                SequencerRequest sr;
                BjjPoint apk = EdDSA::derivePublicKey(userKey(i));
                sr.req = SignedRequest::make(
                    userKey(i), apk.x, 1000 + i, 0, RequestType::Deposit);
                reqs.push_back(sr);
            }
            return build(reqs, batchId);
        }
    };

    Json::Value
    batchRollup2Tx(jtx::Account const& submitter, BuiltBatch const& bb)
    {
        Json::Value tx;
        tx[jss::TransactionType] = "BatchRollup2";
        tx[jss::Account] = submitter.human();
        tx[jss::BatchId] = bb.bp.batchId;
        tx[jss::PrevRoot] = to_string(bb.bp.prevRoot);
        tx[jss::RollupRoot] = to_string(bb.bp.newRoot);
        tx[jss::TxCount] = bb.bp.txCount;
        tx[jss::SequencerPubKey] = strHex(bb.pubKey);
        tx[jss::BatchProof] = strHex(bb.blob);
        return tx;
    }

    // Phase 1 of the two-phase deposit: real XRP from a real AccountRoot into
    // the anchored escrow.
    Json::Value
    rollupDeposit2Tx(
        jtx::Account const& depositor,
        jtx::Account const& escrow,
        std::uint64_t drops)
    {
        Json::Value tx;
        tx[jss::TransactionType] = "RollupDeposit2";
        tx[jss::Account] = depositor.human();
        tx[jss::Destination] = escrow.human();
        tx[jss::Amount] = std::to_string(drops);
        tx[jss::DepositApk] =
            to_string(PoseidonHash::fieldToUint256(userKey(0)));
        return tx;
    }

public:
    void
    testFeatureDisabled()
    {
        testcase("Phase 6 — preflight rejects when featureZKRollup2 disabled");
        jtx::Env env(*this, jtx::supported_amendments() - featureZKRollup2);
        auto submitter = freshSubmitter(env);
        Chain c;
        auto bb = c.deposits(1, 1);
        env(batchRollup2Tx(submitter, bb), jtx::ter(temDISABLED));
    }

    void
    testMalformedBlob()
    {
        testcase("Phase 6 — preflight rejects a malformed sfBatchProof blob");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);
        Chain c;
        auto bb = c.deposits(1, 1);
        auto tx = batchRollup2Tx(submitter, bb);
        tx[jss::BatchProof] = "DEADBEEF";  // not a valid blob
        env(tx, jtx::ter(temMALFORMED));
    }

    void
    testNonMonotonicBatchId()
    {
        testcase("Phase 6 — preclaim rejects a non-first batchId at genesis");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);
        Chain c;
        // batchId 2 with no prior state → expectedBatchId is 1.
        auto bb = c.deposits(2, 1);
        env(batchRollup2Tx(submitter, bb), jtx::ter(temMALFORMED));
    }

    void
    testSuccessfulDepositBatch()
    {
        testcase("Phase 6 — backed deposit batch applies (tesSUCCESS)");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);
        jtx::Account depositor("depositor2_ok");
        env.fund(jtx::XRP(100000), depositor);
        env.close();

        Chain c;

        // Bootstrap: anchors the sequencer key and escrow = submitter.
        env(batchRollup2Tx(submitter, c.bootstrap(1)), jtx::ter(tesSUCCESS));
        env.close();

        auto const need = depositBatchDrops(3);
        auto const escrowBefore = env.balance(submitter).value().xrp();
        auto const depositorBefore = env.balance(depositor).value().xrp();

        // Phase 1: real XRP moves depositor -> escrow.
        env(rollupDeposit2Tx(depositor, submitter, need),
            jtx::ter(tesSUCCESS));
        env.close();

        BEAST_EXPECT(
            env.balance(submitter).value().xrp() ==
            escrowBefore + XRPAmount(need));
        // Depositor pays the amount plus the transaction fee.
        BEAST_EXPECT(
            env.balance(depositor).value().xrp() <
            depositorBefore - XRPAmount(need));

        {
            auto sle = env.current()->read(keylet::rollup_state2());
            BEAST_EXPECT(sle && sle->getFieldU64(sfPendingDeposits) == need);
        }

        // Phase 2: the batch consumes exactly what was escrowed.
        auto bb = c.deposits(2, 3);
        env(batchRollup2Tx(submitter, bb), jtx::ter(tesSUCCESS));
        env.close();

        auto sle = env.current()->read(keylet::rollup_state2());
        BEAST_EXPECT(sle != nullptr);
        if (sle)
        {
            BEAST_EXPECT(sle->getFieldU32(sfBatchCounter) == 2);
            BEAST_EXPECT(sle->getFieldH256(sfRollupRoot) == bb.bp.newRoot);
            // Counter fully consumed, pool credited.
            BEAST_EXPECT(sle->getFieldU64(sfPendingDeposits) == 0);
            BEAST_EXPECT(
                sle->getFieldAmount(sfBalance).xrp().drops() ==
                static_cast<std::int64_t>(need));
        }
    }

    void
    testUnbackedDepositRejected()
    {
        testcase("Phase 6 — batch cannot credit L2 with nothing escrowed");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);

        Chain c;
        env(batchRollup2Tx(submitter, c.bootstrap(1)), jtx::ter(tesSUCCESS));
        env.close();

        // No ttROLLUP_DEPOSIT2 has run, so sfPendingDeposits is 0. Before the
        // backed-deposit change this batch applied and minted L2 balance that
        // no L1 account had ever paid for.
        env(batchRollup2Tx(submitter, c.deposits(2, 3)),
            jtx::ter(tecINSUF_RESERVE_LINE));
        env.close();

        auto sle = env.current()->read(keylet::rollup_state2());
        BEAST_EXPECT(sle != nullptr);
        if (sle)
        {
            // Root and counter did not advance; no pool balance appeared.
            BEAST_EXPECT(sle->getFieldU32(sfBatchCounter) == 1);
            BEAST_EXPECT(sle->getFieldU64(sfPendingDeposits) == 0);
            BEAST_EXPECT(
                !sle->isFieldPresent(sfBalance) ||
                sle->getFieldAmount(sfBalance).xrp().drops() == 0);
        }
    }

    void
    testPartiallyBackedDepositRejected()
    {
        testcase("Phase 6 — batch cannot credit more than was escrowed");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);
        jtx::Account depositor("depositor2_short");
        env.fund(jtx::XRP(100000), depositor);
        env.close();

        Chain c;
        env(batchRollup2Tx(submitter, c.bootstrap(1)), jtx::ter(tesSUCCESS));
        env.close();

        // Escrow one drop less than the batch will try to credit.
        env(rollupDeposit2Tx(depositor, submitter, depositBatchDrops(3) - 1),
            jtx::ter(tesSUCCESS));
        env.close();

        env(batchRollup2Tx(submitter, c.deposits(2, 3)),
            jtx::ter(tecINSUF_RESERVE_LINE));
    }

    void
    testDepositToWrongEscrowRejected()
    {
        testcase("Phase 6 — deposit must target the anchored escrow");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);
        jtx::Account depositor("depositor2_wrong");
        jtx::Account impostor("impostor2");
        env.fund(jtx::XRP(100000), depositor, impostor);
        env.close();

        Chain c;
        env(batchRollup2Tx(submitter, c.bootstrap(1)), jtx::ter(tesSUCCESS));
        env.close();

        // Paying an account of the depositor's choosing would let them park
        // collateral somewhere the rollup cannot spend it from.
        env(rollupDeposit2Tx(depositor, impostor, 5000),
            jtx::ter(tecNO_PERMISSION));
    }

    void
    testDepositBeforeBootstrapRejected()
    {
        testcase("Phase 6 — deposit rejected before the escrow is anchored");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);
        jtx::Account depositor("depositor2_early");
        env.fund(jtx::XRP(100000), depositor);
        env.close();

        // No state SLE yet. Letting this through would let the first depositor
        // nominate an escrow account they control.
        env(rollupDeposit2Tx(depositor, submitter, 5000),
            jtx::ter(tecNO_ENTRY));
    }

    // Pool balance in drops, 0 when the field is absent.
    static std::int64_t
    poolDrops(std::shared_ptr<STLedgerEntry const> const& sle)
    {
        if (!sle || !sle->isFieldPresent(sfBalance))
            return 0;
        return sle->getFieldAmount(sfBalance).xrp().drops();
    }

    void
    testWithdrawalMovesRealXRP()
    {
        testcase("Phase 6 — withdrawal moves real XRP to a distinct account");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);
        jtx::Account depositor("depositor2_wd");
        jtx::Account payee("payee2_wd");
        env.fund(jtx::XRP(100000), depositor, payee);
        env.close();

        Chain c;
        env(batchRollup2Tx(submitter, c.bootstrap(1)), jtx::ter(tesSUCCESS));
        env.close();

        // Fund L2 user 0 with 1000 drops, backed by a real L1 deposit.
        auto const need = depositBatchDrops(1);
        env(rollupDeposit2Tx(depositor, submitter, need), jtx::ter(tesSUCCESS));
        env.close();
        env(batchRollup2Tx(submitter, c.deposits(2, 1)), jtx::ter(tesSUCCESS));
        env.close();

        auto const rootBefore =
            env.current()->read(keylet::rollup_state2())->getFieldH256(
                sfRollupRoot);
        auto const poolBefore =
            poolDrops(env.current()->read(keylet::rollup_state2()));
        auto const payeeBefore = env.balance(payee).value().xrp();
        auto const escrowBefore = env.balance(submitter).value().xrp();
        BEAST_EXPECT(poolBefore == static_cast<std::int64_t>(need));

        // User 0's nonce is 1 after the deposit batch (buildBatch stores
        // req.nonce + 1). Withdraw part of the balance to a DISTINCT account,
        // so the payout leg cannot cancel against the payer the way it does
        // when submitter and destination are both genesis.
        std::uint64_t const wd = 400;
        auto bb = c.withdraw(3, 0, wd, 1, payee.id());
        env(batchRollup2Tx(submitter, bb), jtx::ter(tesSUCCESS));
        env.close();

        // Destination gained exactly the withdrawn drops (no fee on this leg).
        BEAST_EXPECT(
            env.balance(payee).value().xrp() == payeeBefore + XRPAmount(wd));

        // Pool fell by exactly the same.
        auto const sle = env.current()->read(keylet::rollup_state2());
        BEAST_EXPECT(
            poolDrops(sle) == poolBefore - static_cast<std::int64_t>(wd));

        // Escrow funded the payout. It also paid the batch fee, so this leg is
        // an inequality rather than an exact match.
        BEAST_EXPECT(
            env.balance(submitter).value().xrp() <=
            escrowBefore - XRPAmount(wd));

        // The root advanced to the proven post-state.
        BEAST_EXPECT(sle->getFieldH256(sfRollupRoot) == bb.bp.newRoot);
        BEAST_EXPECT(sle->getFieldH256(sfRollupRoot) != rootBefore);
        BEAST_EXPECT(sle->getFieldU32(sfBatchCounter) == 3);
    }

    void
    testWithdrawalBeyondEscrowRejected()
    {
        testcase("Phase 6 — withdrawal rejected when escrow cannot fund it");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);
        jtx::Account depositor("depositor2_drain");
        jtx::Account payee("payee2_drain");
        jtx::Account sink("sink2_drain");
        env.fund(jtx::XRP(100000), depositor, payee, sink);
        env.close();

        Chain c;
        env(batchRollup2Tx(submitter, c.bootstrap(1)), jtx::ter(tesSUCCESS));
        env.close();

        auto const need = depositBatchDrops(1);
        env(rollupDeposit2Tx(depositor, submitter, need), jtx::ter(tesSUCCESS));
        env.close();
        env(batchRollup2Tx(submitter, c.deposits(2, 1)), jtx::ter(tesSUCCESS));
        env.close();

        // Drain the escrow to just above its reserve, leaving far less than
        // the withdrawal needs. The POOL is still solvent (1000 drops vs a
        // 400-drop withdrawal), so this isolates the escrow guard rather than
        // the pool-solvency check that precedes it.
        auto const reserve = env.current()->fees().accountReserve(0);
        auto const bal = env.balance(submitter).value().xrp();
        env(jtx::pay(submitter, sink, jtx::drops(bal - reserve - XRPAmount(200))));
        env.close();
        BEAST_EXPECT(
            env.balance(submitter).value().xrp() < reserve + XRPAmount(400));

        env(batchRollup2Tx(submitter, c.withdraw(3, 0, 400, 1, payee.id())),
            jtx::ter(tecINSUF_RESERVE_LINE));
    }

    void
    testWrongPrevRootRejected()
    {
        testcase("Phase 6 — preclaim rejects a batch off the current root");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);
        jtx::Account depositor("depositor2_chain");
        env.fund(jtx::XRP(100000), depositor);
        env.close();

        Chain c1;
        env(batchRollup2Tx(submitter, c1.bootstrap(1)), jtx::ter(tesSUCCESS));
        env.close();

        // The bootstrap batch is all NoOps, and a NoOp leaves its slot empty —
        // so it does NOT move the root. Apply a real deposit batch to advance
        // it, otherwise a fresh sequencer's prevRoot still matches on-chain
        // and this test would exercise the wrong rejection path.
        env(rollupDeposit2Tx(depositor, submitter, depositBatchDrops(1)),
            jtx::ter(tesSUCCESS));
        env.close();
        env(batchRollup2Tx(submitter, c1.deposits(2, 1)),
            jtx::ter(tesSUCCESS));
        env.close();

        // A SECOND sequencer's batch starts from the empty root, not the
        // on-chain post-batch-2 root → prevRoot mismatch. The root-chain check
        // runs before the backed-deposit check, so this is the code path
        // under test even though nothing is escrowed.
        Chain c2;
        env(batchRollup2Tx(submitter, c2.deposits(3, 1)),
            jtx::ter(tecFAILED_PROCESSING));
    }

    void
    run() override
    {
        testFeatureDisabled();
        testMalformedBlob();
        testNonMonotonicBatchId();
        testSuccessfulDepositBatch();
        testUnbackedDepositRejected();
        testPartiallyBackedDepositRejected();
        testDepositToWrongEscrowRejected();
        testDepositBeforeBootstrapRejected();
        testWithdrawalMovesRealXRP();
        testWithdrawalBeyondEscrowRejected();
        testWrongPrevRootRejected();
    }
};

BEAST_DEFINE_TESTSUITE_MANUAL(BatchVerifier2, zkp_rollup, ripple);

}  // namespace test
}  // namespace ripple
