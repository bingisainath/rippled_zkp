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

    BuiltBatch
    buildDepositBatch(std::uint32_t batchId, std::size_t nDeposits)
    {
        RollupSequencer2 seq(kDepth);
        std::vector<SequencerRequest> reqs;
        for (std::size_t i = 0; i < nDeposits; ++i)
        {
            SequencerRequest sr;
            BjjPoint apk = EdDSA::derivePublicKey(userKey(i));
            sr.req = SignedRequest::make(
                userKey(i), apk.x, 1000 + i, 0, RequestType::Deposit);
            reqs.push_back(sr);
        }
        auto bp = seq.buildBatch(reqs, batchId);
        if (!bp)
            Throw<std::runtime_error>("sequencer failed to build batch");
        BuiltBatch bb;
        bb.bp = *bp;
        bb.pubKey = seq.publicKey();
        bb.blob = bp->serialize();
        return bb;
    }

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

public:
    void
    testFeatureDisabled()
    {
        testcase("Phase 6 — preflight rejects when featureZKRollup2 disabled");
        jtx::Env env(*this, jtx::supported_amendments() - featureZKRollup2);
        auto submitter = freshSubmitter(env);
        auto bb = buildDepositBatch(1, 1);
        env(batchRollup2Tx(submitter, bb), jtx::ter(temDISABLED));
    }

    void
    testMalformedBlob()
    {
        testcase("Phase 6 — preflight rejects a malformed sfBatchProof blob");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);
        auto bb = buildDepositBatch(1, 1);
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
        // batchId 2 with no prior state → expectedBatchId is 1.
        auto bb = buildDepositBatch(2, 1);
        env(batchRollup2Tx(submitter, bb), jtx::ter(temMALFORMED));
    }

    void
    testSuccessfulDepositBatch()
    {
        testcase("Phase 6 — full deposit batch applies (tesSUCCESS)");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);

        auto bb = buildDepositBatch(1, 3);
        env(batchRollup2Tx(submitter, bb), jtx::ter(tesSUCCESS));
        env.close();

        // RollupState2 SLE now exists with counter 1 and the batch's newRoot.
        auto sle = env.current()->read(keylet::rollup_state2());
        BEAST_EXPECT(sle != nullptr);
        if (sle)
        {
            BEAST_EXPECT(sle->getFieldU32(sfBatchCounter) == 1);
            BEAST_EXPECT(sle->getFieldH256(sfRollupRoot) == bb.bp.newRoot);
        }
    }

    void
    testWrongPrevRootRejected()
    {
        testcase("Phase 6 — preclaim rejects a batch off the current root");
        jtx::Env env(*this, jtx::supported_amendments() | featureZKRollup2);
        auto submitter = freshSubmitter(env);

        // Apply batch 1.
        auto bb1 = buildDepositBatch(1, 2);
        env(batchRollup2Tx(submitter, bb1), jtx::ter(tesSUCCESS));
        env.close();

        // A fresh sequencer's batch 2 starts from the empty root, not the
        // on-chain post-batch-1 root → prevRoot mismatch.
        auto bb2 = buildDepositBatch(2, 1);
        env(batchRollup2Tx(submitter, bb2),
            jtx::ter(tecFAILED_PROCESSING));
    }

    void
    run() override
    {
        testFeatureDisabled();
        testMalformedBlob();
        testNonMonotonicBatchId();
        testSuccessfulDepositBatch();
        testWrongPrevRootRejected();
    }
};

BEAST_DEFINE_TESTSUITE_MANUAL(BatchVerifier2, zkp_rollup, ripple);

}  // namespace test
}  // namespace ripple
