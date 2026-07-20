// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// Phase 6 gate — Track 2 end-to-end sequencer pipeline (no rippled Env):
// user signs -> sequencer builds batch -> real Groth16 proof -> verifyBatch,
// with the crucial circuit/tree/blob root-consistency assertions.
//
// MANUAL (keygen + proving are slow). Run:
//   ./rippled --unittest=ripple.zkp.RollupSequencer2

#include "../../../libxrpl/zkp/rollup/BatchCircuitProver.h"
#include "../../../libxrpl/zkp/rollup/RollupSequencer2.h"
#include "../../../libxrpl/zkp/rollup/RollupState2.h"

#include <xrpl/beast/unit_test.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace ripple {
namespace test {

using namespace zkp::rollup;

class RollupSequencer2_test : public beast::unit_test::suite
{
    static constexpr std::size_t kDepth = 8;
    static constexpr char const* kKeyPath = "/tmp/rippled_seq2_keys_test";

    void
    setupOnce()
    {
        static bool done = false;
        if (done)
            return;
        libff::alt_bn128_pp::init_public_params();
        BabyJubjub::initialize();
        PoseidonHash::initialize();
        BatchCircuitProver::initialize(kKeyPath, 8, kDepth);
        done = true;
    }

    static FieldT
    userKey(std::size_t i)
    {
        return FieldT("880000110022003300") + FieldT(i);
    }

    // A deterministic, non-zero L1 payout target for withdrawal tests.
    static AccountID
    payoutAccount()
    {
        AccountID id;
        for (std::size_t b = 0; b < id.size(); ++b)
            id.begin()[b] = static_cast<std::uint8_t>(0xA0 + b);
        return id;
    }

public:
    void
    testGenesisRootConsistency()
    {
        testcase("Phase 6 — empty sequencer root == RollupState2 genesis root");
        setupOnce();

        RollupSequencer2 seq(kDepth);
        BEAST_EXPECT(seq.root() == emptyAccountTreeRoot(kDepth));
    }

    void
    testBuildBatchAndVerify()
    {
        testcase("Phase 6 — sequencer builds a batch that verifyBatch accepts");
        setupOnce();

        RollupSequencer2 seq(kDepth);
        uint256 const prevRoot = seq.root();

        // Three deposits (create accounts), rest padded with NoOps.
        std::vector<SequencerRequest> reqs;
        for (std::size_t i = 0; i < 3; ++i)
        {
            SequencerRequest sr;
            BjjPoint apk = EdDSA::derivePublicKey(userKey(i));
            sr.req = SignedRequest::make(
                userKey(i), apk.x, 100 + i * 10, 0, RequestType::Deposit);
            reqs.push_back(sr);
        }

        auto bp = seq.buildBatch(reqs, /*batchId=*/1);
        BEAST_EXPECT(bp.has_value());
        if (!bp)
            return;

        // Root consistency: the blob's newRoot equals the sequencer's tree
        // root after applying — THE guard that circuit/tree conventions agree.
        BEAST_EXPECT(bp->prevRoot == prevRoot);
        BEAST_EXPECT(bp->newRoot == seq.root());

        // The proof verifies against the recomputed public inputs (mirrors
        // BatchRollup2::preclaim).
        FieldT const prevF = PoseidonHash::uint256ToField(bp->prevRoot);
        FieldT const newF = PoseidonHash::uint256ToField(bp->newRoot);
        FieldT const ehF = bp->computeEntriesHash();
        BEAST_EXPECT(
            BatchCircuitProver::verifyBatch(prevF, newF, ehF, bp->proof));

        // Blob round-trips.
        auto const blob = bp->serialize();
        bool ok = false;
        auto rt = BatchProof2::deserialize(blob, ok);
        BEAST_EXPECT(ok);
        BEAST_EXPECT(rt.newRoot == bp->newRoot);

        // Accounts now exist with the deposited balances at nonce 1.
        auto a0 = seq.account(EdDSA::derivePublicKey(userKey(0)).x);
        BEAST_EXPECT(a0.has_value());
        if (a0)
        {
            BEAST_EXPECT(a0->balance == 100);
            BEAST_EXPECT(a0->nonce == 1);
        }
    }

    void
    testTamperedNewRootRejected()
    {
        testcase("Phase 6 — verifyBatch rejects a tampered newRoot");
        setupOnce();

        RollupSequencer2 seq(kDepth);
        std::vector<SequencerRequest> reqs;
        SequencerRequest sr;
        BjjPoint apk = EdDSA::derivePublicKey(userKey(5));
        sr.req = SignedRequest::make(
            userKey(5), apk.x, 250, 0, RequestType::Deposit);
        reqs.push_back(sr);

        auto bp = seq.buildBatch(reqs, 1);
        BEAST_EXPECT(bp.has_value());
        if (!bp)
            return;

        FieldT const prevF = PoseidonHash::uint256ToField(bp->prevRoot);
        FieldT const badNewF =
            PoseidonHash::uint256ToField(bp->newRoot) + FieldT::one();
        FieldT const ehF = bp->computeEntriesHash();
        BEAST_EXPECT(
            !BatchCircuitProver::verifyBatch(prevF, badNewF, ehF, bp->proof));
    }

    void
    testReplayedNonceRejectedByAdmission()
    {
        testcase("Phase 6 — sequencer admission rejects a stale nonce");
        setupOnce();

        RollupSequencer2 seq(kDepth);
        std::vector<SequencerRequest> reqs;
        SequencerRequest sr;
        BjjPoint apk = EdDSA::derivePublicKey(userKey(6));
        sr.req = SignedRequest::make(
            userKey(6), apk.x, 400, 0, RequestType::Deposit);
        reqs.push_back(sr);
        auto bp1 = seq.buildBatch(reqs, 1);
        BEAST_EXPECT(bp1.has_value());

        // Re-submitting the same nonce-0 request must be refused (account is
        // now at nonce 1).
        BEAST_EXPECT(!seq.admit(sr.req));

        // A withdraw at the correct nonce (1) is admitted.
        auto wreq = SignedRequest::make(
            userKey(6), FieldT("777"), 100, 1, RequestType::Withdraw);
        BEAST_EXPECT(seq.admit(wreq));
    }

    void
    testSecondBatchChains()
    {
        testcase("Phase 6 — second batch chains from the first root");
        setupOnce();

        RollupSequencer2 seq(kDepth);
        std::vector<SequencerRequest> r1;
        {
            SequencerRequest sr;
            BjjPoint apk = EdDSA::derivePublicKey(userKey(7));
            sr.req = SignedRequest::make(
                userKey(7), apk.x, 500, 0, RequestType::Deposit);
            r1.push_back(sr);
        }
        auto bp1 = seq.buildBatch(r1, 1);
        BEAST_EXPECT(bp1.has_value());
        if (!bp1)
            return;

        std::vector<SequencerRequest> r2;
        {
            SequencerRequest sr;
            // A withdrawal's signed `dest` MUST encode the L1 payout target
            // (AccountLeaf.h). buildBatch rejects the batch otherwise, and so
            // does BatchRollup2::preflight.
            sr.destination = payoutAccount();
            sr.req = SignedRequest::make(
                userKey(7),
                accountIdToField(sr.destination),
                200,
                1,
                RequestType::Withdraw);
            r2.push_back(sr);
        }
        auto bp2 = seq.buildBatch(r2, 2);
        BEAST_EXPECT(bp2.has_value());
        if (!bp2)
            return;

        // Chain: batch 2's prevRoot == batch 1's newRoot.
        BEAST_EXPECT(bp2->prevRoot == bp1->newRoot);

        FieldT const prevF = PoseidonHash::uint256ToField(bp2->prevRoot);
        FieldT const newF = PoseidonHash::uint256ToField(bp2->newRoot);
        FieldT const ehF = bp2->computeEntriesHash();
        BEAST_EXPECT(
            BatchCircuitProver::verifyBatch(prevF, newF, ehF, bp2->proof));

        auto a = seq.account(EdDSA::derivePublicKey(userKey(7)).x);
        BEAST_EXPECT(a.has_value());
        if (a)
        {
            BEAST_EXPECT(a->balance == 300);  // 500 - 200
            BEAST_EXPECT(a->nonce == 2);
        }
    }

    // A withdrawal whose signed `dest` does not encode its L1 payout target is
    // exactly the malicious-sequencer redirect: the user signs "pay AccountID
    // X" and the sequencer attaches AccountID Y. buildBatch must refuse it
    // before spending proving time, and BatchRollup2::preflight refuses it
    // again on-chain.
    void
    testWithdrawDestinationMismatchRejected()
    {
        testcase("Phase 6 — withdrawal dest/destination mismatch rejected");
        setupOnce();

        RollupSequencer2 seq(kDepth);

        std::vector<SequencerRequest> r1;
        {
            SequencerRequest sr;
            BjjPoint apk = EdDSA::derivePublicKey(userKey(5));
            sr.req = SignedRequest::make(
                userKey(5), apk.x, 500, 0, RequestType::Deposit);
            r1.push_back(sr);
        }
        BEAST_EXPECT(seq.buildBatch(r1, 1).has_value());

        // The user signs a withdrawal to payoutAccount()...
        AccountID const signedTarget = payoutAccount();

        // ...but the sequencer attaches a DIFFERENT payout AccountID.
        AccountID redirected;
        for (std::size_t b = 0; b < redirected.size(); ++b)
            redirected.begin()[b] = static_cast<std::uint8_t>(0xE0 + b);
        BEAST_EXPECT(redirected != signedTarget);

        std::vector<SequencerRequest> r2;
        {
            SequencerRequest sr;
            sr.destination = redirected;
            sr.req = SignedRequest::make(
                userKey(5),
                accountIdToField(signedTarget),  // signed for the OTHER target
                200,
                1,
                RequestType::Withdraw);
            r2.push_back(sr);
        }
        BEAST_EXPECT(!seq.buildBatch(r2, 2).has_value());

        // A zero payout target is equally invalid.
        std::vector<SequencerRequest> r3;
        {
            SequencerRequest sr;  // sr.destination left as AccountID{}
            sr.req = SignedRequest::make(
                userKey(5),
                accountIdToField(signedTarget),
                200,
                1,
                RequestType::Withdraw);
            r3.push_back(sr);
        }
        BEAST_EXPECT(!seq.buildBatch(r3, 2).has_value());

        // The sequencer's state must be untouched by the rejected batches.
        auto a = seq.account(EdDSA::derivePublicKey(userKey(5)).x);
        BEAST_EXPECT(a.has_value());
        if (a)
        {
            BEAST_EXPECT(a->balance == 500);
            BEAST_EXPECT(a->nonce == 1);
        }
    }

    // Transfer is reserved: the BatchCircuit bans it via `t1 == w`, so the
    // sequencer must reject it at admission rather than at isSatisfied().
    void
    testTransferRejectedAtAdmission()
    {
        testcase("Phase 6 — Transfer rejected at admission (reserved)");
        setupOnce();

        RollupSequencer2 seq(kDepth);
        auto const req = SignedRequest::make(
            userKey(3),
            EdDSA::derivePublicKey(userKey(4)).x,
            10,
            0,
            RequestType::Transfer);
        BEAST_EXPECT(!seq.admit(req));
    }

    void
    run() override
    {
        testGenesisRootConsistency();
        testBuildBatchAndVerify();
        testTamperedNewRootRejected();
        testReplayedNonceRejectedByAdmission();
        testWithdrawDestinationMismatchRejected();
        testTransferRejectedAtAdmission();
        testSecondBatchChains();
    }
};

BEAST_DEFINE_TESTSUITE_MANUAL(RollupSequencer2, zkp, ripple);

}  // namespace test
}  // namespace ripple
