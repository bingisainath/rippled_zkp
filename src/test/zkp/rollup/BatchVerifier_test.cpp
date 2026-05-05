//------------------------------------------------------------------------------
/*
    Phase 1 — Foundation: BatchVerifier integration tests.
    Namespace: ripple::test  (matches ZKPTransaction_test etc.)
*/
//==============================================================================

#include <libxrpl/zkp/rollup/BatchProof.h>
#include <libxrpl/zkp/rollup/BatchVerifier.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>
#include <libxrpl/zkp/rollup/RollupState.h>

#include <test/jtx.h>
#include <test/jtx/Env.h>

#include <xrpl/basics/StringUtilities.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/SecretKey.h>
#include <xrpl/protocol/Sign.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>

#include <cstring>

namespace ripple {
namespace test {

using zkp::rollup::BatchProof;
using zkp::rollup::RollupTxEntry;
using zkp::rollup::RollupTxType;
using zkp::rollup::BATCH_SIZE;
using zkp::rollup::SEQUENCER_SIG_BYTES;
using zkp::rollup::kRollupTreeDepth;

class BatchVerifier_test : public beast::unit_test::suite
{
    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    struct SignedBatch
    {
        BatchProof bp;
        std::vector<std::uint8_t> pubKey;
        std::vector<std::uint8_t> blob;
    };

    static SignedBatch
    makeSignedBatch(
        std::uint32_t batchId,
        uint256 const& prevRoot,
        std::uint32_t n = BATCH_SIZE)
    {
        SignedBatch sb;
        sb.bp.batchId  = batchId;
        sb.bp.prevRoot = prevRoot;
        sb.bp.newRoot  = uint256(static_cast<std::uint64_t>(batchId * 7 + 3));
        sb.bp.txCount  = n;
        sb.bp.proof    = std::vector<std::uint8_t>(190, 0xAB);

        for (std::uint32_t i = 0; i < n; ++i)
        {
            RollupTxEntry e;
            e.commitment = uint256(static_cast<std::uint64_t>(i + 1) * 11);
            e.nullifier  = uint256(
                static_cast<std::uint64_t>(batchId * 10000 + i + 1));
            e.value      = 1'000'000ULL * (i + 1);
            e.txType     = RollupTxType::Deposit;
            sb.bp.entries.push_back(e);
        }

        std::string const seedStr = "sequencer-seed-phase1";
        auto const seed = generateSeed(seedStr);
        auto const kp   = generateKeyPair(KeyType::ed25519, seed);
        auto const& pk  = kp.first;
        auto const& sk  = kp.second;

        sb.pubKey.assign(pk.data(), pk.data() + pk.size());

        uint256 const bh = sb.bp.computeBatchHash();
        auto const sig = sign(pk, sk, Slice(bh.data(), bh.size()));
        if (sig.size() != SEQUENCER_SIG_BYTES)
            throw std::runtime_error("unexpected Ed25519 sig size");
        std::memcpy(sb.bp.sequencerSig.data(), sig.data(), SEQUENCER_SIG_BYTES);

        sb.blob = sb.bp.serialize();
        return sb;
    }

    static Json::Value
    batchRollupTx(jtx::Account const& submitter, SignedBatch const& sb)
    {
        Json::Value tx;
        tx[jss::TransactionType] = "BatchRollup";
        tx[jss::Account]         = submitter.human();
        tx[jss::BatchId]         = sb.bp.batchId;
        tx[jss::PrevRoot]        = to_string(sb.bp.prevRoot);
        tx[jss::RollupRoot]      = to_string(sb.bp.newRoot);
        tx[jss::TxCount]         = sb.bp.txCount;
        tx[jss::SequencerPubKey] = strHex(sb.pubKey);
        tx[jss::BatchProof]      = strHex(sb.blob);
        return tx;
    }

    // -------------------------------------------------------------------------
    // Tests — preflight
    // -------------------------------------------------------------------------

    void
    testFeatureDisabled()
    {
        testcase("preflight rejects when featureZKRollup disabled");
        using namespace jtx;

        Env env(*this, supported_amendments() - featureZKRollup);
        env.fund(XRP(10000), "alice");
        env.close();

        auto sb = makeSignedBatch(1, uint256{});
        auto tx = batchRollupTx(Account("alice"), sb);
        env(tx, ter(temDISABLED));
    }

    void
    testMalformedBlob()
    {
        testcase("preflight rejects malformed sfBatchProof blob");
        using namespace jtx;

        Env env(*this, supported_amendments() | featureZKRollup);
        env.fund(XRP(10000), "alice");
        env.close();

        auto sb = makeSignedBatch(1, uint256{});
        auto tx = batchRollupTx(Account("alice"), sb);
        tx[jss::BatchProof] = "DEADBEEFDEADBEEFDEADBEEFDEADBEEF";
        env(tx, ter(temMALFORMED));
    }

    void
    testTxCountMismatch()
    {
        testcase("preflight rejects sfTxCount != entries.size()");
        using namespace jtx;

        Env env(*this, supported_amendments() | featureZKRollup);
        env.fund(XRP(10000), "alice");
        env.close();

        auto sb = makeSignedBatch(1, uint256{});
        auto tx = batchRollupTx(Account("alice"), sb);
        tx[jss::TxCount] = sb.bp.txCount + 1;
        env(tx, ter(temMALFORMED));
    }

    void
    testBadSignature()
    {
        testcase("preflight rejects wrong Ed25519 signature");
        using namespace jtx;

        Env env(*this, supported_amendments() | featureZKRollup);
        env.fund(XRP(10000), "alice");
        env.close();

        auto sb = makeSignedBatch(1, uint256{});
        if (sb.blob.size() >= SEQUENCER_SIG_BYTES)
            sb.blob[sb.blob.size() - SEQUENCER_SIG_BYTES] ^= 0xFF;

        auto tx = batchRollupTx(Account("alice"), sb);
        tx[jss::BatchProof] = strHex(sb.blob);
        env(tx, ter(temBAD_SIGNATURE));
    }

    // -------------------------------------------------------------------------
    // Tests — preclaim
    // -------------------------------------------------------------------------

    void
    testStalePrevRoot()
    {
        testcase("preclaim rejects stale prevRoot -> tecFAILED_PROCESSING");
        using namespace jtx;

        Env env(*this, supported_amendments() | featureZKRollup);
        env.fund(XRP(10000), "alice");
        env.close();

        auto sb1 = makeSignedBatch(1, uint256{});
        env(batchRollupTx(Account("alice"), sb1), ter(tesSUCCESS));
        env.close();

        auto sb2 = makeSignedBatch(2, uint256{});  // wrong prevRoot
        env(batchRollupTx(Account("alice"), sb2), ter(tecFAILED_PROCESSING));
    }

    void
    testNonMonotonicBatchId()
    {
        testcase("preclaim rejects non-monotonic batchId -> temMALFORMED");
        using namespace jtx;

        Env env(*this, supported_amendments() | featureZKRollup);
        env.fund(XRP(10000), "alice");
        env.close();

        auto sb = makeSignedBatch(5, uint256{});  // should start at 1
        env(batchRollupTx(Account("alice"), sb), ter(temMALFORMED));
    }

    // -------------------------------------------------------------------------
    // Tests — doApply happy path
    // -------------------------------------------------------------------------

    void
    testSuccessfulGenesis()
    {
        testcase("Genesis batch creates RollupState SLE with correct values");
        using namespace jtx;

        Env env(*this, supported_amendments() | featureZKRollup);
        env.fund(XRP(10000), "alice");
        env.close();

        BEAST_EXPECT(!env.le(keylet::rollup_state()));

        auto sb = makeSignedBatch(1, uint256{});
        env(batchRollupTx(Account("alice"), sb), ter(tesSUCCESS));
        env.close();

        auto sle = env.le(keylet::rollup_state());
        BEAST_EXPECT(sle != nullptr);
        if (sle)
        {
            BEAST_EXPECT(sle->getFieldU32(sfBatchCounter) == 1);
            BEAST_EXPECT(sle->getFieldH256(sfRollupRoot) == sb.bp.newRoot);
            BEAST_EXPECT(sle->getFieldU8(sfRollupTreeDepth) == kRollupTreeDepth);
            BEAST_EXPECT(sle->isFieldPresent(sfSequencerKey));
        }
    }

    void
    testSuccessfulSecond()
    {
        testcase("Second batch increments counter and updates root");
        using namespace jtx;

        Env env(*this, supported_amendments() | featureZKRollup);
        env.fund(XRP(10000), "alice");
        env.close();

        auto sb1 = makeSignedBatch(1, uint256{});
        env(batchRollupTx(Account("alice"), sb1), ter(tesSUCCESS));
        env.close();

        auto sb2 = makeSignedBatch(2, sb1.bp.newRoot);
        env(batchRollupTx(Account("alice"), sb2), ter(tesSUCCESS));
        env.close();

        auto sle = env.le(keylet::rollup_state());
        BEAST_EXPECT(sle != nullptr);
        if (sle)
        {
            BEAST_EXPECT(sle->getFieldU32(sfBatchCounter) == 2);
            BEAST_EXPECT(sle->getFieldH256(sfRollupRoot) == sb2.bp.newRoot);
        }
    }

public:
    void
    run() override
    {
        testFeatureDisabled();
        testMalformedBlob();
        testTxCountMismatch();
        testBadSignature();
        testStalePrevRoot();
        testNonMonotonicBatchId();
        testSuccessfulGenesis();
        testSuccessfulSecond();
    }
};

BEAST_DEFINE_TESTSUITE(BatchVerifier, zkp_rollup, ripple);

}  // namespace test
}  // namespace ripple
