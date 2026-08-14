// BatchProof2 wire format round-trip + hash binding.
// Run: ./rippled --unittest=ripple.zkp.BatchProof2

#include "../../../libxrpl/zkp/rollup/BatchProof2.h"
#include "../../../libxrpl/zkp/rollup/BatchCircuit.h"

#include <xrpl/beast/unit_test.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace ripple {
namespace test {

using namespace zkp::rollup;

class BatchProof2_test : public beast::unit_test::suite
{
    void
    setupOnce()
    {
        static bool done = false;
        if (done)
            return;
        libff::alt_bn128_pp::init_public_params();
        BabyJubjub::initialize();
        PoseidonHash::initialize();
        done = true;
    }

    BatchProof2
    sampleBatch(std::uint32_t txCount = 8)
    {
        BatchProof2 bp;
        bp.batchId = 1;
        bp.prevRoot = uint256{7};
        bp.newRoot = uint256{9};
        bp.txCount = txCount;
        bp.proof.assign(137, 0xAB);  // stand-in Groth16 proof bytes
        for (std::uint32_t i = 0; i < txCount; ++i)
        {
            BatchProof2Entry e;
            e.fromApkX = uint256{100 + i};
            e.dest = uint256{200 + i};
            e.value = 1000 + i;
            e.nonce = i;
            e.txType = (i % 2) ? RequestType::Withdraw : RequestType::Deposit;
            for (std::size_t b = 0; b < e.destination.size(); ++b)
                e.destination.begin()[b] = static_cast<std::uint8_t>(i + b);
            bp.entries.push_back(e);
        }
        for (std::size_t i = 0; i < bp.sequencerSig.size(); ++i)
            bp.sequencerSig[i] = static_cast<std::uint8_t>(i);
        return bp;
    }

public:
    void
    testRoundTrip()
    {
        testcase("BatchProof2 serialize/deserialize round-trip");
        setupOnce();

        auto bp = sampleBatch(8);
        BEAST_EXPECT(bp.isWellFormed());

        auto const blob = bp.serialize();
        // 76 header + 137 proof + 8*101 + 64 sig = 1085
        BEAST_EXPECT(blob.size() == 76 + 137 + 8 * 101 + 64);

        bool ok = false;
        auto rt = BatchProof2::deserialize(blob, ok);
        BEAST_EXPECT(ok);
        BEAST_EXPECT(rt.batchId == bp.batchId);
        BEAST_EXPECT(rt.prevRoot == bp.prevRoot);
        BEAST_EXPECT(rt.newRoot == bp.newRoot);
        BEAST_EXPECT(rt.txCount == bp.txCount);
        BEAST_EXPECT(rt.proof == bp.proof);
        BEAST_EXPECT(rt.entries == bp.entries);
        BEAST_EXPECT(rt.sequencerSig == bp.sequencerSig);
    }

    void
    testShortBlobRejected()
    {
        testcase("truncated blob fails to deserialize");
        setupOnce();

        auto blob = sampleBatch(8).serialize();
        blob.resize(blob.size() - 10);
        bool ok = true;
        BatchProof2::deserialize(blob, ok);
        BEAST_EXPECT(!ok);
    }

    void
    testTrailingGarbageRejected()
    {
        testcase("trailing garbage fails to deserialize");
        setupOnce();

        auto blob = sampleBatch(8).serialize();
        blob.push_back(0xFF);
        bool ok = true;
        BatchProof2::deserialize(blob, ok);
        BEAST_EXPECT(!ok);
    }

    void
    testEntriesHashMatchesCircuit()
    {
        testcase("computeEntriesHash matches BatchCircuit native chain");
        setupOnce();

        // Build entries from real signed requests so the message convention
        // is exercised end to end.
        std::vector<SignedRequest> reqs;
        BatchProof2 bp;
        bp.batchId = 1;
        bp.prevRoot = uint256{1};
        bp.newRoot = uint256{2};
        bp.txCount = 3;
        bp.proof.assign(137, 0x01);
        for (std::uint32_t i = 0; i < 3; ++i)
        {
            FieldT ask = FieldT("555000111222") + FieldT(i);
            auto req = SignedRequest::make(
                ask, FieldT("42") + FieldT(i), 500 + i, i,
                RequestType::Deposit);
            reqs.push_back(req);

            BatchProof2Entry e;
            e.fromApkX = PoseidonHash::fieldToUint256(req.from_apk.x);
            e.dest = PoseidonHash::fieldToUint256(req.dest);
            e.value = req.value;
            e.nonce = req.nonce;
            e.txType = req.type;
            bp.entries.push_back(e);
        }

        BEAST_EXPECT(
            bp.computeEntriesHash() ==
            BatchCircuit::computeEntriesHash(reqs));
    }

    void
    testBatchHashBindsEntries()
    {
        testcase("computeBatchHash changes when an entry changes");
        setupOnce();

        auto a = sampleBatch(8);
        auto b = a;
        b.entries[3].value += 1;
        BEAST_EXPECT(a.computeBatchHash() != b.computeBatchHash());

        auto c = a;
        c.newRoot = uint256{10};
        BEAST_EXPECT(a.computeBatchHash() != c.computeBatchHash());
    }

    void
    run() override
    {
        testRoundTrip();
        testShortBlobRejected();
        testTrailingGarbageRejected();
        testEntriesHashMatchesCircuit();
        testBatchHashBindsEntries();
    }
};

BEAST_DEFINE_TESTSUITE(BatchProof2, zkp, ripple);

}  // namespace test
}  // namespace ripple
