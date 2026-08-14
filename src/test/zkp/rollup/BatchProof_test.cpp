/*
    BatchProof unit tests.

    Coverage:
        1. testSerializeRoundtrip     — full N=8 serialize/deserialize fidelity
        2. testTxCountMismatch        — isWellFormed rejects txCount != entries.size()
        3. testEmptyProof             — isWellFormed rejects empty proof bytes
        4. testOversizedBatch         — isWellFormed rejects txCount > BATCH_SIZE
        5. testDeserializeGarbage     — defensive: random bytes never crash
        6. testBatchHashDeterminism   — same input -> same hash
        7. testBatchHashSensitivity   — changing any field changes the hash

    Run with:
        ./rippled --unittest=BatchProof
*/

#include <libxrpl/zkp/rollup/BatchProof.h>

#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/unit_test.h>

#include <random>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {
namespace test {

class BatchProof_test : public beast::unit_test::suite
{
    // Fill a uint256 with deterministic pseudo-random bytes from a seed.
    static uint256
    makeUint256(std::uint64_t seed)
    {
        std::mt19937_64 rng(seed);
        uint256 out;
        for (std::size_t i = 0; i < out.size(); i += 8)
        {
            std::uint64_t v = rng();
            for (int b = 0; b < 8 && i + b < out.size(); ++b)
                out.data()[i + b] =
                    static_cast<std::uint8_t>((v >> (b * 8)) & 0xFF);
        }
        return out;
    }

    static BatchProof
    makeFullBatch(std::uint32_t batchId = 1, std::uint32_t n = BATCH_SIZE)
    {
        BatchProof bp;
        bp.batchId  = batchId;
        bp.prevRoot = makeUint256(batchId * 100 + 1);
        bp.newRoot  = makeUint256(batchId * 100 + 2);
        bp.txCount  = n;
        bp.proof    = std::vector<std::uint8_t>(190, 0xAB);  // mock ~190 B

        for (std::uint32_t i = 0; i < n; ++i)
        {
            RollupTxEntry e;
            e.commitment = makeUint256(batchId * 1000 + i * 10 + 1);
            e.nullifier  = makeUint256(batchId * 1000 + i * 10 + 2);
            e.value      = 1'000'000ULL * (i + 1);  // 1 XRP, 2 XRP, ...
            e.txType     = (i % 2 == 0) ? RollupTxType::Deposit
                                         : RollupTxType::Withdraw;
            // Deterministic destination
            auto d = makeUint256(batchId * 1000 + i * 10 + 3);
            std::memcpy(e.destination.begin(), d.data(), 20);
            bp.entries.push_back(e);
        }

        // Deterministic 64 B fake Ed25519 signature
        for (std::size_t i = 0; i < SEQUENCER_SIG_BYTES; ++i)
            bp.sequencerSig[i] = static_cast<std::uint8_t>(i ^ 0x5A);

        return bp;
    }


    void
    testSerializeRoundtrip()
    {
        testcase("Serialize/deserialize roundtrip for N=8 batch");

        auto const bp = makeFullBatch();
        BEAST_EXPECT(bp.isWellFormed());

        auto blob = bp.serialize();
        BEAST_EXPECT(!blob.empty());

        bool ok = false;
        auto bp2 = BatchProof::deserialize(blob, ok);
        BEAST_EXPECT(ok);

        BEAST_EXPECT(bp2.batchId  == bp.batchId);
        BEAST_EXPECT(bp2.prevRoot == bp.prevRoot);
        BEAST_EXPECT(bp2.newRoot  == bp.newRoot);
        BEAST_EXPECT(bp2.txCount  == bp.txCount);
        BEAST_EXPECT(bp2.proof    == bp.proof);
        BEAST_EXPECT(bp2.sequencerSig == bp.sequencerSig);
        BEAST_EXPECT(bp2.entries.size() == bp.entries.size());
        for (std::size_t i = 0; i < bp.entries.size(); ++i)
            BEAST_EXPECT(bp2.entries[i] == bp.entries[i]);
    }

    void
    testTxCountMismatch()
    {
        testcase("isWellFormed rejects txCount != entries.size()");

        BatchProof bp;
        bp.txCount = 8;
        bp.entries.resize(5);  // declared 8, only 5 entries
        bp.proof = {0x01};
        BEAST_EXPECT(!bp.isWellFormed());
    }

    void
    testEmptyProof()
    {
        testcase("isWellFormed rejects empty proof");

        BatchProof bp;
        bp.txCount = 1;
        bp.entries.resize(1);
        bp.proof.clear();
        BEAST_EXPECT(!bp.isWellFormed());
    }

    void
    testOversizedBatch()
    {
        testcase("isWellFormed rejects txCount > BATCH_SIZE");

        BatchProof bp;
        bp.txCount = BATCH_SIZE + 1;
        bp.entries.resize(BATCH_SIZE + 1);
        bp.proof = {0x01};
        BEAST_EXPECT(!bp.isWellFormed());

        // Also: txCount == 0 is rejected
        BatchProof bp2;
        bp2.txCount = 0;
        bp2.entries.clear();
        bp2.proof = {0x01};
        BEAST_EXPECT(!bp2.isWellFormed());
    }

    void
    testDeserializeGarbage()
    {
        testcase("Deserializing garbage bytes never throws");

        std::mt19937 rng(0xDEADBEEF);
        for (int trial = 0; trial < 50; ++trial)
        {
            std::size_t const len = rng() % 2000;
            std::vector<std::uint8_t> blob(len);
            for (auto& b : blob)
                b = static_cast<std::uint8_t>(rng() & 0xFF);

            bool ok = false;
            BatchProof bp = BatchProof::deserialize(blob, ok);
            (void)bp;
            // Don't care whether ok is true or false — just no crash and
            // if ok==true the result must pass isWellFormed().
            if (ok)
                BEAST_EXPECT(bp.isWellFormed());
        }
    }

    void
    testBatchHashDeterminism()
    {
        testcase("computeBatchHash is deterministic");

        auto const bp = makeFullBatch();
        BEAST_EXPECT(bp.computeBatchHash() == bp.computeBatchHash());

        // Serialize/deserialize -> same hash
        bool ok = false;
        auto const blob = bp.serialize();
        auto const bp2  = BatchProof::deserialize(blob, ok);
        BEAST_EXPECT(ok);
        BEAST_EXPECT(bp2.computeBatchHash() == bp.computeBatchHash());
    }

    void
    testBatchHashSensitivity()
    {
        testcase("computeBatchHash changes when any committed field changes");

        auto const base = makeFullBatch();
        auto const h0   = base.computeBatchHash();

        {
            BatchProof m = base;
            m.batchId = base.batchId + 1;
            BEAST_EXPECT(m.computeBatchHash() != h0);
        }
        {
            BatchProof m = base;
            m.prevRoot = makeUint256(0xFFFF);
            BEAST_EXPECT(m.computeBatchHash() != h0);
        }
        {
            BatchProof m = base;
            m.newRoot = makeUint256(0xEEEE);
            BEAST_EXPECT(m.computeBatchHash() != h0);
        }
        {
            BatchProof m = base;
            m.entries[0].nullifier = makeUint256(0xDDDD);
            BEAST_EXPECT(m.computeBatchHash() != h0);
        }
    }

public:
    void
    run() override
    {
        testSerializeRoundtrip();
        testTxCountMismatch();
        testEmptyProof();
        testOversizedBatch();
        testDeserializeGarbage();
        testBatchHashDeterminism();
        testBatchHashSensitivity();
    }
};

BEAST_DEFINE_TESTSUITE(BatchProof, zkp_rollup, ripple);

}  // namespace test
}  // namespace rollup
}  // namespace zkp
}  // namespace ripple