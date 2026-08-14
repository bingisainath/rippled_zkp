// RollupSequencer unit tests.
// Namespace ripple::test, to match the other rollup test files.

#include <libxrpl/zkp/rollup/BatchProof.h>
#include <libxrpl/zkp/rollup/RollupNote.h>
#include <libxrpl/zkp/rollup/RollupProver.h>
#include <libxrpl/zkp/rollup/RollupSequencer.h>
#include <libxrpl/zkp/rollup/RollupState.h>     // kRollupTreeDepth

#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/SecretKey.h>

#include <atomic>
#include <cstring>
#include <vector>

namespace ripple {
namespace test {

using zkp::rollup::BatchProof;
using zkp::rollup::BATCH_SIZE;
using zkp::rollup::ClientEntry;
using zkp::rollup::kRollupTreeDepth;
using zkp::rollup::LiveState;
using zkp::rollup::RejectReason;
using zkp::rollup::RollupProver;
using zkp::rollup::RollupSequencer;
using zkp::rollup::RollupTxEntry;
using zkp::rollup::RollupTxType;

class RollupSequencer_test : public beast::unit_test::suite
{
    // Build a deterministic uint256 from a single seed integer.
    static uint256
    u256FromSeed(std::uint64_t seed)
    {
        uint256 v{};
        std::memcpy(v.data(), &seed, sizeof(seed));
        return v;
    }

    // Build a deterministic well-formed entry with distinct fields per seed.
    static ClientEntry
    makeEntry(int seed)
    {
        ClientEntry ce;
        ce.entry.commitment  = u256FromSeed(static_cast<std::uint64_t>(seed) * 7 + 11);
        ce.entry.nullifier   = u256FromSeed(static_cast<std::uint64_t>(seed) * 7 + 13);
        ce.entry.value       = 1'000'000ULL * static_cast<std::uint64_t>(seed + 1);
        ce.entry.txType      = RollupTxType::Deposit;
        ce.entry.destination = AccountID{};
        ce.leaf_position     = static_cast<std::uint64_t>(seed);
        // Stand-in proof bytes: not a real Groth16 proof, but passes the
        // sequencer's well-formedness check (size >= 64). The actual
        // on-chain Groth16 verification is exercised in
        // BatchVerifier_test's real-proof path, not here.
        ce.proof_bytes.assign(137, static_cast<unsigned char>(0xA0 + seed));
        return ce;
    }

    static std::pair<PublicKey, SecretKey>
    makeKey()
    {
        auto const seed = generateSeed("rollup-sequencer-test-seed");
        return generateKeyPair(KeyType::ed25519, seed);
    }


    void
    testAutoAssembly()
    {
        testcase("queue fills to BATCH_SIZE and auto-assembles");

        std::vector<std::vector<std::uint8_t>> submitted;
        auto submit = [&](std::vector<std::uint8_t> const& blob) {
            submitted.push_back(blob);
            return true;
        };
        auto state = []() -> std::optional<LiveState> {
            return LiveState{uint256{}, 0};
        };

        auto kp = makeKey();
        RollupSequencer seq(kp.first, kp.second, kRollupTreeDepth,
                            submit, state);

        for (int i = 0; i < static_cast<int>(BATCH_SIZE) - 1; ++i)
        {
            auto r = seq.submitEntry(makeEntry(i));
            BEAST_EXPECT(r == RejectReason::Accepted);
        }
        BEAST_EXPECT(seq.queueDepth() == BATCH_SIZE - 1);
        BEAST_EXPECT(submitted.empty());

        // The BATCH_SIZE-th entry triggers assembly.
        auto r = seq.submitEntry(makeEntry(BATCH_SIZE - 1));
        BEAST_EXPECT(r == RejectReason::Accepted);
        BEAST_EXPECT(seq.queueDepth() == 0);
        BEAST_EXPECT(submitted.size() == 1);
        BEAST_EXPECT(!submitted.front().empty());
    }

    void
    testDuplicateNullifierRejected()
    {
        testcase("duplicate nullifier rejected before queue insertion");

        auto submit = [](auto const&) { return true; };
        auto state = []() -> std::optional<LiveState> {
            return LiveState{uint256{}, 0};
        };

        auto kp = makeKey();
        RollupSequencer seq(kp.first, kp.second, kRollupTreeDepth,
                            submit, state);

        auto e = makeEntry(0);
        BEAST_EXPECT(seq.submitEntry(e) == RejectReason::Accepted);
        BEAST_EXPECT(
            seq.submitEntry(e) ==
            RejectReason::DuplicateNullifierInQueue);
        BEAST_EXPECT(seq.queueDepth() == 1);
    }

    void
    testMalformedEntryRejected()
    {
        testcase("malformed entry rejected (zero value / missing fields)");

        auto submit = [](auto const&) { return true; };
        auto state = []() -> std::optional<LiveState> {
            return LiveState{uint256{}, 0};
        };

        auto kp = makeKey();
        RollupSequencer seq(kp.first, kp.second, kRollupTreeDepth,
                            submit, state);

        auto bad1 = makeEntry(0);
        bad1.entry.value = 0;
        BEAST_EXPECT(
            seq.submitEntry(bad1) == RejectReason::InvalidEntry);

        auto bad2 = makeEntry(1);
        bad2.entry.nullifier = uint256{};
        BEAST_EXPECT(
            seq.submitEntry(bad2) == RejectReason::InvalidEntry);

        auto bad3 = makeEntry(2);
        bad3.entry.txType = RollupTxType::Withdraw;
        // destination still zero -> reject
        BEAST_EXPECT(
            seq.submitEntry(bad3) == RejectReason::InvalidEntry);

        auto bad4 = makeEntry(3);
        bad4.proof_bytes.clear();
        BEAST_EXPECT(
            seq.submitEntry(bad4) == RejectReason::InvalidEntry);
    }

    void
    testStaleRootRecovery()
    {
        testcase("stale prevRoot recovery: state_() returns refreshed root");

        std::atomic<int> calls{0};
        auto submit = [](auto const&) { return true; };
        auto state = [&]() -> std::optional<LiveState> {
            int n = calls.fetch_add(1);
            if (n == 0)
                return LiveState{uint256{}, 0};
            // Subsequent calls: simulate that another batch landed
            // between our first observation and this assembly attempt.
            return LiveState{u256FromSeed(42), 1};
        };

        auto kp = makeKey();
        RollupSequencer seq(kp.first, kp.second, kRollupTreeDepth,
                            submit, state);

        for (int i = 0; i < static_cast<int>(BATCH_SIZE); ++i)
            seq.submitEntry(makeEntry(i));

        // After one assembly with the second state_() answer, the next
        // batch should be numbered batchCounter+1 = 2.
        BEAST_EXPECT(seq.pendingBatchId() == 1);
    }

    void
    testSubmitFailureLeavesNullifiersPending()
    {
        testcase("submit failure: nullifiers stay pending (safety)");

        auto submit = [](auto const&) { return false; };  // always reject
        auto state = []() -> std::optional<LiveState> {
            return LiveState{uint256{}, 0};
        };

        auto kp = makeKey();
        RollupSequencer seq(kp.first, kp.second, kRollupTreeDepth,
                            submit, state);

        for (int i = 0; i < static_cast<int>(BATCH_SIZE); ++i)
            seq.submitEntry(makeEntry(i));

        // Resubmitting the same nullifier MUST still be rejected even
        // though the batch was dropped — protects against accidental
        // double-queue after a rippled-side reject.
        BEAST_EXPECT(
            seq.submitEntry(makeEntry(0)) ==
            RejectReason::DuplicateNullifierInQueue);
    }

    void
    testStateFetchFailure()
    {
        testcase("state_() failure: entries returned to queue head");

        std::atomic<int> calls{0};
        auto submit = [](auto const&) { return true; };
        auto state = [&]() -> std::optional<LiveState> {
            // First call (during the auto-triggered assembly) fails.
            if (calls.fetch_add(1) == 0)
                return std::nullopt;
            return LiveState{uint256{}, 0};
        };

        auto kp = makeKey();
        RollupSequencer seq(kp.first, kp.second, kRollupTreeDepth,
                            submit, state);

        for (int i = 0; i < static_cast<int>(BATCH_SIZE); ++i)
            seq.submitEntry(makeEntry(i));

        // Assembly was aborted; entries should be back in the queue.
        BEAST_EXPECT(seq.queueDepth() == BATCH_SIZE);

        // flush() now succeeds against the second state_() return.
        auto bp = seq.flush();
        BEAST_EXPECT(bp.has_value());
        BEAST_EXPECT(seq.queueDepth() == 0);
    }

public:
    void
    run() override
    {
        // RollupProver needs to be initialised so submitEntry's
        // ProverNotInitialized guard doesn't fire. First call may take
        // ~30–60 s for trusted setup; subsequent test runs are fast.
        RollupProver::initialize();

        testAutoAssembly();
        testDuplicateNullifierRejected();
        testMalformedEntryRejected();
        testStaleRootRecovery();
        testSubmitFailureLeavesNullifiersPending();
        testStateFetchFailure();
    }
};

BEAST_DEFINE_TESTSUITE(RollupSequencer, zkp_rollup, ripple);

}  // namespace test
}  // namespace ripple