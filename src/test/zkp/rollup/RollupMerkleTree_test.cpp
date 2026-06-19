// Copyright (c) 2026 Sainath Annadevara — Trinity College Dublin.
// SPDX-License-Identifier: ISC
//
// test/zkp/rollup/RollupMerkleTree_test.cpp
//
// Phase 3 gate.  Exercises:
//   - empty-tree semantics (Poseidon, not all-zeros)
//   - append + root consistency
//   - update_leaf changes the root  (NOVEL contribution)
//   - update_leaf is reversible
//   - auth path verifies; tampered auth path fails
//   - N=8 sequential updates produce a deterministic root (Phase 5 invariant)
//   - cross-layer consistency: verify() vs the canonical PoseidonHash reference
//   - thread-safety smoke test for the sequencer's concurrent access pattern
//
// Run with:
//   ./rippled --unittest=ripple.zkp.RollupMerkleTree

// #include <xrpl/zkp/rollup/PoseidonHash.h>
#include "../../../libxrpl/zkp/rollup/PoseidonHash.h"
#include "../../../libxrpl/zkp/rollup/RollupMerkleTree.h"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/unit_test.h>

#include <atomic>
#include <stdexcept>
#include <thread>
#include <vector>

namespace ripple {
namespace test {

class RollupMerkleTree_test : public beast::unit_test::suite
{
    using Tree = ripple::zkp::rollup::RollupMerkleTree;
    // using ripple::zkp::rollup::MerkleWitness;

    // Helper: build a uint256 whose first byte is `b`.  Cheap, deterministic,
    // and good enough for non-cryptographic test inputs (we are testing the
    // tree, not the hash function).
    static uint256
    leaf(std::uint8_t b)
    {
        uint256 u{};
        u.begin()[0] = b;
        return u;
    }

    // ------------------------------------------------------------------
    // 1. Empty-tree semantics
    // ------------------------------------------------------------------
    //
    // The single most common bug carried over from a SHA-256 IMT is to assume
    // empty_hashes[0] == uint256{}.  For Poseidon it must be Poseidon(0, 0).
    //
    void
    testEmptyTree()
    {
        testcase("empty tree uses Poseidon(0,0), not zeros");

        Tree tree(4);
        BEAST_EXPECT(tree.size() == 0);
        BEAST_EXPECT(tree.depth() == 4);

        // Empty leaf hash must equal Poseidon(0,0).  This is the property
        // PoseidonCircuit's Merkle gadget assumes about untouched siblings.
        uint256 const poseidon_zero_zero =
            ripple::zkp::rollup::PoseidonHash::hash(uint256{}, uint256{});
        BEAST_EXPECT(tree.emptyHash(0) == poseidon_zero_zero);
        BEAST_EXPECT(tree.emptyHash(0) != uint256{});

        // Higher levels are Poseidon(empty[k-1], empty[k-1]).
        for (std::size_t k = 1; k <= 4; ++k)
        {
            uint256 const expected =
                ripple::zkp::rollup::PoseidonHash::hash(
                    tree.emptyHash(k - 1), tree.emptyHash(k - 1));
            BEAST_EXPECT(tree.emptyHash(k) == expected);
        }

        // Empty root == empty_hashes_[depth].
        BEAST_EXPECT(tree.root() == tree.emptyHash(4));
    }

    // ------------------------------------------------------------------
    // 2. append() advances the root
    // ------------------------------------------------------------------
    void
    testAppendAndRoot()
    {
        testcase("append + root consistency");

        Tree tree(4);
        uint256 const root0 = tree.root();

        std::size_t const pos1 = tree.append(leaf(0xAA));
        BEAST_EXPECT(pos1 == 0);
        uint256 const root1 = tree.root();
        BEAST_EXPECT(root1 != root0);

        std::size_t const pos2 = tree.append(leaf(0xBB));
        BEAST_EXPECT(pos2 == 1);
        uint256 const root2 = tree.root();
        BEAST_EXPECT(root2 != root1);

        BEAST_EXPECT(tree.size() == 2);
    }

    // ------------------------------------------------------------------
    // 3. update_leaf changes the root  --- NOVEL contribution
    // ------------------------------------------------------------------
    void
    testUpdateLeafChangesRoot()
    {
        testcase("update_leaf changes the root");

        Tree tree(4);
        tree.append(leaf(0xAA));
        tree.append(leaf(0xBB));
        uint256 const before = tree.root();

        tree.update_leaf(0, leaf(0xCC));
        uint256 const after = tree.root();
        BEAST_EXPECT(before != after);

        // Tree size doesn't change — update is in-place, not append.
        BEAST_EXPECT(tree.size() == 2);
    }

    // ------------------------------------------------------------------
    // 4. update_leaf is reversible
    // ------------------------------------------------------------------
    //
    // This is the strongest local correctness test: it catches "we forgot to
    // invalidate ancestors" bugs by going there and coming back.
    //
    void
    testUpdateLeafReversible()
    {
        testcase("update_leaf is reversible");

        Tree tree(4);
        uint256 const original = leaf(0xAA);
        tree.append(original);
        tree.append(leaf(0xBB));
        uint256 const root_original = tree.root();

        tree.update_leaf(0, leaf(0xFF));   // mutate
        tree.update_leaf(0, original);      // restore
        uint256 const root_restored = tree.root();

        BEAST_EXPECT(root_original == root_restored);
    }

    // ------------------------------------------------------------------
    // 5. auth path verifies; tampered cases fail
    // ------------------------------------------------------------------
    void
    testAuthPathVerification()
    {
        testcase("auth path verifies; tampered cases fail");

        Tree tree(4);
        tree.append(leaf(0xAA));
        tree.append(leaf(0xBB));
        tree.append(leaf(0xCC));

        // Path length must equal depth.
        auto const path = tree.authPath(1);
        BEAST_EXPECT(path.size() == 4);

        uint256 const root = tree.root();
        BEAST_EXPECT(Tree::verify(leaf(0xBB), path, 1, root));

        // Wrong leaf → fails.
        BEAST_EXPECT(!Tree::verify(leaf(0xDD), path, 1, root));

        // Wrong position → fails.
        BEAST_EXPECT(!Tree::verify(leaf(0xBB), path, 0, root));

        // Tampered sibling → fails.
        auto tampered = path;
        tampered[0] = leaf(0xEE);
        BEAST_EXPECT(!Tree::verify(leaf(0xBB), tampered, 1, root));
    }

    // ------------------------------------------------------------------
    // 6. update_leaf preserves auth path semantics for OTHER leaves
    // ------------------------------------------------------------------
    //
    // After updating leaf 0, leaf 1's membership proof must still verify
    // against the *new* root.  This catches stale-cache bugs in adjacent
    // subtrees.
    //
    void
    testUpdatePreservesOtherLeavesAuthPath()
    {
        testcase("update_leaf preserves other leaves' auth paths");

        Tree tree(4);
        tree.append(leaf(0x01));
        tree.append(leaf(0x02));
        tree.append(leaf(0x03));
        tree.append(leaf(0x04));

        tree.update_leaf(0, leaf(0xAA));
        uint256 const newRoot = tree.root();

        for (std::size_t i = 1; i < 4; ++i)
        {
            auto const path = tree.authPath(i);
            BEAST_EXPECT(
                Tree::verify(leaf(static_cast<std::uint8_t>(i + 1)),
                             path, i, newRoot));
        }
    }

    // ------------------------------------------------------------------
    // 7. Determinism across N=8 sequential operations (the rollup's own
    //    batch size — Phase 5 sequencer invariant)
    // ------------------------------------------------------------------
    void
    testBatchUpdateDeterminism()
    {
        testcase("N=8 batches yield deterministic root");

        Tree t1(32);
        Tree t2(32);

        for (std::uint8_t i = 0; i < 8; ++i)
        {
            uint256 const cm =
                ripple::zkp::rollup::PoseidonHash::hash(leaf(i),
                                                       leaf(i + 100));
            t1.append(cm);
            t2.append(cm);
        }
        BEAST_EXPECT(t1.root() == t2.root());

        for (std::uint8_t i = 0; i < 8; ++i)
        {
            uint256 const newcm =
                ripple::zkp::rollup::PoseidonHash::hash(leaf(i + 200),
                                                       leaf(i + 300));
            t1.update_leaf(i, newcm);
            t2.update_leaf(i, newcm);
        }
        BEAST_EXPECT(t1.root() == t2.root());
    }

    // ------------------------------------------------------------------
    // 8. Cross-layer consistency: tree's root agrees with the canonical
    //    PoseidonHash recursion.
    // ------------------------------------------------------------------
    //
    // The full circuit-vs-tree test (Test 6 in the research doc) requires
    // PoseidonCircuit to be instantiated — that lives in the integration
    // build.  Here we verify the strictly local property: that the tree's
    // root for a known-good leaf set matches what the off-circuit reference
    // computes top-down.  PoseidonGadget is bit-exact with PoseidonHash
    // (Phase 2a gate), so any divergence at this layer would be a tree bug,
    // not a hash bug.
    //
    void
    testRootMatchesPoseidonReference()
    {
        testcase("root matches direct Poseidon recursion (depth 2)");

        // Build a depth-2 tree with all four leaves filled.
        Tree tree(2);
        tree.append(leaf(0x11));
        tree.append(leaf(0x22));
        tree.append(leaf(0x33));
        tree.append(leaf(0x44));

        using ripple::zkp::rollup::PoseidonHash;
        uint256 const left  = PoseidonHash::hash(leaf(0x11), leaf(0x22));
        uint256 const right = PoseidonHash::hash(leaf(0x33), leaf(0x44));
        uint256 const expected_root = PoseidonHash::hash(left, right);

        BEAST_EXPECT(tree.root() == expected_root);
    }

    // ------------------------------------------------------------------
    // 9. Edge cases for the public API
    // ------------------------------------------------------------------
    void
    testApiEdgeCases()
    {
        testcase("invalid arguments are rejected");

        // Depth 0 / >64 → invalid_argument.
        try { Tree z(0); fail("expected throw"); }
        catch (std::invalid_argument const&) { pass(); }
        try { Tree big(65); fail("expected throw"); }
        catch (std::invalid_argument const&) { pass(); }

        Tree tree(4);
        // update_leaf on empty tree → out_of_range.
        try { tree.update_leaf(0, leaf(0x55)); fail("expected throw"); }
        catch (std::out_of_range const&) { pass(); }

        // authPath on empty tree → out_of_range.
        try { (void)tree.authPath(0); fail("expected throw"); }
        catch (std::out_of_range const&) { pass(); }

        // Filling a small tree to capacity then appending one more → overflow.
        Tree tiny(2);  // capacity = 4
        for (int i = 0; i < 4; ++i)
            tiny.append(leaf(static_cast<std::uint8_t>(i)));
        try { tiny.append(leaf(0x99)); fail("expected throw"); }
        catch (std::overflow_error const&) { pass(); }
    }

    // ------------------------------------------------------------------
    // 10. clear() resets to empty state.
    // ------------------------------------------------------------------
    void
    testClear()
    {
        testcase("clear() resets the tree");

        Tree tree(4);
        uint256 const empty_root = tree.root();

        tree.append(leaf(0xAA));
        tree.append(leaf(0xBB));
        BEAST_EXPECT(tree.size() == 2);
        BEAST_EXPECT(tree.root() != empty_root);

        tree.clear();
        BEAST_EXPECT(tree.size() == 0);
        BEAST_EXPECT(tree.root() == empty_root);

        // Re-appending the same leaves yields the same intermediate roots.
        tree.append(leaf(0xAA));
        tree.append(leaf(0xBB));
        // (Determinism is already covered by testBatchUpdateDeterminism;
        //  here we just confirm clear() really did wipe state.)
        BEAST_EXPECT(tree.size() == 2);
    }

    // ------------------------------------------------------------------
    // 11. Concurrency smoke test
    // ------------------------------------------------------------------
    //
    // The sequencer (Phase 5) validates RollupTxEntries from worker threads
    // against a shared canonical tree.  We don't claim linearisability — we
    // just confirm that mixed concurrent reads (root) and writes (append)
    // don't corrupt the tree's internal invariants.  After the workers join,
    // size() must equal the number of appends and root() must match a
    // single-threaded replay of the same sequence (we cannot test for the
    // latter cheaply because thread interleaving determines leaf order; we
    // instead test that all leaves still verify).
    //
    void
    testConcurrentAppendsVerify()
    {
        testcase("concurrent appends yield a verifiable tree");

        Tree tree(8);  // capacity 256
        constexpr int kThreads = 4;
        constexpr int kPerThread = 16;

        std::vector<std::thread> workers;
        std::atomic<int> bytes{1};

        for (int t = 0; t < kThreads; ++t)
        {
            workers.emplace_back([&] {
                for (int i = 0; i < kPerThread; ++i)
                {
                    auto b = static_cast<std::uint8_t>(
                        bytes.fetch_add(1) & 0xFF);
                    tree.append(leaf(b));
                    // Concurrent read; just must not crash or deadlock.
                    (void)tree.root();
                }
            });
        }
        for (auto& w : workers) w.join();

        BEAST_EXPECT(tree.size() ==
                     static_cast<std::size_t>(kThreads * kPerThread));

        // Every leaf still verifies against the final root.
        uint256 const r = tree.root();
        for (std::size_t i = 0; i < tree.size(); ++i)
        {
            auto const w = tree.getWitness(i);
            BEAST_EXPECT(Tree::verify(w.leaf, w.auth_path, w.position, r));
            BEAST_EXPECT(w.root == r);
        }
    }

public:
    void
    run() override
    {
        // Mirror Phase 2 test setup (PoseidonGadget_test.cpp:38).
        // Required before any Fr<alt_bn128_pp> operation.
        libff::alt_bn128_pp::init_public_params();
        ripple::zkp::rollup::PoseidonHash::initialize();
        testEmptyTree();
        testAppendAndRoot();
        testUpdateLeafChangesRoot();
        testUpdateLeafReversible();
        testAuthPathVerification();
        testUpdatePreservesOtherLeavesAuthPath();
        testBatchUpdateDeterminism();
        testRootMatchesPoseidonReference();
        testApiEdgeCases();
        testClear();
        testConcurrentAppendsVerify();
    }
};

BEAST_DEFINE_TESTSUITE(RollupMerkleTree, rollup, ripple);

}  // namespace test
}  // namespace ripple