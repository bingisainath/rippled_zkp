// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// Phase 6 gate — BatchCircuit: one circuit, N account transitions.
// Run: ./rippled --unittest=ripple.zkp.BatchCircuit
//
// Small parameters (depth 4, N<=2) keep the satisfiability tests fast;
// a count-only case reports the constraint budget at production size
// (N=8, depth=16).

#include "../../../libxrpl/zkp/rollup/BatchCircuit.h"

#include <xrpl/beast/unit_test.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <cmath>
#include <optional>
#include <vector>

namespace ripple {
namespace test {

using namespace zkp::rollup;

namespace {

// Minimal native account tree for witness generation (test-only).
struct TestTree
{
    std::size_t depth;
    std::vector<FieldT> leaves;  // 2^depth, all zero (= empty) initially

    explicit TestTree(std::size_t d)
        : depth(d), leaves(std::size_t{1} << d, FieldT::zero())
    {
    }

    FieldT
    root() const
    {
        std::vector<FieldT> level = leaves;
        for (std::size_t d = 0; d < depth; ++d)
        {
            std::vector<FieldT> next(level.size() / 2);
            for (std::size_t i = 0; i < next.size(); ++i)
                next[i] =
                    PoseidonHash::hash(level[2 * i], level[2 * i + 1]);
            level = std::move(next);
        }
        return level[0];
    }

    std::vector<FieldT>
    authPath(std::size_t pos) const
    {
        std::vector<FieldT> path;
        std::vector<FieldT> level = leaves;
        std::size_t idx = pos;
        for (std::size_t d = 0; d < depth; ++d)
        {
            path.push_back(level[idx ^ 1]);
            std::vector<FieldT> next(level.size() / 2);
            for (std::size_t i = 0; i < next.size(); ++i)
                next[i] =
                    PoseidonHash::hash(level[2 * i], level[2 * i + 1]);
            level = std::move(next);
            idx >>= 1;
        }
        return path;
    }

    std::vector<bool>
    posBits(std::size_t pos) const
    {
        std::vector<bool> bits;
        for (std::size_t d = 0; d < depth; ++d)
            bits.push_back((pos >> d) & 1);
        return bits;
    }
};

}  // namespace

class BatchCircuit_test : public beast::unit_test::suite
{
    static constexpr std::size_t kDepth = 4;

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

    static FieldT
    userKey()
    {
        return FieldT("777888999000111222333");
    }
    static FieldT
    userKeyB()
    {
        return FieldT("555666777888999000111");
    }
    static FieldT
    userKeyC()
    {
        return FieldT("222333444555666777888");
    }
    static FieldT
    sequencerKey()
    {
        return FieldT("123123123123123123123");
    }

    // Build the canonical two-entry happy path:
    //   entry 0: create-deposit 100 drops for user A at pos 0 (nonce 0)
    //   entry 1: A withdraws 30 (nonce 1)
    // Returns (witnesses, prev_root, expected_new_root, tree-after).
    struct Scenario
    {
        std::vector<BatchEntryWitness> entries;
        FieldT prev_root;
        FieldT expected_new_root;
    };

    Scenario
    buildDepositThenWithdraw()
    {
        TestTree tree(kDepth);
        Scenario sc;
        sc.prev_root = tree.root();

        BjjPoint const apk = EdDSA::derivePublicKey(userKey());

        // Entry 0: create + deposit 100 @ pos 0.
        {
            BatchEntryWitness ew;
            ew.req = SignedRequest::make(
                userKey(), apk.x, /*value=*/100, /*nonce=*/0,
                RequestType::Deposit);
            ew.old_balance = 0;
            ew.is_create = true;
            ew.leaf_pos = tree.posBits(0);
            ew.auth_path = tree.authPath(0);
            sc.entries.push_back(ew);

            AccountLeaf after;
            after.apk = apk;
            after.balance = 100;
            after.nonce = 1;
            tree.leaves[0] = after.hash();
        }

        // Entry 1: withdraw 30 (nonce now 1).
        {
            BatchEntryWitness ew;
            ew.req = SignedRequest::make(
                userKey(), FieldT("424242"), /*value=*/30, /*nonce=*/1,
                RequestType::Withdraw);
            ew.old_balance = 100;
            ew.is_create = false;
            ew.leaf_pos = tree.posBits(0);
            ew.auth_path = tree.authPath(0);
            sc.entries.push_back(ew);

            AccountLeaf after;
            after.apk = apk;
            after.balance = 70;
            after.nonce = 2;
            tree.leaves[0] = after.hash();
        }

        sc.expected_new_root = tree.root();
        return sc;
    }

    // Run a scenario through a fresh circuit; return satisfaction.
    bool
    runScenario(Scenario const& sc, BatchCircuit* out = nullptr)
    {
        BatchCircuit c(sc.entries.size(), kDepth);
        c.generateConstraints();
        c.generateWitness(sc.prev_root, sc.entries);
        bool const ok = c.isSatisfied();
        if (out)
        {
            // (constraint system is rebuilt by caller when needed)
        }
        return ok;
    }

public:
    void
    testHappyPath()
    {
        testcase("Phase 6 — deposit-then-withdraw batch satisfies the circuit");
        setupOnce();

        auto sc = buildDepositThenWithdraw();
        BatchCircuit c(sc.entries.size(), kDepth);
        c.generateConstraints();
        c.generateWitness(sc.prev_root, sc.entries);

        BEAST_EXPECT(c.isSatisfied());
        BEAST_EXPECT(c.computedNewRoot() == sc.expected_new_root);

        // entriesHash matches the native chain preclaim will recompute.
        std::vector<SignedRequest> reqs;
        for (auto const& e : sc.entries)
            reqs.push_back(e.req);
        BEAST_EXPECT(
            c.computedEntriesHash() ==
            BatchCircuit::computeEntriesHash(reqs));

        log << "BatchCircuit(N=2, depth=4) constraints: "
            << c.constraintCount() << std::endl;
    }

    void
    testOverdraftUnsatisfiable()
    {
        testcase("Phase 6 — overdraft (withdraw 200 of 100) is UNSATISFIABLE");
        setupOnce();

        auto sc = buildDepositThenWithdraw();
        // Corrupt entry 1 into an overdraft, honestly signed.
        sc.entries[1].req = SignedRequest::make(
            userKey(), FieldT("424242"), /*value=*/200, /*nonce=*/1,
            RequestType::Withdraw);
        BEAST_EXPECT(!runScenario(sc));
    }

    void
    testForgedSignatureUnsatisfiable()
    {
        testcase("Phase 6 — tampered signature is UNSATISFIABLE");
        setupOnce();

        auto sc = buildDepositThenWithdraw();
        sc.entries[1].req.sig.s =
            sc.entries[1].req.sig.s + FieldT::one();
        BEAST_EXPECT(!runScenario(sc));
    }

    void
    testSequencerCannotInflateValue()
    {
        testcase("Phase 6 — sequencer-inflated value is UNSATISFIABLE");
        setupOnce();

        auto sc = buildDepositThenWithdraw();
        // Keep the user's signature but claim a bigger withdrawal.
        sc.entries[1].req.value = 60;
        BEAST_EXPECT(!runScenario(sc));
    }

    void
    testReplayUnsatisfiable()
    {
        testcase("Phase 6 — replaying the nonce-0 request is UNSATISFIABLE");
        setupOnce();

        auto sc = buildDepositThenWithdraw();
        // Entry 1 = exact copy of the (applied) entry 0 request, with a
        // path honestly refreshed against the post-entry-0 tree.
        auto replay = sc.entries[0];
        // Recompute the honest path after entry 0 (slot 0 now occupied).
        TestTree tree(kDepth);
        {
            AccountLeaf after;
            after.apk = EdDSA::derivePublicKey(userKey());
            after.balance = 100;
            after.nonce = 1;
            tree.leaves[0] = after.hash();
        }
        replay.leaf_pos = tree.posBits(0);
        replay.auth_path = tree.authPath(0);
        sc.entries[1] = replay;
        BEAST_EXPECT(!runScenario(sc));
    }

    // ---- Phase 7: transfers ------------------------------------------
    //
    // Three accounts are created by deposits, then A transfers to B. The
    // `creditIndex` / `creditKey` knobs let a test misdirect the credit while
    // keeping every OTHER part of the witness internally consistent, so a
    // failure is attributable to the binding constraint and nothing else.
    Scenario
    buildTransfer(
        std::uint64_t value = 30,
        std::optional<std::size_t> creditIndex = std::nullopt,
        std::optional<FieldT> creditKey = std::nullopt)
    {
        TestTree tree(kDepth);
        Scenario sc;
        sc.prev_root = tree.root();

        struct U
        {
            FieldT key;
            BjjPoint apk;
            std::uint64_t bal;
        };
        std::vector<U> us;
        for (auto const& k : {userKey(), userKeyB(), userKeyC()})
            us.push_back({k, EdDSA::derivePublicKey(k), 0});
        std::uint64_t const seed[3] = {100, 50, 20};

        for (std::size_t i = 0; i < 3; ++i)
        {
            BatchEntryWitness ew;
            ew.req = SignedRequest::make(
                us[i].key, us[i].apk.x, seed[i], 0, RequestType::Deposit);
            ew.old_balance = 0;
            ew.is_create = true;
            ew.leaf_pos = tree.posBits(i);
            ew.auth_path = tree.authPath(i);
            sc.entries.push_back(ew);

            us[i].bal = seed[i];
            AccountLeaf after;
            after.apk = us[i].apk;
            after.balance = us[i].bal;
            after.nonce = 1;
            tree.leaves[i] = after.hash();
        }

        // A (leaf 0) transfers `value` to B (leaf 1), unless misdirected.
        std::size_t const toIdx = creditIndex.value_or(1);
        {
            BatchEntryWitness ew;
            ew.req = SignedRequest::make(
                us[0].key, us[1].apk.x, value, /*nonce=*/1,
                RequestType::Transfer);
            ew.old_balance = us[0].bal;
            ew.is_create = false;
            ew.leaf_pos = tree.posBits(0);
            ew.auth_path = tree.authPath(0);

            // Sender's leaf moves FIRST; the recipient leg is proven against
            // the tree that update produced.
            AccountLeaf a;
            a.apk = us[0].apk;
            a.balance = us[0].bal - value;
            a.nonce = 2;
            tree.leaves[0] = a.hash();

            ew.to_apk_x = creditKey.value_or(us[toIdx].apk.x);
            ew.to_old_balance = us[toIdx].bal;
            ew.to_nonce = 1;  // NOT consumed by receiving
            ew.to_leaf_pos = tree.posBits(toIdx);
            ew.to_auth_path = tree.authPath(toIdx);
            sc.entries.push_back(ew);

            AccountLeaf b;
            b.apk = us[toIdx].apk;
            b.balance = us[toIdx].bal + value;
            b.nonce = 1;
            tree.leaves[toIdx] = b.hash();
        }

        sc.expected_new_root = tree.root();
        return sc;
    }

    void
    testTransferHappyPath()
    {
        testcase("Phase 7 — transfer moves value between two leaves");
        setupOnce();

        auto sc = buildTransfer();
        BatchCircuit c(sc.entries.size(), kDepth);
        c.generateConstraints();
        c.generateWitness(sc.prev_root, sc.entries);

        BEAST_EXPECT(c.isSatisfied());
        // Proves BOTH legs landed: sender debited, recipient credited, and
        // the recipient's nonce left alone (any of those wrong => new root
        // differs from the tree the test built independently).
        BEAST_EXPECT(c.computedNewRoot() == sc.expected_new_root);
    }

    void
    testTransferOverdraftUnsatisfiable()
    {
        testcase("Phase 7 — transferring more than the balance is "
                 "UNSATISFIABLE");
        setupOnce();

        // A holds 100; move 500. The sender's new balance wraps in the field
        // and the 64-bit range check cannot be satisfied.
        BEAST_EXPECT(!runScenario(buildTransfer(500)));
    }

    void
    testTransferCannotBeMisdirected()
    {
        testcase("Phase 7 — crediting a leaf other than the signed dest is "
                 "UNSATISFIABLE");
        setupOnce();

        // Everything is internally consistent — C's leaf really is updated,
        // the Merkle paths really do chain — but the signed dest names B.
        // Only is_xfer*(to_x - dest) = 0 catches this. Without that
        // constraint a sequencer could debit A and credit itself.
        auto sc = buildTransfer(
            30, /*creditIndex=*/2,
            /*creditKey=*/EdDSA::derivePublicKey(userKeyC()).x);
        BEAST_EXPECT(!runScenario(sc));
    }

    void
    testNoopPaddingKeepsRoot()
    {
        testcase("Phase 6 — NoOp padding leaves the root unchanged");
        setupOnce();

        TestTree tree(kDepth);
        Scenario sc;
        sc.prev_root = tree.root();

        BjjPoint const apk = EdDSA::derivePublicKey(userKey());
        {
            BatchEntryWitness ew;
            ew.req = SignedRequest::make(
                userKey(), apk.x, 100, 0, RequestType::Deposit);
            ew.old_balance = 0;
            ew.is_create = true;
            ew.leaf_pos = tree.posBits(0);
            ew.auth_path = tree.authPath(0);
            sc.entries.push_back(ew);

            AccountLeaf after;
            after.apk = apk;
            after.balance = 100;
            after.nonce = 1;
            tree.leaves[0] = after.hash();
        }
        FieldT const rootAfterEntry0 = tree.root();

        // NoOp pad: sequencer's own key, empty slot 5, value 0.
        {
            BatchEntryWitness ew;
            ew.req = SignedRequest::make(
                sequencerKey(), FieldT::zero(), 0, 0, RequestType::NoOp);
            ew.old_balance = 0;
            ew.is_create = true;
            ew.leaf_pos = tree.posBits(5);
            ew.auth_path = tree.authPath(5);
            sc.entries.push_back(ew);
        }

        BatchCircuit c(sc.entries.size(), kDepth);
        c.generateConstraints();
        c.generateWitness(sc.prev_root, sc.entries);

        BEAST_EXPECT(c.isSatisfied());
        BEAST_EXPECT(c.computedNewRoot() == rootAfterEntry0);
    }

    void
    testProductionSizeConstraintCount()
    {
        testcase("Phase 6 — constraint budget at N=8, depth=16 (count only)");
        setupOnce();

        BatchCircuit c(8, 16);
        c.generateConstraints();
        log << "BatchCircuit(N=8, depth=16) constraints: "
            << c.constraintCount() << std::endl;
        // Sanity corridor around the ~192K estimate.
        BEAST_EXPECT(c.constraintCount() > 100'000);
        BEAST_EXPECT(c.constraintCount() < 400'000);
    }

    void
    run() override
    {
        testHappyPath();
        testOverdraftUnsatisfiable();
        testForgedSignatureUnsatisfiable();
        testSequencerCannotInflateValue();
        testReplayUnsatisfiable();
        testTransferHappyPath();
        testTransferOverdraftUnsatisfiable();
        testTransferCannotBeMisdirected();
        testNoopPaddingKeepsRoot();
        testProductionSizeConstraintCount();
    }
};

BEAST_DEFINE_TESTSUITE(BatchCircuit, zkp, ripple);

}  // namespace test
}  // namespace ripple
