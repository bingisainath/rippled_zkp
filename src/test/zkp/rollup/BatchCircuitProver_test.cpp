// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// Phase 6 gate — BatchCircuitProver: Groth16 end-to-end over BatchCircuit.
// MANUAL suite (keygen is slow). Run:
//   ./rippled --unittest=ripple.zkp.BatchCircuitProver
// Full-size (N=8, depth=16) benchmark additionally gated by env:
//   ROLLUP_BATCH_BENCH=1 ./rippled --unittest=ripple.zkp.BatchCircuitProver

#include "../../../libxrpl/zkp/rollup/BatchCircuitProver.h"

#include <xrpl/beast/unit_test.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <chrono>
#include <cstdlib>
#include <map>
#include <vector>

namespace ripple {
namespace test {

using namespace zkp::rollup;

namespace {

// Sparse Poseidon Merkle tree (test-only): supports large depths by
// memoizing empty-subtree hashes, so depth-16 paths cost ~depth hashes.
struct SparseTree
{
    std::size_t depth;
    std::map<std::size_t, FieldT> leaves;  // pos -> leaf value
    std::vector<FieldT> empty;             // empty[l] = empty subtree @ lvl l

    explicit SparseTree(std::size_t d) : depth(d)
    {
        empty.resize(d + 1);
        empty[0] = FieldT::zero();
        for (std::size_t l = 1; l <= d; ++l)
            empty[l] = PoseidonHash::hash(empty[l - 1], empty[l - 1]);
    }

    bool
    rangeOccupied(std::size_t level, std::size_t idx) const
    {
        auto const lo = idx << level;
        auto const hi = ((idx + 1) << level);  // exclusive
        auto it = leaves.lower_bound(lo);
        return it != leaves.end() && it->first < hi;
    }

    FieldT
    node(std::size_t level, std::size_t idx) const
    {
        if (!rangeOccupied(level, idx))
            return empty[level];
        if (level == 0)
        {
            auto it = leaves.find(idx);
            return it == leaves.end() ? FieldT::zero() : it->second;
        }
        return PoseidonHash::hash(
            node(level - 1, 2 * idx), node(level - 1, 2 * idx + 1));
    }

    FieldT
    root() const
    {
        return node(depth, 0);
    }

    std::vector<FieldT>
    authPath(std::size_t pos) const
    {
        std::vector<FieldT> path;
        for (std::size_t l = 0; l < depth; ++l)
            path.push_back(node(l, (pos >> l) ^ 1));
        return path;
    }

    std::vector<bool>
    posBits(std::size_t pos) const
    {
        std::vector<bool> bits;
        for (std::size_t l = 0; l < depth; ++l)
            bits.push_back((pos >> l) & 1);
        return bits;
    }
};

double
msSince(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double, std::milli>(
               std::chrono::steady_clock::now() - t0)
        .count();
}

}  // namespace

class BatchCircuitProver_test : public beast::unit_test::suite
{
    // Small correctness shape — keygen stays ~a minute.
    static constexpr std::size_t kN = 2;
    static constexpr std::size_t kDepth = 4;
    static constexpr char const* kKeyPath = "/tmp/rippled_batch_keys_test";

    void
    setupOnce()
    {
        static bool done = false;
        if (done)
            return;
        libff::alt_bn128_pp::init_public_params();
        BabyJubjub::initialize();
        PoseidonHash::initialize();
        BatchCircuitProver::initialize(kKeyPath, kN, kDepth);
        done = true;
    }

    static FieldT
    userKey(std::size_t i)
    {
        return FieldT("900100200300400500") + FieldT(i);
    }

    // deposit(create) 100 @ pos 0, then withdraw 30 — same shape as
    // BatchCircuit_test's happy path.
    struct Scenario
    {
        std::vector<BatchEntryWitness> entries;
        FieldT prev_root;
        FieldT expected_new_root;
    };

    Scenario
    buildScenario(bool overdraft = false)
    {
        SparseTree tree(kDepth);
        Scenario sc;
        sc.prev_root = tree.root();

        BjjPoint const apk = EdDSA::derivePublicKey(userKey(0));

        {
            BatchEntryWitness ew;
            ew.req = SignedRequest::make(
                userKey(0), apk.x, 100, 0, RequestType::Deposit);
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
        {
            BatchEntryWitness ew;
            ew.req = SignedRequest::make(
                userKey(0), FieldT("424242"),
                overdraft ? 200 : 30, 1, RequestType::Withdraw);
            ew.old_balance = 100;
            ew.is_create = false;
            ew.leaf_pos = tree.posBits(0);
            ew.auth_path = tree.authPath(0);
            sc.entries.push_back(ew);

            if (!overdraft)
            {
                AccountLeaf after;
                after.apk = apk;
                after.balance = 70;
                after.nonce = 2;
                tree.leaves[0] = after.hash();
            }
        }
        sc.expected_new_root = tree.root();
        return sc;
    }

public:
    void
    testKeysRoundTrip()
    {
        testcase("Phase 6 — batch keys generate, save, and reload");
        setupOnce();

        BEAST_EXPECT(BatchCircuitProver::isInitialized());
        BEAST_EXPECT(BatchCircuitProver::loadKeys(kKeyPath));
        log << "BatchCircuitProver(N=" << kN << ", depth=" << kDepth
            << ") constraints: " << BatchCircuitProver::constraintCount()
            << std::endl;
    }

    void
    testHonestBatchVerifies()
    {
        testcase("Phase 6 — honest batch proof verifies end-to-end");
        setupOnce();

        auto sc = buildScenario();

        auto t0 = std::chrono::steady_clock::now();
        auto pd = BatchCircuitProver::createBatchProof(
            sc.prev_root, sc.entries);
        double const proveMs = msSince(t0);

        BEAST_EXPECT(!pd.empty());
        BEAST_EXPECT(pd.new_root == sc.expected_new_root);

        std::vector<SignedRequest> reqs;
        for (auto const& e : sc.entries)
            reqs.push_back(e.req);
        BEAST_EXPECT(
            pd.entries_hash == BatchCircuit::computeEntriesHash(reqs));

        t0 = std::chrono::steady_clock::now();
        BEAST_EXPECT(BatchCircuitProver::verifyBatchProof(pd));
        double const verifyMs = msSince(t0);

        log << "prove: " << proveMs << " ms, verify: " << verifyMs
            << " ms, proof: " << pd.proof_bytes.size() << " bytes"
            << std::endl;
    }

    void
    testTamperedPublicsRejected()
    {
        testcase("Phase 6 — tampered public inputs are rejected");
        setupOnce();

        auto sc = buildScenario();
        auto pd = BatchCircuitProver::createBatchProof(
            sc.prev_root, sc.entries);
        BEAST_EXPECT(!pd.empty());

        {
            auto t = pd;
            t.new_root = t.new_root + FieldT::one();
            BEAST_EXPECT(!BatchCircuitProver::verifyBatchProof(t));
        }
        {
            auto t = pd;
            t.entries_hash = t.entries_hash + FieldT::one();
            BEAST_EXPECT(!BatchCircuitProver::verifyBatchProof(t));
        }
        {
            auto t = pd;
            t.prev_root = t.prev_root + FieldT::one();
            BEAST_EXPECT(!BatchCircuitProver::verifyBatchProof(t));
        }
    }

    void
    testTamperedProofBytesRejected()
    {
        testcase("Phase 6 — bit-flipped proof bytes are rejected");
        setupOnce();

        auto sc = buildScenario();
        auto pd = BatchCircuitProver::createBatchProof(
            sc.prev_root, sc.entries);
        BEAST_EXPECT(!pd.empty());

        // Corrupt a byte inside the FIRST proof element (G1 point A). We
        // deliberately avoid the middle: a Groth16 proof serializes as
        // A(G1) || B(G2) || C(G1), and libff recovers a compressed point's
        // y-coordinate by square root on read. An Fp2 sqrt over a non-curve
        // x (the G2 element, which straddles the midpoint) can send
        // Tonelli–Shanks into a pathologically long loop — a malformed-proof
        // DoS that also affects the on-chain verifier (tracked for
        // BatchVerifier2 hardening). Corrupting A exercises the bounded Fp
        // sqrt instead, so the tamper is rejected promptly.
        pd.proof_bytes[2] ^= 0xFFu;
        BEAST_EXPECT(!BatchCircuitProver::verifyBatchProof(pd));
    }

    void
    testUnsatisfiableWitnessRefused()
    {
        testcase("Phase 6 — prover refuses an overdraft witness");
        setupOnce();

        auto sc = buildScenario(/*overdraft=*/true);
        auto pd = BatchCircuitProver::createBatchProof(
            sc.prev_root, sc.entries);
        BEAST_EXPECT(pd.empty());
    }

    void
    testFullSizeBenchmark()
    {
        testcase("Phase 6 — FULL-SIZE benchmark (N=8, depth=16)");

        if (std::getenv("ROLLUP_BATCH_BENCH") == nullptr)
        {
            log << "skipped (set ROLLUP_BATCH_BENCH=1 to run)" << std::endl;
            pass();
            return;
        }
        setupOnce();

        // 8 create-deposits by 8 distinct users at positions 0..7.
        SparseTree tree(16);
        FieldT const prevRoot = tree.root();
        std::vector<BatchEntryWitness> entries;
        for (std::size_t i = 0; i < 8; ++i)
        {
            BjjPoint const apk = EdDSA::derivePublicKey(userKey(i));
            BatchEntryWitness ew;
            ew.req = SignedRequest::make(
                userKey(i), apk.x, 100 + i, 0, RequestType::Deposit);
            ew.old_balance = 0;
            ew.is_create = true;
            ew.leaf_pos = tree.posBits(i);
            ew.auth_path = tree.authPath(i);
            entries.push_back(ew);

            AccountLeaf after;
            after.apk = apk;
            after.balance = 100 + i;
            after.nonce = 1;
            tree.leaves[i] = after.hash();
        }

        // Direct libsnark (the static prover is pinned to the small test
        // shape by setupOnce): circuit -> keygen -> prove -> verify, timed.
        BatchCircuit c(8, 16);
        c.generateConstraints();
        log << "constraints: " << c.constraintCount() << std::endl;

        auto t0 = std::chrono::steady_clock::now();
        auto kp = libsnark::r1cs_gg_ppzksnark_generator<DefaultCurve>(
            c.getConstraintSystem());
        log << "keygen: " << msSince(t0) / 1000.0 << " s" << std::endl;

        c.generateWitness(prevRoot, entries);
        BEAST_EXPECT(c.isSatisfied());

        t0 = std::chrono::steady_clock::now();
        auto proof = libsnark::r1cs_gg_ppzksnark_prover<DefaultCurve>(
            kp.pk, c.getPrimaryInput(), c.getAuxiliaryInput());
        double const proveS = msSince(t0) / 1000.0;
        log << "prove: " << proveS << " s" << std::endl;

        t0 = std::chrono::steady_clock::now();
        bool const ok =
            libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<DefaultCurve>(
                kp.vk, c.getPrimaryInput(), proof);
        log << "verify: " << msSince(t0) << " ms" << std::endl;
        BEAST_EXPECT(ok);
        BEAST_EXPECT(c.computedNewRoot() == tree.root());
    }

    void
    run() override
    {
        testKeysRoundTrip();
        testHonestBatchVerifies();
        testTamperedPublicsRejected();
        testTamperedProofBytesRejected();
        testUnsatisfiableWitnessRefused();
        testFullSizeBenchmark();
    }
};

// MANUAL: keygen cost must not land in the default full-suite run.
BEAST_DEFINE_TESTSUITE_MANUAL(BatchCircuitProver, zkp, ripple);

}  // namespace test
}  // namespace ripple
