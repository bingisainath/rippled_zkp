// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// Phase 2d gate. THIS IS THE PROJECT'S GO/NO-GO TEST.
//
// What it proves: given the PoseidonCircuit composed in Phase 2c, libsnark's
// Groth16 backend can:
//   1. Run trusted-setup and persist (pk, vk) to disk independently of
//      ZkProver's keys (per v2.2 §13.1 the rollup MUST keep its own keys —
//      ZkProver loads SHA-256-circuit keys at the same path otherwise).
//   2. Generate a valid proof for an honest state transition.
//   3. Reject proofs whose public inputs have been tampered with after
//      proving (i.e. soundness at the SNARK layer, not just the R1CS layer).
//   4. Round-trip through proof serialisation (~190 bytes for Groth16/BN-128).
//
// If every test below passes, Phase 2 is complete and Phase 3 (RollupMerkleTree
// with the novel update_leaf()) can proceed.
//
// Run: ./rippled --unittest=ripple.zkp.RollupProver
//
// PERFORMANCE NOTE: Groth16 setup at depth=32 with ~22K constraints takes
// 30–90s on a single core. This suite intentionally runs setup ONCE and
// reuses keys across tests; subsequent runs of the suite within the same
// process boundary will load keys from disk (O(seconds)).

#include "../../../libxrpl/zkp/rollup/PoseidonCircuit.h"
#include "../../../libxrpl/zkp/rollup/PoseidonHash.h"
#include "../../../libxrpl/zkp/rollup/RollupNote.h"
#include "../../../libxrpl/zkp/rollup/RollupProver.h"

#include <xrpl/beast/unit_test.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <cstdio>
#include <string>
#include <vector>

namespace ripple {
namespace test {

using namespace zkp::rollup;

class RollupProver_test : public beast::unit_test::suite
{
    // Use a SEPARATE key path from RollupProver::defaultKeyPath() so that:
    //   (a) running the test suite never clobbers a developer's working keys
    //   (b) the test is hermetic — we can delete the files and force a
    //       fresh setup whenever we want to.
    static std::string
    testKeyPath()
    {
        return "/tmp/rippled_rollup_keys_test";
    }

    static constexpr std::size_t kDepth = 32;

    // Same honest witness builder as PoseidonCircuit_test. Duplicated rather
    // than factored out so each test file is self-contained — Phase 1 lesson
    // learned: shared test helpers across files create build-order surprises
    // in the rippled CMake unity build.
    struct HonestWitness
    {
        RollupNote old_note;
        RollupNote new_note;
        std::vector<bool> leaf_pos;
        std::vector<FieldT> auth_path_old;
        std::vector<FieldT> auth_path_new;
        FieldT prev_root;
        FieldT new_root;
    };

    static HonestWitness
    buildHonestWitness()
    {
        HonestWitness w;
        w.old_note = RollupNote::createRandom(/*value=*/42, /*seed=*/0xC3u);
        w.new_note = RollupNote::createRandom(/*value=*/42, /*seed=*/0xD4u);
        w.new_note.ask = w.old_note.ask;
        w.new_note.apk = w.old_note.apk;

        w.leaf_pos.assign(kDepth, false);

        w.auth_path_old.reserve(kDepth);
        FieldT cur = PoseidonHash::zeroZero();
        w.auth_path_old.push_back(FieldT::zero());
        for (std::size_t lvl = 1; lvl < kDepth; ++lvl)
        {
            w.auth_path_old.push_back(cur);
            cur = PoseidonHash::hash(cur, cur);
        }
        w.auth_path_new = w.auth_path_old;

        auto rootFromLeaf = [&w](FieldT const& leaf) {
            FieldT acc = leaf;
            for (std::size_t lvl = 0; lvl < kDepth; ++lvl)
                acc = PoseidonHash::hash(acc, w.auth_path_old[lvl]);
            return acc;
        };
        w.prev_root = rootFromLeaf(w.old_note.commitment());
        w.new_root = rootFromLeaf(w.new_note.commitment());
        return w;
    }

    // Best-effort cleanup; harmless if files don't exist yet.
    static void
    deleteTestKeys()
    {
        std::string p = testKeyPath();
        std::remove((p + "_pk").c_str());
        std::remove((p + "_vk").c_str());
    }

public:
    void
    testInitializeIsIdempotent()
    {
        testcase("initialize() is idempotent");

        deleteTestKeys();

        // First call: triggers full Groth16 setup. SLOW (~30–90s).
        RollupProver::initialize(testKeyPath(), kDepth);
        std::size_t n1 = RollupProver::constraintCount();
        BEAST_EXPECT(n1 > 0);

        // Second call: should hit the cached static state and return fast.
        RollupProver::initialize(testKeyPath(), kDepth);
        std::size_t n2 = RollupProver::constraintCount();
        BEAST_EXPECT(n1 == n2);
    }

    void
    testKeyPersistence()
    {
        testcase("keys round-trip through disk");

        // Keys must already be on disk from the previous test.
        BEAST_EXPECT(RollupProver::loadKeys(testKeyPath()));
    }

    void
    testKeyPathIsDistinctFromZkProver()
    {
        testcase("rollup key path does NOT collide with ZkProver");

        // v2.2 §13.1 requirement: rollup keys live in their own file.
        // The default path must not be the empty string and must not
        // accidentally point at the existing ZkProver key directory.
        std::string const& p = RollupProver::defaultKeyPath();
        BEAST_EXPECT(!p.empty());
        // If ZkProver is using the canonical /tmp/rippled_zkp_keys path,
        // we must NOT use the same prefix. The rollup default contains
        // the literal string "rollup" by design.
        BEAST_EXPECT(p.find("rollup") != std::string::npos);
    }

    void
    testHonestProofVerifies()
    {
        testcase("honest proof verifies (end-to-end Groth16)");

        RollupProver::initialize(testKeyPath(), kDepth);

        auto w = buildHonestWitness();
        auto pd = RollupProver::createProof(
            w.old_note, w.new_note, w.leaf_pos,
            w.auth_path_old, w.auth_path_new,
            w.prev_root, w.new_root);

        BEAST_EXPECT(!pd.empty());

        // Groth16 proof at BN-128 is fixed-size: 2×G1 + 1×G2 ≈ 190 bytes
        // depending on the serialization. Anything outside [100, 400] is
        // a smell that the format changed underneath us.
        log << "Proof size: " << pd.proof_bytes.size() << " bytes" << std::endl;
        BEAST_EXPECT(pd.proof_bytes.size() >= 100);
        BEAST_EXPECT(pd.proof_bytes.size() <= 400);

        BEAST_EXPECT(pd.anchor == w.prev_root);
        BEAST_EXPECT(pd.new_anchor == w.new_root);
        BEAST_EXPECT(pd.nullifier == w.old_note.nullifier());

        BEAST_EXPECT(RollupProver::verifyProof(pd));
    }

    void
    testTamperedAnchorRejected()
    {
        testcase("proof with mutated anchor is rejected");

        RollupProver::initialize(testKeyPath(), kDepth);

        auto w = buildHonestWitness();
        auto pd = RollupProver::createProof(
            w.old_note, w.new_note, w.leaf_pos,
            w.auth_path_old, w.auth_path_new,
            w.prev_root, w.new_root);
        BEAST_EXPECT(!pd.empty());

        // Mutate the public input. Groth16 must reject — the proof was
        // bound to the original anchor by α, β, γ during setup.
        pd.anchor = pd.anchor + FieldT::one();
        BEAST_EXPECT(!RollupProver::verifyProof(pd));
    }

    void
    testTamperedNullifierRejected()
    {
        testcase("proof with mutated nullifier is rejected");

        RollupProver::initialize(testKeyPath(), kDepth);

        auto w = buildHonestWitness();
        auto pd = RollupProver::createProof(
            w.old_note, w.new_note, w.leaf_pos,
            w.auth_path_old, w.auth_path_new,
            w.prev_root, w.new_root);
        BEAST_EXPECT(!pd.empty());

        pd.nullifier = pd.nullifier + FieldT::one();
        BEAST_EXPECT(!RollupProver::verifyProof(pd));
    }

    void
    testTamperedProofBytesRejected()
    {
        testcase("proof with bit-flipped serialization is rejected");

        RollupProver::initialize(testKeyPath(), kDepth);

        auto w = buildHonestWitness();
        auto pd = RollupProver::createProof(
            w.old_note, w.new_note, w.leaf_pos,
            w.auth_path_old, w.auth_path_new,
            w.prev_root, w.new_root);
        BEAST_EXPECT(!pd.empty());

        // Flip one byte in the middle of the proof. Either:
        //   (a) deserialization throws/rejects → verifyProof returns false
        //   (b) deserialization succeeds but verification fails
        // Either path yields false. Anything else is a soundness failure.
        if (!pd.proof_bytes.empty())
        {
            pd.proof_bytes[pd.proof_bytes.size() / 2] ^= 0xFFu;
        }
        BEAST_EXPECT(!RollupProver::verifyProof(pd));
    }

    void
    testEmptyProofIsRejected()
    {
        testcase("empty proof is rejected without crashing");

        RollupProver::initialize(testKeyPath(), kDepth);

        RollupProofData pd;
        BEAST_EXPECT(pd.empty());
        BEAST_EXPECT(!RollupProver::verifyProof(pd));
    }

    void
    run() override
    {
        // libff init exactly once per process.
        static bool curve_inited = false;
        if (!curve_inited)
        {
            libff::alt_bn128_pp::init_public_params();
            curve_inited = true;
        }

        // Order matters: testInitializeIsIdempotent does the slow setup,
        // then every subsequent test reuses the cached keys.
        testInitializeIsIdempotent();
        testKeyPersistence();
        testKeyPathIsDistinctFromZkProver();
        testHonestProofVerifies();
        testTamperedAnchorRejected();
        testTamperedNullifierRejected();
        testTamperedProofBytesRejected();
        testEmptyProofIsRejected();
    }
};

// `manual` instead of plain `zkp` — this suite takes 30–90s on first run
// because of the trusted-setup, so it should not be in the default fast-test
// rotation. Invoke explicitly via:
//     ./rippled --unittest=ripple.zkp.RollupProver
BEAST_DEFINE_TESTSUITE_MANUAL(RollupProver, rollup, ripple);

}  // namespace test
}  // namespace ripple
