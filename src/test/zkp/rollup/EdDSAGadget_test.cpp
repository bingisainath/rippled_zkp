// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// Phase 6 gate — EdDSA-Poseidon over Baby Jubjub, native + in-circuit.
// Run: ./rippled --unittest=ripple.zkp.EdDSAGadget

#include "../../../libxrpl/zkp/rollup/EdDSA.h"
#include "../../../libxrpl/zkp/rollup/EdDSAGadget.h"

#include <xrpl/beast/unit_test.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace ripple {
namespace test {

using namespace zkp::rollup;

class EdDSAGadget_test : public beast::unit_test::suite
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

    // Deterministic test key/message material.
    static FieldT
    testKey()
    {
        return FieldT("12345678901234567890123456789012345678901234567890");
    }
    static FieldT
    testMsg()
    {
        return FieldT("987654321098765432109876543210");
    }

    // Shared harness: build the gadget, drive a witness from (A, msg, sig),
    // return protoboard satisfaction.
    bool
    runCircuit(
        BjjPoint const& A,
        FieldT const& msg,
        EdDSASignature const& sig,
        std::size_t* constraint_count_out = nullptr)
    {
        libsnark::protoboard<FieldT> pb;

        libsnark::pb_variable<FieldT> ax, ay, rx, ry, s, m;
        ax.allocate(pb, "ax");
        ay.allocate(pb, "ay");
        rx.allocate(pb, "rx");
        ry.allocate(pb, "ry");
        s.allocate(pb, "s");
        m.allocate(pb, "m");

        EdDSAGadget gadget(pb, ax, ay, rx, ry, s, m, "eddsa");
        gadget.generate_r1cs_constraints();

        pb.val(ax) = A.x;
        pb.val(ay) = A.y;
        pb.val(rx) = sig.R.x;
        pb.val(ry) = sig.R.y;
        pb.val(s) = sig.s;
        pb.val(m) = msg;

        gadget.generate_r1cs_witness();

        if (constraint_count_out)
            *constraint_count_out = pb.num_constraints();
        return pb.is_satisfied();
    }

public:
    void
    testNativeSignVerify()
    {
        testcase("Phase 6 — native sign/verify round-trip");
        setupOnce();

        FieldT const ask = testKey();
        FieldT const msg = testMsg();

        BjjPoint const A = EdDSA::derivePublicKey(ask);
        BEAST_EXPECT(BabyJubjub::onCurve(A));

        auto const sig = EdDSA::sign(ask, msg);
        BEAST_EXPECT(BabyJubjub::onCurve(sig.R));
        BEAST_EXPECT(EdDSA::verify(A, msg, sig));
    }

    void
    testNativeDeterministic()
    {
        testcase("Phase 6 — deterministic signatures (same key+msg => same sig)");
        setupOnce();

        auto const s1 = EdDSA::sign(testKey(), testMsg());
        auto const s2 = EdDSA::sign(testKey(), testMsg());
        BEAST_EXPECT(s1.R == s2.R && s1.s == s2.s);
    }

    void
    testNativeRejectsTamperedMessage()
    {
        testcase("Phase 6 — native verify rejects a tampered message");
        setupOnce();

        FieldT const ask = testKey();
        BjjPoint const A = EdDSA::derivePublicKey(ask);
        auto const sig = EdDSA::sign(ask, testMsg());

        BEAST_EXPECT(!EdDSA::verify(A, testMsg() + FieldT::one(), sig));
    }

    void
    testNativeRejectsWrongKey()
    {
        testcase("Phase 6 — native verify rejects a different public key");
        setupOnce();

        auto const sig = EdDSA::sign(testKey(), testMsg());
        BjjPoint const wrongA =
            EdDSA::derivePublicKey(testKey() + FieldT::one());

        BEAST_EXPECT(!EdDSA::verify(wrongA, testMsg(), sig));
    }

    void
    testNativeRejectsTamperedS()
    {
        testcase("Phase 6 — native verify rejects a tampered s");
        setupOnce();

        FieldT const ask = testKey();
        BjjPoint const A = EdDSA::derivePublicKey(ask);
        auto sig = EdDSA::sign(ask, testMsg());
        sig.s = sig.s + FieldT::one();

        BEAST_EXPECT(!EdDSA::verify(A, testMsg(), sig));
    }

    void
    testGadgetAcceptsValidSignature()
    {
        testcase("Phase 6 — circuit satisfied by a valid signature");
        setupOnce();

        FieldT const ask = testKey();
        FieldT const msg = testMsg();
        BjjPoint const A = EdDSA::derivePublicKey(ask);
        auto const sig = EdDSA::sign(ask, msg);

        std::size_t n = 0;
        BEAST_EXPECT(runCircuit(A, msg, sig, &n));
        log << "EdDSAGadget constraints: " << n
            << " (estimate " << EdDSAGadget::constraintCountEstimate() << ")"
            << std::endl;
    }

    void
    testGadgetRejectsTamperedS()
    {
        testcase("Phase 6 — circuit UNSATISFIED for a forged s");
        setupOnce();

        FieldT const ask = testKey();
        FieldT const msg = testMsg();
        BjjPoint const A = EdDSA::derivePublicKey(ask);
        auto sig = EdDSA::sign(ask, msg);
        sig.s = sig.s + FieldT::one();

        BEAST_EXPECT(!runCircuit(A, msg, sig));
    }

    void
    testGadgetRejectsTamperedMessage()
    {
        testcase("Phase 6 — circuit UNSATISFIED for a tampered message");
        setupOnce();

        FieldT const ask = testKey();
        BjjPoint const A = EdDSA::derivePublicKey(ask);
        auto const sig = EdDSA::sign(ask, testMsg());

        BEAST_EXPECT(!runCircuit(A, testMsg() + FieldT::one(), sig));
    }

    void
    testGadgetRejectsWrongKey()
    {
        testcase("Phase 6 — circuit UNSATISFIED for the wrong public key");
        setupOnce();

        auto const sig = EdDSA::sign(testKey(), testMsg());
        BjjPoint const wrongA =
            EdDSA::derivePublicKey(testKey() + FieldT::one());

        BEAST_EXPECT(!runCircuit(wrongA, testMsg(), sig));
    }

    void
    testGadgetRejectsOffCurveR()
    {
        testcase("Phase 6 — circuit UNSATISFIED for an off-curve R");
        setupOnce();

        FieldT const ask = testKey();
        FieldT const msg = testMsg();
        BjjPoint const A = EdDSA::derivePublicKey(ask);
        auto sig = EdDSA::sign(ask, msg);
        sig.R.x = sig.R.x + FieldT::one();  // knock R off the curve

        BEAST_EXPECT(!runCircuit(A, msg, sig));
    }

    void
    run() override
    {
        testNativeSignVerify();
        testNativeDeterministic();
        testNativeRejectsTamperedMessage();
        testNativeRejectsWrongKey();
        testNativeRejectsTamperedS();
        testGadgetAcceptsValidSignature();
        testGadgetRejectsTamperedS();
        testGadgetRejectsTamperedMessage();
        testGadgetRejectsWrongKey();
        testGadgetRejectsOffCurveR();
    }
};

BEAST_DEFINE_TESTSUITE(EdDSAGadget, zkp, ripple);

}  // namespace test
}  // namespace ripple
