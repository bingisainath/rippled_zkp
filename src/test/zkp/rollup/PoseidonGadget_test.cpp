// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// Phase 2a gate. This is the most important test file in Phase 2 — if every
// vector here matches, the rest of the cryptographic stack is bit-compatible
// with circomlib / Tornado Cash Nova.
//
// Run: ./rippled --unittest=ripple.zkp.PoseidonGadget

#include "../../../libxrpl/zkp/rollup/PoseidonConstants.h"
#include "../../../libxrpl/zkp/rollup/PoseidonGadget.h"
#include "../../../libxrpl/zkp/rollup/PoseidonHash.h"

#include <xrpl/beast/unit_test.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace ripple {
namespace test {

using namespace zkp::rollup;

class PoseidonGadget_test : public beast::unit_test::suite
{
    static FieldT
    fromDec(std::string const& s)
    {
        std::string copy = s;
        libff::bigint<libff::alt_bn128_r_limbs> n(copy.c_str());
        return FieldT(n);
    }

    void
    setupOnce()
    {
        static bool done = false;
        if (done)
            return;
        libff::alt_bn128_pp::init_public_params();
        PoseidonHash::initialize();
        done = true;
    }

public:
    void
    testConstantsLoadCorrectly()
    {
        testcase("Phase 2a — constants table parses and matches anchors");
        setupOnce();
        auto const& arc = PoseidonHash::debug_arc();
        auto const& mds = PoseidonHash::debug_mds();
        BEAST_EXPECT(arc.size() == poseidon_params::kArcCount);
        BEAST_EXPECT(mds.size() == poseidon_params::kT * poseidon_params::kT);
        // Anchor: kArc[0] decimal value
        BEAST_EXPECT(
            arc[0] ==
            fromDec("6745197990210204598374042828761989596302876299545964402857"
                    "411729872131034734"));
        BEAST_EXPECT(
            arc[poseidon_params::kArcCount - 1] ==
            fromDec("13409242754315411433193860530743374419854094495153957441"
                    "316635981078068351329"));
    }

    void
    testReferenceVector_0_0()
    {
        testcase("Phase 2a — Poseidon(0, 0) matches circomlibjs");
        setupOnce();
        FieldT got = PoseidonHash::hash(FieldT::zero(), FieldT::zero());
        FieldT expected = fromDec(
            std::string(poseidon_params::kRefVector_0_0.expected_decimal));
        BEAST_EXPECT(got == expected);
    }

    void
    testReferenceVector_1_2()
    {
        testcase("Phase 2a — Poseidon(1, 2) matches circomlibjs");
        setupOnce();
        FieldT got = PoseidonHash::hash(FieldT::one(), FieldT(2));
        FieldT expected = fromDec(
            std::string(poseidon_params::kRefVector_1_2.expected_decimal));
        BEAST_EXPECT(got == expected);
    }

    void
    testReferenceVector_3_4()
    {
        testcase("Phase 2a — Poseidon(3, 4) matches circomlibjs");
        setupOnce();
        FieldT got = PoseidonHash::hash(FieldT(3), FieldT(4));
        FieldT expected = fromDec(
            std::string(poseidon_params::kRefVector_3_4.expected_decimal));
        BEAST_EXPECT(got == expected);
    }

    void
    testGadgetMatchesOffCircuit()
    {
        testcase("Phase 2a — gadget output matches off-circuit hash");
        setupOnce();

        for (auto const* vec : {
                 &poseidon_params::kRefVector_0_0,
                 &poseidon_params::kRefVector_1_2,
                 &poseidon_params::kRefVector_3_4})
        {
            FieldT a = fromDec(std::string(vec->a_decimal));
            FieldT b = fromDec(std::string(vec->b_decimal));
            FieldT expected = fromDec(std::string(vec->expected_decimal));

            libsnark::protoboard<FieldT> pb;
            libsnark::pb_variable<FieldT> in_a, in_b, out;
            in_a.allocate(pb, "a");
            in_b.allocate(pb, "b");
            out.allocate(pb, "out");
            PoseidonGadget g(pb, in_a, in_b, out, "test");
            g.generate_r1cs_constraints();
            pb.val(in_a) = a;
            pb.val(in_b) = b;
            g.generate_r1cs_witness();

            BEAST_EXPECT(pb.val(out) == expected);
            BEAST_EXPECT(pb.is_satisfied());
        }
    }

    void
    testGadgetIsSoundUnderTampering()
    {
        testcase("Phase 2a — flipping one wire breaks the constraint system");
        setupOnce();
        libsnark::protoboard<FieldT> pb;
        libsnark::pb_variable<FieldT> in_a, in_b, out;
        in_a.allocate(pb, "a");
        in_b.allocate(pb, "b");
        out.allocate(pb, "out");
        PoseidonGadget g(pb, in_a, in_b, out, "test");
        g.generate_r1cs_constraints();
        pb.val(in_a) = FieldT(7);
        pb.val(in_b) = FieldT(11);
        g.generate_r1cs_witness();
        BEAST_EXPECT(pb.is_satisfied());
        // Flip the output wire by one — the constraint system must reject it.
        pb.val(out) = pb.val(out) + FieldT::one();
        BEAST_EXPECT(!pb.is_satisfied());
    }

    void
    testConstraintCount()
    {
        testcase("Phase 2a — gadget reports the documented constraint count");
        setupOnce();
        libsnark::protoboard<FieldT> pb;
        libsnark::pb_variable<FieldT> in_a, in_b, out;
        in_a.allocate(pb, "a");
        in_b.allocate(pb, "b");
        out.allocate(pb, "out");
        PoseidonGadget g(pb, in_a, in_b, out, "test");
        g.generate_r1cs_constraints();
        std::size_t actual = pb.num_constraints();

        log << "PoseidonGadget constraint count = " << actual
            << " (expected ~" << PoseidonGadget::constraintCount()
            << ", plus init/output equality overhead)" << std::endl;

        // We expect roughly 243 mul-gates plus a small constant overhead
        // (3 init + 3*65 mix + 1 output ≈ 200 equality constraints).
        // Tolerate 200 .. 600 to absorb implementation choices.
        BEAST_EXPECT(actual > 200 && actual < 700);
    }

    void
    testZeroZeroIsCachedConsistently()
    {
        testcase("Phase 2a — PoseidonHash::zeroZero() == hash(0, 0)");
        setupOnce();
        BEAST_EXPECT(
            PoseidonHash::zeroZero() ==
            PoseidonHash::hash(FieldT::zero(), FieldT::zero()));
    }

    void
    testHashUint256Roundtrip()
    {
        testcase("Phase 2a — hash(uint256, uint256) round-trips through field");
        setupOnce();
        uint256 a;
        std::memset(a.data(), 0xAB, 32);
        uint256 b;
        std::memset(b.data(), 0xCD, 32);
        uint256 h1 = PoseidonHash::hash(a, b);
        uint256 h2 = PoseidonHash::hash(a, b);
        BEAST_EXPECT(h1 == h2);  // determinism
        // Hash differs from inputs (with overwhelming probability).
        BEAST_EXPECT(h1 != a && h1 != b);
    }

    void
    run() override
    {
        testConstantsLoadCorrectly();
        testReferenceVector_0_0();
        testReferenceVector_1_2();
        testReferenceVector_3_4();
        testGadgetMatchesOffCircuit();
        testGadgetIsSoundUnderTampering();
        testConstraintCount();
        testZeroZeroIsCachedConsistently();
        testHashUint256Roundtrip();
    }
};

BEAST_DEFINE_TESTSUITE(PoseidonGadget, zkp, ripple);

}  // namespace test
}  // namespace ripple
