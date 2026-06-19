// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// Phase 2b gate. Run: ./rippled --unittest=ripple.zkp.BabyJubjubGadget

#include "../../../libxrpl/zkp/rollup/BabyJubjub.h"
#include "../../../libxrpl/zkp/rollup/BabyJubjubGadget.h"

#include <xrpl/beast/unit_test.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace ripple {
namespace test {

using namespace zkp::rollup;

class BabyJubjubGadget_test : public beast::unit_test::suite
{
    static FieldT
    fromDec(char const* s)
    {
        libff::bigint<libff::alt_bn128_r_limbs> n(s);
        return FieldT(n);
    }

    void
    setupOnce()
    {
        static bool done = false;
        if (done)
            return;
        libff::alt_bn128_pp::init_public_params();
        BabyJubjub::initialize();
        done = true;
    }

public:
    void
    testGeneratorOnCurve()
    {
        testcase("Phase 2b — BJJ generator point lies on the curve");
        setupOnce();
        BEAST_EXPECT(BabyJubjub::onCurve(BabyJubjub::generator()));
    }

    void
    testIdentityIsNeutral()
    {
        testcase("Phase 2b — identity (0,1) is the additive identity");
        setupOnce();
        BjjPoint id = BjjPoint::identity();
        BjjPoint sum = BabyJubjub::add(BabyJubjub::generator(), id);
        BEAST_EXPECT(sum == BabyJubjub::generator());
    }

    void
    testDoublingIsAdditionWithSelf()
    {
        testcase("Phase 2b — dbl(P) == add(P, P)");
        setupOnce();
        BjjPoint dd = BabyJubjub::dbl(BabyJubjub::generator());
        BjjPoint aa =
            BabyJubjub::add(BabyJubjub::generator(), BabyJubjub::generator());
        BEAST_EXPECT(dd == aa);
        BEAST_EXPECT(BabyJubjub::onCurve(dd));
    }

    void
    testScalarMul_one()
    {
        testcase("Phase 2b — [1]·G == G");
        setupOnce();
        auto v = BabyJubjub::refVector_one();
        FieldT s = fromDec(v.scalar_decimal);
        BjjPoint q = BabyJubjub::mul(BabyJubjub::generator(), s);
        BEAST_EXPECT(q == BabyJubjub::generator());
    }

    void
    testScalarMul_known()
    {
        testcase("Phase 2b — [s]·G matches published EIP-2494 vector");
        setupOnce();
        auto v = BabyJubjub::refVector_known();
        FieldT s = fromDec(v.scalar_decimal);
        FieldT expected_x = fromDec(v.expected_x_decimal);
        FieldT expected_y = fromDec(v.expected_y_decimal);
        BjjPoint q = BabyJubjub::mul(BabyJubjub::generator(), s);
        BEAST_EXPECT(q.x == expected_x);
        BEAST_EXPECT(q.y == expected_y);
        BEAST_EXPECT(BabyJubjub::onCurve(q));
    }

    void
    testAddGadget()
    {
        testcase("Phase 2b — BabyJubjubAddGadget matches off-circuit add");
        setupOnce();
        BjjPoint p1 = BabyJubjub::generator();
        BjjPoint p2 = BabyJubjub::dbl(BabyJubjub::generator());
        BjjPoint expected = BabyJubjub::add(p1, p2);

        libsnark::protoboard<FieldT> pb;
        libsnark::pb_variable<FieldT> x1, y1, x2, y2, x3, y3;
        x1.allocate(pb, "x1");
        y1.allocate(pb, "y1");
        x2.allocate(pb, "x2");
        y2.allocate(pb, "y2");
        x3.allocate(pb, "x3");
        y3.allocate(pb, "y3");
        BabyJubjubAddGadget g(pb, x1, y1, x2, y2, x3, y3, "add");
        g.generate_r1cs_constraints();
        pb.val(x1) = p1.x;
        pb.val(y1) = p1.y;
        pb.val(x2) = p2.x;
        pb.val(y2) = p2.y;
        g.generate_r1cs_witness();
        BEAST_EXPECT(pb.val(x3) == expected.x);
        BEAST_EXPECT(pb.val(y3) == expected.y);
        BEAST_EXPECT(pb.is_satisfied());
    }

    void
    testMulGadget_smallScalar()
    {
        testcase("Phase 2b — BabyJubjubMulGadget agrees with mul() for s=7");
        setupOnce();
        FieldT s(7);
        BjjPoint expected = BabyJubjub::mul(BabyJubjub::generator(), s);

        libsnark::protoboard<FieldT> pb;
        libsnark::pb_variable<FieldT> px, py, qx, qy;
        px.allocate(pb, "px");
        py.allocate(pb, "py");
        qx.allocate(pb, "qx");
        qy.allocate(pb, "qy");
        libsnark::pb_variable_array<FieldT> bits;
        bits.allocate(pb, BabyJubjubMulGadget::kScalarBits, "bits");

        BabyJubjubMulGadget g(pb, px, py, bits, qx, qy, "mul");
        g.generate_r1cs_constraints();

        // Decompose s = 7 into bits (LSB first).
        libff::bigint<libff::alt_bn128_r_limbs> sbn = s.as_bigint();
        for (std::size_t i = 0; i < BabyJubjubMulGadget::kScalarBits; ++i)
            pb.val(bits[i]) =
                sbn.test_bit(i) ? FieldT::one() : FieldT::zero();
        pb.val(px) = BabyJubjub::generator().x;
        pb.val(py) = BabyJubjub::generator().y;

        g.generate_r1cs_witness();
        BEAST_EXPECT(pb.val(qx) == expected.x);
        BEAST_EXPECT(pb.val(qy) == expected.y);
        BEAST_EXPECT(pb.is_satisfied());
    }

    void
    testMulGadget_isUnsatisfiableForWrongOutput()
    {
        testcase("Phase 2b — corrupting the output wire breaks the system");
        setupOnce();
        libsnark::protoboard<FieldT> pb;
        libsnark::pb_variable<FieldT> px, py, qx, qy;
        px.allocate(pb, "px");
        py.allocate(pb, "py");
        qx.allocate(pb, "qx");
        qy.allocate(pb, "qy");
        libsnark::pb_variable_array<FieldT> bits;
        bits.allocate(pb, BabyJubjubMulGadget::kScalarBits, "bits");

        BabyJubjubMulGadget g(pb, px, py, bits, qx, qy, "mul");
        g.generate_r1cs_constraints();

        FieldT s(13);
        libff::bigint<libff::alt_bn128_r_limbs> sbn = s.as_bigint();
        for (std::size_t i = 0; i < BabyJubjubMulGadget::kScalarBits; ++i)
            pb.val(bits[i]) =
                sbn.test_bit(i) ? FieldT::one() : FieldT::zero();
        pb.val(px) = BabyJubjub::generator().x;
        pb.val(py) = BabyJubjub::generator().y;
        g.generate_r1cs_witness();
        BEAST_EXPECT(pb.is_satisfied());

        pb.val(qx) = pb.val(qx) + FieldT::one();
        BEAST_EXPECT(!pb.is_satisfied());
    }

    void
    run() override
    {
        testGeneratorOnCurve();
        testIdentityIsNeutral();
        testDoublingIsAdditionWithSelf();
        testScalarMul_one();
        testScalarMul_known();
        testAddGadget();
        testMulGadget_smallScalar();
        testMulGadget_isUnsatisfiableForWrongOutput();
    }
};

BEAST_DEFINE_TESTSUITE(BabyJubjubGadget, zkp, ripple);

}  // namespace test
}  // namespace ripple
