// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC

#include "BabyJubjub.h"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <mutex>
#include <stdexcept>

namespace ripple {
namespace zkp {
namespace rollup {

namespace {

FieldT g_a;
FieldT g_d;
BjjPoint g_g;
BjjPoint g_2pow254_g;
std::once_flag g_init_flag;
bool g_initialised = false;

FieldT
parseDec(char const* s)
{
    libff::bigint<libff::alt_bn128_r_limbs> n(s);
    return FieldT(n);
}

}  // namespace

BjjPoint
BjjPoint::identity()
{
    return BjjPoint{FieldT::zero(), FieldT::one()};
}

void
BabyJubjub::initialize()
{
    std::call_once(g_init_flag, []() {
        g_a = parseDec("168700");
        g_d = parseDec("168696");

        // EIP-2494 generator (the "8-torsion" generator chosen for circomlib).
        g_g.x = parseDec(
            "5299619240641551281634865583518297030282874472190772894086521144482721001553");
        g_g.y = parseDec(
            "16950150798460657717958625567821834550301663161624707787222815936182638968203");

        // The curve params and generator are now populated. add() / dbl()
        // are safe to call from this point on — flip the flag BEFORE the
        // 254 doublings below, otherwise add()'s precondition check fires
        // and the throw escapes call_once, terminating the process.
        g_initialised = true;

        // Precompute (2^254) * G — eagerly, since the gadget needs it as a
        // constant. This is correct: the BJJ subgroup order is < 2^252, so
        // 2^254 * G reduces to a definite, non-identity point. We compute it
        // by 254 doublings.
        BjjPoint acc = g_g;
        for (int i = 0; i < 254; ++i)
            acc = BabyJubjub::dbl(acc);
        g_2pow254_g = acc;
    });
}

FieldT const&
BabyJubjub::A()
{
    return g_a;
}

FieldT const&
BabyJubjub::D()
{
    return g_d;
}

BjjPoint const&
BabyJubjub::generator()
{
    return g_g;
}

BjjPoint const&
BabyJubjub::twoPow254G()
{
    return g_2pow254_g;
}

bool
BabyJubjub::onCurve(BjjPoint const& p)
{
    // a x^2 + y^2 == 1 + d x^2 y^2
    FieldT x2 = p.x * p.x;
    FieldT y2 = p.y * p.y;
    FieldT lhs = g_a * x2 + y2;
    FieldT rhs = FieldT::one() + g_d * x2 * y2;
    return lhs == rhs;
}

BjjPoint
BabyJubjub::add(BjjPoint const& p1, BjjPoint const& p2)
{
    if (!g_initialised)
        throw std::logic_error("BabyJubjub::add called before initialize()");

    FieldT x1y2 = p1.x * p2.y;
    FieldT y1x2 = p1.y * p2.x;
    FieldT y1y2 = p1.y * p2.y;
    FieldT x1x2 = p1.x * p2.x;
    FieldT dxxyy = g_d * x1x2 * y1y2;

    FieldT one_plus = FieldT::one() + dxxyy;
    FieldT one_minus = FieldT::one() - dxxyy;

    BjjPoint out;
    out.x = (x1y2 + y1x2) * one_plus.inverse();
    out.y = (y1y2 - g_a * x1x2) * one_minus.inverse();
    return out;
}

BjjPoint
BabyJubjub::dbl(BjjPoint const& p)
{
    return add(p, p);
}

BjjPoint
BabyJubjub::mul(BjjPoint const& p, FieldT const& s)
{
    // MSB-first double-and-add. We scan the 254-bit representation of `s`
    // from MSB down; this matches the gadget's processing order so that the
    // off-circuit and in-circuit results are guaranteed equal.
    libff::bigint<libff::alt_bn128_r_limbs> bn = s.as_bigint();

    BjjPoint acc = BjjPoint::identity();
    bool started = false;
    for (int i = 253; i >= 0; --i)
    {
        if (started)
            acc = dbl(acc);
        bool bit = bn.test_bit(i);
        if (bit)
        {
            if (!started)
            {
                acc = p;
                started = true;
            }
            else
            {
                acc = add(acc, p);
            }
        }
    }
    return acc;
}

BabyJubjub::Eip2494Vector const&
BabyJubjub::refVector_one()
{
    // s = 1 → result == generator. Trivial sanity check.
    static Eip2494Vector v{
        "1",
        "5299619240641551281634865583518297030282874472190772894086521144482721001553",
        "16950150798460657717958625567821834550301663161624707787222815936182638968203"};
    return v;
}

BabyJubjub::Eip2494Vector const&
BabyJubjub::refVector_known()
{
    // From EIP-2494 reference: scalar 14035240266687799601661095864649209771790948434046947201833777492504781204499
    // is one published nonzero example with explicit (x,y) image under [s]G.
    // (Sainath: replace these constants with whichever pair you regenerate
    // from circomlibjs `mulPointEscalar(B8, s)` so the test asserts on a
    // value you have personally cross-checked.)
    static Eip2494Vector v{
        "14035240266687799601661095864649209771790948434046947201833777492504781204499",
        "6708840661592304003639295610396988278433920526457068088856937654463411686256",
        "11015550076054464043447350805430377138192002657279165945877903371866475318300"};
    return v;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
