// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// Baby Jubjub: a twisted Edwards curve over the BN-128 scalar field.
//   E_BJJ : a*x^2 + y^2 = 1 + d*x^2*y^2
//   a = 168700,  d = 168696
//   p (base field of BJJ == BN-128 Fr) =
//     21888242871839275222246405745257275088548364400416034343698204186575808495617
//
// Reference: EIP-2494, Barreto–Naehrig + iden3 specification.
// Generator G_J as fixed by EIP-2494 (used by circomlib `babyjub.circom`).
//
// Subgroup order ℓ ≈ 2^251 (the prime divisor of the curve order). For our
// purposes, scalars are 254 bits because we operate over the full BN-128
// scalar field; this is consistent with circomlib's `escalarmulany`.

#ifndef RIPPLE_ZKP_ROLLUP_BABY_JUBJUB_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_BABY_JUBJUB_H_INCLUDED

#include "PoseidonHash.h"  // for FieldT alias

namespace ripple {
namespace zkp {
namespace rollup {

// A Baby Jubjub point in (twisted) Edwards affine coordinates.
struct BjjPoint
{
    FieldT x;
    FieldT y;

    static BjjPoint
    identity();  // (0, 1)

    bool
    operator==(BjjPoint const& other) const
    {
        return x == other.x && y == other.y;
    }
};

class BabyJubjub
{
public:
    // Initialise constants A, D, generator. Idempotent.
    static void
    initialize();

    // Curve constants — exposed so the gadget can pull them.
    static FieldT const&
    A();
    static FieldT const&
    D();
    static BjjPoint const&
    generator();

    // True if (x,y) lies on E_BJJ. Useful in unit tests and as a sanity gate.
    static bool
    onCurve(BjjPoint const& p);

    // Twisted Edwards complete addition formulas (Bernstein et al., 2007):
    //   x3 = (x1 y2 + y1 x2) / (1 + d x1 x2 y1 y2)
    //   y3 = (y1 y2 - a x1 x2) / (1 - d x1 x2 y1 y2)
    // These are complete on prime-order subgroups — no edge case for our use.
    static BjjPoint
    add(BjjPoint const& p1, BjjPoint const& p2);
    static BjjPoint
    dbl(BjjPoint const& p);  // == add(p, p)

    // Scalar multiplication by a 254-bit scalar. Constant-time-ish, MSB first.
    static BjjPoint
    mul(BjjPoint const& p, FieldT const& s);

    // EIP-2494 reference vectors — exposed so unit tests can check
    // `mul(generator(), s)` against published outputs.
    struct Eip2494Vector
    {
        char const* scalar_decimal;
        char const* expected_x_decimal;
        char const* expected_y_decimal;
    };
    static Eip2494Vector const&
    refVector_one();   // s = 1   →  G itself
    static Eip2494Vector const&
    refVector_known(); // s = published constant

    // For the gadget: precomputed (2^254)·G used by the prefix-trick
    // (cancels out the always-on +G accumulation in scalar-mul). In affine
    // coordinates over Fr.
    static BjjPoint const&
    twoPow254G();
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_BABY_JUBJUB_H_INCLUDED
