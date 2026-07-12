// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// Native EdDSA over Baby Jubjub. See EdDSA.h for the scheme definition.

#include "EdDSA.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <stdexcept>
#include <string>

namespace ripple {
namespace zkp {
namespace rollup {

namespace {

using BigInt = boost::multiprecision::cpp_int;

// BJJ prime subgroup order ℓ (EIP-2494: curve order = 8·ℓ).
char const* const kSubgroupOrderDec =
    "2736030358979909402780800718157159386076813972158567259200215660948"
    "447373041";

BigInt const&
subgroupOrder()
{
    static BigInt const l{std::string(kSubgroupOrderDec)};
    return l;
}

// FieldT (canonical representative in [0, p)) -> arbitrary-precision integer.
BigInt
toInt(FieldT const& v)
{
    auto const b = v.as_bigint();  // libff::bigint<4>, 64-bit limbs, LSW first
    BigInt out = 0;
    for (int i = 3; i >= 0; --i)
    {
        out <<= 64;
        out += static_cast<std::uint64_t>(b.data[i]);
    }
    return out;
}

// Non-negative integer < p -> FieldT (via decimal round-trip; not hot-path).
FieldT
fromInt(BigInt const& v)
{
    std::string const dec = v.str();
    return FieldT(libff::bigint<libff::alt_bn128_r_limbs>(dec.c_str()));
}

}  // anonymous namespace

char const*
EdDSA::subgroupOrderDecimal()
{
    return kSubgroupOrderDec;
}

BjjPoint
EdDSA::derivePublicKey(FieldT const& ask)
{
    BigInt const a = toInt(ask) % subgroupOrder();
    if (a == 0)
        throw std::invalid_argument("EdDSA: ask reduces to 0 mod l");
    // [ask]·G == [ask mod l]·G since G has order l; use ask directly.
    return BabyJubjub::mul(BabyJubjub::generator(), ask);
}

FieldT
EdDSA::challenge(BjjPoint const& R, BjjPoint const& A, FieldT const& msg)
{
    FieldT const h1 = PoseidonHash::hash(R.x, R.y);
    FieldT const h2 = PoseidonHash::hash(A.x, A.y);
    FieldT const h3 = PoseidonHash::hash(h1, h2);
    return PoseidonHash::hash(h3, msg);
}

EdDSASignature
EdDSA::sign(FieldT const& ask, FieldT const& msg)
{
    BigInt const l = subgroupOrder();

    BigInt const a = toInt(ask) % l;
    if (a == 0)
        throw std::invalid_argument("EdDSA: ask reduces to 0 mod l");

    BjjPoint const A = derivePublicKey(ask);

    // Deterministic nonce r = H(ask, m) mod l. Domain-separated from the
    // challenge chain by structure (challenge always starts from point
    // coordinates hashed pairwise).
    BigInt r = toInt(PoseidonHash::hash(ask, msg)) % l;
    if (r == 0)
        r = 1;  // vanishing-probability edge; keep r in [1, l)

    BjjPoint const R = BabyJubjub::mul(BabyJubjub::generator(), fromInt(r));

    FieldT const h = challenge(R, A, msg);

    BigInt const s = (r + (toInt(h) % l) * a) % l;

    return EdDSASignature{R, fromInt(s)};
}

bool
EdDSA::verify(BjjPoint const& A, FieldT const& msg, EdDSASignature const& sig)
{
    if (!BabyJubjub::onCurve(sig.R) || !BabyJubjub::onCurve(A))
        return false;

    FieldT const h = challenge(sig.R, A, msg);

    // [s]·G == R + [h]·A  (full 254-bit h; A has order l so this matches
    // the signer's h mod l — see EdDSA.h).
    BjjPoint const lhs = BabyJubjub::mul(BabyJubjub::generator(), sig.s);
    BjjPoint const rhs = BabyJubjub::add(sig.R, BabyJubjub::mul(A, h));

    return lhs == rhs;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
