// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// AccountLeaf + SignedRequest implementations. Hash conventions are
// specified in AccountLeaf.h and shared verbatim with the BatchCircuit.

#include "AccountLeaf.h"

namespace ripple {
namespace zkp {
namespace rollup {

namespace {

// 2^64 and 2^128 as field constants (computed once).
FieldT const&
twoPow64()
{
    static FieldT const v = []() {
        FieldT two = FieldT(2);
        FieldT r = FieldT::one();
        for (int i = 0; i < 64; ++i)
            r = r * two;
        return r;
    }();
    return v;
}

FieldT const&
twoPow128()
{
    static FieldT const v = twoPow64() * twoPow64();
    return v;
}

}  // anonymous namespace

FieldT
AccountLeaf::packBalanceNonce(std::uint64_t balance, std::uint64_t nonce)
{
    return FieldT(balance) + twoPow64() * FieldT(nonce);
}

FieldT
AccountLeaf::hash() const
{
    return PoseidonHash::hash(apk.x, packBalanceNonce(balance, nonce));
}

FieldT
AccountLeaf::emptyLeaf()
{
    return FieldT::zero();
}

FieldT
SignedRequest::packMeta(
    std::uint64_t value,
    std::uint64_t nonce,
    RequestType type)
{
    return FieldT(value) + twoPow64() * FieldT(nonce) +
        twoPow128() * FieldT(static_cast<std::uint64_t>(type));
}

FieldT
SignedRequest::message() const
{
    FieldT const inner = PoseidonHash::hash(from_apk.x, dest);
    return PoseidonHash::hash(inner, packMeta(value, nonce, type));
}

bool
SignedRequest::verifySignature() const
{
    return EdDSA::verify(from_apk, message(), sig);
}

SignedRequest
SignedRequest::make(
    FieldT const& ask,
    FieldT const& dest,
    std::uint64_t value,
    std::uint64_t nonce,
    RequestType type)
{
    SignedRequest req;
    req.from_apk = EdDSA::derivePublicKey(ask);
    req.dest = dest;
    req.value = value;
    req.nonce = nonce;
    req.type = type;
    req.sig = EdDSA::sign(ask, req.message());
    return req;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
