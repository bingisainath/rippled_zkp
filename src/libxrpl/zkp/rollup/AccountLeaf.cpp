// AccountLeaf + SignedRequest implementations. Hash conventions are
// specified in AccountLeaf.h and shared verbatim with the BatchCircuit.

#include "AccountLeaf.h"

#include <cstring>

namespace ripple {
namespace zkp {
namespace rollup {

uint256
accountIdToUint256(AccountID const& id)
{
    static_assert(
        AccountID::bytes == 20, "AccountID must be 20 bytes for this packing");
    uint256 padded{};  // value-initialised: all 32 bytes zero
    // Left-pad: 12 zero bytes, then the AccountID in its native order.
    std::memcpy(padded.begin() + 12, id.data(), AccountID::bytes);
    return padded;
}

FieldT
accountIdToField(AccountID const& id)
{
    // < 2^160 < p, so uint256ToField never actually reduces here.
    return PoseidonHash::uint256ToField(accountIdToUint256(id));
}

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
