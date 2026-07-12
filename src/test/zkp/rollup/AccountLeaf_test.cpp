// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// Phase 6 gate — AccountLeaf hashing + SignedRequest message binding.
// Run: ./rippled --unittest=ripple.zkp.AccountLeaf

#include "../../../libxrpl/zkp/rollup/AccountLeaf.h"

#include <xrpl/beast/unit_test.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace ripple {
namespace test {

using namespace zkp::rollup;

class AccountLeaf_test : public beast::unit_test::suite
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

    static FieldT
    testKey()
    {
        return FieldT("111222333444555666777888999");
    }

public:
    void
    testLeafHashMatchesConvention()
    {
        testcase("Phase 6 — leaf = Poseidon(apk_x, balance + 2^64*nonce)");
        setupOnce();

        AccountLeaf leaf;
        leaf.apk = EdDSA::derivePublicKey(testKey());
        leaf.balance = 1'000'000;  // 1 XRP in drops
        leaf.nonce = 7;

        // Recompute by hand against the documented convention.
        FieldT two64 = FieldT::one();
        for (int i = 0; i < 64; ++i)
            two64 = two64 * FieldT(2);
        FieldT const packed =
            FieldT(std::uint64_t{1'000'000}) + two64 * FieldT(std::uint64_t{7});
        BEAST_EXPECT(leaf.hash() == PoseidonHash::hash(leaf.apk.x, packed));
    }

    void
    testLeafHashBindsEveryField()
    {
        testcase("Phase 6 — leaf hash changes with balance, nonce, key");
        setupOnce();

        AccountLeaf a;
        a.apk = EdDSA::derivePublicKey(testKey());
        a.balance = 500;
        a.nonce = 1;

        AccountLeaf b = a;
        b.balance = 501;
        AccountLeaf c = a;
        c.nonce = 2;
        AccountLeaf d = a;
        d.apk = EdDSA::derivePublicKey(testKey() + FieldT::one());

        BEAST_EXPECT(a.hash() != b.hash());
        BEAST_EXPECT(a.hash() != c.hash());
        BEAST_EXPECT(a.hash() != d.hash());
    }

    void
    testPackingIsInjectiveAtExtremes()
    {
        testcase("Phase 6 — (balance, nonce) packing injective at u64 extremes");
        setupOnce();

        auto const max = std::numeric_limits<std::uint64_t>::max();
        // (max, 0) vs (0, 1): balance saturated must not alias nonce bit 0.
        BEAST_EXPECT(
            AccountLeaf::packBalanceNonce(max, 0) !=
            AccountLeaf::packBalanceNonce(0, 1));
        // (0, max) vs (max, max - 1) style near-collisions.
        BEAST_EXPECT(
            AccountLeaf::packBalanceNonce(0, max) !=
            AccountLeaf::packBalanceNonce(max, max - 1));
        BEAST_EXPECT(
            AccountLeaf::packBalanceNonce(1, 1) !=
            AccountLeaf::packBalanceNonce(0, 1));
    }

    void
    testEmptyLeafIsZero()
    {
        testcase("Phase 6 — empty leaf is the zero field element");
        setupOnce();
        BEAST_EXPECT(AccountLeaf::emptyLeaf() == FieldT::zero());
    }

    void
    testSignedRequestRoundTrip()
    {
        testcase("Phase 6 — SignedRequest::make produces a verifiable request");
        setupOnce();

        auto const req = SignedRequest::make(
            testKey(),
            /*dest=*/FieldT("42"),
            /*value=*/250'000,
            /*nonce=*/3,
            RequestType::Transfer);

        BEAST_EXPECT(req.verifySignature());
        BEAST_EXPECT(BabyJubjub::onCurve(req.from_apk));
    }

    void
    testMessageBindsEveryField()
    {
        testcase("Phase 6 — tampering any request field breaks the signature");
        setupOnce();

        auto const req = SignedRequest::make(
            testKey(), FieldT("42"), 250'000, 3, RequestType::Transfer);
        BEAST_EXPECT(req.verifySignature());

        {
            auto t = req;
            t.value = 250'001;  // sequencer inflates the amount
            BEAST_EXPECT(!t.verifySignature());
        }
        {
            auto t = req;
            t.dest = FieldT("43");  // redirect the funds
            BEAST_EXPECT(!t.verifySignature());
        }
        {
            auto t = req;
            t.nonce = 4;  // replay at a different nonce
            BEAST_EXPECT(!t.verifySignature());
        }
        {
            auto t = req;
            t.type = RequestType::Withdraw;  // change semantics
            BEAST_EXPECT(!t.verifySignature());
        }
        {
            auto t = req;
            t.from_apk =
                EdDSA::derivePublicKey(testKey() + FieldT::one());
            BEAST_EXPECT(!t.verifySignature());  // claim another signer
        }
    }

    void
    testMetaPackingSeparatesTypes()
    {
        testcase("Phase 6 — meta packing distinguishes request types");
        setupOnce();

        // Same (value, nonce), different type => different meta.
        BEAST_EXPECT(
            SignedRequest::packMeta(100, 1, RequestType::Deposit) !=
            SignedRequest::packMeta(100, 1, RequestType::Withdraw));
        // Type cannot alias into nonce bits.
        BEAST_EXPECT(
            SignedRequest::packMeta(
                0, std::numeric_limits<std::uint64_t>::max(),
                RequestType::Deposit) !=
            SignedRequest::packMeta(0, 0, RequestType::Withdraw));
    }

    void
    run() override
    {
        testLeafHashMatchesConvention();
        testLeafHashBindsEveryField();
        testPackingIsInjectiveAtExtremes();
        testEmptyLeafIsZero();
        testSignedRequestRoundTrip();
        testMessageBindsEveryField();
        testMetaPackingSeparatesTypes();
    }
};

BEAST_DEFINE_TESTSUITE(AccountLeaf, zkp, ripple);

}  // namespace test
}  // namespace ripple
