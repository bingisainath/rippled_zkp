// RollupSequencer2: the off-chain Track 2 sequencer. Maintains the account
// tree, admits signed user requests, and builds a single-proof batch blob
// (BatchProof2) ready for submission as a ttBATCH_ROLLUP2 transaction.
//
// Users only SIGN (SignedRequest); the sequencer proves. No user secret ever
// enters the sequencer.

#ifndef RIPPLE_ZKP_ROLLUP_ROLLUP_SEQUENCER2_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ROLLUP_SEQUENCER2_H_INCLUDED

#include "AccountLeaf.h"
#include "AccountTree.h"
#include "BatchProof2.h"

#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/AccountID.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {

// A user request plus the L1 payout target (only meaningful for withdrawals).
struct SequencerRequest
{
    SignedRequest req;
    AccountID destination;  // withdrawals: L1 recipient; else zeros
};

class RollupSequencer2
{
public:
    RollupSequencer2(
        std::size_t depth,
        std::string const& sequencerSeed = "sequencer2-seed-phase6");

    // Admission check (does not mutate state): signature valid, nonce equals
    // the account's current nonce, and (for withdrawals) sufficient balance.
    bool
    admit(SignedRequest const& req) const;

    // Build a batch from up to BATCH2_SIZE requests. Pads with NoOps to the
    // fixed circuit size. Applies the transitions to the account tree, proves
    // the batch, and returns the signed blob. std::nullopt on any failure
    // (bad admission, prover error). Mutates sequencer state on success.
    std::optional<BatchProof2>
    buildBatch(
        std::vector<SequencerRequest> const& requests,
        std::uint32_t batchId);

    // Current account-tree root (uint256, leaf-0 convention).
    uint256
    root() const;

    // The sequencer's 33-byte Ed25519 public key (for sfSequencerPubKey).
    std::vector<std::uint8_t> const&
    publicKey() const
    {
        return pubKey_;
    }

    // Test/introspection: current balance/nonce for an account, if known.
    struct AccountView
    {
        std::size_t index;
        std::uint64_t balance;
        std::uint64_t nonce;
    };
    std::optional<AccountView>
    account(FieldT const& apkX) const;

    // Every account the sequencer knows, for reporting. READ-ONLY: it must not
    // mutate state or advance a nonce, because the demo calls it between
    // batches to show what moved off-chain.
    //
    // These figures live in the sequencer's memory, NOT on L1 — the ledger
    // stores only the root and cannot see them. The proof is what makes this
    // report non-repudiable.
    struct AccountReport
    {
        uint256 apkX;
        std::size_t index;
        std::uint64_t balance;
        std::uint64_t nonce;
    };
    std::vector<AccountReport>
    accounts() const;

private:
    struct Account
    {
        std::size_t index;
        BjjPoint apk;
        std::uint64_t balance;
        std::uint64_t nonce;
    };

    Account*
    find(FieldT const& apkX);
    Account const*
    find(FieldT const& apkX) const;

    std::array<std::uint8_t, 64>
    signBatchHash(uint256 const& batchHash) const;

    std::size_t depth_;
    AccountTree tree_;
    std::map<uint256, Account> accounts_;  // keyed by fieldToUint256(apk_x)
    std::size_t nextIndex_{0};

    std::vector<std::uint8_t> pubKey_;
    std::string seed_;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ROLLUP_SEQUENCER2_H_INCLUDED
