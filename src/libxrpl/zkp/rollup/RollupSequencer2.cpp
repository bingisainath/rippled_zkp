// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// RollupSequencer2 implementation. See RollupSequencer2.h.

#include "RollupSequencer2.h"
#include "BatchCircuitProver.h"

#include <xrpl/protocol/KeyType.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/SecretKey.h>
#include <xrpl/protocol/Seed.h>

#include <stdexcept>

namespace ripple {
namespace zkp {
namespace rollup {

RollupSequencer2::RollupSequencer2(
    std::size_t depth,
    std::string const& sequencerSeed)
    : depth_(depth), tree_(depth), seed_(sequencerSeed)
{
    auto const seed = generateSeed(seed_);
    auto const kp = generateKeyPair(KeyType::ed25519, seed);
    pubKey_.assign(kp.first.data(), kp.first.data() + kp.first.size());
}

RollupSequencer2::Account*
RollupSequencer2::find(FieldT const& apkX)
{
    auto it = accounts_.find(PoseidonHash::fieldToUint256(apkX));
    return it == accounts_.end() ? nullptr : &it->second;
}

RollupSequencer2::Account const*
RollupSequencer2::find(FieldT const& apkX) const
{
    auto it = accounts_.find(PoseidonHash::fieldToUint256(apkX));
    return it == accounts_.end() ? nullptr : &it->second;
}

std::optional<RollupSequencer2::AccountView>
RollupSequencer2::account(FieldT const& apkX) const
{
    if (auto const* a = find(apkX))
        return AccountView{a->index, a->balance, a->nonce};
    return std::nullopt;
}

std::vector<RollupSequencer2::AccountReport>
RollupSequencer2::accounts() const
{
    std::vector<AccountReport> out;
    out.reserve(accounts_.size());
    // accounts_ is keyed by fieldToUint256(apk_x), so iteration order is by
    // that key — stable across calls, which keeps the demo's before/after
    // tables aligned.
    for (auto const& [key, a] : accounts_)
        out.push_back({key, a.index, a.balance, a.nonce});
    return out;
}

uint256
RollupSequencer2::root() const
{
    return PoseidonHash::fieldToUint256(tree_.root());
}

bool
RollupSequencer2::admit(SignedRequest const& req) const
{
    if (!req.verifySignature())
        return false;

    if (req.type == RequestType::NoOp)
        return true;

    auto const* a = find(req.from_apk.x);

    if (req.type == RequestType::Transfer)
    {
        // The recipient must ALREADY exist. An empty slot holds 0, whereas
        // the circuit's to_old_leaf is a Poseidon image, so a transfer into a
        // fresh leaf can never satisfy the inclusion check — catch it here
        // rather than after ~62 s of proving.
        if (!a || req.nonce != a->nonce || req.value > a->balance)
            return false;
        auto const* to = find(req.dest);
        return to != nullptr;
    }

    if (req.type == RequestType::Deposit)
    {
        // Deposit creates the account on first use (nonce 0) or tops up an
        // existing one at its current nonce.
        std::uint64_t const expectedNonce = a ? a->nonce : 0;
        return req.nonce == expectedNonce;
    }

    // Withdraw requires an existing, sufficiently funded account.
    if (!a)
        return false;
    if (req.nonce != a->nonce)
        return false;
    if (req.value > a->balance)
        return false;
    return true;
}

std::array<std::uint8_t, 64>
RollupSequencer2::signBatchHash(uint256 const& batchHash) const
{
    auto const seed = generateSeed(seed_);
    auto const kp = generateKeyPair(KeyType::ed25519, seed);
    auto const sig =
        sign(kp.first, kp.second, Slice(batchHash.data(), batchHash.size()));
    std::array<std::uint8_t, 64> out{};
    if (sig.size() != out.size())
        throw std::logic_error("RollupSequencer2: unexpected sig size");
    std::copy(sig.data(), sig.data() + sig.size(), out.begin());
    return out;
}

std::optional<BatchProof2>
RollupSequencer2::buildBatch(
    std::vector<SequencerRequest> const& requests,
    std::uint32_t batchId)
{
    // Ordering contract with the L1 deposit queue: NONE required.
    //
    // BatchRollup2::preclaim matches each Deposit entry against outstanding
    // claims on (apk_x, drops) without regard to position, so the sequencer
    // may batch deposits in any order and may skip a claim whose depositor has
    // not yet sent a signed L2 request. What it may NOT do is credit a leaf no
    // claim names, or credit an amount no claim escrowed — either makes the
    // batch unprovable at L1.
    //
    // A strict-FIFO rule was considered and rejected: a Deposit entry needs the
    // depositor's in-circuit EdDSA signature, so one depositor who escrows and
    // never follows up would stall the queue head and block deposits for
    // everyone, permanently, for the price of one fee.
    if (requests.size() > BATCH2_SIZE)
        return std::nullopt;

    FieldT const prevRootF = tree_.root();

    std::vector<BatchEntryWitness> witnesses;
    std::vector<BatchProof2Entry> entries;
    witnesses.reserve(BATCH2_SIZE);
    entries.reserve(BATCH2_SIZE);

    // A snapshot of nextIndex_ / accounts_ so we can roll forward atomically:
    // we mutate local copies, and only commit to the members after the proof
    // succeeds.
    auto accounts = accounts_;
    std::size_t nextIndex = nextIndex_;
    AccountTree tree = tree_;

    auto padIndexBase = std::size_t{1} << (depth_ - 1);  // NoOp pad region

    for (std::size_t i = 0; i < BATCH2_SIZE; ++i)
    {
        BatchEntryWitness ew;
        BatchProof2Entry e;

        if (i < requests.size())
        {
            auto const& sr = requests[i];
            auto const& req = sr.req;
            if (!admit(req))
                return std::nullopt;

            // Withdrawals: the signed `dest` must encode the L1 payout target
            // carried alongside it. BatchRollup2::preflight rejects any batch
            // where these disagree, so catch it here rather than spending ~62 s
            // proving a batch L1 will refuse.
            if (req.type == RequestType::Withdraw &&
                (sr.destination == AccountID{} ||
                 req.dest != accountIdToField(sr.destination)))
                return std::nullopt;

            // An explicit NoOp is shaped exactly like a pad slot: it occupies
            // an empty leaf, mutates no account and creates nothing. Handle it
            // before the account lookup below, which would otherwise reject it
            // because only deposits may create accounts.
            //
            // This is what makes a BOOTSTRAP batch possible — a batch that
            // anchors genesis state (sequencer key, escrow account) without
            // crediting any L2 balance. Backed deposits need that: the escrow
            // account must be anchored before the first ttROLLUP_DEPOSIT2, and
            // isWellFormed() rejects an entirely empty batch (txCount == 0).
            if (req.type == RequestType::NoOp)
            {
                std::size_t const padIndex = padIndexBase + i;
                ew.req = req;
                ew.old_balance = 0;
                ew.is_create = true;
                ew.leaf_pos = tree.posBits(padIndex);
                ew.auth_path = tree.authPath(padIndex);
                witnesses.push_back(ew);

                e.fromApkX = PoseidonHash::fieldToUint256(req.from_apk.x);
                e.dest = PoseidonHash::fieldToUint256(req.dest);
                e.value = 0;
                e.nonce = 0;
                e.txType = RequestType::NoOp;
                e.destination = AccountID{};
                entries.push_back(e);
                continue;
            }

            FieldT const apkX = req.from_apk.x;
            uint256 const key = PoseidonHash::fieldToUint256(apkX);
            auto it = accounts.find(key);

            std::size_t index;
            std::uint64_t oldBal;
            bool isCreate;
            if (it == accounts.end())
            {
                if (req.type != RequestType::Deposit)
                    return std::nullopt;  // only deposits create accounts
                index = nextIndex++;
                oldBal = 0;
                isCreate = true;
            }
            else
            {
                index = it->second.index;
                oldBal = it->second.balance;
                isCreate = false;
            }

            ew.req = req;
            ew.old_balance = oldBal;
            ew.is_create = isCreate;
            ew.leaf_pos = tree.posBits(index);
            ew.auth_path = tree.authPath(index);
            // NOTE: pushed at the END of this block — the Transfer branch
            // below still has recipient fields to fill in.

            // Transfer: capture the recipient BEFORE the sender's update, but
            // take the auth path AFTER it — the circuit walks the recipient
            // leg from `mid`, the root the sender's update produced.
            Account* toAcct = nullptr;
            if (req.type == RequestType::Transfer)
            {
                uint256 const toKey = PoseidonHash::fieldToUint256(req.dest);
                auto toIt = accounts.find(toKey);
                if (toIt == accounts.end())
                    return std::nullopt;  // admit() already rejected this
                toAcct = &toIt->second;
                if (toAcct->index == index)
                    return std::nullopt;  // self-transfer: not supported
                ew.to_apk_x = req.dest;
                ew.to_old_balance = toAcct->balance;
                ew.to_nonce = toAcct->nonce;
            }

            // Apply the transition to the local tree + account map.
            std::uint64_t newBal = oldBal;
            if (req.type == RequestType::Deposit)
                newBal = oldBal + req.value;
            else if (
                req.type == RequestType::Withdraw ||
                req.type == RequestType::Transfer)
                newBal = oldBal - req.value;

            AccountLeaf nl;
            nl.apk = req.from_apk;
            nl.balance = newBal;
            nl.nonce = req.nonce + 1;
            tree.setLeaf(index, nl.hash());

            accounts[key] = Account{index, req.from_apk, newBal, req.nonce + 1};

            if (toAcct)
            {
                // Re-read: the map entry above may have been rehashed by the
                // assignment, and for a transfer the recipient is a DIFFERENT
                // key, so the pointer stays valid — but take the index by
                // value to keep that independent of container internals.
                std::size_t const toIndex = toAcct->index;
                std::uint64_t const toNewBal =
                    toAcct->balance + req.value;

                ew.to_leaf_pos = tree.posBits(toIndex);
                ew.to_auth_path = tree.authPath(toIndex);

                AccountLeaf tl;
                tl.apk = toAcct->apk;
                tl.balance = toNewBal;
                tl.nonce = toAcct->nonce;  // recipient nonce NOT consumed
                tree.setLeaf(toIndex, tl.hash());

                toAcct->balance = toNewBal;
            }

            witnesses.push_back(ew);

            e.fromApkX = PoseidonHash::fieldToUint256(apkX);
            e.dest = PoseidonHash::fieldToUint256(req.dest);
            e.value = req.value;
            e.nonce = req.nonce;
            e.txType = req.type;
            e.destination = sr.destination;
        }
        else
        {
            // NoOp pad: sequencer's own key, an empty pad slot, value 0.
            std::size_t const padIndex = padIndexBase + i;
            FieldT const padAsk =
                FieldT("31337") + FieldT(static_cast<std::uint64_t>(i));
            auto padReq = SignedRequest::make(
                padAsk, FieldT::zero(), 0, 0, RequestType::NoOp);

            ew.req = padReq;
            ew.old_balance = 0;
            ew.is_create = true;
            ew.leaf_pos = tree.posBits(padIndex);
            ew.auth_path = tree.authPath(padIndex);
            witnesses.push_back(ew);
            // NoOp leaves the slot empty — no tree mutation.

            e.fromApkX = PoseidonHash::fieldToUint256(padReq.from_apk.x);
            e.dest = uint256{};
            e.value = 0;
            e.nonce = 0;
            e.txType = RequestType::NoOp;
            e.destination = AccountID{};
        }

        entries.push_back(e);
    }

    auto pd = BatchCircuitProver::createBatchProof(prevRootF, witnesses);
    if (pd.empty())
        return std::nullopt;

    BatchProof2 bp;
    bp.batchId = batchId;
    bp.prevRoot = PoseidonHash::fieldToUint256(prevRootF);
    bp.newRoot = PoseidonHash::fieldToUint256(pd.new_root);
    bp.txCount = static_cast<std::uint32_t>(entries.size());
    bp.proof = pd.proof_bytes;
    bp.entries = std::move(entries);
    bp.sequencerSig = signBatchHash(bp.computeBatchHash());

    if (!bp.isWellFormed())
        return std::nullopt;

    // Commit sequencer state now that the proof exists.
    accounts_ = std::move(accounts);
    nextIndex_ = nextIndex;
    tree_ = std::move(tree);

    return bp;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
