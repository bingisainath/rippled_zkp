// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// BatchProof2: the Track 2 (Phase 6, Option A) batch blob. ONE Groth16 proof
// per batch (vs Track 1's N proofs), account-based entries carrying just
// enough for the on-chain verifier to (a) recompute the circuit's entriesHash
// public input and (b) move escrowed XRP in doApply.
//
// Wire format:
//   offset  bytes  field
//   ------  -----  --------------------------------------------
//      0      4    batchId          uint32 LE
//      4     32    prevRoot         uint256  (Poseidon root before batch)
//     36     32    newRoot          uint256  (Poseidon root after batch)
//     68      4    txCount          uint32 LE  (= entries.size(), padded to N)
//     72      4    proofSize        uint32 LE  (bytes of the single proof)
//     76  proofSize  proof          ONE Groth16 proof (~137 B)
//    ...  N*101  entries[]          Track2 account entries (101 B each)
//    +64          sequencerSig      Ed25519 over computeBatchHash()
//
//   Total N=8: 76 + 137 + 8*101 + 64 = 1085 B  (vs Track 1's 2420 B).
//
// Track2 entry (101 B):
//   from_apk_x  32 B  signer public key x-coord (field element as uint256)
//   dest        32 B  message destination field (recipient apk_x, or the
//                     AccountID packed into a field for a withdrawal)
//   value        8 B  drops (LE)
//   nonce        8 B  signer's current leaf nonce (LE)
//   txType       1 B  RequestType {Deposit=0, Withdraw=1, Transfer=2, NoOp=3}
//   destAccount 20 B  XRPL AccountID payout target (withdrawals; zeros else)
//
// The signature (R, s) is NOT on the wire — it is consumed inside the proof
// witness. The proof IS the evidence a valid signature existed.

#ifndef RIPPLE_ZKP_ROLLUP_BATCHPROOF2_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_BATCHPROOF2_H_INCLUDED

#include "AccountLeaf.h"

#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/AccountID.h>

#include <array>
#include <cstdint>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {

constexpr std::uint32_t BATCH2_SIZE = 8;
constexpr std::size_t BATCH2_ENTRY_BYTES = 101;
constexpr std::size_t BATCH2_HEADER_BYTES = 76;   // 4+32+32+4+4
constexpr std::size_t BATCH2_SIG_BYTES = 64;
constexpr std::size_t MAX_BATCH2_BLOB_BYTES = 1'000'000;

struct BatchProof2Entry
{
    uint256 fromApkX;    // 32 B — signer apk_x
    uint256 dest;        // 32 B — message dest field
    std::uint64_t value{0};
    std::uint64_t nonce{0};
    RequestType txType{RequestType::NoOp};
    AccountID destination;  // 20 B — L1 payout target for withdrawals

    bool
    operator==(BatchProof2Entry const& r) const
    {
        return fromApkX == r.fromApkX && dest == r.dest &&
            value == r.value && nonce == r.nonce && txType == r.txType &&
            destination == r.destination;
    }

    // Rebuild the SignedRequest MESSAGE field this entry commits to, using
    // the canonical AccountLeaf convention (sig omitted — not needed to
    // recompute the message / entriesHash).
    FieldT
    message() const;
};

struct BatchProof2
{
    std::uint32_t batchId{0};
    uint256 prevRoot{};
    uint256 newRoot{};
    std::uint32_t txCount{0};

    std::vector<std::uint8_t> proof;  // ONE Groth16 proof
    std::vector<BatchProof2Entry> entries;
    std::array<std::uint8_t, BATCH2_SIG_BYTES> sequencerSig{};

    std::vector<std::uint8_t>
    serialize() const;

    static BatchProof2
    deserialize(std::vector<std::uint8_t> const& blob, bool& ok);

    bool
    isWellFormed() const;

    // The circuit's entriesHash public input, recomputed natively from the
    // entries (Poseidon chain over each entry's message). preclaim uses this
    // to bind the published entry data to the verified proof.
    FieldT
    computeEntriesHash() const;

    // SHA-256(batchId || prevRoot || newRoot || entry bytes) — the digest the
    // sequencer signs with Ed25519 (checked natively in preflight, no circuit).
    uint256
    computeBatchHash() const;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_BATCHPROOF2_H_INCLUDED
