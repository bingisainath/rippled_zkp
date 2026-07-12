//------------------------------------------------------------------------------
/*
    This file is part of rippled_zkp: ZK-Rollup extension for XRPL.
    Copyright (c) 2026 Trinity College Dublin (MSc dissertation).

    Phase 1 — Foundation: BatchProof binary serialization.
    See ZK Rollup on XRPL Technical Development Document v2.2 §8.2.
*/
//==============================================================================

#ifndef RIPPLE_ZKP_ROLLUP_BATCHPROOF_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_BATCHPROOF_H_INCLUDED

#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/AccountID.h>

#include <array>
#include <cstdint>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {

// =============================================================================
// Protocol constants (v2.2)
// =============================================================================

/** Target batch size — prototype: 8. */
constexpr std::uint32_t BATCH_SIZE = 8;

/** Absolute max blob size the transactor will accept (safety net in preflight). */
constexpr std::size_t MAX_BATCH_BLOB_BYTES = 1'000'000;  // 1 MB

/** Fixed per-entry size on the wire (v2.2 §8.2). */
constexpr std::size_t ROLLUP_TX_ENTRY_BYTES = 93;

/** Fixed header size before the Groth16 proof bytes. */
constexpr std::size_t BATCH_HEADER_BYTES =
    4   /* batchId */
  + 32  /* prevRoot */
  + 32  /* newRoot */
  + 4   /* txCount */
  + 4;  /* proofSize */

/** Ed25519 signature length. */
constexpr std::size_t SEQUENCER_SIG_BYTES = 64;

// =============================================================================
// Types
// =============================================================================

/**
 * Per-transaction public data inside a rollup batch.
 *
 * Intentionally fixed-width (93 bytes) to allow O(1) byte-offset parsing.
 * One Groth16 proof per transaction (N proofs total) — the batch is NOT
 * proof-aggregated. The N proofs are independent and verified in a loop in
 * preclaim(); they are bound to a single Merkle root by an on-chain root
 * replay in doApply() (tree.root() == newRoot), not by recursion. Proof
 * aggregation is costed future work (~10-16M constraints), see docs.
 */
enum class RollupTxType : std::uint8_t {
    Deposit  = 0,
    Withdraw = 1
};

struct RollupTxEntry
{
    uint256       commitment;     // 32 B — cm = Poseidon(v, rho, r, a_pk)
    uint256       nullifier;      // 32 B — nf = Poseidon(a_sk, rho)
    std::uint64_t value{0};       //  8 B — XRP drops (LE)
    RollupTxType  txType{RollupTxType::Deposit};  //  1 B
    AccountID     destination;    // 20 B — for withdrawals; zeros for deposits

    bool operator==(RollupTxEntry const& rhs) const
    {
        return commitment  == rhs.commitment
            && nullifier   == rhs.nullifier
            && value       == rhs.value
            && txType      == rhs.txType
            && destination == rhs.destination;
    }
};
static_assert(sizeof(std::uint64_t) == 8,  "u64 must be 8 bytes");
// Wire-size sanity (not memory-size — C++ may pad the struct internally):
//   32+32+8+1+20 = 93 B

/**
 * The serialized batch blob. Wire format (v2.2 §8.2):
 *
 *   offset  bytes  field
 *   ------  -----  --------------------------------------------
 *      0      4    batchId            uint32_t LE
 *      4     32    prevRoot           uint256  (Poseidon root BEFORE batch)
 *     36     32    newRoot            uint256  (Poseidon root AFTER batch)
 *     68      4    txCount            uint32_t LE
 *     72      4    proofSize          uint32_t LE (total proof bytes = N*192)
 *     76  proofSize  proofs           N independent Groth16 proofs (one per tx),
 *                                      concatenated, each padded to a 192 B slot
 *    +N*93           entries[]        N = txCount RollupTxEntry structs
 *    + 64            sequencerSig     Ed25519(sequencerPubKey, batchHash)
 *
 *   Total for N=8: 76 + 8*192 + 8*93 + 64 = 2420 bytes.
 *
 * `sequencerPubKey` lives in sfSequencerPubKey on the STTx — not in the blob.
 */
struct BatchProof
{
    std::uint32_t batchId{0};
    uint256       prevRoot{};
    uint256       newRoot{};
    std::uint32_t txCount{0};  // must equal entries.size() — enforced in preflight

    std::vector<std::uint8_t> proof;                    // N concatenated Groth16 proofs (192 B/slot)
    std::vector<RollupTxEntry> entries;                 // N = txCount
    std::array<std::uint8_t, SEQUENCER_SIG_BYTES> sequencerSig{};

    /**
     * Serialize to a contiguous byte buffer in the v2.2 wire format.
     * Never throws — returns empty vector on internal inconsistency
     * (callers should only serialize after isWellFormed()).
     */
    std::vector<std::uint8_t> serialize() const;

    /**
     * Deserialize from a byte buffer. Returns std::nullopt-style: sets
     * `ok = false` on any parse error (short buffer, bad proofSize, bad
     * txCount). Never throws.
     */
    static BatchProof deserialize(std::vector<std::uint8_t> const& blob, bool& ok);

    /**
     * Structural sanity check — stateless, no crypto. Used by preflight().
     *   1) 1 ≤ txCount ≤ BATCH_SIZE
     *   2) entries.size() == txCount
     *   3) proof is non-empty (Phase 1: any size; Phase 2+: tighter)
     *   4) full serialized size ≤ MAX_BATCH_BLOB_BYTES
     */
    bool isWellFormed() const;

    /**
     * SHA-256(batchId || prevRoot || newRoot || nf_0 || nf_1 || ... || nf_{N-1}).
     *
     * This is the off-chain digest over which the sequencer signs with
     * Ed25519. SHA-256 is used (not Poseidon) because the verification
     * happens in rippled's preflight() using the existing ed25519 helper —
     * no in-circuit work needed.
     *
     * v2.2 Cryptographic Formula Table (§8.1): "Batch Hash".
     */
    uint256 computeBatchHash() const;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_BATCHPROOF_H_INCLUDED