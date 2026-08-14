/*
    BatchProof serialization implementation. See BatchProof.h for the
    wire format.
*/

#include <libxrpl/zkp/rollup/BatchProof.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/digest.h>

#include <cstring>

namespace ripple {
namespace zkp {
namespace rollup {

namespace {

// Little-endian helpers for fixed-width integers. We use LE on the wire
// because rippled's STAmount/STUInt32 fields are already LE internally when
// serialized to JSON-friendly hex; this keeps the blob-level encoding aligned
// with developer intuition when debugging with hexdump.

void
writeU32LE(std::vector<std::uint8_t>& buf, std::uint32_t v)
{
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
}

void
writeU64LE(std::vector<std::uint8_t>& buf, std::uint64_t v)
{
    for (int i = 0; i < 8; ++i)
        buf.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

// Offset-based readers. Return false on underflow.
bool
readU32LE(std::vector<std::uint8_t> const& buf, std::size_t& off, std::uint32_t& out)
{
    if (off + 4 > buf.size())
        return false;
    out = static_cast<std::uint32_t>(buf[off])
        | (static_cast<std::uint32_t>(buf[off + 1]) << 8)
        | (static_cast<std::uint32_t>(buf[off + 2]) << 16)
        | (static_cast<std::uint32_t>(buf[off + 3]) << 24);
    off += 4;
    return true;
}

bool
readU64LE(std::vector<std::uint8_t> const& buf, std::size_t& off, std::uint64_t& out)
{
    if (off + 8 > buf.size())
        return false;
    out = 0;
    for (int i = 0; i < 8; ++i)
        out |= static_cast<std::uint64_t>(buf[off + i]) << (8 * i);
    off += 8;
    return true;
}

bool
readBytes(
    std::vector<std::uint8_t> const& buf,
    std::size_t& off,
    std::uint8_t* dest,
    std::size_t n)
{
    if (off + n > buf.size())
        return false;
    std::memcpy(dest, buf.data() + off, n);
    off += n;
    return true;
}

}  // unnamed namespace

// BatchProof::serialize

std::vector<std::uint8_t>
BatchProof::serialize() const
{
    // Invariant: callers are expected to check isWellFormed() first.
    // We still defend against the most obvious misuse to keep this method
    // exception-safe and idempotent.
    if (txCount != entries.size())
        return {};
    if (proof.empty())
        return {};

    std::vector<std::uint8_t> buf;
    buf.reserve(
        BATCH_HEADER_BYTES + proof.size()
        + entries.size() * ROLLUP_TX_ENTRY_BYTES + SEQUENCER_SIG_BYTES);

    // Header
    writeU32LE(buf, batchId);
    buf.insert(buf.end(), prevRoot.begin(), prevRoot.end());
    buf.insert(buf.end(), newRoot.begin(), newRoot.end());
    writeU32LE(buf, txCount);
    writeU32LE(buf, static_cast<std::uint32_t>(proof.size()));

    // Proof payload
    buf.insert(buf.end(), proof.begin(), proof.end());

    // Entries (fixed 93 B each)
    for (auto const& e : entries)
    {
        buf.insert(buf.end(), e.commitment.begin(), e.commitment.end());
        buf.insert(buf.end(), e.nullifier.begin(),  e.nullifier.end());
        writeU64LE(buf, e.value);
        buf.push_back(static_cast<std::uint8_t>(e.txType));
        buf.insert(buf.end(), e.destination.begin(), e.destination.end());
    }

    // Sequencer signature trailer
    buf.insert(buf.end(), sequencerSig.begin(), sequencerSig.end());

    return buf;
}

// BatchProof::deserialize

BatchProof
BatchProof::deserialize(std::vector<std::uint8_t> const& blob, bool& ok)
{
    ok = false;
    BatchProof bp;

    // Minimum viable blob: header + 1 byte of proof + 0 entries + sig.
    if (blob.size() < BATCH_HEADER_BYTES + 1 + SEQUENCER_SIG_BYTES)
        return bp;

    std::size_t off = 0;

    if (!readU32LE(blob, off, bp.batchId)) return bp;
    if (!readBytes(blob, off, bp.prevRoot.begin(), 32)) return bp;
    if (!readBytes(blob, off, bp.newRoot.begin(), 32))  return bp;
    if (!readU32LE(blob, off, bp.txCount)) return bp;

    std::uint32_t proofSize = 0;
    if (!readU32LE(blob, off, proofSize)) return bp;

    // Sanity: proofSize must leave room for entries + sig.
    if (proofSize == 0) return bp;
    std::size_t const remaining = blob.size() - off;
    std::size_t const expectedEntries =
        static_cast<std::size_t>(bp.txCount) * ROLLUP_TX_ENTRY_BYTES;
    if (remaining < proofSize + expectedEntries + SEQUENCER_SIG_BYTES)
        return bp;

    // Proof
    bp.proof.resize(proofSize);
    if (!readBytes(blob, off, bp.proof.data(), proofSize)) return bp;

    // Entries
    if (bp.txCount > BATCH_SIZE) return bp;  // guard against absurd counts
    bp.entries.reserve(bp.txCount);
    for (std::uint32_t i = 0; i < bp.txCount; ++i)
    {
        RollupTxEntry e;
        if (!readBytes(blob, off, e.commitment.begin(), 32)) return bp;
        if (!readBytes(blob, off, e.nullifier.begin(),  32)) return bp;
        if (!readU64LE(blob, off, e.value)) return bp;

        std::uint8_t tt = 0;
        if (!readBytes(blob, off, &tt, 1)) return bp;
        if (tt > 1) return bp;  // only Deposit=0 or Withdraw=1
        e.txType = static_cast<RollupTxType>(tt);

        if (!readBytes(blob, off, e.destination.begin(), 20)) return bp;

        bp.entries.push_back(std::move(e));
    }

    // Sequencer signature
    if (!readBytes(blob, off, bp.sequencerSig.data(), SEQUENCER_SIG_BYTES))
        return bp;

    // Strict: no trailing bytes. Extra junk is a structural error.
    if (off != blob.size())
        return bp;

    ok = true;
    return bp;
}

// BatchProof::isWellFormed

bool
BatchProof::isWellFormed() const
{
    // (1) txCount in [1, BATCH_SIZE]
    if (txCount == 0 || txCount > BATCH_SIZE)
        return false;

    // (2) entries.size() matches the declared count
    if (entries.size() != txCount)
        return false;

    // (3) proof must have some bytes. This could be tightened to the
    //     exact Groth16 proof length (~190 B for BN-128).
    if (proof.empty())
        return false;

    // (4) total serialized size must fit within the blob cap
    std::size_t const total =
        BATCH_HEADER_BYTES
      + proof.size()
      + entries.size() * ROLLUP_TX_ENTRY_BYTES
      + SEQUENCER_SIG_BYTES;
    if (total > MAX_BATCH_BLOB_BYTES)
        return false;

    // Intra-batch nullifier uniqueness is a preclaim concern (requires
    // access to the nullifier chain in ledger state), not preflight.

    return true;
}

// BatchProof::computeBatchHash
// bh = SHA256( batchId_le4 || prevRoot || newRoot || nf_0 || nf_1 || ... )
//
// This is the off-chain digest the sequencer Ed25519-signs. rippled verifies
// the signature in BatchVerifier::preflight().

uint256
BatchProof::computeBatchHash() const
{
    sha256_hasher h;

    // batchId as LE u32
    std::uint8_t b[4];
    b[0] = static_cast<std::uint8_t>(batchId & 0xFF);
    b[1] = static_cast<std::uint8_t>((batchId >> 8) & 0xFF);
    b[2] = static_cast<std::uint8_t>((batchId >> 16) & 0xFF);
    b[3] = static_cast<std::uint8_t>((batchId >> 24) & 0xFF);
    h(b, sizeof(b));

    // prevRoot, newRoot
    h(prevRoot.data(), prevRoot.size());
    h(newRoot.data(),  newRoot.size());

    // nullifiers in entry order
    for (auto const& e : entries)
        h(e.nullifier.data(), e.nullifier.size());

    // sha256_hasher produces a 256-bit digest convertible to uint256.
    auto const digest = static_cast<sha256_hasher::result_type>(h);
    uint256 out;
    static_assert(sizeof(digest) == 32, "SHA-256 output must be 32 B");
    std::memcpy(out.begin(), digest.data(), 32);
    return out;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple