// BatchProof2 serialization + hashing. Wire format: BatchProof2.h.

#include <libxrpl/zkp/rollup/BatchProof2.h>
#include <libxrpl/zkp/rollup/PoseidonHash.h>

#include <xrpl/protocol/digest.h>

#include <cstring>

namespace ripple {
namespace zkp {
namespace rollup {

namespace {

void
writeU32LE(std::vector<std::uint8_t>& buf, std::uint32_t v)
{
    for (int i = 0; i < 4; ++i)
        buf.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

void
writeU64LE(std::vector<std::uint8_t>& buf, std::uint64_t v)
{
    for (int i = 0; i < 8; ++i)
        buf.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

bool
readU32LE(std::vector<std::uint8_t> const& buf, std::size_t& off, std::uint32_t& out)
{
    if (off + 4 > buf.size())
        return false;
    out = 0;
    for (int i = 0; i < 4; ++i)
        out |= static_cast<std::uint32_t>(buf[off + i]) << (8 * i);
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

}  // anonymous namespace

FieldT
BatchProof2Entry::message() const
{
    FieldT const fromX = PoseidonHash::uint256ToField(fromApkX);
    FieldT const destF = PoseidonHash::uint256ToField(dest);
    FieldT const inner = PoseidonHash::hash(fromX, destF);
    FieldT const meta = SignedRequest::packMeta(value, nonce, txType);
    return PoseidonHash::hash(inner, meta);
}

std::vector<std::uint8_t>
BatchProof2::serialize() const
{
    if (txCount != entries.size() || proof.empty())
        return {};

    std::vector<std::uint8_t> buf;
    buf.reserve(
        BATCH2_HEADER_BYTES + proof.size() +
        entries.size() * BATCH2_ENTRY_BYTES + BATCH2_SIG_BYTES);

    writeU32LE(buf, batchId);
    buf.insert(buf.end(), prevRoot.begin(), prevRoot.end());
    buf.insert(buf.end(), newRoot.begin(), newRoot.end());
    writeU32LE(buf, txCount);
    writeU32LE(buf, static_cast<std::uint32_t>(proof.size()));

    buf.insert(buf.end(), proof.begin(), proof.end());

    for (auto const& e : entries)
    {
        buf.insert(buf.end(), e.fromApkX.begin(), e.fromApkX.end());
        buf.insert(buf.end(), e.dest.begin(), e.dest.end());
        writeU64LE(buf, e.value);
        writeU64LE(buf, e.nonce);
        buf.push_back(static_cast<std::uint8_t>(e.txType));
        buf.insert(buf.end(), e.destination.begin(), e.destination.end());
    }

    buf.insert(buf.end(), sequencerSig.begin(), sequencerSig.end());
    return buf;
}

BatchProof2
BatchProof2::deserialize(std::vector<std::uint8_t> const& blob, bool& ok)
{
    ok = false;
    BatchProof2 bp;
    std::size_t off = 0;

    if (!readU32LE(blob, off, bp.batchId))
        return bp;
    if (!readBytes(blob, off, bp.prevRoot.begin(), 32))
        return bp;
    if (!readBytes(blob, off, bp.newRoot.begin(), 32))
        return bp;
    if (!readU32LE(blob, off, bp.txCount))
        return bp;

    std::uint32_t proofSize = 0;
    if (!readU32LE(blob, off, proofSize))
        return bp;
    if (proofSize == 0 || proofSize > MAX_BATCH2_BLOB_BYTES)
        return bp;
    if (bp.txCount == 0 || bp.txCount > BATCH2_SIZE)
        return bp;

    bp.proof.resize(proofSize);
    if (!readBytes(blob, off, bp.proof.data(), proofSize))
        return bp;

    bp.entries.resize(bp.txCount);
    for (auto& e : bp.entries)
    {
        if (!readBytes(blob, off, e.fromApkX.begin(), 32))
            return bp;
        if (!readBytes(blob, off, e.dest.begin(), 32))
            return bp;
        if (!readU64LE(blob, off, e.value))
            return bp;
        if (!readU64LE(blob, off, e.nonce))
            return bp;
        if (off + 1 > blob.size())
            return bp;
        e.txType = static_cast<RequestType>(blob[off]);
        off += 1;
        if (!readBytes(blob, off, e.destination.begin(), 20))
            return bp;
    }

    if (!readBytes(blob, off, bp.sequencerSig.data(), BATCH2_SIG_BYTES))
        return bp;

    // Reject trailing garbage.
    if (off != blob.size())
        return bp;

    ok = true;
    return bp;
}

bool
BatchProof2::isWellFormed() const
{
    if (txCount == 0 || txCount > BATCH2_SIZE)
        return false;
    if (entries.size() != txCount)
        return false;
    if (proof.empty())
        return false;
    // deserialize() casts a raw wire byte to RequestType, so an out-of-range
    // value can reach us here. Reject it structurally — packMeta would
    // otherwise fold a nonsense type into the entries hash.
    // RequestType is a contiguous 0..3 enum; NoOp is the largest valid value.
    for (auto const& e : entries)
    {
        if (static_cast<std::uint8_t>(e.txType) >
            static_cast<std::uint8_t>(RequestType::NoOp))
            return false;
    }
    std::size_t const total = BATCH2_HEADER_BYTES + proof.size() +
        entries.size() * BATCH2_ENTRY_BYTES + BATCH2_SIG_BYTES;
    if (total > MAX_BATCH2_BLOB_BYTES)
        return false;
    return true;
}

FieldT
BatchProof2::computeEntriesHash() const
{
    FieldT eh = FieldT::zero();
    for (auto const& e : entries)
        eh = PoseidonHash::hash(eh, e.message());
    return eh;
}

uint256
BatchProof2::computeBatchHash() const
{
    sha256_hasher h;

    std::uint8_t b[4];
    for (int i = 0; i < 4; ++i)
        b[i] = static_cast<std::uint8_t>((batchId >> (8 * i)) & 0xFF);
    h(b, sizeof(b));

    h(prevRoot.data(), prevRoot.size());
    h(newRoot.data(), newRoot.size());

    // Every field of every entry — binds the published data to the signature.
    for (auto const& e : entries)
    {
        h(e.fromApkX.data(), e.fromApkX.size());
        h(e.dest.data(), e.dest.size());
        std::uint8_t v[8];
        for (int i = 0; i < 8; ++i)
            v[i] = static_cast<std::uint8_t>((e.value >> (8 * i)) & 0xFF);
        h(v, sizeof(v));
        std::uint8_t nn[8];
        for (int i = 0; i < 8; ++i)
            nn[i] = static_cast<std::uint8_t>((e.nonce >> (8 * i)) & 0xFF);
        h(nn, sizeof(nn));
        std::uint8_t t = static_cast<std::uint8_t>(e.txType);
        h(&t, 1);
        h(e.destination.data(), e.destination.size());
    }

    auto const digest = static_cast<sha256_hasher::result_type>(h);
    uint256 out;
    static_assert(sizeof(digest) == 32, "SHA-256 output must be 32 B");
    std::memcpy(out.begin(), digest.data(), 32);
    return out;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
