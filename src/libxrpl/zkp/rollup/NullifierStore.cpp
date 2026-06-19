//------------------------------------------------------------------------------
/*
    Phase 4a — NullifierStore implementation.
*/
//==============================================================================

#include <libxrpl/zkp/rollup/NullifierStore.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>

#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STVector256.h>

#include <algorithm>

namespace ripple {
namespace zkp {
namespace rollup {

namespace {

std::vector<uint256>
readPageNullifiers(STLedgerEntry const& sle)
{
    auto const& v = sle.getFieldV256(sfHashes);
    return std::vector<uint256>(v.begin(), v.end());
}

void
writePageNullifiers(STLedgerEntry& sle, std::vector<uint256> const& nfs)
{
    // STVector256 has no public mutable accessor; build a fresh value
    // from the input vector and assign by setFieldV256.
    STVector256 v(sfHashes, nfs);
    sle.setFieldV256(sfHashes, v);
}

}  // anonymous namespace

bool
NullifierStore::contains(ReadView const& view, uint256 const& nf)
{
    std::uint32_t pageIndex = 0;
    while (true)
    {
        auto const sle = view.read(keylet::nullifier_page(pageIndex));
        if (!sle)
            return false;

        auto const& v = sle->getFieldV256(sfHashes);
        if (std::find(v.begin(), v.end(), nf) != v.end())
            return true;

        ++pageIndex;
    }
}

bool
NullifierStore::insert(ApplyView& view, uint256 const& nf)
{
    std::uint32_t pageIndex = 0;
    std::shared_ptr<STLedgerEntry> page;
    while (true)
    {
        auto next = view.peek(keylet::nullifier_page(pageIndex));
        if (!next)
            break;
        page = next;
        ++pageIndex;
    }
    if (page)
        --pageIndex;

    if (!page)
    {
        auto sle = std::make_shared<STLedgerEntry>(
            keylet::nullifier_page(0));
        std::vector<uint256> nfs{nf};
        writePageNullifiers(*sle, nfs);
        view.insert(sle);
        return true;
    }

    auto nfs = readPageNullifiers(*page);
    if (nfs.size() < kNullifiersPerPage)
    {
        nfs.push_back(nf);
        writePageNullifiers(*page, nfs);
        view.update(page);
        return true;
    }

    auto newPage = std::make_shared<STLedgerEntry>(
        keylet::nullifier_page(pageIndex + 1));
    std::vector<uint256> newNfs{nf};
    writePageNullifiers(*newPage, newNfs);
    view.insert(newPage);
    return true;
}

bool
NullifierStore::insertBatch(
    ApplyView& view,
    std::vector<uint256> const& nfs)
{
    for (auto const& nf : nfs)
    {
        if (!insert(view, nf))
            return false;
    }
    return true;
}

std::uint32_t
NullifierStore::pageCount(ReadView const& view)
{
    std::uint32_t n = 0;
    while (view.read(keylet::nullifier_page(n)))
        ++n;
    return n;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple