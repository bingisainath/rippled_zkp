/*
    NullifierStore: typed accessor over the ltNULLIFIER_PAGE SLE chain.
*/

#ifndef RIPPLE_ZKP_ROLLUP_NULLIFIERSTORE_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_NULLIFIERSTORE_H_INCLUDED

#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpld/ledger/ApplyView.h>
#include <xrpld/ledger/ReadView.h>

#include <cstdint>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {

// Each NullifierPage SLE holds at most this many nullifier hashes.
// Beyond this, a new page is allocated and linked into the chain.
constexpr std::size_t kNullifiersPerPage = 64;

class NullifierStore
{
public:
    // Walks the page chain starting at pageIndex 0 and returns true
    // iff `nf` is present in any page. Read-only; safe in preclaim().
    static bool
    contains(ReadView const& view, uint256 const& nf);

    // Inserts `nf` into the chain. If the latest page is full, allocates
    // a new page and links it. Mutating; only callable from doApply().
    static bool
    insert(ApplyView& view, uint256 const& nf);

    // Convenience: insert a whole batch's worth of nullifiers atomically.
    // Returns false on the first failure; ApplyView discards on outer return.
    static bool
    insertBatch(ApplyView& view, std::vector<uint256> const& nfs);

    // Page count helper, mainly for tests and logging.
    static std::uint32_t
    pageCount(ReadView const& view);
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_NULLIFIERSTORE_H_INCLUDED