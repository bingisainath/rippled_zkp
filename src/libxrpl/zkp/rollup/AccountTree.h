// AccountTree: the off-chain sparse Poseidon Merkle tree the Track 2
// sequencer maintains over account leaves. Leaf-0 convention (empty leaf =
// FieldT(0), empty-tree root = P^depth(0)) — matches BatchCircuit and
// RollupState2, deliberately NOT RollupMerkleTree's Poseidon(0,0).
//
// Header-only + inline so the sequencer, the blob tool, and unit tests share
// one definition without ODR issues.

#ifndef RIPPLE_ZKP_ROLLUP_ACCOUNT_TREE_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ACCOUNT_TREE_H_INCLUDED

#include "PoseidonHash.h"

#include <cstddef>
#include <map>
#include <stdexcept>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {

class AccountTree
{
public:
    explicit AccountTree(std::size_t depth) : depth_(depth)
    {
        PoseidonHash::initialize();
        empty_.resize(depth_ + 1);
        empty_[0] = FieldT::zero();
        for (std::size_t l = 1; l <= depth_; ++l)
            empty_[l] = PoseidonHash::hash(empty_[l - 1], empty_[l - 1]);
    }

    std::size_t
    depth() const
    {
        return depth_;
    }

    // Current value at a leaf position (FieldT(0) if never set).
    FieldT
    leaf(std::size_t pos) const
    {
        auto it = leaves_.find(pos);
        return it == leaves_.end() ? FieldT::zero() : it->second;
    }

    void
    setLeaf(std::size_t pos, FieldT const& v)
    {
        if (pos >= (std::size_t{1} << depth_))
            throw std::out_of_range("AccountTree::setLeaf pos out of range");
        leaves_[pos] = v;
    }

    // Root over the current leaves.
    FieldT
    root() const
    {
        return node(depth_, 0);
    }

    // Sibling hashes level 0..depth-1 for a leaf position.
    std::vector<FieldT>
    authPath(std::size_t pos) const
    {
        std::vector<FieldT> path;
        path.reserve(depth_);
        for (std::size_t l = 0; l < depth_; ++l)
            path.push_back(node(l, (pos >> l) ^ 1));
        return path;
    }

    // Position bits, LSB-first (level 0 direction first).
    std::vector<bool>
    posBits(std::size_t pos) const
    {
        std::vector<bool> bits;
        bits.reserve(depth_);
        for (std::size_t l = 0; l < depth_; ++l)
            bits.push_back((pos >> l) & 1);
        return bits;
    }

private:
    // Hash of the subtree rooted at (level, idx); empty subtrees fold from
    // the memoized empty-hash table so depth-16 paths cost ~depth hashes.
    FieldT
    node(std::size_t level, std::size_t idx) const
    {
        if (level == 0)
            return leaf(idx);
        auto const lo = idx << level;
        auto const hi = (idx + 1) << level;
        auto it = leaves_.lower_bound(lo);
        if (it == leaves_.end() || it->first >= hi)
            return empty_[level];
        return PoseidonHash::hash(
            node(level - 1, 2 * idx), node(level - 1, 2 * idx + 1));
    }

    std::size_t depth_;
    std::map<std::size_t, FieldT> leaves_;
    std::vector<FieldT> empty_;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ACCOUNT_TREE_H_INCLUDED
