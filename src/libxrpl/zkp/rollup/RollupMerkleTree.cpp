// Copyright (c) 2026 Sainath Annadevara — Trinity College Dublin.
// SPDX-License-Identifier: ISC
//
// rollup/RollupMerkleTree.cpp  --- Phase 3.

#include "RollupMerkleTree.h"

#include "PoseidonHash.h"

#include <stdexcept>

namespace ripple {
namespace zkp {
namespace rollup {

// =============================================================================
// Construction
// =============================================================================

RollupMerkleTree::RollupMerkleTree(std::size_t depth)
    : depth_(depth)
    , capacity_(depth >= 64 ? ~std::size_t{0} : (std::size_t{1} << depth))
    , next_position_(0)
{
    if (depth == 0 || depth > 64)
        throw std::invalid_argument(
            "RollupMerkleTree: depth must be in [1, 64]");

    // One slot per level, plus one for the root level (== depth).
    cached_nodes_.resize(depth_ + 1);
    empty_hashes_.assign(depth_ + 1, uint256{});

    // Precompute empty-subtree hashes.  This calls PoseidonHash::hash, which
    // self-initialises on first use; we therefore do NOT need a separate
    // "constants populated" guard inside this constructor.  This avoids the
    // static-init bug class that bit Phase 2 (cf. Phase 2 audit §5.1).
    initializeEmptyHashes();
}

void
RollupMerkleTree::initializeEmptyHashes()
{

    // PoseidonHash::hash() asserts that initialize() has been called.  Make
    // the dependency explicit and idempotent so callers (sequencer, tests,
    // BatchVerifier) don't have to remember the order.  PoseidonHash::initialize
    // itself ensures alt_bn128_pp::init_public_params() has run.
    PoseidonHash::initialize();
    
    // empty_hashes_[0] = Poseidon(0, 0) — NOT uint256{}.  This is the central
    // semantic difference from IncrementalMerkleTree (cf. v2.2 §5).
    empty_hashes_[0] = h(uint256{}, uint256{});

    for (std::size_t level = 1; level <= depth_; ++level)
    {
        empty_hashes_[level] = h(empty_hashes_[level - 1],
                                 empty_hashes_[level - 1]);
    }
}

// =============================================================================
// Hash (delegates to the off-circuit Poseidon reference)
// =============================================================================

uint256
RollupMerkleTree::h(uint256 const& left, uint256 const& right)
{
    // PoseidonHash::hash is the single source of truth for Poseidon semantics
    // (cf. Phase 2 audit §3.1).  PoseidonGadget produces bit-exactly the same
    // outputs in-circuit, which is what the cross-layer test relies on.
    return PoseidonHash::hash(left, right);
}

// =============================================================================
// Sparse node store
// =============================================================================

uint256
RollupMerkleTree::getNode(std::size_t level, std::size_t position) const
{
    if (level >= cached_nodes_.size())
        return empty_hashes_[depth_];

    auto const& at_level = cached_nodes_[level];
    auto const it = at_level.find(position);
    if (it != at_level.end())
        return it->second;

    return empty_hashes_[level];
}

void
RollupMerkleTree::setNode(
    std::size_t level,
    std::size_t position,
    uint256 const& value)
{
    if (level >= cached_nodes_.size())
        return;
    cached_nodes_[level][position] = value;
}

// =============================================================================
// append()
// =============================================================================
//
// Algorithm (mirrors IncrementalMerkleTree::append + updateFrontier, but with
// Poseidon as the inner hash):
//
//   1. Reject if the tree is full.
//   2. Set leaf at level 0, position next_position_.
//   3. Walk up: at each level, look up the sibling (existing cached node, or
//      empty_hashes_[level] if untouched) and hash to compute the parent.
//      Cache the parent at the next level, repeat until level == depth_.
//   4. Increment next_position_.
//
// Cost: exactly `depth_` Poseidon evaluations.  No recomputation of nodes at
// positions that don't lie on the path of the new leaf.

std::size_t
RollupMerkleTree::append(uint256 const& leaf)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (next_position_ >= capacity_)
        throw std::overflow_error("RollupMerkleTree: tree is full");

    std::size_t const position = next_position_;
    setNode(0, position, leaf);

    // Walking up the tree along the path of the leaf at `position`:
    // recomputePathFromLeaf does exactly this.  We bump next_position_
    // *first* so that getNode() correctly treats `position` as occupied.
    ++next_position_;
    recomputePathFromLeaf(position);

    return position;
}

// =============================================================================
// update_leaf()  --- NOVEL CONTRIBUTION (Phase 3)
// =============================================================================
//
// Replace the leaf at `index` (which must already exist, i.e. been appended
// previously) and recompute the Poseidon path from that leaf up to the root.
//
// Why this is novel: the inherited IncrementalMerkleTree has only append();
// it cannot mutate an existing leaf.  Lin et al.'s ZkDeposit/ZkWithdraw model
// treats every commitment as single-spend (a new note per transaction), so
// they never had to update a leaf in place.  An account-based rollup, in
// contrast, *must* update existing accounts when their balance changes — and
// the only Merkle-friendly way to do that without rebuilding the tree is
// O(log n) path recomputation, which is what this method does.
//
// Cost: exactly `depth_` Poseidon evaluations.  Same as append().

void
RollupMerkleTree::update_leaf(
    std::size_t index,
    uint256 const& new_commitment)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (index >= next_position_)
        throw std::out_of_range(
            "RollupMerkleTree::update_leaf: index >= size()");

    // Replace the leaf.  We don't bump next_position_ — the leaf already
    // existed; only its value changes.
    setNode(0, index, new_commitment);

    // Recompute every ancestor of `index` up to the root.
    recomputePathFromLeaf(index);
}

// =============================================================================
// recomputePathFromLeaf — shared between append and update_leaf
// =============================================================================
//
// Caller must hold mutex_.  Walks from level 0 up to level depth_, computing
// each parent as Poseidon(left_child, right_child).  Sibling lookups return
// the appropriate empty hash if the sibling subtree is untouched, which is
// the same convention the in-circuit Merkle membership gadget uses, so the
// roots agree by construction.

uint256
RollupMerkleTree::recomputePathFromLeaf(std::size_t index)
{
    std::size_t pos = index;

    for (std::size_t level = 0; level < depth_; ++level)
    {
        bool const is_right = (pos & 1u) != 0;
        std::size_t const sibling_pos = is_right ? (pos - 1) : (pos + 1);

        uint256 const node    = getNode(level, pos);
        uint256 const sibling = getNode(level, sibling_pos);

        uint256 const parent =
            is_right ? h(sibling, node) : h(node, sibling);

        pos >>= 1;
        setNode(level + 1, pos, parent);
    }

    return getNode(depth_, 0);
}

// =============================================================================
// root()
// =============================================================================

uint256
RollupMerkleTree::root() const
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (next_position_ == 0)
        return empty_hashes_[depth_];

    return getNode(depth_, 0);
}

// =============================================================================
// authPath()
// =============================================================================
//
// Returns the `depth_` sibling hashes that, together with the leaf at
// `position`, recompute the root.  At each level the sibling is either an
// existing cached node or empty_hashes_[level].  This is what
// PoseidonCircuit's Merkle membership gadget consumes as auth_path[].

std::vector<uint256>
RollupMerkleTree::authPath(std::size_t position) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (position >= next_position_)
        throw std::out_of_range("RollupMerkleTree::authPath: position >= size()");

    std::vector<uint256> path;
    path.reserve(depth_);

    std::size_t pos = position;
    for (std::size_t level = 0; level < depth_; ++level)
    {
        std::size_t const sibling_pos = pos ^ 1u;  // flip lowest bit
        path.push_back(getNode(level, sibling_pos));
        pos >>= 1;
    }
    return path;
}

// =============================================================================
// verify() — static helper, walks an auth path
// =============================================================================

bool
RollupMerkleTree::verify(
    uint256 const& leaf,
    std::vector<uint256> const& auth_path,
    std::size_t position,
    uint256 const& expected_root)
{
    uint256 cur = leaf;
    std::size_t pos = position;

    for (std::size_t level = 0; level < auth_path.size(); ++level)
    {
        bool const is_right = (pos & 1u) != 0;
        cur = is_right
            ? h(auth_path[level], cur)
            : h(cur, auth_path[level]);
        pos >>= 1;
    }
    return cur == expected_root;
}

// =============================================================================
// Introspection helpers
// =============================================================================

std::size_t
RollupMerkleTree::size() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return next_position_;
}

uint256
RollupMerkleTree::emptyHash(std::size_t level) const
{
    if (level > depth_)
        throw std::out_of_range("RollupMerkleTree::emptyHash: level > depth");
    return empty_hashes_[level];
}

MerkleWitness
RollupMerkleTree::getWitness(std::size_t position) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (position >= next_position_)
        throw std::out_of_range(
            "RollupMerkleTree::getWitness: position >= size()");

    MerkleWitness w;
    w.leaf = getNode(0, position);
    w.position = position;
    w.root = (next_position_ == 0) ? empty_hashes_[depth_] : getNode(depth_, 0);

    w.auth_path.reserve(depth_);
    std::size_t pos = position;
    for (std::size_t level = 0; level < depth_; ++level)
    {
        w.auth_path.push_back(getNode(level, pos ^ 1u));
        pos >>= 1;
    }
    return w;
}

void
RollupMerkleTree::clear()
{
    std::lock_guard<std::mutex> lock(mutex_);

    next_position_ = 0;
    for (auto& level : cached_nodes_)
        level.clear();

    // empty_hashes_ stays as-is — they're constants for this depth.
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple