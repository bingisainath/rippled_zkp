// RollupMerkleTree: a Poseidon-based incremental Merkle tree with
// update_leaf(), and the off-circuit twin of PoseidonCircuit's Merkle
// membership gadget.
//
// This is deliberately NOT a subclass or a modification of
// ripple::zkp::IncrementalMerkleTree, because three properties of that
// class are incompatible with the rollup design:
//
//   1. Its hash() has SHA-256 hardcoded, with no injection point.
//   2. Its empty_hashes_[0] is uint256{} (all zeros); Poseidon needs
//      empty_hashes_[0] = Poseidon(0, 0), a non-zero field element.
//   3. update_leaf() is absent entirely — ZkDeposit and ZkWithdraw never
//      need it, because they treat notes as single-spend.
//
// The frontier-array layout, cached_nodes_ map and O(log n) append cost are
// taken from IncrementalMerkleTree as a design reference; that class itself
// is not touched.

#ifndef RIPPLE_ZKP_ROLLUP_ROLLUP_MERKLE_TREE_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ROLLUP_MERKLE_TREE_H_INCLUDED

#include <xrpl/basics/base_uint.h>  // ripple::uint256

#include <cstddef>
#include <map>
#include <mutex>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {

/// Default Merkle depth.  Matches PoseidonCircuit's compile-time depth
/// and the treeDepth field stored in the on-chain RollupState SLE.
/// A tree of depth d holds up to 2^d leaves.
constexpr std::size_t kDefaultRollupTreeDepth = 16;

/// MerkleWitness — the data the prover hands to PoseidonCircuit.
///
/// `auth_path[i]` is the sibling hash at level `i` (level 0 = leaf level).
/// `position` is the leaf index, whose binary representation tells the
/// circuit at each level whether the witnessed node is the left or right child.
struct MerkleWitness
{
    uint256 leaf{};
    std::vector<uint256> auth_path{};
    std::size_t position{0};
    uint256 root{};
};

/// RollupMerkleTree.
///
/// Provides:
///   - append(leaf): O(log n), frontier-style, bit-exact with the IMT design
///     reference but using Poseidon as the inner hash function.
///   - update_leaf(index, new_cm): O(log n), recomputes the path from `index`
///     up to the root using cached siblings.  Absent from IncrementalMerkleTree.
///   - authPath(position): the `depth` Poseidon sibling hashes a circuit needs.
///   - verify(...): convenience static-style verifier that walks an auth path.
///
/// Thread safety: append() and update_leaf() take an internal mutex so the
/// sequencer can validate entries from multiple worker threads
/// against a shared canonical tree.  Pure read methods (root, authPath, size,
/// depth) are also lock-protected because they share the same internal maps.
class RollupMerkleTree
{
public:
    /// Construct an empty tree of the given depth.  Depth must be in [1, 64];
    /// kDefaultRollupTreeDepth is the production value.
    explicit RollupMerkleTree(std::size_t depth = kDefaultRollupTreeDepth);

    // core interface

    /// Append a new leaf.  Returns the leaf's position (0-indexed).
    /// Throws std::overflow_error if the tree is full.
    std::size_t
    append(uint256 const& leaf);

    /// Update an existing leaf in place.  Recomputes the Poseidon path from
    /// `index` up to the root.
    ///
    /// `index` must be < size(), i.e. the leaf must already have been
    /// appended.  Throws std::out_of_range otherwise.
    void
    update_leaf(std::size_t index, uint256 const& new_commitment);

    /// Current Merkle root (Poseidon hash all the way up).
    uint256
    root() const;

    /// Authentication path for the leaf at `position`.  Length == depth().
    /// `position` must be < size(); throws std::out_of_range otherwise.
    std::vector<uint256>
    authPath(std::size_t position) const;

    /// Static verifier — walks `auth_path` from `leaf` up to a root, using
    /// `position`'s bits to decide left/right at each level.  Returns true
    /// iff the resulting root equals `expected_root`.
    static bool
    verify(
        uint256 const& leaf,
        std::vector<uint256> const& auth_path,
        std::size_t position,
        uint256 const& expected_root);

    // introspection

    std::size_t
    depth() const noexcept
    {
        return depth_;
    }

    /// Number of leaves currently stored (== next append position).
    std::size_t
    size() const;

    /// Maximum leaves storable at this depth (= 2^depth).
    std::size_t
    capacity() const noexcept
    {
        return capacity_;
    }

    /// Read-only access to the empty-subtree hash at `level`.  Useful for
    /// tests that want to assert empty_hashes_[0] == Poseidon(0, 0).
    uint256
    emptyHash(std::size_t level) const;

    /// Convenience: bundle leaf + path + position + root into a single
    /// witness struct ready to feed into PoseidonCircuit.
    MerkleWitness
    getWitness(std::size_t position) const;

    /// Reset the tree to its empty state.  After clear(), root() ==
    /// emptyHash(depth) and size() == 0.  Used by tests and by the sequencer
    /// when it needs a fresh dry-run copy.
    void
    clear();

    // Frontier serialisation
    //
    // Round-trip the tree's mutable state to a compact byte blob suitable
    // for storage in the RollupState SLE. The serialised form contains
    // exactly the data needed to reconstruct correct roots and auth paths
    // for all subsequent append() and update_leaf() calls.
    //
    // Wire format (little-endian):
    //   8 bytes  : next_position_
    //   For each level L in [0, depth_]:
    //     1 byte   : presence flag (1 if a frontier node exists at L, 0 otherwise)
    //     if present:
    //       8 bytes  : position within level
    //       32 bytes : node hash
    //
    // Total max size: 8 + (depth_+1) * (1 + 8 + 32) = 8 + 33*41 = 1361 bytes
    // in the worst case at depth 32. Well within STI_VL limits.

    std::vector<std::uint8_t> serialiseFrontier() const;
    void deserialiseFrontier(std::vector<std::uint8_t> const& blob);

private:
    // internal hash
    //
    // Internal h(L, R) = Poseidon(L, R), exactly the function PoseidonCircuit
    // uses for Merkle membership.  Off-loaded to PoseidonHash so that there is
    // a single source of truth for Poseidon semantics across off-circuit and
    // in-circuit code.
    static uint256
    h(uint256 const& left, uint256 const& right);

    // node access
    //
    // cached_nodes_[level][position] stores any node we have ever committed
    // to.  A missing entry means "this subtree is empty at this level" and
    // resolves to empty_hashes_[level].  This mirrors the IMT design but
    // with Poseidon-based empty hashes.
    uint256
    getNode(std::size_t level, std::size_t position) const;

    void
    setNode(std::size_t level, std::size_t position, uint256 const& value);

    // bootstrap & path recomputation

    /// Populate empty_hashes_[0..depth_] with
    ///   empty_hashes_[0]   = Poseidon(0, 0)
    ///   empty_hashes_[k+1] = Poseidon(empty_hashes_[k], empty_hashes_[k])
    void
    initializeEmptyHashes();

    /// Recompute and cache every ancestor of leaf `index`, propagating up to
    /// the root.  Used by both append() and update_leaf().  Returns the new
    /// root.  Caller must hold the mutex.
    uint256
    recomputePathFromLeaf(std::size_t index);

    // members

    std::size_t const depth_;
    std::size_t const capacity_;       // == 1 << depth_
    std::size_t       next_position_;  // # leaves appended so far

    /// empty_hashes_[k] is the Poseidon hash of an entirely-empty subtree of
    /// height k.  empty_hashes_[depth_] is the root of an empty tree.
    std::vector<uint256> empty_hashes_;

    /// cached_nodes_[level][position] -> node value.  Sparse: only entries
    /// that have been written are present.  Reads of missing entries return
    /// empty_hashes_[level].
    std::vector<std::map<std::size_t, uint256>> cached_nodes_;

    /// Mutex guarding next_position_ and cached_nodes_.  mutable because
    /// const reads (root(), authPath(), getNode()) need to lock too.
    mutable std::mutex mutex_;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ROLLUP_MERKLE_TREE_H_INCLUDED