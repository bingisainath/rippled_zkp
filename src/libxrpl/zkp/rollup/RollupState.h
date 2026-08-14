/*
    This file is part of rippled_zkp: ZK-Rollup extension for XRPL.

    RollupState: Track 1's rollup state SLE, including tree-frontier
    persistence.
*/

#ifndef RIPPLE_ZKP_ROLLUP_ROLLUPSTATE_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ROLLUPSTATE_H_INCLUDED

#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace ripple {

class ApplyView;
class ReadView;

namespace zkp {
namespace rollup {

class RollupMerkleTree;

// Depth reduction, 32 -> 16: 2^16 = 65536 leaf slots is ample for the
// prototype, which uses 8 fixed genesis slots. Halving the depth halves the
// in-circuit Merkle path length, cutting proving time further. All depth
// literals (kDefaultRollupTreeDepth, the RollupProver defaults) and the circuit
// must agree; the genesis root (kGenesisRollupRoot) recomputes from this value.
constexpr std::uint8_t  kRollupTreeDepth = 16;
constexpr std::size_t   kRollupBatchSize  = 8;

// Root of the empty Poseidon Merkle tree pre-loaded with 8 genesis null-notes
// (createRandom(0, seed) for seed=0..7). This is the prevRoot the sequencer
// must use for the first batch, and the value preclaim checks when no
// RollupState SLE exists yet.
uint256 const&
kGenesisRollupRoot();

class RollupState
{
public:
    static std::uint32_t batchCounter(STLedgerEntry const& sle);
    static uint256       rollupRoot  (STLedgerEntry const& sle);
    static std::uint8_t  treeDepth   (STLedgerEntry const& sle);

    static void setBatchCounter(STLedgerEntry& sle, std::uint32_t v);
    static void setRollupRoot  (STLedgerEntry& sle, uint256 const& r);

    static std::shared_ptr<STLedgerEntry const>
    read(ReadView const& view);

    static std::shared_ptr<STLedgerEntry>
    peek(ApplyView& view);

    static std::shared_ptr<STLedgerEntry>
    createGenesis(ApplyView& view,
                  std::vector<std::uint8_t> const& sequencerPubKey);

    // Tree-frontier persistence.
    // RollupMerkleTree has a std::mutex (non-movable, non-copyable), so we
    // must return it by unique_ptr rather than by value.
    static std::unique_ptr<RollupMerkleTree>
    loadTree(STLedgerEntry const& sle);

    static void
    storeTree(STLedgerEntry& sle, RollupMerkleTree const& tree);
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif