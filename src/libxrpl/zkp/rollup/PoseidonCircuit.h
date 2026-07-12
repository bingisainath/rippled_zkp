// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// PoseidonCircuit: the per-note R1CS proving circuit for Phase 2.
//
// Public inputs (primary):
//   - anchor      : prevRoot of the Merkle tree
//   - new_anchor  : root after this leaf has been updated
//   - nullifier   : nf = Poseidon(ask, rho)
//   - value_pub   : the deposited / withdrawn amount (unhidden in the rollup
//                   prototype — the dissertation's threat model is integrity,
//                   not privacy; per v2.2 §1.3, privacy is out of scope for
//                   the rollup, in scope only for the existing ZkDeposit pool).
//   - is_withdraw : value-conservation flag. 1 => spend (value == value_pub
//                   enforced: cannot withdraw more than the spent note holds);
//                   0 => deposit (value minted from an escrowed L1 deposit).
//                   Set by the on-chain verifier from the entry's txType.
//
// Private inputs (auxiliary):
//   - value (matches value_pub via constraint)
//   - rho, r
//   - ask (BJJ scalar) as 254-bit decomposition
//   - apk_x, apk_y (computed by the in-circuit BJJ scalar mul)
//   - leaf position bits (for auth path direction)
//   - auth path siblings × tree_depth
//   - new_leaf commitment (same value, new rho/r — supplied by the witness)
//
// Constraints proved (per research doc §2.3 sub-phase 2c):
//   1. apk = [ask] · G_J                 — BabyJubjubMulGadget
//   2. cm  = Poseidon(value, rho, r, apk_x)  — three PoseidonGadgets
//   3. nf  = Poseidon(ask, rho)          — one PoseidonGadget
//   4. cm  is at position `leaf_pos` in the Merkle tree rooted at `anchor`
//      via Poseidon auth path                 — tree_depth PoseidonGadgets
//   5. cm' (new commitment for same account) sits at the same `leaf_pos` and
//      hashes up to `new_anchor` via the same auth path
//                                            — another tree_depth PoseidonGadgets
//
// Constraint budget at depth=32 (single note slot):
//   1×BJJ_mul (~5300) + 4×Poseidon (~972) + 32×Poseidon (~7776) ×2 paths
//   ≈ 5300 + 972 + 15552 ≈ 21800   <-- single-note worst case
// At N=1 the test target is therefore ~9–22K depending on whether we
// include both prevRoot and newRoot path checks. The doc cites ~9.2K for
// the prevRoot-only single-note circuit; we include both paths for full
// rollup soundness (per v2.2 §13.1 entry 5 "correct leaf update to newRoot").

#ifndef RIPPLE_ZKP_ROLLUP_POSEIDON_CIRCUIT_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_POSEIDON_CIRCUIT_H_INCLUDED

#include "BabyJubjubGadget.h"
#include "PoseidonGadget.h"
#include "PoseidonHash.h"
#include "RollupNote.h"

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <memory>

namespace ripple {
namespace zkp {
namespace rollup {

class PoseidonCircuit
{
public:
    explicit PoseidonCircuit(std::size_t tree_depth);
    ~PoseidonCircuit();

    PoseidonCircuit(PoseidonCircuit const&) = delete;
    PoseidonCircuit&
    operator=(PoseidonCircuit const&) = delete;

    // Build the constraint system. Idempotent — a second call is a no-op.
    void
    generateConstraints();

    // Witness generation for a single-note state transition.
    //   old_note  : the spent note (anchored in prevRoot)
    //   new_note  : the freshly committed note (anchored in newRoot at same leaf pos)
    //   leaf_pos  : binary path from leaf to root, LSB = bottom-of-tree direction
    //   auth_path_old : sibling hashes for old_note's commitment, level 0..depth-1
    //   auth_path_new : sibling hashes for new_note's commitment (typically equal to
    //                   auth_path_old in this prototype since we update one leaf
    //                   at a time)
    //   prev_root, new_root : externally computed roots (off-circuit Poseidon)
    void
    generateWitness(
        RollupNote const& old_note,
        RollupNote const& new_note,
        std::vector<bool> const& leaf_pos,
        std::vector<FieldT> const& auth_path_old,
        std::vector<FieldT> const& auth_path_new,
        FieldT const& prev_root,
        FieldT const& new_root,
        bool is_withdraw = false);

    // Returns the Poseidon-canonical empty root for a tree of `depth`. This
    // is the value that Phase 4a will substitute for `kGenesisRollupRoot()`
    // in `RollupState.h` (per the Phase 1 closeout, §9.2).
    static FieldT
    empty_tree_root(std::size_t depth);

    // libsnark plumbing.
    libsnark::r1cs_constraint_system<FieldT>
    getConstraintSystem() const;
    libsnark::r1cs_primary_input<FieldT>
    getPrimaryInput() const;
    libsnark::r1cs_auxiliary_input<FieldT>
    getAuxiliaryInput() const;

    std::size_t
    constraintCount() const;

    std::size_t
    treeDepth() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_POSEIDON_CIRCUIT_H_INCLUDED
