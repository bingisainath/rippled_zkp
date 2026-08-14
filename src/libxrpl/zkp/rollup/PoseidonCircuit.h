// PoseidonCircuit: the per-note R1CS proving circuit used by Track 1.
//
// Public inputs, in allocation order (5):
//   anchor       Merkle root before this leaf is updated
//   new_cm       the new note commitment. NOT the post-update root: the new
//                root is enforced off-circuit by doApply's deterministic
//                replay, which ties this commitment to the batch's newRoot.
//   nullifier    nf = Poseidon(ask, rho)
//   value_pub    the deposited or withdrawn amount. Unhidden: the threat
//                model for the rollup is integrity, not confidentiality.
//   is_withdraw  value-conservation flag, set by the on-chain verifier from
//                the entry's txType. 1 => spend, with value == value_pub
//                enforced so a note cannot be over-withdrawn; 0 => deposit,
//                minted against escrowed L1 funds.
//
// Private inputs: value, rho, r, the spending key ask as a 254-bit
// decomposition, apk_x/apk_y from the in-circuit scalar multiplication, the
// leaf position bits, and the auth-path siblings.
//
// Constraints proved:
//   1. apk = [ask]*G_J
//   2. cm  = Poseidon(value, rho, r, apk_x)
//   3. nf  = Poseidon(ask, rho)
//   4. cm is at leaf_pos in the tree rooted at anchor, via a Poseidon path
//   5. new_cm is well formed for the same account, which binds value_pub
//
// The circuit walks ONE Merkle path, not two. An earlier revision proved a
// second path up to the post-update root; moving that binding to doApply's
// replay halves the Poseidon path work at no on-chain cost.

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
    // is the value substituted for `kGenesisRollupRoot()` in
    // `RollupState.h`.
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
