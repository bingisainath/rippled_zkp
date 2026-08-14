// BatchCircuit (Track 2): one Groth16 proof attests to a whole batch of N
// account-state transitions, so L1 verifies a single proof regardless of N.
//
// Public inputs (3):
//   prev_root     account-tree Poseidon root before the batch
//   new_root      root after all N entries
//   entries_hash  Poseidon chain eh_{i+1} = Poseidon(eh_i, msg_i). preclaim
//                 recomputes it natively from the published entries, binding
//                 that data to the proven statement.
//
// Per entry, over witnessed SignedRequest fields, signature, old balance and
// auth path: the type is one of {Deposit, Withdraw, Transfer, NoOp}; msg is
// built to the AccountLeaf.h specification; EdDSAGadget proves the owner
// signed it; the old leaf is proven a member of r_i and the new leaf hashes
// back up the same siblings; 64-bit range checks keep the packings canonical
// and catch overdraft and overflow.
//
// Range-checking old_bal and nonce is NOT redundant: without it a prover
// could supply the alias (old_bal + 2^64*k, nonce - k) — the same packed
// leaf — and smuggle 2^64*k extra drops through the balance arithmetic.
//
// Transfer adds a recipient leg: a second path carries the recipient leaf
// from an intermediate root up to r_{i+1}, and is_xfer*(to_x - dest) = 0
// binds the credited leaf to the signed destination, so a sequencer cannot
// redirect a transfer. For every other type is_xfer = 0 collapses the leg
// onto the sender's own updated leaf, so no second tree walk is witnessed
// and a NoOp against an empty pad slot stays satisfiable. Transferring to a
// leaf that does not exist is impossible by construction: an empty slot
// holds 0, while to_old_leaf is a Poseidon output.
//
// NoOp padding: the sequencer signs a NoOp against an empty slot with a
// throwaway key and the new-leaf mux leaves the slot empty, so r_{i+1} = r_i
// and any batch can be padded to N.
//
// Known prototype caveats:
//   - A malicious sequencer could apply a user's first request (nonce 0,
//     is_create) at two empty slots, creating duplicate leaves for one key.
//     Deposits still need matching L1 escrow per application, so this
//     misattributes rather than mints; creation dedup is enforced
//     off-circuit by the transactor.
//   - msg carries no chain or domain tag, so cross-deployment signature
//     replay is out of scope for the prototype.

#ifndef RIPPLE_ZKP_ROLLUP_BATCH_CIRCUIT_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_BATCH_CIRCUIT_H_INCLUDED

#include "AccountLeaf.h"
#include "EdDSAGadget.h"
#include "PoseidonHash.h"

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <memory>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {

// Everything the prover (sequencer) knows about one entry.
struct BatchEntryWitness
{
    SignedRequest req;              // signed by the account owner
    std::uint64_t old_balance = 0;  // leaf balance before this entry
    bool is_create = false;         // true: old slot is EMPTY (0)
    std::vector<bool> leaf_pos;     // depth bits, LSB-first (level 0 first)
    std::vector<FieldT> auth_path;  // sibling per level, 0..depth-1

    // Recipient leg (Transfer only)
    // For every non-Transfer type these are IGNORED: the circuit muxes the
    // recipient leaf to the sender's own post-update leaf, so the sequencer
    // supplies the sender's position and auth path again (identical siblings,
    // since only that one leaf changed) and the leg collapses to a no-op.
    FieldT to_apk_x = FieldT::zero();  // recipient apk_x; must equal req.dest
    std::uint64_t to_old_balance = 0;  // recipient balance BEFORE the credit
    std::uint64_t to_nonce = 0;        // recipient nonce; NOT incremented
    std::vector<bool> to_leaf_pos;     // recipient position bits
    std::vector<FieldT> to_auth_path;  // siblings AFTER the sender's update
};

class BatchCircuit
{
public:
    BatchCircuit(std::size_t batch_size, std::size_t tree_depth);
    ~BatchCircuit();

    BatchCircuit(BatchCircuit const&) = delete;
    BatchCircuit&
    operator=(BatchCircuit const&) = delete;

    // Build the constraint system. Idempotent.
    void
    generateConstraints();

    // Fill the witness for a full batch. entries.size() must equal
    // batchSize(); each entry's leaf_pos/auth_path must have treeDepth()
    // elements. Throws std::invalid_argument / std::logic_error on
    // structurally invalid input (an unsatisfiable-but-well-formed witness
    // is NOT detected here — the proof simply won't verify).
    void
    generateWitness(
        FieldT const& prev_root,
        std::vector<BatchEntryWitness> const& entries);

    // Public inputs as computed by the last generateWitness().
    FieldT
    computedNewRoot() const;
    FieldT
    computedEntriesHash() const;

    // Native mirror of the in-circuit entries-hash chain. Used by the
    // sequencer (blob build) and by preclaim (blob check) — must match the
    // circuit bit-for-bit.
    static FieldT
    computeEntriesHash(std::vector<SignedRequest> const& reqs);

    // libsnark plumbing (same surface as PoseidonCircuit).
    libsnark::r1cs_constraint_system<FieldT>
    getConstraintSystem() const;
    libsnark::r1cs_primary_input<FieldT>
    getPrimaryInput() const;
    libsnark::r1cs_auxiliary_input<FieldT>
    getAuxiliaryInput() const;

    bool
    isSatisfied() const;  // pb.is_satisfied() — test convenience

    std::size_t
    constraintCount() const;
    std::size_t
    batchSize() const;
    std::size_t
    treeDepth() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_BATCH_CIRCUIT_H_INCLUDED
