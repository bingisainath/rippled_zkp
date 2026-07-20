// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// BatchCircuit: the Phase 6 (Option A / Track 2) monolithic batch circuit.
// ONE Groth16 proof attests to a whole batch of N account-state transitions,
// so L1 verifies a single proof regardless of N — O(1) verification, versus
// Track 1's N per-entry proofs.
//
// ============================== Statement ==============================
// Public inputs (exactly 3):
//   prev_root    : account-tree Poseidon root before the batch (= r_0)
//   new_root     : root after all N entries applied            (= r_N)
//   entries_hash : Poseidon chain over the N request messages:
//                    eh_0 = 0 ; eh_{i+1} = Poseidon(eh_i, msg_i)
//                  where msg_i is the SignedRequest message (AccountLeaf.h).
//                  preclaim recomputes this natively from the blob entries,
//                  binding the published entry data to the proven statement.
//
// Per entry i (witness: SignedRequest fields, sig, old balance, auth path):
//   1. type ∈ {Deposit, Withdraw, Transfer, NoOp}
//      bits (t1,t0): Deposit=00, Withdraw=01, Transfer=10, NoOp=11.
//      is_xfer = t1*(1-t0) = t1 - w selects the Transfer case.
//   2. meta = value + 2^64·nonce + 2^128·type          (linear)
//      msg  = Poseidon(Poseidon(from_x, dest), meta)   (= AccountLeaf.h spec)
//   3. from_apk on-curve  AND  EdDSAGadget(from_apk, R, s, msg) verifies.
//      => the sequencer can only include transitions the owner signed.
//   4. old_leaf = Poseidon(from_x, old_bal + 2^64·nonce), or 0 if is_create
//      (is_create forces old_bal = 0 and nonce = 0).
//      old_leaf is a member of r_i at leaf_pos (16-level Poseidon path).
//   5. new_bal = old_bal + value (Deposit) | old_bal − value (Withdraw/Transfer)
//      64-bit range checks on value, nonce, old_bal, new_bal make the
//      packings canonical and catch overdraft/overflow. (Range-checking
//      old_bal/nonce is NOT redundant: without it a prover could supply
//      the alias old_bal + 2^64·k, nonce − k — same packed leaf value —
//      and smuggle 2^64·k extra drops through the balance arithmetic.)
//   6. new_leaf = Poseidon(from_x, new_bal + 2^64·(nonce+1)); a NoOp
//      instead re-uses old_leaf unchanged (nonce not consumed).
//   7. The SAME path siblings hash new_leaf up to an intermediate root mid_i.
//   8. RECIPIENT leg (Transfer only). A second 16-level path carries the
//      recipient leaf from mid_i up to r_{i+1}:
//        to_old_leaf = Poseidon(to_x, to_old_bal + 2^64·to_nonce)
//        to_new_bal  = to_old_bal + is_xfer·value
//        to_new_leaf = Poseidon(to_x, to_new_bal + 2^64·to_nonce)
//      The recipient's nonce is NOT consumed — they did not sign.
//      is_xfer·(to_x − dest) = 0 binds the credited leaf to the signed dest,
//      so a sequencer cannot redirect a transfer to itself.
//
//      For every NON-Transfer type is_xfer = 0, hence to_new_bal = to_old_bal
//      and the two recipient paths are identical, forcing r_{i+1} = mid_i.
//      The recipient leaf is then muxed to the sender's own post-update leaf
//      (to_base = new_base) so the witness needs no second tree walk and the
//      leg is satisfiable even for a NoOp against an EMPTY pad slot, where
//      new_base = 0 is not a Poseidon image of anything.
//
//      A Transfer to a leaf that does not yet exist is impossible by
//      construction: an empty slot holds 0, while to_old_leaf is a Poseidon
//      output, so the inclusion check cannot pass. Recipients must already
//      exist; the sequencer rejects such requests at admission.
//   9. eh_{i+1} = Poseidon(eh_i, msg_i).
//
// Chain glue: r_0 == prev_root, r_N == new_root, eh_N == entries_hash.
//
// NoOp padding: the sequencer signs the NoOp message with its own throwaway
// key against an EMPTY slot (is_create=1, value=0); the new-leaf mux keeps
// the slot empty, so r_{i+1} = r_i. Any batch can thus be padded to N.
//
// Known prototype caveats (documented for the dissertation):
//   - A malicious sequencer could apply a user's FIRST request (nonce 0,
//     is_create) twice at two different empty slots, creating duplicate
//     leaves for one apk. For Deposits this requires matching L1 escrow
//     funds per application (checked in doApply), so it is not a mint;
//     dedup of creations is enforced off-circuit by the transactor.
//   - msg carries no chain/domain tag; cross-deployment sig replay is out
//     of scope for the prototype.
//
// Constraint budget (measured by BatchCircuit_test; estimate per entry):
//   EdDSAGadget ~14.5K + 37 Poseidon (~9K) + ranges (~0.3K) + glue
//   ≈ 24K per entry  →  ≈ 192K for N=8 at depth 16.
// Phase 7 adds the recipient leg: 2 leaf hashes + 2*depth path hashes
// (34 more Poseidon, ~8.3K) + 3 range gadgets, so ≈ 32K per entry.
// The measured total is printed by BatchCircuit_test — use that, not this.

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

    // ---- Recipient leg (Transfer only) --------------------------------
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
