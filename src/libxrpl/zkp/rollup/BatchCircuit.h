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
//   1. type ∈ {Deposit, Withdraw, NoOp}   (Transfer reserved, rejected)
//      bits (t1,t0): Deposit=00, Withdraw=01, NoOp=11; t1*(1-t0)=0 bans 10.
//   2. meta = value + 2^64·nonce + 2^128·type          (linear)
//      msg  = Poseidon(Poseidon(from_x, dest), meta)   (= AccountLeaf.h spec)
//   3. from_apk on-curve  AND  EdDSAGadget(from_apk, R, s, msg) verifies.
//      => the sequencer can only include transitions the owner signed.
//   4. old_leaf = Poseidon(from_x, old_bal + 2^64·nonce), or 0 if is_create
//      (is_create forces old_bal = 0 and nonce = 0).
//      old_leaf is a member of r_i at leaf_pos (16-level Poseidon path).
//   5. new_bal = old_bal + value (Deposit) | old_bal − value (Withdraw)
//      64-bit range checks on value, nonce, old_bal, new_bal make the
//      packings canonical and catch overdraft/overflow. (Range-checking
//      old_bal/nonce is NOT redundant: without it a prover could supply
//      the alias old_bal + 2^64·k, nonce − k — same packed leaf value —
//      and smuggle 2^64·k extra drops through the balance arithmetic.)
//   6. new_leaf = Poseidon(from_x, new_bal + 2^64·(nonce+1)); a NoOp
//      instead re-uses old_leaf unchanged (nonce not consumed).
//   7. The SAME path siblings hash new_leaf up to r_{i+1} — sound because
//      entry i changes exactly one leaf between r_i and r_{i+1}.
//   8. eh_{i+1} = Poseidon(eh_i, msg_i).
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
