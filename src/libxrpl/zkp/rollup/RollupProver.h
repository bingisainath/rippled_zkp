// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// RollupProver: Groth16 setup / prove / verify for the PoseidonCircuit.
// Per v2.2 §13.1, this MUST keep its own keys, separate from ZkProver's
// SHA-256-bound keys. Default key path: /tmp/rippled_rollup_keys_{pk,vk}.
//
// Phase 4b additions:
//   - verifyEntry(RollupTxEntry, proof_bytes): pack public inputs from a
//     single batch entry and verify the per-entry Poseidon proof on the
//     consensus hot path. The N=8 batch is verified as 8 sequential calls
//     in BatchVerifier::preclaim() (see design Figure 3 / Figure 5).
//   - createEntryProof(...): convenience wrapper that takes the per-entry
//     witness directly. Used by RollupSequencer test harnesses and by the
//     replacement Phase 1 success-path tests.

#ifndef RIPPLE_ZKP_ROLLUP_ROLLUP_PROVER_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ROLLUP_PROVER_H_INCLUDED

#include "PoseidonCircuit.h"
#include "PoseidonHash.h"
#include "RollupNote.h"

#include <libxrpl/zkp/rollup/BatchProof.h>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <memory>
#include <string>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {

struct RollupProofData
{
    std::vector<unsigned char> proof_bytes;  // serialised Groth16 proof (~190B)
    FieldT anchor;
    FieldT new_anchor;
    FieldT nullifier;
    FieldT value_pub;

    bool
    empty() const
    {
        return proof_bytes.empty();
    }
};

class RollupProver
{
public:
    // Default key path. Distinct from ZkProver's path on purpose.
    static std::string const&
    defaultKeyPath();

    // One-shot initialisation: load keys from disk, or generate-and-save if
    // they don't exist yet. Idempotent.
    //
    // IMPORTANT (v2.2 §13.1): never call ZkProver::initialize() in this path.
    // ZkProver loads SHA-256-circuit keys; we load Poseidon-circuit keys.
    static void
    initialize(std::string const& key_path = defaultKeyPath(),
               std::size_t tree_depth = 32);

    // Generate fresh keys for a Poseidon circuit at the given depth and save
    // them. Throws on failure.
    static void
    generateKeys(std::string const& key_path, std::size_t tree_depth);

    // Try to load keys; returns false if files don't exist or are corrupt.
    static bool
    loadKeys(std::string const& key_path);

    // Save the currently-held keys to disk.
    static void
    saveKeys(std::string const& key_path);

    // Generate a Groth16 proof attesting to the (old_note, new_note,
    // auth_path, prev_root, new_root) state transition.
    static RollupProofData
    createProof(
        RollupNote const& old_note,
        RollupNote const& new_note,
        std::vector<bool> const& leaf_pos,
        std::vector<FieldT> const& auth_path_old,
        std::vector<FieldT> const& auth_path_new,
        FieldT const& prev_root,
        FieldT const& new_root);

    // Verify a serialised proof against the four public inputs.
    // Returns true iff the proof is well-formed AND satisfies the verifier.
    static bool
    verifyProof(RollupProofData const& proof_data);

    // ===================================================================
    // Phase 4b: per-entry batch helpers
    // ===================================================================

    // Verify one BatchProof entry. Packs the four FieldT public inputs from
    // the wire-format entry plus the supplied (prevRoot, newRoot) anchors,
    // then calls verifyProof. Returns false if proof bytes are empty, if
    // the keys aren't initialised, or if the Groth16 check fails.
    //
    // Used by BatchVerifier::verifyBatchProof() in the preclaim loop.
    //
    // Phase 4a routed this through ZkProver::verifyProof (the "integration
    // shortcut" disclosed in Phase 4a §5). Phase 4b swaps it for the real
    // PoseidonCircuit-bound verifier — one function call change in
    // BatchVerifier.cpp.
    static bool
    verifyEntry(
        BatchProof const& bp,
        std::size_t entryIndex,
        std::vector<unsigned char> const& entryProof);

    // Convenience: build a per-entry RollupProofData and call verifyProof.
    // Same semantics as verifyEntry but takes the four public inputs
    // directly (e.g. for tests that don't carry a full BatchProof).
    static bool
    verifyEntryPublicInputs(
        FieldT const& prev_root,
        FieldT const& new_root,
        FieldT const& nullifier,
        FieldT const& value_pub,
        std::vector<unsigned char> const& proof_bytes);

    static bool
    isInitialized();

    // Convenience: number of constraints in the cached circuit.
    static std::size_t
    constraintCount();

private:
    static std::shared_ptr<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>
        proving_key_;
    static std::shared_ptr<
        libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>
        verification_key_;
    static std::shared_ptr<PoseidonCircuit> circuit_;
    static std::size_t tree_depth_;
    static bool initialised_;

    static std::vector<unsigned char>
    serializeProof(libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve> const& p);
    static libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve>
    deserializeProof(std::vector<unsigned char> const& bytes);

    // Map a uint256 -> FieldT in the same convention used by
    // PoseidonCircuit's public-input allocation. Falls back to
    // MerkleCircuit::uint256ToFieldElement if available; otherwise
    // implemented in the .cpp using libff::bigint construction.
    static FieldT
    uint256ToField(uint256 const& v);
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ROLLUP_PROVER_H_INCLUDED