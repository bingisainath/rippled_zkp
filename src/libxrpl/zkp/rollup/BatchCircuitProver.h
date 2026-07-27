// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// BatchCircuitProver: Groth16 setup / prove / verify for the Phase 6
// BatchCircuit (Track 2). One proof per batch of N account transitions.
//
// Key discipline (v2.2 §13.1, same rule as RollupProver vs ZkProver):
// this class owns its OWN key pair at its OWN path — never share keys
// with RollupProver (different circuit) or ZkProver (different hash).
// Default path: /tmp/rippled_rollup_batch_keys_{pk,vk}.
//
// The proof statement has exactly 3 public inputs:
//   (prev_root, new_root, entries_hash)  — see BatchCircuit.h.

#ifndef RIPPLE_ZKP_ROLLUP_BATCH_CIRCUIT_PROVER_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_BATCH_CIRCUIT_PROVER_H_INCLUDED

#include "BatchCircuit.h"

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <memory>
#include <string>
#include <vector>

namespace ripple {
namespace zkp {
namespace rollup {

struct BatchProofData
{
    std::vector<unsigned char> proof_bytes;  // serialized Groth16 (~137 B)
    FieldT prev_root;
    FieldT new_root;
    FieldT entries_hash;

    bool
    empty() const
    {
        return proof_bytes.empty();
    }
};

class BatchCircuitProver
{
public:
    static std::string const&
    defaultKeyPath();

    // Load keys from disk or generate-and-save on first run. Idempotent.
    // Production shape: batch_size=8, tree_depth=16 (keygen is a one-time
    // multi-minute operation at ~250K constraints).
    static void
    initialize(
        std::string const& key_path = defaultKeyPath(),
        std::size_t batch_size = 8,
        std::size_t tree_depth = 16);

    // Load ONLY the verification key — for a node that verifies batches but
    // never builds them (i.e. rippled itself; proving happens in a separate
    // sequencer/tool process — see gen_batch_blob2). The proving key is the
    // large one (hundreds of thousands of curve points; ~65-70s to
    // deserialise); verifyBatch() never touches it, only
    // verification_key_. Skips circuit construction too (also unneeded for
    // verification). Throws if no cached vk exists — the prover process
    // must have generated keys at least once already.
    static void
    initializeVerifierOnly(std::string const& key_path = defaultKeyPath());

    static void
    generateKeys(
        std::string const& key_path,
        std::size_t batch_size,
        std::size_t tree_depth);

    static bool
    loadKeys(std::string const& key_path);

    static void
    saveKeys(std::string const& key_path);

    // Prove a full batch. entries.size() must equal the initialized
    // batch_size (pad with NoOps first — BatchCircuit.h). On success the
    // returned publics are the circuit-computed (prev_root, new_root,
    // entries_hash). Returns empty() data on failure.
    static BatchProofData
    createBatchProof(
        FieldT const& prev_root,
        std::vector<BatchEntryWitness> const& entries);

    // Verify a serialized batch proof against the three public inputs.
    static bool
    verifyBatchProof(BatchProofData const& pd);

    static bool
    verifyBatch(
        FieldT const& prev_root,
        FieldT const& new_root,
        FieldT const& entries_hash,
        std::vector<unsigned char> const& proof_bytes);

    static bool
    isInitialized();

    static std::size_t
    constraintCount();
    static std::size_t
    batchSize();
    static std::size_t
    treeDepth();

private:
    static std::shared_ptr<
        libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>
        proving_key_;
    static std::shared_ptr<
        libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>
        verification_key_;
    static std::shared_ptr<BatchCircuit> circuit_;
    static std::size_t batch_size_;
    static std::size_t tree_depth_;
    static bool initialised_;

    static std::vector<unsigned char>
    serializeProof(libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve> const& p);
    static libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve>
    deserializeProof(std::vector<unsigned char> const& bytes);
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_BATCH_CIRCUIT_PROVER_H_INCLUDED
