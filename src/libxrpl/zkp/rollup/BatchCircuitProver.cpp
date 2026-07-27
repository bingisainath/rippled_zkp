// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// BatchCircuitProver implementation. Mirrors RollupProver's key handling
// (load-or-generate with a constraint-count staleness check) for the
// Phase 6 BatchCircuit.

#include "BatchCircuitProver.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace ripple {
namespace zkp {
namespace rollup {

std::shared_ptr<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>
    BatchCircuitProver::proving_key_;
std::shared_ptr<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>
    BatchCircuitProver::verification_key_;
std::shared_ptr<BatchCircuit> BatchCircuitProver::circuit_;
std::size_t BatchCircuitProver::batch_size_ = 8;
std::size_t BatchCircuitProver::tree_depth_ = 16;
bool BatchCircuitProver::initialised_ = false;

// A single BN254 Groth16 proof is ~137 bytes; 256 is a generous ceiling
// that still rejects any oversized blob before it reaches the deserializer.
constexpr std::size_t kMaxProofBytes = 256;

std::string const&
BatchCircuitProver::defaultKeyPath()
{
    // Distinct from RollupProver's /tmp/rippled_rollup_keys on purpose.
    static std::string const p = "/tmp/rippled_rollup_batch_keys";
    return p;
}

void
BatchCircuitProver::initializeVerifierOnly(std::string const& key_path)
{
    if (initialised_)
        return;

    DefaultCurve::init_public_params();
    PoseidonHash::initialize();
    BabyJubjub::initialize();

    std::ifstream vk_file(key_path + "_vk", std::ios::binary);
    if (!vk_file.good())
        throw std::runtime_error(
            "BatchCircuitProver::initializeVerifierOnly: no verification "
            "key at " +
            key_path +
            "_vk (run the prover tool once first to generate keys)");

    verification_key_ = std::make_shared<
        libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>();
    vk_file >> *verification_key_;

    std::cout << "[BatchCircuitProver] Loaded verification key ONLY from "
              << key_path
              << " (this node verifies batches; it never builds them, so "
                 "it never needs the large proving key)"
              << std::endl;
    initialised_ = true;
}

void
BatchCircuitProver::initialize(
    std::string const& key_path,
    std::size_t batch_size,
    std::size_t tree_depth)
{
    if (initialised_)
        return;

    DefaultCurve::init_public_params();
    PoseidonHash::initialize();
    BabyJubjub::initialize();

    batch_size_ = batch_size;
    tree_depth_ = tree_depth;
    circuit_ = std::make_shared<BatchCircuit>(batch_size_, tree_depth_);
    circuit_->generateConstraints();

    if (!loadKeys(key_path))
    {
        std::cout << "[BatchCircuitProver] No cached keys at " << key_path
                  << "; running r1cs_gg_ppzksnark_generator() over "
                  << circuit_->constraintCount()
                  << " constraints (one-time setup, several minutes at "
                     "production size)."
                  << std::endl;
        generateKeys(key_path, batch_size_, tree_depth_);
        saveKeys(key_path);
        std::cout << "[BatchCircuitProver] Generated Groth16 keys at "
                  << key_path << " ("
                  << proving_key_->constraint_system.num_constraints()
                  << " constraints)" << std::endl;
    }
    else
    {
        std::cout << "[BatchCircuitProver] Loaded Groth16 keys from "
                  << key_path << " ("
                  << proving_key_->constraint_system.num_constraints()
                  << " constraints)" << std::endl;
    }
    initialised_ = true;
}

void
BatchCircuitProver::generateKeys(
    std::string const& key_path,
    std::size_t batch_size,
    std::size_t tree_depth)
{
    DefaultCurve::init_public_params();
    PoseidonHash::initialize();
    BabyJubjub::initialize();

    if (!circuit_ || circuit_->batchSize() != batch_size ||
        circuit_->treeDepth() != tree_depth)
    {
        circuit_ = std::make_shared<BatchCircuit>(batch_size, tree_depth);
        circuit_->generateConstraints();
    }

    auto cs = circuit_->getConstraintSystem();
    auto kp = libsnark::r1cs_gg_ppzksnark_generator<DefaultCurve>(cs);

    proving_key_ = std::make_shared<
        libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>(
        std::move(kp.pk));
    verification_key_ = std::make_shared<
        libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>(
        std::move(kp.vk));
}

bool
BatchCircuitProver::loadKeys(std::string const& key_path)
{
    std::ifstream pk_file(key_path + "_pk", std::ios::binary);
    std::ifstream vk_file(key_path + "_vk", std::ios::binary);
    if (!pk_file.good() || !vk_file.good())
        return false;

    try
    {
        proving_key_ = std::make_shared<
            libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>();
        verification_key_ = std::make_shared<
            libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>();
        pk_file >> *proving_key_;
        vk_file >> *verification_key_;

        if (!circuit_)
        {
            circuit_ =
                std::make_shared<BatchCircuit>(batch_size_, tree_depth_);
            circuit_->generateConstraints();
        }
        if (proving_key_->constraint_system.num_constraints() !=
            circuit_->constraintCount())
        {
            std::cerr << "[BatchCircuitProver] Cached keys at " << key_path
                      << " are STALE (constraint count "
                      << proving_key_->constraint_system.num_constraints()
                      << " != " << circuit_->constraintCount()
                      << "); regenerating." << std::endl;
            proving_key_.reset();
            verification_key_.reset();
            return false;
        }
        return true;
    }
    catch (std::exception const& e)
    {
        std::cerr << "[BatchCircuitProver] Failed to load keys: " << e.what()
                  << std::endl;
        proving_key_.reset();
        verification_key_.reset();
        return false;
    }
}

void
BatchCircuitProver::saveKeys(std::string const& key_path)
{
    if (!proving_key_ || !verification_key_)
        throw std::logic_error("BatchCircuitProver::saveKeys: no keys held");

    std::ofstream pk_file(key_path + "_pk", std::ios::binary);
    std::ofstream vk_file(key_path + "_vk", std::ios::binary);
    pk_file << *proving_key_;
    vk_file << *verification_key_;
}

BatchProofData
BatchCircuitProver::createBatchProof(
    FieldT const& prev_root,
    std::vector<BatchEntryWitness> const& entries)
{
    BatchProofData out;
    if (!initialised_)
    {
        std::cerr << "[BatchCircuitProver] createBatchProof: not initialised"
                  << std::endl;
        return out;
    }

    try
    {
        // Fresh circuit per witness (protoboard is single-shot).
        BatchCircuit local(batch_size_, tree_depth_);
        local.generateConstraints();
        local.generateWitness(prev_root, entries);

        if (!local.isSatisfied())
        {
            std::cerr << "[BatchCircuitProver] witness does not satisfy the "
                         "constraint system — refusing to prove"
                      << std::endl;
            return out;
        }

        auto proof = libsnark::r1cs_gg_ppzksnark_prover<DefaultCurve>(
            *proving_key_, local.getPrimaryInput(),
            local.getAuxiliaryInput());

        out.proof_bytes = serializeProof(proof);
        out.prev_root = prev_root;
        out.new_root = local.computedNewRoot();
        out.entries_hash = local.computedEntriesHash();
        return out;
    }
    catch (std::exception const& e)
    {
        std::cerr << "[BatchCircuitProver] createBatchProof failed: "
                  << e.what() << std::endl;
        return BatchProofData{};
    }
}

bool
BatchCircuitProver::verifyBatchProof(BatchProofData const& pd)
{
    return verifyBatch(
        pd.prev_root, pd.new_root, pd.entries_hash, pd.proof_bytes);
}

bool
BatchCircuitProver::verifyBatch(
    FieldT const& prev_root,
    FieldT const& new_root,
    FieldT const& entries_hash,
    std::vector<unsigned char> const& proof_bytes)
{
    if (!initialised_ || !verification_key_)
        return false;
    if (proof_bytes.empty())
        return false;

    // Defence-in-depth against malformed-proof denial of service. A
    // Groth16 proof for this curve serializes to a small, fixed length
    // (~137 B: A||B||C over BN254). libff recovers compressed points by
    // square root on read, and an Fp2 sqrt over a non-curve coordinate can
    // loop pathologically — so we bound the input length before touching
    // the deserializer. This catches truncated / oversized blobs cheaply.
    // NOTE (BatchVerifier2 hardening): a SAME-LENGTH corruption of the G2
    // element can still hit the slow sqrt path; fully closing that needs
    // uncompressed point serialization or a bounded-iteration sqrt in the
    // vendored libff. Documented limitation shared with Track 1.
    if (proof_bytes.size() > kMaxProofBytes)
        return false;

    try
    {
        auto const proof = deserializeProof(proof_bytes);

        libsnark::r1cs_primary_input<FieldT> primary;
        primary.push_back(prev_root);
        primary.push_back(new_root);
        primary.push_back(entries_hash);

        return libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<DefaultCurve>(
            *verification_key_, primary, proof);
    }
    catch (std::exception const& e)
    {
        std::cerr << "[BatchCircuitProver] verifyBatch failed: " << e.what()
                  << std::endl;
        return false;
    }
}

bool
BatchCircuitProver::isInitialized()
{
    return initialised_;
}

std::size_t
BatchCircuitProver::constraintCount()
{
    return circuit_ ? circuit_->constraintCount() : 0;
}

std::size_t
BatchCircuitProver::batchSize()
{
    return batch_size_;
}

std::size_t
BatchCircuitProver::treeDepth()
{
    return tree_depth_;
}

std::vector<unsigned char>
BatchCircuitProver::serializeProof(
    libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve> const& p)
{
    std::stringstream ss(std::ios::binary | std::ios::out);
    ss << p;
    auto str = ss.str();
    return std::vector<unsigned char>(str.begin(), str.end());
}

libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve>
BatchCircuitProver::deserializeProof(std::vector<unsigned char> const& bytes)
{
    std::stringstream ss(
        std::string(bytes.begin(), bytes.end()),
        std::ios::binary | std::ios::in);
    libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve> p;
    ss >> p;
    return p;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
