// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC

#include "RollupProver.h"

#include <libxrpl/zkp/rollup/PoseidonHash.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace ripple {
namespace zkp {
namespace rollup {

std::shared_ptr<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>
    RollupProver::proving_key_;
std::shared_ptr<libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>
    RollupProver::verification_key_;
std::shared_ptr<PoseidonCircuit> RollupProver::circuit_;
std::size_t RollupProver::tree_depth_ = 16;  // Lever #2: was 32
bool RollupProver::initialised_ = false;

std::string const&
RollupProver::defaultKeyPath()
{
    static std::string const p = "/tmp/rippled_rollup_keys";
    return p;
}

void
RollupProver::initializeVerifierOnly(std::string const& key_path)
{
    if (initialised_)
        return;

    DefaultCurve::init_public_params();
    PoseidonHash::initialize();
    BabyJubjub::initialize();

    std::ifstream vk_file(key_path + "_vk", std::ios::binary);
    if (!vk_file.good())
        throw std::runtime_error(
            "RollupProver::initializeVerifierOnly: no verification key at " +
            key_path +
            "_vk (run the prover tool once first to generate keys)");

    verification_key_ = std::make_shared<
        libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>();
    vk_file >> *verification_key_;

    std::cout << "[RollupProver] Loaded verification key ONLY from "
              << key_path
              << " (this node verifies batches; it never builds them, so "
                 "it never needs the large proving key)"
              << std::endl;
    initialised_ = true;
}

void
RollupProver::initialize(std::string const& key_path, std::size_t tree_depth)
{
    if (initialised_)
        return;

    DefaultCurve::init_public_params();
    PoseidonHash::initialize();
    BabyJubjub::initialize();

    tree_depth_ = tree_depth;
    circuit_ = std::make_shared<PoseidonCircuit>(tree_depth_);
    circuit_->generateConstraints();

    if (!loadKeys(key_path))
    {
        std::cout << "[RollupProver] No cached keys at " << key_path
                  << "; running r1cs_gg_ppzksnark_generator() (this is a "
                     "one-time setup, ~30–60s on first build)." << std::endl;
        generateKeys(key_path, tree_depth_);
        saveKeys(key_path);
        std::cout << "[RollupProver] Generated Groth16 keys at " << key_path
                  << " (" << proving_key_->constraint_system.num_constraints()
                  << " constraints)" << std::endl;
    }
    else
    {
        std::cout << "[RollupProver] Loaded Groth16 keys from " << key_path
                  << " (" << proving_key_->constraint_system.num_constraints()
                  << " constraints)" << std::endl;
    }
    initialised_ = true;
}

void
RollupProver::generateKeys(std::string const& key_path, std::size_t tree_depth)
{
    DefaultCurve::init_public_params();
    PoseidonHash::initialize();
    BabyJubjub::initialize();

    if (!circuit_ || circuit_->treeDepth() != tree_depth)
    {
        circuit_ = std::make_shared<PoseidonCircuit>(tree_depth);
        circuit_->generateConstraints();
    }

    auto cs = circuit_->getConstraintSystem();
    auto kp = libsnark::r1cs_gg_ppzksnark_generator<DefaultCurve>(cs);

    proving_key_ =
        std::make_shared<libsnark::r1cs_gg_ppzksnark_proving_key<DefaultCurve>>(
            std::move(kp.pk));
    verification_key_ = std::make_shared<
        libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve>>(
        std::move(kp.vk));
}

bool
RollupProver::loadKeys(std::string const& key_path)
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

        // Sanity: check the cached proving key's constraint count matches
        // the circuit at the configured depth. If it doesn't, the keys are
        // stale (e.g., circuit was changed since they were generated) and
        // we must regenerate.
        if (!circuit_)
        {
            circuit_ = std::make_shared<PoseidonCircuit>(tree_depth_);
            circuit_->generateConstraints();
        }
        auto current_cs = circuit_->getConstraintSystem();
        if (proving_key_->constraint_system.num_constraints() !=
            current_cs.num_constraints())
        {
            std::cerr
                << "[RollupProver] Cached key constraint count ("
                << proving_key_->constraint_system.num_constraints()
                << ") differs from current circuit ("
                << current_cs.num_constraints()
                << "). Regenerating." << std::endl;
            proving_key_.reset();
            verification_key_.reset();
            return false;
        }
        return true;
    }
    catch (std::exception const& e)
    {
        std::cerr << "[RollupProver] loadKeys failed: " << e.what() << std::endl;
        proving_key_.reset();
        verification_key_.reset();
        return false;
    }
}

void
RollupProver::saveKeys(std::string const& key_path)
{
    if (!proving_key_ || !verification_key_)
        throw std::logic_error("RollupProver::saveKeys: keys not loaded");

    {
        std::ofstream pk_file(key_path + "_pk", std::ios::binary);
        pk_file << *proving_key_;
    }
    {
        std::ofstream vk_file(key_path + "_vk", std::ios::binary);
        vk_file << *verification_key_;
    }
}

std::vector<unsigned char>
RollupProver::serializeProof(
    libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve> const& p)
{
    std::stringstream ss(std::ios::binary | std::ios::out);
    ss << p;
    auto str = ss.str();
    return std::vector<unsigned char>(str.begin(), str.end());
}

libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve>
RollupProver::deserializeProof(std::vector<unsigned char> const& bytes)
{
    std::stringstream ss(
        std::string(bytes.begin(), bytes.end()),
        std::ios::binary | std::ios::in);
    libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve> p;
    ss >> p;
    return p;
}

RollupProofData
RollupProver::createProof(
    RollupNote const& old_note,
    RollupNote const& new_note,
    std::vector<bool> const& leaf_pos,
    std::vector<FieldT> const& auth_path_old,
    std::vector<FieldT> const& auth_path_new,
    FieldT const& prev_root,
    FieldT const& new_root,
    bool is_withdraw)
{
    if (!initialised_)
        initialize();

    // Build a fresh circuit instance for this witness — libsnark's protoboard
    // is single-shot for witness assignment.
    PoseidonCircuit local(tree_depth_);
    local.generateConstraints();
    local.generateWitness(
        old_note, new_note, leaf_pos,
        auth_path_old, auth_path_new,
        prev_root, new_root, is_withdraw);

    auto primary = local.getPrimaryInput();
    auto aux = local.getAuxiliaryInput();

    auto proof = libsnark::r1cs_gg_ppzksnark_prover<DefaultCurve>(
        *proving_key_, primary, aux);

    RollupProofData out;
    out.proof_bytes = serializeProof(proof);
    out.anchor = prev_root;
    // Lever #1: the 2nd public input is now the new commitment (new_cm), not
    // the post-update root. (Field reused; carries new_cm.) The new root is
    // enforced off-circuit by doApply's replay.
    out.new_anchor = new_note.commitment();
    out.nullifier = old_note.nullifier();
    out.value_pub = FieldT(new_note.value);
    out.is_withdraw = is_withdraw;
    return out;
}

bool
RollupProver::verifyProof(RollupProofData const& proof_data)
{
    if (!initialised_)
        initialize();
    if (proof_data.empty())
        return false;

    // Public-input vector — MUST match PoseidonCircuit's allocation order:
    //   anchor, new_cm, nullifier, value_pub, is_withdraw.
    libsnark::r1cs_primary_input<FieldT> primary;
    primary.push_back(proof_data.anchor);
    primary.push_back(proof_data.new_anchor);
    primary.push_back(proof_data.nullifier);
    primary.push_back(proof_data.value_pub);
    primary.push_back(proof_data.is_withdraw ? FieldT::one() : FieldT::zero());

    try
    {
        auto proof = deserializeProof(proof_data.proof_bytes);
        return libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<DefaultCurve>(
            *verification_key_, primary, proof);
    }
    catch (std::exception const& e)
    {
        std::cerr << "[RollupProver] verifyProof failed: " << e.what()
                  << std::endl;
        return false;
    }
}

// ----------------------------------------------------------------------------
// Phase 4b: per-entry batch helpers
// ----------------------------------------------------------------------------

bool
RollupProver::isInitialized()
{
    return initialised_;
}

FieldT
RollupProver::uint256ToField(uint256 const& v)
{
    return PoseidonHash::uint256ToField(v);
}

bool
RollupProver::verifyEntryPublicInputs(
    FieldT const& prev_root,
    FieldT const& new_root,
    FieldT const& nullifier,
    FieldT const& value_pub,
    std::vector<unsigned char> const& proof_bytes,
    bool is_withdraw)
{
    RollupProofData pd;
    pd.proof_bytes  = proof_bytes;
    pd.anchor       = prev_root;
    pd.new_anchor   = new_root;
    pd.nullifier    = nullifier;
    pd.value_pub    = value_pub;
    pd.is_withdraw  = is_withdraw;
    return verifyProof(pd);
}

bool
RollupProver::verifyEntry(
    BatchProof const& bp,
    std::size_t entryIndex,
    std::vector<unsigned char> const& entryProof)
{
    if (!isInitialized())
    {
        std::cerr << "[RollupProver] verifyEntry: not initialised"
                  << std::endl;
        return false;
    }
    if (entryIndex >= bp.entries.size())
        return false;
    if (entryProof.empty())
        return false;

    auto const& e = bp.entries[entryIndex];

    // Pack public inputs in the order PoseidonCircuit allocates them
    // (Lever #1, single-path circuit):
    //   anchor    = prevRoot         (this entry's input-tree root)
    //   new_cm    = e.commitment     (the new note commitment, binds value)
    //   nullifier = e.nullifier      (Poseidon(ask, rho_old))
    //   value_pub = FieldT(e.value)  (the transferred drops, public)
    //
    // The circuit no longer proves the new root in-circuit. Instead it proves
    // new_cm is well-formed and commits value_pub; binding new_cm to
    // e.commitment here, plus doApply's deterministic root-replay (which
    // inserts e.commitment and asserts the result == bp.newRoot), is what
    // ties the proven value to the on-chain root. All eight entries share
    // prevRoot as the input anchor.
    //
    // The 5th public input (is_withdraw) is derived HERE from the entry's
    // declared txType. For a withdrawal the circuit's value-conservation
    // constraint forces the spent note's value == e.value, so a sequencer
    // cannot withdraw more than the note it is spending holds. A prover cannot
    // dodge this by mislabelling: if the entry is a Withdraw, doApply moves
    // e.value of real XRP, and this verifier requires the conservation proof.
    bool const isWithdraw = (e.txType == RollupTxType::Withdraw);
    return verifyEntryPublicInputs(
        uint256ToField(bp.prevRoot),
        uint256ToField(e.commitment),
        uint256ToField(e.nullifier),
        FieldT(e.value),
        entryProof,
        isWithdraw);
}

std::size_t
RollupProver::constraintCount()
{
    if (!circuit_)
        return 0;
    return circuit_->constraintCount();
}

libsnark::r1cs_gg_ppzksnark_verification_key<DefaultCurve> const&
RollupProver::verificationKey()
{
    if (!verification_key_)
        throw std::runtime_error(
            "RollupProver::verificationKey: not initialised — call "
            "initialize() or initializeVerifierOnly() first");
    return *verification_key_;
}

libsnark::r1cs_gg_ppzksnark_proof<DefaultCurve>
RollupProver::deserializeProofPublic(std::vector<unsigned char> const& bytes)
{
    return deserializeProof(bytes);
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple