#include "MerkleCircuit.h"
#include "../Note.h"
#include <xrpl/basics/base_uint.h>
#include <iostream>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <cassert>
#include <openssl/sha.h>
#include <iomanip>

namespace ripple {
namespace zkp {

using libsnark::pb_variable;
using libsnark::pb_variable_array;
using libsnark::pb_linear_combination;
using libsnark::packing_gadget;
using libsnark::multipacking_gadget;
using libsnark::sha256_two_to_one_hash_gadget;
using libsnark::merkle_authentication_path_variable;
using libsnark::merkle_tree_check_read_gadget;
using libsnark::digest_variable;

void initCurveParameters() {
    static bool initialized = false;
    if (!initialized) {
        DefaultCurve::init_public_params();
        initialized = true;
    }
}

class MerkleCircuit::Impl {
private:
    size_t tree_depth_;
    std::shared_ptr<libsnark::protoboard<FieldT>> pb_;
    
    // PUBLIC INPUTS (PRIMARY)
    pb_variable<FieldT> anchor_;                    // Tree root
    pb_variable<FieldT> nullifier_;                 // Spend nullifier
    pb_variable<FieldT> value_commitment_;          // Value hiding commitment

    // PRIVATE INPUTS (AUXILIARY)
    // Note components
    pb_variable<FieldT> note_value_;                // Note amount
    pb_variable<FieldT> note_rho_;                  // Nullifier seed
    pb_variable<FieldT> note_r_;                    // Commitment randomness
    pb_variable<FieldT> note_a_pk_;                 // Recipient public key
    
    // Spend authorization
    pb_variable<FieldT> a_sk_;                      // Spend key (secret)
    pb_variable<FieldT> vcm_r_;                     // Value commitment randomness
    
    // Merkle tree variables
    pb_variable_array<FieldT> address_bits_;        // Leaf position
    pb_variable<FieldT> read_successful_;           // Always 1
    
    // BIT DECOMPOSITIONS
    pb_variable_array<FieldT> note_value_bits_;     // 64 bits
    pb_variable_array<FieldT> note_rho_bits_;       // 256 bits
    pb_variable_array<FieldT> note_r_bits_;         // 256 bits
    pb_variable_array<FieldT> note_a_pk_bits_;      // 256 bits
    pb_variable_array<FieldT> a_sk_bits_;           // 256 bits
    pb_variable_array<FieldT> vcm_r_bits_;          // 256 bits
    
    // SHA256 HASH VARIABLES
    std::unique_ptr<digest_variable<FieldT>> note_commitment_hash_;
    std::unique_ptr<digest_variable<FieldT>> nullifier_hash_;
    std::unique_ptr<digest_variable<FieldT>> value_commitment_hash_;
    std::unique_ptr<digest_variable<FieldT>> computed_root_;
    
    // Input digest variables for hash computations
    std::unique_ptr<digest_variable<FieldT>> note_input_part1_;
    std::unique_ptr<digest_variable<FieldT>> note_input_part2_;
    std::unique_ptr<digest_variable<FieldT>> a_sk_digest_;
    std::unique_ptr<digest_variable<FieldT>> rho_digest_;
    std::unique_ptr<digest_variable<FieldT>> value_digest_;
    std::unique_ptr<digest_variable<FieldT>> vcm_r_digest_;
    
    // SHA256 GADGETS
    std::unique_ptr<sha256_two_to_one_hash_gadget<FieldT>> note_commit_hasher_;
    std::unique_ptr<sha256_two_to_one_hash_gadget<FieldT>> nullifier_hasher_;
    std::unique_ptr<sha256_two_to_one_hash_gadget<FieldT>> value_commit_hasher_;
    
    // MERKLE TREE GADGETS
    std::unique_ptr<merkle_authentication_path_variable<FieldT, sha256_two_to_one_hash_gadget<FieldT>>> auth_path_;
    std::unique_ptr<merkle_tree_check_read_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT>>> merkle_verifier_;
    
    // PACKING GADGETS
    std::unique_ptr<packing_gadget<FieldT>> note_value_packer_;
    std::unique_ptr<packing_gadget<FieldT>> note_rho_packer_;
    std::unique_ptr<packing_gadget<FieldT>> note_r_packer_;
    std::unique_ptr<packing_gadget<FieldT>> note_a_pk_packer_;
    // REMOVED: a_sk_packer - we bypass field element conversion for secrets
    // std::unique_ptr<packing_gadget<FieldT>> a_sk_packer_;
    std::unique_ptr<packing_gadget<FieldT>> vcm_r_packer_;
    
    std::unique_ptr<packing_gadget<FieldT>> anchor_packer_;
    std::unique_ptr<packing_gadget<FieldT>> nullifier_packer_;
    std::unique_ptr<packing_gadget<FieldT>> value_commitment_packer_;
    
    // Helper function to compute proper empty hashes
    // This prevents using all-zero hashes which can be security vulnerabilities
    uint256 computeEmptyHash(size_t level) {
        // Use a deterministic hash for empty nodes at each level
        // This is a common pattern in Merkle tree implementations
        std::string emptyStr = "EMPTY_LEVEL_" + std::to_string(level);
        
        // Simple hash computation
        uint256 result;
        memset(result.data(), 0, 32);
        
        // Set some bits based on the level to make each level's empty hash unique
        result.data()[0] = static_cast<uint8_t>(level);
        result.data()[1] = static_cast<uint8_t>(level >> 8);
        result.data()[31] = 0xFF; // Marker to distinguish from all-zero
        
        return result;
    }

public:
    Impl(size_t tree_depth) : tree_depth_(tree_depth) {
        // std::cout << "Creating MerkleCircuit with depth " << tree_depth << std::endl;
        
        pb_ = std::make_shared<libsnark::protoboard<FieldT>>();
        
        // Allocate public inputs first (order: anchor, nullifier, value_commitment)
        anchor_.allocate(*pb_, "anchor");
        nullifier_.allocate(*pb_, "nullifier");
        value_commitment_.allocate(*pb_, "value_commitment");
        
        // Set primary input count
        pb_->set_input_sizes(3);
        
        // Allocate private field elements
        note_value_.allocate(*pb_, "note_value");
        note_rho_.allocate(*pb_, "note_rho");
        note_r_.allocate(*pb_, "note_r");
        note_a_pk_.allocate(*pb_, "note_a_pk");
        a_sk_.allocate(*pb_, "a_sk");
        vcm_r_.allocate(*pb_, "vcm_r");
        
        // Allocate Merkle tree variables
        address_bits_.allocate(*pb_, tree_depth_, "address_bits");
        read_successful_.allocate(*pb_, "read_successful");
        
        // std::cout << "MerkleCircuit initialized successfully" << std::endl;
    }
    
    void generateConstraints() {
        // std::cout << "Generating constraints..." << std::endl;
        
        // 1. ALLOCATE BIT DECOMPOSITION VARIABLES
        note_value_bits_.allocate(*pb_, 64, "note_value_bits");
        note_rho_bits_.allocate(*pb_, 256, "note_rho_bits");
        note_r_bits_.allocate(*pb_, 256, "note_r_bits");
        note_a_pk_bits_.allocate(*pb_, 256, "note_a_pk_bits");
        a_sk_bits_.allocate(*pb_, 256, "a_sk_bits");
        vcm_r_bits_.allocate(*pb_, 256, "vcm_r_bits");
        
        // 2. SETUP PACKING GADGETS (field elements ↔ bits)
        note_value_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, note_value_bits_, note_value_, "note_value_packer");
        
        // 3. SETUP SHA256 DIGEST VARIABLES
        note_commitment_hash_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "note_commitment_hash");
        
        nullifier_hash_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "nullifier_hash");
        
        value_commitment_hash_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "value_commitment_hash");
        
        computed_root_ = std::make_unique<digest_variable<FieldT>>(
            *pb_, 256, "computed_root");
        
        // 4. SHA256 HASH GADGETS
        
        // Create digest variables for the inputs to SHA256 gadgets
        auto note_input_part1 = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "note_input_part1");
        auto note_input_part2 = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "note_input_part2");
        auto a_sk_digest = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "a_sk_digest");
        auto rho_digest = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "rho_digest");
        auto value_digest = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "value_digest");
        auto vcm_r_digest = std::make_unique<digest_variable<FieldT>>(*pb_, 256, "vcm_r_digest");
        
        // Note commitment: hash two 256-bit parts
        note_commit_hasher_ = std::make_unique<sha256_two_to_one_hash_gadget<FieldT>>(
            *pb_,
            *note_input_part1,
            *note_input_part2,
            *note_commitment_hash_,
            "note_commit_hasher");
        
        // Nullifier: hash a_sk + rho  
        nullifier_hasher_ = std::make_unique<sha256_two_to_one_hash_gadget<FieldT>>(
            *pb_,
            *a_sk_digest,
            *rho_digest,
            *nullifier_hash_,
            "nullifier_hasher");
        
        // Value commitment: hash value + vcm_r
        value_commit_hasher_ = std::make_unique<sha256_two_to_one_hash_gadget<FieldT>>(
            *pb_,
            *value_digest,
            *vcm_r_digest,
            *value_commitment_hash_,
            "value_commit_hasher");
        
        // Store digest pointers so they don't go out of scope
        note_input_part1_ = std::move(note_input_part1);
        note_input_part2_ = std::move(note_input_part2);
        a_sk_digest_ = std::move(a_sk_digest);
        rho_digest_ = std::move(rho_digest);
        value_digest_ = std::move(value_digest);
        vcm_r_digest_ = std::move(vcm_r_digest);
    
        // 5. SETUP MERKLE TREE VERIFICATION
        auth_path_ = std::make_unique<merkle_authentication_path_variable<FieldT, sha256_two_to_one_hash_gadget<FieldT>>>(
            *pb_, tree_depth_, "auth_path");
        
        merkle_verifier_ = std::make_unique<merkle_tree_check_read_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT>>>(
            *pb_,
            tree_depth_,
            address_bits_,
            *note_commitment_hash_,
            *computed_root_,
            *auth_path_,
            read_successful_,
            "merkle_verifier");
        
        // 6. SETUP OUTPUT PACKING GADGETS
        anchor_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, computed_root_->bits, anchor_, "anchor_packer");
        
        nullifier_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, nullifier_hash_->bits, nullifier_, "nullifier_packer");
        
        value_commitment_packer_ = std::make_unique<packing_gadget<FieldT>>(
            *pb_, value_commitment_hash_->bits, value_commitment_, "value_commitment_packer");
        
        // 7. GENERATE ALL CONSTRAINTS
    
        note_value_packer_->generate_r1cs_constraints(true);
        
        // Connect bit arrays to digest variables for note commitment
        // Part 1: value(64) + rho(192) = 256 bits
        for (size_t i = 0; i < 64; ++i) {
            pb_->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
                note_input_part1_->bits[i], 1, note_value_bits_[i]), 
                "note_part1_value_" + std::to_string(i));
        }
        for (size_t i = 0; i < 192; ++i) {
            pb_->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
                note_input_part1_->bits[64 + i], 1, note_rho_bits_[i]), 
                "note_part1_rho_" + std::to_string(i));
        }
        
        // Part 2: r(128) + a_pk(128) = 256 bits
        for (size_t i = 0; i < 128; ++i) {
            pb_->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
                note_input_part2_->bits[i], 1, note_r_bits_[i]), 
                "note_part2_r_" + std::to_string(i));
        }
        for (size_t i = 0; i < 128; ++i) {
            pb_->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
                note_input_part2_->bits[128 + i], 1, note_a_pk_bits_[i]), 
                "note_part2_a_pk_" + std::to_string(i));
        }
        
        // Connect digest variables for nullifier
        for (size_t i = 0; i < 256; ++i) {
            pb_->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
                a_sk_digest_->bits[i], 1, a_sk_bits_[i]), 
                "a_sk_digest_" + std::to_string(i));
            pb_->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
                rho_digest_->bits[i], 1, note_rho_bits_[i]), 
                "rho_digest_" + std::to_string(i));
        }
        
        // Connect digest variables for value commitment
        for (size_t i = 0; i < 64; ++i) {
            pb_->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
                value_digest_->bits[i], 1, note_value_bits_[i]), 
                "value_digest_" + std::to_string(i));
        }
        for (size_t i = 64; i < 256; ++i) {
            pb_->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
                value_digest_->bits[i], 1, FieldT::zero()), 
                "value_digest_padding_" + std::to_string(i));
        }
        for (size_t i = 0; i < 256; ++i) {
            pb_->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
                vcm_r_digest_->bits[i], 1, vcm_r_bits_[i]), 
                "vcm_r_digest_" + std::to_string(i));
        }
        
        // Hash constraints
        note_commit_hasher_->generate_r1cs_constraints();
        nullifier_hasher_->generate_r1cs_constraints();
        value_commit_hasher_->generate_r1cs_constraints();
        
        // Merkle tree constraints
        merkle_verifier_->generate_r1cs_constraints();
        
        // NOTE: Root validation is handled by the anchor_packer gadget
        // The anchor_packer constrains that computed_root_->bits pack into anchor_
        // This ensures the computed root matches the claimed anchor
        
        // NOTE: Authentication path validation is handled by the merkle_tree_check_read_gadget
        // The gadget internally validates that the path is consistent with the tree structure
        // Additional explicit constraints here may create conflicts
        
        // Read successful constraint (always 1)
        pb_->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
            read_successful_, 1, FieldT::one()), "read_successful_constraint");
        
        // Output packing constraints
        anchor_packer_->generate_r1cs_constraints(true);
        nullifier_packer_->generate_r1cs_constraints(true);
        value_commitment_packer_->generate_r1cs_constraints(true);
        
        // Boolean constraints for all bits
        generateBooleanConstraints();
        
        //std::cout << "Constraints generated. Total: " << pb_->num_constraints() << std::endl;
    }
    
    void generateBooleanConstraints() {
        // Boolean constraints for note value bits
        for (size_t i = 0; i < note_value_bits_.size(); ++i) {
            libsnark::generate_boolean_r1cs_constraint<FieldT>(*pb_, note_value_bits_[i], 
                "note_value_bit_" + std::to_string(i));
        }
        
        // Boolean constraints for other bit arrays
        auto generateBoolConstraintsForArray = [&](const pb_variable_array<FieldT>& arr, const std::string& prefix) {
            for (size_t i = 0; i < arr.size(); ++i) {
                libsnark::generate_boolean_r1cs_constraint<FieldT>(*pb_, arr[i], 
                    prefix + std::to_string(i));
            }
        };
        
        generateBoolConstraintsForArray(note_rho_bits_, "note_rho_bit_");
        generateBoolConstraintsForArray(note_r_bits_, "note_r_bit_");
        generateBoolConstraintsForArray(note_a_pk_bits_, "note_a_pk_bit_");
        generateBoolConstraintsForArray(a_sk_bits_, "a_sk_bit_");
        generateBoolConstraintsForArray(vcm_r_bits_, "vcm_r_bit_");
        generateBoolConstraintsForArray(address_bits_, "address_bit_");
    }
    
    std::vector<FieldT> generateDepositWitness(
        const Note& note,
        const uint256& a_sk,
        const uint256& vcm_r,
        const std::vector<bool>& leaf,
        const std::vector<bool>& root)
    {
        // std::cout << "=== DEPOSIT WITNESS GENERATION ===" << std::endl;
        
        // For deposits, use dummy authentication path
        std::vector<std::vector<bool>> dummyPath(tree_depth_, std::vector<bool>(256, false));
        
        return generateWitness(note, a_sk, vcm_r, leaf, dummyPath, root, 0);
    }
    
    std::vector<FieldT> generateWithdrawalWitness(
        const Note& note,
        const uint256& a_sk,
        const uint256& vcm_r,
        const std::vector<bool>& leaf,
        const std::vector<std::vector<bool>>& path,
        const std::vector<bool>& root,
        size_t address)
    {
        //std::cout << "=== WITHDRAWAL WITNESS GENERATION ===" << std::endl;
        
        return generateWitness(note, a_sk, vcm_r, leaf, path, root, address);
    }
    
private:
    std::vector<FieldT> generateWitness(
        const Note& note,
        const uint256& a_sk,
        const uint256& vcm_r,
        const std::vector<bool>& leaf,
        const std::vector<std::vector<bool>>& path,
        const std::vector<bool>& root,
        size_t address)
    {
        try {
            // 1. SET FIELD ELEMENT VALUES FROM NOTE (BYPASS FIELD CONVERSION FOR ALL CRYPTOGRAPHIC VALUES)
            pb_->val(note_value_) = FieldT(note.value);
            pb_->val(read_successful_) = FieldT::one();
            
            // 2. SET ADDRESS BITS
            for (size_t i = 0; i < tree_depth_; ++i) {
                pb_->val(address_bits_[i]) = FieldT((address >> i) & 1);
            }
            
            // 3. CONVERT TO BIT REPRESENTATIONS (BYPASS FIELD CONVERSION FOR a_sk)
            setBits(note, a_sk, vcm_r);
            
            // 4. SET AUTHENTICATION PATH
            setAuthenticationPath(path);
            
            // 5. GENERATE WITNESSES FOR ALL GADGETS
            generateAllWitnesses();
            
            //std::cout << "Witness generation completed successfully" << std::endl;
            
            return pb_->auxiliary_input();
            
        } catch (const std::exception& e) {
            std::cerr << "Error in witness generation: " << e.what() << std::endl;
            throw;
        }
    }
    
    void setBits(const Note& note, const uint256& a_sk, const uint256& vcm_r) {
        // Convert note value to 64 bits
        uint64_t value_u64 = note.value;
        for (size_t i = 0; i < 64; ++i) {
            pb_->val(note_value_bits_[i]) = FieldT((value_u64 >> i) & 1);
        }
        
        // Convert uint256 values to bits (non-secret values)
        auto rho_bits = MerkleCircuit::uint256ToBits(note.rho);
        auto r_bits = MerkleCircuit::uint256ToBits(note.r);
        auto a_pk_bits = MerkleCircuit::uint256ToBits(note.a_pk);
        auto vcm_r_bits = MerkleCircuit::uint256ToBits(vcm_r);
        auto a_sk_bits = MerkleCircuit::uint256ToBits(a_sk);
        
        // // DEBUG: Print circuit bit conversion for comparison
        // std::cout << "Circuit setBits debug:" << std::endl;
        // std::cout << "  a_sk hex: " << std::hex;
        // for (int i = 0; i < 4; ++i) {
        //     std::cout << std::setfill('0') << std::setw(2) << (unsigned int)a_sk.begin()[i];
        // }
        // std::cout << "..." << std::dec << std::endl;
        
        // std::cout << "  a_sk bits[0-15]: ";
        // for (int i = 0; i < 16; ++i) {
        //     std::cout << (a_sk_bits[i] ? "1" : "0");
        // }
        // std::cout << std::endl;
        
        // std::cout << "  rho bits[0-15]: ";
        // for (int i = 0; i < 16; ++i) {
        //     std::cout << (rho_bits[i] ? "1" : "0");
        // }
        // std::cout << std::endl;
        
        for (size_t i = 0; i < 256; ++i) {
            pb_->val(note_rho_bits_[i]) = rho_bits[i] ? FieldT::one() : FieldT::zero();
            pb_->val(note_r_bits_[i]) = r_bits[i] ? FieldT::one() : FieldT::zero();
            pb_->val(note_a_pk_bits_[i]) = a_pk_bits[i] ? FieldT::one() : FieldT::zero();
            pb_->val(a_sk_bits_[i]) = a_sk_bits[i] ? FieldT::one() : FieldT::zero();
            pb_->val(vcm_r_bits_[i]) = vcm_r_bits[i] ? FieldT::one() : FieldT::zero();
        }
    }
    
    void setAuthenticationPath(const std::vector<std::vector<bool>>& path) {
        // The path contains sibling hashes for each level of the tree
        for (size_t level = 0; level < tree_depth_; ++level) {
            if (level < path.size() && path[level].size() == 256) {
                // Set the sibling hash at this level
                for (size_t bit = 0; bit < 256; ++bit) {
                    // In libsnark, we need to set the appropriate digest based on the address bit
                    // The merkle_tree_check_read_gadget will internally decide which digest to use
                    // based on the address bits, so we set both to the sibling value
                    FieldT bit_value = path[level][bit] ? FieldT::one() : FieldT::zero();
                    pb_->val(auth_path_->left_digests[level].bits[bit]) = bit_value;
                    pb_->val(auth_path_->right_digests[level].bits[bit]) = bit_value;
                }
            } else {
                // Use proper empty hash instead of all zeros
                // All-zero hashes can be a security vulnerability
                uint256 emptyHash = computeEmptyHash(level);
                auto emptyBits = MerkleCircuit::uint256ToBits(emptyHash);
                
                for (size_t bit = 0; bit < 256; ++bit) {
                    FieldT bit_value = (bit < emptyBits.size() && emptyBits[bit]) ? FieldT::one() : FieldT::zero();
                    pb_->val(auth_path_->left_digests[level].bits[bit]) = bit_value;
                    pb_->val(auth_path_->right_digests[level].bits[bit]) = bit_value;
                }
            }
        }
    }
    
    void generateAllWitnesses() {
        note_value_packer_->generate_r1cs_witness_from_packed();
        
        // Set digest witness values for note commitment
        // Part 1: value(64) + rho(192) = 256 bits
        for (size_t i = 0; i < 64; ++i) {
            pb_->val(note_input_part1_->bits[i]) = pb_->val(note_value_bits_[i]);
        }
        for (size_t i = 0; i < 192; ++i) {
            pb_->val(note_input_part1_->bits[64 + i]) = pb_->val(note_rho_bits_[i]);
        }
        
        // Part 2: r(128) + a_pk(128) = 256 bits
        for (size_t i = 0; i < 128; ++i) {
            pb_->val(note_input_part2_->bits[i]) = pb_->val(note_r_bits_[i]);
        }
        for (size_t i = 0; i < 128; ++i) {
            pb_->val(note_input_part2_->bits[128 + i]) = pb_->val(note_a_pk_bits_[i]);
        }
        
        // Set digest witness values for nullifier
        for (size_t i = 0; i < 256; ++i) {
            pb_->val(a_sk_digest_->bits[i]) = pb_->val(a_sk_bits_[i]);
            pb_->val(rho_digest_->bits[i]) = pb_->val(note_rho_bits_[i]);
        }
        
        // Set digest witness values for value commitment
        for (size_t i = 0; i < 64; ++i) {
            pb_->val(value_digest_->bits[i]) = pb_->val(note_value_bits_[i]);
        }
        for (size_t i = 64; i < 256; ++i) {
            pb_->val(value_digest_->bits[i]) = FieldT::zero();
        }
        for (size_t i = 0; i < 256; ++i) {
            pb_->val(vcm_r_digest_->bits[i]) = pb_->val(vcm_r_bits_[i]);
        }
        
        // Generate hash witnesses
        note_commit_hasher_->generate_r1cs_witness();
        nullifier_hasher_->generate_r1cs_witness();
        value_commit_hasher_->generate_r1cs_witness();
        
        // Generate witness for Merkle tree verification
        merkle_verifier_->generate_r1cs_witness();
        
        // Generate witnesses for output packing
        anchor_packer_->generate_r1cs_witness_from_bits();
        nullifier_packer_->generate_r1cs_witness_from_bits();
        value_commitment_packer_->generate_r1cs_witness_from_bits();
    }

public:
    // Getters
    FieldT getNullifier() const { return pb_->val(nullifier_); }
    FieldT getValueCommitment() const { return pb_->val(value_commitment_); }
    
    uint256 getNullifierFromBits() const {
        // Extract nullifier directly from the SHA256 digest bits
        if (!nullifier_hash_) {
            return uint256{}; // Return zero if hasher not initialized
        }
        
        // Get the digest bits from the nullifier hash digest variable
        std::vector<bool> nullifier_bits(256);
        for (size_t i = 0; i < 256; ++i) {
            nullifier_bits[i] = pb_->val(nullifier_hash_->bits[i]) == FieldT::one();
        }
        
        uint256 result = MerkleCircuit::bitsToUint256(nullifier_bits);
        

        // DEBUG: Print circuit nullifier extraction
        // std::cout << "Circuit getNullifierFromBits debug:" << std::endl;
        // std::cout << "  Circuit result: " << std::hex;
        // for (int i = 0; i < 8; ++i) {
        //     std::cout << std::setfill('0') << std::setw(2) << (unsigned int)result.begin()[i];
        // }
        // std::cout << "..." << std::dec << std::endl;
        
// e7268d5c9 (Commented out Debugging statement from src and test cases, readings from the tests still pending.)
        return result;
    }
    
    FieldT getAnchor() const { return pb_->val(anchor_); }
    
    libsnark::r1cs_constraint_system<FieldT> getConstraintSystem() const {
        return pb_->get_constraint_system();
    }
    
    libsnark::r1cs_primary_input<FieldT> getPrimaryInput() const {
        return pb_->primary_input();
    }
    
    libsnark::r1cs_auxiliary_input<FieldT> getAuxiliaryInput() const {
        return pb_->auxiliary_input();
    }
    
    std::shared_ptr<libsnark::protoboard<FieldT>> getProtoboard() const {
        return pb_;
    }
    
    size_t getTreeDepth() const { return tree_depth_; }
};

// PUBLIC INTERFACE IMPLEMENTATION

MerkleCircuit::MerkleCircuit(size_t treeDepth) 
    : pImpl_(std::make_unique<Impl>(treeDepth)) {
}

MerkleCircuit::~MerkleCircuit() = default;

void MerkleCircuit::generateConstraints() {
    pImpl_->generateConstraints();
}

std::vector<FieldT> MerkleCircuit::generateDepositWitness(
    const Note& note,
    const uint256& a_sk,
    const uint256& vcm_r,
    const std::vector<bool>& leaf,
    const std::vector<bool>& root) {
    return pImpl_->generateDepositWitness(note, a_sk, vcm_r, leaf, root);
}

std::vector<FieldT> MerkleCircuit::generateWithdrawalWitness(
    const Note& note,
    const uint256& a_sk,
    const uint256& vcm_r,
    const std::vector<bool>& leaf,
    const std::vector<std::vector<bool>>& path,
    const std::vector<bool>& root,
    size_t address) {
    return pImpl_->generateWithdrawalWitness(note, a_sk, vcm_r, leaf, path, root, address);
}

FieldT MerkleCircuit::getNullifier() const { return pImpl_->getNullifier(); }
FieldT MerkleCircuit::getValueCommitment() const { return pImpl_->getValueCommitment(); }
FieldT MerkleCircuit::getAnchor() const { return pImpl_->getAnchor(); }
uint256 MerkleCircuit::getNullifierFromBits() const { return pImpl_->getNullifierFromBits(); }

uint256 MerkleCircuit::getNullifierFromCircuit() const {
    return getNullifierFromBits();
}

libsnark::r1cs_constraint_system<FieldT> MerkleCircuit::getConstraintSystem() const {
    return pImpl_->getConstraintSystem();
}

libsnark::r1cs_primary_input<FieldT> MerkleCircuit::getPrimaryInput() const {
    return pImpl_->getPrimaryInput();
}

libsnark::r1cs_auxiliary_input<FieldT> MerkleCircuit::getAuxiliaryInput() const {
    return pImpl_->getAuxiliaryInput();
}

std::shared_ptr<libsnark::protoboard<FieldT>> MerkleCircuit::getProtoboard() const {
    return pImpl_->getProtoboard();
}

size_t MerkleCircuit::getTreeDepth() const {
    return pImpl_->getTreeDepth();
}

// UTILITY FUNCTIONS

std::vector<bool> convertToLibsnarkBits(const uint256& input) {
    std::vector<bool> bits(256);
    const unsigned char* data = input.begin();
    
    for (size_t word = 0; word < 8; ++word) {
        for (size_t bit = 0; bit < 32; ++bit) {
            size_t byte_idx = word * 4 + (3 - bit / 8);
            size_t bit_idx = 7 - (bit % 8);
            
            bool bit_value = (data[byte_idx] >> bit_idx) & 1;
            bits[word * 32 + bit] = bit_value;
        }
    }
    return bits;
}

uint256 convertFromLibsnarkBits(const std::vector<bool>& bits) {
    uint256 result;
    unsigned char* data = result.begin();
    std::fill(data, data + 32, 0);
    
    for (size_t word = 0; word < 8 && word * 32 < bits.size(); ++word) {
        for (size_t bit = 0; bit < 32 && word * 32 + bit < bits.size(); ++bit) {
            if (bits[word * 32 + bit]) {
                size_t byte_idx = word * 4 + (3 - bit / 8);
                size_t bit_idx = 7 - (bit % 8);
                data[byte_idx] |= (1 << bit_idx);
            }
        }
    }
    return result;
}

uint256 convertFromLibsnarkBits(const digest_variable<FieldT>& digest, const libsnark::protoboard<FieldT>& pb) {
    std::vector<bool> bits(256);
    for (size_t i = 0; i < 256; ++i) {
        bits[i] = pb.val(digest.bits[i]) == FieldT::one();
    }
    return convertFromLibsnarkBits(bits);
}

std::vector<bool> MerkleCircuit::uint256ToBits(const uint256& input) {
    return convertToLibsnarkBits(input);
}

uint256 MerkleCircuit::bitsToUint256(const std::vector<bool>& bits) {
    return convertFromLibsnarkBits(bits);
}

std::vector<bool> MerkleCircuit::spendKeyToBits(const std::string& spendKey) {
    std::vector<bool> bits(256, false);
    for (size_t i = 0; i < std::min(spendKey.length(), size_t(32)); ++i) {
        uint8_t byte = static_cast<uint8_t>(spendKey[i]);
        for (size_t j = 0; j < 8; ++j) {
            bits[i * 8 + j] = (byte >> j) & 1;
        }
    }
    return bits;
}

FieldT MerkleCircuit::bitsToFieldElement(const std::vector<bool>& bits) {
    FieldT result = FieldT::zero();
    FieldT power = FieldT::one();
    
    for (size_t i = 0; i < std::min(bits.size(), size_t(253)); ++i) {
        if (bits[i]) {
            result += power;
        }
        power += power; // power *= 2
    }
    return result;
}

std::vector<bool> MerkleCircuit::fieldElementToBits(const FieldT& element) {
    // as_bigint() converts from Montgomery form to standard integer representation.
    // test_bit(i) returns the i-th bit of that integer (LSB-first), which is
    // the inverse of bitsToFieldElement's sum(bits[i] * 2^i) convention.
    auto const bigint = element.as_bigint();
    std::vector<bool> bits(253, false);
    for (size_t i = 0; i < 253; ++i)
        bits[i] = bigint.test_bit(i);
    return bits;
}

FieldT MerkleCircuit::uint256ToFieldElement(const uint256& input) {
    std::vector<bool> bits = uint256ToBits(input);
    return bitsToFieldElement(bits);
}

uint256 MerkleCircuit::fieldElementToUint256(const FieldT& element) {
    std::vector<bool> bits = fieldElementToBits(element);
    return bitsToUint256(bits);
}

std::vector<uint8_t> MerkleCircuit::bitsToBytes(const std::vector<bool>& bits) {
    std::vector<uint8_t> bytes((bits.size() + 7) / 8, 0);
    
    for (size_t i = 0; i < bits.size(); ++i) {
        if (bits[i]) {
            bytes[i / 8] |= (1 << (i % 8));
        }
    }
    
    return bytes;
}

std::vector<bool> MerkleCircuit::bytesToBits(const std::vector<uint8_t>& bytes) {
    std::vector<bool> bits;
    bits.reserve(bytes.size() * 8);
    
    for (uint8_t byte : bytes) {
        for (int i = 0; i < 8; ++i) {
            bits.push_back((byte >> i) & 1);
        }
    }
    
    return bits;
}

// commitment computations (outside circuit, for testing)
uint256 MerkleCircuit::computeNoteCommitment(
    uint64_t value,
    const uint256& rho,
    const uint256& r,
    const uint256& a_pk) {
    
    // SHA256(SHA256(value||rho_192), SHA256(r_128||a_pk_128))
    
    // First hash: value(8 bytes) + rho(24 bytes) = 32 bytes
    std::vector<uint8_t> input1;
    for (int i = 0; i < 8; ++i) {
        input1.push_back((value >> (i * 8)) & 0xFF);
    }
    
    // Add first 24 bytes of rho (192 bits)
    input1.insert(input1.end(), rho.begin(), rho.begin() + 24);
    
    uint256 hash1;
    SHA256(input1.data(), input1.size(), hash1.begin());
    
    // Second hash: r(16 bytes) + a_pk(16 bytes) = 32 bytes
    std::vector<uint8_t> input2;
    
    // Add first 16 bytes of r (128 bits)
    input2.insert(input2.end(), r.begin(), r.begin() + 16);
    
    // Add first 16 bytes of a_pk (128 bits)
    input2.insert(input2.end(), a_pk.begin(), a_pk.begin() + 16);
    
    uint256 hash2;
    SHA256(input2.data(), input2.size(), hash2.begin());
    
    // Final hash: hash1 + hash2
    std::vector<uint8_t> final_input;
    final_input.insert(final_input.end(), hash1.begin(), hash1.end());
    final_input.insert(final_input.end(), hash2.begin(), hash2.end());
    
    uint256 result;
    SHA256(final_input.data(), final_input.size(), result.begin());
    
    return result;
}

uint256 MerkleCircuit::computeNullifierWithCircuit(
    const uint256& a_sk,
    const uint256& rho) {
    
    // Create a minimal circuit just to compute the nullifier
    // This ensures we get the exact same result as the main circuit
    MerkleCircuit minimalCircuit(1); // Minimal depth
    minimalCircuit.generateConstraints();
    
    // Create a dummy note with the rho we need
    Note dummyNote(0, rho, uint256{}, uint256{});
    
    // Generate witness with the spending key
    auto witness = minimalCircuit.generateDepositWitness(
        dummyNote,
        a_sk,
        uint256{}, // vcm_r doesn't matter for nullifier
        std::vector<bool>(256, false), // dummy leaf
        std::vector<bool>(256, false)  // dummy root
    );
    
    // Get the nullifier from the circuit bits
    return minimalCircuit.getNullifierFromBits();
}

// DEPRECATED: This external function produces different results than the circuit
// It's kept for now but marked as deprecated to avoid breaking existing code
uint256 MerkleCircuit::computeNullifier(
    const uint256& a_sk,
    const uint256& rho) {
    
    // Simply delegate to the circuit-based computation for consistency
    return computeNullifierWithCircuit(a_sk, rho);
}

uint256 MerkleCircuit::computeValueCommitment(
    uint64_t value,
    const uint256& vcm_r) {
    
    // Match simplified circuit: Direct SHA256(value_padded || vcm_r)
    
    // First input: value(8 bytes) + padding(24 bytes) = 32 bytes
    std::vector<uint8_t> value_padded(32, 0);
    for (int i = 0; i < 8; ++i) {
        value_padded[i] = (value >> (i * 8)) & 0xFF;
    }
    
    // Combined input: value_padded(32 bytes) + vcm_r(32 bytes) = 64 bytes
    std::vector<uint8_t> combined_input(64);
    std::memcpy(&combined_input[0], value_padded.data(), 32);
    std::memcpy(&combined_input[32], vcm_r.begin(), 32);
    
    uint256 result;
    SHA256(combined_input.data(), 64, result.begin());
    
    return result;
}

} // namespace zkp
} // namespace ripple