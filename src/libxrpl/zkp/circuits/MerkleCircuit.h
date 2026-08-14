#pragma once

#include <memory>
#include <vector>
#include <string>
#include <array>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <xrpl/basics/base_uint.h>

namespace ripple { namespace zkp { struct Note; } }

namespace ripple {
namespace zkp {

using DefaultCurve = libff::alt_bn128_pp;
using FieldT = libff::Fr<DefaultCurve>;

using libsnark::digest_variable;
using libsnark::block_variable;
using libsnark::sha256_compression_function_gadget;
using libsnark::sha256_two_to_one_hash_gadget;
using libsnark::merkle_authentication_path_variable;
using libsnark::merkle_tree_check_read_gadget;

/**
 * Merkle Circuit Implementation
 * 
 * Based on the Zcash protocol specification (Sapling/Orchard).
 * Implements zero-knowledge proofs for shielded transactions with:
 * 
 * CRYPTOGRAPHIC COMMITMENTS:
 * - Note Commitment: cm = SHA256(value || rho || r || a_pk)
 * - Nullifier: nf = SHA256(a_sk || rho) 
 * - Value Commitment: vcm = SHA256(value || vcm_r) [for hiding]
 * 
 * MERKLE TREE INTEGRATION:
 * - Proves note membership in commitment tree
 * - Authentication path verification using SHA256
 * - Prevents double-spending via nullifier
 * 
 * PUBLIC INPUTS: [anchor, nullifier, value_commitment]
 * PRIVATE INPUTS: [Note(value, rho, r, a_pk), a_sk, vcm_r, auth_path]
 * 
 * SECURITY PROPERTIES:
 * - Hiding: Values are cryptographically hidden via commitments
 * - Binding: Cannot create fake commitments or change committed values
 * - Unforgeability: Must know spend key to create valid nullifier
 * - Non-malleability: Proofs cannot be modified without detection
 */
class MerkleCircuit
{
public:
    /**
     * Construct a shielded transaction circuit.
     * @param treeDepth The depth of the note commitment tree (typically 32).
     */
    explicit MerkleCircuit(size_t treeDepth);

    ~MerkleCircuit();

    /**
     * Generate R1CS constraints for the circuit.
     * 
     * CONSTRAINT CATEGORIES:
     * 1. Note Commitment Constraints:
     *    - cm = SHA256(value || rho || r || a_pk)
     *    - All components properly packed/unpacked
     * 
     * 2. Nullifier Derivation Constraints:
     *    - nf = SHA256(a_sk || rho)
     *    - Ensures spend authorization
     * 
     * 3. Value Commitment Constraints:
     *    - vcm = SHA256(value || vcm_r)
     *    - Provides value hiding property
     * 
     * 4. Merkle Tree Constraints:
     *    - Authentication path verification
     *    - Root computation and matching
     * 
     * 5. Boolean and Range Constraints:
     *    - All bits ∈ {0,1}
     *    - Value range checks
     */
    void generateConstraints();

    /**
     * Generate witness for deposit (note creation).
     * 
     * DEPOSITS create new notes and add them to the commitment tree.
     * The note is not yet in the tree, so we use a dummy authentication path.
     * 
     * @param note The note being created
     * @param a_sk The spend authority secret key (32 bytes)
     * @param vcm_r Value commitment randomness (32 bytes, for hiding)
     * @param leaf The computed note commitment (256 bits)
     * @param root The current tree root (256 bits)
     * @return Complete witness vector for proof generation
     */
    std::vector<FieldT> generateDepositWitness(
        const Note& note,
        const uint256& a_sk,
        const uint256& vcm_r,
        const std::vector<bool>& leaf,
        const std::vector<bool>& root);

    /**
     * Generate witness for withdrawal (note spending).
     * 
     * WITHDRAWALS spend existing notes from the commitment tree.
     * Requires valid authentication path proving note membership.
     * 
     * @param note The note being spent
     * @param a_sk The spend authority secret key (32 bytes)
     * @param vcm_r Value commitment randomness (32 bytes, for hiding)
     * @param leaf The note commitment (256 bits)
     * @param path The Merkle authentication path (vector of 256-bit siblings)
     * @param root The tree root (256 bits)
     * @param address The leaf position in the tree (for path verification)
     * @return Complete witness vector for proof generation
     */
    std::vector<FieldT> generateWithdrawalWitness(
        const Note& note,
        const uint256& a_sk,
        const uint256& vcm_r,
        const std::vector<bool>& leaf,
        const std::vector<std::vector<bool>>& path,
        const std::vector<bool>& root,
        size_t address);

    /**
     * Get the computed nullifier (public output).
     * nf = SHA256(a_sk || rho)
     * 
     * Used to prevent double-spending by tracking spent nullifiers.
     * Each note can only be spent once, producing a unique nullifier.
     */
    FieldT getNullifier() const;

    /**
     * Get the computed value commitment (public output).
     * vcm = SHA256(value || vcm_r)
     * 
     * Provides cryptographic hiding of the note value while allowing
     * homomorphic operations for balance verification.
     */
    FieldT getValueCommitment() const;

    /**
     * Get nullifier directly from digest bits (not packed field element).
     * Returns the full 256-bit nullifier hash.
     * 
     * This is needed because the packed field element can only hold 253 bits.
     */
    uint256 getNullifierFromBits() const;

    /**
     * Get the anchor/root (public output).
     * 
     * The Merkle tree root that the note was proven to be in.
     * Anchors prevent rollback attacks and ensure note validity.
     */
    FieldT getAnchor() const;

    // Circuit system accessors
    libsnark::r1cs_constraint_system<FieldT> getConstraintSystem() const;
    libsnark::r1cs_primary_input<FieldT> getPrimaryInput() const;
    libsnark::r1cs_auxiliary_input<FieldT> getAuxiliaryInput() const;
    std::shared_ptr<libsnark::protoboard<FieldT>> getProtoboard() const;
    size_t getTreeDepth() const;

    // UTILITY FUNCTIONS

    /**
     * Convert uint256 to bits (little-endian within bytes).
     */
    static std::vector<bool> uint256ToBits(const uint256& input);

    /**
     * Convert bits back to uint256 (little-endian within bytes).
     */
    static uint256 bitsToUint256(const std::vector<bool>& bits);

    /**
     * Convert spend key (hex string) to bits for circuit input.
     */
    static std::vector<bool> spendKeyToBits(const std::string& spendKey);

    /**
     * Pack bits into a field element (sum of bits[i] * 2^i).
     * Used for converting SHA256 outputs to field elements.
     * Handles field overflow by truncating to fit the field modulus.
     */
    static FieldT bitsToFieldElement(const std::vector<bool>& bits);
    
    /**
     * Unpack field element into bits.
     * Inverse of bitsToFieldElement.
     */
    static std::vector<bool> fieldElementToBits(const FieldT& element);

    /**
     * Convert uint256 directly to field element.
     * Handles large integers that might exceed field modulus.
     */
    static FieldT uint256ToFieldElement(const uint256& input);

    /**
     * Convert field element back to uint256.
     */
    static uint256 fieldElementToUint256(const FieldT& element);

    /**
     * Convert bits to bytes (8 bits per byte, little-endian).
     * Used for SHA256 input preparation.
     */
    static std::vector<uint8_t> bitsToBytes(const std::vector<bool>& bits);

    /**
     * Convert bytes to bits (8 bits per byte, little-endian).
     * Used for converting hash outputs to circuit bits.
     */
    static std::vector<bool> bytesToBits(const std::vector<uint8_t>& bytes);

    /**
     * Note commitment computation (outside circuit).
     * cm = SHA256(value || rho || r || a_pk)
     * 
     * This matches the circuit computation and is used for testing/verification.
     */
    static uint256 computeNoteCommitment(
        uint64_t value,
        const uint256& rho,
        const uint256& r,
        const uint256& a_pk);

    /**
     * Nullifier computation using circuit (canonical).
     * nf = SHA256(a_sk || rho)
     * 
     * This creates a minimal circuit to compute the nullifier exactly as the main circuit does.
     * This ensures consistency between external nullifier computation and circuit computation.
     */
    static uint256 computeNullifierWithCircuit(
        const uint256& a_sk,
        const uint256& rho);

    /**
     * Get nullifier from this circuit instance.
     * Should only be called after witness generation has been completed.
     * Returns the nullifier computed by this circuit.
     */
    uint256 getNullifierFromCircuit() const;

    /**
     * Nullifier computation (outside circuit) - DEPRECATED.
     * nf = SHA256(a_sk || rho)
     * 
     * This now redirects to computeNullifierWithCircuit for consistency.
     * Kept for compatibility but should use computeNullifierWithCircuit instead.
     */
    static uint256 computeNullifier(
        const uint256& a_sk,
        const uint256& rho);

    /**
     * Value commitment computation (outside circuit).
     * vcm = SHA256(value || vcm_r)
     * 
     * This matches the circuit computation and is used for testing/verification.
     */
    static uint256 computeValueCommitment(
        uint64_t value,
        const uint256& vcm_r);

private:
    /**
     * Private implementation using PIMPL pattern.
     * Hides complex libsnark implementation details from header.
     */
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

/**
 * Initialize elliptic curve parameters for proofs.
 * Uses alt_bn128 curve which provides ~128 bits of security.
 * 
 * MUST be called before creating any MerkleCircuit instances.
 * Thread-safe and idempotent.
 */
void initCurveParameters();

} // namespace zkp
} // namespace ripple