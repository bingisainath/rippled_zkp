// Off-circuit Poseidon hash — the single source of truth for hash values
// computed outside any libsnark protoboard. Used by:
//   - PoseidonGadget unit tests (compare in-circuit output to off-circuit output)
//   - RollupMerkleTree, for sibling hashing
//   - Witness generation, for cm and nf computation
//
// Bit-exact compatible with circomlib's poseidon.circom and circomlibjs.

#ifndef RIPPLE_ZKP_ROLLUP_POSEIDON_HASH_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_POSEIDON_HASH_H_INCLUDED

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <vector>
#include <xrpl/basics/base_uint.h>

namespace ripple {
namespace zkp {
namespace rollup {

using DefaultCurve = libff::alt_bn128_pp;
using FieldT = libff::Fr<DefaultCurve>;

class PoseidonHash
{
public:
    // Initialise the constant tables (parses round constants & MDS into FieldT).
    // Idempotent and thread-safe. Must be called after
    // libff::alt_bn128_pp::init_public_params() but before any hash() call.
    static void
    initialize();

    // Two-input hash — the binary Merkle case. Called by the IMT and by
    // commitment / nullifier derivation. Equivalent to circomlib
    // poseidon.circom with nInputs = 2.
    static FieldT
    hash(FieldT const& a, FieldT const& b);

    // Generic n-input hash for n in {1, 2}. (Only n=2 is needed here;
    // the 1-input form is exposed for nullifier compatibility tests.)
    static FieldT
    hashN(std::vector<FieldT> const& inputs);

    // Convenience: convert uint256 ↔ FieldT and hash.
    // Note: a uint256 may exceed the BN-128 field modulus; this function
    // performs an explicit reduction (mod p). The BatchProof wire
    // format already constrains commitments / nullifiers to be valid field
    // elements, so the reduction is normally a no-op.
    static uint256
    hash(uint256 const& a, uint256 const& b);

    // Conversion helpers — wrappers around libff to keep call sites tidy.
    static FieldT
    uint256ToField(uint256 const& v);
    static uint256
    fieldToUint256(FieldT const& v);

    // Returns the precomputed Poseidon(0, 0) used as empty_hashes_[0]
    // in RollupMerkleTree.
    static FieldT const&
    zeroZero();

    // Test helpers — exposed only so unit tests can validate the parameter
    // table loaded correctly. Returns the t*t MDS as a flat row-major vector,
    // or the (R_F + R_P) * t round constants as a flat vector.
    static std::vector<FieldT> const&
    debug_mds();
    static std::vector<FieldT> const&
    debug_arc();

private:
    static void
    permute(FieldT state[3]);
    static void
    sBoxFull(FieldT state[3]);
    static void
    sBoxPartial(FieldT state[3]);
    static void
    addRoundConstants(FieldT state[3], std::size_t round_idx);
    static void
    mixLayer(FieldT state[3]);
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_POSEIDON_HASH_H_INCLUDED
