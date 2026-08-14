// In-circuit Poseidon-pi permutation as a libsnark gadget.
//
// Cost per round, counting multiplicative constraints only:
//   - Full round:    3 lanes x x->x^5, i.e. 3 x (x*x, x2*x2, x4*x) = 9 gates
//   - Partial round: 1 lane  x x->x^5                              = 3 gates
//   - The mix layer and round-constant addition are both linear in R1CS and
//     therefore free.
//
// Total for t=3: 8 * 9 + 57 * 3 = 243 gates, plus three lane-equality
// constraints projecting the initial state into the protoboard. This is the
// unoptimised form; the Hadeshash partial-round equivalence transform would
// bring it lower, so 243 is the conservative figure.

#ifndef RIPPLE_ZKP_ROLLUP_POSEIDON_GADGET_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_POSEIDON_GADGET_H_INCLUDED

#include "PoseidonHash.h"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>

namespace ripple {
namespace zkp {
namespace rollup {

// PoseidonGadget: enforces output == Poseidon(left, right).
//
// Wire interface:
//   - left, right : pb_linear_combination<FieldT>   (inputs, may be variables or LCs)
//   - output      : pb_variable<FieldT>             (allocated by caller, set by witness gen)
//
// Usage pattern (mirrors libsnark sha256_two_to_one_hash_gadget):
//   pb_variable<FieldT> out;
//   out.allocate(pb, "poseidon_out");
//   PoseidonGadget g(pb, left_lc, right_lc, out, "poseidon");
//   g.generate_r1cs_constraints();
//   ...
//   g.generate_r1cs_witness();   // pb is responsible for left/right values

class PoseidonGadget : public libsnark::gadget<FieldT>
{
public:
    PoseidonGadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_linear_combination<FieldT> const& left,
        libsnark::pb_linear_combination<FieldT> const& right,
        libsnark::pb_variable<FieldT> const& output,
        std::string const& annotation_prefix);

    void
    generate_r1cs_constraints();

    void
    generate_r1cs_witness();

    // Reports the multiplicative constraint cost, for the
    // constraint-budget test and for profiling.
    static constexpr std::size_t
    constraintCount()
    {
        return 8 * 9 + 57 * 3;  // 243
    }

private:
    libsnark::pb_linear_combination<FieldT> left_;
    libsnark::pb_linear_combination<FieldT> right_;
    libsnark::pb_variable<FieldT> output_;

    // Internal wires. Allocated in ctor:
    //   state_[r][lane] is the lane value entering round r for lane in {0,1,2}.
    //   state_[kTotalRounds][lane] is the post-permutation state.
    //
    // Within each round we also need x², x⁴ aux wires for the S-box.
    //   sbox_x2_[r][lane], sbox_x4_[r][lane], sbox_out_[r][lane]
    // (only lane 0 is allocated for partial rounds — the others are unchanged).
    //
    // Mix-layer outputs go into state_[r+1][...].
    std::vector<std::array<libsnark::pb_variable<FieldT>, 3>> state_;
    std::vector<std::array<libsnark::pb_variable<FieldT>, 3>> sbox_x2_;
    std::vector<std::array<libsnark::pb_variable<FieldT>, 3>> sbox_x4_;
    std::vector<std::array<libsnark::pb_variable<FieldT>, 3>> sbox_out_;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_POSEIDON_GADGET_H_INCLUDED
