// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// In-circuit Poseidon-π permutation as a libsnark gadget.
//
// Constraint shape (per round):
//   - Full round:  3 lanes × x→x^5 = 3 × (x*x=x2, x2*x2=x4, x4*x=x5) = 9 mul gates
//   - Partial round: 1 lane × x→x^5 = 3 mul gates
//   - Mix layer is linear in r1cs — costs 0 multiplicative constraints.
//   - Round-constant addition is linear — costs 0 multiplicative constraints.
//
// Total per Poseidon(t=3): 8 * 9 + 57 * 3 = 72 + 171 = 243 mul gates.
// Plus three lane-equality constraints to project initial state into the
// protoboard. The "≈200" in the v2.1 doc is based on the optimised mixing
// layer for partial rounds (Hadeshash partial-round equivalence transform);
// we reach 243 in the unoptimised form, which is the conservative figure
// for the ~74K total estimate. (74000 / 8 entries = 9250 / proof slot;
// each entry uses ≈40 Poseidon calls → ≈9700 mul gates → matches.)

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

    // Reports the multiplicative constraint cost. Used by Phase 2c's
    // constraint-budget test and by Phase 2d's profiling.
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
