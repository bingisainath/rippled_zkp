// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// EdDSAGadget: in-circuit EdDSA-Poseidon verification over Baby Jubjub —
// the one genuinely new cryptographic component of the Phase 6 batch
// circuit (Option A). Composes the existing PoseidonGadget and
// BabyJubjubMul/AddGadget; verifies the scheme defined in EdDSA.h:
//
//   h = H(H(H(R.x, R.y), H(A.x, A.y)), m)      4 × PoseidonGadget
//   [s]·G == R + [h]·A                          2 × BabyJubjubMulGadget
//                                               1 × BabyJubjubAddGadget
//   R on-curve: a·x² + y² = 1 + d·x²·y²         3 mul + 1 linear constraint
//
// Wire interface — all six inputs are allocated by the CALLER (they will be
// witness variables of the enclosing BatchCircuit; A comes from the account
// leaf, R/s from the user's signature, m from the entry data):
//
//   ax, ay : public key A
//   rx, ry : signature commitment R
//   s      : signature response (decomposed to 254 bits in-gadget)
//   msg    : the signed message field element
//
// The gadget has no output wire — it is a pure verification gadget: the
// constraint system is satisfiable iff (R, s) is a valid signature by A
// over msg.
//
// Constraint budget (measured by EdDSAGadget_test):
//   2 × BJJ mul  ≈ 2 × 3820
//   4 × Poseidon =     972
//   add + packs + pins + curve-check ≈ 20
//   total        ≈ 8,600   (below the ~11K planning estimate)
//
// Soundness notes:
//   - h is decomposed to 254 bits with a packing constraint. A malicious
//     prover could use the alias h+p when h < 2^254 − p (≈ a 24% window):
//     this gives at most ONE alternative effective challenge per attempt
//     and does not enable forgery (still requires solving the verification
//     equation for a challenge the prover does not control).
//   - s is range-limited to 254 bits, not < ℓ: (R, s+ℓ) may also satisfy
//     the circuit for the SAME message — benign EdDSA malleability; replay
//     is excluded by the account nonce, not by signature uniqueness.

#ifndef RIPPLE_ZKP_ROLLUP_EDDSA_GADGET_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_EDDSA_GADGET_H_INCLUDED

#include "BabyJubjubGadget.h"
#include "EdDSA.h"
#include "PoseidonGadget.h"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>

#include <memory>

namespace ripple {
namespace zkp {
namespace rollup {

class EdDSAGadget : public libsnark::gadget<FieldT>
{
public:
    EdDSAGadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT> const& ax,
        libsnark::pb_variable<FieldT> const& ay,
        libsnark::pb_variable<FieldT> const& rx,
        libsnark::pb_variable<FieldT> const& ry,
        libsnark::pb_variable<FieldT> const& s,
        libsnark::pb_variable<FieldT> const& msg,
        std::string const& annotation_prefix);

    void
    generate_r1cs_constraints();

    // Caller must have set ax, ay, rx, ry, s, msg on the protoboard first.
    void
    generate_r1cs_witness();

    // Planning estimate (upper bound); the unit test logs the exact figure.
    static constexpr std::size_t
    constraintCountEstimate()
    {
        return 2 * BabyJubjubMulGadget::constraintCount()  // s·G, h·A
             + 4 * PoseidonGadget::constraintCount()       // challenge chain
             + BabyJubjubAddGadget::constraintCount()      // R + h·A
             + 2   // packing s, h
             + 2   // generator pins
             + 2   // final equality
             + 4;  // on-curve check for R
    }

private:
    // Inputs (caller-allocated).
    libsnark::pb_variable<FieldT> ax_, ay_, rx_, ry_, s_, msg_;

    // Challenge chain h1 = H(rx,ry), h2 = H(ax,ay), h3 = H(h1,h2), h = H(h3,msg).
    libsnark::pb_variable<FieldT> h1_, h2_, h3_, h_;
    std::unique_ptr<PoseidonGadget> pose_r_, pose_a_, pose_ra_, pose_h_;

    // Bit decompositions (booleanity enforced inside the mul gadgets).
    libsnark::pb_variable_array<FieldT> s_bits_, h_bits_;
    std::unique_ptr<libsnark::packing_gadget<FieldT>> pack_s_, pack_h_;

    // Generator coordinates, pinned to constants.
    libsnark::pb_variable<FieldT> gx_, gy_;

    // [s]·G and [h]·A and their sum with R.
    libsnark::pb_variable<FieldT> sg_x_, sg_y_, ha_x_, ha_y_, sum_x_, sum_y_;
    std::unique_ptr<BabyJubjubMulGadget> mul_sg_, mul_ha_;
    std::unique_ptr<BabyJubjubAddGadget> add_rha_;

    // On-curve auxiliaries for R.
    libsnark::pb_variable<FieldT> rx2_, ry2_, rx2ry2_;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_EDDSA_GADGET_H_INCLUDED
