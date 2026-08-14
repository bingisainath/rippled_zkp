// Baby Jubjub R1CS gadgets.
//
//   1. BabyJubjubAddGadget — incomplete twisted Edwards addition, about 6
//      multiplicative constraints per call.
//   2. BabyJubjubMulGadget — fixed-base scalar multiplication using the
//      prefix trick to avoid identity-element edge cases, about 1.6K
//      constraints for a 254-bit scalar.
//
// Soundness note: the prefix trick adds (2^254)*G to the accumulator up
// front, so every intermediate addition is between two non-identity points.
// After all 254 bits are processed the known constant offset is removed by
// injecting -((2^254)*G) as the final summand. The off-circuit
// BabyJubjub::mul() reproduces this convention bit-for-bit — it does not
// need the trick itself, but witness generation must agree with the
// in-circuit values.

#ifndef RIPPLE_ZKP_ROLLUP_BABY_JUBJUB_GADGET_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_BABY_JUBJUB_GADGET_H_INCLUDED

#include "BabyJubjub.h"
#include "PoseidonHash.h"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>

namespace ripple {
namespace zkp {
namespace rollup {

// Adds two points (x1,y1), (x2,y2) on Baby Jubjub. Output (x3,y3) is allocated
// by the caller. Uses incomplete formulas — caller must guarantee the inputs
// are non-identity and not opposites.
class BabyJubjubAddGadget : public libsnark::gadget<FieldT>
{
public:
    BabyJubjubAddGadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT> const& x1,
        libsnark::pb_variable<FieldT> const& y1,
        libsnark::pb_variable<FieldT> const& x2,
        libsnark::pb_variable<FieldT> const& y2,
        libsnark::pb_variable<FieldT> const& x3,
        libsnark::pb_variable<FieldT> const& y3,
        std::string const& annotation_prefix);

    void
    generate_r1cs_constraints();
    void
    generate_r1cs_witness();

    static constexpr std::size_t
    constraintCount()
    {
        return 6;  // x1*y2, y1*x2, x1*x2, y1*y2, dxx*yy, then two scaled-eq constraints
    }

private:
    libsnark::pb_variable<FieldT> x1_, y1_, x2_, y2_, x3_, y3_;

    // Auxiliary witnesses.
    libsnark::pb_variable<FieldT> x1y2_, y1x2_, x1x2_, y1y2_;
    libsnark::pb_variable<FieldT> dxx_yy_;  // d * x1x2 * y1y2
    libsnark::pb_variable<FieldT> num_x_, num_y_;
    libsnark::pb_variable<FieldT> denom_x_, denom_y_;
};

// Scalar mul over Baby Jubjub by an N-bit scalar. The scalar is provided as
// a `pb_variable_array<FieldT>` of N bits (LSB-first to match libsnark
// convention). The base point P is provided as (x,y) variables. Output point
// (qx, qy) is allocated by the caller.
//
// Implementation: standard double-and-add scanning bits MSB-first, with the
// prefix-trick (start accumulator at (2^N)·P, end by adding -(2^N)·P).
class BabyJubjubMulGadget : public libsnark::gadget<FieldT>
{
public:
    static constexpr std::size_t kScalarBits = 254;

    BabyJubjubMulGadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT> const& px,
        libsnark::pb_variable<FieldT> const& py,
        libsnark::pb_variable_array<FieldT> const& scalar_bits,
        libsnark::pb_variable<FieldT> const& qx,
        libsnark::pb_variable<FieldT> const& qy,
        std::string const& annotation_prefix);

    void
    generate_r1cs_constraints();
    void
    generate_r1cs_witness();

    static constexpr std::size_t
    constraintCount()
    {
        // Per bit: 2 muxes (8 constraints) + 1 add (6) + 1 dbl (6) ≈ 20.
        // Plus 254 booleanity = 254. Plus final correction add.
        // Conservative figure: 20 * 254 + 254 + 6 = 5340. This will
        // measure exactly.
        return 20 * kScalarBits + kScalarBits + 6;
    }

private:
    libsnark::pb_variable<FieldT> px_, py_;
    libsnark::pb_variable_array<FieldT> bits_;
    libsnark::pb_variable<FieldT> qx_, qy_;

    // Per-bit running accumulator (acc_x[i], acc_y[i]). acc_*[0] = (2^254)·P.
    std::vector<libsnark::pb_variable<FieldT>> acc_x_;
    std::vector<libsnark::pb_variable<FieldT>> acc_y_;

    // Per-bit "double" of the previous accumulator and conditional add result.
    std::vector<libsnark::pb_variable<FieldT>> dbl_x_;
    std::vector<libsnark::pb_variable<FieldT>> dbl_y_;
    std::vector<libsnark::pb_variable<FieldT>> sum_x_;
    std::vector<libsnark::pb_variable<FieldT>> sum_y_;

    // Sub-gadgets.
    std::vector<std::unique_ptr<BabyJubjubAddGadget>> dbl_gadgets_;
    std::vector<std::unique_ptr<BabyJubjubAddGadget>> add_gadgets_;

    // Final correction: subtract (2^254)·P. Implemented via add with negated x.
    libsnark::pb_variable<FieldT> neg_offset_x_, neg_offset_y_;
    std::unique_ptr<BabyJubjubAddGadget> final_correction_gadget_;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_BABY_JUBJUB_GADGET_H_INCLUDED
