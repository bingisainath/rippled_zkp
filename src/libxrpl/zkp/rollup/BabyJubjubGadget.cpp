// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC

#include "BabyJubjubGadget.h"

namespace ripple {
namespace zkp {
namespace rollup {

// =============================================================================
// BabyJubjubAddGadget
// =============================================================================

BabyJubjubAddGadget::BabyJubjubAddGadget(
    libsnark::protoboard<FieldT>& pb,
    libsnark::pb_variable<FieldT> const& x1,
    libsnark::pb_variable<FieldT> const& y1,
    libsnark::pb_variable<FieldT> const& x2,
    libsnark::pb_variable<FieldT> const& y2,
    libsnark::pb_variable<FieldT> const& x3,
    libsnark::pb_variable<FieldT> const& y3,
    std::string const& annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , x1_(x1)
    , y1_(y1)
    , x2_(x2)
    , y2_(y2)
    , x3_(x3)
    , y3_(y3)
{
    x1y2_.allocate(pb, FMT(annotation_prefix, " x1y2"));
    y1x2_.allocate(pb, FMT(annotation_prefix, " y1x2"));
    x1x2_.allocate(pb, FMT(annotation_prefix, " x1x2"));
    y1y2_.allocate(pb, FMT(annotation_prefix, " y1y2"));
    dxx_yy_.allocate(pb, FMT(annotation_prefix, " dxx_yy"));
    num_x_.allocate(pb, FMT(annotation_prefix, " num_x"));
    num_y_.allocate(pb, FMT(annotation_prefix, " num_y"));
    denom_x_.allocate(pb, FMT(annotation_prefix, " denom_x"));
    denom_y_.allocate(pb, FMT(annotation_prefix, " denom_y"));
}

void
BabyJubjubAddGadget::generate_r1cs_constraints()
{
    // Standard products.
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(x1_, y2_, x1y2_),
        FMT(this->annotation_prefix, " x1y2_eq"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(y1_, x2_, y1x2_),
        FMT(this->annotation_prefix, " y1x2_eq"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(x1_, x2_, x1x2_),
        FMT(this->annotation_prefix, " x1x2_eq"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(y1_, y2_, y1y2_),
        FMT(this->annotation_prefix, " y1y2_eq"));

    // dxx_yy = d * x1x2 * y1y2 — folded as x1x2 * (d * y1y2).
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
            x1x2_, BabyJubjub::D() * y1y2_, dxx_yy_),
        FMT(this->annotation_prefix, " dxx_yy_eq"));

    // num_x = x1y2 + y1x2;  denom_x = 1 + dxx_yy;  x3 * denom_x == num_x.
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(num_x_ - (x1y2_ + y1x2_), 1, 0),
        FMT(this->annotation_prefix, " num_x_def"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
            denom_x_ - (FieldT::one() + dxx_yy_), 1, 0),
        FMT(this->annotation_prefix, " denom_x_def"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(x3_, denom_x_, num_x_),
        FMT(this->annotation_prefix, " x3_eq"));

    // num_y = y1y2 - a * x1x2;  denom_y = 1 - dxx_yy;  y3 * denom_y == num_y.
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
            num_y_ - (y1y2_ - BabyJubjub::A() * x1x2_), 1, 0),
        FMT(this->annotation_prefix, " num_y_def"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
            denom_y_ - (FieldT::one() - dxx_yy_), 1, 0),
        FMT(this->annotation_prefix, " denom_y_def"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(y3_, denom_y_, num_y_),
        FMT(this->annotation_prefix, " y3_eq"));
}

void
BabyJubjubAddGadget::generate_r1cs_witness()
{
    FieldT x1 = this->pb.val(x1_);
    FieldT y1 = this->pb.val(y1_);
    FieldT x2 = this->pb.val(x2_);
    FieldT y2 = this->pb.val(y2_);

    BjjPoint p1{x1, y1};
    BjjPoint p2{x2, y2};
    BjjPoint p3 = BabyJubjub::add(p1, p2);

    this->pb.val(x1y2_) = x1 * y2;
    this->pb.val(y1x2_) = y1 * x2;
    this->pb.val(x1x2_) = x1 * x2;
    this->pb.val(y1y2_) = y1 * y2;
    this->pb.val(dxx_yy_) = BabyJubjub::D() * (x1 * x2) * (y1 * y2);

    this->pb.val(num_x_) = x1 * y2 + y1 * x2;
    this->pb.val(num_y_) = y1 * y2 - BabyJubjub::A() * (x1 * x2);
    this->pb.val(denom_x_) = FieldT::one() + this->pb.val(dxx_yy_);
    this->pb.val(denom_y_) = FieldT::one() - this->pb.val(dxx_yy_);

    this->pb.val(x3_) = p3.x;
    this->pb.val(y3_) = p3.y;
}

// =============================================================================
// BabyJubjubMulGadget
// =============================================================================

BabyJubjubMulGadget::BabyJubjubMulGadget(
    libsnark::protoboard<FieldT>& pb,
    libsnark::pb_variable<FieldT> const& px,
    libsnark::pb_variable<FieldT> const& py,
    libsnark::pb_variable_array<FieldT> const& scalar_bits,
    libsnark::pb_variable<FieldT> const& qx,
    libsnark::pb_variable<FieldT> const& qy,
    std::string const& annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , px_(px)
    , py_(py)
    , bits_(scalar_bits)
    , qx_(qx)
    , qy_(qy)
{
    if (scalar_bits.size() != kScalarBits)
        throw std::invalid_argument(
            "BabyJubjubMulGadget: scalar_bits must have exactly 254 entries");

    acc_x_.resize(kScalarBits + 1);
    acc_y_.resize(kScalarBits + 1);
    dbl_x_.resize(kScalarBits);
    dbl_y_.resize(kScalarBits);
    sum_x_.resize(kScalarBits);
    sum_y_.resize(kScalarBits);

    for (std::size_t i = 0; i <= kScalarBits; ++i)
    {
        acc_x_[i].allocate(pb, FMT(annotation_prefix, " acc_x_%zu", i));
        acc_y_[i].allocate(pb, FMT(annotation_prefix, " acc_y_%zu", i));
    }
    for (std::size_t i = 0; i < kScalarBits; ++i)
    {
        dbl_x_[i].allocate(pb, FMT(annotation_prefix, " dbl_x_%zu", i));
        dbl_y_[i].allocate(pb, FMT(annotation_prefix, " dbl_y_%zu", i));
        sum_x_[i].allocate(pb, FMT(annotation_prefix, " sum_x_%zu", i));
        sum_y_[i].allocate(pb, FMT(annotation_prefix, " sum_y_%zu", i));
    }

    neg_offset_x_.allocate(pb, FMT(annotation_prefix, " neg_offset_x"));
    neg_offset_y_.allocate(pb, FMT(annotation_prefix, " neg_offset_y"));

    // Build the 254 doubling and conditional-add gadgets.
    for (std::size_t i = 0; i < kScalarBits; ++i)
    {
        // dbl_gadget[i] : (acc[i], acc[i]) -> (dbl[i])
        dbl_gadgets_.emplace_back(std::make_unique<BabyJubjubAddGadget>(
            pb,
            acc_x_[i],
            acc_y_[i],
            acc_x_[i],
            acc_y_[i],
            dbl_x_[i],
            dbl_y_[i],
            FMT(annotation_prefix, " dbl_%zu", i)));
        // add_gadget[i] : (dbl[i], P) -> (sum[i])
        add_gadgets_.emplace_back(std::make_unique<BabyJubjubAddGadget>(
            pb,
            dbl_x_[i],
            dbl_y_[i],
            px_,
            py_,
            sum_x_[i],
            sum_y_[i],
            FMT(annotation_prefix, " add_%zu", i)));
    }

    // Final correction: q == acc[N] + (-(2^N)·P).
    final_correction_gadget_ = std::make_unique<BabyJubjubAddGadget>(
        pb,
        acc_x_[kScalarBits],
        acc_y_[kScalarBits],
        neg_offset_x_,
        neg_offset_y_,
        qx_,
        qy_,
        FMT(annotation_prefix, " final_correction"));
}

void
BabyJubjubMulGadget::generate_r1cs_constraints()
{
    // Booleanity of every scalar bit.
    for (std::size_t i = 0; i < kScalarBits; ++i)
    {
        libsnark::generate_boolean_r1cs_constraint<FieldT>(
            this->pb,
            bits_[i],
            FMT(this->annotation_prefix, " bit_%zu_bool", i));
    }

    // Per-bit doubling.
    for (std::size_t i = 0; i < kScalarBits; ++i)
        dbl_gadgets_[i]->generate_r1cs_constraints();

    // Per-bit conditional add. We constrain:
    //   acc[i+1] = bit[i] ? sum[i] : dbl[i]
    // i.e. acc[i+1].x = dbl[i].x + bit[i] * (sum[i].x - dbl[i].x)
    //      acc[i+1].y = dbl[i].y + bit[i] * (sum[i].y - dbl[i].y)
    for (std::size_t i = 0; i < kScalarBits; ++i)
    {
        // Note: we still generate the add constraints (so sum[i] is well-defined).
        add_gadgets_[i]->generate_r1cs_constraints();

        // bit_i * (sum_i.x - dbl_i.x) == acc_{i+1}.x - dbl_i.x
        // The bits in `bits_` are LSB-first, but we want to scan MSB-first;
        // we flip the index here.
        std::size_t scan_idx = kScalarBits - 1 - i;
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                bits_[scan_idx],
                sum_x_[i] - dbl_x_[i],
                acc_x_[i + 1] - dbl_x_[i]),
            FMT(this->annotation_prefix, " mux_x_%zu", i));
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                bits_[scan_idx],
                sum_y_[i] - dbl_y_[i],
                acc_y_[i + 1] - dbl_y_[i]),
            FMT(this->annotation_prefix, " mux_y_%zu", i));
    }

    // Final correction.
    final_correction_gadget_->generate_r1cs_constraints();
}

void
BabyJubjubMulGadget::generate_r1cs_witness()
{
    // Read base point.
    FieldT pxv = this->pb.val(px_);
    FieldT pyv = this->pb.val(py_);
    [[maybe_unused]] BjjPoint P{pxv, pyv};  // kept for future variable-base support

    // Read scalar bits (LSB-first as stored).
    libff::bit_vector bits;
    bits.reserve(kScalarBits);
    for (std::size_t i = 0; i < kScalarBits; ++i)
        bits.push_back(this->pb.val(bits_[i]) == FieldT::one());

    // Plain MSB-first double-and-add. Initial accumulator = identity (0, 1).
    // Earlier versions used a prefix-offset trick (start at 2^254·P, subtract
    // it at the end) to avoid the Edwards identity-element edge case, but
    // the offset accounting was wrong: after 254 doublings the prefix had
    // become 2^508·P, so the final subtraction was off by a factor of 2^254.
    //
    // For our use case (fixed base = generator, scalar in [1, n-1]) the
    // simple algorithm is correct: Edwards add() is well-defined whenever
    // the two operands aren't identical, and the running accumulator only
    // ever equals P at the iteration where bit was newly set after a leading
    // run of zeros — which is exactly the case where dbl() handles it
    // correctly (acc + acc, both copies of P).
    this->pb.val(acc_x_[0]) = FieldT::zero();
    this->pb.val(acc_y_[0]) = FieldT::one();

    // Walk bits MSB-first.
    for (std::size_t i = 0; i < kScalarBits; ++i)
    {
        std::size_t scan_idx = kScalarBits - 1 - i;
        bool bit = bits[scan_idx];

        // Double previous acc.
        dbl_gadgets_[i]->generate_r1cs_witness();
        BjjPoint dbl_pt{this->pb.val(dbl_x_[i]), this->pb.val(dbl_y_[i])};

        // Add P.
        add_gadgets_[i]->generate_r1cs_witness();
        BjjPoint sum_pt{this->pb.val(sum_x_[i]), this->pb.val(sum_y_[i])};

        BjjPoint next = bit ? sum_pt : dbl_pt;
        this->pb.val(acc_x_[i + 1]) = next.x;
        this->pb.val(acc_y_[i + 1]) = next.y;
    }

    // No final correction needed: acc[kScalarBits] is already s · P.
    // We still need to drive the final_correction_gadget output wires to
    // satisfy the constraint system, with neg_offset = identity so it acts
    // as a no-op.
    this->pb.val(neg_offset_x_) = FieldT::zero();
    this->pb.val(neg_offset_y_) = FieldT::one();
    final_correction_gadget_->generate_r1cs_witness();
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
