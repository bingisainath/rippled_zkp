// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// In-circuit EdDSA-Poseidon verification. See EdDSAGadget.h.

#include "EdDSAGadget.h"

namespace ripple {
namespace zkp {
namespace rollup {

EdDSAGadget::EdDSAGadget(
    libsnark::protoboard<FieldT>& pb,
    libsnark::pb_variable<FieldT> const& ax,
    libsnark::pb_variable<FieldT> const& ay,
    libsnark::pb_variable<FieldT> const& rx,
    libsnark::pb_variable<FieldT> const& ry,
    libsnark::pb_variable<FieldT> const& s,
    libsnark::pb_variable<FieldT> const& msg,
    std::string const& annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , ax_(ax)
    , ay_(ay)
    , rx_(rx)
    , ry_(ry)
    , s_(s)
    , msg_(msg)
{
    // ----- challenge chain wires -----
    h1_.allocate(pb, FMT(annotation_prefix, " h1"));
    h2_.allocate(pb, FMT(annotation_prefix, " h2"));
    h3_.allocate(pb, FMT(annotation_prefix, " h3"));
    h_.allocate(pb, FMT(annotation_prefix, " h"));

    pose_r_ = std::make_unique<PoseidonGadget>(
        pb, rx_, ry_, h1_, FMT(annotation_prefix, " pose_r"));
    pose_a_ = std::make_unique<PoseidonGadget>(
        pb, ax_, ay_, h2_, FMT(annotation_prefix, " pose_a"));
    pose_ra_ = std::make_unique<PoseidonGadget>(
        pb, h1_, h2_, h3_, FMT(annotation_prefix, " pose_ra"));
    pose_h_ = std::make_unique<PoseidonGadget>(
        pb, h3_, msg_, h_, FMT(annotation_prefix, " pose_h"));

    // ----- bit decompositions -----
    s_bits_.allocate(
        pb, BabyJubjubMulGadget::kScalarBits, FMT(annotation_prefix, " s_bits"));
    h_bits_.allocate(
        pb, BabyJubjubMulGadget::kScalarBits, FMT(annotation_prefix, " h_bits"));

    pack_s_ = std::make_unique<libsnark::packing_gadget<FieldT>>(
        pb, s_bits_, s_, FMT(annotation_prefix, " pack_s"));
    pack_h_ = std::make_unique<libsnark::packing_gadget<FieldT>>(
        pb, h_bits_, h_, FMT(annotation_prefix, " pack_h"));

    // ----- generator (pinned to constants in constraints) -----
    gx_.allocate(pb, FMT(annotation_prefix, " gx"));
    gy_.allocate(pb, FMT(annotation_prefix, " gy"));

    // ----- scalar muls and the RHS sum -----
    sg_x_.allocate(pb, FMT(annotation_prefix, " sg_x"));
    sg_y_.allocate(pb, FMT(annotation_prefix, " sg_y"));
    ha_x_.allocate(pb, FMT(annotation_prefix, " ha_x"));
    ha_y_.allocate(pb, FMT(annotation_prefix, " ha_y"));
    sum_x_.allocate(pb, FMT(annotation_prefix, " sum_x"));
    sum_y_.allocate(pb, FMT(annotation_prefix, " sum_y"));

    mul_sg_ = std::make_unique<BabyJubjubMulGadget>(
        pb, gx_, gy_, s_bits_, sg_x_, sg_y_, FMT(annotation_prefix, " mul_sG"));
    mul_ha_ = std::make_unique<BabyJubjubMulGadget>(
        pb, ax_, ay_, h_bits_, ha_x_, ha_y_, FMT(annotation_prefix, " mul_hA"));
    add_rha_ = std::make_unique<BabyJubjubAddGadget>(
        pb,
        rx_,
        ry_,
        ha_x_,
        ha_y_,
        sum_x_,
        sum_y_,
        FMT(annotation_prefix, " add_R_hA"));

    // ----- on-curve auxiliaries for R -----
    rx2_.allocate(pb, FMT(annotation_prefix, " rx2"));
    ry2_.allocate(pb, FMT(annotation_prefix, " ry2"));
    rx2ry2_.allocate(pb, FMT(annotation_prefix, " rx2ry2"));
}

void
EdDSAGadget::generate_r1cs_constraints()
{
    // Pin generator coordinates (same pattern as PoseidonCircuit).
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
            gx_ - BabyJubjub::generator().x, 1, 0),
        FMT(this->annotation_prefix, " gx_const"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
            gy_ - BabyJubjub::generator().y, 1, 0),
        FMT(this->annotation_prefix, " gy_const"));

    // Challenge chain.
    pose_r_->generate_r1cs_constraints();
    pose_a_->generate_r1cs_constraints();
    pose_ra_->generate_r1cs_constraints();
    pose_h_->generate_r1cs_constraints();

    // Bit packings. Booleanity of both arrays is enforced by the mul gadgets,
    // so packing only needs the linear sum constraint.
    pack_s_->generate_r1cs_constraints(false);
    pack_h_->generate_r1cs_constraints(false);

    // [s]·G and [h]·A.
    mul_sg_->generate_r1cs_constraints();
    mul_ha_->generate_r1cs_constraints();

    // R + [h]·A.
    add_rha_->generate_r1cs_constraints();

    // [s]·G == R + [h]·A.
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(sg_x_ - sum_x_, 1, 0),
        FMT(this->annotation_prefix, " eq_x"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(sg_y_ - sum_y_, 1, 0),
        FMT(this->annotation_prefix, " eq_y"));

    // R on-curve: a·rx² + ry² == 1 + d·rx²·ry².
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(rx_, rx_, rx2_),
        FMT(this->annotation_prefix, " rx_sq"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(ry_, ry_, ry2_),
        FMT(this->annotation_prefix, " ry_sq"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(rx2_, ry2_, rx2ry2_),
        FMT(this->annotation_prefix, " rx2ry2"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
            BabyJubjub::A() * rx2_ + ry2_ - BabyJubjub::D() * rx2ry2_
                - FieldT::one(),
            1,
            0),
        FMT(this->annotation_prefix, " r_on_curve"));
}

void
EdDSAGadget::generate_r1cs_witness()
{
    // Inputs (ax, ay, rx, ry, s, msg) must already be on the protoboard.

    // Challenge chain — each Poseidon gadget reads its inputs off the pb.
    pose_r_->generate_r1cs_witness();
    pose_a_->generate_r1cs_witness();
    pose_ra_->generate_r1cs_witness();
    pose_h_->generate_r1cs_witness();

    // Decompose s and h into bits (fills the bit arrays from the packed
    // values already on the protoboard).
    pack_s_->generate_r1cs_witness_from_packed();
    pack_h_->generate_r1cs_witness_from_packed();

    // Generator.
    this->pb.val(gx_) = BabyJubjub::generator().x;
    this->pb.val(gy_) = BabyJubjub::generator().y;

    // Scalar muls, then the RHS sum.
    mul_sg_->generate_r1cs_witness();
    mul_ha_->generate_r1cs_witness();
    add_rha_->generate_r1cs_witness();

    // On-curve auxiliaries.
    FieldT const rxv = this->pb.val(rx_);
    FieldT const ryv = this->pb.val(ry_);
    this->pb.val(rx2_) = rxv * rxv;
    this->pb.val(ry2_) = ryv * ryv;
    this->pb.val(rx2ry2_) = this->pb.val(rx2_) * this->pb.val(ry2_);
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
