// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC

#include "PoseidonGadget.h"
#include "PoseidonConstants.h"
#include "PoseidonHash.h"

namespace ripple {
namespace zkp {
namespace rollup {

using poseidon_params::kFullRounds;
using poseidon_params::kPartialRounds;
using poseidon_params::kT;
using poseidon_params::kTotalRounds;

PoseidonGadget::PoseidonGadget(
    libsnark::protoboard<FieldT>& pb,
    libsnark::pb_linear_combination<FieldT> const& left,
    libsnark::pb_linear_combination<FieldT> const& right,
    libsnark::pb_variable<FieldT> const& output,
    std::string const& annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , left_(left)
    , right_(right)
    , output_(output)
{
    // Allocate the per-round state lanes. We need state_[0..kTotalRounds].
    state_.resize(kTotalRounds + 1);
    sbox_x2_.resize(kTotalRounds);
    sbox_x4_.resize(kTotalRounds);
    sbox_out_.resize(kTotalRounds);

    for (std::size_t r = 0; r <= kTotalRounds; ++r)
    {
        for (std::size_t l = 0; l < 3; ++l)
        {
            state_[r][l].allocate(
                this->pb,
                FMT(annotation_prefix, " state_%zu_%zu", r, l));
        }
    }

    std::size_t const half_full = kFullRounds / 2;

    for (std::size_t r = 0; r < kTotalRounds; ++r)
    {
        bool const is_full = (r < half_full) ||
                             (r >= half_full + kPartialRounds);
        std::size_t const lanes = is_full ? 3 : 1;
        for (std::size_t l = 0; l < lanes; ++l)
        {
            sbox_x2_[r][l].allocate(
                this->pb, FMT(annotation_prefix, " sbox_x2_%zu_%zu", r, l));
            sbox_x4_[r][l].allocate(
                this->pb, FMT(annotation_prefix, " sbox_x4_%zu_%zu", r, l));
            sbox_out_[r][l].allocate(
                this->pb, FMT(annotation_prefix, " sbox_out_%zu_%zu", r, l));
        }
    }
}

void
PoseidonGadget::generate_r1cs_constraints()
{
    auto const& arc = PoseidonHash::debug_arc();
    auto const& mds = PoseidonHash::debug_mds();

    // Initial state injection:
    //   state_[0][0] == 0
    //   state_[0][1] == left
    //   state_[0][2] == right
    // We constrain each by a multiplicative constraint of the form (x - y) * 1 = 0,
    // i.e. one mul gate per equality. (Alternatively use add_r1cs_constraint
    // with `linear_term, ONE, linear_term` style — same constraint count.)
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(state_[0][0], 1, FieldT::zero()),
        FMT(this->annotation_prefix, " init_lane0_zero"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(state_[0][1] - left_, 1, 0),
        FMT(this->annotation_prefix, " init_lane1_left"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(state_[0][2] - right_, 1, 0),
        FMT(this->annotation_prefix, " init_lane2_right"));

    std::size_t const half_full = kFullRounds / 2;

    for (std::size_t r = 0; r < kTotalRounds; ++r)
    {
        bool const is_full = (r < half_full) ||
                             (r >= half_full + kPartialRounds);
        std::size_t const lanes = is_full ? 3 : 1;

        // ----- S-box layer with ARC -----
        // For each S-boxed lane l, let z_l = state_[r][l] + arc[r*3 + l].
        // Constrain: x2 = z * z;  x4 = x2 * x2;  out = x4 * z.
        for (std::size_t l = 0; l < lanes; ++l)
        {
            auto z = state_[r][l] + arc[r * kT + l];

            // x2 = z * z
            this->pb.add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(z, z, sbox_x2_[r][l]),
                FMT(this->annotation_prefix, " sbox_x2_%zu_%zu", r, l));
            // x4 = x2 * x2
            this->pb.add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    sbox_x2_[r][l], sbox_x2_[r][l], sbox_x4_[r][l]),
                FMT(this->annotation_prefix, " sbox_x4_%zu_%zu", r, l));
            // out = x4 * z
            this->pb.add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    sbox_x4_[r][l], z, sbox_out_[r][l]),
                FMT(this->annotation_prefix, " sbox_out_%zu_%zu", r, l));
        }

        // ----- Mix layer -----
        // For each output lane k, build the linear combination
        //   sum_j mds[k*3 + j] * lane_after_sbox[j]
        // where lane_after_sbox[j] is sbox_out_[r][j] for S-boxed lanes,
        // and (state_[r][j] + arc[r*3 + j]) for non-S-boxed lanes (partial rounds).
        for (std::size_t k = 0; k < 3; ++k)
        {
            libsnark::linear_combination<FieldT> lc;
            for (std::size_t j = 0; j < 3; ++j)
            {
                if (j < lanes)
                {
                    lc = lc + mds[k * kT + j] * sbox_out_[r][j];
                }
                else
                {
                    // Non-S-boxed lane in a partial round — value is z_j directly.
                    auto z_j = state_[r][j] + arc[r * kT + j];
                    lc = lc + z_j * mds[k * kT + j];
                }
            }
            // state_[r+1][k] == lc
            this->pb.add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(state_[r + 1][k] - lc, 1, 0),
                FMT(this->annotation_prefix, " mix_%zu_%zu", r, k));
        }
    }

    // Project final state lane 0 onto output_.
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
            output_ - state_[kTotalRounds][0], 1, 0),
        FMT(this->annotation_prefix, " output_eq"));
}

void
PoseidonGadget::generate_r1cs_witness()
{
    auto const& arc = PoseidonHash::debug_arc();
    auto const& mds = PoseidonHash::debug_mds();

    // Evaluate left_/right_ from the linear combinations.
    left_.evaluate(this->pb);
    right_.evaluate(this->pb);
    FieldT const a = this->pb.lc_val(left_);
    FieldT const b = this->pb.lc_val(right_);

    // Lay down state[0].
    this->pb.val(state_[0][0]) = FieldT::zero();
    this->pb.val(state_[0][1]) = a;
    this->pb.val(state_[0][2]) = b;

    std::size_t const half_full = kFullRounds / 2;

    FieldT cur[3] = {
        this->pb.val(state_[0][0]),
        this->pb.val(state_[0][1]),
        this->pb.val(state_[0][2])};

    for (std::size_t r = 0; r < kTotalRounds; ++r)
    {
        bool const is_full = (r < half_full) ||
                             (r >= half_full + kPartialRounds);
        std::size_t const lanes = is_full ? 3 : 1;

        // ARC + S-box.
        FieldT z[3] = {
            cur[0] + arc[r * kT + 0],
            cur[1] + arc[r * kT + 1],
            cur[2] + arc[r * kT + 2]};

        FieldT after_sbox[3] = {z[0], z[1], z[2]};

        for (std::size_t l = 0; l < lanes; ++l)
        {
            FieldT x2 = z[l] * z[l];
            FieldT x4 = x2 * x2;
            FieldT x5 = x4 * z[l];
            this->pb.val(sbox_x2_[r][l]) = x2;
            this->pb.val(sbox_x4_[r][l]) = x4;
            this->pb.val(sbox_out_[r][l]) = x5;
            after_sbox[l] = x5;
        }

        // Mix.
        FieldT next[3];
        for (std::size_t k = 0; k < 3; ++k)
        {
            FieldT acc = FieldT::zero();
            for (std::size_t j = 0; j < 3; ++j)
                acc += mds[k * kT + j] * after_sbox[j];
            next[k] = acc;
            this->pb.val(state_[r + 1][k]) = acc;
        }
        cur[0] = next[0];
        cur[1] = next[1];
        cur[2] = next[2];
    }

    // Output projection.
    this->pb.val(output_) = cur[0];
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
