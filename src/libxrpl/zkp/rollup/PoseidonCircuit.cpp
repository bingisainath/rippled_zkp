// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC

#include "PoseidonCircuit.h"

#include <libsnark/gadgetlib1/protoboard.hpp>

namespace ripple {
namespace zkp {
namespace rollup {

class PoseidonCircuit::Impl
{
public:
    explicit Impl(std::size_t tree_depth) : tree_depth_(tree_depth)
    {
        if (tree_depth_ == 0 || tree_depth_ > 64)
            throw std::invalid_argument(
                "PoseidonCircuit: tree_depth must be in [1, 64]");

        PoseidonHash::initialize();
        BabyJubjub::initialize();

        pb_ = std::make_shared<libsnark::protoboard<FieldT>>();

        // ----- Allocate primary inputs -----
        anchor_.allocate(*pb_, "anchor");
        new_anchor_.allocate(*pb_, "new_anchor");
        nullifier_.allocate(*pb_, "nullifier");
        value_pub_.allocate(*pb_, "value_pub");
        pb_->set_input_sizes(4);

        // ----- Allocate auxiliary inputs -----
        // Note 1 (old / spent)
        value_.allocate(*pb_, "value");
        rho_.allocate(*pb_, "rho");
        r_.allocate(*pb_, "r");

        // BJJ scalar bits and apk
        ask_bits_.allocate(*pb_, BabyJubjubMulGadget::kScalarBits, "ask_bits");
        gx_.allocate(*pb_, "gx");
        gy_.allocate(*pb_, "gy");
        apk_x_.allocate(*pb_, "apk_x");
        apk_y_.allocate(*pb_, "apk_y");

        // ask packed (for nullifier hash)
        ask_packed_.allocate(*pb_, "ask_packed");

        // Intermediate Poseidon outputs for cm
        cm_half1_.allocate(*pb_, "cm_half1");
        cm_half2_.allocate(*pb_, "cm_half2");
        cm_.allocate(*pb_, "cm");

        // New note's commitment slot
        new_value_.allocate(*pb_, "new_value");
        new_rho_.allocate(*pb_, "new_rho");
        new_r_.allocate(*pb_, "new_r");
        new_cm_half1_.allocate(*pb_, "new_cm_half1");
        new_cm_half2_.allocate(*pb_, "new_cm_half2");
        new_cm_.allocate(*pb_, "new_cm");

        // Auth path & per-level state
        leaf_pos_bits_.allocate(*pb_, tree_depth_, "leaf_pos_bits");
        auth_old_.resize(tree_depth_);
        auth_new_.resize(tree_depth_);
        path_old_.resize(tree_depth_ + 1);
        path_new_.resize(tree_depth_ + 1);
        for (std::size_t i = 0; i < tree_depth_; ++i)
        {
            auth_old_[i].allocate(*pb_, FMT("", "auth_old_%zu", i));
            auth_new_[i].allocate(*pb_, FMT("", "auth_new_%zu", i));
        }
        for (std::size_t i = 0; i <= tree_depth_; ++i)
        {
            path_old_[i].allocate(*pb_, FMT("", "path_old_%zu", i));
            path_new_[i].allocate(*pb_, FMT("", "path_new_%zu", i));
        }

        // Per-level "left/right" muxed wires.
        left_old_.resize(tree_depth_);
        right_old_.resize(tree_depth_);
        left_new_.resize(tree_depth_);
        right_new_.resize(tree_depth_);
        for (std::size_t i = 0; i < tree_depth_; ++i)
        {
            left_old_[i].allocate(*pb_, FMT("", "left_old_%zu", i));
            right_old_[i].allocate(*pb_, FMT("", "right_old_%zu", i));
            left_new_[i].allocate(*pb_, FMT("", "left_new_%zu", i));
            right_new_[i].allocate(*pb_, FMT("", "right_new_%zu", i));
        }
    }

    void
    generateConstraints()
    {
        if (constraints_built_)
            return;

        // ===== 1. Pin generator coordinates =====
        // gx, gy are constants (BJJ generator). Constrain them equal to
        // the off-circuit values.
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                gx_ - BabyJubjub::generator().x, 1, 0),
            "gx_const");
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                gy_ - BabyJubjub::generator().y, 1, 0),
            "gy_const");

        // ===== 2. apk = [ask] · G =====
        bjj_mul_ = std::make_unique<BabyJubjubMulGadget>(
            *pb_, gx_, gy_, ask_bits_, apk_x_, apk_y_, "bjj_mul");
        bjj_mul_->generate_r1cs_constraints();

        // ===== 3. ask_packed must equal sum(bit_i * 2^i) =====
        // Pack ask bits back into a field element for the nullifier.
        libsnark::packing_gadget<FieldT> ask_pack(
            *pb_, ask_bits_, ask_packed_, "ask_pack");
        ask_pack.generate_r1cs_constraints(false);
        // Note: false = bits already enforced boolean by bjj_mul_.

        // ===== 4. Commitment cm = Poseidon(Poseidon(value,rho), Poseidon(r,apk_x)) =====
        cm_h1_gadget_ = std::make_unique<PoseidonGadget>(
            *pb_, value_, rho_, cm_half1_, "cm_h1");
        cm_h1_gadget_->generate_r1cs_constraints();

        cm_h2_gadget_ = std::make_unique<PoseidonGadget>(
            *pb_, r_, apk_x_, cm_half2_, "cm_h2");
        cm_h2_gadget_->generate_r1cs_constraints();

        cm_gadget_ = std::make_unique<PoseidonGadget>(
            *pb_, cm_half1_, cm_half2_, cm_, "cm");
        cm_gadget_->generate_r1cs_constraints();

        // ===== 5. Nullifier nf = Poseidon(ask, rho) =====
        nf_gadget_ = std::make_unique<PoseidonGadget>(
            *pb_, ask_packed_, rho_, nullifier_, "nf");
        nf_gadget_->generate_r1cs_constraints();

        // ===== 6. value_pub == value =====
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(value_pub_ - value_, 1, 0),
            "value_pub_eq");

        // ===== 7. New commitment (same structure, fresh rho/r) =====
        new_cm_h1_gadget_ = std::make_unique<PoseidonGadget>(
            *pb_, new_value_, new_rho_, new_cm_half1_, "new_cm_h1");
        new_cm_h1_gadget_->generate_r1cs_constraints();

        new_cm_h2_gadget_ = std::make_unique<PoseidonGadget>(
            *pb_, new_r_, apk_x_, new_cm_half2_, "new_cm_h2");
        new_cm_h2_gadget_->generate_r1cs_constraints();

        new_cm_gadget_ = std::make_unique<PoseidonGadget>(
            *pb_, new_cm_half1_, new_cm_half2_, new_cm_, "new_cm");
        new_cm_gadget_->generate_r1cs_constraints();

        // ===== 8. Merkle auth path: cm hashes up to anchor =====
        // path_old_[0] = cm.
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(path_old_[0] - cm_, 1, 0),
            "path_old_base");
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(path_new_[0] - new_cm_, 1, 0),
            "path_new_base");

        for (std::size_t i = 0; i < tree_depth_; ++i)
        {
            // Booleanity of leaf_pos bit
            libsnark::generate_boolean_r1cs_constraint<FieldT>(
                *pb_,
                leaf_pos_bits_[i],
                FMT("", "leaf_pos_bool_%zu", i));

            // Mux:
            //   if bit == 0: left = path[i], right = sibling
            //   if bit == 1: left = sibling, right = path[i]
            // Use the standard linear-formula trick:
            //   left  = path[i] + bit * (sibling - path[i])
            //   right = sibling + bit * (path[i] - sibling)
            pb_->add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    leaf_pos_bits_[i],
                    auth_old_[i] - path_old_[i],
                    left_old_[i] - path_old_[i]),
                FMT("", "mux_left_old_%zu", i));
            pb_->add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    leaf_pos_bits_[i],
                    path_old_[i] - auth_old_[i],
                    right_old_[i] - auth_old_[i]),
                FMT("", "mux_right_old_%zu", i));

            pb_->add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    leaf_pos_bits_[i],
                    auth_new_[i] - path_new_[i],
                    left_new_[i] - path_new_[i]),
                FMT("", "mux_left_new_%zu", i));
            pb_->add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    leaf_pos_bits_[i],
                    path_new_[i] - auth_new_[i],
                    right_new_[i] - auth_new_[i]),
                FMT("", "mux_right_new_%zu", i));

            // path[i+1] = Poseidon(left, right)
            level_old_gadgets_.emplace_back(std::make_unique<PoseidonGadget>(
                *pb_,
                left_old_[i],
                right_old_[i],
                path_old_[i + 1],
                FMT("", "level_old_%zu", i)));
            level_old_gadgets_.back()->generate_r1cs_constraints();

            level_new_gadgets_.emplace_back(std::make_unique<PoseidonGadget>(
                *pb_,
                left_new_[i],
                right_new_[i],
                path_new_[i + 1],
                FMT("", "level_new_%zu", i)));
            level_new_gadgets_.back()->generate_r1cs_constraints();
        }

        // path_old_[depth] == anchor; path_new_[depth] == new_anchor.
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                path_old_[tree_depth_] - anchor_, 1, 0),
            "anchor_eq");
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                path_new_[tree_depth_] - new_anchor_, 1, 0),
            "new_anchor_eq");

        constraints_built_ = true;
    }

    void
    generateWitness(
        RollupNote const& old_note,
        RollupNote const& new_note,
        std::vector<bool> const& leaf_pos,
        std::vector<FieldT> const& auth_path_old,
        std::vector<FieldT> const& auth_path_new,
        FieldT const& prev_root,
        FieldT const& new_root)
    {
        if (!constraints_built_)
            throw std::logic_error(
                "PoseidonCircuit::generateWitness called before "
                "generateConstraints");
        if (leaf_pos.size() != tree_depth_)
            throw std::invalid_argument(
                "leaf_pos length must equal tree_depth");
        if (auth_path_old.size() != tree_depth_ ||
            auth_path_new.size() != tree_depth_)
            throw std::invalid_argument(
                "auth path length must equal tree_depth");

        // Public inputs
        pb_->val(anchor_) = prev_root;
        pb_->val(new_anchor_) = new_root;
        pb_->val(value_pub_) = FieldT(old_note.value);

        // Old note privates
        pb_->val(value_) = FieldT(old_note.value);
        pb_->val(rho_) = old_note.rho;
        pb_->val(r_) = old_note.r;

        // BJJ scalar bits (LSB-first decomposition of `ask`)
        libff::bigint<libff::alt_bn128_r_limbs> ask_bn = old_note.ask.as_bigint();
        for (std::size_t i = 0; i < BabyJubjubMulGadget::kScalarBits; ++i)
        {
            pb_->val(ask_bits_[i]) =
                ask_bn.test_bit(i) ? FieldT::one() : FieldT::zero();
        }

        // Generator constants
        pb_->val(gx_) = BabyJubjub::generator().x;
        pb_->val(gy_) = BabyJubjub::generator().y;

        // Run BJJ scalar mul witness generation -> apk_x, apk_y
        bjj_mul_->generate_r1cs_witness();

        // Pack ask bits back
        FieldT ask_acc = FieldT::zero();
        FieldT pow2 = FieldT::one();
        for (std::size_t i = 0; i < BabyJubjubMulGadget::kScalarBits; ++i)
        {
            if (pb_->val(ask_bits_[i]) == FieldT::one())
                ask_acc += pow2;
            pow2 = pow2 + pow2;
        }
        pb_->val(ask_packed_) = ask_acc;

        // cm and nf
        cm_h1_gadget_->generate_r1cs_witness();
        cm_h2_gadget_->generate_r1cs_witness();
        cm_gadget_->generate_r1cs_witness();
        nf_gadget_->generate_r1cs_witness();
        pb_->val(nullifier_) = pb_->lc_val(nullifier_);

        // New note privates and new cm
        pb_->val(new_value_) = FieldT(new_note.value);
        pb_->val(new_rho_) = new_note.rho;
        pb_->val(new_r_) = new_note.r;
        new_cm_h1_gadget_->generate_r1cs_witness();
        new_cm_h2_gadget_->generate_r1cs_witness();
        new_cm_gadget_->generate_r1cs_witness();

        // Auth path bits and siblings
        for (std::size_t i = 0; i < tree_depth_; ++i)
        {
            pb_->val(leaf_pos_bits_[i]) =
                leaf_pos[i] ? FieldT::one() : FieldT::zero();
            pb_->val(auth_old_[i]) = auth_path_old[i];
            pb_->val(auth_new_[i]) = auth_path_new[i];
        }

        // Walk up
        pb_->val(path_old_[0]) = pb_->val(cm_);
        pb_->val(path_new_[0]) = pb_->val(new_cm_);
        for (std::size_t i = 0; i < tree_depth_; ++i)
        {
            FieldT cur_old = pb_->val(path_old_[i]);
            FieldT cur_new = pb_->val(path_new_[i]);
            FieldT sib_old = pb_->val(auth_old_[i]);
            FieldT sib_new = pb_->val(auth_new_[i]);
            bool bit = leaf_pos[i];

            FieldT left_o = bit ? sib_old : cur_old;
            FieldT right_o = bit ? cur_old : sib_old;
            FieldT left_n = bit ? sib_new : cur_new;
            FieldT right_n = bit ? cur_new : sib_new;
            pb_->val(left_old_[i]) = left_o;
            pb_->val(right_old_[i]) = right_o;
            pb_->val(left_new_[i]) = left_n;
            pb_->val(right_new_[i]) = right_n;

            level_old_gadgets_[i]->generate_r1cs_witness();
            level_new_gadgets_[i]->generate_r1cs_witness();
        }
    }

    libsnark::r1cs_constraint_system<FieldT>
    getConstraintSystem() const
    {
        return pb_->get_constraint_system();
    }
    libsnark::r1cs_primary_input<FieldT>
    getPrimaryInput() const
    {
        return pb_->primary_input();
    }
    libsnark::r1cs_auxiliary_input<FieldT>
    getAuxiliaryInput() const
    {
        return pb_->auxiliary_input();
    }
    std::size_t
    constraintCount() const
    {
        return pb_->num_constraints();
    }
    std::size_t
    treeDepth() const
    {
        return tree_depth_;
    }

private:
    std::size_t tree_depth_;
    std::shared_ptr<libsnark::protoboard<FieldT>> pb_;
    bool constraints_built_ = false;

    // Public
    libsnark::pb_variable<FieldT> anchor_, new_anchor_, nullifier_, value_pub_;

    // Private — old note
    libsnark::pb_variable<FieldT> value_, rho_, r_;
    libsnark::pb_variable_array<FieldT> ask_bits_;
    libsnark::pb_variable<FieldT> ask_packed_;
    libsnark::pb_variable<FieldT> gx_, gy_, apk_x_, apk_y_;
    libsnark::pb_variable<FieldT> cm_half1_, cm_half2_, cm_;

    // Private — new note
    libsnark::pb_variable<FieldT> new_value_, new_rho_, new_r_;
    libsnark::pb_variable<FieldT> new_cm_half1_, new_cm_half2_, new_cm_;

    // Auth path
    libsnark::pb_variable_array<FieldT> leaf_pos_bits_;
    std::vector<libsnark::pb_variable<FieldT>> auth_old_, auth_new_;
    std::vector<libsnark::pb_variable<FieldT>> path_old_, path_new_;
    std::vector<libsnark::pb_variable<FieldT>> left_old_, right_old_;
    std::vector<libsnark::pb_variable<FieldT>> left_new_, right_new_;

    // Sub-gadgets
    std::unique_ptr<BabyJubjubMulGadget> bjj_mul_;
    std::unique_ptr<PoseidonGadget> cm_h1_gadget_, cm_h2_gadget_, cm_gadget_;
    std::unique_ptr<PoseidonGadget> new_cm_h1_gadget_, new_cm_h2_gadget_,
        new_cm_gadget_;
    std::unique_ptr<PoseidonGadget> nf_gadget_;
    std::vector<std::unique_ptr<PoseidonGadget>> level_old_gadgets_;
    std::vector<std::unique_ptr<PoseidonGadget>> level_new_gadgets_;
};

PoseidonCircuit::PoseidonCircuit(std::size_t tree_depth)
    : impl_(std::make_unique<Impl>(tree_depth))
{
}

PoseidonCircuit::~PoseidonCircuit() = default;

void
PoseidonCircuit::generateConstraints()
{
    impl_->generateConstraints();
}

void
PoseidonCircuit::generateWitness(
    RollupNote const& old_note,
    RollupNote const& new_note,
    std::vector<bool> const& leaf_pos,
    std::vector<FieldT> const& auth_path_old,
    std::vector<FieldT> const& auth_path_new,
    FieldT const& prev_root,
    FieldT const& new_root)
{
    impl_->generateWitness(
        old_note, new_note, leaf_pos, auth_path_old, auth_path_new,
        prev_root, new_root);
}

FieldT
PoseidonCircuit::empty_tree_root(std::size_t depth)
{
    PoseidonHash::initialize();
    FieldT cur = PoseidonHash::zeroZero();  // empty_hashes_[0]
    for (std::size_t i = 1; i < depth; ++i)
        cur = PoseidonHash::hash(cur, cur);
    return cur;
}

libsnark::r1cs_constraint_system<FieldT>
PoseidonCircuit::getConstraintSystem() const
{
    return impl_->getConstraintSystem();
}
libsnark::r1cs_primary_input<FieldT>
PoseidonCircuit::getPrimaryInput() const
{
    return impl_->getPrimaryInput();
}
libsnark::r1cs_auxiliary_input<FieldT>
PoseidonCircuit::getAuxiliaryInput() const
{
    return impl_->getAuxiliaryInput();
}
std::size_t
PoseidonCircuit::constraintCount() const
{
    return impl_->constraintCount();
}
std::size_t
PoseidonCircuit::treeDepth() const
{
    return impl_->treeDepth();
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
