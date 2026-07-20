// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// BatchCircuit implementation. Statement and conventions: BatchCircuit.h.
// Gadget composition mirrors PoseidonCircuit.cpp (Impl idiom, mux pattern).

#include "BatchCircuit.h"

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

#include <stdexcept>

namespace ripple {
namespace zkp {
namespace rollup {

namespace {

FieldT const&
twoPow64()
{
    static FieldT const v = []() {
        FieldT two = FieldT(2);
        FieldT r = FieldT::one();
        for (int i = 0; i < 64; ++i)
            r = r * two;
        return r;
    }();
    return v;
}

FieldT const&
twoPow128()
{
    static FieldT const v = twoPow64() * twoPow64();
    return v;
}

constexpr std::size_t kRangeBits = 64;

}  // anonymous namespace

// ===========================================================================
// Impl
// ===========================================================================

class BatchCircuit::Impl
{
public:
    Impl(std::size_t batch_size, std::size_t tree_depth)
        : batch_size_(batch_size), tree_depth_(tree_depth)
    {
        if (batch_size_ == 0)
            throw std::invalid_argument("BatchCircuit: batch_size == 0");
        if (tree_depth_ == 0)
            throw std::invalid_argument("BatchCircuit: tree_depth == 0");

        pb_ = std::make_unique<libsnark::protoboard<FieldT>>();

        // ----- Public inputs MUST be the first allocated wires -----
        prev_root_.allocate(*pb_, "prev_root");
        new_root_.allocate(*pb_, "new_root");
        entries_hash_.allocate(*pb_, "entries_hash");
        pb_->set_input_sizes(3);

        // ----- Global chain wires -----
        roots_.resize(batch_size_ + 1);
        eh_.resize(batch_size_ + 1);
        for (std::size_t i = 0; i <= batch_size_; ++i)
        {
            roots_[i].allocate(*pb_, FMT("", "root_%zu", i));
            eh_[i].allocate(*pb_, FMT("", "eh_%zu", i));
        }

        // ----- Per-entry wires and sub-gadgets -----
        entries_.resize(batch_size_);
        for (std::size_t i = 0; i < batch_size_; ++i)
            allocateEntry(i);
    }

    void
    generateConstraints()
    {
        if (constraints_built_)
            return;

        // Chain glue.
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(roots_[0] - prev_root_, 1, 0),
            "root0_is_prev");
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                roots_[batch_size_] - new_root_, 1, 0),
            "rootN_is_new");
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(eh_[0], 1, 0), "eh0_is_zero");
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                eh_[batch_size_] - entries_hash_, 1, 0),
            "ehN_is_public");

        for (std::size_t i = 0; i < batch_size_; ++i)
            constrainEntry(i);

        constraints_built_ = true;
    }

    void
    generateWitness(
        FieldT const& prev_root,
        std::vector<BatchEntryWitness> const& ews)
    {
        if (!constraints_built_)
            throw std::logic_error(
                "BatchCircuit::generateWitness before generateConstraints");
        if (ews.size() != batch_size_)
            throw std::invalid_argument(
                "BatchCircuit: entries.size() != batch_size");

        pb_->val(prev_root_) = prev_root;
        pb_->val(roots_[0]) = prev_root;
        pb_->val(eh_[0]) = FieldT::zero();

        for (std::size_t i = 0; i < batch_size_; ++i)
            witnessEntry(i, ews[i]);

        pb_->val(new_root_) = pb_->val(roots_[batch_size_]);
        pb_->val(entries_hash_) = pb_->val(eh_[batch_size_]);
    }

    // ------------------------------------------------------------------
    std::unique_ptr<libsnark::protoboard<FieldT>> pb_;
    std::size_t const batch_size_;
    std::size_t const tree_depth_;
    bool constraints_built_ = false;

    // Public.
    libsnark::pb_variable<FieldT> prev_root_, new_root_, entries_hash_;

    // Global chains.
    std::vector<libsnark::pb_variable<FieldT>> roots_;  // r_0 .. r_N
    std::vector<libsnark::pb_variable<FieldT>> eh_;     // eh_0 .. eh_N

    struct EntryWires
    {
        // Request data.
        libsnark::pb_variable<FieldT> from_x, from_y, dest;
        libsnark::pb_variable<FieldT> value, nonce, old_bal, new_bal;
        libsnark::pb_variable<FieldT> t0, t1, w;  // type bits, w = t0*t1
        libsnark::pb_variable<FieldT> is_create, dv;  // dv = t0*value
        libsnark::pb_variable<FieldT> is_xfer, xv;  // is_xfer = t1-w; xv = *value

        // Recipient leg (Transfer). mid = root after the sender's update.
        libsnark::pb_variable<FieldT> mid;
        libsnark::pb_variable<FieldT> to_x, to_old_bal, to_nonce, to_new_bal;
        libsnark::pb_variable<FieldT> to_old_packed, to_new_packed;
        libsnark::pb_variable<FieldT> to_old_pose, to_new_pose;
        libsnark::pb_variable<FieldT> to_base_o, to_base_n;

        // Hash wires.
        libsnark::pb_variable<FieldT> meta, m1, msg;
        libsnark::pb_variable<FieldT> old_packed, old_pose, old_used;
        libsnark::pb_variable<FieldT> new_packed, new_pose, new_base;

        // Signature.
        libsnark::pb_variable<FieldT> rx, ry, s;

        // from_apk on-curve auxiliaries.
        libsnark::pb_variable<FieldT> ax2, ay2, ax2y2;

        // Range-check bit arrays.
        libsnark::pb_variable_array<FieldT> value_bits, nonce_bits,
            old_bal_bits, new_bal_bits;
        libsnark::pb_variable_array<FieldT> to_old_bal_bits, to_nonce_bits,
            to_new_bal_bits;

        // Merkle path (sender).
        libsnark::pb_variable_array<FieldT> pos_bits;
        std::vector<libsnark::pb_variable<FieldT>> auth;
        std::vector<libsnark::pb_variable<FieldT>> po, pn;  // depth+1 each
        std::vector<libsnark::pb_variable<FieldT>> lo, ro, ln, rn;

        // Merkle path (recipient): mid -> roots_[i+1].
        libsnark::pb_variable_array<FieldT> to_pos_bits;
        std::vector<libsnark::pb_variable<FieldT>> to_auth;
        std::vector<libsnark::pb_variable<FieldT>> qo, qn;  // depth+1 each
        std::vector<libsnark::pb_variable<FieldT>> qlo, qro, qln, qrn;

        // Gadgets.
        std::unique_ptr<PoseidonGadget> g_m1, g_msg, g_old, g_new, g_eh;
        std::unique_ptr<PoseidonGadget> g_to_old, g_to_new;
        std::unique_ptr<EdDSAGadget> g_sig;
        std::unique_ptr<libsnark::packing_gadget<FieldT>> g_value_range,
            g_nonce_range, g_old_bal_range, g_new_bal_range,
            g_to_old_bal_range, g_to_nonce_range, g_to_new_bal_range;
        std::vector<std::unique_ptr<PoseidonGadget>> g_po, g_pn, g_qo, g_qn;
    };
    std::vector<EntryWires> entries_;

private:
    void
    allocateEntry(std::size_t i)
    {
        auto& e = entries_[i];
        auto n = [i](char const* base) {
            return FMT("", "e%zu_%s", i, base);
        };

        e.from_x.allocate(*pb_, n("from_x"));
        e.from_y.allocate(*pb_, n("from_y"));
        e.dest.allocate(*pb_, n("dest"));
        e.value.allocate(*pb_, n("value"));
        e.nonce.allocate(*pb_, n("nonce"));
        e.old_bal.allocate(*pb_, n("old_bal"));
        e.new_bal.allocate(*pb_, n("new_bal"));
        e.t0.allocate(*pb_, n("t0"));
        e.t1.allocate(*pb_, n("t1"));
        e.w.allocate(*pb_, n("w"));
        e.is_create.allocate(*pb_, n("is_create"));
        e.dv.allocate(*pb_, n("dv"));
        e.is_xfer.allocate(*pb_, n("is_xfer"));
        e.xv.allocate(*pb_, n("xv"));

        e.mid.allocate(*pb_, n("mid"));
        e.to_x.allocate(*pb_, n("to_x"));
        e.to_old_bal.allocate(*pb_, n("to_old_bal"));
        e.to_nonce.allocate(*pb_, n("to_nonce"));
        e.to_new_bal.allocate(*pb_, n("to_new_bal"));
        e.to_old_packed.allocate(*pb_, n("to_old_packed"));
        e.to_new_packed.allocate(*pb_, n("to_new_packed"));
        e.to_old_pose.allocate(*pb_, n("to_old_pose"));
        e.to_new_pose.allocate(*pb_, n("to_new_pose"));
        e.to_base_o.allocate(*pb_, n("to_base_o"));
        e.to_base_n.allocate(*pb_, n("to_base_n"));

        e.meta.allocate(*pb_, n("meta"));
        e.m1.allocate(*pb_, n("m1"));
        e.msg.allocate(*pb_, n("msg"));
        e.old_packed.allocate(*pb_, n("old_packed"));
        e.old_pose.allocate(*pb_, n("old_pose"));
        e.old_used.allocate(*pb_, n("old_used"));
        e.new_packed.allocate(*pb_, n("new_packed"));
        e.new_pose.allocate(*pb_, n("new_pose"));
        e.new_base.allocate(*pb_, n("new_base"));

        e.rx.allocate(*pb_, n("rx"));
        e.ry.allocate(*pb_, n("ry"));
        e.s.allocate(*pb_, n("s"));

        e.ax2.allocate(*pb_, n("ax2"));
        e.ay2.allocate(*pb_, n("ay2"));
        e.ax2y2.allocate(*pb_, n("ax2y2"));

        e.value_bits.allocate(*pb_, kRangeBits, n("value_bits"));
        e.nonce_bits.allocate(*pb_, kRangeBits, n("nonce_bits"));
        e.old_bal_bits.allocate(*pb_, kRangeBits, n("old_bal_bits"));
        e.new_bal_bits.allocate(*pb_, kRangeBits, n("new_bal_bits"));
        e.to_old_bal_bits.allocate(*pb_, kRangeBits, n("to_old_bal_bits"));
        e.to_nonce_bits.allocate(*pb_, kRangeBits, n("to_nonce_bits"));
        e.to_new_bal_bits.allocate(*pb_, kRangeBits, n("to_new_bal_bits"));

        e.pos_bits.allocate(*pb_, tree_depth_, n("pos_bits"));
        e.auth.resize(tree_depth_);
        e.po.resize(tree_depth_ + 1);
        e.pn.resize(tree_depth_ + 1);
        e.lo.resize(tree_depth_);
        e.ro.resize(tree_depth_);
        e.ln.resize(tree_depth_);
        e.rn.resize(tree_depth_);
        for (std::size_t l = 0; l < tree_depth_; ++l)
        {
            e.auth[l].allocate(*pb_, FMT("", "e%zu_auth_%zu", i, l));
            e.lo[l].allocate(*pb_, FMT("", "e%zu_lo_%zu", i, l));
            e.ro[l].allocate(*pb_, FMT("", "e%zu_ro_%zu", i, l));
            e.ln[l].allocate(*pb_, FMT("", "e%zu_ln_%zu", i, l));
            e.rn[l].allocate(*pb_, FMT("", "e%zu_rn_%zu", i, l));
        }
        for (std::size_t l = 0; l <= tree_depth_; ++l)
        {
            e.po[l].allocate(*pb_, FMT("", "e%zu_po_%zu", i, l));
            e.pn[l].allocate(*pb_, FMT("", "e%zu_pn_%zu", i, l));
        }

        e.to_pos_bits.allocate(*pb_, tree_depth_, n("to_pos_bits"));
        e.to_auth.resize(tree_depth_);
        e.qo.resize(tree_depth_ + 1);
        e.qn.resize(tree_depth_ + 1);
        e.qlo.resize(tree_depth_);
        e.qro.resize(tree_depth_);
        e.qln.resize(tree_depth_);
        e.qrn.resize(tree_depth_);
        for (std::size_t l = 0; l < tree_depth_; ++l)
        {
            e.to_auth[l].allocate(*pb_, FMT("", "e%zu_to_auth_%zu", i, l));
            e.qlo[l].allocate(*pb_, FMT("", "e%zu_qlo_%zu", i, l));
            e.qro[l].allocate(*pb_, FMT("", "e%zu_qro_%zu", i, l));
            e.qln[l].allocate(*pb_, FMT("", "e%zu_qln_%zu", i, l));
            e.qrn[l].allocate(*pb_, FMT("", "e%zu_qrn_%zu", i, l));
        }
        for (std::size_t l = 0; l <= tree_depth_; ++l)
        {
            e.qo[l].allocate(*pb_, FMT("", "e%zu_qo_%zu", i, l));
            e.qn[l].allocate(*pb_, FMT("", "e%zu_qn_%zu", i, l));
        }

        // Sub-gadgets (allocate their internals now, constrain later).
        e.g_m1 = std::make_unique<PoseidonGadget>(
            *pb_, e.from_x, e.dest, e.m1, n("g_m1"));
        e.g_msg = std::make_unique<PoseidonGadget>(
            *pb_, e.m1, e.meta, e.msg, n("g_msg"));
        e.g_old = std::make_unique<PoseidonGadget>(
            *pb_, e.from_x, e.old_packed, e.old_pose, n("g_old"));
        e.g_new = std::make_unique<PoseidonGadget>(
            *pb_, e.from_x, e.new_packed, e.new_pose, n("g_new"));
        e.g_to_old = std::make_unique<PoseidonGadget>(
            *pb_, e.to_x, e.to_old_packed, e.to_old_pose, n("g_to_old"));
        e.g_to_new = std::make_unique<PoseidonGadget>(
            *pb_, e.to_x, e.to_new_packed, e.to_new_pose, n("g_to_new"));
        e.g_eh = std::make_unique<PoseidonGadget>(
            *pb_, eh_[i], e.msg, eh_[i + 1], n("g_eh"));
        e.g_sig = std::make_unique<EdDSAGadget>(
            *pb_, e.from_x, e.from_y, e.rx, e.ry, e.s, e.msg, n("g_sig"));

        e.g_value_range = std::make_unique<libsnark::packing_gadget<FieldT>>(
            *pb_, e.value_bits, e.value, n("g_value_range"));
        e.g_nonce_range = std::make_unique<libsnark::packing_gadget<FieldT>>(
            *pb_, e.nonce_bits, e.nonce, n("g_nonce_range"));
        e.g_old_bal_range =
            std::make_unique<libsnark::packing_gadget<FieldT>>(
                *pb_, e.old_bal_bits, e.old_bal, n("g_old_bal_range"));
        e.g_new_bal_range =
            std::make_unique<libsnark::packing_gadget<FieldT>>(
                *pb_, e.new_bal_bits, e.new_bal, n("g_new_bal_range"));
        e.g_to_old_bal_range =
            std::make_unique<libsnark::packing_gadget<FieldT>>(
                *pb_, e.to_old_bal_bits, e.to_old_bal,
                n("g_to_old_bal_range"));
        e.g_to_nonce_range =
            std::make_unique<libsnark::packing_gadget<FieldT>>(
                *pb_, e.to_nonce_bits, e.to_nonce, n("g_to_nonce_range"));
        e.g_to_new_bal_range =
            std::make_unique<libsnark::packing_gadget<FieldT>>(
                *pb_, e.to_new_bal_bits, e.to_new_bal,
                n("g_to_new_bal_range"));

        for (std::size_t l = 0; l < tree_depth_; ++l)
        {
            e.g_po.emplace_back(std::make_unique<PoseidonGadget>(
                *pb_, e.lo[l], e.ro[l], e.po[l + 1],
                FMT("", "e%zu_g_po_%zu", i, l)));
            e.g_pn.emplace_back(std::make_unique<PoseidonGadget>(
                *pb_, e.ln[l], e.rn[l], e.pn[l + 1],
                FMT("", "e%zu_g_pn_%zu", i, l)));
            e.g_qo.emplace_back(std::make_unique<PoseidonGadget>(
                *pb_, e.qlo[l], e.qro[l], e.qo[l + 1],
                FMT("", "e%zu_g_qo_%zu", i, l)));
            e.g_qn.emplace_back(std::make_unique<PoseidonGadget>(
                *pb_, e.qln[l], e.qrn[l], e.qn[l + 1],
                FMT("", "e%zu_g_qn_%zu", i, l)));
        }
    }

    void
    constrainEntry(std::size_t i)
    {
        auto& e = entries_[i];
        auto n = [i](char const* base) {
            return FMT("", "e%zu_%s", i, base);
        };

        // ----- 1. Type bits: booleanity, w = t0*t1, forbid Transfer -----
        libsnark::generate_boolean_r1cs_constraint<FieldT>(
            *pb_, e.t0, n("t0_bool"));
        libsnark::generate_boolean_r1cs_constraint<FieldT>(
            *pb_, e.t1, n("t1_bool"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.t0, e.t1, e.w), n("w_def"));
        // Transfer (t1=1, t0=0) selector: is_xfer = t1*(1-t0) = t1 - w.
        // Boolean for free: t0,t1 are boolean and w = t0*t1.
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.is_xfer - e.t1 + e.w, 1, 0),
            n("is_xfer_def"));

        // ----- 2. is_create semantics; NoOp forces value = 0 -----
        libsnark::generate_boolean_r1cs_constraint<FieldT>(
            *pb_, e.is_create, n("is_create_bool"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.is_create, e.old_bal, 0),
            n("create_zero_bal"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.is_create, e.nonce, 0),
            n("create_zero_nonce"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.w, e.value, 0),
            n("noop_zero_value"));

        // ----- 3. meta = value + 2^64 nonce + 2^128 (t0 + 2 t1) -----
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.meta - e.value - twoPow64() * e.nonce -
                    twoPow128() * (e.t0 + FieldT(2) * e.t1),
                1,
                0),
            n("meta_def"));

        // ----- 4. Message hashes + entries-hash link -----
        e.g_m1->generate_r1cs_constraints();
        e.g_msg->generate_r1cs_constraints();
        e.g_eh->generate_r1cs_constraints();

        // ----- 5. from_apk on-curve: a*x^2 + y^2 = 1 + d*x^2*y^2 -----
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.from_x, e.from_x, e.ax2),
            n("ax_sq"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.from_y, e.from_y, e.ay2),
            n("ay_sq"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.ax2, e.ay2, e.ax2y2),
            n("ax2y2"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                BabyJubjub::A() * e.ax2 + e.ay2 -
                    BabyJubjub::D() * e.ax2y2 - FieldT::one(),
                1,
                0),
            n("a_on_curve"));

        // ----- 6. EdDSA verification -----
        e.g_sig->generate_r1cs_constraints();

        // ----- 7. Old leaf, creation mux -----
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.old_packed - e.old_bal - twoPow64() * e.nonce, 1, 0),
            n("old_packed_def"));
        e.g_old->generate_r1cs_constraints();
        // is_create=1 -> old_used = 0 ; is_create=0 -> old_used = old_pose
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.is_create, e.old_pose, e.old_pose - e.old_used),
            n("old_used_mux"));

        // ----- 8. Balance arithmetic -----
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.t0, e.value, e.dv),
            n("dv_def"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.is_xfer, e.value, e.xv),
            n("xv_def"));
        // Deposit(+value) / Withdraw(-value) / Transfer(-value, via xv) /
        // NoOp(0, since value=0):
        //   new_bal = old_bal + value - 2*dv - 2*xv
        // A Transfer has t0=0 so dv=0; xv=value makes it debit the sender
        // exactly as a Withdraw does.
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.new_bal - e.old_bal - e.value + FieldT(2) * e.dv +
                    FieldT(2) * e.xv,
                1,
                0),
            n("new_bal_def"));

        // Recipient balance: credited by exactly the same value, and ONLY
        // for a Transfer. is_xfer=0 forces to_new_bal == to_old_bal, which
        // is what collapses the recipient leg to a no-op below.
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.to_new_bal - e.to_old_bal - e.xv, 1, 0),
            n("to_new_bal_def"));

        // Bind the credited leaf to the SIGNED dest. Without this a sequencer
        // could debit Alice and credit itself: dest is covered by the user's
        // EdDSA signature (via m1), to_x is not.
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.is_xfer, e.to_x - e.dest, 0),
            n("to_x_is_dest"));

        // ----- 9. Range checks (canonical 64-bit packings) -----
        e.g_value_range->generate_r1cs_constraints(true);
        e.g_nonce_range->generate_r1cs_constraints(true);
        e.g_old_bal_range->generate_r1cs_constraints(true);
        e.g_new_bal_range->generate_r1cs_constraints(true);
        // Same aliasing argument as the sender side (BatchCircuit.h §5):
        // without canonical 64-bit packings a prover could offset
        // to_old_bal by 2^64·k and to_nonce by −k, leaving to_old_packed
        // unchanged while smuggling drops into to_new_bal.
        e.g_to_old_bal_range->generate_r1cs_constraints(true);
        e.g_to_nonce_range->generate_r1cs_constraints(true);
        e.g_to_new_bal_range->generate_r1cs_constraints(true);

        // ----- 10. New leaf; NoOp mux (keep the slot unchanged) -----
        //   new_packed = new_bal + 2^64 * (nonce + 1 - w)
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.new_packed - e.new_bal -
                    twoPow64() * (e.nonce + FieldT::one() - e.w),
                1,
                0),
            n("new_packed_def"));
        e.g_new->generate_r1cs_constraints();
        // w=1 -> new_base = old_used ; w=0 -> new_base = new_pose
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.w, e.old_used - e.new_pose, e.new_base - e.new_pose),
            n("new_base_mux"));

        // ----- 11. Merkle paths (shared position bits and siblings) -----
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.po[0] - e.old_used, 1, 0),
            n("po_base"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.pn[0] - e.new_base, 1, 0),
            n("pn_base"));

        for (std::size_t l = 0; l < tree_depth_; ++l)
        {
            libsnark::generate_boolean_r1cs_constraint<FieldT>(
                *pb_, e.pos_bits[l], FMT("", "e%zu_pos_bool_%zu", i, l));

            // Old path mux (PoseidonCircuit pattern).
            pb_->add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    e.pos_bits[l], e.auth[l] - e.po[l], e.lo[l] - e.po[l]),
                FMT("", "e%zu_mux_lo_%zu", i, l));
            pb_->add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    e.pos_bits[l], e.po[l] - e.auth[l], e.ro[l] - e.auth[l]),
                FMT("", "e%zu_mux_ro_%zu", i, l));
            e.g_po[l]->generate_r1cs_constraints();

            // New path mux — same bit, same sibling.
            pb_->add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    e.pos_bits[l], e.auth[l] - e.pn[l], e.ln[l] - e.pn[l]),
                FMT("", "e%zu_mux_ln_%zu", i, l));
            pb_->add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    e.pos_bits[l], e.pn[l] - e.auth[l], e.rn[l] - e.auth[l]),
                FMT("", "e%zu_mux_rn_%zu", i, l));
            e.g_pn[l]->generate_r1cs_constraints();
        }

        // ----- 12. Recipient leaf hashes and the no-op mux -----
        //   to_old_packed = to_old_bal + 2^64 * to_nonce
        //   to_new_packed = to_new_bal + 2^64 * to_nonce   (SAME nonce:
        //   the recipient did not sign, so their nonce is not consumed)
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.to_old_packed - e.to_old_bal - twoPow64() * e.to_nonce,
                1,
                0),
            n("to_old_packed_def"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.to_new_packed - e.to_new_bal - twoPow64() * e.to_nonce,
                1,
                0),
            n("to_new_packed_def"));
        e.g_to_old->generate_r1cs_constraints();
        e.g_to_new->generate_r1cs_constraints();

        // is_xfer=1 -> to_base = the recipient's real leaf
        // is_xfer=0 -> to_base = new_base, i.e. the sender's own post-update
        //              leaf. Both legs then hash the SAME value up the SAME
        //              path, so qo[depth] == qn[depth] and mid == r_{i+1}.
        //              This also keeps the leg satisfiable for a NoOp against
        //              an empty pad slot, where new_base = 0 is not a
        //              Poseidon image and no real leaf could stand in.
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.is_xfer,
                e.to_old_pose - e.new_base,
                e.to_base_o - e.new_base),
            n("to_base_o_mux"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.is_xfer,
                e.to_new_pose - e.new_base,
                e.to_base_n - e.new_base),
            n("to_base_n_mux"));

        // ----- 13. Recipient Merkle path: mid -> roots_[i+1] -----
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.qo[0] - e.to_base_o, 1, 0),
            n("qo_base"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(e.qn[0] - e.to_base_n, 1, 0),
            n("qn_base"));

        for (std::size_t l = 0; l < tree_depth_; ++l)
        {
            libsnark::generate_boolean_r1cs_constraint<FieldT>(
                *pb_, e.to_pos_bits[l], FMT("", "e%zu_qpos_bool_%zu", i, l));

            pb_->add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    e.to_pos_bits[l],
                    e.to_auth[l] - e.qo[l],
                    e.qlo[l] - e.qo[l]),
                FMT("", "e%zu_mux_qlo_%zu", i, l));
            pb_->add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    e.to_pos_bits[l],
                    e.qo[l] - e.to_auth[l],
                    e.qro[l] - e.to_auth[l]),
                FMT("", "e%zu_mux_qro_%zu", i, l));
            e.g_qo[l]->generate_r1cs_constraints();

            pb_->add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    e.to_pos_bits[l],
                    e.to_auth[l] - e.qn[l],
                    e.qln[l] - e.qn[l]),
                FMT("", "e%zu_mux_qln_%zu", i, l));
            pb_->add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    e.to_pos_bits[l],
                    e.qn[l] - e.to_auth[l],
                    e.qrn[l] - e.to_auth[l]),
                FMT("", "e%zu_mux_qrn_%zu", i, l));
            e.g_qn[l]->generate_r1cs_constraints();
        }

        // ----- 14. Root chaining: r_i -> mid -> r_{i+1} -----
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.po[tree_depth_] - roots_[i], 1, 0),
            n("old_root_link"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.pn[tree_depth_] - e.mid, 1, 0),
            n("mid_root_link"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.qo[tree_depth_] - e.mid, 1, 0),
            n("to_old_root_link"));
        pb_->add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                e.qn[tree_depth_] - roots_[i + 1], 1, 0),
            n("new_root_link"));
    }

    void
    witnessEntry(std::size_t i, BatchEntryWitness const& ew)
    {
        auto& e = entries_[i];
        auto const& req = ew.req;

        if (ew.leaf_pos.size() != tree_depth_ ||
            ew.auth_path.size() != tree_depth_)
            throw std::invalid_argument(
                "BatchCircuit: leaf_pos/auth_path size != tree_depth");

        if (req.type == RequestType::Transfer &&
            (ew.to_leaf_pos.size() != tree_depth_ ||
             ew.to_auth_path.size() != tree_depth_))
            throw std::invalid_argument(
                "BatchCircuit: Transfer to_leaf_pos/to_auth_path size != "
                "tree_depth");

        bool const isNoop = (req.type == RequestType::NoOp);
        bool const isWithdraw = (req.type == RequestType::Withdraw);

        // Request data.
        pb_->val(e.from_x) = req.from_apk.x;
        pb_->val(e.from_y) = req.from_apk.y;
        pb_->val(e.dest) = req.dest;
        pb_->val(e.value) = FieldT(req.value);
        pb_->val(e.nonce) = FieldT(req.nonce);
        pb_->val(e.old_bal) = FieldT(ew.old_balance);

        auto const typeVal = static_cast<std::uint64_t>(req.type);
        pb_->val(e.t0) = FieldT(typeVal & 1);
        pb_->val(e.t1) = FieldT((typeVal >> 1) & 1);
        pb_->val(e.w) = pb_->val(e.t0) * pb_->val(e.t1);
        pb_->val(e.is_create) =
            ew.is_create ? FieldT::one() : FieldT::zero();
        pb_->val(e.dv) = pb_->val(e.t0) * pb_->val(e.value);
        pb_->val(e.is_xfer) = pb_->val(e.t1) - pb_->val(e.w);
        pb_->val(e.xv) = pb_->val(e.is_xfer) * pb_->val(e.value);
        // Field-arithmetic form; an overdraft wraps into a huge field
        // element and the 64-bit range check becomes unsatisfiable.
        pb_->val(e.new_bal) = pb_->val(e.old_bal) + pb_->val(e.value) -
            FieldT(2) * pb_->val(e.dv) - FieldT(2) * pb_->val(e.xv);

        // meta / message hashes.
        pb_->val(e.meta) = pb_->val(e.value) +
            twoPow64() * pb_->val(e.nonce) +
            twoPow128() * (pb_->val(e.t0) + FieldT(2) * pb_->val(e.t1));
        e.g_m1->generate_r1cs_witness();
        e.g_msg->generate_r1cs_witness();
        e.g_eh->generate_r1cs_witness();

        // Signature + on-curve auxiliaries.
        pb_->val(e.rx) = req.sig.R.x;
        pb_->val(e.ry) = req.sig.R.y;
        pb_->val(e.s) = req.sig.s;
        pb_->val(e.ax2) = req.from_apk.x * req.from_apk.x;
        pb_->val(e.ay2) = req.from_apk.y * req.from_apk.y;
        pb_->val(e.ax2y2) = pb_->val(e.ax2) * pb_->val(e.ay2);
        e.g_sig->generate_r1cs_witness();

        // Old leaf.
        pb_->val(e.old_packed) =
            pb_->val(e.old_bal) + twoPow64() * pb_->val(e.nonce);
        e.g_old->generate_r1cs_witness();
        pb_->val(e.old_used) =
            ew.is_create ? FieldT::zero() : pb_->val(e.old_pose);

        // New leaf.
        pb_->val(e.new_packed) = pb_->val(e.new_bal) +
            twoPow64() *
                (pb_->val(e.nonce) + FieldT::one() - pb_->val(e.w));
        e.g_new->generate_r1cs_witness();
        pb_->val(e.new_base) =
            isNoop ? pb_->val(e.old_used) : pb_->val(e.new_pose);

        // Recipient leg. For a non-Transfer the mux discards to_old_pose /
        // to_new_pose entirely, so zeros are a valid (and canonical) filler —
        // they still have to satisfy the 64-bit range checks, which 0 does.
        bool const isXfer = (req.type == RequestType::Transfer);
        pb_->val(e.to_x) = isXfer ? ew.to_apk_x : FieldT::zero();
        pb_->val(e.to_old_bal) =
            isXfer ? FieldT(ew.to_old_balance) : FieldT::zero();
        pb_->val(e.to_nonce) = isXfer ? FieldT(ew.to_nonce) : FieldT::zero();
        pb_->val(e.to_new_bal) = pb_->val(e.to_old_bal) + pb_->val(e.xv);

        pb_->val(e.to_old_packed) =
            pb_->val(e.to_old_bal) + twoPow64() * pb_->val(e.to_nonce);
        pb_->val(e.to_new_packed) =
            pb_->val(e.to_new_bal) + twoPow64() * pb_->val(e.to_nonce);
        e.g_to_old->generate_r1cs_witness();
        e.g_to_new->generate_r1cs_witness();

        pb_->val(e.to_base_o) =
            isXfer ? pb_->val(e.to_old_pose) : pb_->val(e.new_base);
        pb_->val(e.to_base_n) =
            isXfer ? pb_->val(e.to_new_pose) : pb_->val(e.new_base);

        // Range decompositions (from the packed values already set).
        e.g_value_range->generate_r1cs_witness_from_packed();
        e.g_nonce_range->generate_r1cs_witness_from_packed();
        e.g_old_bal_range->generate_r1cs_witness_from_packed();
        e.g_new_bal_range->generate_r1cs_witness_from_packed();
        e.g_to_old_bal_range->generate_r1cs_witness_from_packed();
        e.g_to_nonce_range->generate_r1cs_witness_from_packed();
        e.g_to_new_bal_range->generate_r1cs_witness_from_packed();

        // Merkle paths.
        pb_->val(e.po[0]) = pb_->val(e.old_used);
        pb_->val(e.pn[0]) = pb_->val(e.new_base);
        for (std::size_t l = 0; l < tree_depth_; ++l)
        {
            bool const bit = ew.leaf_pos[l];
            pb_->val(e.pos_bits[l]) =
                bit ? FieldT::one() : FieldT::zero();
            pb_->val(e.auth[l]) = ew.auth_path[l];

            FieldT const sib = ew.auth_path[l];
            FieldT const cur_o = pb_->val(e.po[l]);
            FieldT const cur_n = pb_->val(e.pn[l]);
            pb_->val(e.lo[l]) = bit ? sib : cur_o;
            pb_->val(e.ro[l]) = bit ? cur_o : sib;
            pb_->val(e.ln[l]) = bit ? sib : cur_n;
            pb_->val(e.rn[l]) = bit ? cur_n : sib;

            e.g_po[l]->generate_r1cs_witness();  // sets po[l+1]
            e.g_pn[l]->generate_r1cs_witness();  // sets pn[l+1]
        }

        // Intermediate root: the tree after the sender's leaf changed.
        pb_->val(e.mid) = pb_->val(e.pn[tree_depth_]);

        // Recipient path. For a non-Transfer we walk the SENDER's position and
        // siblings again: only that one leaf moved, so its siblings are
        // unchanged, and starting from new_base the walk reproduces mid
        // exactly — which is what forces r_{i+1} == mid.
        pb_->val(e.qo[0]) = pb_->val(e.to_base_o);
        pb_->val(e.qn[0]) = pb_->val(e.to_base_n);
        for (std::size_t l = 0; l < tree_depth_; ++l)
        {
            bool const bit = isXfer ? ew.to_leaf_pos[l] : ew.leaf_pos[l];
            FieldT const sib = isXfer ? ew.to_auth_path[l] : ew.auth_path[l];

            pb_->val(e.to_pos_bits[l]) =
                bit ? FieldT::one() : FieldT::zero();
            pb_->val(e.to_auth[l]) = sib;

            FieldT const cur_o = pb_->val(e.qo[l]);
            FieldT const cur_n = pb_->val(e.qn[l]);
            pb_->val(e.qlo[l]) = bit ? sib : cur_o;
            pb_->val(e.qro[l]) = bit ? cur_o : sib;
            pb_->val(e.qln[l]) = bit ? sib : cur_n;
            pb_->val(e.qrn[l]) = bit ? cur_n : sib;

            e.g_qo[l]->generate_r1cs_witness();  // sets qo[l+1]
            e.g_qn[l]->generate_r1cs_witness();  // sets qn[l+1]
        }

        // Advance the root chain.
        pb_->val(roots_[i + 1]) = pb_->val(e.qn[tree_depth_]);

        (void)isWithdraw;  // semantics fully captured by t0/dv above
    }
};

// ===========================================================================
// Public surface
// ===========================================================================

BatchCircuit::BatchCircuit(std::size_t batch_size, std::size_t tree_depth)
    : impl_(std::make_unique<Impl>(batch_size, tree_depth))
{
}

BatchCircuit::~BatchCircuit() = default;

void
BatchCircuit::generateConstraints()
{
    impl_->generateConstraints();
}

void
BatchCircuit::generateWitness(
    FieldT const& prev_root,
    std::vector<BatchEntryWitness> const& entries)
{
    impl_->generateWitness(prev_root, entries);
}

FieldT
BatchCircuit::computedNewRoot() const
{
    return impl_->pb_->val(impl_->new_root_);
}

FieldT
BatchCircuit::computedEntriesHash() const
{
    return impl_->pb_->val(impl_->entries_hash_);
}

FieldT
BatchCircuit::computeEntriesHash(std::vector<SignedRequest> const& reqs)
{
    FieldT eh = FieldT::zero();
    for (auto const& r : reqs)
        eh = PoseidonHash::hash(eh, r.message());
    return eh;
}

libsnark::r1cs_constraint_system<FieldT>
BatchCircuit::getConstraintSystem() const
{
    return impl_->pb_->get_constraint_system();
}

libsnark::r1cs_primary_input<FieldT>
BatchCircuit::getPrimaryInput() const
{
    return impl_->pb_->primary_input();
}

libsnark::r1cs_auxiliary_input<FieldT>
BatchCircuit::getAuxiliaryInput() const
{
    return impl_->pb_->auxiliary_input();
}

bool
BatchCircuit::isSatisfied() const
{
    return impl_->pb_->is_satisfied();
}

std::size_t
BatchCircuit::constraintCount() const
{
    return impl_->pb_->num_constraints();
}

std::size_t
BatchCircuit::batchSize() const
{
    return impl_->batch_size_;
}

std::size_t
BatchCircuit::treeDepth() const
{
    return impl_->tree_depth_;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
