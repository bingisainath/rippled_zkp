// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// AccountLeaf + SignedRequest: the Track 2 (Phase 6, Option A) state model.
//
// Track 1 uses note commitments and nullifiers (RollupNote). Track 2 is
// account-based: one leaf per account, replay protection via an in-leaf
// nonce, authorization via EdDSA — so the batch witness never contains a
// user secret (the sequencer proves; users only sign).
//
// ============================ Hash conventions ============================
// These are CANONICAL: the native code here and the Phase 6 BatchCircuit
// must implement them bit-for-bit identically.
//
// Leaf hash (one Poseidon call — packing is sound because the circuit
// range-checks balance and nonce to 64 bits):
//
//   leaf = Poseidon( apk_x ,  balance + 2^64 * nonce )
//
// Empty leaf (unoccupied tree slot; the "old leaf" in an account-creation
// entry): the field element 0 — NOT Poseidon of anything. This matches the
// convention that a tree slot holds 0 until first written.
//
// Request message (two Poseidon calls; txType folds into the packed meta):
//
//   meta = value + 2^64 * nonce + 2^128 * txType
//   msg  = Poseidon( Poseidon(from_apk_x, dest) , meta )
//
// where `dest` is:
//   Transfer  : recipient's apk_x
//   Withdraw  : the 20-byte XRPL AccountID left-padded into a field element
//   Deposit   : from_apk_x (self — the L1 escrow deposit credits the signer)
//   NoOp      : 0
//
// The user signs msg with EdDSA (EdDSA.h). The signature binds every field
// of the request: any mutation changes msg and breaks EdDSA_verify.

#ifndef RIPPLE_ZKP_ROLLUP_ACCOUNT_LEAF_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ACCOUNT_LEAF_H_INCLUDED

#include "BabyJubjub.h"
#include "EdDSA.h"
#include "PoseidonHash.h"

#include <cstdint>

namespace ripple {
namespace zkp {
namespace rollup {

// Request kinds. NoOp exists so short batches can be padded with entries
// that are still provable (a NoOp proves "this leaf did not change").
enum class RequestType : std::uint8_t {
    Deposit = 0,   // L1 escrow -> L2 balance (leaf may be created)
    Withdraw = 1,  // L2 balance -> L1 AccountID
    Transfer = 2,  // L2 -> L2 (two-leaf update; Phase 6 stretch goal)
    NoOp = 3       // padding: no state change
};

struct AccountLeaf
{
    BjjPoint apk;               // account public key (x is the identity)
    std::uint64_t balance = 0;  // XRP drops
    std::uint64_t nonce = 0;    // replay counter, +1 per authorized spend

    // leaf = Poseidon(apk_x, balance + 2^64 * nonce)
    FieldT
    hash() const;

    // The unoccupied-slot value: FieldT(0).
    static FieldT
    emptyLeaf();

    // balance + 2^64 * nonce  (the packed second Poseidon input).
    static FieldT
    packBalanceNonce(std::uint64_t balance, std::uint64_t nonce);
};

struct SignedRequest
{
    BjjPoint from_apk;      // signer's public key (full point — the circuit
                            // needs (x, y) for the EdDSA scalar mul)
    FieldT dest;            // see header comment for per-type meaning
    std::uint64_t value = 0;
    std::uint64_t nonce = 0;  // must equal the signer's current leaf nonce
    RequestType type = RequestType::NoOp;
    EdDSASignature sig;

    // meta = value + 2^64 * nonce + 2^128 * txType
    static FieldT
    packMeta(std::uint64_t value, std::uint64_t nonce, RequestType type);

    // msg = Poseidon(Poseidon(from_apk_x, dest), meta)
    FieldT
    message() const;

    // Native admission check: EdDSA::verify(from_apk, message(), sig).
    bool
    verifySignature() const;

    // Build-and-sign in one step (the user-side operation, ~1 ms).
    static SignedRequest
    make(
        FieldT const& ask,
        FieldT const& dest,
        std::uint64_t value,
        std::uint64_t nonce,
        RequestType type);
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ACCOUNT_LEAF_H_INCLUDED
