// AccountLeaf + SignedRequest: Track 2's state model. Where Track 1 uses
// note commitments and nullifiers (RollupNote), Track 2 is account-based —
// one leaf per account, replay protection via an in-leaf nonce, and
// authorization via EdDSA, so the batch witness never contains a user
// secret. The sequencer proves; users only sign.
//
// The hash conventions below are CANONICAL: the native code here and
// BatchCircuit must implement them bit-for-bit identically.
//
// Leaf hash — one Poseidon call. Packing is sound because the circuit
// range-checks balance and nonce to 64 bits:
//
//   leaf = Poseidon( apk_x , balance + 2^64 * nonce )
//
// An unoccupied slot — also the "old leaf" of an account-creation entry —
// holds the field element 0, NOT Poseidon of anything.
//
// Request message — two Poseidon calls, with txType folded into the packed
// meta word:
//
//   meta = value + 2^64 * nonce + 2^128 * txType
//   msg  = Poseidon( Poseidon(from_apk_x, dest) , meta )
//
// where dest is the recipient's apk_x for a Transfer, the 20-byte XRPL
// AccountID left-padded into a field element for a Withdraw, from_apk_x
// itself for a Deposit (the L1 escrow credits the signer), and 0 for a NoOp.
//
// The user signs msg with EdDSA (EdDSA.h), which binds every field of the
// request: any mutation changes msg and breaks verification.

#ifndef RIPPLE_ZKP_ROLLUP_ACCOUNT_LEAF_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ACCOUNT_LEAF_H_INCLUDED

#include "BabyJubjub.h"
#include "EdDSA.h"
#include "PoseidonHash.h"

#include <xrpl/protocol/AccountID.h>

#include <cstdint>

namespace ripple {
namespace zkp {
namespace rollup {

// Withdraw `dest` encoding — CANONICAL.
//
// A withdrawal's signed `dest` field is the 20-byte XRPL AccountID left-padded
// into a 32-byte big-endian buffer (12 zero bytes, then the AccountID), read as
// a field element. The value is < 2^160 << p, so the reduction in
// uint256ToField is always a no-op and the encoding round-trips exactly.
//
// WHY THIS MATTERS: BatchProof2Entry carries the payout AccountID in a SEPARATE
// wire field (`destination`) that the USER's EdDSA signature does not cover.
// Binding the two — dest == accountIdToField(destination) — is what stops a
// malicious sequencer redirecting a withdrawal to itself. BatchRollup2::preflight
// enforces it; without this helper the convention was documentation only.
uint256
accountIdToUint256(AccountID const& id);

FieldT
accountIdToField(AccountID const& id);

// Request kinds. NoOp exists so short batches can be padded with entries
// that are still provable (a NoOp proves "this leaf did not change").
enum class RequestType : std::uint8_t {
    Deposit = 0,   // L1 escrow -> L2 balance (leaf may be created)
    Withdraw = 1,  // L2 balance -> L1 AccountID
    Transfer = 2,  // L2 -> L2 (two-leaf update)
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
