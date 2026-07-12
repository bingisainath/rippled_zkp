// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// EdDSA over Baby Jubjub with a Poseidon challenge hash — the off-circuit
// (native) half of Phase 6's batch-circuit authorization scheme.
//
// Scheme (circomlib EdDSAPoseidonVerifier-shaped, adapted to our 2-to-1
// Poseidon):
//
//   keygen :  A = [a]·G                     a = ask mod ℓ, a ≠ 0
//   sign   :  r = H(ask, m) mod ℓ           deterministic nonce (RFC-8032 style)
//             R = [r]·G
//             h = challenge(R, A, m)
//             s = (r + h·a) mod ℓ
//   verify :  [s]·G == R + [h]·A            and R on-curve
//
// where the challenge is chained through the 2-to-1 Poseidon:
//
//   challenge(R, A, m) = H( H( H(R.x, R.y), H(A.x, A.y) ), m )
//
// ℓ is the prime order of the BJJ subgroup (≈ 2^250.99). Scalar arithmetic
// mod ℓ is done with boost::multiprecision (FieldT is mod p, not mod ℓ).
//
// Note on h: the verifier multiplies A by the FULL (unreduced) 254-bit h.
// This is consistent with the signer using h mod ℓ in s, because A has
// order ℓ: [h]·A == [h mod ℓ]·A. The in-circuit verifier (EdDSAGadget)
// uses the same convention.
//
// Known prototype caveats (documented, standard for EdDSA):
//   - s is range-limited to 254 bits, not < ℓ: a signature (R, s+ℓ) for the
//     SAME message may also verify (classic EdDSA malleability). This never
//     allows forging a signature on a NEW message.
//   - No subgroup (cofactor-8) check on R; the challenge binds R so small-
//     subgroup components cannot change the signed message.

#ifndef RIPPLE_ZKP_ROLLUP_EDDSA_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_EDDSA_H_INCLUDED

#include "BabyJubjub.h"
#include "PoseidonHash.h"

namespace ripple {
namespace zkp {
namespace rollup {

struct EdDSASignature
{
    BjjPoint R;  // nonce commitment [r]·G
    FieldT s;    // response, canonical representative of a value < ℓ
};

class EdDSA
{
public:
    // Requires libff init + BabyJubjub::initialize() + PoseidonHash::initialize()
    // to have been called (same preconditions as the rest of the rollup stack).

    // A = [ask]·G. ask is reduced mod ℓ internally; throws if ask ≡ 0 (mod ℓ).
    static BjjPoint
    derivePublicKey(FieldT const& ask);

    // h = H(H(H(R.x, R.y), H(A.x, A.y)), m) — shared verbatim by EdDSAGadget.
    static FieldT
    challenge(BjjPoint const& R, BjjPoint const& A, FieldT const& msg);

    // Deterministic signature (no RNG — nonce derived from key and message).
    static EdDSASignature
    sign(FieldT const& ask, FieldT const& msg);

    // Full verification: R on-curve AND [s]·G == R + [h]·A.
    static bool
    verify(BjjPoint const& A, FieldT const& msg, EdDSASignature const& sig);

    // The BJJ prime subgroup order ℓ as a field element's worth of bytes is
    // not representable — exposed as a decimal string for tests.
    static char const*
    subgroupOrderDecimal();
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_EDDSA_H_INCLUDED
