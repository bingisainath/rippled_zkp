// EdDSA over Baby Jubjub with a Poseidon challenge hash — the native,
// off-circuit half of Track 2's authorization scheme. Shaped after
// circomlib's EdDSAPoseidonVerifier, adapted to a 2-to-1 Poseidon.
//
//   keygen :  A = [a]*G                     a = ask mod l, a != 0
//   sign   :  r = H(ask, m) mod l           deterministic nonce
//             R = [r]*G
//             h = challenge(R, A, m)
//             s = (r + h*a) mod l
//   verify :  [s]*G == R + [h]*A            and R on-curve
//
//   challenge(R, A, m) = H( H( H(R.x, R.y), H(A.x, A.y) ), m )
//
// l is the prime order of the BJJ subgroup (about 2^250.99). Scalar
// arithmetic mod l uses boost::multiprecision, since FieldT is mod p.
//
// The verifier multiplies A by the FULL unreduced 254-bit h. This agrees
// with the signer using h mod l in s because A has order l, so
// [h]*A == [h mod l]*A. EdDSAGadget uses the same convention.
//
// Known prototype caveats, both standard for EdDSA:
//   - s is range-limited to 254 bits rather than to < l, so (R, s+l) may
//     verify for the SAME message. This never allows forging a signature
//     on a NEW message.
//   - No cofactor-8 subgroup check on R; the challenge binds R, so
//     small-subgroup components cannot change the signed message.

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
