// RollupNote: a single user account state in Track 1's rollup, replacing a
// uint256-keyed note with Baby Jubjub keys.
//
//   value : uint64    XRP drops
//   rho   : FieldT    note nonce, giving uniqueness within the tree
//   r     : FieldT    blinding factor, kept for hiding even though the
//                     Poseidon commitment is purely algebraic
//   ask   : FieldT    spending key, a BJJ scalar
//   apk   : BjjPoint  apk = [ask]*G
//
// Cached derivations:
//   cm : Poseidon(value, rho, r, apk_x). Only apk_x is hashed — apk_y is
//        determined by the curve equation up to sign, so omitting it saves
//        one Poseidon call per commitment without weakening binding.
//   nf : Poseidon(ask, rho)

#ifndef RIPPLE_ZKP_ROLLUP_ROLLUP_NOTE_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ROLLUP_NOTE_H_INCLUDED

#include "BabyJubjub.h"
#include "PoseidonHash.h"

#include <cstdint>

namespace ripple {
namespace zkp {
namespace rollup {

class RollupNote
{
public:
    std::uint64_t value{0};
    FieldT rho;
    FieldT r;
    FieldT ask;
    BjjPoint apk;

    // Default-constructed note has all zero field elements and identity apk.
    RollupNote();

    // Build a note from explicit components. Recomputes apk from ask.
    static RollupNote
    fromComponents(
        std::uint64_t value,
        FieldT const& rho,
        FieldT const& r,
        FieldT const& ask);

    // Random-but-valid note for tests (uses libff's PRG-style sample if available;
    // otherwise a simple counter + Poseidon).
    static RollupNote
    createRandom(std::uint64_t value, std::uint64_t test_seed);

    // Commitment: cm = Poseidon( Poseidon(value, rho), Poseidon(r, apk_x) )
    // Two-stage to fit our 2-input Poseidon. The four-input version is
    // semantically equivalent and saves one round; we use two-stage for clarity
    // and because it costs only one extra ~243-constraint Poseidon call.
    FieldT
    commitment() const;

    // Nullifier: nf = Poseidon(ask, rho)
    FieldT
    nullifier() const;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ROLLUP_NOTE_H_INCLUDED
