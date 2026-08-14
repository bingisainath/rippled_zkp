
#include "RollupNote.h"

namespace ripple {
namespace zkp {
namespace rollup {

RollupNote::RollupNote()
    : value(0)
    , rho(FieldT::zero())
    , r(FieldT::zero())
    , ask(FieldT::zero())
    , apk(BjjPoint::identity())
{
}

RollupNote
RollupNote::fromComponents(
    std::uint64_t value,
    FieldT const& rho,
    FieldT const& r,
    FieldT const& ask)
{
    RollupNote n;
    n.value = value;
    n.rho = rho;
    n.r = r;
    n.ask = ask;
    n.apk = BabyJubjub::mul(BabyJubjub::generator(), ask);
    return n;
}

RollupNote
RollupNote::createRandom(std::uint64_t value, std::uint64_t test_seed)
{
    // Deterministic-but-distinct field elements derived from the seed via
    // Poseidon. Avoids depending on a PRNG and keeps tests reproducible.
    PoseidonHash::initialize();
    BabyJubjub::initialize();

    FieldT seed_f(test_seed);
    FieldT rho = PoseidonHash::hash(seed_f, FieldT(1));
    FieldT r = PoseidonHash::hash(seed_f, FieldT(2));
    FieldT ask = PoseidonHash::hash(seed_f, FieldT(3));

    return fromComponents(value, rho, r, ask);
}

FieldT
RollupNote::commitment() const
{
    PoseidonHash::initialize();
    FieldT v_field(value);
    FieldT half1 = PoseidonHash::hash(v_field, rho);
    FieldT half2 = PoseidonHash::hash(r, apk.x);
    return PoseidonHash::hash(half1, half2);
}

FieldT
RollupNote::nullifier() const
{
    PoseidonHash::initialize();
    return PoseidonHash::hash(ask, rho);
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
