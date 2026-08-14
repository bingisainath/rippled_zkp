
#include "PoseidonHash.h"
#include "PoseidonConstants.h"

#include <libff/algebra/fields/bigint.hpp>
#include <mutex>
#include <stdexcept>

namespace ripple {
namespace zkp {
namespace rollup {

namespace {

// Parsed once at initialise() time.
std::vector<FieldT> g_arc;   // size = (R_F + R_P) * t = 195
std::vector<FieldT> g_mds;   // size = t*t = 9
FieldT g_zero_zero;          // Poseidon(0, 0) cached
std::once_flag g_init_flag;
bool g_initialised = false;

// Parse a decimal string into a FieldT. libff::Fr<...> exposes operator>>
// from std::istream which accepts decimal; we use that for portability.
FieldT
parseDecimal(std::string_view s)
{
    // libff requires a mutable null-terminated string for mpz_set_str-ish APIs.
    std::string copy{s};
    // libff::bigint has constructor from const char* assumed decimal;
    // alt_bn128 uses a 4-limb bigint.
    libff::bigint<libff::alt_bn128_r_limbs> n(copy.c_str());
    return FieldT(n);
}

void
loadConstantsOnce()
{
    using namespace poseidon_params;

    g_arc.reserve(kArcCount);
    for (auto const& s : kArcDecimal)
        g_arc.push_back(parseDecimal(s));

    g_mds.reserve(kT * kT);
    for (auto const& s : kMdsDecimal)
        g_mds.push_back(parseDecimal(s));

    // Sanity: the table sizes are exactly what the permutation expects.
    if (g_arc.size() != poseidon_params::kArcCount)
        throw std::logic_error(
            "PoseidonHash: ARC table size mismatch");
    if (g_mds.size() != poseidon_params::kT * poseidon_params::kT)
        throw std::logic_error(
            "PoseidonHash: MDS table size mismatch");

    // The ARC and MDS tables are now populated; hash() is safe to call.
    // Set the flag BEFORE the call to avoid a chicken-and-egg throw inside
    // call_once (which would escape and std::terminate the process).
    g_initialised = true;
 
    // Precompute the canonical empty_hashes_[0] used by the IMT.
    g_zero_zero = PoseidonHash::hash(FieldT::zero(), FieldT::zero());
}

}  // anonymous namespace

void
PoseidonHash::initialize()
{
    std::call_once(g_init_flag, loadConstantsOnce);
}

void
PoseidonHash::addRoundConstants(FieldT state[3], std::size_t round_idx)
{
    // Each round adds t=3 constants, indexed [round*3 .. round*3+2].
    std::size_t base = round_idx * poseidon_params::kT;
    state[0] += g_arc[base + 0];
    state[1] += g_arc[base + 1];
    state[2] += g_arc[base + 2];
}

void
PoseidonHash::sBoxFull(FieldT state[3])
{
    // x → x^5 on every lane.
    for (int i = 0; i < 3; ++i)
    {
        FieldT x2 = state[i] * state[i];
        FieldT x4 = x2 * x2;
        state[i] = x4 * state[i];
    }
}

void
PoseidonHash::sBoxPartial(FieldT state[3])
{
    // x → x^5 only on lane 0.
    FieldT x2 = state[0] * state[0];
    FieldT x4 = x2 * x2;
    state[0] = x4 * state[0];
}

void
PoseidonHash::mixLayer(FieldT state[3])
{
    // Multiply by MDS (3x3) — straightforward dot products.
    FieldT s0 = state[0] * g_mds[0] + state[1] * g_mds[1] + state[2] * g_mds[2];
    FieldT s1 = state[0] * g_mds[3] + state[1] * g_mds[4] + state[2] * g_mds[5];
    FieldT s2 = state[0] * g_mds[6] + state[1] * g_mds[7] + state[2] * g_mds[8];
    state[0] = s0;
    state[1] = s1;
    state[2] = s2;
}

void
PoseidonHash::permute(FieldT state[3])
{
    using poseidon_params::kFullRounds;
    using poseidon_params::kPartialRounds;

    std::size_t round = 0;
    std::size_t const half_full = kFullRounds / 2;  // 4

    // First half of full rounds.
    for (std::size_t i = 0; i < half_full; ++i, ++round)
    {
        addRoundConstants(state, round);
        sBoxFull(state);
        mixLayer(state);
    }

    // Partial rounds.
    for (std::size_t i = 0; i < kPartialRounds; ++i, ++round)
    {
        addRoundConstants(state, round);
        sBoxPartial(state);
        mixLayer(state);
    }

    // Second half of full rounds.
    for (std::size_t i = 0; i < half_full; ++i, ++round)
    {
        addRoundConstants(state, round);
        sBoxFull(state);
        mixLayer(state);
    }
}

FieldT
PoseidonHash::hash(FieldT const& a, FieldT const& b)
{
    if (!g_initialised)
        throw std::logic_error(
            "PoseidonHash::hash called before initialize()");

    // Sponge with rate=2, capacity=1.
    // Initial state = [0, a, b]; after permutation, output = state[0].
    // (This matches circomlib's `Poseidon(2)` which absorbs both inputs in
    //  one block and squeezes one output.)
    FieldT state[3] = {FieldT::zero(), a, b};
    permute(state);
    return state[0];
}

FieldT
PoseidonHash::hashN(std::vector<FieldT> const& inputs)
{
    if (inputs.size() == 2)
        return hash(inputs[0], inputs[1]);

    if (inputs.size() == 1)
    {
        // 1-input form: state = [0, a, 0]; squeeze state[0].
        FieldT state[3] = {FieldT::zero(), inputs[0], FieldT::zero()};
        permute(state);
        return state[0];
    }

    throw std::invalid_argument(
        "PoseidonHash::hashN currently supports n in {1, 2}");
}

FieldT const&
PoseidonHash::zeroZero()
{
    if (!g_initialised)
        throw std::logic_error(
            "PoseidonHash::zeroZero called before initialize()");
    return g_zero_zero;
}

uint256
PoseidonHash::hash(uint256 const& a, uint256 const& b)
{
    return fieldToUint256(hash(uint256ToField(a), uint256ToField(b)));
}

FieldT
PoseidonHash::uint256ToField(uint256 const& v)
{
    // uint256 is 32 bytes big-endian. libff bigint expects limbs little-endian.
    // We go through a 64-character hex round-trip to avoid endianness traps.
    std::string hex = strHex(v);  // 64-char upper-hex
    libff::bigint<libff::alt_bn128_r_limbs> n;
    // mpz_set_str path: prepend 0x and parse base 16 via a temporary mpz.
    mpz_t tmp;
    mpz_init(tmp);
    mpz_set_str(tmp, hex.c_str(), 16);
    // Reduce mod r.
    mpz_t r;
    mpz_init(r);
    FieldT::field_char().to_mpz(r);  // BN-128 r (modulus of Fr)
    mpz_mod(tmp, tmp, r);
    n = libff::bigint<libff::alt_bn128_r_limbs>(tmp);
    mpz_clear(tmp);
    mpz_clear(r);
    return FieldT(n);
}

uint256
PoseidonHash::fieldToUint256(FieldT const& v)
{
    // Pull out the residue and serialise as 32-byte big-endian.
    libff::bigint<libff::alt_bn128_r_limbs> n = v.as_bigint();
    mpz_t tmp;
    mpz_init(tmp);
    n.to_mpz(tmp);
    // Export to bytes.
    std::array<unsigned char, 32> bytes{};
    std::size_t count = 0;
    mpz_export(bytes.data(), &count, 1 /*order: MSB first*/, 1, 1, 0, tmp);
    mpz_clear(tmp);
    // mpz_export left-aligns; we want right-aligned in 32-byte big-endian.
    if (count < 32)
    {
        std::array<unsigned char, 32> shifted{};
        std::copy(
            bytes.begin(),
            bytes.begin() + count,
            shifted.begin() + (32 - count));
        bytes = shifted;
    }
    uint256 out;
    std::memcpy(out.data(), bytes.data(), 32);
    return out;
}

std::vector<FieldT> const&
PoseidonHash::debug_mds()
{
    return g_mds;
}

std::vector<FieldT> const&
PoseidonHash::debug_arc()
{
    return g_arc;
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple
