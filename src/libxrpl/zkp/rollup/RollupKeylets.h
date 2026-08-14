/*
    This file is part of rippled_zkp: ZK-Rollup extension for XRPL.

    Shared keylet definitions for the rollup ledger objects.
*/

#ifndef RIPPLE_ZKP_ROLLUP_ROLLUPKEYLETS_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ROLLUPKEYLETS_H_INCLUDED

#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/digest.h>

#include <cstdint>
#include <string>

namespace ripple {
namespace keylet {

// Rollup SLE keylets — SHARED header.
//
// WHY A SHARED HEADER:
//   ZkDeposit.cpp / ZkWithdraw.cpp define keylet::shielded_pool() as inline
//   functions in per-file `namespace keylet { ... }` blocks. This pattern
//   works only while each file is compiled in isolation and never ODR-clashes
//   with the others. For the rollup module we have multiple .cpp files
//   (BatchVerifier.cpp, RollupState.cpp, tests, sequencer later) that all
//   need rollup_state() and nullifier_page(). A shared header with `inline`
//   linkage gives us one definition across all TUs with no linker errors.

/**
 * Singleton RollupState SLE.
 *
 * Confirmed:
 *   ltSHIELDED_POOL uses Keylet(ltSHIELDED_POOL, uint256{}).
 *   If we also used uint256{} for the rollup state, the in-memory hash lookup
 *   key would collide (same 0-hash, different type tag) and — more dangerously
 *   — reading sfCommitmentCount from the wrong SLE would silently return 0.
 *
 * Defence: domain-separate via sha512Half("ZKRollupState"). The static const
 * ensures the hash is computed exactly once per process.
 *
 * Ledger entry type: 0x0084 (confirmed free; 0x0080 collides
 * with ltOracle, 0x0081 with ltCredential).
 */
inline Keylet
rollup_state()
{
    static uint256 const ROLLUP_STATE_TAG =
        sha512Half(std::string("ZKRollupState"));
    return Keylet(ltROLLUP_STATE, ROLLUP_STATE_TAG);
}

/**
 * NullifierPage SLE keyed by page index.
 *
 * The nullifier set grows linearly — one page holds up to 64 Poseidon
 * nullifiers. Pages form a linked list via sfIndexNext.
 *
 * Keylet derivation: sha512Half(pageIndex || uint256{}) — distinct from
 * rollup_state() tag because the first byte of sha512Half(pair{u32,u256{}})
 * depends on pageIndex.
 *
 * Declared here so the nullifier store can use it without
 * edits to this header.
 *
 * Ledger entry type: 0x0085 (confirmed free).
 */
inline Keylet
nullifier_page(std::uint32_t pageIndex)
{
    return Keylet(
        ltNULLIFIER_PAGE,
        sha512Half(std::make_pair(pageIndex, uint256{})));
}

/**
 * Track 2 rollup state SLE — INDEPENDENT of Track 1.
 *
 * Reuses the ltROLLUP_STATE ledger entry type but a DIFFERENT domain tag,
 * so the two tracks keep separate roots / batch counters / frontiers in the
 * same ledger without colliding. No new ledger format registration needed.
 */
inline Keylet
rollup_state2()
{
    static uint256 const ROLLUP_STATE2_TAG =
        sha512Half(std::string("ZKRollupState2"));
    return Keylet(ltROLLUP_STATE, ROLLUP_STATE2_TAG);
}

}  // namespace keylet
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ROLLUPKEYLETS_H_INCLUDED