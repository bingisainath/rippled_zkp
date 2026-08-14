/*
    RollupModule: node-startup hook for RollupProver key loading.
*/

#ifndef RIPPLE_ZKP_ROLLUP_ROLLUPMODULE_H_INCLUDED
#define RIPPLE_ZKP_ROLLUP_ROLLUPMODULE_H_INCLUDED

#include <string>

namespace ripple {
namespace zkp {
namespace rollup {

class RollupModule
{
public:
    // Called once from Application.cpp at node startup, before any
    // transaction can be dispatched. Loads the RollupProver Groth16
    // keys from disk (or runs trusted setup if they don't exist).
    //
    // Idempotent: safe to call multiple times.
    //
    // Default key path is /tmp/rippled_rollup_keys -- explicitly
    // separate from ZkProver's /tmp/rippled_zkp_keys to honour the
    // Coexistence boundary.
    static void
    onStart(std::string const& keyPath = "/tmp/rippled_rollup_keys");

    // Inverse of onStart, used in shutdown and in the test harness.
    static void
    onStop();

    static bool
    isStarted() noexcept;
};

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple

#endif  // RIPPLE_ZKP_ROLLUP_ROLLUPMODULE_H_INCLUDED