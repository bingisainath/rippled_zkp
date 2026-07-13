//------------------------------------------------------------------------------
/*
    Phase 4a — RollupModule implementation.
*/
//==============================================================================

#include <libxrpl/zkp/rollup/RollupModule.h>
#include <libxrpl/zkp/rollup/RollupProver.h>
#include <libxrpl/zkp/rollup/BatchCircuitProver.h>

#include <atomic>

namespace ripple {
namespace zkp {
namespace rollup {

namespace {
std::atomic<bool> g_started{false};
}  // anonymous namespace

void
RollupModule::onStart(std::string const& keyPath)
{
    if (g_started.load(std::memory_order_acquire))
        return;

    // RollupProver::initialize() runs trusted setup if keys are absent,
    // or loads them from disk if present. Bounded one-time cost; never
    // call this from inside preclaim() (consensus-critical path).
    RollupProver::initialize(keyPath);

    // Track 2 (Phase 6): bring up the BatchCircuit prover/verifier keys at
    // its own path. Same one-time keygen cost (~35 s at N=8, depth=16) if
    // absent. Both tracks are now serviceable by this node.
    BatchCircuitProver::initialize();

    g_started.store(true, std::memory_order_release);
}

void
RollupModule::onStop()
{
    g_started.store(false, std::memory_order_release);
    // RollupProver holds keys in static storage; no explicit teardown
    // required for correctness. Clearing the started flag forces
    // re-initialisation on the next onStart() (used by tests).
}

bool
RollupModule::isStarted() noexcept
{
    return g_started.load(std::memory_order_acquire);
}

}  // namespace rollup
}  // namespace zkp
}  // namespace ripple