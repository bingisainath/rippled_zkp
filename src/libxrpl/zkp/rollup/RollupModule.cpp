//------------------------------------------------------------------------------
/*
    Phase 4a — RollupModule implementation.
*/
//==============================================================================

#include <libxrpl/zkp/rollup/RollupModule.h>
#include <libxrpl/zkp/rollup/RollupProver.h>
#include <libxrpl/zkp/rollup/BatchCircuitProver.h>

#include <atomic>
#include <iostream>

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

    // rippled only ever VERIFIES batches — proving happens in a separate
    // sequencer/tool process (see gen_batch_blob2). Loading the full
    // proving key here would cost ~65-70s per boot for a key this process
    // structurally never uses; initializeVerifierOnly() loads just the
    // small verification key instead. Falls back to the full initialize()
    // (which self-generates keys if absent — the original behavior) if no
    // cached keys exist yet anywhere: that first-ever run still needs SOME
    // process to create the keys, and rippled doing it itself is a
    // reasonable one-time fallback rather than a hard failure.
    try
    {
        RollupProver::initializeVerifierOnly(keyPath);
    }
    catch (std::exception const& e)
    {
        std::cout << "[RollupModule] " << e.what()
                  << " — falling back to full initialize() (one-time "
                     "keygen if this is genuinely the first run)."
                  << std::endl;
        RollupProver::initialize(keyPath);
    }

    // Track 2 (Phase 6): same reasoning, at BatchCircuitProver's own path.
    try
    {
        BatchCircuitProver::initializeVerifierOnly();
    }
    catch (std::exception const& e)
    {
        std::cout << "[RollupModule] " << e.what()
                  << " — falling back to full initialize() (one-time "
                     "keygen if this is genuinely the first run)."
                  << std::endl;
        BatchCircuitProver::initialize();
    }

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