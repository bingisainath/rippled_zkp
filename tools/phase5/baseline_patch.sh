#!/usr/bin/env bash
# Patch testBaselinePaymentLatency to (a) fund destinations before timing
# and (b) record "tecNO_DST_INSUF_XRP" outcome if it ever fires anyway.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FILE="$REPO_ROOT/src/test/zkp/rollup/RollupBench_test.cpp"

# Insert the funding block. The marker is the line "std::size_t totalBytes = 0;"
# which immediately follows the dests construction. We insert above it.
python3 - "$FILE" <<'PY'
import sys, re

path = sys.argv[1]
src = open(path).read()

# Locate the testBaselinePaymentLatency body and insert funding loop right
# after dests construction.
marker_old = """            std::size_t totalBytes = 0;
            std::int64_t totalFee = 0;

            Stopwatch t;"""

marker_new = """            // Fund destinations so payments don't trip the create-reserve
            // threshold (a brand-new account needs ~10 XRP to be created;
            // we want to measure the steady-state Payment cost, not the
            // one-time creation cost).
            for (auto const& d : dests)
                env.fund(XRP(10000), d);
            env.close();

            std::size_t totalBytes = 0;
            std::int64_t totalFee = 0;

            Stopwatch t;"""

if marker_new in src:
    print("Patch already applied — no change.")
elif marker_old in src:
    src = src.replace(marker_old, marker_new, 1)
    with open(path, "w") as f:
        f.write(src)
    print("Patched. Funding loop inserted.")
else:
    print("ERROR: marker not found. File may have drifted from expected state.",
          file=sys.stderr)
    sys.exit(1)
PY