#!/usr/bin/env bash
# Copyright (c) 2026 Sainath Annadevara — Trinity College Dublin
# Phase 5 driver for the slim benchmark suite.
#
# Reuses existing build state; assumes `tests=ON` and `xrpld=ON` are
# already set in CMakeCache.txt (they will be after the first Phase 5
# day's debugging — see audit's "build gotchas" section).
#
# Usage:
#     bash tools/phase5/run_phase5.sh [num_runs]

set -euo pipefail

NUM_RUNS="${1:-5}"
RIPPLED_ROOT="${RIPPLED_ROOT:-$HOME/Sainath/rippled_zkp}"
BUILD_DIR="${BUILD_DIR:-$RIPPLED_ROOT/build}"
CSV_PATH="${ROLLUP_BENCH_CSV:-/tmp/rollup_bench.csv}"
OUT_DIR="${PHASE5_OUT:-$RIPPLED_ROOT/docs/phase5_results}"
JOBS="${JOBS:-4}"

RIPPLED_BIN="$BUILD_DIR/build/Release/rippled"
if [[ ! -x "$RIPPLED_BIN" ]]; then
    # Try a few known locations
    RIPPLED_BIN=$(find "$BUILD_DIR" -maxdepth 4 -name 'rippled' -type f \
                  -executable 2>/dev/null | head -1)
fi
if [[ -z "$RIPPLED_BIN" || ! -x "$RIPPLED_BIN" ]]; then
    echo "Need to build first. Running:" >&2
    echo "  cd $BUILD_DIR && cmake --build . -j$JOBS --target rippled" >&2
    cd "$BUILD_DIR"
    cmake --build . -j"$JOBS" --target rippled
    RIPPLED_BIN="$BUILD_DIR/build/Release/rippled"
fi

if [[ ! -x "$RIPPLED_BIN" ]]; then
    echo "ERROR: rippled binary not found at expected location after build." >&2
    exit 1
fi

cd "$RIPPLED_ROOT"

echo "==> Incremental build (picks up Phase 5 test source)..."
cd "$BUILD_DIR"
cmake --build . -j"$JOBS" --target rippled

echo "==> Running RollupBench (NUM_RUNS=$NUM_RUNS)..."
rm -f "$CSV_PATH"
ROLLUP_BENCH_CSV="$CSV_PATH" \
    ROLLUP_BENCH_RUNS="$NUM_RUNS" \
    "$RIPPLED_BIN" --unittest=ripple.zkp_rollup.RollupBench --unittest-log

if [[ ! -f "$CSV_PATH" ]]; then
    echo "ERROR: CSV was not emitted." >&2
    exit 1
fi
echo "==> CSV: $CSV_PATH ($(wc -l < "$CSV_PATH") lines)"

# Optional: append the live end-to-end L2->L1 samples (real tesSUCCESS on a
# standalone node). Off by default because it boots a node and runs
# gen_batch_blob (~72s/run). Enable with RUN_LIVE=1.
if [[ "${RUN_LIVE:-0}" == "1" ]]; then
    echo "==> Running live end-to-end harness (RUN_LIVE=1)..."
    ROLLUP_BENCH_CSV="$CSV_PATH" \
        bash "$RIPPLED_ROOT/tools/phase5/bench_live_e2e.sh" "$NUM_RUNS"
    echo "==> CSV now: $CSV_PATH ($(wc -l < "$CSV_PATH") lines)"
fi

echo "==> Analysing..."
mkdir -p "$OUT_DIR"
PY=python3
if ! "$PY" -c "import pandas, matplotlib" 2>/dev/null; then
    "$PY" -m pip install --user --break-system-packages \
        pandas matplotlib tabulate
fi
"$PY" "$RIPPLED_ROOT/tools/phase5/analyse_bench.py" \
    --csv "$CSV_PATH" --out "$OUT_DIR"

echo "==> Done."
echo "    Tables:  $OUT_DIR/summary.md, $OUT_DIR/summary.tex"
echo "    Figures: $OUT_DIR/fig_proof_pipeline.pdf,"
echo "             $OUT_DIR/fig_baseline_vs_rollup.pdf"