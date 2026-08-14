#!/usr/bin/env bash
# check_build_state.sh — inspect the current build state on the VM and
# tell you whether you can skip Conan / CMake configure.
#
# Run from anywhere:
#     bash tools/phase5/check_build_state.sh
#
# This is a read-only inspection. It changes nothing.

set -u

RIPPLED_ROOT="${RIPPLED_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
BUILD_DIR="${BUILD_DIR:-$RIPPLED_ROOT/build}"

CMAKE_CACHE="$BUILD_DIR/CMakeCache.txt"
RIPPLED_BIN="$BUILD_DIR/rippled"

# Locate the Conan toolchain wherever Conan actually wrote it.
# Conan 2's default layout in this fork is build/build/generators/;
# some other forks use build/build/Release/generators/.
TOOLCHAIN_FILE=""
for c in \
    "$BUILD_DIR/build/generators/conan_toolchain.cmake" \
    "$BUILD_DIR/build/Release/generators/conan_toolchain.cmake" \
    "$BUILD_DIR/generators/conan_toolchain.cmake"; do
    if [[ -f "$c" ]]; then
        TOOLCHAIN_FILE="$c"
        break
    fi
done
if [[ -z "$TOOLCHAIN_FILE" ]]; then
    # fallback: search anywhere under build/
    TOOLCHAIN_FILE=$(find "$BUILD_DIR" -name conan_toolchain.cmake -type f \
        2>/dev/null | head -1)
fi
# Default to the conventional path for the "missing" message
if [[ -z "$TOOLCHAIN_FILE" ]]; then
    TOOLCHAIN_FILE="$BUILD_DIR/build/generators/conan_toolchain.cmake"
fi

echo "==================================================================="
echo "rippled_zkp build-state inspection"
echo "==================================================================="
echo "RIPPLED_ROOT: $RIPPLED_ROOT"
echo "BUILD_DIR:    $BUILD_DIR"
echo ""

# 1. Repo presence
echo "--- 1. Source tree ---"
if [[ -d "$RIPPLED_ROOT" ]]; then
    echo "  OK  Source tree present"
    cd "$RIPPLED_ROOT" 2>/dev/null
    BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "?")
    LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "(no tags)")
    echo "      Branch:   $BRANCH"
    echo "      Last tag: $LAST_TAG"
else
    echo "  XX  RIPPLED_ROOT not found"
    exit 1
fi
echo ""

# 2. Build directory
echo "--- 2. Build directory ---"
if [[ -d "$BUILD_DIR" ]]; then
    echo "  OK  build/ exists"
    BUILD_SIZE=$(du -sh "$BUILD_DIR" 2>/dev/null | cut -f1)
    echo "      Size: $BUILD_SIZE"
else
    echo "  XX  build/ does not exist - first-time build needed"
fi
echo ""

# 3. Conan state
echo "--- 3. Conan ---"
if command -v conan >/dev/null 2>&1; then
    CONAN_VER=$(conan --version 2>/dev/null)
    echo "  OK  $CONAN_VER"
else
    echo "  XX  conan command not found in PATH"
fi

if [[ -f "$TOOLCHAIN_FILE" ]]; then
    echo "  OK  Conan toolchain present: $TOOLCHAIN_FILE"
    TC_AGE=$(stat -c '%y' "$TOOLCHAIN_FILE" 2>/dev/null | cut -d. -f1)
    echo "      Last modified: $TC_AGE"
    echo "      => the benchmark script will SKIP conan install"
else
    echo "  XX  No Conan toolchain at $TOOLCHAIN_FILE"
    echo "      => the benchmark script will RUN conan install (slow)"
fi

if [[ -d "$HOME/.conan2" ]]; then
    CONAN_CACHE_SIZE=$(du -sh "$HOME/.conan2" 2>/dev/null | cut -f1)
    echo "      Conan cache size: $CONAN_CACHE_SIZE"
fi
echo ""

# 4. CMake state
echo "--- 4. CMake ---"
if command -v cmake >/dev/null 2>&1; then
    CMAKE_VER=$(cmake --version 2>/dev/null | head -1)
    echo "  OK  $CMAKE_VER"
fi

if [[ -f "$CMAKE_CACHE" ]]; then
    echo "  OK  CMakeCache.txt present"
    CC_AGE=$(stat -c '%y' "$CMAKE_CACHE" 2>/dev/null | cut -d. -f1)
    echo "      Last modified: $CC_AGE"
    BT=$(grep '^CMAKE_BUILD_TYPE:' "$CMAKE_CACHE" 2>/dev/null | cut -d= -f2)
    CC=$(grep '^CMAKE_C_COMPILER:' "$CMAKE_CACHE" 2>/dev/null | cut -d= -f2)
    CXX=$(grep '^CMAKE_CXX_COMPILER:' "$CMAKE_CACHE" 2>/dev/null | cut -d= -f2)
    echo "      Build type: $BT"
    echo "      C   compiler: $CC"
    echo "      C++ compiler: $CXX"
    echo "      => the benchmark script will SKIP cmake configure"
else
    echo "  XX  No CMakeCache.txt"
    echo "      => the benchmark script will RUN cmake configure"
fi
echo ""

# 5. Compiler versions
echo "--- 5. Compilers ---"
if [[ -x /usr/bin/gcc-13 ]]; then
    GCC13_VER=$(/usr/bin/gcc-13 --version | head -1)
    echo "  OK  $GCC13_VER"
else
    echo "  XX  /usr/bin/gcc-13 not present"
fi
if [[ -x /usr/bin/g++-13 ]]; then
    GXX13_VER=$(/usr/bin/g++-13 --version | head -1)
    echo "  OK  $GXX13_VER"
else
    echo "  XX  /usr/bin/g++-13 not present"
fi
echo ""

# 6. rippled binary
echo "--- 6. rippled binary ---"
if [[ -x "$RIPPLED_BIN" ]]; then
    RIPPLED_VER=$("$RIPPLED_BIN" --version 2>/dev/null | head -1 \
        || echo "(could not run --version)")
    BIN_AGE=$(stat -c '%y' "$RIPPLED_BIN" 2>/dev/null | cut -d. -f1)
    BIN_SIZE=$(du -h "$RIPPLED_BIN" 2>/dev/null | cut -f1)
    echo "  OK  Binary present: $RIPPLED_BIN"
    echo "      Version:       $RIPPLED_VER"
    echo "      Built:         $BIN_AGE"
    echo "      Size:          $BIN_SIZE"
else
    echo "  XX  No rippled binary at $RIPPLED_BIN"
fi
echo ""

# 7. Trusted-setup keys
echo "--- 7. Trusted-setup keys ---"
PK="/tmp/rippled_rollup_keys_pk"
VK="/tmp/rippled_rollup_keys_vk"
if [[ -f "$PK" && -f "$VK" ]]; then
    PK_SIZE=$(du -h "$PK" 2>/dev/null | cut -f1)
    VK_SIZE=$(du -h "$VK" 2>/dev/null | cut -f1)
    echo "  OK  Proving key:      $PK ($PK_SIZE)"
    echo "  OK  Verification key: $VK ($VK_SIZE)"
    echo "      => keygen will be SKIPPED (~60s saved)"
else
    echo "  XX  Keys missing at /tmp/rippled_rollup_keys_*"
    echo "      => First test run will spend ~60s on trusted setup"
fi
echo ""

# 8. Disk hygiene
echo "--- 8. Disk hygiene ---"
echo "  /tmp usage:"
df -h /tmp 2>/dev/null | tail -1 | awk '{printf "      %s used of %s (%s)\n", $3, $2, $5}'
echo "  Home usage:"
df -h "$HOME" 2>/dev/null | tail -1 | awk '{printf "      %s used of %s (%s)\n", $3, $2, $5}'
echo ""

# Summary
echo "==================================================================="
echo "Recommendation:"
echo "==================================================================="
if [[ -f "$TOOLCHAIN_FILE" && -f "$CMAKE_CACHE" && -x "$RIPPLED_BIN" ]]; then
    echo "  Everything is in place. The next benchmark run will be FAST:"
    echo "  it'll just do an incremental build of the new test files."
    echo ""
    echo "  Run:  bash tools/phase5/run_phase5.sh 5"
elif [[ -f "$TOOLCHAIN_FILE" && -f "$CMAKE_CACHE" ]]; then
    echo "  Conan + CMake already configured. Just need to compile rippled."
    echo ""
    echo "  Run:  bash tools/phase5/run_phase5.sh 5"
elif [[ -f "$TOOLCHAIN_FILE" ]]; then
    echo "  Conan installed but CMake not configured. The script will run"
    echo "  cmake configure + build (a few minutes), then the tests."
    echo ""
    echo "  Run:  bash tools/phase5/run_phase5.sh 5"
else
    echo "  First-time build. The script will run conan install + cmake"
    echo "  configure + build (~30-60 min), then the tests."
    echo ""
    echo "  Run:  bash tools/phase5/run_phase5.sh 5"
fi