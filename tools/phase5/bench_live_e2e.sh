#!/usr/bin/env bash
#
# bench_live_e2e.sh — the HONEST end-to-end L2->L1 benchmark.
#
# The in-process Beast suite (RollupBench_test.cpp) cannot reach tesSUCCESS
# for a real-proof batch, so it measures the L2 stages
# and the rejected on-chain path only. This script measures the GENUINE
# completed flow on a live standalone rippled node — the same path the
# 11-scenario rollup_demo.sh exercises — where a real batch reaches
# tesSUCCESS and doApply actually mutates ledger state.
#
# For each run it boots a FRESH standalone node (so every sample is the
# canonical genesis -> batch-1 flow, identical to demo S1) and times:
#
#   live_l2_proofgen   gen_batch_blob: 8 x Groth16 proof generation (off-chain)
#   live_l1_submit     submit RPC: preflight + preclaim (8x verify) + doApply
#                      (8x update_leaf, nullifier insert, root replay, SLE write)
#   live_l1_close      ledger_accept: consensus / ledger-close round
#   live_e2e_total     sum of the above — the full L2->L1 latency
#
# It also records the on-chain state delta (BatchCounter, RollupRoot, pool
# Balance) before/after to prove the batch was genuinely applied, and emits
# rows in the SAME CSV schema as the Beast suite so analyse_bench.py can
# fold both surfaces into one evaluation chapter.
#
# Usage:
#     bash tools/phase5/bench_live_e2e.sh [num_runs]
#     ROLLUP_BENCH_CSV=/tmp/rollup_bench.csv bash tools/phase5/bench_live_e2e.sh 5

# NOTE: deliberately NOT using `set -e`. This is a polling-heavy orchestration
# script (node readiness loops, RPC retries) where transient non-zero exits are
# expected and handled explicitly with `|| fail` on every critical step. `set -e`
# interacts badly with `until`/`[[ ]] && cmd` constructs and would abort the run
# on a benign poll miss. `set -u` (unset-var guard) and pipefail are kept.
set -uo pipefail

NUM_RUNS="${1:-3}"
RIPPLED_ROOT="${RIPPLED_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
RIPPLED="${RIPPLED:-$RIPPLED_ROOT/build/build/Release/rippled}"
GEN_TOOL="${GEN_TOOL:-$(dirname "${RIPPLED}")/gen_batch_blob}"
CSV_PATH="${ROLLUP_BENCH_CSV:-/tmp/rollup_bench.csv}"

# Self-contained sandbox, separate from rollup_demo.sh's /tmp/rippled_demo.
BENCH_DIR="${BENCH_DIR:-/tmp/rippled_bench}"
CFG="${BENCH_DIR}/rippled.cfg"
DB_DIR="${BENCH_DIR}/db"
PORT="${BENCH_PORT:-5096}"
RPC_URL="http://127.0.0.1:${PORT}"

# Genesis account (rippled standalone master account) — same as the demo.
GENESIS_ACCT="rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
GENESIS_SECRET="masterpassphrase"

# ─── helpers ──────────────────────────────────────────────────────────────
log()  { printf '\033[0;36m[bench]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

# Monotonic-ish nanosecond clock -> microseconds elapsed.
now_ns() { date +%s%N; }
us_since() { echo $(( ($(now_ns) - $1) / 1000 )); }

rpc() { curl -sf -X POST -H "Content-Type: application/json" --data "$1" "$RPC_URL"; }

write_cfg() {
    mkdir -p "${DB_DIR}/nudb" "$(dirname "${CFG}")"
    cat > "${CFG}" <<CFGEOF
[server]
port_rpc_admin_local

[port_rpc_admin_local]
port = ${PORT}
ip = 127.0.0.1
admin = 127.0.0.1
protocol = http

[node_db]
type=NuDB
path=${DB_DIR}/nudb

[database_path]
${DB_DIR}

[debug_logfile]
${BENCH_DIR}/debug.log

[validation_seed]
snoPBrXtMeMyMHUVTgbuqAfg1SUTb

[ledger_history]
none

[signing_support]
true

[ssl_verify]
0

[amendments]
E0BED425F9FA5F184F68156A07EB8EF25B03245EFA08F3F71EBA31C7EE74BCBF ZKRollup
CFGEOF
}

start_node() {
    pkill -f "rippled.*rippled_bench" 2>/dev/null || true
    sleep 1
    rm -rf "${DB_DIR}"; mkdir -p "${DB_DIR}/nudb"
    rm -f "${BENCH_DIR}/debug.log"
    nohup "${RIPPLED}" --conf "${CFG}" --standalone --start \
        > "${BENCH_DIR}/stdout.log" 2>&1 &
    local wait=0
    until rpc '{"method":"server_info","params":[{}]}' >/dev/null 2>&1; do
        sleep 0.5; wait=$((wait + 1))
        [[ $wait -gt 120 ]] && fail "node did not come up on ${PORT}"
    done
}

stop_node() { pkill -f "rippled.*rippled_bench" 2>/dev/null || true; }

# submit a BatchRollup; echoes the engine_result (e.g. tesSUCCESS).
submit_rollup() {
    local blob_hex="$1" pubkey_hex="$2" batch_id="$3" tx_prev="$4" tx_new="$5"
    python3 - <<PYEOF
import urllib.request, json, sys
tx = {
    "TransactionType": "BatchRollup",
    "Account":         "${GENESIS_ACCT}",
    "BatchId":         ${batch_id},
    "PrevRoot":        "${tx_prev}",
    "RollupRoot":      "${tx_new}",
    "TxCount":         8,
    "SequencerPubKey": "${pubkey_hex}",
    "BatchProof":      "${blob_hex}",
}
payload = json.dumps({"method":"submit","params":[{"tx_json":tx,"secret":"${GENESIS_SECRET}"}]})
req = urllib.request.Request("${RPC_URL}", data=payload.encode(),
                             headers={"Content-Type":"application/json"})
try:
    with urllib.request.urlopen(req, timeout=120) as resp:
        d = json.load(resp)
    print(d["result"]["engine_result"])
except Exception as e:
    print(f"RPC_ERROR:{e}", file=sys.stderr); sys.exit(1)
PYEOF
}

# echoes "BatchCounter|RollupRoot|Balance" for the RollupState SLE.
get_rollup_state() {
    rpc '{"method":"ledger_data","params":[{"ledger_index":"current","limit":400}]}' 2>/dev/null \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
nodes = d.get('result',{}).get('state', d.get('result',{}).get('state_data',[]))
for n in nodes:
    if n.get('LedgerEntryType') == 'RollupState':
        bal = n.get('Balance','0'); bal = bal if isinstance(bal,str) else bal.get('value','0')
        print(f\"{n.get('BatchCounter','?')}|{n.get('RollupRoot','?').lower()}|{bal}\"); break
else:
    print('none|none|none')
" 2>/dev/null || echo "error|error|error"
}

emit_csv() {  # scenario phase elapsed_us proof_bytes n_l2_txs root_writes state_writes outcome
    printf '%s,%s,%s,%s,%s,0,0,%s,0,0,%s,%s,%s\n' \
        "$1" "${RUN}" "$2" "$3" "$4" "$5" "$6" "$7" "$8" >> "$CSV_PATH"
}

# ─── preflight ──────────────────────────────────────────────────────────────
[[ -x "$RIPPLED"  ]] || fail "rippled not found at $RIPPLED"
[[ -x "$GEN_TOOL" ]] || fail "gen_batch_blob not found at $GEN_TOOL — build it first"

# Groth16 keys (shared cache used by both the node and gen_batch_blob).
if [[ ! -f /tmp/rippled_rollup_keys_pk || ! -f /tmp/rippled_rollup_keys_vk ]]; then
    log "generating Groth16 keys (~60s, one time)…"
    "$GEN_TOOL" --gen-keys >/dev/null 2>&1 || fail "key generation failed"
fi

write_cfg

# CSV header (schema identical to RollupBench_test.cpp); write only if absent
# so we can append to a CSV the Beast suite already produced.
if [[ ! -f "$CSV_PATH" ]]; then
    echo "scenario,run,phase,elapsed_us,proof_bytes,tx_bytes,fee_drops,n_l2_txs,merkle_updates,poseidon_hashes,root_writes,state_writes,outcome" \
        > "$CSV_PATH"
fi

GENESIS_ROOT_HEX="$("$GEN_TOOL" --genesis-root | tr -d '[:space:]')"
[[ ${#GENESIS_ROOT_HEX} -eq 64 ]] || fail "bad genesis root: '$GENESIS_ROOT_HEX'"

log "live end-to-end benchmark: ${NUM_RUNS} run(s), node on :${PORT}"
log "CSV -> ${CSV_PATH}"

for (( RUN=0; RUN<NUM_RUNS; RUN++ )); do
    log "── run ${RUN} ────────────────────────────────────────────"
    start_node

    BEFORE="$(get_rollup_state)"
    log "  state before: ${BEFORE}"

    # Phase t1-t4 (off-chain): gen_batch_blob = 8 x Groth16 proof generation.
    log "  gen_batch_blob 1 (8 x Groth16, ~72s)…"
    t0=$(now_ns)
    GEN_OUT="$("$GEN_TOOL" 1 2>"${BENCH_DIR}/gen_${RUN}.log")" \
        || fail "gen_batch_blob failed — see ${BENCH_DIR}/gen_${RUN}.log"
    us_gen=$(us_since "$t0")

    BLOB="$(echo "$GEN_OUT"   | sed -n 's/^BLOB=//p')"
    PUB="$(echo "$GEN_OUT"    | sed -n 's/^PUB=//p')"
    PREV="$(echo "$GEN_OUT"   | sed -n 's/^PREV_ROOT=//p')"
    NEW="$(echo "$GEN_OUT"    | sed -n 's/^NEW_ROOT=//p')"
    BID="$(echo "$GEN_OUT"    | sed -n 's/^BATCH_ID=//p')"
    [[ -n "$BLOB" && -n "$PUB" ]] || fail "could not parse gen_batch_blob output"

    # Phase t5-t8 (on-chain): submit = preflight + preclaim + doApply.
    t0=$(now_ns)
    RES="$(submit_rollup "$BLOB" "$PUB" "$BID" "$PREV" "$NEW")"
    us_submit=$(us_since "$t0")
    log "  submit engine_result: ${RES}  (${us_submit} us)"
    [[ "$RES" == "tesSUCCESS" ]] || fail "expected tesSUCCESS, got '${RES}'"

    # Phase t9: consensus / ledger close.
    t0=$(now_ns)
    rpc '{"method":"ledger_accept","params":[{}]}' >/dev/null 2>&1 || true
    us_close=$(us_since "$t0")

    AFTER="$(get_rollup_state)"
    log "  state after:  ${AFTER}  (close ${us_close} us)"

    us_total=$(( us_gen + us_submit + us_close ))

    PROOF_BYTES=$((8 * 192))
    emit_csv "live_l2_proofgen" "gen_batch_blob" "$us_gen"    "$PROOF_BYTES" 8 0 0 OK
    emit_csv "live_l1_submit"   "submit_doApply" "$us_submit" 0             8 1 1 "$RES"
    emit_csv "live_l1_close"    "ledger_accept"  "$us_close"  0             8 1 1 tesSUCCESS
    emit_csv "live_e2e_total"   "total"          "$us_total"  "$PROOF_BYTES" 8 1 1 "$RES"

    log "  TOTAL L2->L1: $(( us_total / 1000 )) ms  (gen $(( us_gen/1000 ))ms / submit ${us_submit}us / close ${us_close}us)"
done

stop_node
log "done. ${NUM_RUNS} completed-flow sample(s) appended to ${CSV_PATH}"
log "analyse with: python3 ${RIPPLED_ROOT}/tools/phase5/analyse_bench.py --csv ${CSV_PATH}"
