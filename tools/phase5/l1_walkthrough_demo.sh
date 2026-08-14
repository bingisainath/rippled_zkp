#!/usr/bin/env bash
#  l1_walkthrough_demo.sh — Narrate the FULL transaction flow (sequence-diagram
#  steps 1-22) for ONE real BatchRollup, end to end.
#
#  L2 side (steps 1-9):  gen_batch_blob --verbose  → printed from its stderr.
#  L1 side (steps 10-22): rippled runs with ZKR_WALKTHROUGH=1, which makes
#                         BatchVerifier's preflight/preclaim/doApply emit
#                         "[L1-WALKTHROUGH][STEP N]" lines into debug.log; this
#                         script greps and prints them after a tesSUCCESS submit.
#
#  One-shot: boots a node, submits ONE deposit batch, prints the whole flow,
#  then SHUTS THE NODE DOWN. Does not modify any existing script.
#  Separate port (5099), dir (/tmp/zkwt_node), pkill token (zkwt_node).
#
#  Usage:  bash tools/phase5/l1_walkthrough_demo.sh
set -uo pipefail

RIPPLED_ROOT="${RIPPLED_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
RIPPLED="${RIPPLED:-$RIPPLED_ROOT/build/build/Release/rippled}"
GEN_TOOL="${GEN_TOOL:-$(dirname "${RIPPLED}")/gen_batch_blob}"

WORK_DIR="${WORK_DIR:-/tmp/zkwt_node}"   # runtime only (db + logs); safe in /tmp
CFG="${WORK_DIR}/rippled.cfg"
DB_DIR="${WORK_DIR}/db"
LOG="${WORK_DIR}/debug.log"
PORT="${ZKWT_PORT:-5099}"
RPC_URL="http://127.0.0.1:${PORT}"
KILL_TOKEN="zkwt_node"

# Persistent evidence directory outside /tmp. Each run gets a
# timestamped subfolder so successive runs don't overwrite each other.
OUT_BASE="${OUT_DIR:-$HOME/walkthrough_evidence}"
RUN_DIR="${OUT_BASE}/run_$(date +%Y%m%d_%H%M%S)"
L2_TRACE="${RUN_DIR}/l2_trace.txt"
L1_TRACE="${RUN_DIR}/l1_trace.txt"

GENESIS_ACCT="rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
GENESIS_SECRET="snoPBrXtMeMyMHUVTgbuqAfg1SUTb"
ZKR_HASH="E0BED425F9FA5F184F68156A07EB8EF25B03245EFA08F3F71EBA31C7EE74BCBF"

C_HDR=$'\033[1;36m'; C_OK=$'\033[0;32m'; C_INFO=$'\033[0;34m'
C_WARN=$'\033[1;33m'; C_ERR=$'\033[0;31m'; C_L1=$'\033[1;35m'; C_OFF=$'\033[0m'
hdr()  { printf '\n%s══ %s ══%s\n' "$C_HDR" "$*" "$C_OFF"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_OK"  "$C_OFF" "$*"; }
info() { printf '%s[INFO]%s %s\n' "$C_INFO" "$C_OFF" "$*"; }
stop_node() { pkill -f "rippled.*${KILL_TOKEN}" 2>/dev/null || true; }
fail() { printf '%s[FAIL]%s %s\n' "$C_ERR" "$C_OFF" "$*"; stop_node; exit 1; }

rpc() { curl -sf -X POST -H "Content-Type: application/json" --data "$1" "$RPC_URL"; }
close_ledger() { rpc '{"method":"ledger_accept","params":[{}]}' >/dev/null 2>&1 || true; }

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
${LOG}

[validation_seed]
snoPBrXtMeMyMHUVTgbuqAfg1SUTb

[ledger_history]
none

[signing_support]
true

[ssl_verify]
0

[rpc_startup]
{ "command": "log_level", "severity": "info" }

[amendments]
${ZKR_HASH} ZKRollup
CFGEOF
}

start_node() {
    stop_node
    sleep 1
    rm -rf "${DB_DIR}"; mkdir -p "${DB_DIR}/nudb"; rm -f "${LOG}"
    # ZKR_WALKTHROUGH=1 turns on the [L1-WALKTHROUGH] narration in BatchVerifier.
    ZKR_WALKTHROUGH=1 nohup "${RIPPLED}" --conf "${CFG}" --standalone --start \
        > "${WORK_DIR}/stdout.log" 2>&1 &
    local w=0
    until rpc '{"method":"server_info","params":[{}]}' >/dev/null 2>&1; do
        sleep 0.5; w=$((w+1)); [[ $w -gt 120 ]] && fail "node did not start on :${PORT}"
    done
}

submit_rollup() {  # blob pub batchId prevRoot newRoot
    python3 - "$@" <<PYEOF
import urllib.request, json, sys
blob, pub, bid, prev, new = sys.argv[1:6]
tx = {"TransactionType":"BatchRollup","Account":"${GENESIS_ACCT}",
      "BatchId":int(bid),"PrevRoot":prev,"RollupRoot":new,"TxCount":8,
      "SequencerPubKey":pub,"BatchProof":blob}
body = json.dumps({"method":"submit","params":[{"tx_json":tx,"secret":"${GENESIS_SECRET}"}]})
req = urllib.request.Request("${RPC_URL}", data=body.encode(), headers={"Content-Type":"application/json"})
try:
    with urllib.request.urlopen(req, timeout=180) as resp:
        print(json.load(resp)["result"]["engine_result"])
except Exception as e:
    print(f"RPC_ERROR:{e}", file=sys.stderr); sys.exit(1)
PYEOF
}

# ─── preflight ──────────────────────────────────────────────
[[ -x "$RIPPLED"  ]] || fail "rippled not found at $RIPPLED"
[[ -x "$GEN_TOOL" ]] || fail "gen_batch_blob not found at $GEN_TOOL"
if [[ ! -f /tmp/rippled_rollup_keys_pk ]]; then
    info "generating Groth16 keys (~60s, one-time)…"
    "$GEN_TOOL" --gen-keys >/dev/null 2>&1 || fail "key generation failed"
fi

mkdir -p "${RUN_DIR}" || fail "cannot create evidence dir ${RUN_DIR}"

clear 2>/dev/null || true
cat <<BANNER
${C_HDR}╔══════════════════════════════════════════════════════════════════╗
║  ZK-ROLLUP FULL-FLOW WALKTHROUGH — sequence-diagram steps 1-22    ║
╚══════════════════════════════════════════════════════════════════╝${C_OFF}
BANNER

# ─── boot ───────────────────────────────────────────────────
hdr "Boot a standalone node with ZKR_WALKTHROUGH=1 (L1 narration ON)"
write_cfg
start_node
ok "Node live on :${PORT} (ZKR_WALKTHROUGH=1)"

# ─── L2 side: steps 1-9 ─────────────────────────────────────
hdr "L2 SIDE — sequence-diagram steps 1-9 (off-chain, in the sequencer)"
info "Running: gen_batch_blob 1 --verbose  (8 Groth16 proofs, ~25-30s)…"
GEN1="$("$GEN_TOOL" 1 --verbose 2>"${L2_TRACE}")" \
    || fail "deposit gen failed (see ${L2_TRACE})"
# Show the L2 trace (steps 1-9) — the [STEP n] lines from gen_batch_blob stderr.
grep -E "STEP|idx|DEPOSIT|WITHDRAW|VERBOSE|====" "${L2_TRACE}" || true
eval "$(echo "$GEN1" | grep -E '^(BLOB|PUB|PREV_ROOT|NEW_ROOT|BATCH_ID)=' | sed 's/^/D_/')"

# ─── submit → triggers L1 steps 10-22 ───────────────────────
hdr "SUBMIT to L1 — triggers the on-chain path (steps 10-22)"
RES1="$(submit_rollup "$D_BLOB" "$D_PUB" "$D_BATCH_ID" "$D_PREV_ROOT" "$D_NEW_ROOT")"
[[ "$RES1" == "tesSUCCESS" ]] || fail "deposit batch -> $RES1 (expected tesSUCCESS)"
close_ledger
ok "engine_result = ${RES1}"

# ─── L1 side: steps 10-22 from debug.log ────────────────────
hdr "L1 SIDE — sequence-diagram steps 10-22 (on the consensus hot path)"
sleep 1   # let the log flush
if grep -q "L1-WALKTHROUGH" "${LOG}" 2>/dev/null; then
    # Save the L1 trace (deduped to the first pass) into the evidence dir…
    grep "L1-WALKTHROUGH" "${LOG}" | sed -E 's/.*(\[L1-WALKTHROUGH\])/\1/' \
      | awk '!seen[$0]++' > "${L1_TRACE}"
    # …and print it to screen in colour.
    sed -E 's/^(\[L1-WALKTHROUGH\])/'"${C_L1}"'\1/; s/$/'"${C_OFF}"'/' "${L1_TRACE}"
else
    printf '%s[WARN]%s no [L1-WALKTHROUGH] lines in debug.log — check log_level/env\n' \
        "$C_WARN" "$C_OFF"
fi

# ─── done: shut the node down (one-shot) ────────────────────
hdr "DONE — full flow narrated (steps 1-22). Shutting node down."
stop_node
ok "Node on :${PORT} stopped."
ok "Evidence saved under ${RUN_DIR}:"
info "   L2 trace (steps 1-9)  : ${L2_TRACE}"
info "   L1 trace (steps 10-22): ${L1_TRACE}"
info "   (runtime db/full log remain in ${WORK_DIR})"
