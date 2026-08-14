#!/usr/bin/env bash
#  accumulate_xrp_demo.sh — "Watch XRP ACCUMULATE across ZK withdrawal batches"
#
#  Unlike live_xrp_transfer_demo.sh (which boots a FRESH node every run and so
#  always ends at 30 XRP), this script boots ONE persistent node and leaves it
#  running. You then submit successive withdrawal batches yourself and watch the
#  destination balance climb: 30 -> 50 -> 70 -> 90 ...
#
#  It does NOT modify or depend on live_xrp_transfer_demo.sh or ~/rollup_demo.sh.
#  Separate port (5098), dir (/tmp/zkacc_node) and pkill token (zkacc_node).
#
#    1. boot a fresh standalone node (stays UP until you kill it)
#    2. submit a DEPOSIT batch (8 deposits) -> rollup pool funded to 160 XRP
#    3. pre-fund the destination with the 10 XRP reserve (normal Payment)
#    4. print ready-to-paste commands; each adds +20 XRP via a ZK proof
#
#  Usage:  bash tools/phase5/accumulate_xrp_demo.sh
#  Then:   bash tools/phase5/withdraw_round.sh 2    # 30 XRP
#          bash tools/phase5/withdraw_round.sh 3    # 50 XRP
#          bash tools/phase5/withdraw_round.sh 4    # 70 XRP
#  Stop:   pkill -f "rippled.*zkacc_node"
set -uo pipefail

RIPPLED_ROOT="${RIPPLED_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
RIPPLED="${RIPPLED:-$RIPPLED_ROOT/build/build/Release/rippled}"
GEN_TOOL="${GEN_TOOL:-$(dirname "${RIPPLED}")/gen_batch_blob}"

WORK_DIR="${WORK_DIR:-/tmp/zkacc_node}"
CFG="${WORK_DIR}/rippled.cfg"
DB_DIR="${WORK_DIR}/db"
PORT="${ZKACC_PORT:-5098}"
RPC_URL="http://127.0.0.1:${PORT}"
KILL_TOKEN="zkacc_node"

GENESIS_ACCT="rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
GENESIS_SECRET="snoPBrXtMeMyMHUVTgbuqAfg1SUTb"
ZKR_HASH="E0BED425F9FA5F184F68156A07EB8EF25B03245EFA08F3F71EBA31C7EE74BCBF"
DEST="${DEST:-rQsWK5BwuZY2kcCiyjx3z24LxKfbcDYBLg}"

C_HDR=$'\033[1;36m'; C_OK=$'\033[0;32m'; C_INFO=$'\033[0;34m'
C_WARN=$'\033[1;33m'; C_ERR=$'\033[0;31m'; C_OFF=$'\033[0m'
hdr()  { printf '\n%s══ %s ══%s\n' "$C_HDR" "$*" "$C_OFF"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_OK"  "$C_OFF" "$*"; }
info() { printf '%s[INFO]%s %s\n' "$C_INFO" "$C_OFF" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
# NOTE: on failure we DO NOT kill the node — leave it up for inspection.
fail() { printf '%s[FAIL]%s %s\n' "$C_ERR" "$C_OFF" "$*"; exit 1; }

rpc() { curl -sf -X POST -H "Content-Type: application/json" --data "$1" "$RPC_URL"; }
close_ledger() { rpc '{"method":"ledger_accept","params":[{}]}' >/dev/null 2>&1 || true; }
drops_to_xrp() { python3 -c "print(f'{int(\"$1\")/1_000_000:.6f}')" 2>/dev/null || echo "?"; }

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
${WORK_DIR}/debug.log

[validation_seed]
snoPBrXtMeMyMHUVTgbuqAfg1SUTb

[ledger_history]
none

[signing_support]
true

[ssl_verify]
0

[amendments]
${ZKR_HASH} ZKRollup
CFGEOF
}

start_node() {
    pkill -f "rippled.*${KILL_TOKEN}" 2>/dev/null || true
    sleep 1
    rm -rf "${DB_DIR}"; mkdir -p "${DB_DIR}/nudb"; rm -f "${WORK_DIR}/debug.log"
    nohup "${RIPPLED}" --conf "${CFG}" --standalone --start \
        > "${WORK_DIR}/stdout.log" 2>&1 &
    local w=0
    until rpc '{"method":"server_info","params":[{}]}' >/dev/null 2>&1; do
        sleep 0.5; w=$((w+1)); [[ $w -gt 120 ]] && fail "node did not start on :${PORT}"
    done
}

get_pool() {
    rpc '{"method":"ledger_data","params":[{"ledger_index":"current","limit":400}]}' 2>/dev/null \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
for n in d.get('result',{}).get('state',[]):
    if n.get('LedgerEntryType') == 'RollupState':
        print(f\"{n.get('BatchCounter','?')}|{n.get('RollupRoot','?')[:16]}…|{n.get('Balance','0')}\"); break
else:
    print('none|none|none')
" 2>/dev/null || echo "error|error|error"
}

get_balance() {
    rpc "{\"method\":\"account_info\",\"params\":[{\"account\":\"$1\",\"ledger_index\":\"current\"}]}" 2>/dev/null \
    | python3 -c "import sys,json;r=json.load(sys.stdin).get('result',{});print(r.get('account_data',{}).get('Balance','DOES_NOT_EXIST') if 'account_data' in r else 'DOES_NOT_EXIST')" 2>/dev/null \
    || echo "DOES_NOT_EXIST"
}

prefund() {  # account drops — normal Payment from genesis
    python3 - "$@" <<PYEOF
import urllib.request, json, sys
acct, drops = sys.argv[1], sys.argv[2]
tx = {"TransactionType":"Payment","Account":"${GENESIS_ACCT}","Destination":acct,"Amount":str(drops)}
body = json.dumps({"method":"submit","params":[{"tx_json":tx,"secret":"${GENESIS_SECRET}"}]})
req = urllib.request.Request("${RPC_URL}", data=body.encode(), headers={"Content-Type":"application/json"})
try:
    with urllib.request.urlopen(req, timeout=60) as resp:
        print(json.load(resp)["result"]["engine_result"])
except Exception as e:
    print(f"RPC_ERROR:{e}", file=sys.stderr); sys.exit(1)
PYEOF
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

clear 2>/dev/null || true
cat <<BANNER
${C_HDR}╔══════════════════════════════════════════════════════════════════╗
║   ZK-ROLLUP LIVE DEMO — XRP ACCUMULATES across ZK withdrawals     ║
╚══════════════════════════════════════════════════════════════════╝${C_OFF}
BANNER

# ─── 1. boot ────────────────────────────────────────────────
hdr "STEP 1 — Boot a fresh standalone XRPL node (it will STAY UP)"
write_cfg
start_node
ZKR=$(rpc '{"method":"feature","params":[{"feature":"'"${ZKR_HASH}"'"}]}' \
      | python3 -c "import sys,json;d=json.load(sys.stdin);f=list(d['result'].values())[0] if d.get('result') else {};print(f.get('enabled','?'))" 2>/dev/null)
ok "Node live on :${PORT} — featureZKRollup enabled = ${ZKR}"
info "Rollup state at genesis: $(get_pool)  (BatchCounter|Root|PoolDrops)"

# ─── 2. deposit batch funds the pool ────────────────────────
hdr "STEP 2 — Submit a DEPOSIT batch (8 ZK proofs) to fund the rollup pool"
info "Generating 8 Groth16 proofs (~25-30s)…"
GEN1="$("$GEN_TOOL" 1 2>"${WORK_DIR}/gen_deposit.log")" || fail "deposit gen failed (see gen_deposit.log)"
eval "$(echo "$GEN1" | grep -E '^(BLOB|PUB|PREV_ROOT|NEW_ROOT|BATCH_ID)=' | sed 's/^/D_/')"
RES1="$(submit_rollup "$D_BLOB" "$D_PUB" "$D_BATCH_ID" "$D_PREV_ROOT" "$D_NEW_ROOT")"
[[ "$RES1" == "tesSUCCESS" ]] || fail "deposit batch -> $RES1 (expected tesSUCCESS)"
close_ledger
IFS='|' read -r CTR ROOT POOL <<< "$(get_pool)"
ok "Rollup pool funded: BatchCounter=${CTR}, pool=${POOL} drops ($(drops_to_xrp "$POOL") XRP)"

# ─── 3. pre-fund destination ────────────────────────────────
hdr "STEP 3 — Pre-fund the withdrawal destination with the 10 XRP reserve"
info "Destination: ${DEST}"
info "(A BatchRollup cannot CREATE a new account — rippled invariant — so we seed"
info " it once with a normal Payment; each ZK withdrawal then ADDS +20 XRP.)"
PF="$(prefund "$DEST" 10000000)"
[[ "$PF" == "tesSUCCESS" ]] || fail "pre-fund payment -> $PF"
close_ledger
BAL="$(get_balance "$DEST")"
ok "account_info -> Balance = ${BAL} drops ($(drops_to_xrp "$BAL") XRP, reserve only)"

# ─── 4. hand off to the user ────────────────────────────────
hdr "READY — node is UP. Add +20 XRP per command, watch it accumulate"
cat <<NEXT
${C_OK}
  The node is running on :${PORT} and will stay up until you kill it.
  Each command below generates 8 Groth16 proofs (~25-30s) and submits one
  withdrawal batch that credits +20 XRP to ${DEST}:

     bash tools/phase5/withdraw_round.sh 2     # -> 30 XRP
     bash tools/phase5/withdraw_round.sh 3     # -> 50 XRP
     bash tools/phase5/withdraw_round.sh 4     # -> 70 XRP
     bash tools/phase5/withdraw_round.sh 5     # -> 90 XRP   (and so on)

  IMPORTANT: run them in order (batchId must be strictly increasing, and each
  batch chains its prevRoot from the previous one — that is the rollup's
  append-only invariant working as designed).

  Check the destination balance any time:
     ${RIPPLED} --conf ${CFG} account_info ${DEST}

  Inspect the rollup pool / root / counter any time:
     curl -s -X POST -H "Content-Type: application/json" \\
       --data '{"method":"ledger_data","params":[{"ledger_index":"current","limit":400}]}' \\
       ${RPC_URL} | python3 -m json.tool | grep -A6 RollupState

  When finished, stop the node:
     pkill -f "rippled.*${KILL_TOKEN}"
${C_OFF}
NEXT
ok "Setup complete. Node left running on :${PORT}."
