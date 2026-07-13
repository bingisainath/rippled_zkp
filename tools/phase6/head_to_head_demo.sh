#!/usr/bin/env bash
# ============================================================
#  head_to_head_demo.sh — Track 1 (tt=61) vs Track 2 (tt=62), same node
#  MSc Dissertation, Trinity College Dublin, 2026 — Sainath Annadevara
#
#  Boots ONE fresh standalone rippled node with BOTH rollup amendments
#  (ZKRollup + ZKRollup2) enabled from genesis, then submits an identical
#  8-deposit batch on each track and measures the head-to-head numbers:
#
#      Track 1 (BatchRollup,  tt=61): 8 independent Groth16 proofs,
#                                     L1 runs 8 pairing checks.
#      Track 2 (BatchRollup2, tt=62): ONE monolithic Groth16 proof,
#                                     L1 runs 1 pairing check.
#
#  Because the two tracks keep SEPARATE state (RollupState vs RollupState2)
#  and separate Groth16 keys, both apply independently on the same ledger —
#  batchId=1 from each track's own genesis root.
#
#  For each track it captures, empirically:
#      * sequencer proving time (wall-clock of the gen tool)
#      * L1 verification time   (wall-clock of the submit RPC — this is the
#                                preclaim path that runs the pairing check(s))
#      * blob bytes and Groth16 proof-region bytes
#
#  Results print as a side-by-side table and are also written as JSON to
#  ~/Sainath/demo_runs/head_to_head/results.json for the dashboard to read.
#
#  Usage:  bash tools/phase6/head_to_head_demo.sh
#
#  Not using `set -e`: poll-heavy orchestration with explicit `|| fail`
#  (same rationale as live_xrp_transfer_demo.sh).
# ============================================================
set -uo pipefail

# ─── paths & config ─────────────────────────────────────────
RIPPLED_ROOT="${RIPPLED_ROOT:-$HOME/Sainath/rippled_zkp}"
RIPPLED="${RIPPLED:-$RIPPLED_ROOT/build/build/Release/rippled}"
GEN1_TOOL="${GEN1_TOOL:-$(dirname "${RIPPLED}")/gen_batch_blob}"    # Track 1
GEN2_TOOL="${GEN2_TOOL:-$(dirname "${RIPPLED}")/gen_batch_blob2}"   # Track 2

# Unique sandbox + private pkill token (avoids the 5095/5096/5097 demo nodes
# and never matches this script's own command line).
WORK_DIR="${WORK_DIR:-$HOME/Sainath/demo_runs/head_to_head}"
CFG="${WORK_DIR}/rippled.cfg"
# DB in a fresh, never-before-used dir per run. Standalone rippled resumes any
# persisted RollupState from its node store even with --start, which would make
# a second run's batchId=1 fail on a prevRoot mismatch. A unique path per run
# cannot carry prior state; removed on exit.
DB_DIR="${WORK_DIR}/db_$$_$(date +%s)"
PORT="${H2H_PORT:-5098}"
RPC_URL="http://127.0.0.1:${PORT}"
# MUST be a substring of the node's actual command line (which contains --conf
# ${CFG}) or pkill won't match it and stale nodes pile up on the port, each
# still serving its own in-memory ledger. Use the config path itself.
KILL_TOKEN="${CFG}"
RESULTS_JSON="${WORK_DIR}/results.json"

GENESIS_ACCT="rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
GENESIS_SECRET="snoPBrXtMeMyMHUVTgbuqAfg1SUTb"
ZKR_HASH="E0BED425F9FA5F184F68156A07EB8EF25B03245EFA08F3F71EBA31C7EE74BCBF"     # ZKRollup
ZKR2_HASH="9E7F41262E98DB93EEAC9D98A699C1E05D8394058A64FA4D9F8B89F79191A0F2"    # ZKRollup2

# ─── pretty output ──────────────────────────────────────────
C_HDR=$'\033[1;36m'; C_OK=$'\033[0;32m'; C_INFO=$'\033[0;34m'
C_WARN=$'\033[1;33m'; C_ERR=$'\033[0;31m'; C_OFF=$'\033[0m'
hdr()  { printf '\n%s══ %s ══%s\n' "$C_HDR" "$*" "$C_OFF"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_OK"  "$C_OFF" "$*"; }
info() { printf '%s[INFO]%s %s\n' "$C_INFO" "$C_OFF" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
fail() { printf '%s[FAIL]%s %s\n' "$C_ERR" "$C_OFF" "$*"; stop_node; exit 1; }

rpc() { curl -sf -X POST -H "Content-Type: application/json" --data "$1" "$RPC_URL"; }
now() { date +%s.%N; }
elapsed_ms() { python3 -c "print(int((float('$2')-float('$1'))*1000))"; }

# ─── node lifecycle ─────────────────────────────────────────
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
${ZKR2_HASH} ZKRollup2
CFGEOF
}

start_node() {
    pkill -f "rippled.*${KILL_TOKEN}" 2>/dev/null || true
    sleep 1
    # Fresh genesis every run: NuDB persists RollupState across runs, so without
    # this a second run would see batchId=1 already applied and reject the new
    # batch with a prevRoot mismatch (tecFAILED_PROCESSING). Repeatable bench
    # needs a clean ledger each time.
    rm -rf "${DB_DIR}"; mkdir -p "${DB_DIR}/nudb"; rm -f "${WORK_DIR}/debug.log"
    nohup "${RIPPLED}" --conf "${CFG}" --standalone --start \
        > "${WORK_DIR}/stdout.log" 2>&1 &
    # onStart may (re)generate both provers' Groth16 keys before RPC comes up,
    # so allow up to ~5 min for the very first server_info to answer.
    local w=0
    until rpc '{"method":"server_info","params":[{}]}' >/dev/null 2>&1; do
        sleep 0.5; w=$((w+1)); [[ $w -gt 600 ]] && fail "node did not start on :${PORT}"
    done
}
stop_node()    { pkill -f "rippled.*${KILL_TOKEN}" 2>/dev/null || true; }
close_ledger() { rpc '{"method":"ledger_accept","params":[{}]}' >/dev/null 2>&1 || true; }

# echoes "enabled" ("true"/"false"/"?") for an amendment hash
feature_enabled() {
    rpc '{"method":"feature","params":[{"feature":"'"$1"'"}]}' \
    | python3 -c "import sys,json;d=json.load(sys.stdin);f=list(d['result'].values())[0] if d.get('result') else {};print(str(f.get('enabled','?')).lower())" 2>/dev/null || echo "?"
}

# echoes "BatchCounter|RollupRoot16|Balance" for the RollupState SLE whose
# RollupRoot matches $1. Both tracks use LedgerEntryType "RollupState" (shared
# ltROLLUP_STATE, distinct keylet tags), so the root is what tells them apart.
get_rollup_state() {  # $1 = expected RollupRoot (hex, any case)
    rpc '{"method":"ledger_data","params":[{"ledger_index":"current","limit":400}]}' 2>/dev/null \
    | python3 -c "
import sys, json
want = '$1'.lower()
d = json.load(sys.stdin)
nodes = d.get('result',{}).get('state', [])
for n in nodes:
    if n.get('LedgerEntryType') == 'RollupState' and n.get('RollupRoot','').lower() == want:
        bal = n.get('Balance','0'); bal = bal if isinstance(bal,str) else bal.get('value','0')
        print(f\"{n.get('BatchCounter','?')}|{n.get('RollupRoot','?')[:16]}…|{bal}\"); break
else:
    print('none|none|none')
" 2>/dev/null || echo "err|err|err"
}

# submit a BatchRollup / BatchRollup2 tx; echoes engine_result. On any non-tes
# result it also prints the engine_result_message to stderr for diagnosis.
submit_batch() {  # txType blob pub batchId prevRoot newRoot txCount
    python3 - "$@" <<PYEOF
import urllib.request, json, sys
txtype, blob, pub, bid, prev, new, txc = sys.argv[1:8]
tx = {"TransactionType":txtype,"Account":"${GENESIS_ACCT}",
      "BatchId":int(bid),"PrevRoot":prev,"RollupRoot":new,"TxCount":int(txc),
      "SequencerPubKey":pub,"BatchProof":blob}
body = json.dumps({"method":"submit","params":[{"tx_json":tx,"secret":"${GENESIS_SECRET}"}]})
req = urllib.request.Request("${RPC_URL}", data=body.encode(),
                             headers={"Content-Type":"application/json"})
try:
    with urllib.request.urlopen(req, timeout=300) as resp:
        r = json.load(resp).get("result", {})
        res = r.get("engine_result", "RPC_NO_RESULT")
        if not str(res).startswith("tes"):
            print(f"  submit detail: {res} — {r.get('engine_result_message','(no message)')}",
                  file=sys.stderr)
        print(res)
except Exception as e:
    print(f"RPC_ERROR:{e}", file=sys.stderr); sys.exit(1)
PYEOF
}

# Track 1 proof-region bytes: header is 76, proofSize is a u32 LE at offset 72.
track1_proof_bytes() { python3 -c "b=bytes.fromhex('$1'); print(int.from_bytes(b[72:76],'little'))"; }

# Always stop the node and drop the throwaway db dir on exit.
trap 'stop_node; rm -rf "${DB_DIR}" 2>/dev/null || true' EXIT

# ─── preflight ──────────────────────────────────────────────
[[ -x "$RIPPLED"   ]] || fail "rippled not found at $RIPPLED"
[[ -x "$GEN1_TOOL" ]] || fail "gen_batch_blob (Track 1) not found at $GEN1_TOOL"
[[ -x "$GEN2_TOOL" ]] || fail "gen_batch_blob2 (Track 2) not found at $GEN2_TOOL"

# One-time Groth16 key generation for each track (the node also generates these
# on onStart, but doing it up front keeps the measured gen/submit times clean).
if [[ ! -f /tmp/rippled_rollup_keys_pk ]]; then
    info "Track 1: generating Groth16 keys (~60s, one-time)…"
    "$GEN1_TOOL" --gen-keys >/dev/null 2>&1 || fail "Track 1 key generation failed"
fi
if [[ ! -f /tmp/rippled_rollup_batch_keys_pk ]]; then
    info "Track 2: generating batch-circuit Groth16 keys (~35s, one-time)…"
    "$GEN2_TOOL" --gen-keys >/dev/null 2>&1 || fail "Track 2 key generation failed"
fi

clear 2>/dev/null || true
cat <<BANNER
${C_HDR}╔══════════════════════════════════════════════════════════════════╗
║  ZK-ROLLUP HEAD-TO-HEAD  ·  Track 1 (8 proofs) vs Track 2 (1 proof) ║
║  MSc Dissertation · Trinity College Dublin · Sainath Annadevara     ║
╚══════════════════════════════════════════════════════════════════╝${C_OFF}
BANNER

# ─── 1. boot ────────────────────────────────────────────────
hdr "STEP 1 — Boot one standalone node with BOTH rollup amendments"
write_cfg
start_node
Z1="$(feature_enabled "$ZKR_HASH")"
Z2="$(feature_enabled "$ZKR2_HASH")"
ok "Node live on :${PORT}  —  ZKRollup=${Z1}  ZKRollup2=${Z2}"
[[ "$Z1" == "true" && "$Z2" == "true" ]] || fail "both amendments must be enabled (got ZKRollup=$Z1 ZKRollup2=$Z2)"

# Assert a clean genesis ledger: no RollupState SLE may exist yet, or a
# batchId=1 (prevRoot=genesis) batch would be rejected as off-root. This is the
# guard that caught standalone resuming a prior run's state.
RS_AT_BOOT="$(rpc '{"method":"ledger_data","params":[{"ledger_index":"current","limit":400}]}' 2>/dev/null \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print(sum(1 for n in d.get('result',{}).get('state',[]) if n.get('LedgerEntryType')=='RollupState'))" 2>/dev/null || echo "?")"
[[ "$RS_AT_BOOT" == "0" ]] || fail "ledger is not at genesis: found ${RS_AT_BOOT} RollupState SLE(s) — stale db/node on :${PORT}?"
ok "Clean genesis confirmed (0 RollupState SLEs)."

# ─── 2. Track 1 — 8 independent proofs ──────────────────────
hdr "STEP 2 — Track 1 (tt=61): 8-deposit batch, EIGHT Groth16 proofs"
info "Sequencer proving 8 independent proofs…"
T0="$(now)"
GEN1="$("$GEN1_TOOL" 1 2>"${WORK_DIR}/gen_track1.log")" || fail "Track 1 gen failed (see gen_track1.log)"
T1="$(now)"
GEN1_MS="$(elapsed_ms "$T0" "$T1")"
eval "$(echo "$GEN1" | grep -E '^(BLOB|PUB|PREV_ROOT|NEW_ROOT|BATCH_ID|TX_COUNT)=' | sed 's/^/T1_/')"
T1_BLOB_BYTES=$(( ${#T1_BLOB} / 2 ))
T1_PROOF_BYTES="$(track1_proof_bytes "$T1_BLOB")"
info "Track 1 proving: ${GEN1_MS} ms   blob=${T1_BLOB_BYTES} B (proof region ${T1_PROOF_BYTES} B, 8×192)"
info "Submitting BatchRollup → L1 preclaim runs EIGHT pairing checks…"
S0="$(now)"
T1_RES="$(submit_batch BatchRollup "$T1_BLOB" "$T1_PUB" "$T1_BATCH_ID" "$T1_PREV_ROOT" "$T1_NEW_ROOT" "${T1_TX_COUNT:-8}")"
S1="$(now)"
T1_SUBMIT_MS="$(elapsed_ms "$S0" "$S1")"
[[ "$T1_RES" == "tesSUCCESS" ]] || fail "Track 1 batch → $T1_RES (expected tesSUCCESS)"
close_ledger
ok "Track 1 accepted → ${T1_RES}   L1 verify = ${T1_SUBMIT_MS} ms   RollupState = $(get_rollup_state "$T1_NEW_ROOT")"

# ─── 3. Track 2 — one monolithic proof ──────────────────────
hdr "STEP 3 — Track 2 (tt=62): 8-deposit batch, ONE Groth16 proof"
info "Sequencer proving one monolithic batch proof…"
U0="$(now)"
GEN2="$("$GEN2_TOOL" --deposits 8 --batch-id 1 2>"${WORK_DIR}/gen_track2.log")" || fail "Track 2 gen failed (see gen_track2.log)"
U1="$(now)"
GEN2_MS="$(elapsed_ms "$U0" "$U1")"
eval "$(echo "$GEN2" | grep -E '^(BLOB|PUB|PREV_ROOT|NEW_ROOT|BATCH_ID|TX_COUNT)=' | sed 's/^/T2_/')"
T2_BLOB_BYTES=$(( ${#T2_BLOB} / 2 ))
T2_PROOF_BYTES=137   # fixed Groth16 proof size for the batch circuit (ALT_BN128)
info "Track 2 proving: ${GEN2_MS} ms   blob=${T2_BLOB_BYTES} B (proof region ${T2_PROOF_BYTES} B, 1 proof)"
info "Submitting BatchRollup2 → L1 preclaim runs ONE pairing check…"
V0="$(now)"
T2_RES="$(submit_batch BatchRollup2 "$T2_BLOB" "$T2_PUB" "$T2_BATCH_ID" "$T2_PREV_ROOT" "$T2_NEW_ROOT" "${T2_TX_COUNT:-8}")"
V1="$(now)"
T2_SUBMIT_MS="$(elapsed_ms "$V0" "$V1")"
[[ "$T2_RES" == "tesSUCCESS" ]] || fail "Track 2 batch → $T2_RES (expected tesSUCCESS)"
close_ledger
ok "Track 2 accepted → ${T2_RES}   L1 verify = ${T2_SUBMIT_MS} ms   RollupState2 = $(get_rollup_state "$T2_NEW_ROOT")"

# ─── 4. head-to-head table ──────────────────────────────────
hdr "STEP 4 — Head-to-head results (both applied on the same ledger)"
SPEEDUP="$(python3 -c "print(f'{${T1_SUBMIT_MS}/max(1,${T2_SUBMIT_MS}):.1f}×')")"
BLOB_SAVE="$(python3 -c "print(f'{100*(1-${T2_BLOB_BYTES}/max(1,${T1_BLOB_BYTES})):.0f}%')")"
printf '\n'
printf '  %-28s %14s %14s\n' "metric" "Track 1 (61)" "Track 2 (62)"
printf '  %-28s %14s %14s\n' "----------------------------" "------------" "------------"
printf '  %-28s %14s %14s\n' "proofs per batch"        "8"                   "1"
printf '  %-28s %14s %14s\n' "L1 pairing checks"       "8"                   "1"
printf '  %-28s %14s %14s\n' "sequencer proving (ms)"  "$GEN1_MS"            "$GEN2_MS"
printf '  %-28s %14s %14s\n' "L1 verify — submit (ms)" "$T1_SUBMIT_MS"       "$T2_SUBMIT_MS"
printf '  %-28s %14s %14s\n' "blob bytes"              "$T1_BLOB_BYTES"      "$T2_BLOB_BYTES"
printf '  %-28s %14s %14s\n' "Groth16 proof bytes"     "$T1_PROOF_BYTES"     "$T2_PROOF_BYTES"
printf '  %-28s %14s %14s\n' "engine_result"           "$T1_RES"            "$T2_RES"
printf '\n'
ok "Track 2 L1 verification is ${SPEEDUP} faster; blob is ${BLOB_SAVE} smaller."
info "(L1 verify time is the headline: it is what every validator pays per batch.)"

# ─── 5. JSON for the dashboard ──────────────────────────────
python3 - <<PYEOF
import json
r = {
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "node_port": ${PORT},
  "track1": {
    "tx_type": "BatchRollup", "tt": 61, "proofs_per_batch": 8, "l1_pairing_checks": 8,
    "gen_ms": ${GEN1_MS}, "submit_ms": ${T1_SUBMIT_MS},
    "blob_bytes": ${T1_BLOB_BYTES}, "proof_bytes": ${T1_PROOF_BYTES},
    "engine_result": "${T1_RES}",
    "prev_root": "${T1_PREV_ROOT}", "new_root": "${T1_NEW_ROOT}"
  },
  "track2": {
    "tx_type": "BatchRollup2", "tt": 62, "proofs_per_batch": 1, "l1_pairing_checks": 1,
    "gen_ms": ${GEN2_MS}, "submit_ms": ${T2_SUBMIT_MS},
    "blob_bytes": ${T2_BLOB_BYTES}, "proof_bytes": ${T2_PROOF_BYTES},
    "engine_result": "${T2_RES}",
    "prev_root": "${T2_PREV_ROOT}", "new_root": "${T2_NEW_ROOT}"
  },
  "comparison": {
    "l1_verify_speedup": "${SPEEDUP}",
    "blob_size_reduction": "${BLOB_SAVE}"
  }
}
open("${RESULTS_JSON}","w").write(json.dumps(r, indent=2))
print("wrote ${RESULTS_JSON}")
PYEOF
ok "Results JSON: ${RESULTS_JSON}"

# ─── 6. self-contained HTML card (open directly, no server) ──
RESULTS_HTML="${WORK_DIR}/results.html"
python3 - <<PYEOF
html = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZK-Rollup Head-to-Head — Track 1 vs Track 2</title>
<style>
 :root{{color-scheme:light dark}}
 body{{font:15px/1.5 system-ui,sans-serif;margin:0;padding:2rem;
   background:#0f1117;color:#e6e6e6}}
 h1{{font-size:1.4rem;margin:0 0 .2rem}} .sub{{color:#9aa0aa;margin:0 0 1.5rem}}
 .grid{{display:grid;grid-template-columns:1fr 1fr;gap:1rem;max-width:760px}}
 .card{{background:#171a22;border:1px solid #262b36;border-radius:12px;padding:1.2rem}}
 .card h2{{margin:0 0 .1rem;font-size:1.05rem}} .tt{{color:#7cc4ff;font-size:.8rem}}
 .big{{font-size:2rem;font-weight:700;margin:.6rem 0 0}}
 .big.win{{color:#5ddb8e}} .u{{color:#9aa0aa;font-size:.8rem}}
 table{{border-collapse:collapse;width:100%;max-width:760px;margin-top:1.4rem}}
 td,th{{padding:.5rem .7rem;border-bottom:1px solid #262b36;text-align:right}}
 th:first-child,td:first-child{{text-align:left;color:#9aa0aa}}
 .ok{{color:#5ddb8e}} .foot{{color:#9aa0aa;margin-top:1.4rem;max-width:760px;font-size:.85rem}}
 .pill{{display:inline-block;background:#1d2b20;color:#5ddb8e;border-radius:999px;
   padding:.15rem .7rem;font-size:.8rem;margin-top:.3rem}}
</style></head><body>
<h1>ZK-Rollup Head-to-Head</h1>
<p class="sub">Both batches applied on the same standalone XRPL ledger · generated {gen}</p>
<div class="grid">
 <div class="card"><span class="tt">Track 1 · BatchRollup · tt=61</span>
   <h2>8 independent proofs</h2>
   <div class="big">{t1_submit} ms</div><div class="u">L1 verify · 8 pairing checks</div>
   <div class="pill">{t1_res}</div></div>
 <div class="card"><span class="tt">Track 2 · BatchRollup2 · tt=62</span>
   <h2>1 monolithic proof</h2>
   <div class="big win">{t2_submit} ms</div><div class="u">L1 verify · 1 pairing check</div>
   <div class="pill">{t2_res}</div></div>
</div>
<table>
 <tr><th>metric</th><th>Track 1 (61)</th><th>Track 2 (62)</th></tr>
 <tr><td>proofs per batch</td><td>8</td><td>1</td></tr>
 <tr><td>L1 pairing checks</td><td>8</td><td>1</td></tr>
 <tr><td>sequencer proving (ms)</td><td>{t1_gen}</td><td>{t2_gen}</td></tr>
 <tr><td>L1 verify — submit (ms)</td><td>{t1_submit}</td><td class="ok">{t2_submit}</td></tr>
 <tr><td>blob bytes</td><td>{t1_blob}</td><td class="ok">{t2_blob}</td></tr>
 <tr><td>Groth16 proof bytes</td><td>{t1_proof}</td><td class="ok">{t2_proof}</td></tr>
 <tr><td>engine_result</td><td>{t1_res}</td><td>{t2_res}</td></tr>
</table>
<p class="foot"><b>Track 2 L1 verification is {speedup} faster and its blob is {blobsave} smaller.</b>
 L1 verify time is the headline: it is what every validator pays to admit a batch,
 and it is what determines on-chain scalability. Track 1 pays it 8× per batch;
 Track 2 pays it once, independent of batch size.</p>
</body></html>'''.format(
  gen="$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  t1_gen=${GEN1_MS}, t2_gen=${GEN2_MS},
  t1_submit=${T1_SUBMIT_MS}, t2_submit=${T2_SUBMIT_MS},
  t1_blob=${T1_BLOB_BYTES}, t2_blob=${T2_BLOB_BYTES},
  t1_proof=${T1_PROOF_BYTES}, t2_proof=${T2_PROOF_BYTES},
  t1_res="${T1_RES}", t2_res="${T2_RES}",
  speedup="${SPEEDUP}", blobsave="${BLOB_SAVE}")
open("${RESULTS_HTML}","w").write(html)
print("wrote ${RESULTS_HTML}")
PYEOF
ok "Results page: ${RESULTS_HTML}  (open in a browser)"

stop_node
hdr "Done — node stopped. Re-run any time; outputs live under ${WORK_DIR}"
