#!/usr/bin/env python3
# Copyright (c) 2026 Sainath Annadevara — Trinity College Dublin
# MSc dissertation: ZK Rollup on XRPL — Phase 5
#
# analyse_bench.py — consumes /tmp/rollup_bench.csv emitted by the
# RollupBench unittest and produces dissertation evaluation artefacts:
#
#   summary.md           — Markdown table for the evaluation chapter
#   summary.tex          — booktabs LaTeX table fragment, \input{}able
#   fig_proof_pipeline.pdf — bar chart: prove / verify / on-chain pipeline
#   fig_baseline_vs_rollup.pdf — fee + bytes comparison
#
# Usage:
#     python3 tools/phase5/analyse_bench.py \
#         --csv /tmp/rollup_bench.csv \
#         --out docs/phase5_results/

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

try:
    import pandas as pd
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError as e:
    print(
        f"ERROR: needs pandas + matplotlib ({e}). Install with: "
        "pip install --user --break-system-packages pandas matplotlib tabulate",
        file=sys.stderr,
    )
    sys.exit(1)


SCENARIOS = {
    "prover_createProof": "Prover (createProof)",
    "verifier_verifyProof": "Verifier (verifyProof)",
    "onchain_pipeline_n8": "On-chain pipeline (preflight+preclaim, N=8)",
    "baseline_payment_x8": "Baseline (8x Payment)",
    # Phase 5b additions:
    "l2_pipeline_n8": "L2 pipeline (per-phase, N=8)",
    "merkle_rollup_n8": "Merkle work: rollup batch (N=8)",
    "merkle_baseline_n8": "Merkle work: N independent txs",
    "live_l2_proofgen": "Live L2 proof-gen (gen_batch_blob)",
    "live_l1_submit": "Live L1 submit (preflight+preclaim+doApply)",
    "live_l1_close": "Live L1 ledger close",
    "live_e2e_total": "Live end-to-end L2->L1 total",
}

# The original coarse-grained scenarios that have no per-phase breakdown and
# belong in the flat per-scenario summary table.
FLAT_SCENARIOS = [
    "prover_createProof",
    "verifier_verifyProof",
    "onchain_pipeline_n8",
    "baseline_payment_x8",
]

SUCCESS_OUTCOMES = {
    "OK", "VALID", "tesSUCCESS", "temBAD_PROOF", "tecNO_DST_INSUF_XRP",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Analyse Phase 5 bench CSV")
    p.add_argument("--csv", default="/tmp/rollup_bench.csv")
    p.add_argument("--out", default="docs/phase5_results")
    return p.parse_args()


def load(csv_path: str) -> pd.DataFrame:
    if not os.path.exists(csv_path):
        sys.exit(f"CSV not found: {csv_path}")
    df = pd.read_csv(csv_path)
    expected = {
        "scenario", "run", "elapsed_us", "proof_bytes", "tx_bytes",
        "fee_drops", "outcome",
    }
    missing = expected - set(df.columns)
    if missing:
        sys.exit(f"CSV missing columns: {missing}")

    # Phase 5b columns are optional — backfill defaults so a CSV produced by
    # the pre-5b suite still analyses cleanly.
    defaults = {
        "phase": "", "n_l2_txs": 0, "merkle_updates": 0,
        "poseidon_hashes": 0, "root_writes": 0, "state_writes": 0,
    }
    for col, dflt in defaults.items():
        if col not in df.columns:
            df[col] = dflt
    df["phase"] = df["phase"].fillna("")
    return df


def summarise(df: pd.DataFrame) -> pd.DataFrame:
    """Per-scenario aggregates over the flat (un-phased) scenarios."""
    df = df[df["outcome"].isin(SUCCESS_OUTCOMES)
            & df["scenario"].isin(FLAT_SCENARIOS)].copy()

    g = (
        df.groupby("scenario")
        .agg(
            runs=("run", "count"),
            elapsed_us_mean=("elapsed_us", "mean"),
            elapsed_us_std=("elapsed_us", "std"),
            elapsed_us_min=("elapsed_us", "min"),
            elapsed_us_max=("elapsed_us", "max"),
            proof_bytes_mean=("proof_bytes", "mean"),
            tx_bytes_mean=("tx_bytes", "mean"),
            fee_drops_mean=("fee_drops", "mean"),
        )
    )
    return g


def _mean_us(df: pd.DataFrame, scenario: str, phase: str | None = None) -> float:
    sub = df[df["scenario"] == scenario]
    if phase is not None:
        sub = sub[sub["phase"] == phase]
    return float(sub["elapsed_us"].mean()) if not sub.empty else float("nan")


def phase5b_markdown(df: pd.DataFrame) -> list[str]:
    """Markdown sections for the per-phase, Merkle-work, and live-e2e data."""
    d = df[df["outcome"].isin(SUCCESS_OUTCOMES)].copy()
    out: list[str] = []

    def ms(us: float) -> str:
        return "n/a" if us != us else f"{us/1000:.1f} ms"

    def us(x: float) -> str:
        return "n/a" if x != x else f"{x:.0f} us"

    # --- L2 per-phase breakdown -------------------------------------------
    l2 = d[d["scenario"] == "l2_pipeline_n8"]
    if not l2.empty:
        out.append("\n## L2 pipeline — per-phase breakdown (N=8 batch)\n")
        out.append("Off-chain stages, mean over runs. `createProof` is 8x "
                   "Groth16 proof generation and dominates; everything else "
                   "is sub-millisecond.\n")
        g = (l2.groupby("phase")["elapsed_us"]
             .agg(["mean", "std", "count"]).reindex(
                 ["witness", "createProof", "serialize", "sign", "total_l2"]))
        out.append("| Phase | Mean | Std.dev | Per-L2-tx (mean/8) |")
        out.append("|---|---|---|---|")
        for phase, row in g.iterrows():
            if row["mean"] != row["mean"]:
                continue
            out.append(f"| {phase} | {ms(row['mean'])} | "
                       f"{ms(row['std'])} | {ms(row['mean']/8)} |")

    # --- Merkle-tree work: rollup vs N independent ------------------------
    mr = d[d["scenario"] == "merkle_rollup_n8"]
    mb = d[d["scenario"] == "merkle_baseline_n8"]
    if not mr.empty and not mb.empty:
        out.append("\n## Merkle-tree work: rollup batch vs N independent L1 txs\n")
        out.append("Both commit the same 8 leaf transitions, so the Poseidon "
                   "*compute* is identical. The rollup's saving is the on-chain "
                   "footprint: **one** root/state write and **one** L1 "
                   "transaction instead of eight.\n")
        out.append("| Metric | Rollup (N=8 batch) | N independent txs | Ratio |")
        out.append("|---|---|---|---|")

        def cell(series, col):
            return int(round(series[col].mean())) if not series.empty else 0

        rows = [
            ("Merkle leaf updates", "merkle_updates"),
            ("Poseidon hashes", "poseidon_hashes"),
            ("On-chain root writes", "root_writes"),
            ("On-chain state writes", "state_writes"),
        ]
        for label, col in rows:
            rv, bv = cell(mr, col), cell(mb, col)
            ratio = f"{bv/rv:.0f}x" if rv else "—"
            out.append(f"| {label} | {rv} | {bv} | {ratio} |")
        out.append(f"| Wall-clock (mean) | {us(_mean_us(d,'merkle_rollup_n8'))} "
                   f"| {us(_mean_us(d,'merkle_baseline_n8'))} | ~1x |")
        out.append("\n*Headline:* the rollup reduces on-chain root/state "
                   "writes and L1 transactions by **8x** for an 8-entry batch "
                   "while performing the same Merkle compute.\n")

    # --- Live end-to-end L2->L1 -------------------------------------------
    le = d[d["scenario"] == "live_e2e_total"]
    if not le.empty:
        out.append("\n## Live end-to-end L2->L1 (standalone node, real tesSUCCESS)\n")
        out.append("Measured on a live standalone rippled node where the batch "
                   "genuinely reaches `tesSUCCESS` and `doApply` mutates ledger "
                   "state. Means over runs.\n")
        out.append("| Stage | Mean | Notes |")
        out.append("|---|---|---|")
        out.append(f"| L2 proof generation | {ms(_mean_us(d,'live_l2_proofgen'))} "
                   "| 8x Groth16, off-chain |")
        out.append(f"| L1 submit (preflight+preclaim+doApply) | "
                   f"{ms(_mean_us(d,'live_l1_submit'))} | consensus hot path |")
        out.append(f"| L1 ledger close | {ms(_mean_us(d,'live_l1_close'))} "
                   "| ledger_accept |")
        out.append(f"| **End-to-end total** | "
                   f"**{ms(_mean_us(d,'live_e2e_total'))}** | full L2->L1 |")
        tot = _mean_us(d, "live_e2e_total")
        sub = _mean_us(d, "live_l1_submit")
        if sub == sub:
            out.append(f"\n- **On-chain (L1) cost per batch:** {ms(sub)} "
                       f"= {ms(sub/8)} amortised per L2 transaction.")
        if tot == tot:
            out.append(f"- **End-to-end per L2 tx (incl. proof gen):** "
                       f"{ms(tot/8)}.")
    return out


def write_markdown(summary: pd.DataFrame, df: pd.DataFrame, out_path: Path) -> None:
    lines = ["# Phase 5 — Benchmark Summary\n"]
    lines.append("Elapsed times in microseconds, aggregated over successful "
                 "runs only. `proof_bytes` is the per-proof or per-batch "
                 "Groth16 byte count; `tx_bytes` is the serialised STTx "
                 "size; `fee_drops` is the ledger-recorded fee.\n")
    lines.append("## Per-scenario aggregates\n")
    try:
        lines.append(summary.to_markdown())
    except Exception:
        lines.append(summary.to_string())
    lines.append("\n## Headline numbers\n")

    def safe_get(scenario: str, col: str) -> float:
        try:
            return float(summary.loc[scenario, col])
        except (KeyError, ValueError):
            return float("nan")

    def ms(us: float) -> str:
        if us != us:  # NaN
            return "n/a"
        return f"{us/1000:.1f} ms"

    lines.append(
        f"- **Per-proof generation (mean):** "
        f"{ms(safe_get('prover_createProof', 'elapsed_us_mean'))}"
    )
    lines.append(
        f"- **Per-proof verification (mean):** "
        f"{ms(safe_get('verifier_verifyProof', 'elapsed_us_mean'))}"
    )
    lines.append(
        f"- **On-chain pipeline, N=8 (mean):** "
        f"{ms(safe_get('onchain_pipeline_n8', 'elapsed_us_mean'))}"
    )
    lines.append(
        f"- **Baseline 8x Payment (mean):** "
        f"{ms(safe_get('baseline_payment_x8', 'elapsed_us_mean'))}"
    )

    # Ratios
    rollup_fee = safe_get("onchain_pipeline_n8", "fee_drops_mean")
    base_fee = safe_get("baseline_payment_x8", "fee_drops_mean")
    if rollup_fee == rollup_fee and base_fee == base_fee and rollup_fee > 0:
        lines.append(
            f"\n- **Fee amortisation:** {base_fee/rollup_fee:.2f}x "
            f"(baseline / rollup, mean drops)"
        )

    rollup_bytes = safe_get("onchain_pipeline_n8", "tx_bytes_mean")
    base_bytes = safe_get("baseline_payment_x8", "tx_bytes_mean")
    if (rollup_bytes == rollup_bytes and base_bytes == base_bytes
            and rollup_bytes > 0):
        lines.append(
            f"- **Ledger-byte ratio:** {base_bytes/rollup_bytes:.2f}x "
            f"(baseline / rollup, mean bytes)"
        )

    lines += phase5b_markdown(df)

    out_path.write_text("\n".join(lines))
    print(f"  wrote {out_path}")


def plot_merkle_writes(df: pd.DataFrame, out_path: Path) -> None:
    """Bar chart: on-chain writes, rollup batch vs N independent txs."""
    d = df[df["scenario"].isin(["merkle_rollup_n8", "merkle_baseline_n8"])]
    if d.empty:
        print(f"  skipped {out_path} (no merkle data)")
        return
    g = d.groupby("scenario")[["root_writes", "state_writes"]].mean()
    labels = ["Rollup batch\n(N=8)", "N independent\ntxs"]
    idx = ["merkle_rollup_n8", "merkle_baseline_n8"]
    g = g.reindex(idx)

    fig, ax = plt.subplots(figsize=(6, 4))
    import numpy as np
    x = np.arange(len(idx))
    w = 0.35
    ax.bar(x - w/2, g["root_writes"], w, label="Root writes", color="#4C72B0")
    ax.bar(x + w/2, g["state_writes"], w, label="State writes", color="#C44E52")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("On-chain writes per 8 L2 transitions")
    ax.set_title("L1 write amplification: rollup vs un-batched")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    print(f"  wrote {out_path}")


def plot_l2_phases(df: pd.DataFrame, out_path: Path) -> None:
    """Stacked/bar chart of the L2 per-phase wall-clock (log scale)."""
    d = df[df["scenario"] == "l2_pipeline_n8"]
    if d.empty:
        print(f"  skipped {out_path} (no L2-phase data)")
        return
    phases = ["witness", "createProof", "serialize", "sign"]
    means_ms = [d[d["phase"] == p]["elapsed_us"].mean() / 1000 for p in phases]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(phases, means_ms, color="#55A868")
    ax.set_yscale("log")
    ax.set_ylabel("Wall-clock (ms, log scale)")
    ax.set_title("L2 pipeline phase costs (N=8 batch)")
    for i, m in enumerate(means_ms):
        if m == m:
            ax.annotate(f"{m:.2f}", xy=(i, m), xytext=(0, 3),
                        textcoords="offset points", ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    print(f"  wrote {out_path}")


def write_latex(summary: pd.DataFrame, out_path: Path) -> None:
    def safe_get(scenario: str, col: str) -> float:
        try:
            return float(summary.loc[scenario, col])
        except (KeyError, ValueError):
            return float("nan")

    def fmt_ms(us: float) -> str:
        return f"{us/1000:.1f}" if us == us else "---"

    def fmt_us(us: float) -> str:
        return f"{us:.0f}" if us == us else "---"

    def fmt_int(x: float) -> str:
        return f"{int(round(x))}" if x == x else "---"

    lines = [
        r"\begin{table}[t]",
        r"  \centering",
        r"  \caption{Phase 5 microbenchmarks on \texttt{vma77.scss.tcd.ie} "
        r"(Ubuntu 22.04, GCC-13, single core, Groth16 keys cached). "
        r"Prover and verifier times measured directly via "
        r"\texttt{RollupProver}; on-chain pipeline measured end-to-end via "
        r"\texttt{jtx::Env} along the Phase 4b tampered-rejection path; "
        r"baseline is eight individual \texttt{Payment} transactions through "
        r"the same \texttt{Env}.}",
        r"  \label{tab:phase5-benchmarks}",
        r"  \begin{tabular}{lrrr}",
        r"    \toprule",
        r"    Scenario & Mean & Std.\ dev. & Range \\",
        r"    \midrule",
    ]

    for scenario in [
        "prover_createProof",
        "verifier_verifyProof",
        "onchain_pipeline_n8",
        "baseline_payment_x8",
    ]:
        if scenario not in summary.index:
            continue
        label = SCENARIOS[scenario]
        mean = safe_get(scenario, "elapsed_us_mean")
        std  = safe_get(scenario, "elapsed_us_std")
        lo   = safe_get(scenario, "elapsed_us_min")
        hi   = safe_get(scenario, "elapsed_us_max")
        # Pick units sensibly: verifier in microseconds, others in ms
        if scenario == "verifier_verifyProof":
            lines.append(
                f"    {label} (us) & {fmt_us(mean)} & {fmt_us(std)} & "
                f"{fmt_us(lo)}--{fmt_us(hi)} \\\\"
            )
        else:
            lines.append(
                f"    {label} (ms) & {fmt_ms(mean)} & {fmt_ms(std)} & "
                f"{fmt_ms(lo)}--{fmt_ms(hi)} \\\\"
            )

    lines += [
        r"    \bottomrule",
        r"  \end{tabular}",
        r"\end{table}",
        "",
    ]
    out_path.write_text("\n".join(lines))
    print(f"  wrote {out_path}")


def plot_proof_pipeline(df: pd.DataFrame, out_path: Path) -> None:
    successful = {"OK", "VALID", "tesSUCCESS", "temBAD_PROOF", "tecNO_DST_INSUF_XRP"}
    d = df[df["outcome"].isin(successful)].copy()

    scenarios = ["prover_createProof", "verifier_verifyProof",
                 "onchain_pipeline_n8"]
    means_ms = []
    stds_ms  = []
    labels   = []
    for s in scenarios:
        sub = d[d["scenario"] == s]
        if sub.empty:
            continue
        means_ms.append(sub["elapsed_us"].mean() / 1000)
        stds_ms.append(sub["elapsed_us"].std() / 1000)
        labels.append(SCENARIOS[s])

    if not means_ms:
        print(f"  skipped {out_path} (no data)")
        return

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(labels, means_ms, yerr=stds_ms, capsize=4,
                  color=["#4C72B0", "#55A868", "#C44E52"])
    ax.set_ylabel("Wall-clock time (ms, mean +/- std.dev.)")
    ax.set_title("Phase 5: ZK rollup component latencies")
    plt.setp(ax.get_xticklabels(), rotation=10, ha="right")
    for bar, mean in zip(bars, means_ms):
        ax.annotate(f"{mean:.1f} ms",
                    xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    print(f"  wrote {out_path}")


def plot_baseline_vs_rollup(df: pd.DataFrame, out_path: Path) -> None:
    successful = {"OK", "VALID", "tesSUCCESS", "temBAD_PROOF", "tecNO_DST_INSUF_XRP"}
    d = df[df["outcome"].isin(successful) &
           df["scenario"].isin(["onchain_pipeline_n8",
                                "baseline_payment_x8"])].copy()
    if d.empty:
        print(f"  skipped {out_path} (no comparable data)")
        return

    g = d.groupby("scenario")[["tx_bytes", "fee_drops"]].mean()

    fig, axes = plt.subplots(1, 2, figsize=(8, 4))
    g["tx_bytes"].plot(kind="bar", ax=axes[0], color="#4C72B0")
    axes[0].set_title("Ledger bytes (mean)")
    axes[0].set_ylabel("Bytes")
    axes[0].tick_params(axis="x", rotation=15)

    g["fee_drops"].plot(kind="bar", ax=axes[1], color="#55A868")
    axes[1].set_title("Fee (drops, mean)")
    axes[1].set_ylabel("Drops")
    axes[1].tick_params(axis="x", rotation=15)

    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    print(f"  wrote {out_path}")


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = load(args.csv)
    summary = summarise(df)

    print(f"Analysing {args.csv} -> {out_dir}")
    write_markdown(summary, df, out_dir / "summary.md")
    write_latex(summary, out_dir / "summary.tex")
    plot_proof_pipeline(df, out_dir / "fig_proof_pipeline.pdf")
    plot_baseline_vs_rollup(df, out_dir / "fig_baseline_vs_rollup.pdf")
    plot_merkle_writes(df, out_dir / "fig_merkle_writes.pdf")
    plot_l2_phases(df, out_dir / "fig_l2_phases.pdf")
    print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())