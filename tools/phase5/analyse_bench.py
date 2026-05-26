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
    return df


def summarise(df: pd.DataFrame) -> pd.DataFrame:
    """Per-scenario aggregates over successful runs."""
    successful = {"OK", "VALID", "tesSUCCESS", "temBAD_PROOF", "tecNO_DST_INSUF_XRP"}
    df = df[df["outcome"].isin(successful)].copy()

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


def write_markdown(summary: pd.DataFrame, out_path: Path) -> None:
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

    out_path.write_text("\n".join(lines))
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
    write_markdown(summary, out_dir / "summary.md")
    write_latex(summary, out_dir / "summary.tex")
    plot_proof_pipeline(df, out_dir / "fig_proof_pipeline.pdf")
    plot_baseline_vs_rollup(df, out_dir / "fig_baseline_vs_rollup.pdf")
    print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())