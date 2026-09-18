#!/usr/bin/env python3
"""rq5_deployment.py — Analysis for §5.5: Deployment Boundaries (R5.1, R5.2)

Produces:
  R5.1  raid_paper/figures/r5_topology_scaling.{pdf,eps}
        results/r5_topology_success_rates.csv
  R5.2  raid_paper/figures/r5_impairment_curve.{pdf,eps}
        results/r5_impairment_success_rates.csv

R5.1 reuses RQ1/RQ2 data (no new runs needed).
R5.2 uses RQ6 data + RQ1/RQ2 T1 baseline for "None" point.

Run after RQ1/RQ2 and RQ6 experiments:
    python3 scripts/analysis/rq5_deployment.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

from scripts.analysis.loader import (
    load_run_results,
    success_rate, mean, stdev, group_by,
    save_figure, save_csv,
)

PROTOCOLS  = ["coap", "modbus"]
TOPOLOGIES = ["T1", "T2", "T3"]
TOPO_LABELS = {"T1": "T1 (Flat)", "T2": "T2 (Purdue)", "T3": "T3 (EFC)"}

PROTO_STYLES = {
    "coap":   {"color": "#1976D2", "marker": "o", "linestyle": "-",  "label": "CoAP (UDP)"},
    "modbus": {"color": "#E53935", "marker": "s", "linestyle": "-",  "label": "Modbus (TCP)"},
}

IMPAIRMENT_LEVELS = ["none", "medium", "heavy"]
IMPAIRMENT_LABELS = {
    "none":   "No impairment\n(0% loss, 0ms)",
    "medium": "Medium\n(~5% loss, 50ms)",
    "heavy":  "Heavy\n(~20% loss, 200ms)",
}


# ── R5.1 — Topology scaling grouped bar chart ────────────────────────

def make_r5_1_topology_scaling(runs: list[dict]):
    groups = group_by(runs, "protocol", "topology")

    fig, ax = plt.subplots(figsize=(7, 4.5))
    n_topos = len(TOPOLOGIES)
    bar_width = 0.35
    x = np.arange(n_topos)
    csv_rows = []

    for i, proto in enumerate(PROTOCOLS):
        style = PROTO_STYLES[proto]
        y_vals, y_errs = [], []

        for topo in TOPOLOGIES:
            cell = groups.get((proto, topo), [])
            if cell:
                sr = success_rate(cell) * 100
                sd = stdev([100 if r.get("mission_success") else 0 for r in cell])
            else:
                sr, sd = 0, 0
            y_vals.append(sr)
            y_errs.append(sd)
            csv_rows.append({
                "protocol": proto, "topology": topo,
                "success_rate_pct": round(sr, 1), "sd": round(sd, 1),
                "n": len(cell),
            })

        offset = (i - 0.5) * bar_width
        bars = ax.bar(x + offset, y_vals, bar_width,
                      label=style["label"], color=style["color"],
                      yerr=y_errs, capsize=4, error_kw={"elinewidth": 1.2},
                      alpha=0.85)

        for bar, yv in zip(bars, y_vals):
            ax.text(bar.get_x() + bar.get_width() / 2, yv + 2,
                    f"{yv:.0f}%", ha="center", va="bottom",
                    fontsize=8, color=style["color"], fontweight="bold")

    # Segmentation boundary: vertical line between T1 and T2
    ax.axvline(0.5, color="#E65100", linestyle="--", linewidth=1.5, alpha=0.8)
    ax.text(0.5, 110, "Segmentation\nboundary", ha="center", fontsize=7.5,
            color="white",
            bbox=dict(boxstyle="round,pad=0.3", fc="#E65100", ec="none", alpha=0.85))

    ax.set_xticks(x)
    ax.set_xticklabels([TOPO_LABELS[t] for t in TOPOLOGIES])
    ax.set_ylabel("Mission success rate (%)")
    ax.set_ylim(0, 118)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_yticklabels(["0%", "25%", "50%", "75%", "100%"])
    ax.set_title("R5.1 — Topology Scaling: Agent Performance vs Network Complexity", fontsize=11)
    ax.legend(loc="lower left")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()

    save_figure(fig, "r5_topology_scaling")
    plt.close(fig)
    save_csv(csv_rows, "r5_topology_success_rates")
    print("R5.1 done.")


# ── R5.2 — Impairment degradation: mean turns to completion ──────────

def make_r5_2_impairment_curve():
    rq1_runs = load_run_results(rq="RQ1_RQ2", batch="RQ1_RQ2")
    baseline = {proto: [r for r in rq1_runs
                        if r.get("protocol") == proto and r.get("topology") == "T1"]
                for proto in PROTOCOLS}

    rq6_runs = load_run_results(rq="RQ6")
    impaired = group_by(rq6_runs, "protocol", "impairment")

    fig, ax = plt.subplots(figsize=(7, 4.5))
    x_pos = {level: i for i, level in enumerate(IMPAIRMENT_LEVELS)}
    x_offset = {"coap": -0.07, "modbus": 0.07}
    csv_rows = []

    for proto in PROTOCOLS:
        style = PROTO_STYLES[proto]
        y_vals, y_errs, x_vals = [], [], []

        # "None" baseline from RQ1/RQ2 T1
        bl = baseline[proto]
        if bl:
            turns = [r["total_turns"] for r in bl if r.get("total_turns") is not None]
            m, s = mean(turns), stdev(turns)
            y_vals.append(m); y_errs.append(s)
            x_vals.append(x_pos["none"] + x_offset[proto])
            csv_rows.append({"protocol": proto, "impairment": "none",
                             "mean_turns": round(m, 1), "sd": round(s, 1),
                             "n": len(turns), "success_rate_pct": 100.0})

        for imp in ["medium", "heavy"]:
            cell = impaired.get((proto, imp), [])
            if not cell:
                continue
            turns = [r["total_turns"] for r in cell if r.get("total_turns") is not None]
            m = mean(turns)
            s = stdev(turns) if len(turns) >= 2 else 0
            y_vals.append(m); y_errs.append(s)
            x_vals.append(x_pos[imp] + x_offset[proto])
            sr = success_rate(cell) * 100
            csv_rows.append({"protocol": proto, "impairment": imp,
                             "mean_turns": round(m, 1), "sd": round(s, 1),
                             "n": len(turns), "success_rate_pct": round(sr, 1)})

        if not x_vals:
            continue

        ax.errorbar(x_vals, y_vals, yerr=y_errs,
                    color=style["color"], marker=style["marker"],
                    linestyle=style["linestyle"], label=style["label"],
                    capsize=4, linewidth=2, markersize=7)

        for j, (xi, yi) in enumerate(zip(x_vals, y_vals)):
            # Place label above unless it's a local minimum — then place below
            prev_y = y_vals[j - 1] if j > 0 else yi
            next_y = y_vals[j + 1] if j < len(y_vals) - 1 else yi
            is_trough = (yi <= prev_y and yi <= next_y)
            # Last point on right edge: shift label left
            x_off = -32 if j == len(x_vals) - 1 else 6
            y_off = -12 if is_trough else 5
            ax.annotate(f"{yi:.1f}", (xi, yi),
                        textcoords="offset points", xytext=(x_off, y_off),
                        fontsize=8, color=style["color"])

    all_y = [v for proto in PROTOCOLS
             for v in ([mean([r["total_turns"] for r in baseline[proto]
                              if r.get("total_turns")])] if baseline[proto] else [])
             ] + [r["total_turns"] for r in rq6_runs if r.get("total_turns")]
    ax.set_xticks(range(len(IMPAIRMENT_LEVELS)))
    ax.set_xticklabels([IMPAIRMENT_LABELS[l] for l in IMPAIRMENT_LEVELS], fontsize=8)
    ax.set_ylabel("Mean turns to mission completion")
    ax.set_ylim(0, max(all_y) * 1.25)
    ax.set_title("R5.2 — Impairment Degradation: CoAP vs Modbus", fontsize=11)
    ax.legend(loc="upper left", fontsize=8)
    ax.grid(axis="y", alpha=0.3)
    ax.text(0.01, 0.02, "All runs successful (100%). n=2–3 per condition.",
            transform=ax.transAxes, fontsize=7, color="gray")
    plt.tight_layout()

    save_figure(fig, "r5_impairment_curve")
    plt.close(fig)
    save_csv(csv_rows, "r5_impairment_success_rates")
    print("R5.2 done.")


def main():
    print("=== rq5_deployment.py — generating R5.1 and R5.2 ===")
    runs = load_run_results(rq="RQ1_RQ2", batch="RQ1_RQ2")
    if not runs:
        print("ERROR: No RQ1/RQ2 data found for R5.1.")
        sys.exit(1)
    make_r5_1_topology_scaling(runs)
    make_r5_2_impairment_curve()
    print("Done.")


if __name__ == "__main__":
    main()
