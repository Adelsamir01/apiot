#!/usr/bin/env python3
"""rq1_capability.py — Analysis for §5.1: Capability Baseline (R1.1, R1.2)

Produces:
  R1.1  raid_paper/figures/r1_success_heatmap.{pdf,eps}
        results/r1_success_heatmap.csv
  R1.2  raid_paper/figures/r1_mission_timeline.{pdf,eps}
        results/r1_mission_timeline.csv

Run after all RQ1/RQ2 experiments are complete:
    python3 scripts/analysis/rq1_capability.py
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
    load_run_results, load_all_tool_histories,
    success_rate, mean, stdev, group_by,
    save_figure, save_csv, ensure_figures_dir,
)

PROTOCOLS  = ["coap", "modbus"]
TOPOLOGIES = ["T1", "T2", "T3"]
TOPO_LABELS = {"T1": "T1 (Flat)", "T2": "T2 (Purdue)", "T3": "T3 (EFC)"}


# ── R1.1 — Success heatmap ────────────────────────────────────────────

def make_r1_1_heatmap(runs: list[dict]):
    """4-value cell heatmap: success rate | median turns | median duration | N."""
    groups = group_by(runs, "protocol", "topology")

    # Build data matrices
    nrows, ncols = len(PROTOCOLS), len(TOPOLOGIES)
    success_mat  = np.zeros((nrows, ncols))
    turns_mat    = np.zeros((nrows, ncols))
    dur_mat      = np.zeros((nrows, ncols))
    n_mat        = np.zeros((nrows, ncols), dtype=int)

    csv_rows = []
    for i, proto in enumerate(PROTOCOLS):
        for j, topo in enumerate(TOPOLOGIES):
            cell_runs = groups.get((proto, topo), [])
            n = len(cell_runs)
            n_mat[i, j] = n
            if n == 0:
                continue
            sr = success_rate(cell_runs)
            # Median turns and duration computed over SUCCESSFUL runs only
            # (to match table caption; failed runs terminated early)
            success_runs = [r for r in cell_runs if r.get("mission_success")]
            turns = [r.get("total_turns", 0) or 0 for r in success_runs]
            durs  = [r.get("duration_seconds", 0) or 0 for r in success_runs]
            success_mat[i, j] = sr
            turns_mat[i, j]   = np.median(turns) if turns else 0
            dur_mat[i, j]      = np.median(durs) / 60 if durs else 0
            csv_rows.append({
                "protocol": proto, "topology": topo,
                "success_rate": round(sr, 3),
                "n": n,
                "median_turns": round(float(np.median(turns)), 1) if turns else 0,
                "stdev_turns": round(stdev(turns), 1),
                "median_duration_min": round(float(np.median(durs)) / 60, 1) if durs else 0,
            })

    fig, ax = plt.subplots(figsize=(8, 3.5))
    # Use "magma" colormap: HCI-compliant, perceptually uniform, and colorblind-friendly.
    im = ax.imshow(success_mat, cmap="magma", vmin=0, vmax=1, aspect="auto")

    ax.set_xticks(range(ncols))
    ax.set_xticklabels([TOPO_LABELS[t] for t in TOPOLOGIES])
    ax.set_yticks(range(nrows))
    ax.set_yticklabels([p.upper() for p in PROTOCOLS])
    ax.set_xlabel("Topology")
    ax.set_ylabel("Protocol")
    ax.set_title("R1.1 — Mission Success Rate (HCI-Compliant Heatmap)", fontsize=11)

    for i in range(nrows):
        for j in range(ncols):
            n = n_mat[i, j]
            if n == 0:
                ax.text(j, i, "n/a", ha="center", va="center", fontsize=9, color="gray")
                continue
            sr_pct = int(success_mat[i, j] * 100)
            
            # Simplified text: Bold percentage + small n count
            # "magma" is dark at low values, light at high values.
            # Color threshold at 0.5 ensures readability.
            text_color = "white" if success_mat[i, j] < 0.5 else "black"
            
            ax.text(j, i, f"{sr_pct}%", ha="center", va="center",
                    fontsize=12, fontweight="bold", color=text_color)
            ax.text(j, i+0.25, f"(n={n})", ha="center", va="center",
                    fontsize=8, color=text_color)

    cbar = plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("Success Rate", size=9)
    plt.tight_layout()

    save_figure(fig, "r1_success_heatmap")
    save_csv(csv_rows, "r1_success_heatmap")
    plt.close(fig)
    print("R1.1 done.")


# ── R1.2 — Mission timeline bar chart ─────────────────────────────────

def make_r1_2_timeline(runs: list[dict]):
    """Grouped bar chart: median turns to first exploit / phase transition / complete."""
    groups = group_by(runs, "protocol", "topology")

    csv_rows = []
    conditions = []
    first_exploit_vals = []
    phase_trans_vals   = []
    complete_vals      = []

    for proto in PROTOCOLS:
        for topo in TOPOLOGIES:
            cell_runs = groups.get((proto, topo), [])
            if not cell_runs:
                continue
            label = f"{proto.upper()}\n{TOPO_LABELS[topo]}"
            conditions.append(label)

            fe = [r.get("first_exploit_turn") or 0 for r in cell_runs]
            pt = [r.get("phase_transition_turn") or 0 for r in cell_runs]
            mc = [r.get("total_turns") or 0 for r in cell_runs]

            first_exploit_vals.append(mean(fe))
            phase_trans_vals.append(mean(pt))
            complete_vals.append(mean(mc))

            csv_rows.append({
                "protocol": proto, "topology": topo,
                "mean_first_exploit_turn": round(mean(fe), 1),
                "mean_phase_transition_turn": round(mean(pt), 1),
                "mean_complete_turn": round(mean(mc), 1),
            })

    if not conditions:
        print("R1.2: No data — skipping.")
        return

    x = np.arange(len(conditions))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(x - width, first_exploit_vals, width, label="First exploit", color="#2196F3")
    ax.bar(x,          phase_trans_vals,  width, label="Phase transition", color="#FF9800")
    ax.bar(x + width,  complete_vals,     width, label="Mission complete", color="#4CAF50")

    ax.set_xticks(x)
    ax.set_xticklabels(conditions, fontsize=8)
    ax.set_ylabel("Turn number (mean across replicates)")
    ax.set_title("R1.2 — Mission Timeline: Key Milestones per Condition", fontsize=11)
    ax.legend()
    plt.tight_layout()

    save_figure(fig, "r1_mission_timeline")
    save_csv(csv_rows, "r1_mission_timeline")
    plt.close(fig)
    print("R1.2 done.")


def main():
    print("=== rq1_capability.py — generating R1.1 and R1.2 ===")
    runs = load_run_results(rq="RQ1_RQ2", batch="RQ1_RQ2")
    if not runs:
        print("ERROR: No RQ1_RQ2 run results found. Run experiments first.")
        sys.exit(1)
    print(f"Loaded {len(runs)} RQ1/RQ2 runs.")
    make_r1_1_heatmap(runs)
    make_r1_2_timeline(runs)
    print("Done.")


if __name__ == "__main__":
    main()
