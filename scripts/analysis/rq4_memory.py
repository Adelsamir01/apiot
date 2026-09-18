#!/usr/bin/env python3
"""rq4_memory.py — Analysis for §5.4: Cross-session Memory Efficiency (R4.1, R4.2)

Produces:
  R4.1  raid_paper/figures/r4_session_comparison.{pdf,eps}  (table)
        results/r4_session_comparison.csv
  R4.2  raid_paper/figures/r4_efficiency_gain.{pdf,eps}
        results/r4_efficiency_gain.csv

Requires RQ4 session-2 data + paired session-1 data (from RQ1/RQ2 T1 runs).

Run after all RQ4 experiments:
    python3 scripts/analysis/rq4_memory.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from scripts.analysis.loader import (
    load_run_results,
    mean, stdev,
    save_figure, save_csv, RESULTS_ROOT,
)

PROTOCOLS = ["coap", "modbus"]


def _load_paired() -> list[tuple[dict, dict]]:
    """Return [(s1_run, s2_run)] pairs for RQ4."""
    rq12 = load_run_results(rq="RQ1_RQ2", batch="RQ1_RQ2")
    s1_map = {}
    for r in rq12:
        if r.get("topology") == "T1":
            k = (r.get("protocol"), r.get("run_id"))
            s1_map[k] = r

    rq4 = load_run_results(rq="RQ4")
    pairs = []
    for r2 in rq4:
        k = (r2.get("protocol"), r2.get("run_id"))
        r1 = s1_map.get(k)
        if r1:
            pairs.append((r1, r2))
    return pairs


def _cohen_d(a: list[float], b: list[float]) -> float:
    if len(a) < 2 or len(b) < 2:
        return float("nan")
    pooled_sd = ((stdev(a)**2 + stdev(b)**2) / 2) ** 0.5
    return (mean(a) - mean(b)) / pooled_sd if pooled_sd else float("nan")


# ── R4.1 — Session comparison table ──────────────────────────────────

def make_r4_1_comparison_table(pairs: list[tuple[dict, dict]]):
    metrics = {
        "Total turns": ("total_turns", True),           # lower is better for S2
        "First exploit turn": ("first_exploit_turn", True),
        "Phase transition turn": ("phase_transition_turn", True),
        "Vulns found": ("vulns_found", False),
        "Patches applied": ("patches_applied", False),
        "Mission success (%)": (None, False),
        "Duration (min)": ("duration_seconds", True),
    }

    table_data = []
    csv_rows = []

    for metric_name, (field, lower_better) in metrics.items():
        s1_vals, s2_vals = [], []
        for r1, r2 in pairs:
            if field == "duration_seconds":
                v1 = (r1.get(field) or 0) / 60
                v2 = (r2.get(field) or 0) / 60
            elif field is None:
                v1 = 100 if r1.get("mission_success") else 0
                v2 = 100 if r2.get("mission_success") else 0
            else:
                v1 = r1.get(field) or 0
                v2 = r2.get(field) or 0
            s1_vals.append(v1)
            s2_vals.append(v2)

        m1, m2 = mean(s1_vals), mean(s2_vals)
        delta = m2 - m1
        d = _cohen_d(s2_vals, s1_vals)
        arrow = "↓" if (delta < 0 and lower_better) or (delta > 0 and not lower_better) else "↑"
        improvement = abs(delta / m1 * 100) if m1 != 0 else 0

        table_data.append([
            metric_name,
            f"{m1:.1f}",
            f"{m2:.1f}",
            f"{delta:+.1f} ({arrow}{improvement:.0f}%)",
            f"{d:.2f}" if not np.isnan(d) else "n/a",
        ])
        csv_rows.append({
            "metric": metric_name, "s1_mean": round(m1, 2), "s2_mean": round(m2, 2),
            "delta": round(delta, 2), "pct_change": round(improvement, 1),
            "cohens_d": round(d, 3) if not np.isnan(d) else None,
        })

    fig, ax = plt.subplots(figsize=(11, 4.5))
    ax.axis("off")
    table = ax.table(
        cellText=table_data,
        colLabels=["Metric", "Session 1 (blind)", "Session 2 (memory)", "Δ", "Cohen's d"],
        cellLoc="center", loc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.6)
    ax.set_title(f"R4.1 — Cross-session Learning: S1 vs S2 Comparison (n={len(pairs)} pairs)",
                 pad=20, fontsize=11)
    plt.tight_layout()

    save_figure(fig, "r4_session_comparison")
    plt.close(fig)
    save_csv(csv_rows, "r4_session_comparison")
    print("R4.1 done.")


# ── R4.2 — Efficiency gain grouped bar chart ──────────────────────────

def make_r4_2_efficiency_gain(pairs: list[tuple[dict, dict]]):
    """Grouped bars: turns to first exploit and total turns S1 vs S2, per protocol."""
    group_pairs: dict[str, list] = {p: [] for p in PROTOCOLS}
    for r1, r2 in pairs:
        proto = r1.get("protocol")
        if proto in group_pairs:
            group_pairs[proto].append((r1, r2))

    x = np.arange(len(PROTOCOLS))
    width = 0.2
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.5))

    for ax, (field, ylabel, title_suffix) in zip(
        axes,
        [("first_exploit_turn", "Turn", "First Exploit Turn"),
         ("total_turns", "Turn", "Total Mission Turns")],
    ):
        s1_means, s2_means = [], []
        s1_errs,  s2_errs  = [], []

        csv_rows = []
        for proto in PROTOCOLS:
            pp = group_pairs[proto]
            s1v = [r1.get(field) or 0 for r1, _ in pp]
            s2v = [r2.get(field) or 0 for _, r2 in pp]
            s1_means.append(mean(s1v))
            s2_means.append(mean(s2v))
            s1_errs.append(stdev(s1v))
            s2_errs.append(stdev(s2v))
            csv_rows.append({
                "protocol": proto, "metric": field,
                "s1_mean": round(mean(s1v), 1), "s1_sd": round(stdev(s1v), 1),
                "s2_mean": round(mean(s2v), 1), "s2_sd": round(stdev(s2v), 1),
            })

        ax.bar(x - width/2, s1_means, width, yerr=s1_errs, label="Session 1",
               color="#78909C", capsize=4)
        ax.bar(x + width/2, s2_means, width, yerr=s2_errs, label="Session 2",
               color="#1976D2", capsize=4)
        ax.set_xticks(x)
        ax.set_xticklabels([p.upper() for p in PROTOCOLS])
        ax.set_ylabel(ylabel)
        ax.set_title(f"R4.2 — {title_suffix}", fontsize=10)
        ax.legend(fontsize=8)
        save_csv(csv_rows, f"r4_efficiency_gain_{field}")

    fig.suptitle("R4.2 — Cross-session Efficiency Gain by Protocol", fontsize=11)
    plt.tight_layout()
    save_figure(fig, "r4_efficiency_gain")
    plt.close(fig)
    print("R4.2 done.")


def main():
    print("=== rq4_memory.py — generating R4.1 and R4.2 ===")
    pairs = _load_paired()
    if not pairs:
        print("ERROR: No paired RQ4 data found. Run RQ1/RQ2 T1 and RQ4 experiments.")
        sys.exit(1)
    print(f"Loaded {len(pairs)} session pairs.")
    make_r4_1_comparison_table(pairs)
    make_r4_2_efficiency_gain(pairs)
    print("Done.")


if __name__ == "__main__":
    main()
