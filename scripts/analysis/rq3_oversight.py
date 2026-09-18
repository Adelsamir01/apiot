#!/usr/bin/env python3
"""rq3_oversight.py — Analysis for §5.2: Oversight Ablation (R2.1–R2.4)

Produces:
  R2.1  raid_paper/figures/r2_oversight_grouped_bars.{pdf,eps}
        results/r2_oversight_metrics.csv
  R2.2  raid_paper/figures/r2_degenerate_behaviour.{pdf,eps}  (table as figure)
        results/r2_degenerate_patterns.csv
  R2.3  raid_paper/figures/r2_overseer_interventions.{pdf,eps}
        results/r2_intervention_breakdown.csv
  R2.4  raid_paper/figures/r2_productive_calls_timeline.{pdf,eps}
        results/r2_productive_calls_timeline.csv

Requires RQ1_RQ2 T1 data (ON condition) + RQ3 data (OFF condition).

Run after all RQ1/RQ2 and RQ3 experiments:
    python3 scripts/analysis/rq3_oversight.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from scripts.analysis.loader import (
    load_run_results, load_all_tool_histories,
    success_rate, mean, stdev, group_by,
    save_figure, save_csv,
)

PROTOCOLS = ["coap", "modbus", "mqtt"]

# Tool categories for productive-call analysis (EXT7 names + legacy pre-EXT7)
EXPLOIT_TOOLS = {
    # EXT7 protocol primitives
    "coap_send", "modbus_request", "tcp_send", "udp_send",
    "mqtt_publish", "mqtt_subscribe",
    "verify_crash", "verify_shell",
    # pre-EXT7 legacy
    "execute_exploit", "modbus_write_coil", "modbus_mbap_overflow",
    "coap_option_overflow", "brute_force_ssh", "brute_force_telnet",
    "http_cmd_injection",
}
BLUE_TOOLS = {
    "iptables_rule", "protocol_block", "modbus_fc_filter",
    "coap_rate_limit", "verify_patch", "list_patches",
    # legacy
    "analyze_attacks", "apply_patch",
}
RECON_TOOLS = {"get_network_state", "get_actionable_targets", "inspect_lab",
               "run_command", "stealth_check"}


def _load_on_off() -> tuple[list[dict], list[dict]]:
    """Return (ON-condition runs, OFF-condition runs) for T1 only."""
    rq12 = load_run_results(rq="RQ1_RQ2", batch="RQ1_RQ2")
    on_runs  = [r for r in rq12 if r.get("topology") == "T1"]
    rq3_runs = load_run_results(rq="RQ3")
    off_runs = [r for r in rq3_runs
                if r.get("overseer_mode", "full" if r.get("overseer") else "off") == "off"]
    return on_runs, off_runs


def _load_guards_only() -> list[dict]:
    """Return the new deterministic-guards-only arm, if it has been run."""
    return [r for r in load_run_results(rq="RQ3")
            if r.get("overseer_mode") == "guards-only"]


def make_three_arm_summary(on_runs, guards_runs, off_runs):
    """Write the compact three-arm metrics used for manuscript insertion."""
    rows = []
    for label, runs in [
        ("full", on_runs),
        ("guards-only", guards_runs),
        ("off", off_runs),
    ]:
        successful = [r for r in runs if r.get("mission_success")]
        turns = [r.get("total_turns") for r in successful if r.get("total_turns") is not None]
        redundant = [r.get("redundant_call_rate") for r in runs
                     if r.get("redundant_call_rate") is not None]
        rows.append({
            "overseer_mode": label,
            "n": len(runs),
            "mission_success": sum(1 for r in runs if r.get("mission_success")),
            "success_pct": round(success_rate(runs) * 100, 1),
            "mean_turns_successful": round(mean(turns), 2) if turns else "",
            "mean_redundant_call_rate": round(mean(redundant), 3) if redundant else "",
        })
    save_csv(rows, "r2_three_arm_oversight_metrics")
    print("Three-arm oversight summary done.")


# ── R2.1 — Grouped bar chart: 5 metrics ON vs OFF ────────────────────

def make_r2_1_grouped_bars(on_runs, off_runs):
    # R2.1 focuses on efficiency (both conditions achieve ~100% success on T1).
    # Key story: overseer ON reduces redundant recon calls and total turns.
    metrics = {
        "Mission success (%)":       (success_rate(on_runs) * 100, success_rate(off_runs) * 100),
        "Mean turns":                 (mean([r.get("total_turns", 0) or 0 for r in on_runs]),
                                       mean([r.get("total_turns", 0) or 0 for r in off_runs])),
        "Redundant call rate (%)":   (mean([r.get("redundant_call_rate", 0) or 0 for r in on_runs]) * 100,
                                       mean([r.get("redundant_call_rate", 0) or 0 for r in off_runs]) * 100),
        "Vulns found (mean)":         (mean([r.get("vulns_found", 0) or 0 for r in on_runs]),
                                       mean([r.get("vulns_found", 0) or 0 for r in off_runs])),
        "Patches applied (mean)":     (mean([r.get("patches_applied", 0) or 0 for r in on_runs]),
                                       mean([r.get("patches_applied", 0) or 0 for r in off_runs])),
    }

    labels = list(metrics.keys())
    on_vals  = [metrics[k][0] for k in labels]
    off_vals = [metrics[k][1] for k in labels]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 4.5))
    bars_on  = ax.bar(x - width/2, on_vals,  width, label="Overseer ON",  color="#1976D2")
    bars_off = ax.bar(x + width/2, off_vals, width, label="Overseer OFF", color="#E53935", alpha=0.8)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylabel("Value")
    ax.set_title("R2.1 — Oversight Ablation: 5 Key Metrics (T1, all protocols)", fontsize=11)
    ax.legend()

    for bar in bars_on:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.5,
                f"{h:.1f}", ha="center", va="bottom", fontsize=8)
    for bar in bars_off:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.5,
                f"{h:.1f}", ha="center", va="bottom", fontsize=8, color="#E53935")

    plt.tight_layout()
    save_figure(fig, "r2_oversight_grouped_bars")
    plt.close(fig)

    csv_rows = [
        {"metric": k, "overseer_on": round(v[0], 2), "overseer_off": round(v[1], 2),
         "delta": round(v[0] - v[1], 2)}
        for k, v in metrics.items()
    ]
    save_csv(csv_rows, "r2_oversight_metrics")
    print("R2.1 done.")


# ── R2.2 — Degenerate behaviour catalogue (table figure) ──────────────

def make_r2_2_degenerate_table(off_rows: list[dict]):
    """Detect and count degenerate patterns in OFF-condition tool history."""
    from collections import Counter

    # Pattern detection
    patterns = {
        "Repetitive same-tool loop": 0,
        "Infinite recon loop (no exploit)": 0,
        "Premature phase transition": 0,
        "Exploit without verification": 0,
        "No blue-team transition": 0,
    }

    # Group by run
    runs_rows: dict = {}
    for row in off_rows:
        key = (row.get("_protocol"), row.get("_run_id"))
        runs_rows.setdefault(key, []).append(row)

    for (proto, run_id), rows in runs_rows.items():
        tool_seq = [r["tool_name"] for r in rows]

        # Repetitive same-tool: 4+ identical consecutive calls
        consec = 1
        for i in range(1, len(tool_seq)):
            if tool_seq[i] == tool_seq[i-1]:
                consec += 1
                if consec >= 4:
                    patterns["Repetitive same-tool loop"] += 1
                    break
            else:
                consec = 1

        # Infinite recon: >5 recon tools with 0 exploit tools in first 15 calls
        first15 = tool_seq[:15]
        if (sum(1 for t in first15 if t in RECON_TOOLS) > 8
                and sum(1 for t in first15 if t in EXPLOIT_TOOLS) == 0):
            patterns["Infinite recon loop (no exploit)"] += 1

        # Premature phase transition: blue tool before turn 5
        for row in rows:
            if row["tool_name"] in BLUE_TOOLS and (row.get("turn_number") or 0) < 5:
                patterns["Premature phase transition"] += 1
                break

        # Exploit without verification: attack tool not followed by verify_*
        _attack_tools = {"coap_send", "modbus_request", "tcp_send", "udp_send",
                         "mqtt_publish", "execute_exploit"}
        for i, t in enumerate(tool_seq[:-1]):
            if t in _attack_tools:
                next_t = tool_seq[i+1]
                if next_t not in {"verify_crash", "verify_shell"}:
                    patterns["Exploit without verification"] += 1
                    break

        # No blue-team transition: no blue tool in entire run
        if not any(t in BLUE_TOOLS for t in tool_seq):
            patterns["No blue-team transition"] += 1

    # Plot as table
    fig, ax = plt.subplots(figsize=(8, 3))
    ax.axis("off")

    total_runs = len(runs_rows)
    table_data = [
        [name, str(count), f"{count/max(total_runs,1)*100:.0f}%"]
        for name, count in patterns.items()
    ]
    table = ax.table(
        cellText=table_data,
        colLabels=["Degenerate Pattern", "Runs Affected", "% of OFF Runs"],
        cellLoc="center", loc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.6)
    ax.set_title("R2.2 — Degenerate Behaviour Catalogue (Overseer OFF)", fontsize=11, pad=15)
    plt.tight_layout()

    save_figure(fig, "r2_degenerate_behaviour")
    plt.close(fig)

    csv_rows = [{"pattern": k, "runs_affected": v,
                 "pct_of_off_runs": round(v/max(total_runs,1)*100, 1)}
                for k, v in patterns.items()]
    save_csv(csv_rows, "r2_degenerate_patterns")
    print("R2.2 done.")


# ── R2.3 — Overseer intervention breakdown (pie/stacked bar) ──────────

def make_r2_3_interventions(on_rows: list[dict]):
    """Breakdown of overseer_flag values across ON-condition runs."""
    from collections import Counter
    flags = [r.get("overseer_flag", "none") for r in on_rows]
    counts = Counter(flags)

    # Exclude 'none' and 'disabled' from breakdown (they're not interventions)
    intervention_counts = {k: v for k, v in counts.items()
                           if k not in ("none", "disabled")}
    total_interventions = sum(intervention_counts.values())
    total_calls = len(on_rows)

    if not intervention_counts:
        print("R2.3: No interventions found — skipping figure.")
        return

    labels = list(intervention_counts.keys())
    sizes  = list(intervention_counts.values())
    colors = ["#FF9800", "#9C27B0", "#2196F3", "#4CAF50", "#F44336"][:len(labels)]

    fig, axes = plt.subplots(1, 2, figsize=(10, 4))

    # Pie chart
    axes[0].pie(sizes, labels=labels, autopct="%1.0f%%", colors=colors, startangle=90)
    axes[0].set_title(f"R2.3a — Intervention Type Breakdown\n"
                      f"(n={total_interventions} interventions / {total_calls} tool calls)")

    # Bar: intervention rate over turns (rolling 10-turn window)
    on_rows_sorted = sorted(on_rows, key=lambda r: r.get("turn_number") or 0)
    turn_nums = [r.get("turn_number") or 0 for r in on_rows_sorted]
    is_intervention = [1 if r.get("overseer_flag", "none") not in ("none", "disabled") else 0
                       for r in on_rows_sorted]
    window = 10
    if len(turn_nums) >= window:
        rolling = [mean(is_intervention[max(0, i-window):i+1])
                   for i in range(len(is_intervention))]
        axes[1].plot(turn_nums, rolling, color="#1976D2")
        axes[1].set_xlabel("Turn number")
        axes[1].set_ylabel("Intervention rate (rolling 10-turn)")
        axes[1].set_title("R2.3b — Intervention Rate Over Mission Progress")
        axes[1].axhline(y=mean(is_intervention), color="gray", linestyle="--",
                        label=f"Overall mean = {mean(is_intervention):.2f}")
        axes[1].legend(fontsize=8)
    else:
        axes[1].text(0.5, 0.5, "Insufficient data", ha="center", va="center",
                     transform=axes[1].transAxes)

    plt.tight_layout()
    save_figure(fig, "r2_overseer_interventions")
    plt.close(fig)

    csv_rows = [{"flag": k, "count": v,
                 "pct_of_interventions": round(v/max(total_interventions,1)*100, 1)}
                for k, v in intervention_counts.items()]
    save_csv(csv_rows, "r2_intervention_breakdown")
    print("R2.3 done.")


# ── R2.4 — Per-turn productive call timeline ──────────────────────────

def make_r2_4_productive_timeline(on_rows, off_rows):
    """Line plot: fraction of calls that are productive (not recon) per turn bucket."""
    def productive_fraction_by_turn(rows):
        from collections import defaultdict
        bucket_size = 5
        buckets: dict[int, list[float]] = defaultdict(list)
        for row in rows:
            t = row.get("turn_number") or 0
            bucket = (t // bucket_size) * bucket_size
            is_prod = 1 if row["tool_name"] in (EXPLOIT_TOOLS | BLUE_TOOLS) else 0
            buckets[bucket].append(is_prod)
        return sorted(buckets.items()), {b: mean(v) for b, v in buckets.items()}

    on_sorted,  on_frac  = productive_fraction_by_turn(on_rows)
    off_sorted, off_frac = productive_fraction_by_turn(off_rows)

    all_buckets = sorted(set(list(on_frac.keys()) + list(off_frac.keys())))

    fig, ax = plt.subplots(figsize=(9, 4))
    on_vals  = [on_frac.get(b, np.nan) for b in all_buckets]
    off_vals = [off_frac.get(b, np.nan) for b in all_buckets]

    ax.plot(all_buckets, on_vals,  marker="o", label="Overseer ON",  color="#1976D2")
    ax.plot(all_buckets, off_vals, marker="s", label="Overseer OFF", color="#E53935", linestyle="--")
    ax.set_xlabel("Turn number (bucket size=5)")
    ax.set_ylabel("Productive call fraction")
    ax.set_ylim(0, 1.05)
    ax.set_title("R2.4 — Productive Call Rate Over Mission: Overseer ON vs OFF", fontsize=11)
    ax.legend()
    ax.axhline(0.5, color="gray", linestyle=":", linewidth=0.8)
    plt.tight_layout()

    save_figure(fig, "r2_productive_calls_timeline")
    plt.close(fig)

    csv_rows = [{"turn_bucket": b,
                 "productive_frac_on": round(on_frac.get(b, 0), 3),
                 "productive_frac_off": round(off_frac.get(b, 0), 3)}
                for b in all_buckets]
    save_csv(csv_rows, "r2_productive_calls_timeline")
    print("R2.4 done.")


def main():
    print("=== rq3_oversight.py — generating R2.1–R2.4 ===")
    on_runs, off_runs = _load_on_off()
    guards_runs = _load_guards_only()
    if not on_runs and not off_runs:
        print("ERROR: No RQ1_RQ2 or RQ3 data found.")
        sys.exit(1)
    print(f"FULL runs (T1): {len(on_runs)}  |  GUARDS-ONLY runs: {len(guards_runs)}  |  OFF runs: {len(off_runs)}")

    on_rows  = load_all_tool_histories(rq="RQ1_RQ2", batch="RQ1_RQ2")
    on_rows  = [r for r in on_rows if r.get("_topology") == "T1"]
    rq3_rows = load_all_tool_histories(rq="RQ3")
    off_rows = [r for r in rq3_rows if r.get("_overseer_mode") == "off"]

    make_r2_1_grouped_bars(on_runs, off_runs)
    make_r2_2_degenerate_table(off_rows)
    make_r2_3_interventions(on_rows)
    make_r2_4_productive_timeline(on_rows, off_rows)
    if guards_runs:
        make_three_arm_summary(on_runs, guards_runs, off_runs)
    print("Done.")


if __name__ == "__main__":
    main()
