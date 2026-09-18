#!/usr/bin/env python3
"""rq2_behaviour.py — Analysis for §5.3: Behavioural Profile (R3.1–R3.4)

Produces:
  R3.1  raid_paper/figures/r3_tool_distribution.{pdf,eps}
        results/r3_tool_distribution.csv
  R3.2  raid_paper/figures/r3_exploit_timing.{pdf,eps}
        results/r3_exploit_timing.csv
  R3.3  raid_paper/figures/r3_failure_taxonomy.{pdf,eps}  (table)
        results/r3_failure_modes.csv
  R3.4  raid_paper/figures/r3_stall_histogram.{pdf,eps}
        results/r3_stall_durations.csv

Run after all RQ1/RQ2 experiments:
    python3 scripts/analysis/rq2_behaviour.py
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
    mean, stdev, group_by,
    save_figure, save_csv,
)

PROTOCOLS  = ["coap", "modbus"]
TOPOLOGIES = ["T1", "T2", "T3"]

PHASE_COLORS = {"red": "#E53935", "blue": "#1976D2"}

# Tool groupings for stacked bar (EXT7: protocol primitives)
TOOL_GROUPS = {
    "Exploit":  {"coap_send", "modbus_request", "tcp_send", "udp_send", "create_tool",
                 # legacy names retained for backwards-compat with pre-EXT7 runs
                 "execute_exploit", "modbus_write_coil", "modbus_mbap_overflow",
                 "coap_option_overflow", "brute_force_ssh", "brute_force_telnet",
                 "http_cmd_injection"},
    "Verify":   {"verify_crash", "verify_shell", "verify_patch"},
    "Recon":    {"get_network_state", "get_actionable_targets", "inspect_lab",
                 "stealth_check", "run_command"},
    "Blue":     {"iptables_rule", "protocol_block", "modbus_fc_filter", "coap_rate_limit",
                 "list_patches",
                 # legacy names retained for backwards-compat
                 "analyze_attacks", "apply_patch"},
}
GROUP_COLORS = {"Exploit": "#E53935", "Verify": "#FF9800",
                "Recon": "#78909C", "Blue": "#1976D2"}


def _classify_tool(tool_name: str) -> str:
    for group, tools in TOOL_GROUPS.items():
        if tool_name in tools:
            return group
    return "Other"


# ── R3.1 — 100% stacked tool-call bars ────────────────────────────────

def make_r3_1_tool_distribution(all_rows: list[dict]):
    groups = {}
    for row in all_rows:
        key = (row.get("_protocol"), row.get("_topology"))
        groups.setdefault(key, []).append(row)

    conditions = []
    fractions: dict[str, list[float]] = {g: [] for g in TOOL_GROUPS}

    for proto in PROTOCOLS:
        for topo in TOPOLOGIES:
            rows = groups.get((proto, topo), [])
            if not rows:
                continue
            conditions.append(f"{proto.upper()}\n{topo}")
            total = max(len(rows), 1)
            for group in TOOL_GROUPS:
                count = sum(1 for r in rows if _classify_tool(r["tool_name"]) == group)
                fractions[group].append(count / total)

    if not conditions:
        print("R3.1: No data.")
        return

    x = np.arange(len(conditions))
    fig, ax = plt.subplots(figsize=(10, 4))

    bottoms = np.zeros(len(conditions))
    for group, vals in fractions.items():
        ax.bar(x, vals, bottom=bottoms, label=group,
               color=GROUP_COLORS[group], width=0.6)
        bottoms += np.array(vals)

    ax.set_xticks(x)
    ax.set_xticklabels(conditions, fontsize=8)
    ax.set_ylabel("Fraction of tool calls")
    ax.set_ylim(0, 1.05)
    ax.set_title("R3.1 — Tool Call Distribution by Protocol × Topology", fontsize=11)
    ax.legend(loc="upper right", fontsize=8)
    ax.axhline(1.0, color="gray", linewidth=0.5)
    plt.tight_layout()

    save_figure(fig, "r3_tool_distribution")
    plt.close(fig)

    csv_rows = []
    for i, (proto, topo) in enumerate(
            [(p, t) for p in PROTOCOLS for t in TOPOLOGIES
             if groups.get((p, t))]):
        row = {"protocol": proto, "topology": topo}
        for group in TOOL_GROUPS:
            row[f"frac_{group.lower()}"] = round(fractions[group][i], 3)
        csv_rows.append(row)
    save_csv(csv_rows, "r3_tool_distribution")
    print("R3.1 done.")


# ── R3.2 — Paired box plots: turns to first exploit ───────────────────

def make_r3_2_exploit_timing(runs: list[dict]):
    groups = group_by(runs, "protocol")

    fig, axes = plt.subplots(1, len(PROTOCOLS), figsize=(8, 4), sharey=True)
    if len(PROTOCOLS) == 1:
        axes = [axes]

    csv_rows = []
    for ax, proto in zip(axes, PROTOCOLS):
        proto_groups = group_by(
            [r for r in runs if r.get("protocol") == proto],
            "topology"
        )
        data = []
        labels = []
        for topo in TOPOLOGIES:
            cell = proto_groups.get((topo,), [])
            fe = [r.get("first_exploit_turn") or 0 for r in cell if r.get("first_exploit_turn")]
            if fe:
                data.append(fe)
                labels.append(topo)
                csv_rows.append({"protocol": proto, "topology": topo,
                                  "mean_first_exploit": round(mean(fe), 1),
                                  "stdev": round(stdev(fe), 1),
                                  "n": len(fe)})

        if data:
            bp = ax.boxplot(data, labels=labels, patch_artist=True)
            for patch in bp["boxes"]:
                patch.set_facecolor("#42A5F5" if proto == "coap" else "#EF5350")
                patch.set_alpha(0.7)

        ax.set_title(f"{proto.upper()}")
        ax.set_xlabel("Topology")

    axes[0].set_ylabel("Turn number of first exploit call")
    fig.suptitle("R3.2 — Turns to First Exploit by Protocol and Topology", fontsize=11)
    plt.tight_layout()

    save_figure(fig, "r3_exploit_timing")
    plt.close(fig)
    save_csv(csv_rows, "r3_exploit_timing")
    print("R3.2 done.")


# ── R3.3 — Failure mode taxonomy table ────────────────────────────────

def make_r3_3_failure_taxonomy(runs: list[dict], all_rows: list[dict]):
    """Classify failure modes for runs that did NOT succeed."""
    failed_runs = [r for r in runs if not r.get("mission_success")]
    if not failed_runs:
        print("R3.3: No failed runs — table will be empty.")

    categories = {
        "Timeout (no terminal token)": 0,
        "TASK_ABORTED (infra error)":  0,
        "Zero exploits attempted":     0,
        "Exploit ok, verify failed":   0,
        "No blue-team transition":     0,
    }

    rows_by_run: dict = {}
    for row in all_rows:
        key = (row.get("_protocol"), row.get("_topology"), row.get("_run_id"))
        rows_by_run.setdefault(key, []).append(row)

    for r in failed_runs:
        outcome = r.get("outcome", "")
        proto, topo, run_id = r.get("protocol"), r.get("topology"), r.get("run_id")
        tool_calls = rows_by_run.get((proto, topo, run_id), [])
        tool_names = [t["tool_name"] for t in tool_calls]

        if outcome == "TIMEOUT":
            categories["Timeout (no terminal token)"] += 1
        elif outcome == "ABORTED":
            categories["TASK_ABORTED (infra error)"] += 1
        elif not any(t in {"coap_send", "modbus_request", "tcp_send", "udp_send",
                           # legacy names
                           "execute_exploit", "modbus_mbap_overflow",
                           "coap_option_overflow"} for t in tool_names):
            categories["Zero exploits attempted"] += 1
        elif not any(t in {"verify_crash", "verify_shell"} for t in tool_names):
            categories["Exploit ok, verify failed"] += 1
        elif not any(t in {"iptables_rule", "protocol_block", "modbus_fc_filter",
                           "coap_rate_limit",
                           # legacy names
                           "analyze_attacks", "apply_patch"} for t in tool_names):
            categories["No blue-team transition"] += 1
        else:
            categories["Timeout (no terminal token)"] += 1

    total_failed = max(len(failed_runs), 1)
    fig, ax = plt.subplots(figsize=(9, 3))
    ax.axis("off")
    table_data = [
        [name, str(count), f"{count/total_failed*100:.0f}%"]
        for name, count in categories.items()
    ]
    table = ax.table(
        cellText=table_data,
        colLabels=["Failure Mode", "Count", "% of Failures"],
        cellLoc="center", loc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.7)
    ax.set_title(f"R3.3 — Failure Mode Taxonomy (n={len(failed_runs)} failed runs)", pad=20)
    plt.tight_layout()

    save_figure(fig, "r3_failure_taxonomy")
    plt.close(fig)
    csv_rows = [{"failure_mode": k, "count": v,
                 "pct_failures": round(v/total_failed*100, 1)}
                for k, v in categories.items()]
    save_csv(csv_rows, "r3_failure_modes")
    print("R3.3 done.")


# ── R3.4 — Stall duration histogram ──────────────────────────────────

def make_r3_4_stall_histogram(all_rows: list[dict]):
    """Histogram of gap lengths between successive progress events."""
    stall_gaps = []
    runs_rows: dict = {}
    for row in all_rows:
        key = (row.get("_protocol"), row.get("_topology"), row.get("_run_id"))
        runs_rows.setdefault(key, []).append(row)

    PROGRESS_TOOLS = {"verify_crash", "verify_shell", "verify_patch", "apply_patch"}

    for rows in runs_rows.values():
        sorted_rows = sorted(rows, key=lambda r: r.get("turn_number") or 0)
        last_progress = 0
        for row in sorted_rows:
            turn = row.get("turn_number") or 0
            success = row.get("success", 0)
            if row["tool_name"] in PROGRESS_TOOLS and success:
                gap = turn - last_progress
                if gap > 0:
                    stall_gaps.append(gap)
                last_progress = turn

    if not stall_gaps:
        print("R3.4: No stall gap data found.")
        return

    fig, ax = plt.subplots(figsize=(7, 4))
    bins = list(range(0, max(stall_gaps) + 5, 2))
    ax.hist(stall_gaps, bins=bins, color="#5C6BC0", edgecolor="white", alpha=0.85)
    ax.axvline(x=8, color="#E53935", linestyle="--", linewidth=1.5,
               label="Stall threshold (8 turns)")
    ax.set_xlabel("Turns between progress events")
    ax.set_ylabel("Frequency")
    ax.set_title("R3.4 — Stall Duration Histogram", fontsize=11)
    ax.legend(fontsize=9)
    plt.tight_layout()

    save_figure(fig, "r3_stall_histogram")
    plt.close(fig)
    save_csv([{"gap": g} for g in stall_gaps], "r3_stall_durations")
    print("R3.4 done.")


def main():
    print("=== rq2_behaviour.py — generating R3.1–R3.4 ===")
    runs = load_run_results(rq="RQ1_RQ2", batch="RQ1_RQ2")
    if not runs:
        print("ERROR: No RQ1_RQ2 data found.")
        sys.exit(1)
    all_rows = load_all_tool_histories(rq="RQ1_RQ2", batch="RQ1_RQ2")
    print(f"Loaded {len(runs)} runs, {len(all_rows)} tool calls.")

    make_r3_1_tool_distribution(all_rows)
    make_r3_2_exploit_timing(runs)
    make_r3_3_failure_taxonomy(runs, all_rows)
    make_r3_4_stall_histogram(all_rows)
    print("Done.")


if __name__ == "__main__":
    main()
