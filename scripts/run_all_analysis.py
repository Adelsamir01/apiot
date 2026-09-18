#!/usr/bin/env python3
"""run_all_analysis.py — Run all analysis scripts to produce all 14 paper outputs.

Calls each rq*_*.py analysis script in sequence. Use after all experiments complete.

Usage:
    python3 scripts/run_all_analysis.py            # all outputs
    python3 scripts/run_all_analysis.py --rq R1    # specific outputs only
    python3 scripts/run_all_analysis.py --check    # check which outputs exist
"""

import argparse
import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
FIGURES_DIR = SCRIPTS_DIR.parent / "raid_paper" / "figures"

ANALYSIS_SCRIPTS = [
    ("R1.1 + R1.2", "rq1_capability.py",  "§5.1 Capability Baseline"),
    ("R2.1–R2.4",   "rq3_oversight.py",   "§5.2 Oversight Ablation"),
    ("R3.1–R3.4",   "rq2_behaviour.py",   "§5.3 Behavioural Profile"),
    ("R4.1 + R4.2", "rq4_memory.py",      "§5.4 Cross-session Memory"),
    ("R5.1 + R5.2", "rq5_deployment.py",  "§5.5 Deployment Boundaries"),
]

EXPECTED_FIGURES = [
    "r1_success_heatmap",
    "r1_mission_timeline",
    "r2_oversight_grouped_bars",
    "r2_degenerate_behaviour",
    "r2_overseer_interventions",
    "r2_productive_calls_timeline",
    "r3_tool_distribution",
    "r3_exploit_timing",
    "r3_failure_taxonomy",
    "r3_stall_histogram",
    "r4_session_comparison",
    "r4_efficiency_gain",
    "r5_topology_scaling",
    "r5_impairment_curve",
]


def check_outputs():
    print(f"\nFigure output status ({FIGURES_DIR}):\n")
    total = len(EXPECTED_FIGURES)
    found = 0
    for name in EXPECTED_FIGURES:
        eps = FIGURES_DIR / f"{name}.eps"
        pdf = FIGURES_DIR / f"{name}.pdf"
        status = "✓" if eps.exists() else "·"
        if eps.exists():
            found += 1
        print(f"  {status} {name}.eps  {'(+ PDF)' if pdf.exists() else ''}")
    print(f"\n{found}/{total} figures produced.\n")
    return found == total


def main():
    parser = argparse.ArgumentParser(description="Run all APIOT analysis scripts")
    parser.add_argument("--rq", choices=["R1", "R2", "R3", "R4", "R5"],
                        help="Run only a specific set of analyses")
    parser.add_argument("--check", action="store_true",
                        help="Check which figure outputs exist without running scripts")
    args = parser.parse_args()

    if args.check:
        all_done = check_outputs()
        sys.exit(0 if all_done else 1)

    scripts_to_run = ANALYSIS_SCRIPTS
    if args.rq:
        scripts_to_run = [s for s in ANALYSIS_SCRIPTS if s[0].startswith(args.rq)]

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    failures = []
    for outputs, script_name, description in scripts_to_run:
        script_path = SCRIPTS_DIR / "analysis" / script_name
        print(f"\n{'='*60}")
        print(f"Running {script_name}  ({description})")
        print(f"Outputs: {outputs}")
        print(f"{'='*60}")

        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(SCRIPTS_DIR.parent),
        )
        if result.returncode != 0:
            print(f"[FAIL] {script_name} exited with code {result.returncode}")
            failures.append(script_name)
        else:
            print(f"[OK] {script_name}")

    print(f"\n{'='*60}")
    if failures:
        print(f"FAILED: {', '.join(failures)}")
        print("Check for missing data (run check_results.py to see experiment status)")
        sys.exit(1)
    else:
        check_outputs()
        print("All analysis complete.")


if __name__ == "__main__":
    main()
