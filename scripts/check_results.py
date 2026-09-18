#!/usr/bin/env python3
"""check_results.py — Quick summary of experiment run completion status.

Scans results/ for run_result.json files and prints a per-batch, per-condition
completion table. Run at any point to see how many experiments are done.

Usage:
    python3 scripts/check_results.py
    python3 scripts/check_results.py --results-dir /path/to/results
"""

import argparse
import json
from pathlib import Path

# Expected conditions (rq, protocol, topology, overseer, impairment, session, run)
EXPECTED_RUNS = []

# RQ1/RQ2
for proto in ["coap", "modbus"]:
    for topo in ["T1", "T2", "T3"]:
        for run in [1, 2, 3]:
            EXPECTED_RUNS.append({
                "rq": "RQ1_RQ2", "protocol": proto, "topology": topo,
                "overseer": True, "impairment": "none", "session": 1, "run_id": run,
                "label": f"RQ1_RQ2/{proto}_{topo}_run{run}",
            })

# RQ1/RQ2 MQTT (hard protocol — T1 only, overseer ON)
for run in [1, 2, 3]:
    EXPECTED_RUNS.append({
        "rq": "RQ1_RQ2", "protocol": "mqtt", "topology": "T1",
        "overseer": True, "impairment": "none", "session": 1, "run_id": run,
        "label": f"RQ1_RQ2/mqtt_T1_run{run}",
    })

# RQ3 (OFF condition only)
for proto in ["coap", "modbus", "mqtt"]:
    for run in [1, 2, 3]:
        EXPECTED_RUNS.append({
            "rq": "RQ3", "protocol": proto, "topology": "T1",
            "overseer": False, "impairment": "none", "session": 1, "run_id": run,
            "label": f"RQ3/{proto}_T1_no_overseer_run{run}",
        })

# RQ4 (session 2 only — session 1 reuses RQ1/RQ2 T1 data)
for proto in ["coap", "modbus"]:
    for run in [1, 2, 3]:
        EXPECTED_RUNS.append({
            "rq": "RQ4", "protocol": proto, "topology": "T1",
            "overseer": True, "impairment": "none", "session": 2, "run_id": run,
            "label": f"RQ4/{proto}_T1_s2_run{run}",
        })

# RQ6 (Medium + Heavy × 2 protocols × 3 replicates = 12 runs; None reuses RQ1/RQ2 T1)
for proto in ["coap", "modbus"]:
    for imp in ["medium", "heavy"]:
        for run in [1, 2, 3]:
            EXPECTED_RUNS.append({
                "rq": "RQ6", "protocol": proto, "topology": "T1",
                "overseer": True, "impairment": imp, "session": 1, "run_id": run,
                "label": f"RQ6/{proto}_T1_{imp}_run{run}",
            })

# Model sensitivity (3 conditions × 4 models × 3 runs = 36 new runs)
_SENS_MODELS = [
    "google/gemini-3.1-pro-preview",
    "anthropic/claude-sonnet-4-6",
    "openai/gpt-5.4",
    "z-ai/glm-5",
]
_SENS_CONDITIONS = [
    ("easy",  "coap", False),   # guided CoAP T1
    ("hard",  "mqtt", False),   # guided MQTT T1
    ("blind", "coap", True),    # blind CoAP T1
]
for model in _SENS_MODELS:
    slug = model.replace("/", "_")
    for cond, proto, blind in _SENS_CONDITIONS:
        for run in [1, 2, 3]:
            EXPECTED_RUNS.append({
                "rq": "MODEL_SENS", "protocol": proto, "topology": "T1",
                "overseer": True, "impairment": "none", "session": 1, "run_id": run,
                "model": model, "blind": blind,
                "label": f"MODEL_SENS/{cond}/{slug}/{proto}_T1_run{run}",
            })


def _load_result(results_dir: Path, label: str) -> dict | None:
    p = results_dir / label / "run_result.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="Check APIOT experiment run completion")
    parser.add_argument("--results-dir", default="results",
                        help="Path to results directory (default: results/)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show all runs, not just missing ones")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)

    by_rq: dict[str, list[dict]] = {}
    for spec in EXPECTED_RUNS:
        rq = spec["rq"]
        result = _load_result(results_dir, spec["label"])
        by_rq.setdefault(rq, []).append((spec, result))

    total = len(EXPECTED_RUNS)
    done = 0
    complete = 0

    print(f"\n{'='*70}")
    print(f"APIOT — Experiment Run Status  (results: {results_dir})")
    print(f"{'='*70}")

    for rq, runs in sorted(by_rq.items()):
        rq_done = sum(1 for _, r in runs if r is not None)
        rq_complete = sum(1 for _, r in runs if r and r.get("mission_success"))
        print(f"\n  {rq}  [{rq_done}/{len(runs)} done, {rq_complete} successful]")

        if args.verbose or rq_done < len(runs):
            for spec, result in runs:
                if result is None:
                    status = "MISSING"
                else:
                    outcome = result.get("outcome", "?")
                    success = result.get("mission_success", False)
                    turns = result.get("total_turns", "?")
                    dur = result.get("duration_seconds", 0)
                    mins, secs = divmod(int(dur), 60)
                    status = f"{outcome} {'✓' if success else '✗'}  turns={turns}  {mins}m{secs}s"
                if result is None or args.verbose:
                    print(f"    {'✓' if result else '·'} {spec['label']:<45}  {status}")

        done += rq_done
        complete += rq_complete

    print(f"\n{'='*70}")
    print(f"  Total: {done}/{total} runs done  |  {complete} mission successes  |  {total-done} pending")
    print(f"{'='*70}\n")

    # Per-condition success rate summary (useful for paper)
    print("  Success rates by condition:")
    for rq, runs in sorted(by_rq.items()):
        successes = [r for _, r in runs if r and r.get("mission_success")]
        attempted = [r for _, r in runs if r is not None]
        if attempted:
            rate = len(successes) / len(attempted) * 100
            print(f"    {rq:12s}  {len(successes)}/{len(attempted)} = {rate:.0f}%")


if __name__ == "__main__":
    main()
