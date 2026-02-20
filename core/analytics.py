"""analytics.py — Transform raw JSON logs into research-grade metrics.

Calculates PPV (Packets-Per-Vulnerability), TTR (Time-to-Remediation),
Success Rate, and Remediation Efficacy. Outputs LaTeX table and CSV.
"""

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
RESULTS_CSV = DATA_DIR / "final_results.csv"


def load_attack_log(path: Path | None = None) -> list[dict]:
    """Load attack_log.json entries."""
    p = path or DATA_DIR / "attack_log.json"
    if not p.exists() or p.stat().st_size == 0:
        return []
    return json.loads(p.read_text())


def load_remediation_log(path: Path | None = None) -> list[dict]:
    """Load remediation_log.json entries."""
    p = path or DATA_DIR / "remediation_log.json"
    if not p.exists() or p.stat().st_size == 0:
        return []
    data = json.loads(p.read_text())
    return data if isinstance(data, list) else [data]


def compute_ppv(entries: list[dict]) -> float | None:
    """Packets-Per-Vulnerability: total packets until first crash_verified or shell success."""
    total_packets = 0
    for e in entries:
        total_packets += e.get("packets_sent", 0)
        if e.get("outcome") in ("crash_verified", "success"):
            return total_packets / 1.0 if total_packets > 0 else None
    return None


def compute_ttr(attack_entries: list[dict], remediation_entries: list[dict]) -> float | None:
    """Time-to-Remediation: duration from first success to patch applied (seconds)."""
    success_ts = None
    for e in attack_entries:
        if e.get("outcome") in ("crash_verified", "success"):
            success_ts = e.get("timestamp")
            break
    if success_ts is None:
        return None

    patch_ts = None
    for r in remediation_entries:
        if r.get("applied"):
            patch_ts = r.get("timestamp") or r.get("elapsed_s")
            if "timestamp" in r:
                patch_ts = r["timestamp"]
            elif "elapsed_s" in r:
                patch_ts = success_ts + r["elapsed_s"]
            break
    if patch_ts is None:
        return None
    return patch_ts - success_ts if isinstance(patch_ts, (int, float)) else None


def compute_metrics(
    attack_log_path: Path | None = None,
    remediation_log_path: Path | None = None,
) -> dict:
    """Compute aggregate metrics from logs."""
    attacks = load_attack_log(attack_log_path)
    remediations = load_remediation_log(remediation_log_path)

    crashes = sum(1 for e in attacks if e.get("outcome") == "crash_verified")
    successes = sum(1 for e in attacks if e.get("outcome") == "success")
    total_vulns = crashes + successes
    total_packets = sum(e.get("packets_sent", 0) for e in attacks)
    patches_applied = sum(1 for r in remediations if r.get("applied"))
    patch_verified = sum(1 for e in attacks if e.get("outcome") == "patch_verified")

    ppv = total_packets / total_vulns if total_vulns > 0 else None
    ttr = None
    if attacks and remediations:
        first_success = next(
            (e for e in attacks if e.get("outcome") in ("crash_verified", "success")),
            None,
        )
        first_patch = next((r for r in remediations if r.get("applied")), None)
        if first_success and first_patch:
            t_s = first_success.get("timestamp")
            t_p = first_patch.get("timestamp")
            if t_s is not None and t_p is not None:
                ttr = t_p - t_s
            else:
                ttr = first_patch.get("elapsed_s")

    return {
        "total_steps": len(attacks),
        "total_packets": total_packets,
        "crashes_verified": crashes,
        "shell_successes": successes,
        "total_vulnerabilities": total_vulns,
        "ppv": ppv,
        "ttr_sec": ttr,
        "patches_applied": patches_applied,
        "patch_verified": patch_verified,
        "remediation_efficacy": (
            patch_verified / patches_applied if patches_applied > 0 else None
        ),
    }


def aggregate_scenario_results(results: list[dict]) -> dict:
    """Aggregate per-scenario results into overall metrics."""
    ppvs = [r["ppv"] for r in results if r.get("ppv") is not None]
    ttrs = [r["ttr_sec"] for r in results if r.get("ttr_sec") is not None]
    successes = sum(r.get("total_vulnerabilities", 0) for r in results)
    total_scenarios = len(results)
    success_count = sum(1 for r in results if r.get("total_vulnerabilities", 0) > 0)
    sr = (success_count / total_scenarios * 100) if total_scenarios > 0 else 0
    efficacy = [
        r["remediation_efficacy"]
        for r in results
        if r.get("remediation_efficacy") is not None
    ]

    return {
        "avg_ppv": sum(ppvs) / len(ppvs) if ppvs else None,
        "avg_ttr": sum(ttrs) / len(ttrs) if ttrs else None,
        "success_rate_pct": sr,
        "total_vulnerabilities": successes,
        "remediation_efficacy_pct": (
            sum(efficacy) / len(efficacy) * 100 if efficacy else None
        ),
        "scenario_count": total_scenarios,
    }


def to_latex_table(results: list[dict], scenario_ids: list[str]) -> str:
    """Generate LaTeX table (booktabs style)."""
    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{APIOT Benchmark Results}",
        r"\label{tab:apiot-benchmark}",
        r"\begin{tabular}{lcccc}",
        r"\toprule",
        r"Scenario & PPV & TTR (s) & Success & Remediation \\",
        r"        &     &         & Rate (\%) & Efficacy (\%) \\",
        r"\midrule",
    ]
    for i, r in enumerate(results):
        sid = scenario_ids[i] if i < len(scenario_ids) else f"Scenario {i+1}"
        ppv = f"{r['ppv']:.1f}" if r.get("ppv") is not None else "—"
        ttr = f"{r['ttr_sec']:.2f}" if r.get("ttr_sec") is not None else "—"
        vulns = r.get("total_vulnerabilities", 0)
        sr = "100" if vulns > 0 else "0"
        eff = (
            f"{r['remediation_efficacy']*100:.0f}"
            if r.get("remediation_efficacy") is not None
            else "—"
        )
        lines.append(f"{sid} & {ppv} & {ttr} & {sr} & {eff} \\\\")

    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\end{table}",
        ]
    )
    return "\n".join(lines)


def to_csv_rows(results: list[dict], scenario_ids: list[str], agg: dict) -> list[dict]:
    """Build CSV-compatible row dicts."""
    rows = []
    for i, r in enumerate(results):
        rows.append({
            "scenario": scenario_ids[i] if i < len(scenario_ids) else f"scenario_{i+1}",
            "ppv": r.get("ppv"),
            "ttr_sec": r.get("ttr_sec"),
            "total_packets": r.get("total_packets"),
            "total_vulnerabilities": r.get("total_vulnerabilities"),
            "remediation_efficacy": (
                r["remediation_efficacy"] * 100
                if r.get("remediation_efficacy") is not None
                else None
            ),
        })
    rows.append({
        "scenario": "AGGREGATE",
        "ppv": agg.get("avg_ppv"),
        "ttr_sec": agg.get("avg_ttr"),
        "total_packets": None,
        "total_vulnerabilities": agg.get("total_vulnerabilities"),
        "remediation_efficacy": agg.get("remediation_efficacy_pct"),
    })
    return rows


def write_csv(rows: list[dict], path: Path | None = None) -> None:
    """Write CSV file."""
    p = path or RESULTS_CSV
    p.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        p.write_text("scenario,ppv,ttr_sec,total_packets,total_vulnerabilities,remediation_efficacy\n")
        return
    import csv
    with open(p, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["scenario", "ppv", "ttr_sec", "total_packets", "total_vulnerabilities", "remediation_efficacy"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
