"""analytics.py — Analytics dashboard + benchmark metrics for APIOT.

Part 1: Analytics class using persistent memory (MemoryStore).
Part 2: Legacy benchmark functions (compute_metrics, etc.) used by run_benchmark.py.
"""

import csv
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
RESULTS_CSV = DATA_DIR / "final_results.csv"


# ── Part 1: MemoryStore-backed analytics ─────────────────────────────

class Analytics:
    """Aggregates and reports APIOT metrics from persistent memory."""

    def __init__(self, memory):
        self.memory = memory

    def session_summary(self, session_id: str | None = None) -> dict:
        if session_id:
            rows = self.memory._conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchall()
        else:
            rows = self.memory._conn.execute(
                "SELECT * FROM sessions ORDER BY start_time DESC LIMIT 1"
            ).fetchall()
        if not rows:
            return {"error": "No sessions found"}
        data = dict(rows[0])

        tool_rows = self.memory._conn.execute(
            "SELECT tool_name, success FROM tool_history WHERE session_id = ?",
            (data["id"],)
        ).fetchall()
        tools_used = {}
        for r in tool_rows:
            name = r["tool_name"]
            if name not in tools_used:
                tools_used[name] = {"calls": 0, "successes": 0}
            tools_used[name]["calls"] += 1
            if r["success"]:
                tools_used[name]["successes"] += 1

        data["tools_used"] = tools_used
        data["total_tool_calls"] = len(tool_rows)
        return data

    def cross_session_trends(self, limit: int = 20) -> dict:
        sessions = self.memory.get_session_history(limit=limit)
        if not sessions:
            return {"error": "No sessions found"}

        total_vulns = sum(s.get("vulns_found", 0) for s in sessions)
        total_patches = sum(s.get("patches_applied", 0) for s in sessions)
        total_devices = sum(s.get("devices_tested", 0) for s in sessions)

        return {
            "total_sessions": len(sessions),
            "total_vulns_found": total_vulns,
            "total_patches_applied": total_patches,
            "total_devices_tested": total_devices,
            "avg_vulns_per_session": total_vulns / len(sessions),
            "avg_patches_per_session": total_patches / len(sessions),
            "patch_rate": total_patches / max(total_vulns, 1),
        }

    def device_risk_scores(self) -> list[dict]:
        profiles = self.memory.get_all_device_profiles()
        scored = []
        for p in profiles:
            ip = p["ip"]
            findings = self.memory.get_findings_for_device(ip)
            patches = self.memory.get_patches_for_device(ip)
            open_vulns = [f for f in findings if f.get("status") == "open"]
            verified_patches = [pat for pat in patches if pat.get("verified")]

            risk = len(open_vulns) * 10 - len(verified_patches) * 5
            if p.get("status") == "compromised":
                risk += 20
            risk = max(risk, 0)

            scored.append({
                "ip": ip,
                "device_name": p.get("device_name", "?"),
                "status": p.get("status", "unknown"),
                "risk_score": risk,
                "open_vulns": len(open_vulns),
                "verified_patches": len(verified_patches),
            })
        scored.sort(key=lambda x: -x["risk_score"])
        return scored

    def tool_effectiveness_report(self) -> dict:
        rows = self.memory._conn.execute(
            "SELECT tool_name, success FROM tool_history"
        ).fetchall()
        stats = {}
        for r in rows:
            name = r["tool_name"]
            if name not in stats:
                stats[name] = {"calls": 0, "successes": 0, "rate": 0.0}
            stats[name]["calls"] += 1
            if r["success"]:
                stats[name]["successes"] += 1
        for s in stats.values():
            s["rate"] = s["successes"] / s["calls"] if s["calls"] else 0.0
        return stats

    def format_report(self) -> str:
        lines = ["=== APIOT Analytics Report ===\n"]

        trends = self.cross_session_trends()
        if "error" not in trends:
            lines.append(f"Sessions: {trends['total_sessions']}")
            lines.append(f"Total vulns: {trends['total_vulns_found']}, "
                         f"Avg/session: {trends['avg_vulns_per_session']:.1f}")
            lines.append(f"Total patches: {trends['total_patches_applied']}, "
                         f"Patch rate: {trends['patch_rate']:.0%}")
            lines.append("")

        risks = self.device_risk_scores()
        if risks:
            lines.append("Device Risk Scores:")
            for r in risks:
                lines.append(f"  {r['ip']} ({r['device_name']}): "
                             f"risk={r['risk_score']}, open={r['open_vulns']}, "
                             f"patched={r['verified_patches']}")
            lines.append("")

        tools = self.tool_effectiveness_report()
        if tools:
            lines.append("Tool Effectiveness:")
            for name, s in sorted(tools.items(), key=lambda x: -x[1]["rate"]):
                lines.append(f"  {name}: {s['successes']}/{s['calls']} ({s['rate']:.0%})")

        lines.append("\n=== End Report ===")
        return "\n".join(lines)


# ── Part 2: Legacy benchmark functions ────────────────────────────────


def load_attack_log(path: Path | None = None) -> list[dict]:
    p = path or DATA_DIR / "attack_log.json"
    if not p.exists() or p.stat().st_size == 0:
        return []
    return json.loads(p.read_text())


def load_remediation_log(path: Path | None = None) -> list[dict]:
    p = path or DATA_DIR / "remediation_log.json"
    if not p.exists() or p.stat().st_size == 0:
        return []
    data = json.loads(p.read_text())
    return data if isinstance(data, list) else [data]


def compute_metrics(attack_log_path=None, remediation_log_path=None) -> dict:
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
            (e for e in attacks if e.get("outcome") in ("crash_verified", "success")), None)
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
    ppvs = [r["ppv"] for r in results if r.get("ppv") is not None]
    ttrs = [r["ttr_sec"] for r in results if r.get("ttr_sec") is not None]
    successes = sum(r.get("total_vulnerabilities", 0) for r in results)
    total_scenarios = len(results)
    success_count = sum(1 for r in results if r.get("total_vulnerabilities", 0) > 0)
    sr = (success_count / total_scenarios * 100) if total_scenarios > 0 else 0
    efficacy = [r["remediation_efficacy"] for r in results if r.get("remediation_efficacy") is not None]

    return {
        "avg_ppv": sum(ppvs) / len(ppvs) if ppvs else None,
        "avg_ttr": sum(ttrs) / len(ttrs) if ttrs else None,
        "success_rate_pct": sr,
        "total_vulnerabilities": successes,
        "remediation_efficacy_pct": (sum(efficacy) / len(efficacy) * 100 if efficacy else None),
        "scenario_count": total_scenarios,
    }


def to_latex_table(results: list[dict], scenario_ids: list[str]) -> str:
    lines = [
        r"\begin{table}[htbp]", r"\centering",
        r"\caption{APIOT Benchmark Results}", r"\label{tab:apiot-benchmark}",
        r"\begin{tabular}{lcccc}", r"\toprule",
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
        eff = (f"{r['remediation_efficacy']*100:.0f}" if r.get("remediation_efficacy") is not None else "—")
        lines.append(f"{sid} & {ppv} & {ttr} & {sr} & {eff} \\\\")
    lines.extend([r"\bottomrule", r"\end{tabular}", r"\end{table}"])
    return "\n".join(lines)


def to_csv_rows(results: list[dict], scenario_ids: list[str], agg: dict) -> list[dict]:
    rows = []
    for i, r in enumerate(results):
        rows.append({
            "scenario": scenario_ids[i] if i < len(scenario_ids) else f"scenario_{i+1}",
            "ppv": r.get("ppv"), "ttr_sec": r.get("ttr_sec"),
            "total_packets": r.get("total_packets"),
            "total_vulnerabilities": r.get("total_vulnerabilities"),
            "remediation_efficacy": (r["remediation_efficacy"] * 100 if r.get("remediation_efficacy") is not None else None),
        })
    rows.append({
        "scenario": "AGGREGATE", "ppv": agg.get("avg_ppv"), "ttr_sec": agg.get("avg_ttr"),
        "total_packets": None, "total_vulnerabilities": agg.get("total_vulnerabilities"),
        "remediation_efficacy": agg.get("remediation_efficacy_pct"),
    })
    return rows


def write_csv(rows: list[dict], path: Path | None = None) -> None:
    p = path or RESULTS_CSV
    p.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        p.write_text("scenario,ppv,ttr_sec,total_packets,total_vulnerabilities,remediation_efficacy\n")
        return
    with open(p, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["scenario", "ppv", "ttr_sec", "total_packets",
                           "total_vulnerabilities", "remediation_efficacy"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
