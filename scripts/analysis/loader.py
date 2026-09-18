"""loader.py — Common data loading utilities for APIOT analysis scripts.

All analysis scripts import from here to ensure consistent data loading,
filtering, and derived-field computation.
"""

import json
import sqlite3
from pathlib import Path
from typing import Iterator

RESULTS_ROOT = Path(__file__).resolve().parent.parent.parent / "artifact" / "sanitized-runs"

# Pre-EXT7 run to exclude: used old toolset (execute_exploit/analyze_attacks),
# incompatible with EXT7 tool-name-based analysis.
STALE_GIT_HASH = "60d18da"

# EXT7 tool name sets for metric derivation from memory.db
_EXPLOIT_TOOL_NAMES = frozenset({
    # EXT7 protocol primitives
    "coap_send", "modbus_request", "tcp_send", "udp_send",
    "mqtt_publish", "mqtt_subscribe",
    # pre-EXT7 legacy names (kept for backward-compat with old runs)
    "execute_exploit", "modbus_write_coil", "modbus_mbap_overflow",
    "coap_option_overflow", "brute_force_ssh", "brute_force_telnet",
    "http_cmd_injection",
})
_BLUE_TOOL_NAMES = frozenset({
    "iptables_rule", "protocol_block", "modbus_fc_filter",
    "coap_rate_limit", "verify_patch", "list_patches",
    # legacy
    "analyze_attacks", "apply_patch",
})
_RECON_TOOL_NAMES = frozenset({
    "get_network_state", "get_actionable_targets", "inspect_lab",
    "run_command", "stealth_check",
})


# ── run_result.json loading ──────────────────────────────────────────

def iter_run_results(results_dir: Path = RESULTS_ROOT) -> Iterator[dict]:
    """Yield all run_result.json dicts found under results_dir."""
    for p in sorted(results_dir.rglob("run_result.json")):
        try:
            data = json.loads(p.read_text())
            data["_path"] = str(p.parent)
            # Derive batch from directory structure (top-level folder under results/).
            # e.g. results/RQ1_RQ2/coap_T1_run1 → batch="RQ1_RQ2"
            #      results/MODEL_SENS/easy/gemini/coap_T1_run1 → batch="MODEL_SENS"
            rel = p.parent.relative_to(results_dir)
            data["_batch"] = rel.parts[0] if rel.parts else "unknown"
            yield data
        except Exception:
            continue


def augment_from_db(run: dict) -> dict:
    """Populate missing turn-level metrics from memory.db.

    run_result.json often has null for total_turns, first_exploit_turn, etc.
    because the agent writes these fields but older runs pre-date the EXT4
    columns. This function reads them directly from the SQLite tool_history.

    Fields populated (only if currently null/missing):
      total_turns           — max(turn_number) in tool_history
      first_exploit_turn    — turn of first exploit-class tool call
      phase_transition_turn — turn of first blue-phase tool call
      total_tool_calls      — total rows in tool_history
      recon_calls           — calls that are pure recon (no attack/patch value)
      redundant_call_rate   — recon_calls / total_tool_calls
    """
    run_dir = Path(run["_path"])
    rows = load_tool_history(run_dir)
    if not rows:
        return run

    turn_numbers = [r.get("turn_number") or 0 for r in rows]
    if turn_numbers and not run.get("total_turns"):
        run["total_turns"] = max(turn_numbers)

    if not run.get("first_exploit_turn"):
        for r in rows:
            if r.get("tool_name") in _EXPLOIT_TOOL_NAMES:
                run["first_exploit_turn"] = r.get("turn_number")
                break

    if not run.get("phase_transition_turn"):
        for r in rows:
            if r.get("tool_name") in _BLUE_TOOL_NAMES or r.get("mission_phase") == "blue":
                run["phase_transition_turn"] = r.get("turn_number")
                break

    total = len(rows)
    recon = sum(1 for r in rows if r.get("tool_name") in _RECON_TOOL_NAMES)
    run["total_tool_calls"] = total
    run["recon_calls"] = recon
    run["redundant_call_rate"] = round(recon / total, 3) if total else 0.0

    # Fill blue_tool_calls and vulns_found for old-schema runs that lack them.
    # blue_tool_calls: count tool_history rows whose tool_name is a blue tool.
    # vulns_found: count verify_crash/verify_shell rows that succeeded.
    if "blue_tool_calls" not in run:
        run["blue_tool_calls"] = sum(
            1 for r in rows if r.get("tool_name") in _BLUE_TOOL_NAMES
        )
    if "vulns_found" not in run:
        run["vulns_found"] = sum(
            1 for r in rows
            if r.get("tool_name") in ("verify_crash", "verify_shell")
            and r.get("success") == 1
        )

    return run


def apply_task_abandonment(runs: list[dict]) -> None:
    """Flag task-abandonment false-completes in a list of run dicts (in-place).

    Marks runs where the agent called TASK_COMPLETE but did no real work:
      - Non-MQTT: vulns_found=0 AND blue_tool_calls=0
      - MQTT: first_exploit_turn is None (never published or subscribed)
    Only applies to new-schema runs (vulns_found + blue_tool_calls present).
    """
    for r in runs:
        has_new_schema = "vulns_found" in r and "blue_tool_calls" in r
        false_complete_non_mqtt = (
            has_new_schema
            and r.get("protocol") != "mqtt"
            and r.get("outcome") == "COMPLETE"
            and r.get("mission_success") is True
            and r.get("vulns_found", 0) == 0
            and r.get("blue_tool_calls", 0) == 0
        )
        false_complete_mqtt = (
            has_new_schema
            and r.get("protocol") == "mqtt"
            and r.get("outcome") == "COMPLETE"
            and r.get("mission_success") is True
            and r.get("first_exploit_turn") is None
        )
        false_complete = false_complete_non_mqtt or false_complete_mqtt
        r["task_abandonment"] = false_complete
        if false_complete:
            r["mission_success"] = False


def load_run_results(rq: str | None = None,
                     batch: str | None = None,
                     results_dir: Path = RESULTS_ROOT) -> list[dict]:
    """Load all run results, optionally filtered by RQ and/or batch directory.

    Excludes the pre-EXT7 stale run (git hash 60d18da) and augments
    each run with turn-level metrics from memory.db.

    Args:
        rq:    Filter by run_result.json "rq" field (e.g. "RQ1_RQ2", "RQ3").
        batch: Filter by top-level results directory (e.g. "RQ1_RQ2", "MODEL_SENS").
               Use this to exclude MODEL_SENS runs from RQ1_RQ2 analysis —
               MODEL_SENS runs intentionally set rq="RQ1_RQ2" but live under
               results/MODEL_SENS/, so rq-filter alone is not sufficient.
    """
    runs = list(iter_run_results(results_dir))
    # Exclude pre-EXT7 stale run that used incompatible toolset
    runs = [r for r in runs if r.get("git_hash_apiot") != STALE_GIT_HASH]
    # Augment with DB metrics where run_result.json has nulls
    runs = [augment_from_db(r) for r in runs]
    # Flag task-abandonment false-completes (GPT-5.4 MQTT pattern, etc.)
    apply_task_abandonment(runs)
    if rq:
        runs = [r for r in runs if r.get("rq") == rq]
    if batch:
        runs = [r for r in runs if r.get("_batch") == batch]
    return runs


# ── tool_history loading from memory.db ─────────────────────────────

def load_tool_history(run_dir: Path) -> list[dict]:
    """Load tool_history rows from a run's memory.db."""
    db_path = run_dir / "memory.db"
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT * FROM tool_history ORDER BY created_at ASC"
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def load_all_tool_histories(rq: str | None = None,
                             batch: str | None = None,
                             results_dir: Path = RESULTS_ROOT) -> list[dict]:
    """Load all tool_history rows across runs, annotated with run metadata."""
    all_rows = []
    for run in load_run_results(rq=rq, batch=batch, results_dir=results_dir):
        run_dir = Path(run["_path"])
        rows = load_tool_history(run_dir)
        for row in rows:
            row["_rq"]        = run.get("rq")
            row["_protocol"]  = run.get("protocol")
            row["_topology"]  = run.get("topology")
            row["_overseer"]  = run.get("overseer")
            row["_overseer_mode"] = run.get(
                "overseer_mode", "full" if run.get("overseer") else "off"
            )
            row["_impairment"]= run.get("impairment")
            row["_session"]   = run.get("session")
            row["_run_id"]    = run.get("run_id")
            row["_path"]      = run.get("_path")
            row["_mission_success"] = run.get("mission_success", False)
        all_rows.extend(rows)
    return all_rows


# ── Derived metrics ──────────────────────────────────────────────────

def success_rate(runs: list[dict]) -> float:
    """Mission success rate (0.0–1.0) across a list of run dicts."""
    if not runs:
        return 0.0
    return sum(1 for r in runs if r.get("mission_success")) / len(runs)


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def stdev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = mean(values)
    return (sum((v - m) ** 2 for v in values) / (len(values) - 1)) ** 0.5


def group_by(runs: list[dict], *keys: str) -> dict:
    """Group run dicts by a tuple of key values."""
    groups: dict = {}
    for r in runs:
        k = tuple(r.get(key) for key in keys)
        groups.setdefault(k, []).append(r)
    return groups


# ── Figure output helpers ────────────────────────────────────────────

FIGURES_DIR = Path(__file__).resolve().parent.parent.parent / "raid_paper" / "figures"
RESULTS_CSV_DIR = Path(__file__).resolve().parent.parent.parent / "results"


def ensure_figures_dir() -> Path:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    return FIGURES_DIR


def save_figure(fig, name: str) -> Path:
    """Save a matplotlib figure as both PDF and EPS (LNCS requires EPS)."""
    import matplotlib
    matplotlib.use("Agg")
    ensure_figures_dir()
    pdf_path = FIGURES_DIR / f"{name}.pdf"
    eps_path = FIGURES_DIR / f"{name}.eps"
    fig.savefig(pdf_path, bbox_inches="tight", dpi=150)
    fig.savefig(eps_path, bbox_inches="tight", format="eps")
    print(f"  Saved: {pdf_path}")
    print(f"  Saved: {eps_path}")
    return pdf_path


def save_csv(rows: list[dict], name: str) -> Path:
    """Save a list of dicts as CSV to results/."""
    import csv
    RESULTS_CSV_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_CSV_DIR / f"{name}.csv"
    if rows:
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
    print(f"  Saved CSV: {path}")
    return path
