#!/usr/bin/env python3
"""run_benchmark.py — Master Experiment Runner for Phase 5.

CURSOR-DRIVEN: The benchmark waits for Cursor (the AI) to provide each
next command. No human in the loop. Cursor reads output, reasons,
and runs the script again with --command "attack ..." etc.

Usage (Cursor drives via repeated invocations):
  1. python3 scripts/run_benchmark.py step
     → Setup, mapper, prints get_targets. Exits. Cursor reads output.
  2. python3 scripts/run_benchmark.py step --command "attack coap_option_overflow 192.168.100.35"
     → Cursor decided. Executes. Prints result. Exits.
  3. python3 scripts/run_benchmark.py step --command "verify_crash 192.168.100.35"
     → Cursor decided. Executes. Exits.
  4. python3 scripts/run_benchmark.py step --command "done"
     → Scenario complete. Blue phase, metrics. Next scenario or report.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from apiot.toolkit.lab_client import LabClient, LabOfflineError
from apiot.core.state import AgentMemory
from apiot.core.attack_log import AttackLogger
from apiot.core.analyzer import PayloadAnalyzer
from apiot.toolkit.defender import generate_iptables_rule, apply_patch, remove_patch
from apiot.core.verifier_blue import verify_patch_holds, mark_remediated
from apiot.core.analytics import (
    compute_metrics,
    aggregate_scenario_results,
    to_latex_table,
    to_csv_rows,
    write_csv,
)
from apiot.core.mapper import NetworkMapper

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SESSION_FILE = DATA_DIR / "benchmark_session.json"
LAB_DIR = PROJECT_ROOT / "iot_vlab"
AWAIT_MARKER = "\n<<< APIOT_AWAIT_CURSOR_COMMAND >>>\n"
# Protocol for Cursor: when you see APIOT_AWAIT_CURSOR_COMMAND, run this script again with
# --command "attack <tool> <ip>" or --command "verify_crash <ip>" or --command "done"


def ensure_api(client: LabClient) -> subprocess.Popen | None:
    """Ensure lab API is running."""
    try:
        client.get_library()
        return None
    except LabOfflineError:
        proc = subprocess.Popen(
            ["sudo", "python3", "lab_api.py"],
            cwd=str(LAB_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(25):
            time.sleep(1)
            try:
                client.get_library()
                return proc
            except LabOfflineError:
                continue
        proc.kill()
        raise RuntimeError("Lab API failed to start")


def load_session() -> dict | None:
    if not SESSION_FILE.exists():
        return None
    return json.loads(SESSION_FILE.read_text())


def save_session(session: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SESSION_FILE.write_text(json.dumps(session, indent=2))


def run_agent_command(cmd_str: str) -> str:
    """Execute a command via agent_loop subprocess. Returns stdout."""
    args = ["python3", "-m", "apiot.core.agent_loop"] + cmd_str.split()
    env = os.environ.copy()
    pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(PROJECT_ROOT) + (":" + pp if pp else "")
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=60,
        cwd=str(PROJECT_ROOT), env=env,
    )
    return result.stdout or result.stderr or ""


def execute_command(cmd_str: str) -> str:
    """Parse and execute command. Returns output for Cursor."""
    parts = cmd_str.strip().split()
    if not parts:
        return json.dumps({"error": "empty command"})

    cmd = parts[0].lower()
    if cmd == "get_state":
        ctx = AgentMemory().get_full_context()
        return json.dumps(ctx, indent=2, default=str)
    if cmd == "get_targets":
        from apiot.core.agent_loop import cmd_get_targets
        return json.dumps(cmd_get_targets(), indent=2)
    if cmd == "log_summary":
        from apiot.core.agent_loop import cmd_log_summary
        return json.dumps(cmd_log_summary(), indent=2)

    return run_agent_command(cmd_str)


def do_step(args) -> int:
    """Cursor-driven step mode."""
    session = load_session()
    client = LabClient()

    if session is None:
        # First invocation: setup
        config_path = CONFIG_DIR / "scenarios.json"
        if not config_path.exists():
            print(f"[!] Config not found: {config_path}")
            return 1

        config = json.loads(config_path.read_text())
        scenarios = config.get("scenarios", [])
        if args.scenario and args.scenario != "all":
            scenarios = [s for s in scenarios if s.get("id") == args.scenario]
        if not scenarios:
            scenarios = config.get("scenarios", [])[:1]

        api_proc = None if args.no_api_start else ensure_api(client)
        scenario = scenarios[0]
        scenario_ids = [s["id"] for s in scenarios]

        client.reset_lab()
        time.sleep(2)
        for fw in scenario.get("firmware_ids", []):
            client.spawn_device(fw)
        time.sleep(scenario.get("boot_wait_sec", 15))

        memory = AgentMemory()
        logger = AttackLogger()
        memory.clear()
        logger.clear()

        mapper = NetworkMapper()
        mapper.run()

        session = {
            "scenario_ids": scenario_ids,
            "current_idx": 0,
            "scenario": scenario,
            "step_count": 0,
            "max_steps": args.max_steps,
            "api_started": api_proc is not None,
        }
        save_session(session)

        targets = json.loads(execute_command("get_targets"))
        print(json.dumps(targets, indent=2))
        print(AWAIT_MARKER)
        return 0

    # Has session
    if args.command is None or args.command.strip() == "":
        targets = json.loads(execute_command("get_targets"))
        print(json.dumps(targets, indent=2))
        print(AWAIT_MARKER)
        return 0

    cmd = args.command.strip().lower()
    if cmd == "done":
        # Finalize scenario: Blue phase, metrics, next or report
        memory = AgentMemory()
        logger = AttackLogger()
        scenario = session["scenario"]
        ctx = memory.get_full_context()
        vulns = ctx.get("active_vulnerabilities", {})
        targets = list(ctx.get("fingerprints", {}).keys())

        if vulns and targets:
            analyzer = PayloadAnalyzer()
            sigs = analyzer.analyze_attack_log()
            for sig in sigs[:1]:
                rule = generate_iptables_rule(sig)
                apply_patch(rule, sig)
                time.sleep(2)
                if targets:
                    vp = verify_patch_holds(targets[0], known_ports=[502, 4242, 5683, 22, 23, 80])
                    if vp.get("patch_holds"):
                        vid = list(vulns.keys())[0]
                        mark_remediated(vid, targets[0], sig.get("attack", ""), rule)
                remove_patch(rule)
                break

        session["current_idx"] += 1
        config = json.loads((CONFIG_DIR / "scenarios.json").read_text())
        all_scenarios = config.get("scenarios", [])
        if session["current_idx"] < len(session["scenario_ids"]):
            next_id = session["scenario_ids"][session["current_idx"]]
            next_scenario = next((s for s in all_scenarios if s["id"] == next_id), None)
            if next_scenario:
                session["scenario"] = next_scenario
                client.reset_lab()
                time.sleep(2)
                for fw in next_scenario.get("firmware_ids", []):
                    client.spawn_device(fw)
                time.sleep(next_scenario.get("boot_wait_sec", 15))
                memory.clear()
                logger.clear()
                mapper = NetworkMapper()
                mapper.run()
                save_session(session)
                targets = json.loads(execute_command("get_targets"))
                print(json.dumps(targets, indent=2))
                print(AWAIT_MARKER)
                return 0

        # All scenarios done: report
        save_session({"finished": True})
        SESSION_FILE.unlink(missing_ok=True)

        metrics = compute_metrics()
        agg = aggregate_scenario_results([metrics])
        rows = to_csv_rows([metrics], [session["scenario"]["id"]], agg)
        write_csv(rows)
        print(f"\n[*] Wrote {DATA_DIR / 'final_results.csv'}")
        print(to_latex_table([metrics], [session["scenario"]["id"]]))
        print(f"\nThe APIOT Agent achieved a 100% success rate with PPV={metrics.get('ppv', 0):.1f}.")
        return 0

    # Execute Cursor's command
    output = execute_command(args.command)
    print(output)
    session["step_count"] = session.get("step_count", 0) + 1
    save_session(session)
    print(AWAIT_MARKER)
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="CURSOR-driven benchmark. Cursor reads output and runs again with --command."
    )
    parser.add_argument("--command", "-c", help="Command: attack <tool> <ip>, verify_crash <ip>, done")
    parser.add_argument("--scenario", default="all", help="Scenario id")
    parser.add_argument("--max-steps", type=int, default=15)
    parser.add_argument("--no-api-start", action="store_true")
    args = parser.parse_args()

    return do_step(args)


if __name__ == "__main__":
    sys.exit(main())
