#!/usr/bin/env python3
"""full_autonomous_run.py — Lab setup/teardown for the LLM-driven Red Agent.

This script only manages infrastructure. The actual attack decisions
are made by the LLM agent (Cursor/Claude) calling:

    sudo python3 -m apiot.core.agent_loop <command> [args]

Test sequence (LLM drives steps 2-5):
  1. [script] Setup: start API, spawn targets, wait for DHCP.
  2. [LLM]   Discovery: call mapper to populate state.
  3. [LLM]   Reasoning: read targets, pick attack based on arch tags.
  4. [LLM]   Attack: call agent_loop attack/verify commands.
  5. [LLM]   Verify: confirm vulnerability in network_state.json.
  6. [script] Teardown: reset lab, stop API.

Usage:
    sudo python3 apiot/tests/full_autonomous_run.py setup
    # ... LLM does its thing ...
    sudo python3 apiot/tests/full_autonomous_run.py teardown
    sudo python3 apiot/tests/full_autonomous_run.py verify
"""

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

LAB_DIR = PROJECT_ROOT / "iot_vlab"


def ensure_api(client: LabClient) -> subprocess.Popen | None:
    try:
        client.get_library()
        print("[*] Lab API already running.")
        return None
    except LabOfflineError:
        print("[*] Starting lab API...")
        proc = subprocess.Popen(
            ["sudo", "python3", "lab_api.py"],
            cwd=str(LAB_DIR),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(20):
            time.sleep(1)
            try:
                client.get_library()
                print(f"[*] Lab API up (PID {proc.pid}).")
                return proc
            except LabOfflineError:
                continue
        print("[!] API failed to start.")
        proc.kill()
        sys.exit(1)


def cmd_setup():
    """Spin up the lab with heterogeneous targets."""
    client = LabClient()
    memory = AgentMemory()
    logger = AttackLogger()
    memory.clear()
    logger.clear()

    ensure_api(client)
    client.reset_lab()

    print("\n[setup] Spawning zephyr_coap (MCU CoAP Sensor)...")
    r1 = client.spawn_device("zephyr_coap")
    print(f"  run_id: {r1.get('run_id')}")

    print("[setup] Spawning dvrf_v03 (MIPS Linux Router)...")
    r2 = client.spawn_device("dvrf_v03")
    print(f"  run_id: {r2.get('run_id')}")

    print("\n[setup] Waiting 20s for boot + DHCP...")
    time.sleep(20)

    topo = client.get_topology()
    print("\n[setup] Topology:")
    for d in topo:
        print(f"  {d['firmware_id']:20s}  ip={d['ip']:18s}  alive={d['alive']}")

    print("\n[setup] Lab is ready. Now run the mapper and agent commands:")
    print("  sudo python3 -m apiot.core.mapper")
    print("  sudo python3 -m apiot.core.agent_loop get_targets")
    print("  sudo python3 -m apiot.core.agent_loop attack <tool> <ip>")
    print("  sudo python3 -m apiot.core.agent_loop verify_crash <ip>")
    print("  sudo python3 -m apiot.core.agent_loop log_summary")


def cmd_teardown():
    """Reset the lab and stop the API."""
    client = LabClient()
    try:
        r = client.reset_lab()
        print(f"[teardown] Lab reset: stopped {r.get('stopped', 0)} device(s).")
    except Exception as e:
        print(f"[teardown] Reset failed: {e}")
    subprocess.run(["sudo", "pkill", "-f", "python3 lab_api.py"],
                   capture_output=True)
    print("[teardown] Done.")


def cmd_verify():
    """Check that the autonomous run produced results."""
    memory = AgentMemory()
    logger = AttackLogger()
    state = memory.get_full_context()
    summary = logger.get_summary()

    vulns = state.get("active_vulnerabilities", {})
    print("\n=== AUTONOMOUS RUN VERIFICATION ===\n")
    print(f"  Targets fingerprinted: {len(state.get('fingerprints', {}))}")
    print(f"  Vulnerabilities found: {len(vulns)}")
    print(f"  Attack steps logged:   {summary['total_steps']}")
    print(f"  Total packets sent:    {summary['total_packets']}")
    print(f"  Crashes verified:      {summary['crashes_verified']}")
    print(f"  Packets/vulnerability: {summary['packets_per_vulnerability']:.1f}")

    ok = len(vulns) >= 1
    print(f"\n  RESULT: {'PASS' if ok else 'FAIL'} — "
          f"{'vulnerability_confirmed entry exists' if ok else 'no vulnerabilities recorded'}")

    if vulns:
        print("\n  Vulnerabilities:")
        for vid, v in vulns.items():
            print(f"    {vid}: {v.get('attack')} on {v.get('ip')}")

    return 0 if ok else 1


def main():
    if len(sys.argv) < 2:
        print("Usage: full_autonomous_run.py <setup|teardown|verify>")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "setup":
        cmd_setup()
    elif cmd == "teardown":
        cmd_teardown()
    elif cmd == "verify":
        sys.exit(cmd_verify())
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
