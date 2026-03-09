#!/usr/bin/env python3
"""full_autonomous_run.py — Infrastructure check for the LLM-driven Red Agent.

Requires iot_vlab to be running with targets already spawned.
APIOT does NOT start, stop, or respawn iot_vlab.

The actual attack decisions are made by the LLM agent calling:
    sudo python3 -m apiot.core.agent_loop <command> [args]

Usage:
    sudo python3 apiot/tests/full_autonomous_run.py check
    # ... LLM does its thing ...
    sudo python3 apiot/tests/full_autonomous_run.py verify
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from apiot.toolkit.lab_client import LabClient, LabOfflineError
from apiot.core.state import AgentMemory
from apiot.core.attack_log import AttackLogger


def cmd_check():
    """Verify the lab is running and has devices."""
    client = LabClient()

    try:
        lib = client.get_library()
    except LabOfflineError:
        print("[!] Lab API is not running. Start iot_vlab manually first.")
        sys.exit(1)

    topo = client.get_topology()
    print(f"[check] Lab is online. {len(lib)} firmware(s), {len(topo)} device(s).")

    if not topo:
        print("[!] No devices in the lab. Spawn targets via iot_vlab before running the agent.")
        sys.exit(1)

    print("\n[check] Topology:")
    for d in topo:
        print(f"  {d['firmware_id']:20s}  ip={d['ip']:18s}  alive={d['alive']}")

    print("\n[check] Lab is ready. Now run the mapper and agent commands:")
    print("  sudo python3 -m apiot.core.mapper")
    print("  sudo python3 -m apiot.core.agent_loop get_targets")
    print("  sudo python3 -m apiot.core.agent_loop attack <tool> <ip>")
    print("  sudo python3 -m apiot.core.agent_loop verify_crash <ip>")
    print("  sudo python3 -m apiot.core.agent_loop log_summary")


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
        print("Usage: full_autonomous_run.py <check|verify>")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "check":
        cmd_check()
    elif cmd == "verify":
        sys.exit(cmd_verify())
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
