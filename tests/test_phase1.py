#!/usr/bin/env python3
"""test_phase1.py — Integration test for apiot Phase 1 against a live iot_vlab.

Requires iot_vlab to be running with at least one device spawned.
APIOT does NOT start, stop, or respawn iot_vlab.

Run with:  sudo python3 -m apiot.tests.test_phase1   (from llm_iot/)
      or:  sudo python3 apiot/tests/test_phase1.py
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from apiot.toolkit.lab_client import LabClient, LabOfflineError
from apiot.toolkit.recon import scan_subnet, fingerprint_target
from apiot.core.state import AgentMemory

API_URL = "http://localhost:5000"
PASS = 0
FAIL = 0


def check(label: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}  {detail}")


def main():
    client = LabClient(base_url=API_URL)
    memory = AgentMemory()
    memory.clear()

    try:
        client.get_library()
        print("[*] Lab API is reachable.")
    except LabOfflineError:
        print("[!] Lab API is not running. Start iot_vlab manually first.")
        sys.exit(1)

    run_tests(client, memory)

    print(f"\n{'='*50}")
    print(f"Results: {PASS} passed, {FAIL} failed out of {PASS+FAIL}")
    print(f"{'='*50}")
    sys.exit(1 if FAIL else 0)


def run_tests(client: LabClient, memory: AgentMemory):
    # --- 1. Library ---
    print("\n--- Test: get_library ---")
    lib = client.get_library()
    check("Library returns a list", isinstance(lib, list))
    fw_ids = [f["id"] for f in lib]
    check("zephyr_echo in library", "zephyr_echo" in fw_ids)
    check("dvrf_v03 in library", "dvrf_v03" in fw_ids)

    # --- 2. Topology ---
    print("\n--- Test: topology ---")
    topo = client.get_topology()
    check("Topology is a list", isinstance(topo, list))
    check("At least one device in topology", len(topo) >= 1,
          f"got {len(topo)} — spawn devices via iot_vlab before running this test")

    topo_ips = [d["ip"] for d in topo if d.get("ip") and d["ip"] not in ("pending", "unknown")]

    # --- 3. Subnet scan ---
    print("\n--- Test: scan_subnet ---")
    hosts = scan_subnet("192.168.100.10-50")
    check("scan_subnet returns list", isinstance(hosts, list))
    check("At least 1 host found", len(hosts) >= 1, f"found {len(hosts)}")
    host_ips = [h["ip"] for h in hosts]

    for h in hosts:
        memory.update_host(h["ip"], {"mac": h["mac"], "vendor": h["vendor"]})

    # --- 4. Fingerprint (first available target) ---
    target_ip = topo_ips[0] if topo_ips else (host_ips[0] if host_ips else "192.168.100.1")
    print(f"\n--- Test: fingerprint_target({target_ip}) ---")
    fp = fingerprint_target(target_ip, ports="22,23,80,502,4242,5683")
    check("fingerprint returns dict", isinstance(fp, dict))
    check("fingerprint has ip field", fp.get("ip") == target_ip)
    check("fingerprint has ports dict", isinstance(fp.get("ports"), dict))

    memory.update_fingerprint(target_ip, fp)

    # --- 5. Verify persisted state ---
    print("\n--- Test: AgentMemory persistence ---")
    state = memory.get_full_context()
    check("State has discovered_hosts", len(state["discovered_hosts"]) >= 1)
    check("State has fingerprints", len(state["fingerprints"]) >= 1)

    fresh = AgentMemory()
    fresh_state = fresh.get_full_context()
    check("State survives reload from disk",
          fresh_state["discovered_hosts"] == state["discovered_hosts"])

    print(f"\n[*] Final state file: {memory.path}")
    print(json.dumps(state, indent=2)[:2000])


if __name__ == "__main__":
    main()
