#!/usr/bin/env python3
"""test_phase1.py — Integration test for apiot Phase 1 against the live iot_vlab.

Run with:  sudo python3 -m apiot.tests.test_phase1   (from llm_iot/)
      or:  sudo python3 apiot/tests/test_phase1.py
"""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from apiot.toolkit.lab_client import LabClient, LabOfflineError
from apiot.toolkit.recon import scan_subnet, fingerprint_target
from apiot.core.state import AgentMemory

LAB_DIR = PROJECT_ROOT / "iot_vlab"
API_URL = "http://localhost:5000"
PASS = 0
FAIL = 0
api_proc = None


def check(label: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}  {detail}")


def ensure_api_running(client: LabClient) -> subprocess.Popen | None:
    """If the API is not running, start it. Returns the Popen or None."""
    try:
        client.get_library()
        print("[*] Lab API already running.")
        return None
    except LabOfflineError:
        print("[*] Lab API not running — starting it...")
        proc = subprocess.Popen(
            ["sudo", "python3", "lab_api.py"],
            cwd=str(LAB_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait for API to come up
        for _ in range(20):
            time.sleep(1)
            try:
                client.get_library()
                print("[*] Lab API started (PID %d)." % proc.pid)
                return proc
            except LabOfflineError:
                continue
        print("[!] Failed to start lab API after 20s.")
        proc.kill()
        sys.exit(1)


def main():
    global api_proc
    client = LabClient(base_url=API_URL)
    memory = AgentMemory()
    memory.clear()

    api_proc = ensure_api_running(client)

    try:
        run_tests(client, memory)
    finally:
        # Always clean up lab and API
        try:
            client.reset_lab()
        except Exception:
            pass
        if api_proc:
            os.kill(api_proc.pid, signal.SIGTERM)
            api_proc.wait(timeout=5)
            print("[*] Stopped lab API.")

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

    # --- 2. Reset lab ---
    print("\n--- Test: reset_lab ---")
    res = client.reset_lab()
    check("reset_lab returns status", res.get("status") == "reset")

    # --- 3. Spawn devices ---
    print("\n--- Test: spawn zephyr_echo ---")
    spawn1 = client.spawn_device("zephyr_echo")
    run_id_echo = spawn1.get("run_id", "")
    check("zephyr_echo spawned", bool(run_id_echo), str(spawn1))

    print("\n--- Test: spawn dvrf_v03 ---")
    spawn2 = client.spawn_device("dvrf_v03")
    run_id_dvrf = spawn2.get("run_id", "")
    check("dvrf_v03 spawned", bool(run_id_dvrf), str(spawn2))

    # --- 4. Wait for boot + DHCP ---
    print("\n[*] Waiting 15s for boot / DHCP leases...")
    time.sleep(15)

    # --- 5. Topology ---
    print("\n--- Test: topology ---")
    topo = client.get_topology()
    check("Topology is a list", isinstance(topo, list))
    check("Two devices in topology", len(topo) == 2, f"got {len(topo)}")

    # Collect IPs from topology
    echo_entry = next((d for d in topo if d["firmware_id"] == "zephyr_echo"), None)
    dvrf_entry = next((d for d in topo if d["firmware_id"] == "dvrf_v03"), None)
    check("zephyr_echo in topology", echo_entry is not None)
    check("dvrf_v03 in topology", dvrf_entry is not None)

    echo_ip = echo_entry["ip"] if echo_entry else None
    dvrf_ip = dvrf_entry["ip"] if dvrf_entry else None

    has_echo_ip = echo_ip and echo_ip not in ("pending", "unknown")
    # dvrf may still be booting (60-90s), so IP may be pending — that's OK

    # --- 6. Subnet scan ---
    print("\n--- Test: scan_subnet ---")
    hosts = scan_subnet("192.168.100.0/24")
    check("scan_subnet returns list", isinstance(hosts, list))
    check("At least 1 host found", len(hosts) >= 1, f"found {len(hosts)}")
    host_ips = [h["ip"] for h in hosts]

    if has_echo_ip:
        check("zephyr_echo IP in scan results", echo_ip in host_ips,
              f"echo_ip={echo_ip}, found={host_ips}")

    # Save discovered hosts to memory
    for h in hosts:
        memory.update_host(h["ip"], {"mac": h["mac"], "vendor": h["vendor"]})

    # --- 7. Fingerprint (on echo device if IP available, else gateway) ---
    target_ip = echo_ip if has_echo_ip else "192.168.100.1"
    target_ports = "4242" if has_echo_ip else "1-1024"
    print(f"\n--- Test: fingerprint_target({target_ip}, ports={target_ports}) ---")
    fp = fingerprint_target(target_ip, ports=target_ports)
    check("fingerprint returns dict", isinstance(fp, dict))
    check("fingerprint has ip field", fp.get("ip") == target_ip)
    check("fingerprint has ports dict", isinstance(fp.get("ports"), dict))

    # Save fingerprint to memory
    memory.update_fingerprint(target_ip, fp)

    # --- 8. Verify persisted state ---
    print("\n--- Test: AgentMemory persistence ---")
    state = memory.get_full_context()
    check("State has discovered_hosts", len(state["discovered_hosts"]) >= 1)
    check("State has fingerprints", len(state["fingerprints"]) >= 1)

    # Re-load from disk to verify persistence
    fresh = AgentMemory()
    fresh_state = fresh.get_full_context()
    check("State survives reload from disk",
          fresh_state["discovered_hosts"] == state["discovered_hosts"])

    # --- 9. Cleanup ---
    print("\n--- Test: cleanup ---")
    res = client.reset_lab()
    check("reset_lab after tests", res.get("status") == "reset")
    topo = client.get_topology()
    check("Topology empty after reset", len(topo) == 0, f"got {len(topo)}")

    # Print final state summary
    print(f"\n[*] Final state file: {memory.path}")
    print(json.dumps(state, indent=2)[:2000])


if __name__ == "__main__":
    main()
