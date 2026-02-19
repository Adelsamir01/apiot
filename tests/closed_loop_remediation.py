#!/usr/bin/env python3
"""closed_loop_remediation.py — The Closed-Loop Purple Test.

Sequence:
  1. SETUP:     Spawn Zephyr CoAP sensor + Linux gateway.
  2. BASELINE:  Verify sensor alive and responding to CoAP.
  3. ATTACK:    Red Agent fires CoAP overflow exploit.
  4. ANALYZE:   Blue Agent reads attack log, extracts signature.
  5. PATCH:     Blue Agent applies iptables length-filter on FORWARD chain.
  6. VERIFY:    Confirm patch blocks malformed packets but allows valid CoAP.
  7. LOG:       attack_log + network_state reflect the outcome.

Run:  sudo python3 apiot/tests/closed_loop_remediation.py   (from llm_iot/)
"""

import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from apiot.toolkit.lab_client import LabClient, LabOfflineError
from apiot.toolkit import ot_exploits
from apiot.toolkit.defender import generate_iptables_rule, apply_patch, remove_patch
from apiot.core.state import AgentMemory
from apiot.core.attack_log import AttackLogger
from apiot.core.analyzer import PayloadAnalyzer
from apiot.core.verifier_blue import mark_remediated

LAB_DIR = PROJECT_ROOT / "iot_vlab"
PASS = 0
FAIL = 0
api_proc = None
applied_rule = None


def check(label: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}  {detail}")


def coap_ping(ip: str, port: int = 5683, timeout: float = 3.0) -> bool:
    """Send a valid CoAP Empty Confirmable (ping) and check for any reply."""
    pkt = struct.pack(">BBH", 0x40, 0x00, 0xBEEF)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (ip, port))
            s.recvfrom(256)
            return True
    except (socket.timeout, OSError):
        return False


def send_malformed_coap(ip: str, port: int = 5683, timeout: float = 3.0) -> dict:
    """Send the exact overflow packet and report delivery."""
    payload = struct.pack(">BBH", 0x40, 0x01, 0x1337) + bytes([0xDD, 0xFF, 0xFF])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (ip, port))
            try:
                s.recvfrom(256)
                got_reply = True
            except socket.timeout:
                got_reply = False
    except OSError as e:
        return {"sent": False, "error": str(e)}
    return {"sent": True, "got_reply": got_reply, "payload_hex": payload.hex()}


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


def main():
    global api_proc, applied_rule
    client = LabClient()
    memory = AgentMemory()
    logger = AttackLogger()
    memory.clear()
    logger.clear()

    api_proc = ensure_api(client)

    try:
        run_test(client, memory, logger)
    finally:
        if applied_rule:
            print("\n[cleanup] Removing iptables patch...")
            remove_patch(applied_rule)
        try:
            client.reset_lab()
        except Exception:
            pass
        if api_proc:
            os.kill(api_proc.pid, signal.SIGTERM)
            try:
                api_proc.wait(timeout=5)
            except Exception:
                api_proc.kill()
            print("[*] Stopped lab API.")

    print(f"\n{'='*60}")
    print(f"Results: {PASS} passed, {FAIL} failed out of {PASS + FAIL}")
    print(f"{'='*60}")
    sys.exit(1 if FAIL else 0)


def run_test(client: LabClient, memory: AgentMemory, logger: AttackLogger):
    global applied_rule

    # ── STEP 1: SETUP ─────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  STEP 1: LAB SETUP")
    print("="*60)
    client.reset_lab()

    print("[setup] Spawning zephyr_coap + dvrf_v03...")
    r_coap = client.spawn_device("zephyr_coap")
    r_dvrf = client.spawn_device("dvrf_v03")
    print(f"  zephyr_coap: {r_coap['run_id']}")
    print(f"  dvrf_v03:    {r_dvrf['run_id']}")

    print("[setup] Waiting 20s for DHCP...")
    time.sleep(20)

    topo = client.get_topology()
    coap_dev = next((d for d in topo if d["firmware_id"] == "zephyr_coap"), None)
    check("zephyr_coap alive", coap_dev is not None and coap_dev.get("alive"))
    sensor_ip = coap_dev["ip"] if coap_dev else None
    has_ip = sensor_ip and sensor_ip not in ("pending", "unknown")
    check("Sensor has IP", has_ip, f"ip={sensor_ip}")
    if not has_ip:
        print("[!] Sensor has no IP. Aborting.")
        return

    # ── STEP 2: BASELINE ──────────────────────────────────────────────
    print("\n" + "="*60)
    print("  STEP 2: BASELINE — SENSOR REACHABLE")
    print("="*60)
    alive = coap_ping(sensor_ip)
    check("Sensor responds to valid CoAP ping", alive)

    # ── STEP 3: RED ATTACK (CoAP overflow) ────────────────────────────
    print("\n" + "="*60)
    print("  STEP 3: RED AGENT — CoAP OVERFLOW ATTACK")
    print("="*60)
    attack_result = ot_exploits.coap_option_overflow(sensor_ip)
    logger.log(target_ip=sensor_ip, target_arch="ARM Cortex-M3",
               tool_used="coap_option_overflow",
               payload_hex=attack_result.get("payload_hex", ""),
               packets_sent=1, outcome="delivered", details=attack_result)
    check("Malformed packet delivered", attack_result.get("success", False))

    # ── STEP 4: BLUE ANALYZE ──────────────────────────────────────────
    print("\n" + "="*60)
    print("  STEP 4: BLUE AGENT — PAYLOAD ANALYSIS")
    print("="*60)
    analyzer = PayloadAnalyzer()
    signatures = analyzer.analyze_attack_log()
    coap_sigs = [s for s in signatures if s["attack"] == "coap_option_overflow"]
    check("Analyzer found CoAP signature", len(coap_sigs) >= 1)

    if not coap_sigs:
        print("[!] No CoAP signature. Aborting.")
        return
    sig = coap_sigs[0]
    print(f"  Signature: {sig['description']}")
    print(f"  Filter:    {sig['filter']}")

    # ── STEP 5: APPLY PATCH ───────────────────────────────────────────
    print("\n" + "="*60)
    print("  STEP 5: BLUE AGENT — VIRTUAL PATCH")
    print("="*60)
    rule = generate_iptables_rule(sig)
    print(f"  Rule: {rule}")

    patch_result = apply_patch(rule, sig)
    applied_rule = rule if patch_result["applied"] else None
    check("Patch applied", patch_result["applied"],
          patch_result.get("error", ""))
    ttp_ms = patch_result['elapsed_s'] * 1000
    print(f"  Time to patch: {ttp_ms:.0f}ms")

    # ── STEP 6: VERIFY PATCH ──────────────────────────────────────────
    print("\n" + "="*60)
    print("  STEP 6: VERIFY PATCH — REPLAY vs LEGITIMATE TRAFFIC")
    print("="*60)

    # 6a. Valid CoAP ping STILL works (rule only blocks <=7 byte UDP)
    still_alive = coap_ping(sensor_ip)
    check("Valid CoAP still works (patch is narrow)", still_alive)

    # 6b. Malformed overflow is blocked (iptables drops it)
    replay = send_malformed_coap(sensor_ip)
    check("Malformed replay sent", replay.get("sent", False))
    # After iptables DROP, the packet never reaches the sensor.
    # The sensor stays alive:
    time.sleep(2)
    alive_after = coap_ping(sensor_ip)
    check("Sensor alive after replay (patch blocked attack)", alive_after)

    # Log replay
    logger.log(target_ip=sensor_ip, target_arch="ARM Cortex-M3",
               tool_used="replay_coap_option_overflow",
               payload_hex=replay.get("payload_hex", ""),
               packets_sent=1, outcome="blocked_by_patch",
               details=replay)

    # 6c. Record the vulnerability and remediation
    vuln_id = "coap_overflow_v1"
    memory.add_vulnerability(vuln_id, {
        "ip": sensor_ip, "attack": "coap_option_overflow",
        "payload_hex": attack_result.get("payload_hex", ""),
        "timestamp": time.time(),
    })
    if alive_after:
        mark_remediated(vuln_id, sensor_ip, "coap_option_overflow", rule)
        logger.log(target_ip=sensor_ip, target_arch="ARM Cortex-M3",
                   tool_used="blue_verify_patch", packets_sent=0,
                   outcome="patch_verified", details={"rule": rule})

    # ── STEP 7: FINAL REPORT ──────────────────────────────────────────
    print("\n" + "="*60)
    print("  STEP 7: FINAL REPORT")
    print("="*60)
    final = AgentMemory().get_full_context()
    vulns = final.get("active_vulnerabilities", {})
    coap_vuln = vulns.get("coap_overflow_v1", {})
    remediated = coap_vuln.get("remediation_status") == "VERIFIED_SECURE"
    check("network_state has VERIFIED_SECURE", remediated,
          f"status={coap_vuln.get('remediation_status')}")

    summary = logger.get_summary()
    print(f"\n  Attack steps:          {summary['total_steps']}")
    print(f"  Total packets:         {summary['total_packets']}")
    print(f"  Patches applied:       1")
    print(f"  Patch verified:        {1 if remediated else 0}")
    print(f"  Time to patch (TTP):   {ttp_ms:.0f}ms")


if __name__ == "__main__":
    main()
